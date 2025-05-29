#!/usr/bin/env python3

import os
import sys
import json
import requests
from datetime import datetime
import urllib3

# Disable SSL warnings - use only in development or with self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_env_var(var_name, default=None, required=False):
    """Get environment variable or return default value"""
    value = os.environ.get(var_name, default)
    if required and value is None:
        print(f"ERROR: Required environment variable {var_name} is not set.")
        sys.exit(1)
    return value

def query_elasticsearch():
    """Query Elasticsearch using environment variables for configuration"""
    
    # Get environment variables
    es_host = get_env_var("ES_HOST", required=True)
    es_index = get_env_var("ES_INDEX", required=True)
    start_date = get_env_var("START_DATE", "")
    end_date = get_env_var("END_DATE", "")
    
    # Debug date range
    print(f"Using date range: {start_date} to {end_date}")
    
    # Get authentication if provided
    username = get_env_var("ES_USERNAME", "")
    password = get_env_var("ES_PASSWORD", "")
    auth = None
    if username and password:
        auth = (username, password)
    
    # Build the search URL
    search_url = f"{es_host}/{es_index}/_search"
    print(f"Using Elasticsearch URL: {search_url}")
    
    # Prepare the query to get high severity issues for all issue types
    query = {
        "size": 10000,  # Increased size limit to get more results
        "query": {
            "bool": {
                "must": [
                    {
                        "terms": {
                            "severity.keyword": ["critical", "high"]
                        }
                    }
                ]
            }
        },
        "aggs": {
            "by_app_code": {
                "terms": {
                    "field": "appCode.keyword",
                    "size": 10000
                },
                "aggs": {
                    "issue_types": {
                        "terms": {
                            "field": "issueType.keyword",
                            "size": 1000
                        }
                    }
                }
            },
            "all_issue_types": {
                "terms": {
                    "field": "issueType.keyword",
                    "size": 1000
                }
            }
        }
    }
    
    # Add date range filter if both start and end dates are provided
    if start_date and end_date:
        date_range = {
            "range": {
                "timestamp": {
                    "gte": start_date,
                    "lte": end_date
                }
            }
        }
        query["query"]["bool"]["must"].append(date_range)
        print(f"Added date range filter: {json.dumps(date_range, indent=2)}")
    
    # Set headers
    headers = {
        "Content-Type": "application/json"
    }
    
    # Debug query
    print(f"Using query: {json.dumps(query, indent=2)}")
    
    try:
        # Send the request
        print("Sending request to Elasticsearch...")
        response = requests.post(
            search_url,
            headers=headers,
            json=query,
            auth=auth,
            verify=False
        )
        
        # Check response
        if response.status_code == 200:
            result = response.json()
            print(f"Got successful response from Elasticsearch")
            
            # Process aggregations to get app codes with high severity issues and their issue types
            app_codes_with_issues = []
            all_issue_types = set()
            
            if "aggregations" in result:
                # Get all issue types
                if "all_issue_types" in result["aggregations"]:
                    for bucket in result["aggregations"]["all_issue_types"]["buckets"]:
                        all_issue_types.add(bucket["key"])
                
                # Get app codes and their specific issue types
                if "by_app_code" in result["aggregations"]:
                    for app_bucket in result["aggregations"]["by_app_code"]["buckets"]:
                        if app_bucket["doc_count"] > 0:
                            app_code = app_bucket["key"]
                            app_issue_types = []
                            
                            if "issue_types" in app_bucket:
                                for type_bucket in app_bucket["issue_types"]["buckets"]:
                                    app_issue_types.append(type_bucket["key"])
                            
                            app_codes_with_issues.append({
                                "app_code": app_code,
                                "issue_types": app_issue_types,
                                "count": app_bucket["doc_count"]
                            })
            
            # Save result to file if output path is provided
            output_file = get_env_var("OUTPUT_FILE", "")
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Query results saved to {output_file}")
                print(f"Found {len(app_codes_with_issues)} app codes with high severity issues")
                print(f"Total issue types found: {len(all_issue_types)}")
                print(f"Issue types: {', '.join(sorted(all_issue_types))}")
                
                # Print sample of the data
                hits = result.get("hits", {}).get("hits", [])
                if hits:
                    print("\nSample of first result:")
                    print(json.dumps(hits[0], indent=2))
            else:
                hits = result.get("hits", {}).get("hits", [])
                total = result.get("hits", {}).get("total", {}).get("value", 0)
                print(f"Query returned {total} results across {len(app_codes_with_issues)} app codes")
            
            return True
        else:
            print(f"ERROR: Query failed with status code {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"ERROR: Failed to query Elasticsearch: {str(e)}")
        return False

if __name__ == "__main__":
    success = query_elasticsearch()
    sys.exit(0 if success else 1) 