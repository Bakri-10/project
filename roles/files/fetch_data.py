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
    issue_type_str = get_env_var("ISSUE_TYPE", "Vulnerability")
    issue_types = [it.strip() for it in issue_type_str.split(',') if it.strip()]
    
    # Get authentication if provided
    username = get_env_var("ES_USERNAME", "")
    password = get_env_var("ES_PASSWORD", "")
    auth = None
    if username and password:
        auth = (username, password)
    
    # Build the search URL
    search_url = f"{es_host}/{es_index}/_search"
    
    # Prepare the query to get high severity issues
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
                    "size": 10000  # Also increase aggregation size limit
                }
            }
        }
    }

    # Add issue type filter
    if len(issue_types) == 1:
        query["query"]["bool"]["must"].append({"term": {"issueType.keyword": issue_types[0]}})
    elif len(issue_types) > 1:
        query["query"]["bool"]["must"].append({"terms": {"issueType.keyword": issue_types}})
    
    # Add date range filter if both start and end dates are provided
    if start_date and end_date:
        query["query"]["bool"]["must"].append(
            {
                "range": {
                    "timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            }
        )
    
    # Set headers
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        # Send the request
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
            
            # Process aggregations to get app codes with high severity issues
            app_codes_with_issues = []
            if "aggregations" in result and "by_app_code" in result["aggregations"]:
                for bucket in result["aggregations"]["by_app_code"]["buckets"]:
                    if bucket["doc_count"] > 0:
                        app_codes_with_issues.append(bucket["key"])
            
            # Save result to file if output path is provided
            output_file = get_env_var("OUTPUT_FILE", "")
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Query results saved to {output_file}")
                print(f"Found {len(app_codes_with_issues)} app codes with high severity issues")
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