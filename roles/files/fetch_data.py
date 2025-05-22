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
    app_codes = get_env_var("APP_CODES", "").split(",")
    start_date = get_env_var("START_DATE", "")
    end_date = get_env_var("END_DATE", "")
    issue_type_str = get_env_var("ISSUE_TYPE", "Vulnerability")  # Default to Vulnerability if not specified
    issue_types = [it.strip() for it in issue_type_str.split(',') if it.strip()] # Split and remove empty strings
    
    # Get authentication if provided
    username = get_env_var("ES_USERNAME", "")
    password = get_env_var("ES_PASSWORD", "")
    auth = None
    if username and password:
        auth = (username, password)
    
    # Build the search URL
    search_url = f"{es_host}/{es_index}/_search"
    
    # Prepare the query
    query = {
        "query": {
            "bool": {
                "must": [
                    
                ]
            }
        }
    }

    # Add issue type filter
    if len(issue_types) == 1:
        query["query"]["bool"]["must"].append({"term": {"issueType.keyword": issue_types[0]}})
    elif len(issue_types) > 1:
        query["query"]["bool"]["must"].append({"terms": {"issueType.keyword": issue_types}})
    else: # Fallback or if empty after stripping
        query["query"]["bool"]["must"].append({"term": {"issueType.keyword": "Vulnerability"}})
    
    # Add app codes filter if provided
    if app_codes and app_codes[0]:
        query["query"]["bool"]["must"].append(
            {"terms": {"appCode.keyword": app_codes}}
        )
    
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
            verify=False  # Only use in development or with self-signed certs
        )
        
        # Check response
        if response.status_code == 200:
            # Process and return data
            result = response.json()
            
            # Save result to file if output path is provided
            output_file = get_env_var("OUTPUT_FILE", "")
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Query results saved to {output_file}")
            else:
                # Print summary to stdout
                hits = result.get("hits", {}).get("hits", [])
                total = result.get("hits", {}).get("total", {}).get("value", 0)
                print(f"Query returned {total} results")
                
                # Print first few results as summary
                if hits:
                    print("\nSample results:")
                    for i, hit in enumerate(hits[:3]):
                        print(f"{i+1}. {json.dumps(hit['_source'], indent=2)}")
            
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
