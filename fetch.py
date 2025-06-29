#!/usr/bin/env python3

import os
import sys
import json
import requests
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
        "_source": ["issueType"],
        "query": {
            "bool": {
                "must": [
                    {
                        "terms": {
                            "priority.keyword": ["P1", "P2"]
                        }
                    }
                ],
                "filter": [
                    {
                        "terms": {
                            "issueState.keyword": ["OPEN"]
                        }
                    },
                    {
                        "terms": {
                            "issueType.keyword": ["AV TSS", "Cryptography", "Open Data", "TSS", "Vulnerability"]
                        }
                    }
                ]
            }
        },
        "size": 100
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            search_url,
            headers=headers,
            json=query,
            auth=auth,
            verify=False
        )
        
        if response.status_code == 200:
            result = response.json()
            hits = result.get("hits", {}).get("hits", [])
            total = result.get("hits", {}).get("total", {}).get("value", 0)
            
            print(f"Found {total} issues")
            
            if hits:
                for hit in hits:
                    source = hit['_source']
                    issue_type = source.get('issueType', 'N/A')
                    print(issue_type)
            
            return True
        else:
            print(f"ERROR: Query failed with status code {response.status_code}")
            print(f"Response: {response.text}")
            return False
    
    except Exception as e:
        print(f"ERROR: Failed to query Elasticsearch: {str(e)}")
        return False

def search_custodian_contact(custodian_name=None):
    """Search for custodian contact details in IIPM index"""
    
    # Get IIPM-specific environment variables
    es_host = get_env_var("ES_HOST", required=True)
    iipm_index = get_env_var("IIPM_INDEX", required=True)
    username = get_env_var("ES_USERNAME", "")
    password = get_env_var("ES_PASSWORD", "")
    
    if not custodian_name:
        custodian_name = get_env_var("CUSTODIAN_NAME", "")
        if not custodian_name:
            print("ERROR: No custodian name provided. Set CUSTODIAN_NAME environment variable or pass as argument.")
            return False
    
    auth = None
    if username and password:
        auth = (username, password)
    
    # Build the search URL
    search_url = f"{es_host}/{iipm_index}/_search"
    
    # Query to search for custodian
    query = {
        "_source": [
            "appCode", "name", "lineOfBusiness", 
            "contactPerson", "contactType", "contactMechanism", 
            "roles.IT_CUSTODIAN.id", "app_custodian_name"
        ],
        "query": {
            "bool": {
                "should": [
                    {
                        "match": {
                            "app_custodian_name": {
                                "query": custodian_name,
                                "fuzziness": "AUTO"
                            }
                        }
                    },
                    {
                        "match": {
                            "contactPerson": {
                                "query": custodian_name,
                                "fuzziness": "AUTO"  
                            }
                        }
                    }
                ],
                "minimum_should_match": 1
            }
        },
        "size": 100
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            search_url,
            headers=headers,
            json=query,
            auth=auth,
            verify=False
        )
        
        if response.status_code == 200:
            result = response.json()
            hits = result.get("hits", {}).get("hits", [])
            
            if hits:
                print(f"\nFound {len(hits)} matching records for custodian: {custodian_name}")
                print("-" * 80)
                
                for hit in hits:
                    source = hit['_source']
                    print(f"App Code: {source.get('appCode', 'N/A')}")
                    print(f"App Name: {source.get('name', 'N/A')}")
                    print(f"Line of Business: {source.get('lineOfBusiness', 'N/A')}")
                    print(f"Contact Person: {source.get('contactPerson', 'N/A')}")
                    print(f"Contact Type: {source.get('contactType', 'N/A')}")
                    print(f"Contact Mechanism: {source.get('contactMechanism', 'N/A')}")
                    print(f"App Custodian Name: {source.get('app_custodian_name', 'N/A')}")
                    print(f"App Custodian ID: {source.get('roles', {}).get('IT_CUSTODIAN', {}).get('id', 'N/A')}")
                    print("-" * 80)
                return True
            else:
                print(f"No matching records found for custodian: {custodian_name}")
                print("Try searching with a different name or check the spelling")
                return False
        else:
            print(f"ERROR: Search failed with status code {response.status_code}")
            print(f"Response: {response.text}")
            return False
    
    except Exception as e:
        print(f"ERROR: Failed to search for custodian: {str(e)}")
        return False



def main():
    """Main function"""
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "search-custodian":
            custodian_name = sys.argv[2] if len(sys.argv) > 2 else None
            search_custodian_contact(custodian_name)
        elif command == "query":
            query_elasticsearch()
        else:
            print("Usage: python fetch_data.py [query|search-custodian [name]]")
            print("\nCommands:")
            print("  query                    - Run compliance data query (fetch issueType)")
            print("  search-custodian [name]  - Search for custodian contact details")
            print("\nEnvironment Variables:")
            print("  ES_HOST                  - Elasticsearch host URL (required)")
            print("  ES_INDEX                 - Elasticsearch index name (required for query)")
            print("  IIPM_INDEX               - IIPM index name (required for custodian search)")
            print("  ES_USERNAME              - Elasticsearch username (optional)")
            print("  ES_PASSWORD              - Elasticsearch password (optional)")
            print("  CUSTODIAN_NAME           - Custodian name to search (optional)")
    else:
        # Default action - run compliance query
        query_elasticsearch()

if __name__ == '__main__':
    main() 
