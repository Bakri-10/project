import json
import argparse
from elasticsearch import Elasticsearch, helpers
from requests.auth import HTTPBasicAuth
import requests
from datetime import datetime
import sys
import math

def parse_arguments():
    parser = argparse.ArgumentParser(description='Publish Compliance data to Elasticsearch')
    parser.add_argument('--es-url', required=True, help='Elasticsearch URL')
    parser.add_argument('--es-service-id', required=True, help='Elasticsearch service id')
    parser.add_argument('--es-password', required=True, help='Elasticsearch service id password')
    parser.add_argument('--json-file-path', required=True, help='Compliance data as retrieved via the ansible task')
    parser.add_argument('--compliance-index-name', required=True, help='Compliance elasticsearch index name')
    parser.add_argument('--iipm-index-name', required=True, help='IIPM elasticsearch index name')
    return parser.parse_args()

def fetch_iipm_data(es, iipm_index_name):
    """Fetch data from the IIPM index"""
    try:
        # Query to fetch all appcodes and their enrichment data
        query = {
            "_source": ["appCode", "name", "lineOfBusiness", "contactPerson", "contactType", "contactMechanism", "roles.IT_CUSTODIAN.id", "roles.IT_EXECUTIVE.id", "roles.GROUP_MANAGER.id", "app_custodian_name"],
            "query": {
                "exists": {
                    "field": "appCode"
                }
            }
        }
        response = es.search(index=iipm_index_name, **query, size=10000)
        if not response['hits']['hits']:
            raise ValueError(f"No data found in the IIPM index: {iipm_index_name}")
        return response
    except Exception as e:
        print(f"Error fetching IIPM data: {e}")
        return None

def create_iipm_lookup(iipm_data):
    """Create a lookup dictionary """
    iipm_data_lookup_dict = {}
    for hit in iipm_data['hits']['hits']:
        source = hit['_source']
        appcode = source.get("appCode")
        if appcode:
            iipm_data_lookup_dict[appcode] = {
                "name": source.get("name"),
                "lineOfBusiness": source.get("lineOfBusiness"),
                "contactPerson": source.get("contactPerson"),
                "contactType": source.get("contactType"),
                "contactMechanism": source.get("contactMechanism"),
                "appCustodianId": source.get("roles", {}).get("IT_CUSTODIAN", {}).get("id"),
                "app_custodian_name": source.get("app_custodian_name")
            }
    # For "Multiple App Codes Selected" or "No App Code Selected", set the values to "Unknown"
    iipm_data_lookup_dict["Multiple App Codes Selected"] = {
        "name": "Unknown",
        "lineOfBusiness": "Unknown",
        "contactPerson": "Unknown",
        "contactType": "Unknown",
        "contactMechanism": "Unknown",
        "appCustodianId": "Unknown",
        "app_custodian_name": "Unknown"
    }
    iipm_data_lookup_dict["No App Code Selected"] = {
        "name": "Unknown",
        "lineOfBusiness": "Unknown",
        "contactPerson": "Unknown",
        "contactType": "Unknown",
        "contactMechanism": "Unknown",
        "appCustodianId": "Unknown",
        "app_custodian_name": "Unknown"
    }
    return iipm_data_lookup_dict

def main(argv):
    args = parse_arguments()
    es_url = args.es_url
    es_service_id = args.es_service_id
    es_password = args.es_password
    json_file_path = args.json_file_path
    compliance_index_name = args.compliance_index_name
    iipm_index_name = args.iipm_index_name

    try:
        with open(json_file_path) as file:
            data = json.load(file)
    except json.JSONDecodeError as e:
        print(f"Error loading JSON data: {e}")
        return
    
    es = Elasticsearch(
        [es_url],
        http_auth=HTTPBasicAuth(es_service_id, es_password),
        node_class='requests'
    )
    
    # Create index if it doesn't exist (following sample pattern)
    if not es.indices.exists(index=compliance_index_name):
        es.indices.create(index=compliance_index_name)
        print(f"Index '{compliance_index_name}' created.")
    
    # Fetch IIPM data for enrichment
    iipm_data = fetch_iipm_data(es, iipm_index_name)
    iipm_lookup = {}
    if iipm_data:
        iipm_lookup = create_iipm_lookup(iipm_data)
    
    indexing_timestamp = datetime.now()
    actions = []
    
    # Process compliance data (assuming it's a list, not nested under "results")
    compliance_data = data if isinstance(data, list) else data.get("results", [])
    
    for item in compliance_data:
        item["timestamp"] = indexing_timestamp
        
        # Enrich with IIPM data if available
        app_code = item.get("appCode")
        if app_code and app_code in iipm_lookup:
            item["contact-info"] = iipm_lookup[app_code]
        
        actions.append({
            "_index": compliance_index_name,
            "_source": item
        })
    
    if actions:
        try:
            helpers.bulk(es, actions)
            print(len(actions))  # testing - to be removed.
            print("Data successfully indexed.")
        except Exception as e:
            print(f"Error indexing data: {e}")
    else:
        print(f"No actions to index.")

if __name__ == '__main__':
    main(sys.argv[1:]) 
