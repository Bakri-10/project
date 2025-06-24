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
    
def clean_data(item):
    """Clean invalid fields in the item."""
    for key, value in item.items():
        # Check for NaN as a float
        if isinstance(value, float) and math.isnan(value):
            item[key] = None  # Replace NaN with None
        
        # Check for NaN as a string
        if isinstance(value, str) and value.lower() == "nan":
            item[key] = None  # Replace "NaN" string with None
    return item

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

def initialize_elasticsearch(es_url, es_service_id, es_password):
    """
    Initializes an Elasticsearch client with the provided credentials.
    
    Args:
        es_url (str): The Elasticsearch URL.
        es_service_id (str): The service ID for authentication.
        es_password (str): The password for authentication.
    
    Returns:
        Elasticsearch: An instance of the Elasticsearch client, or None if an error occurs.
    """
    try:
        es = Elasticsearch(
            [es_url],
            http_auth=HTTPBasicAuth(es_service_id, es_password),
            node_class='requests'
        )
        return es
    except Exception as e:
        print(f"Error initializing Elasticsearch: {e}")
        return None

def load_json_file(json_file_path):
    """
    Loads JSON data from a file.
    
    Args:
        json_file_path (str): The path to the compliance data JSON file.
    
    Returns:
        dict: The loaded compliance JSON data as a dictionary, or None if an error occurs.
    """
    try:
        with open(json_file_path) as file:
            compliance_data = json.load(file)
        return compliance_data
    except json.JSONDecodeError as e:
        print(f"Error loading JSON data: {e}")
        return None
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        return None

def enrich_and_update_compliance_data(es, compliance_data, iipm_lookup, compliance_index_name):
    """
    Enriches compliance data with IIPM data and updates the Elasticsearch index.
    
    Args:
        es (Elasticsearch): The Elasticsearch client.
        compliance_data (list): The list of compliance data.
        iipm_lookup (dict): The lookup dictionary for IIPM data.
        compliance_index_name (str): The name of the Elasticsearch index to update.
    """
    indexing_timestamp = datetime.now()
    for item in compliance_data:
        compliance_id = item.get("complianceId")  # Use complianceId instead of Finding ID
        app_code = item.get("appCode", "N/A")
        
        if not compliance_id:
            print("Skipping record without a valid 'complianceId'")
            continue
            
        item = clean_data(item) 
        item["timestamp"] = indexing_timestamp
        
        # Enrich with IIPM data if available
        if app_code and app_code in iipm_lookup:
            item["iipm"] = iipm_lookup[app_code]
        
        try:
            es.update(
                index=compliance_index_name,
                id=compliance_id,  # Use compliance_id as document ID
                body={
                    "doc": item,
                    "doc_as_upsert": True
                }
            )
            print(f"Successfully updated/created record for complianceId: {compliance_id}")
        except Exception as e:
            print(f"Error updating/creating record with complianceId {compliance_id}: {e}")

def main(argv):
    args = parse_arguments()
    es_url = args.es_url
    es_service_id = args.es_service_id
    es_password = args.es_password
    json_file_path = args.json_file_path
    compliance_index_name = args.compliance_index_name
    iipm_index_name = args.iipm_index_name

    compliance_data = load_json_file(json_file_path)
    if compliance_data is None:
        print("Failed to load compliance data. Exiting.")
        sys.exit(1)
    
    es = initialize_elasticsearch(es_url, es_service_id, es_password)
    if es is None:
        print("Failed to initialize Elasticsearch client. Exiting.")
        sys.exit(1)
    
    iipm_data = fetch_iipm_data(es, iipm_index_name)
    if iipm_data is None:
        print("Failed to fetch IIPM data. Exiting.")
        sys.exit(1)
    
    iipm_lookup = create_iipm_lookup(iipm_data)
    enrich_and_update_compliance_data(es, compliance_data, iipm_lookup, compliance_index_name)
    print("Compliance data enrichment completed successfully.")

if __name__ == '__main__':
    main(sys.argv[1:]) 
