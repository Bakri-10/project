import json
import argparse
from elasticsearch import Elasticsearch, helpers, BadRequestError
from requests.auth import HTTPBasicAuth
from datetime import datetime
import sys

def parse_arguments():
    parser = argparse.ArgumentParser(description='Publish Chorus API Compliance Reporting JSON data to Elasticsearch')
    parser.add_argument('--es-url', required=True, help='Elasticsearch URL')
    parser.add_argument('--es-service-id', required=True, help='Elasticsearch service id')
    parser.add_argument('--es-password', required=True, help='Elasticsearch service id password')
    parser.add_argument('--json-file-path', required=True, help='JSON data as retrieved via the ansible playbook')
    parser.add_argument('--index-name', required=True, help='Elasticsearch index name')
    
    return parser.parse_args()

def transform_roles(data):
    print("I am here in parse_json_file")
    transformed_data = []
    for record in data:
        # Extract general fields
        app_code = record.get("appCode", "N/A")
        name = record.get("name", "N/A")
        line_of_business = record.get("lineOfBusiness", "N/A")
        contact_person = record.get("contactPerson", "N/A")
        contact_type = record.get("contactType", "N/A")
        contact_mechanism = record.get("contactMechanism", "N/A")
        
        # Process roles
        roles = record.get("roles", {})
        flattened_roles = {}
        for role, employees in roles.items():
            flattened_roles[role] = [emp["employeeId"] for emp in employees]
        
        # Add transformed record
        transformed_data.append({
            "appCode": app_code,
            "name": name,
            "lineOfBusiness": line_of_business,
            "contactPerson": contact_person,
            "contactType": contact_type,
            "contactMechanism": contact_mechanism,
            "roles": flattened_roles
        })
    return transformed_data

def format_roles(data):
    if "roles" in data and data["roles"]:
        # Check if roles is actually a dictionary
        if not isinstance(data["roles"], dict):
            print(f"Warning: roles field is not a dictionary in format_roles for item {data.get('appCode', 'unknown')}: {type(data['roles'])} - {data['roles']}")
            # Convert to empty dict if it's not a dictionary
            data["roles"] = {}
            return data
            
        try:
            for role, values in data["roles"].items():
                # Convert list to comma-separated string
                if isinstance(values, list):
                    data["roles"][role] = ", ".join(str(v) for v in values)
                elif isinstance(values, str):
                    data["roles"][role] = values
                else:
                    data["roles"][role] = str(values) if values else ""
        except Exception as e:
            print(f"Error formatting roles for item {data.get('appCode', 'unknown')}: {e}")
            data["roles"] = {}
    return data

# Function to transform roles into objects to new json format
def transform_roles_obj(data):
    for item in data:
        if "roles" in item and item["roles"]:
            # Check if roles is actually a dictionary
            if not isinstance(item["roles"], dict):
                print(f"Warning: roles field is not a dictionary for item {item.get('appCode', 'unknown')}: {type(item['roles'])} - {item['roles']}")
                # Convert to empty dict if it's not a dictionary
                item["roles"] = {}
                continue
                
            transformed_roles = {}
            try:
                for role, value in item["roles"].items():
                    if value:  # Check if the value is not empty
                        if isinstance(value, str) and "," in value:  # If the value is comma-separated, split into a list
                            transformed_roles[role] = {"ids": [v.strip() for v in value.split(",")]}
                        elif isinstance(value, str):  # Otherwise, treat it as a single ID
                            transformed_roles[role] = {"id": value.strip()}
                        elif isinstance(value, list):  # If it's already a list, handle it
                            if len(value) > 1:
                                transformed_roles[role] = {"ids": [str(v).strip() for v in value]}
                            elif len(value) == 1:
                                transformed_roles[role] = {"id": str(value[0]).strip()}
                            else:
                                transformed_roles[role] = {}
                        else:  # For any other type, convert to string
                            transformed_roles[role] = {"id": str(value).strip()}
                    else:  # If the value is empty, set it to an empty object
                        transformed_roles[role] = {}
                item["roles"] = transformed_roles
            except Exception as e:
                print(f"Error processing roles for item {item.get('appCode', 'unknown')}: {e}")
                item["roles"] = {}
    return data

# Function to ensure proper field formatting for Elasticsearch
def format_fields_for_elasticsearch(data):
    """
    Ensure fields are properly formatted for Elasticsearch indexing
    to create both text and keyword mappings
    """
    formatted_data = []
    for item in data:
        # Create a copy to avoid modifying original data
        formatted_item = item.copy()
        
        # Ensure string fields are properly formatted for keyword mapping
        string_fields = ['lineOfBusiness', 'contactPerson', 'contactType', 'contactMechanism', 'appCode', 'name']
        for field in string_fields:
            if field in formatted_item and formatted_item[field]:
                # Ensure the field value is a string and not None
                if formatted_item[field] != "N/A" and formatted_item[field] is not None:
                    formatted_item[field] = str(formatted_item[field])
        
        formatted_data.append(formatted_item)
    
    return formatted_data

def main(argv):
    args = parse_arguments()
    es_url = args.es_url
    es_service_id = args.es_service_id
    es_password = args.es_password
    json_file_path = args.json_file_path
    index_name = args.index_name.lower()  # Elasticsearch indices must be lowercase
    
    print(f"Processing JSON file: {json_file_path}")
    
    # Single JSON file read and processing
    try:
        with open(json_file_path, "r") as infile:
            data = json.load(infile)
            
        if not data:
            print("Error: JSON file is empty or contains no data.")
            return
            
        print(f"Loaded {len(data)} records from JSON file")
        
        # Process data through all transformation steps
        print("Step 1: Transforming roles...")
        try:
            transformed_data = transform_roles(data)
        except Exception as e:
            print(f"Error in transform_roles: {e}")
            return
        
        print("Step 2: Formatting roles...")
        try:
            if isinstance(transformed_data, list):
                formatted_data = []
                for i, item in enumerate(transformed_data):
                    try:
                        formatted_item = format_roles(item)
                        formatted_data.append(formatted_item)
                    except Exception as e:
                        print(f"Error formatting roles for record {i} (appCode: {item.get('appCode', 'unknown')}): {e}")
                        # Add the item without role formatting as fallback
                        formatted_data.append(item)
            else:
                formatted_data = format_roles(transformed_data)
        except Exception as e:
            print(f"Error in format_roles step: {e}")
            return
            
        print("Step 3: Converting roles to objects...")
        try:
            final_data = transform_roles_obj(formatted_data)
        except Exception as e:
            print(f"Error in transform_roles_obj: {e}")
            return
        
        print("Step 4: Formatting fields for Elasticsearch...")
        try:
            final_data = format_fields_for_elasticsearch(final_data)
        except Exception as e:
            print(f"Error in format_fields_for_elasticsearch: {e}")
            return
        
        # Validate data structure before sending to Elasticsearch
        valid_data = []
        for i, item in enumerate(final_data):
            try:
                if not isinstance(item, dict):
                    print(f"Warning: Skipping invalid data structure at index {i}: {type(item)}")
                    continue
                if "roles" in item and not isinstance(item["roles"], dict):
                    print(f"Warning: Invalid roles structure for item {item.get('appCode', 'unknown')}, converting to empty dict")
                    item["roles"] = {}
                valid_data.append(item)
            except Exception as e:
                print(f"Error validating item at index {i}: {e}")
                continue
        
        final_data = valid_data
        print("Data transformation completed successfully")
        
    except FileNotFoundError:
        print(f"Error: The file {json_file_path} was not found.")
        return
    except json.JSONDecodeError as e:
        print(f"Error loading JSON data: {e}")
        return
    except Exception as e:
        print(f"Error processing JSON data: {e}")
        return
        
    # Test Elasticsearch connection with timeout and retry settings
    try:
        es = Elasticsearch(
            [es_url],
            http_auth=HTTPBasicAuth(es_service_id, es_password),
            retry_on_timeout=True,
            timeout=30,
            max_retries=3,
            node_class='requests'
        )
        
        # Test connection
        if not es.ping():
            print("Error: Cannot connect to Elasticsearch")
            return
            
        print("Elasticsearch connection successful")
        
    except Exception as e:
        print(f"Error connecting to Elasticsearch: {e}")
        return
    
    # Ensure index exists with proper settings
    try:
        if not es.indices.exists(index=index_name):
            # Create index with basic settings
            index_settings = {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1
                },
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "appCode": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        },
                        "name": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        },
                        "lineOfBusiness": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        },
                        "contactPerson": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        },
                        "contactType": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        },
                        "contactMechanism": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        },
                        "roles": {"type": "object"}
                    }
                }
            }
            es.indices.create(index=index_name, body=index_settings)
            print(f"Index '{index_name}' created with settings.")
        else:
            print(f"Using existing index '{index_name}'")
    except BadRequestError as e:
        print(f"Error creating/checking index (Bad Request): {e}")
        return
    except Exception as e:
        print(f"Error creating/checking index: {e}")
        return
        
    # Process documents for Elasticsearch
    print("Starting Elasticsearch updates...")
    indexing_timestamp = datetime.now().isoformat()
    
    success_count = 0
    error_count = 0
    
    for appcode_detail in final_data:
        if not appcode_detail.get("appCode"):
            print("Warning: Skipping record without appCode")
            error_count += 1
            continue
            
        # Adding timestamp to each record
        appcode_detail["timestamp"] = indexing_timestamp
        appCode = appcode_detail["appCode"]
        
        try:
            # Debug: Show the structure of roles field if it exists
            if "roles" in appcode_detail:
                roles_type = type(appcode_detail["roles"])
                if not isinstance(appcode_detail["roles"], dict):
                    print(f"Debug: Document {appCode} has roles of type {roles_type}: {appcode_detail['roles']}")
                    
            # Check if document exists
            if es.exists(index=index_name, id=appCode):
                # Update existing document by adding/merging new fields
                response = es.update(
                    index=index_name, 
                    id=appCode, 
                    body={
                        "doc": appcode_detail,
                        "doc_as_upsert": True
                    }
                )
                print(f"✓ Document {appCode} updated: {response['result']}")
                success_count += 1
            else:
                # Create new document
                response = es.index(index=index_name, id=appCode, body=appcode_detail)
                print(f"✓ Document {appCode} created: {response['result']}")
                success_count += 1
                
        except Exception as e:
            print(f"✗ Error processing document {appCode}: {e}")
            print(f"   Document structure: {appcode_detail}")
            error_count += 1
            
    # Summary
    print(f"\n=== Update Summary ===")
    print(f"Successfully processed: {success_count}")
    print(f"Errors encountered: {error_count}")
    print(f"Total records: {len(final_data)}")
    
    if error_count == 0:
        print("✓ All updates completed successfully!")
    else:
        print(f"⚠ Completed with {error_count} errors")

if __name__ == '__main__':
    main(sys.argv[1:]) 
