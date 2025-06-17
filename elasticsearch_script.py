import json
import argparse
from elasticsearch import Elasticsearch, helpers, BadRequestError
from requests.auth import HTTPBasicAuth
from datetime import datetime
import sys
import re

def parse_arguments():
    parser = argparse.ArgumentParser(description='Publish Chorus API Compliance Reporting JSON data to Elasticsearch')
    parser.add_argument('--es-url', required=True, help='Elasticsearch URL')
    parser.add_argument('--es-service-id', required=True, help='Elasticsearch service id')
    parser.add_argument('--es-password', required=True, help='Elasticsearch service id password')
    parser.add_argument('--json-file-path', required=True, help='JSON data as retrieved via the ansible playbook')
    parser.add_argument('--index-name', required=True, help='Elasticsearch index name')
    
    # Debug: Show raw command line arguments
    print(f"Debug - Raw sys.argv: {sys.argv}")
    
    # Check if any arguments contain dictionary-like strings that need parsing
    for i, arg in enumerate(sys.argv):
        if isinstance(arg, str) and ('{' in arg and '}' in arg):
            print(f"Warning: Argument {i} appears to contain dictionary data: {arg}")
    
    try:
        args = parser.parse_args()
        
        # Debug: Show parsed arguments
        print(f"Debug - Parsed arguments:")
        for arg_name, arg_value in vars(args).items():
            print(f"  {arg_name}: {type(arg_value)} = {arg_value}")
            # Additional check for contaminated arguments
            if not isinstance(arg_value, str):
                print(f"  WARNING: {arg_name} is not a string! Type: {type(arg_value)}")
            
        return args
    except Exception as e:
        print(f"Error parsing arguments: {e}")
        raise

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
    print(f"=== MAIN FUNCTION START ===")
    print(f"Raw argv parameter: {argv}")
    
    args = parse_arguments()
    
    print(f"=== AFTER PARSE_ARGUMENTS ===")
    es_url = args.es_url
    es_service_id = args.es_service_id
    es_password = args.es_password
    json_file_path = args.json_file_path
    index_name = args.index_name
    
    print(f"Individual variable assignments:")
    print(f"  es_url: {type(es_url)} = {es_url}")
    print(f"  es_service_id: {type(es_service_id)} = {es_service_id}")
    print(f"  es_password: {type(es_password)} = {es_password}")
    print(f"  json_file_path: {type(json_file_path)} = {json_file_path}")
    print(f"  index_name: {type(index_name)} = {index_name}")
    
    # Clean up other arguments if they contain dictionary data
    def extract_clean_value(arg_name, arg_value):
        if isinstance(arg_value, str) and ('{' in arg_value or 'es_url' in arg_value):
            print(f"Cleaning malformed argument {arg_name}: {arg_value}")
            # For es_url, extract the actual URL
            if arg_name == 'es_url' and 'https://' in arg_value:
                import re
                url_match = re.search(r'https://[^,}\s\'\"]+', arg_value)
                if url_match:
                    cleaned = url_match.group(0)
                    print(f"Extracted clean {arg_name}: {cleaned}")
                    return cleaned
        return arg_value
    
    # Clean up arguments
    es_url = extract_clean_value('es_url', es_url)
    es_service_id = extract_clean_value('es_service_id', es_service_id)
    json_file_path = extract_clean_value('json_file_path', json_file_path)
    
    # Debug: Show what we received
    print(f"Debug - Raw arguments received:")
    print(f"  es_url type: {type(es_url)} = {es_url}")
    print(f"  es_service_id type: {type(es_service_id)} = {es_service_id}")
    print(f"  json_file_path type: {type(json_file_path)} = {json_file_path}")
    print(f"  index_name type: {type(index_name)} = {index_name}")
    
    # Handle index_name parsing - it might be a string representation of a dictionary
    if not isinstance(index_name, str):
        print(f"ERROR: index_name is not a string! Type: {type(index_name)}, Value: {index_name}")
        return
    
    # Check if index_name looks like a dictionary string and try to parse it
    if index_name.startswith('{') or 'server_compliance_metrics_index' in index_name:
        print(f"Index name appears to contain dictionary data: {index_name}")
        
        # Try to extract the actual index name from common patterns
        import re
        
        # Clean up the string first - remove backslashes and quotes
        cleaned_string = index_name.replace('\\', '').replace('"', '').replace("'", "")
        print(f"Cleaned string: {cleaned_string}")
        
        # Look for patterns like "server_compliance_metrics_index: some-index-name" or similar
        patterns = [
            r'server_compliance_metrics_index[:\s]*([a-zA-Z0-9_.-]+)',
            r'atu0-server-compliance-metrics',
            r'[a-z0-9]+-server-compliance-[a-z0-9]+'
        ]
        
        extracted_name = None
        for pattern in patterns:
            match = re.search(pattern, cleaned_string, re.IGNORECASE)
            if match:
                if match.groups():
                    extracted_name = match.group(1).strip().rstrip(',').rstrip('}')
                else:
                    extracted_name = match.group(0).strip().rstrip(',').rstrip('}')
                print(f"Extracted index name using pattern '{pattern}': {extracted_name}")
                break
        
        if extracted_name:
            index_name = extracted_name
        else:
            # Last resort - try to find any valid index-like string
            potential_indices = re.findall(r'[a-z][a-z0-9_.-]*', cleaned_string.lower())
            valid_indices = [idx for idx in potential_indices if len(idx) > 5 and ('compliance' in idx or 'server' in idx)]
            
            if valid_indices:
                index_name = valid_indices[0]
                print(f"Using potential index name: {index_name}")
            else:
                print("Cannot extract a valid index name from the provided string.")
                print("Please check your Ansible playbook variable expansion.")
                print(f"Available potential matches: {potential_indices}")
                return
    
    # Additional safety check - ensure it's still a string after extraction
    if not isinstance(index_name, str):
        print(f"ERROR: After extraction attempt, index_name is still not a string! Type: {type(index_name)}")
        return
    
    index_name = index_name.lower()  # Elasticsearch indices must be lowercase
    print(f"Final index name: {index_name}")
    print(f"CHECKPOINT 1 - index_name type: {type(index_name)}, value: {index_name}")
    
    # Validate index name according to Elasticsearch rules
    if not re.match(r'^[a-z0-9][a-z0-9_.-]*$', index_name):
        print(f"ERROR: Invalid index name '{index_name}'. Index names must start with a lowercase letter or number and contain only lowercase letters, numbers, hyphens, underscores, and dots.")
        return
    
    if len(index_name) > 255 or len(index_name) == 0:
        print(f"ERROR: Index name length must be between 1 and 255 characters. Current length: {len(index_name)}")
        return
        
    # Store the validated index name to prevent accidental overwriting
    VALIDATED_INDEX_NAME = str(index_name)  # Ensure it's always a string
    
    def get_safe_index_name():
        """Return the validated index name, ensuring it's always a string"""
        return VALIDATED_INDEX_NAME
    
    print(f"Processing JSON file: {json_file_path}")
    
    # Single JSON file read and processing
    try:
        with open(json_file_path, "r") as infile:
            data = json.load(infile)
            
        print(f"CHECKPOINT 2 - index_name type: {type(index_name)}, value: {index_name}")
            
        if not data:
            print("Error: JSON file is empty or contains no data.")
            return
            
        print(f"Loaded {len(data)} records from JSON file")
        print(f"CHECKPOINT 3 - index_name type: {type(index_name)}, value: {index_name}")
        
        # Debug: Show first few records of raw data
        print("\n=== DEBUGGING RAW DATA ===")
        print(f"Type of data: {type(data)}")
        if isinstance(data, list) and len(data) > 0:
            print(f"First record structure: {data[0]}")
            print(f"Keys in first record: {list(data[0].keys()) if isinstance(data[0], dict) else 'Not a dict'}")
        elif isinstance(data, dict):
            print(f"Data is a dictionary with keys: {list(data.keys())}")
        else:
            print(f"Unexpected data type: {type(data)}")
        
        # Process data through all transformation steps
        print("\nStep 1: Transforming roles...")
        try:
            transformed_data = transform_roles(data)
            print(f"After transform_roles: {len(transformed_data)} records")
            if transformed_data and len(transformed_data) > 0:
                print(f"Sample transformed record: {transformed_data[0]}")
        except Exception as e:
            print(f"Error in transform_roles: {e}")
            return
        
        print(f"CHECKPOINT 4 - index_name type: {type(index_name)}, value: {index_name}")
        
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
            print(f"After format_roles: {len(formatted_data)} records")
        except Exception as e:
            print(f"Error in format_roles step: {e}")
            return
            
        print(f"CHECKPOINT 5 - index_name type: {type(index_name)}, value: {index_name}")
            
        print("Step 3: Converting roles to objects...")
        try:
            final_data = transform_roles_obj(formatted_data)
            print(f"After transform_roles_obj: {len(final_data)} records")
        except Exception as e:
            print(f"Error in transform_roles_obj: {e}")
            return
        
        print(f"CHECKPOINT 6 - index_name type: {type(index_name)}, value: {index_name}")
        
        print("Step 4: Formatting fields for Elasticsearch...")
        try:
            final_data = format_fields_for_elasticsearch(final_data)
            print(f"After format_fields_for_elasticsearch: {len(final_data)} records")
        except Exception as e:
            print(f"Error in format_fields_for_elasticsearch: {e}")
            return
        
        print(f"CHECKPOINT 7 - index_name type: {type(index_name)}, value: {index_name}")
        
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
        print(f"Data transformation completed successfully. Final records: {len(final_data)}")
        
        # Debug: Show final data structure
        if final_data and len(final_data) > 0:
            print(f"Sample final record: {final_data[0]}")
            print(f"Final record keys: {list(final_data[0].keys()) if isinstance(final_data[0], dict) else 'Not a dict'}")
        else:
            print("WARNING: No data to index! All records may have been filtered out.")
            return
        
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
        
        # Get Elasticsearch info for troubleshooting
        try:
            es_info = es.info()
            print(f"Elasticsearch server version: {es_info.get('version', {}).get('number', 'unknown')}")
            print(f"Cluster name: {es_info.get('cluster_name', 'unknown')}")
        except Exception as e:
            print(f"Could not retrieve Elasticsearch server info: {e}")
            
        # Show client version
        try:
            import elasticsearch
            print(f"Elasticsearch client version: {elasticsearch.__version__}")
        except Exception as e:
            print(f"Could not retrieve Elasticsearch client version: {e}")
        
    except Exception as e:
        print(f"Error connecting to Elasticsearch: {e}")
        return
    
    # Ensure index exists with proper settings
    index_settings = None  # Initialize to avoid undefined variable in error handling
    try:
        safe_index_name = get_safe_index_name()
        print(f"Checking if index '{safe_index_name}' exists...")
        index_exists = es.indices.exists(index=safe_index_name)
        print(f"Index exists check result: {index_exists}")
        
        if not index_exists:
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
            
            # Try newer API first, fall back to older API
            try:
                # Newer elasticsearch client (8.x+)
                es.indices.create(index=safe_index_name, **index_settings)
                print(f"Index '{safe_index_name}' created with settings (new API).")
            except TypeError:
                # Older elasticsearch client (7.x and below)
                es.indices.create(index=safe_index_name, body=index_settings)
                print(f"Index '{safe_index_name}' created with settings (legacy API).")
            except BadRequestError as mapping_error:
                print(f"Complex mapping failed, trying simpler approach: {mapping_error}")
                # Try creating with just basic settings, no complex mapping
                simple_settings = {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 1
                    }
                }
                try:
                    es.indices.create(index=safe_index_name, **simple_settings)
                    print(f"Index '{safe_index_name}' created with simple settings (new API).")
                except TypeError:
                    es.indices.create(index=safe_index_name, body=simple_settings)
                    print(f"Index '{safe_index_name}' created with simple settings (legacy API).")
        else:
            print(f"Using existing index '{safe_index_name}'")
    except BadRequestError as e:
        print(f"Error creating/checking index (Bad Request): {e}")
        print(f"Error details: {e.info if hasattr(e, 'info') else 'No additional info'}")
        print(f"Index name (type: {type(index_name)}): {index_name}")
        if index_settings:
            print(f"Index settings: {index_settings}")
        else:
            print("Index settings: Not defined (index may already exist)")
        return
    except Exception as e:
        print(f"Error creating/checking index: {e}")
        print(f"Error type: {type(e).__name__}")
        print(f"Index name (type: {type(index_name)}): {index_name}")
        return
        
    # Process documents for Elasticsearch
    print(f"Starting Elasticsearch updates for {len(final_data)} records...")
    print(f"Target index: {get_safe_index_name()}")
    indexing_timestamp = datetime.now().isoformat()
    
    success_count = 0
    error_count = 0
    
    # First, let's check what's currently in the index
    try:
        total_docs_query = {"query": {"match_all": {}}}
        try:
            count_response = es.count(index=get_safe_index_name(), body=total_docs_query)
        except TypeError:
            count_response = es.count(index=get_safe_index_name(), **total_docs_query)
        
        total_docs = count_response.get('count', 0)
        print(f"Current documents in index: {total_docs}")
        
        # Show a sample of existing documents with appCode
        if total_docs > 0:
            sample_query = {
                "query": {"exists": {"field": "appCode"}},
                "size": 3,
                "_source": ["appCode", "name", "affectedItemName", "documentType"]
            }
            try:
                sample_response = es.search(index=get_safe_index_name(), body=sample_query)
            except TypeError:
                sample_response = es.search(index=get_safe_index_name(), **sample_query)
            
            sample_docs = sample_response.get('hits', {}).get('hits', [])
            print(f"Sample existing documents with appCode:")
            for doc in sample_docs:
                source = doc.get('_source', {})
                print(f"  - ID: {doc.get('_id')}, appCode: {source.get('appCode')}, name: {source.get('name', 'N/A')}, type: {source.get('documentType', 'compliance')}")
    except Exception as e:
        print(f"Could not check existing documents: {e}")
        print("Proceeding with updates anyway...")
    
    for i, appcode_detail in enumerate(final_data):
        print(f"Processing record {i+1}/{len(final_data)}: {appcode_detail.get('appCode', 'NO_APPCODE')}")
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
            
            # Search for existing compliance records with this appCode
            # Use a simpler, more reliable query that focuses on the _source appCode field
            search_query = {
                "query": {
                    "bool": {
                        "should": [
                            # Primary search in _source.appCode using exact match
                            {"term": {"appCode.keyword": appCode}},
                            {"term": {"appCode": appCode}},
                            # Also exclude documents that are just application metadata
                            {"bool": {
                                "must": [
                                    {"term": {"appCode.keyword": appCode}},
                                    {"bool": {
                                        "must_not": [
                                            {"term": {"documentType.keyword": "application_metadata"}}
                                        ]
                                    }}
                                ]
                            }}
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
            
            # Debug: Print the search query being used
            print(f"Debug: Searching for appCode '{appCode}' with query: {json.dumps(search_query, indent=2)}")
            
            try:
                # Try newer API first
                search_response = es.search(index=get_safe_index_name(), body=search_query, size=1000)
            except TypeError:
                # Fall back if body parameter doesn't work
                search_response = es.search(index=get_safe_index_name(), **search_query, size=1000)
            
            # Debug: Print search response details
            total_hits = search_response.get('hits', {}).get('total', {})
            if isinstance(total_hits, dict):
                total_count = total_hits.get('value', 0)
            else:
                total_count = total_hits  # For older ES versions
            
            print(f"Debug: Search returned {total_count} total hits")
            
            existing_records = search_response.get('hits', {}).get('hits', [])
            
            if existing_records:
                print(f"Found {len(existing_records)} existing records for appCode {appCode}")
                # Debug: Show the first record structure
                if len(existing_records) > 0:
                    first_record = existing_records[0]
                    print(f"Debug: First record ID: {first_record.get('_id')}")
                    print(f"Debug: First record source appCode: {first_record.get('_source', {}).get('appCode')}")
                    if 'fields' in first_record:
                        print(f"Debug: First record fields.appCode: {first_record.get('fields', {}).get('appCode')}")
            else:
                print(f"No existing compliance records found for appCode {appCode}")
                # Debug: Let's try a simple match_all query to see what records exist
                debug_query = {"query": {"match_all": {}}}
                try:
                    debug_response = es.search(index=get_safe_index_name(), body=debug_query, size=5)
                    debug_records = debug_response.get('hits', {}).get('hits', [])
                    print(f"Debug: Found {len(debug_records)} total records in index")
                    if debug_records:
                        sample_record = debug_records[0]
                        print(f"Debug: Sample record structure:")
                        print(f"  - _source keys: {list(sample_record.get('_source', {}).keys())}")
                        print(f"  - fields keys: {list(sample_record.get('fields', {}).keys()) if 'fields' in sample_record else 'No fields'}")
                        print(f"  - Sample appCode in _source: {sample_record.get('_source', {}).get('appCode')}")
                        if 'fields' in sample_record:
                            print(f"  - Sample appCode in fields: {sample_record.get('fields', {}).get('appCode')}")
                except Exception as debug_error:
                    print(f"Debug query failed: {debug_error}")
            
            if existing_records:
                # Update all existing compliance records for this appCode
                updated_count = 0
                for record in existing_records:
                    record_id = record['_id']
                    
                    # Get the existing source document
                    existing_source = record.get('_source', {})
                    
                    # Merge new application data into existing source
                    updated_source = existing_source.copy()
                    
                    # Add/update application metadata in _source
                    updated_source.update({
                        "name": appcode_detail.get("name"),
                        "lineOfBusiness": appcode_detail.get("lineOfBusiness"),
                        "contactPerson": appcode_detail.get("contactPerson"),
                        "contactType": appcode_detail.get("contactType"),
                        "contactMechanism": appcode_detail.get("contactMechanism"),
                        "roles": appcode_detail.get("roles", {}),
                        "timestamp": indexing_timestamp  # Update timestamp
                    })
                    
                    # Remove any None values
                    updated_source = {k: v for k, v in updated_source.items() if v is not None}
                    
                    try:
                        # Update the entire document source
                        try:
                            response = es.update(
                                index=get_safe_index_name(),
                                id=record_id,
                                doc=updated_source
                            )
                        except TypeError:
                            response = es.update(
                                index=get_safe_index_name(),
                                id=record_id,
                                body={"doc": updated_source}
                            )
                        
                        updated_count += 1
                        print(f"SUCCESS: Updated compliance record {record_id} for appCode {appCode}")
                        
                    except Exception as update_error:
                        print(f"ERROR: Error updating compliance record {record_id}: {update_error}")
                        error_count += 1
                        continue
                
                if updated_count > 0:
                    print(f"SUCCESS: Updated {updated_count} compliance records for appCode {appCode}")
                    success_count += updated_count
                else:
                    print(f"WARNING: No compliance records were updated for appCode {appCode}")
            else:
                # No existing records found - create a new document with the application data
                print(f"Creating new document for appCode {appCode} since no existing compliance records found")
                
                # Create a new document with application metadata
                new_document = {
                    "appCode": appCode,
                    "name": appcode_detail.get("name"),
                    "lineOfBusiness": appcode_detail.get("lineOfBusiness"),
                    "contactPerson": appcode_detail.get("contactPerson"),
                    "contactType": appcode_detail.get("contactType"),
                    "contactMechanism": appcode_detail.get("contactMechanism"),
                    "roles": appcode_detail.get("roles", {}),
                    "timestamp": indexing_timestamp,
                    "documentType": "application_metadata"  # To distinguish from compliance records
                }
                
                # Remove any None values
                new_document = {k: v for k, v in new_document.items() if v is not None}
                
                try:
                    # Index the new document
                    try:
                        response = es.index(
                            index=get_safe_index_name(),
                            document=new_document
                        )
                    except TypeError:
                        response = es.index(
                            index=get_safe_index_name(),
                            body=new_document
                        )
                    
                    print(f"SUCCESS: Created new document for appCode {appCode} with ID: {response.get('_id')}")
                    success_count += 1
                    
                except Exception as create_error:
                    print(f"ERROR: Error creating new document for appCode {appCode}: {create_error}")
                    error_count += 1
                
        except Exception as e:
            print(f"ERROR: Error processing document {appCode}: {e}")
            print(f"   Document structure: {appcode_detail}")
            error_count += 1
            
    # Summary
    print(f"\n=== Update Summary ===")
    print(f"Successfully processed: {success_count}")
    print(f"Errors encountered: {error_count}")
    print(f"Total records: {len(final_data)}")
    
    if error_count == 0:
        print("SUCCESS: All updates completed successfully!")
    else:
        print(f"WARNING: Completed with {error_count} errors")

if __name__ == '__main__':
    main(sys.argv[1:]) 
