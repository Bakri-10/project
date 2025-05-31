#!/usr/bin/env python3

from elasticsearch import Elasticsearch
import json
import sys
import math
import datetime

def get_existing_data(es, target_index):
    """Fetch existing data from target Elasticsearch index."""
    try:
        query = {
            "_source": True,  # Get all fields
            "query": {
                "match_all": {}
            }
        }
        
        response = es.search(index=target_index, body=query, size=10000)
        existing_data = {}
        
        for hit in response['hits']['hits']:
            source = hit['_source']
            appcode = source.get("appCode")
            if appcode:
                existing_data[appcode] = {
                    "_id": hit['_id'],
                    "data": source  # Store all existing fields
                }
        return existing_data
    except Exception as e:
        print(f"Error fetching existing data: {e}")
        return {}

def fetch_iipm_data(es, iipm_index_name):
    """Fetch data from the IIPM index and create a lookup dictionary."""
    try:
        # Query to fetch all appcodes and contact information
        query = {
            "_source": [
                "appCode",
                "contactMail",  # Add contact mail field
                "roles.IT_CUSTODIAN.id",
                "roles.IT_EXECUTIVE.id",
                "roles.GROUP_MANAGER.id"
            ],
            "query": {
                "exists": {
                    "field": "appCode"
                }
            }
        }
        
        response = es.search(index=iipm_index_name, body=query, size=10000)
        
        if not response['hits']['hits']:
            print(f"No data found in the IIPM index: {iipm_index_name}")
            return {}
            
        lookup = {}
        
        for hit in response['hits']['hits']:
            source = hit['_source']
            appcode = source.get("appCode")
            
            if appcode:
                lookup[appcode] = {
                    "contactMail": source.get("contactMail"),
                    "appCustodianId": source.get("roles", {}).get("IT_CUSTODIAN", {}).get("id"),
                    "l4_id": source.get("roles", {}).get("IT_EXECUTIVE", {}).get("id"),
                    "l5_id": source.get("roles", {}).get("GROUP_MANAGER", {}).get("id")
                }
        
        return lookup
        
    except Exception as e:
        print(f"Error fetching IIPM data: {e}")
        return {}

def clean_data(item):
    """Clean invalid fields in the item."""
    for key, value in item.items():
        # Check for NaN as a float
        if isinstance(value, float) and math.isnan(value):
            item[key] = None
    return item

def compare_and_update(es, target_index, iipm_data, existing_data):
    """Compare IIPM data with existing data and update differences."""
    updates = {
        'new': [],
        'modified': [],
        'unchanged': []
    }
    
    for appcode, iipm_item in iipm_data.items():
        clean_iipm_item = clean_data(iipm_item.copy())
        
        if appcode not in existing_data:
            # For new records, we need minimum required fields
            new_record = {
                "appCode": appcode,
                "contactMail": clean_iipm_item.get("contactMail"),
                "appCustodianId": clean_iipm_item.get("appCustodianId"),
                "l4_id": clean_iipm_item.get("l4_id"),
                "l5_id": clean_iipm_item.get("l5_id")
            }
            updates['new'].append(appcode)
            es.index(index=target_index, body=new_record)
        else:
            existing = existing_data[appcode]['data']
            # Merge IIPM data with existing data
            merged_data = existing.copy()
            merged_data.update(clean_iipm_item)
            
            # Check if any IIPM fields are different
            if any(clean_iipm_item[k] != existing.get(k) for k in clean_iipm_item.keys()):
                updates['modified'].append(appcode)
                es.update(
                    index=target_index,
                    id=existing_data[appcode]['_id'],
                    body={'doc': clean_iipm_item}
                )
            else:
                updates['unchanged'].append(appcode)
    
    return updates

def main():
    if len(sys.argv) != 5:
        print("Usage: fetch_iipm_data.py <elasticsearch_host> <iipm_index_name> <target_index_name> <output_file>")
        sys.exit(1)
    
    es_host = sys.argv[1]
    iipm_index = sys.argv[2]
    target_index = sys.argv[3]
    output_file = sys.argv[4]
    
    try:
        es = Elasticsearch([es_host])
        
        # Fetch existing data from target index
        print("Fetching existing data from target index...")
        existing_data = get_existing_data(es, target_index)
        
        # Fetch new data from IIPM
        print("Fetching data from IIPM...")
        iipm_data = fetch_iipm_data(es, iipm_index)
        
        # Compare and update
        print("Comparing and updating records...")
        updates = compare_and_update(es, target_index, iipm_data, existing_data)
        
        # Write update summary to output file
        summary = {
            'timestamp': str(datetime.datetime.now()),
            'updates': updates,
            'stats': {
                'new_records': len(updates['new']),
                'modified_records': len(updates['modified']),
                'unchanged_records': len(updates['unchanged']),
                'total_records_processed': len(iipm_data)
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
            
        print(f"Update complete. New records: {len(updates['new'])}, Modified: {len(updates['modified'])}, Unchanged: {len(updates['unchanged'])}")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 