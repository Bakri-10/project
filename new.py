from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan, bulk
import os

# Load environment variables
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER")
ES_PASS = os.getenv("ES_PASS")

# Index names
IIPM_INDEX = "iipm_index"
NPID_INDEX = "npid_index"
HYGIENE_INDEX = "server_hygiene_index"

# Connect to ES
es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS))

# Track updates
updates = []

# Scan through all IIPM records
for doc in scan(es, index=IIPM_INDEX):
    source = doc['_source']
    server_name = source.get('server_name')

    if not server_name:
        continue

    # Match NPID record
    npid_res = es.search(index=NPID_INDEX, query={"match": {"server_name": server_name}})
    if npid_res['hits']['hits']:
        npid_doc = npid_res['hits']['hits'][0]
        npid_source = npid_doc['_source']
        update_fields = {}

        for field in ["custodian", "contact_type", "contact_method"]:
            iipm_val = source.get(field)
            npid_val = npid_source.get(field)
            if iipm_val and iipm_val != npid_val:
                update_fields[field] = iipm_val

        if update_fields:
            updates.append({
                "_op_type": "update",
                "_index": NPID_INDEX,
                "_id": npid_doc["_id"],
                "doc": update_fields
            })

    # Match Hygiene record for flagging
    hygiene_res = es.search(index=HYGIENE_INDEX, query={"match": {"server_name": server_name}})
    if hygiene_res['hits']['hits']:
        hygiene_doc = hygiene_res['hits']['hits'][0]
        hygiene_source = hygiene_doc['_source']
        hygiene_status = hygiene_source.get("status", "").lower()

        if hygiene_status == "non-compliant":
            updates.append({
                "_op_type": "update",
                "_index": HYGIENE_INDEX,
                "_id": hygiene_doc["_id"],
                "doc": {"needs_attention": True}
            })

# Execute bulk updates
if updates:
    bulk(es, updates)
    print(f"Updated {len(updates)} documents.")
else:
    print("No updates necessary.")
