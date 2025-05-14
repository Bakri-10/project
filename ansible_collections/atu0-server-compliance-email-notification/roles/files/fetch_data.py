import json
import logging
import os
import urllib.parse
import base64
import argparse
from elasticsearch import Elasticsearch
import ssl
import sys
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_arguments():
    parser = argparse.ArgumentParser(description='Fetch data from Elasticsearch and save to JSON files')
    parser.add_argument('--es-url', required=True, help='Elasticsearch URL')
    parser.add_argument('--es-service-id', required=True, help='Elasticsearch service id')
    parser.add_argument('--es-password', required=True, help='Elasticsearch service id password')
    parser.add_argument('--index-name', required=True, help='Elasticsearch index name')
    parser.add_argument('--app-codes', required=True, nargs='+', help='List of application codes')
    return parser.parse_args()

def fetch_data(es, index_name, app_codes):
    # Calculate date range (today)
    today = datetime.now()
    start_date = today.replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%S")
    end_date = today.replace(hour=23, minute=59, second=59, microsecond=999999).strftime("%Y-%m-%dT%H:%M:%S")
    
    logging.info(f"Using date range: {start_date} to {end_date}")
    
    results = {}
    queries = {
        "p1_p2_vulnerabilities": {
            "index": index_name,
            "body": {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"issueType.keyword": "Vulnerability"}},
                            {"terms": {"appCode.keyword": app_codes}},
                            {"range": {"timestamp": {"gte": start_date, "lte": end_date}}}
                        ],
                        "must_not": [
                            {"term": {"priority.keyword": "P3"}},
                            {"term": {"dataSource.keyword": "Nexus IQ"}}
                        ]
                    }
                },
                "aggs": {
                    "by_appCode": {
                        "terms": {"field": "appCode.keyword", "size": len(app_codes)},
                        "aggs": {
                            "by_affectedItemType": {
                                "terms": {"field": "affectedItemType.keyword", "size": 10},
                                "aggs": {
                                    "by_time": {
                                        "date_histogram": {
                                            "field": "timestamp",
                                            "calendar_interval": "1d"
                                        },
                                        "aggs": {
                                            "unique_issues": {
                                                "cardinality": {"field": "issueName.keyword"}
                                            },
                                            "p1_count": {
                                                "filter": {"term": {"priority.keyword": "P1"}},
                                                "aggs": {
                                                    "issue_names": {
                                                        "terms": {"field": "issueName.keyword", "size": 1000}
                                                    }
                                                }
                                            },
                                            "p2_count": {
                                                "filter": {"term": {"priority.keyword": "P2"}},
                                                "aggs": {
                                                    "issue_names": {
                                                        "terms": {"field": "issueName.keyword", "size": 1000}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "cryptography_tss_opendata": {
            "index": index_name,
            "body": {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"issueType.keyword": ["TSS", "Open Data", "Cryptography"]}},
                            {"terms": {"appCode.keyword": app_codes}},
                            {"range": {"timestamp": {"gte": start_date, "lte": end_date}}}
                        ]
                    }
                },
                "aggs": {
                    "by_appCode": {
                        "terms": {"field": "appCode.keyword", "size": len(app_codes)},
                        "aggs": {
                            "by_issueType": {
                                "terms": {"field": "issueType.keyword", "size": 10},
                                "aggs": {
                                    "by_time": {
                                        "date_histogram": {
                                            "field": "timestamp",
                                            "calendar_interval": "1d"
                                        },
                                        "aggs": {
                                            "unique_issues": {
                                                "cardinality": {"field": "issueName.keyword"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "trends": {
            "index": index_name,
            "body": {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"issueType.keyword": "Vulnerability"}},
                            {"terms": {"appCode.keyword": app_codes}},
                            {"range": {"timestamp": {"gte": start_date, "lte": end_date}}}
                        ],
                        "must_not": [
                            {"term": {"priority.keyword": "P3"}},
                            {"term": {"dataSource.keyword": "Nexus IQ"}}
                        ]
                    }
                },
                "aggs": {
                    "by_interval": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "6d",
                            "format": "yyyy-MM-dd"
                        },
                        "aggs": {
                            "by_appCode": {
                                "terms": {"field": "appCode.keyword", "size": len(app_codes)},
                                "aggs": {
                                    "by_affectedItemType": {
                                        "terms": {"field": "affectedItemType.keyword", "size": 10},
                                        "aggs": {
                                            "unique_issues": {
                                                "cardinality": {"field": "issueName.keyword"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    for key, query in queries.items():
        try:
            response = es.search(index=query['index'], body=query['body'])
            results[key] = response
        except Exception as e:
            logging.error(f"Error fetching data for {key}: {str(e)}")
            # Create an empty response structure to avoid processing errors
            results[key] = {"aggregations": {"by_appCode": {"buckets": []}}}
    
    return results

def save_results_to_json(results):
    # Create temp directory if it doesn't exist
    temp_dir = "temp"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
        
    for key, result in results.items():
        output_file = os.path.join(temp_dir, f'{key}.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False)
        logging.info(f"Saved JSON file: {output_file}")

def main(argv):
    args = parse_arguments()
    es_url = args.es_url
    es_service_id = args.es_service_id
    es_password = args.es_password
    index_name = args.index_name
    app_codes = args.app_codes
    
    # Log received parameters (excluding password)
    logging.info(f"Elasticsearch URL: {es_url}")
    logging.info(f"Index name: {index_name}")
    logging.info(f"App codes: {app_codes}")
    
    # Create Elasticsearch client with appropriate settings
    try:
        context = ssl.create_default_context()
        # For self-signed certificates, you might need this
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        es = Elasticsearch(
            hosts=[es_url],
            basic_auth=(es_service_id, es_password),
            ssl_context=context,
            verify_certs=False,
            timeout=30
        )
        
        # Verify connection
        if not es.ping():
            logging.error("Elasticsearch connection failed")
            sys.exit(1)
            
        logging.info("Connected to Elasticsearch successfully")
        logging.info("Fetching data from Elasticsearch")
        results = fetch_data(es, index_name, app_codes)
        logging.info("Saving results to JSON files")
        save_results_to_json(results)
        logging.info("Data fetching complete")
        
    except Exception as e:
        logging.error(f"Error connecting to Elasticsearch: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv[1:]) 