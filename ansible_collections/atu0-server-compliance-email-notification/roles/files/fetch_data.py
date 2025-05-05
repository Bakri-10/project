import json
import logging
import os
import http.client
import urllib.parse
import base64
import argparse
from requests.auth import HTTPBasicAuth
from elasticsearch import Elasticsearch
import sys

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
                            {"range": {"timestamp": {"gte": "2025-02-21T00:00:00", "lte": "2025-02-21T23:59:59"}}}
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
                            {"range": {"timestamp": {"gte": "2025-02-21T00:00:00", "lte": "2025-02-21T23:59:59"}}}
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
                            {"range": {"timestamp": {"gte": "2025-02-21T00:00:00", "lte": "2025-02-21T23:59:59"}}}
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
            logging.error(f"Error fetching data for {key}: {e}")
    
    return results

def save_results_to_json(results):
    for key, result in results.items():
        with open(f'{key}.json', 'w') as f:
            json.dump(result, f)
        logging.info(f"Saved JSON file: {key}.json")

def main(argv):
    args = parse_arguments()
    es_url = args.es_url
    es_service_id = args.es_service_id
    es_password = args.es_password
    index_name = args.index_name
    app_codes = args.app_codes
    
    es = Elasticsearch(
        [es_url],
        http_auth=HTTPBasicAuth(es_service_id, es_password),
        node_class='requests'
    )
    
    logging.info("Fetching data from Elasticsearch")
    results = fetch_data(es, index_name, app_codes)
    logging.info("Saving results to JSON files")
    save_results_to_json(results)
    logging.info("Data fetching complete")

if __name__ == "__main__":
    main(sys.argv[1:]) 