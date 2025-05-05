import json
import logging
import csv
from collections import defaultdict
import os
import argparse
import string

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_arguments():
    parser = argparse.ArgumentParser(description='Process data from JSON files and generate CSV and email content')
    parser.add_argument('--input-dir', required=True, help='Directory containing input JSON files')
    parser.add_argument('--output-dir', required=True, help='Directory to save output CSV and email content')
    return parser.parse_args()

def load_results_from_json(input_dir):
    results = {}
    for key in ["p1_p2_vulnerabilities", "cryptography_tss_opendata", "trends"]:
        try:
            with open(os.path.join(input_dir, f'{key}.json'), 'r') as f:
                results[key] = json.load(f)
                logging.info(f"Loaded data from {key}.json")
        except FileNotFoundError:
            logging.error(f"File not found: {key}.json")
    return results

def process_data(results):
    processed_data = defaultdict(lambda: defaultdict(list))
    for key, data in results.items():
        if key == "p1_p2_vulnerabilities":
            for bucket in data.get('aggregations', {}).get('by_appCode', {}).get('buckets', []):
                app_code = bucket['key']
                for item_type in bucket.get('by_affectedItemType', {}).get('buckets', []):
                    item_type_key = item_type['key']
                    for time_bucket in item_type.get('by_time', {}).get('buckets', []):
                        date = time_bucket['key_as_string']
                        unique_issues = time_bucket.get('unique_issues', {}).get('value', 0)
                        for issue in time_bucket.get('p2_count', {}).get('issue_names', {}).get('buckets', []):
                            processed_data[app_code][item_type_key].append({
                                'date': date,
                                'unique_issues': unique_issues,
                                'issue_name': issue['key']
                            })
        elif key == "cryptography_tss_opendata":
            for bucket in data.get('aggregations', {}).get('by_appCode', {}).get('buckets', []):
                app_code = bucket['key']
                for issue_type in bucket.get('by_issueType', {}).get('buckets', []):
                    issue_type_key = issue_type['key']
                    for time_bucket in issue_type.get('by_time', {}).get('buckets', []):
                        date = time_bucket['key_as_string']
                        unique_issues = time_bucket.get('unique_issues', {}).get('value', 0)
                        processed_data[app_code][issue_type_key].append({
                            'date': date,
                            'unique_issues': unique_issues
                        })
        elif key == "trends":
            for interval in data.get('aggregations', {}).get('by_interval', {}).get('buckets', []):
                date = interval['key_as_string']
                for app_code_bucket in interval.get('by_appCode', {}).get('buckets', []):
                    app_code = app_code_bucket['key']
                    for item_type in app_code_bucket.get('by_affectedItemType', {}).get('buckets', []):
                        item_type_key = item_type['key']
                        unique_issues = item_type.get('unique_issues', {}).get('value', 0)
                        processed_data[app_code][item_type_key].append({
                            'date': date,
                            'unique_issues': unique_issues
                        })
    return processed_data

def save_to_csv(processed_data, output_dir):
    for app_code, data in processed_data.items():
        for item_type, records in data.items():
            if not records:  # Skip if no records
                continue
            csv_file = os.path.join(output_dir, f'{app_code}_{item_type}.csv')
            with open(csv_file, 'w', newline='') as csvfile:
                fieldnames = ['date', 'unique_issues']
                if records and 'issue_name' in records[0]:
                    fieldnames.append('issue_name')
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for record in records:
                    writer.writerow(record)
            logging.info(f"Saved CSV file: {csv_file}")

def generate_email_content(processed_data, output_dir):
    email_content = {}
    
    # Try to load the email template
    template_path = os.path.join(output_dir, 'email_template.txt')
    template = ""
    try:
        with open(template_path, 'r') as f:
            template = f.read()
    except FileNotFoundError:
        logging.warning(f"Email template not found at {template_path}. Using default format.")
    
    for app_code, data in processed_data.items():
        if template:
            # Prepare template variables
            vulnerability_list = ""
            vulnerability_count = 0
            crypto_count = 0
            tss_count = 0
            opendata_count = 0
            
            # Count vulnerabilities and build the list
            for item_type, records in data.items():
                if "Vulnerabilities" in item_type:
                    vulnerability_count += len(records)
                    for record in records:
                        if 'issue_name' in record:
                            vulnerability_list += f"P2      | {record['issue_name']}\n"
                elif "Cryptography" in item_type:
                    crypto_count += len(records)
                elif "TSS" in item_type:
                    tss_count += len(records)
                elif "Open Data" in item_type:
                    opendata_count += len(records)
            
            # Fill the template
            email_body = template.format(
                app_code=app_code,
                vulnerability_count=vulnerability_count,
                vulnerability_list=vulnerability_list,
                crypto_count=crypto_count,
                tss_count=tss_count,
                opendata_count=opendata_count,
                contact_email="feyi.sodipo@rbc.com"
            )
        else:
            # Use the original format if no template
            email_body = f"Dear Team,\n\nPlease find below the latest IT risk metrics Overview for app code: {app_code}.\n\n"
            for item_type, records in data.items():
                email_body += f"==========================\n{item_type} - [{len(records)}]\n==========================\n"
                if item_type == "Windows Server Vulnerabilities":
                    email_body += "Priority | Issue Name\n-----------------------------\n"
                    for record in records:
                        email_body += f"P2      | {record.get('issue_name', 'Unknown')}\n"
                else:
                    email_body += f"{item_type} Issues - [Count]: {len(records)}\n"
                email_body += "\n"
            email_body += "Best regards,\nATU0 Compliance Team\nSecurity Engineering\nfeyi.sodipo@rbc.com\n"
        
        email_content[app_code] = email_body
        email_file = os.path.join(output_dir, f'{app_code}_email.txt')
        with open(email_file, 'w') as f:
            f.write(email_body)
        logging.info(f"Saved email content file: {email_file}")
    
    return email_content

def main():
    args = parse_arguments()
    
    # Ensure input and output directories exist
    if not os.path.exists(args.input_dir):
        logging.error(f"Input directory does not exist: {args.input_dir}")
        return
    
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
        logging.info(f"Created output directory: {args.output_dir}")
    
    # Create sample data if no JSON files exist (for testing)
    json_files = [f for f in os.listdir(args.input_dir) if f.endswith('.json')]
    if not json_files:
        logging.warning("No JSON files found. Creating sample data for testing.")
        create_sample_data(args.input_dir)
    
    results = load_results_from_json(args.input_dir)
    processed_data = process_data(results)
    
    if not processed_data:
        logging.warning("No data processed. Creating sample processed data for testing.")
        processed_data = create_sample_processed_data()
    
    save_to_csv(processed_data, args.output_dir)
    generate_email_content(processed_data, args.output_dir)
    logging.info("Data processing and email generation complete")

def create_sample_data(output_dir):
    """Create sample data files for testing when real data is unavailable"""
    sample_data = {
        "p1_p2_vulnerabilities": {
            "aggregations": {
                "by_appCode": {
                    "buckets": [
                        {
                            "key": "ATU0",
                            "by_affectedItemType": {
                                "buckets": [
                                    {
                                        "key": "Windows Server Vulnerabilities",
                                        "by_time": {
                                            "buckets": [
                                                {
                                                    "key_as_string": "2025-02-21",
                                                    "unique_issues": {"value": 5},
                                                    "p2_count": {
                                                        "issue_names": {
                                                            "buckets": [
                                                                {"key": "CVE-2023-12345"},
                                                                {"key": "CVE-2023-23456"},
                                                                {"key": "CVE-2023-34567"},
                                                                {"key": "CVE-2023-45678"},
                                                                {"key": "CVE-2023-56789"}
                                                            ]
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        },
        "cryptography_tss_opendata": {
            "aggregations": {
                "by_appCode": {
                    "buckets": [
                        {
                            "key": "ATU0",
                            "by_issueType": {
                                "buckets": [
                                    {
                                        "key": "Cryptography",
                                        "by_time": {
                                            "buckets": [
                                                {
                                                    "key_as_string": "2025-02-21",
                                                    "unique_issues": {"value": 3}
                                                }
                                            ]
                                        }
                                    },
                                    {
                                        "key": "TSS",
                                        "by_time": {
                                            "buckets": [
                                                {
                                                    "key_as_string": "2025-02-21",
                                                    "unique_issues": {"value": 2}
                                                }
                                            ]
                                        }
                                    },
                                    {
                                        "key": "Open Data",
                                        "by_time": {
                                            "buckets": [
                                                {
                                                    "key_as_string": "2025-02-21",
                                                    "unique_issues": {"value": 1}
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        },
        "trends": {
            "aggregations": {
                "by_interval": {
                    "buckets": [
                        {
                            "key_as_string": "2025-02-21",
                            "by_appCode": {
                                "buckets": [
                                    {
                                        "key": "ATU0",
                                        "by_affectedItemType": {
                                            "buckets": [
                                                {
                                                    "key": "Windows Server Vulnerabilities",
                                                    "unique_issues": {"value": 5}
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        }
    }
    
    for key, data in sample_data.items():
        with open(os.path.join(output_dir, f"{key}.json"), "w") as f:
            json.dump(data, f)
        logging.info(f"Created sample data file: {key}.json")

def create_sample_processed_data():
    """Create sample processed data for testing"""
    return {
        "ATU0": {
            "Windows Server Vulnerabilities": [
                {"date": "2025-02-21", "unique_issues": 5, "issue_name": "CVE-2023-12345"},
                {"date": "2025-02-21", "unique_issues": 5, "issue_name": "CVE-2023-23456"},
                {"date": "2025-02-21", "unique_issues": 5, "issue_name": "CVE-2023-34567"},
                {"date": "2025-02-21", "unique_issues": 5, "issue_name": "CVE-2023-45678"},
                {"date": "2025-02-21", "unique_issues": 5, "issue_name": "CVE-2023-56789"}
            ],
            "Cryptography": [
                {"date": "2025-02-21", "unique_issues": 3}
            ],
            "TSS": [
                {"date": "2025-02-21", "unique_issues": 2}
            ],
            "Open Data": [
                {"date": "2025-02-21", "unique_issues": 1}
            ]
        }
    }

if __name__ == "__main__":
    main() 