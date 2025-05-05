import json
import logging
import csv
from collections import defaultdict
import os
import argparse

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
            for bucket in data['aggregations']['by_appCode']['buckets']:
                app_code = bucket['key']
                for item_type in bucket['by_affectedItemType']['buckets']:
                    item_type_key = item_type['key']
                    for time_bucket in item_type['by_time']['buckets']:
                        date = time_bucket['key_as_string']
                        unique_issues = time_bucket['unique_issues']['value']
                        for issue in time_bucket['p2_count']['issue_names']['buckets']:
                            processed_data[app_code][item_type_key].append({
                                'date': date,
                                'unique_issues': unique_issues,
                                'issue_name': issue['key']
                            })
        elif key == "cryptography_tss_opendata":
            for bucket in data['aggregations']['by_appCode']['buckets']:
                app_code = bucket['key']
                for issue_type in bucket['by_issueType']['buckets']:
                    issue_type_key = issue_type['key']
                    for time_bucket in issue_type['by_time']['buckets']:
                        date = time_bucket['key_as_string']
                        unique_issues = time_bucket['unique_issues']['value']
                        processed_data[app_code][issue_type_key].append({
                            'date': date,
                            'unique_issues': unique_issues
                        })
        elif key == "trends":
            for interval in data['aggregations']['by_interval']['buckets']:
                date = interval['key_as_string']
                for app_code_bucket in interval['by_appCode']['buckets']:
                    app_code = app_code_bucket['key']
                    for item_type in app_code_bucket['by_affectedItemType']['buckets']:
                        item_type_key = item_type['key']
                        unique_issues = item_type['unique_issues']['value']
                        processed_data[app_code][item_type_key].append({
                            'date': date,
                            'unique_issues': unique_issues
                        })
    return processed_data

def save_to_csv(processed_data, output_dir):
    for app_code, data in processed_data.items():
        for item_type, records in data.items():
            csv_file = os.path.join(output_dir, f'{app_code}_{item_type}.csv')
            with open(csv_file, 'w', newline='') as csvfile:
                fieldnames = ['date', 'unique_issues']
                if 'issue_name' in records[0]:
                    fieldnames.append('issue_name')
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for record in records:
                    writer.writerow(record)
                logging.info(f"Saved CSV file: {csv_file}")

def generate_email_content(processed_data, output_dir):
    email_content = {}
    for app_code, data in processed_data.items():
        email_body = f"Dear Team,\n\nPlease find below the latest IT risk metrics Overview for app code: {app_code}\n\n"
        for item_type, records in data.items():
            email_body += f"==========================\n{item_type} - [{len(records)}]\n==========================\n"
            if item_type == "Windows Server Vulnerabilities":
                email_body += "Priority | Issue Name\n------------------------\n"
                for record in records:
                    email_body += f"P2      | {record['issue_name']}\n"
            else:
                email_body += f"{item_type} Issues - [Count]: {len(records)}\n"
            email_body += "\n"
        email_body += "Best regards,\n[Your Name]\n[Your Position]\n[Your Contact Information]\n"
        
        email_content[app_code] = email_body
        email_file = os.path.join(output_dir, f'{app_code}_email.txt')
        with open(email_file, 'w') as f:
            f.write(email_body)
        logging.info(f"Saved email content file: {email_file}")
    
    return email_content

def main():
    args = parse_arguments()
    results = load_results_from_json(args.input_dir)
    processed_data = process_data(results)
    save_to_csv(processed_data, args.output_dir)
    generate_email_content(processed_data, args.output_dir)

if __name__ == "__main__":
    main() 