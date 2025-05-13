import json
import logging
import csv
from collections import defaultdict
import os
import argparse
import sys

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_arguments():
    parser = argparse.ArgumentParser(description='Process data from JSON files and generate CSV and email content')
    parser.add_argument('--input-dir', required=True, help='Directory containing input JSON files')
    parser.add_argument('--output-dir', required=True, help='Directory to save output CSV and email content')
    return parser.parse_args()

def load_results_from_json(input_dir):
    results = {}
    temp_dir = os.path.join(input_dir, "temp")
    
    # Check if temp directory exists
    if not os.path.exists(temp_dir):
        logging.error(f"Temp directory not found: {temp_dir}")
        return results
        
    for key in ["p1_p2_vulnerabilities", "cryptography_tss_opendata", "trends"]:
        try:
            file_path = os.path.join(temp_dir, f'{key}.json')
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    results[key] = json.load(f)
                    logging.info(f"Loaded data from {file_path}")
            else:
                logging.warning(f"File not found: {file_path}")
                # Create empty structure to avoid processing errors
                results[key] = {"aggregations": {"by_appCode": {"buckets": []}}}
        except Exception as e:
            logging.error(f"Error loading {key}.json: {str(e)}")
            # Create empty structure to avoid processing errors
            results[key] = {"aggregations": {"by_appCode": {"buckets": []}}}
    return results

def process_data(results):
    processed_data = defaultdict(lambda: defaultdict(list))
    
    try:
        for key, data in results.items():
            if key == "p1_p2_vulnerabilities" and "aggregations" in data:
                if "by_appCode" in data['aggregations'] and "buckets" in data['aggregations']['by_appCode']:
                    for bucket in data['aggregations']['by_appCode']['buckets']:
                        app_code = bucket['key']
                        if "by_affectedItemType" in bucket and "buckets" in bucket['by_affectedItemType']:
                            for item_type in bucket['by_affectedItemType']['buckets']:
                                item_type_key = item_type['key']
                                if "by_time" in item_type and "buckets" in item_type['by_time']:
                                    for time_bucket in item_type['by_time']['buckets']:
                                        date = time_bucket['key_as_string']
                                        unique_issues = time_bucket['unique_issues']['value']
                                        if "p2_count" in time_bucket and "issue_names" in time_bucket['p2_count'] and "buckets" in time_bucket['p2_count']['issue_names']:
                                            for issue in time_bucket['p2_count']['issue_names']['buckets']:
                                                processed_data[app_code][item_type_key].append({
                                                    'date': date,
                                                    'unique_issues': unique_issues,
                                                    'issue_name': issue['key']
                                                })
            elif key == "cryptography_tss_opendata" and "aggregations" in data:
                if "by_appCode" in data['aggregations'] and "buckets" in data['aggregations']['by_appCode']:
                    for bucket in data['aggregations']['by_appCode']['buckets']:
                        app_code = bucket['key']
                        if "by_issueType" in bucket and "buckets" in bucket['by_issueType']:
                            for issue_type in bucket['by_issueType']['buckets']:
                                issue_type_key = issue_type['key']
                                if "by_time" in issue_type and "buckets" in issue_type['by_time']:
                                    for time_bucket in issue_type['by_time']['buckets']:
                                        date = time_bucket['key_as_string']
                                        unique_issues = time_bucket['unique_issues']['value']
                                        processed_data[app_code][issue_type_key].append({
                                            'date': date,
                                            'unique_issues': unique_issues
                                        })
            elif key == "trends" and "aggregations" in data:
                if "by_interval" in data['aggregations'] and "buckets" in data['aggregations']['by_interval']:
                    for interval in data['aggregations']['by_interval']['buckets']:
                        date = interval['key_as_string']
                        if "by_appCode" in interval and "buckets" in interval['by_appCode']:
                            for app_code_bucket in interval['by_appCode']['buckets']:
                                app_code = app_code_bucket['key']
                                if "by_affectedItemType" in app_code_bucket and "buckets" in app_code_bucket['by_affectedItemType']:
                                    for item_type in app_code_bucket['by_affectedItemType']['buckets']:
                                        item_type_key = item_type['key']
                                        unique_issues = item_type['unique_issues']['value']
                                        processed_data[app_code][item_type_key].append({
                                            'date': date,
                                            'unique_issues': unique_issues
                                        })
    except Exception as e:
        logging.error(f"Error processing data: {str(e)}")
    
    # If no data was processed, create a placeholder for ATU0
    if not processed_data:
        processed_data["ATU0"]["No Data Available"] = [{"date": "N/A", "unique_issues": 0}]
            
    return processed_data

def save_to_csv(processed_data, output_dir):
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    for app_code, data in processed_data.items():
        for item_type, records in data.items():
            if not records:
                logging.warning(f"No records to save for {app_code}_{item_type}")
                continue
                
            try:
                csv_file = os.path.join(output_dir, f'{app_code}_{item_type}.csv')
                with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['date', 'unique_issues']
                    if records and 'issue_name' in records[0]:
                        fieldnames.append('issue_name')
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for record in records:
                        writer.writerow(record)
                    logging.info(f"Saved CSV file: {csv_file}")
            except Exception as e:
                logging.error(f"Error saving CSV for {app_code}_{item_type}: {str(e)}")

def generate_email_content(processed_data, output_dir):
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    email_content = {}
    for app_code, data in processed_data.items():
        try:
            email_body = f"Dear Team,\n\nPlease find below the latest IT risk metrics Overview for app code: {app_code}\n\n"
            
            if not data:
                email_body += "No compliance data was found for this application code.\n\n"
            else:
                for item_type, records in data.items():
                    email_body += f"==========================\n{item_type} - [{len(records)}]\n==========================\n"
                    if item_type == "Windows Server Vulnerabilities" and records and 'issue_name' in records[0]:
                        email_body += "Priority | Issue Name\n------------------------\n"
                        for record in records:
                            email_body += f"P2      | {record.get('issue_name', 'Unknown')}\n"
                    else:
                        email_body += f"{item_type} Issues - [Count]: {len(records)}\n"
                    email_body += "\n"
                    
            email_body += "Best regards,\nServer Compliance Team\n"
            
            email_content[app_code] = email_body
            email_file = os.path.join(output_dir, f'{app_code}_email.txt')
            
            with open(email_file, 'w', encoding='utf-8') as f:
                f.write(email_body)
                
            logging.info(f"Saved email content file: {email_file}")
        except Exception as e:
            logging.error(f"Error generating email content for {app_code}: {str(e)}")
    
    return email_content

def main():
    try:
        args = parse_arguments()
        logging.info(f"Input directory: {args.input_dir}")
        logging.info(f"Output directory: {args.output_dir}")
        
        results = load_results_from_json(args.input_dir)
        processed_data = process_data(results)
        save_to_csv(processed_data, args.output_dir)
        generate_email_content(processed_data, args.output_dir)
        
        logging.info("Data processing complete")
    except Exception as e:
        logging.error(f"Fatal error in main process: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 