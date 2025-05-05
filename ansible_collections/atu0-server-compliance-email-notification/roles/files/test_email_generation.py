#!/usr/bin/env python3
"""
Test script to verify email generation without Elasticsearch dependency.
This script uses the mock JSON files and process_data.py to generate the email content.
"""

import os
import sys
import logging
import argparse
from process_data import load_results_from_json, process_data, generate_email_content

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_arguments():
    parser = argparse.ArgumentParser(description='Test email generation without Elasticsearch')
    parser.add_argument('--input-dir', default='.', help='Directory containing input JSON files')
    parser.add_argument('--output-dir', default='./output', help='Directory to save output email content')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    logging.info("Loading mock JSON data...")
    results = load_results_from_json(args.input_dir)
    
    logging.info("Processing data...")
    processed_data = process_data(results)
    
    logging.info("Generating email content...")
    email_content = generate_email_content(processed_data, args.output_dir)
    
    logging.info("Email content generation complete!")
    for app_code, content in email_content.items():
        logging.info(f"Generated email for {app_code}")
        print("\n" + "="*50)
        print(f"Email Preview for {app_code}:")
        print("="*50)
        print(content)
        print("="*50)

if __name__ == "__main__":
    main() 