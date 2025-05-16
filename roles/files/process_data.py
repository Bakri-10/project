#!/usr/bin/env python3

import os
import sys
import json
import smtplib
import argparse
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

def get_env_var(var_name, default=None, required=False):
    """Get environment variable or return default value"""
    value = os.environ.get(var_name, default)
    if required and value is None:
        print(f"ERROR: Required environment variable {var_name} is not set.")
        sys.exit(1)
    return value

def load_vulnerability_data(file_path):
    """Load vulnerability data from JSON file"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Extract hits from Elasticsearch response
        hits = data.get('hits', {}).get('hits', [])
        total = data.get('hits', {}).get('total', {}).get('value', 0)
        
        return hits, total
    except Exception as e:
        print(f"ERROR: Failed to load vulnerability data: {str(e)}")
        return [], 0

def analyze_vulnerabilities(hits):
    """Analyze vulnerability data and extract useful metrics"""
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    
    app_codes = set()
    vulnerability_types = set()
    
    for hit in hits:
        source = hit.get('_source', {})
        
        # Count by severity
        severity = source.get('severity', '').lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        # Collect unique app codes
        app_code = source.get('appCode')
        if app_code:
            app_codes.add(app_code)
        
        # Collect unique vulnerability types
        vuln_type = source.get('vulnerabilityType')
        if vuln_type:
            vulnerability_types.add(vuln_type)
    
    return {
        "severity_counts": severity_counts,
        "app_codes": list(app_codes),
        "vulnerability_types": list(vulnerability_types),
        "high_severity_count": severity_counts["critical"] + severity_counts["high"]
    }

def generate_report(input_file, output_file):
    """Generate a formatted report from vulnerability data"""
    hits, total = load_vulnerability_data(input_file)
    
    if total == 0:
        print("No vulnerabilities found.")
        return False
    
    # Analyze the data
    analysis = analyze_vulnerabilities(hits)
    
    # Create report content
    report = {
        "summary": {
            "total_vulnerabilities": total,
            "high_severity_count": analysis["high_severity_count"],
            "app_codes": analysis["app_codes"],
            "generated_at": datetime.now().isoformat(),
        },
        "severity_breakdown": analysis["severity_counts"],
        "vulnerability_types": analysis["vulnerability_types"],
        "raw_data": hits[:10]  # Include first 10 vulnerabilities as examples
    }
    
    # Write report to file
    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report generated and saved to {output_file}")
        return True
    except Exception as e:
        print(f"ERROR: Failed to generate report: {str(e)}")
        return False

def prepare_email_content(template_file, report_data):
    """Prepare email content using template and report data"""
    try:
        # Load template
        with open(template_file, 'r') as f:
            template = f.read()
        
        # Load report data
        with open(report_data, 'r') as f:
            data = json.load(f)
        
        # Extract data for template
        report_date = datetime.now().strftime("%Y-%m-%d")
        app_code = ",".join(data["summary"]["app_codes"]) if data["summary"]["app_codes"] else "Unknown"
        total_vulnerabilities = data["summary"]["total_vulnerabilities"]
        high_severity_count = data["summary"]["high_severity_count"]
        
        # Replace placeholders in template
        content = template
        content = content.replace("{{ report_date }}", report_date)
        content = content.replace("{{ app_code }}", app_code)
        content = content.replace("{{ total_vulnerabilities }}", str(total_vulnerabilities))
        content = content.replace("{{ high_severity_count }}", str(high_severity_count))
        
        # Handle conditional sections
        if high_severity_count > 0:
            # Keep the high severity warning
            content = content.replace("{% if high_severity_count > 0 %}", "")
            content = content.replace("{% endif %}", "")
        else:
            # Remove the conditional section
            start = content.find("{% if high_severity_count > 0 %}")
            end = content.find("{% endif %}") + 11
            content = content[:start] + content[end:]
        
        return content
    except Exception as e:
        print(f"ERROR: Failed to prepare email content: {str(e)}")
        return None

def main():
    """Main function to process vulnerability data"""
    parser = argparse.ArgumentParser(description='Process vulnerability data from Elasticsearch')
    parser.add_argument('--input', required=True, help='Input JSON file with vulnerability data')
    parser.add_argument('--output', required=True, help='Output file for the processed report')
    parser.add_argument('--email-template', help='Email template file for notifications')
    parser.add_argument('--email-output', help='Output file for the email content')
    
    args = parser.parse_args()
    
    # Generate report
    success = generate_report(args.input, args.output)
    
    # If email template is provided, prepare email content
    if success and args.email_template and args.email_output:
        email_content = prepare_email_content(args.email_template, args.output)
        if email_content:
            try:
                with open(args.email_output, 'w') as f:
                    f.write(email_content)
                print(f"Email content generated and saved to {args.email_output}")
            except Exception as e:
                print(f"ERROR: Failed to save email content: {str(e)}")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 