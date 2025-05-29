#!/usr/bin/env python3

import os
import sys
import json
import smtplib
import argparse
from datetime import datetime, timedelta
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
        print(f"ERROR: Failed to load data from file: {str(e)}")
        return [], 0

def analyze_issues(hits):
    """Analyze issue data and extract useful metrics"""
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    
    app_codes = set()
    issue_types = set()
    high_severity_issues = []
    
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
        
        # Collect unique issue types
        issue_type = source.get('issueType')
        if issue_type:
            issue_types.add(issue_type)
        
        # Collect high severity issues for the table
        if severity in ['critical', 'high']:
            high_severity_issues.append({
                'type': source.get('issueType', 'Unknown'),
                'severity': severity.upper(),
                'component': source.get('component', 'Unknown'),
                'remediation_link': source.get('remediationLink', 'N/A')
            })
    
    return {
        "severity_counts": severity_counts,
        "app_codes": list(app_codes),
        "issue_types": list(issue_types),
        "high_severity_count": severity_counts["critical"] + severity_counts["high"],
        "high_severity_issues": high_severity_issues
    }

def identify_non_compliant_apps(hits):
    """Identify non-compliant apps based on severity thresholds"""
    app_compliance = {}
    
    # Define compliance thresholds
    thresholds = {
        "critical": 0,  # Any critical finding makes an app non-compliant
        "high": 2,      # More than 2 high findings make an app non-compliant
        "medium": 5     # More than 5 medium findings make an app non-compliant
    }
    
    # Group findings by app
    for hit in hits:
        source = hit.get('_source', {})
        app_code = source.get('appCode')
        severity = source.get('severity', '').lower()
        
        if not app_code:
            continue
            
        if app_code not in app_compliance:
            app_compliance[app_code] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "is_compliant": True,
                "reasons": []
            }
        
        if severity in app_compliance[app_code]:
            app_compliance[app_code][severity] += 1
    
    # Check compliance for each app
    for app_code, data in app_compliance.items():
        if data["critical"] > thresholds["critical"]:
            data["is_compliant"] = False
            data["reasons"].append(f"Has {data['critical']} critical findings (threshold: {thresholds['critical']})")
        
        if data["high"] > thresholds["high"]:
            data["is_compliant"] = False
            data["reasons"].append(f"Has {data['high']} high findings (threshold: {thresholds['high']})")
            
        if data["medium"] > thresholds["medium"]:
            data["is_compliant"] = False
            data["reasons"].append(f"Has {data['medium']} medium findings (threshold: {thresholds['medium']})")
    
    return app_compliance

def generate_report(input_file, output_file):
    """Generate a formatted report from data"""
    hits, total = load_vulnerability_data(input_file)
    
    if total == 0:
        print("No issues found.")
        return False
    
    # Analyze the data
    analysis = analyze_issues(hits)
    
    # Get compliance status for each app
    compliance_status = identify_non_compliant_apps(hits)
    
    # Get date range (last 7 days by default)
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)
    
    # Create report content
    report = {
        "summary": {
            "total_vulnerabilities": total,
            "high_severity_count": analysis["high_severity_count"],
            "app_codes": analysis["app_codes"],
            "issue_types": analysis["issue_types"],
            "generated_at": datetime.now().strftime("%Y-%m-%d"),
            "start_date": start_date.strftime("%Y-%m-%d"),
            "end_date": end_date.strftime("%Y-%m-%d"),
            "high_severity_issues": analysis["high_severity_issues"],
            "non_compliant_apps": [
                {
                    "app_code": app_code,
                    "reasons": data["reasons"],
                    "severity_counts": {
                        "critical": data["critical"],
                        "high": data["high"],
                        "medium": data["medium"],
                        "low": data["low"],
                        "info": data["info"]
                    }
                }
                for app_code, data in compliance_status.items()
                if not data["is_compliant"]
            ]
        },
        "severity_breakdown": analysis["severity_counts"],
        "issue_types": analysis["issue_types"],
        "compliance_details": compliance_status,
        "raw_data": hits[:10]  # Include first 10 issues as examples
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
        report_date = data["summary"]["generated_at"]
        app_code = ",".join(data["summary"]["app_codes"]) if data["summary"]["app_codes"] else "Unknown"
        total_vulnerabilities = data["summary"]["total_vulnerabilities"]
        high_severity_count = data["summary"]["high_severity_count"]
        start_date = data["summary"]["start_date"]
        end_date = data["summary"]["end_date"]
        high_severity_issues = data["summary"]["high_severity_issues"]
        non_compliant_apps = data["summary"].get("non_compliant_apps", [])
        
        # Get severity counts
        severity_counts = data["severity_breakdown"]
        critical_count = severity_counts.get("critical", 0)
        high_count = severity_counts.get("high", 0)
        medium_count = severity_counts.get("medium", 0)
        low_count = severity_counts.get("low", 0)
        info_count = severity_counts.get("info", 0)
        
        # Get issue types if available
        issue_types = ", ".join(data["summary"]["issue_types"]) if "issue_types" in data["summary"] else "Vulnerability"
        
        # Replace placeholders in template
        content = template
        content = content.replace("{{ report_date }}", report_date)
        content = content.replace("{{ app_code }}", app_code)
        content = content.replace("{{ total_vulnerabilities }}", str(total_vulnerabilities))
        content = content.replace("{{ high_severity_count }}", str(high_severity_count))
        content = content.replace("{{ start_date }}", start_date)
        content = content.replace("{{ end_date }}", end_date)
        content = content.replace("{{ issue_types }}", issue_types)
        content = content.replace("{{ critical_count }}", str(critical_count))
        content = content.replace("{{ high_count }}", str(high_count))
        content = content.replace("{{ medium_count }}", str(medium_count))
        content = content.replace("{{ low_count }}", str(low_count))
        content = content.replace("{{ info_count }}", str(info_count))
        content = content.replace("{{ generated_at }}", report_date)
        
        # Handle high severity issues table
        if high_severity_issues:
            table_rows = []
            for issue in high_severity_issues:
                table_rows.append(f"| {issue['type']} | {issue['severity']} | {issue['component']} | {issue['remediation_link']} |")
            content = content.replace("{% for issue in high_severity_issues %}\n| {{ issue.type }} | {{ issue.severity }} | {{ issue.component }} | {{ issue.remediation_link | default('N/A') }} |\n{% endfor %}", "\n".join(table_rows))
        
        # Handle non-compliant apps section
        if non_compliant_apps:
            content = content.replace("{% if non_compliant_apps %}", "")
            content = content.replace("{% endif %}", "")
            
            # Replace reasons list
            reasons = non_compliant_apps[0]["reasons"]
            reasons_text = "\n".join([f"- {reason}" for reason in reasons])
            content = content.replace("{% for reason in non_compliant_apps[0].reasons %}\n- {{ reason }}\n{% endfor %}", reasons_text)
            
            # Replace severity counts
            severity_counts = non_compliant_apps[0]["severity_counts"]
            for severity, count in severity_counts.items():
                content = content.replace(f"{{{{ non_compliant_apps[0].severity_counts.{severity} }}}}", str(count))
        else:
            # Remove the non-compliant section if there are no non-compliant apps
            start = content.find("{% if non_compliant_apps %}")
            end = content.find("{% endif %}", start) + len("{% endif %}")
            if start != -1 and end != -1:
                content = content[:start] + content[end:]
        
        return content
    except Exception as e:
        print(f"ERROR: Failed to prepare email content: {str(e)}")
        return None

def main():
    """Main function to process data"""
    parser = argparse.ArgumentParser(description='Process data from Elasticsearch')
    parser.add_argument('--input', required=True, help='Input JSON file with data')
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