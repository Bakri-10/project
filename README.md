# ATU0 Server Compliance Email Notification

This project provides an automated solution for fetching server compliance data from Elasticsearch, processing it, and sending email notifications with compliance reports.

## Overview

The solution consists of:

1. A Python script to fetch data from Elasticsearch (`fetch_data.py`)
2. A Python script to process the data and generate CSV and email reports (`process_data.py`)
3. Ansible tasks to orchestrate the entire process and send emails

## Prerequisites

- Python 3.x
- Required Python packages: 
  - ansible
  - elasticsearch
  - requests

## Directory Structure

```
ansible_collections/
└── atu0-server-compliance-email-notification/
    └── roles/
        ├── files/
        │   ├── fetch_data.py
        │   └── process_data.py
        │   └── email_template.txt
        └── tasks/
            ├── main.yml
            ├── fetch_data.yml
            └── process_data.yml
        └── main.yml
```

## Installation

### Using Ansible Tower/AWX (Recommended)

1. Clone this repository or download the files to the Ansible Tower/AWX server or project location.
2. Import the project into Tower/AWX as a project.
3. Create a job template with the following settings:
   - Name: ATU0 Server Compliance Email Notification
   - Job Type: Run
   - Inventory: Your preferred inventory (with localhost available)
   - Project: The project containing this repository
   - Playbook: `ansible_collections/atu0-server-compliance-email-notification/roles/main.yml`
   - Credentials: Machine credentials with appropriate access
   
4. Add the following survey variables to the job template:
   - `survey_appcode`: Application code (default: ATU0)
   - `es_url`: Elasticsearch URL
   - `es_service_id`: Elasticsearch service ID
   - `es_service_id_password`: Elasticsearch service password (sensitive)
   - `server_compliance_metrics_index`: Name of the Elasticsearch index
   - `email_to`: Email address to send notifications to

5. Run the job template from Tower/AWX.

### Local Execution (Alternative)

If you need to run the playbook locally (not recommended for production):

```bash
# Install required packages
pip install ansible elasticsearch requests

# Run the playbook directly
ansible-playbook -i localhost, -c local ansible_collections/atu0-server-compliance-email-notification/roles/main.yml
```

## Configuration

The main configuration parameters can be set in Tower/AWX as survey variables:

- `es_service_id`: The Elasticsearch service ID
- `es_service_id_password`: The Elasticsearch service password
- `email_to`: The email address to send notifications to
- `es_url`: The Elasticsearch server URL
- `server_compliance_metrics_index`: The Elasticsearch index name to query
- `app_codes`: Application code(s) to include in the report

## How It Works

1. The Ansible playbook runs the `fetch_data.py` script to query Elasticsearch for server compliance data
2. The script saves the raw data to JSON files
3. The playbook then runs the `process_data.py` script to:
   - Process the JSON data
   - Generate CSV files with processed data
   - Create email content with a summary of the compliance metrics
4. Finally, the playbook sends an email notification with the compliance report

## Email Notification

The email notification includes:
- A summary of Windows Server Vulnerabilities (P2 priority)
- Counts of Cryptography, TSS, and Open Data issues
- Compliance trends over time

## Ansible Tower / AWX Integration

This solution is designed to work seamlessly with Ansible Tower or AWX. Key features include:

- Variables can be defined through Tower surveys
- Sensitive credentials can be managed securely in Tower
- Email notifications use Tower's configured SMTP server
- Job scheduling can be managed through Tower
- Results and logs are centralized in the Tower interface

## Troubleshooting

If you encounter issues:

1. Check job logs in Ansible Tower/AWX
2. Verify your Elasticsearch connection details are correct
3. Ensure you have proper permissions to access the Elasticsearch indices
4. Check that all required Python packages are installed on the Tower execution node
5. Verify Tower has SMTP access configured correctly for email sending

## License

[Your License Information]

## Contact

For questions or support, contact: feyi.sodipo@example.com #   p r o j e c t  
 