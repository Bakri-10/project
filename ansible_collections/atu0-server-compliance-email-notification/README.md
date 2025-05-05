# ATU0 Server Compliance Email Notification

An Ansible collection for automating the generation and delivery of server compliance reports via email.

## Overview

This collection fetches vulnerability and compliance data from Elasticsearch, processes it, and sends formatted email notifications to application custodians with details about their servers' compliance status.

## Requirements

- Python 3.6+
- Ansible 2.9+
- Python Packages:
  - elasticsearch
  - requests

## Files Structure

```
ansible_collections/atu0-server-compliance-email-notification/
├── README.md
├── main.yml (Main playbook entry point)
├── roles/
    ├── tasks/
    │   ├── main.yml
    │   ├── fetch_data.yml
    │   └── process_data.yml
    └── files/
        ├── fetch_data.py
        ├── process_data.py
        ├── temp/ (For temporary files)
        └── output/ (For generated reports)
```

## Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `app_codes` | List of application codes to process | `"ATU0"` |
| `es_url` | Elasticsearch URL | `https://e87a6cd02ed34b0b844d64cc7d8c41a9.ece.saifg.rbc.com:9243` |
| `es_service_id` | Elasticsearch service ID | `SATU0SRVECEWRITE` |
| `es_service_id_password` | Elasticsearch service password | `R4@.iE@GmdVMp3` |
| `server_compliance_metrics_index` | Elasticsearch index name | `atu0-server-compliance-metrics` |
| `custodian_email` | Email address for notifications | `feyi.sodipo@rbc.com` |

## How to Run

You can run this Ansible collection with the following command:

```bash
ansible-playbook ansible_collections/atu0-server-compliance-email-notification/main.yml
```

## Process Flow

1. The playbook starts by defining necessary variables
2. It then executes a Python script to fetch data from Elasticsearch
3. Another Python script processes this data and generates reports
4. Finally, an email notification is sent to the application custodian

## Email Format

The email notification contains:
- A summary of all vulnerabilities found
- Detailed information about P1 and P2 vulnerabilities
- Information about cryptography, TSS, and other compliance issues

## Customization

You can customize this collection by modifying:
- The variables in `main.yml` to change the application code or Elasticsearch details
- The Python scripts to change the data processing logic or report format
- The email template in `process_data.py` to change the notification format 