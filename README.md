# ADX Cybersecurity Lab Assets

Files included:
- `01_create_table_and_mappings.kql`
- `02_ingest_commands.kql`
- `03_detection_queries.kql`
- `04_update_policy_and_alert_table.kql`
- `05_dashboard_queries.kql`
- `automation_logic_app_workflow.json`
- `send_alert_email.py`

These assets target the exact files:
- `windows_security_logs_10000.jsonl`
- `mac_security_logs_10000.jsonl`
- `linux_security_logs_10000.jsonl`
- `merged_security_logs_30000.json`

Before running the ingestion commands, upload the four data files to an Azure Blob Storage container and replace the placeholder values for:
- `<storage-account>`
- `<container>`
- `<sas-token>`
- `<cluster-uri>`
- `<database>`
- `<adx-admin-email>`
- `<subscription-id>`
- `<resource-group>`
- `<logic-app-resource-id>`

Recommended ingest format:
- use `multijson` for the `.jsonl` source files
- use `json` for the merged array file
