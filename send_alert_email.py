"""
Send abnormal ADX detections by Outlook email.

Requirements:
    pip install azure-kusto-data msal requests

Authentication:
    Option A: Service principal using AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
    Option B: Managed identity adaptation can be added later.

Environment variables required:
    KUSTO_CLUSTER=https://<cluster>.<region>.kusto.windows.net
    KUSTO_DATABASE=<database>
    AZURE_TENANT_ID=<tenant-id>
    AZURE_CLIENT_ID=<app-id>
    AZURE_CLIENT_SECRET=<secret>
    GRAPH_SENDER_USER_ID=<sender@domain.com>
    ALERT_RECIPIENTS=<recipient1@domain.com,recipient2@domain.com>
"""

from __future__ import annotations

import json
import os
from html import escape
from typing import List, Dict

import msal
import requests
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder

QUERY = r"""
DetectSecurityAnomalies()
| where activity_type == 'Abnormal'
| where timestamp >= ago(5m)
| project timestamp, device, os, user=user_norm, ip=client_ip, process=process_norm, pid, event, severity, abnormal_reason, alert_key
| distinct *
| order by timestamp desc
"""


def get_kusto_client() -> KustoClient:
    cluster = os.environ["KUSTO_CLUSTER"]
    client_id = os.environ["AZURE_CLIENT_ID"]
    client_secret = os.environ["AZURE_CLIENT_SECRET"]
    tenant_id = os.environ["AZURE_TENANT_ID"]
    kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(
        cluster, client_id, client_secret, tenant_id
    )
    return KustoClient(kcsb)


def query_alerts() -> List[Dict]:
    client = get_kusto_client()
    database = os.environ["KUSTO_DATABASE"]
    response = client.execute(database, QUERY)
    rows = []
    primary = response.primary_results[0]
    columns = [c.column_name for c in primary.columns]
    for row in primary:
        rows.append(dict(zip(columns, row)))
    return rows


def get_graph_token() -> str:
    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ["AZURE_CLIENT_ID"]
    client_secret = os.environ["AZURE_CLIENT_SECRET"]
    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )
    token_result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in token_result:
        raise RuntimeError(f"Unable to acquire Graph token: {json.dumps(token_result, indent=2)}")
    return token_result["access_token"]


def build_email_html(rows: List[Dict]) -> str:
    row_html = "".join(
        f"<tr>"
        f"<td>{escape(str(r.get('timestamp', '')))}</td>"
        f"<td>{escape(str(r.get('user', '')))}</td>"
        f"<td>{escape(str(r.get('ip', '')))}</td>"
        f"<td>{escape(str(r.get('process', '')))}</td>"
        f"<td>{escape(str(r.get('pid', '')))}</td>"
        f"<td>{escape(str(r.get('event', '')))}</td>"
        f"<td>{escape(str(r.get('severity', '')))}</td>"
        f"<td>{escape(str(r.get('abnormal_reason', '')))}</td>"
        f"</tr>"
        for r in rows
    )
    return f"""
    <html>
      <body>
        <h2>ADX Cyber Alert</h2>
        <p>The following abnormal records were detected in the last 5 minutes.</p>
        <table border="1" cellpadding="6" cellspacing="0">
          <tr>
            <th>Timestamp</th><th>User</th><th>IP address</th><th>Process</th><th>PID</th><th>Event</th><th>Severity</th><th>Reason</th>
          </tr>
          {row_html}
        </table>
      </body>
    </html>
    """


def send_mail(rows: List[Dict]) -> None:
    if not rows:
        print("No abnormal detections in the last 5 minutes.")
        return

    token = get_graph_token()
    sender = os.environ["GRAPH_SENDER_USER_ID"]
    recipients = [r.strip() for r in os.environ["ALERT_RECIPIENTS"].split(",") if r.strip()]

    to_recipients = [{"emailAddress": {"address": r}} for r in recipients]
    payload = {
        "message": {
            "subject": f"ADX alert: {len(rows)} abnormal security event(s) detected",
            "body": {
                "contentType": "HTML",
                "content": build_email_html(rows),
            },
            "toRecipients": to_recipients,
        },
        "saveToSentItems": "true",
    }

    response = requests.post(
        f"https://graph.microsoft.com/v1.0/users/{sender}/sendMail",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=30,
    )
    response.raise_for_status()
    print(f"Sent alert email to: {', '.join(recipients)}")


if __name__ == "__main__":
    alerts = query_alerts()
    send_mail(alerts)
