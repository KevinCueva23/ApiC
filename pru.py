import json
import os
import requests
import zipfile
import csv
from flask import Flask, jsonify

app = Flask(__name__)

CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
TENANT_ID = os.environ.get("TENANT_ID")


def get_token():
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    body = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials"
    }
    response = requests.post(url, data=body)
    return response.json().get("access_token")


@app.route('/defender_agents_report', methods=['GET'])
def defender_agents_report():
    auth_token = get_token()

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer " + auth_token
    }

    body = {
        "reportName": "DefenderAgents",
        "select": [
            "DeviceId", "_ManagedBy","DeviceName", "DeviceState", "PendingFullScan", "PendingReboot",
            "PendingManualSteps", "PendingOfflineScan", "CriticalFailure",
            "MalwareProtectionEnabled", "RealTimeProtectionEnabled", "NetworkInspectionSystemEnabled",
            "SignatureUpdateOverdue", "QuickScanOverdue", "FullScanOverdue", "RebootRequired",
            "FullScanRequired", "EngineVersion", "SignatureVersion", "AntiMalwareVersion",
            "LastQuickScanDateTime", "LastFullScanDateTime", "LastQuickScanSignatureVersion",
            "LastFullScanSignatureVersion", "LastReportedDateTime", "UPN", "UserEmail", "UserName"
        ]
    }

    response = requests.post("https://graph.microsoft.com/v1.0/deviceManagement/reports/exportJobs", 
                             data=json.dumps(body), headers=headers)
    report_id = response.json().get('id')

    status = ""
    while status != "completed":
        url = f"https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('{report_id}')"
        response = requests.get(url, headers=headers)
        status = response.json().get('status')
        print(f"Esperando... Estado: {status}")

   
    download_url = response.json().get('url')
    r = requests.get(download_url)

    os.makedirs('data', exist_ok=True)

    zip_file_path = 'data/defender_agents.zip'
    with open(zip_file_path, 'wb') as f:
        f.write(r.content)

    result_dict = {}
    with zipfile.ZipFile(zip_file_path, 'r') as myzip:
        with myzip.open(myzip.namelist()[0]) as myfile:
            lines = str(myfile.read(), 'utf-8').splitlines()
            rows = list(csv.reader(lines))
            result_dict = {row[0]: dict(zip(rows[0], row)) for row in rows[1:]}

    return jsonify(result_dict)


if __name__ == '__main__':
    app.run(debug=True)
