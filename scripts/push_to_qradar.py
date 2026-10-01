import requests
import json
import yaml
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# QRadar Configuration
QRADAR_HOST = "100.53.225.8"
QRADAR_TOKEN = "f1cc9405-c31c-4c75-b4ab-aef6b1fc1bfc"
HEADERS = {
    "SEC": QRADAR_TOKEN,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

RULES = [
    {
        "name": "SIGMA - PowerShell Encoded Command Execution",
        "type": "EVENT",
        "enabled": True,
        "notes": "Detects PowerShell execution with Base64 encoded commands",
        "groups": ["Default"]
    },
    {
        "name": "SIGMA - Mimikatz LSASS Memory Access",
        "type": "EVENT",
        "enabled": True,
        "notes": "Detects Mimikatz credential dumping via LSASS access",
        "groups": ["Default"]
    },
    {
        "name": "SIGMA - Suspicious Scheduled Task Creation",
        "type": "EVENT",
        "enabled": True,
        "notes": "Detects creation of suspicious scheduled tasks for persistence",
        "groups": ["Default"]
    },
    {
        "name": "OWASP - Broken Access Control Attempt",
        "type": "EVENT",
        "enabled": True,
        "notes": "Detects attempts to access resources beyond user authorization",
        "groups": ["Default"]
    },
    {
        "name": "OWASP - Sensitive Data Over HTTP",
        "type": "EVENT",
        "enabled": True,
        "notes": "Detects sensitive data transmitted over unencrypted HTTP",
        "groups": ["Default"]
    },
    {
        "name": "OWASP - DNS Tunneling Exfiltration",
        "type": "EVENT",
        "enabled": True,
        "notes": "Detects DNS tunneling used for data exfiltration",
        "groups": ["Default"]
    },
    {
        "name": "CUSTOM - New Local User Created",
        "type": "EVENT",
        "enabled": True,
        "notes": "Detects creation of new local user accounts",
        "groups": ["Default"]
    },
    {
        "name": "CUSTOM - User Added to Admin Group",
        "type": "EVENT",
        "enabled": True,
        "notes": "Detects when user is added to administrators group",
        "groups": ["Default"]
    },
    {
        "name": "CUSTOM - New Firewall Rule Added",
        "type": "EVENT",
        "enabled": True,
        "notes": "Detects addition of new firewall rules",
        "groups": ["Default"]
    },
    {
        "name": "CUSTOM - Disabled Account Login Attempt",
        "type": "EVENT",
        "enabled": True,
        "notes": "Detects login attempts using disabled user accounts",
        "groups": ["Default"]
    }
]

def create_qradar_rule(rule):
    url = f"https://{QRADAR_HOST}/api/analytics/rules"
    
    response = requests.post(
        url,
        headers=HEADERS,
        json=rule,
        verify=False
    )
    
    if response.status_code in [200, 201]:
        print(f"[+] Rule created: {rule['name']}")
        return response.json()
    else:
        print(f"[-] Failed: {rule['name']} - {response.status_code} - {response.text}")
        return None

def get_existing_rules():
    url = f"https://{QRADAR_HOST}/api/analytics/rules"
    response = requests.get(url, headers=HEADERS, verify=False)
    if response.status_code == 200:
        return response.json()
    return []

def main():
    print("[*] Starting QRadar Rule Deployment...")
    print(f"[*] Target: {QRADAR_HOST}")
    print(f"[*] Total rules to deploy: {len(RULES)}\n")
    
    existing = get_existing_rules()
    existing_names = [r['name'] for r in existing]
    print(f"[*] Existing rules in QRadar: {len(existing_names)}\n")
    
    success = 0
    failed = 0
    skipped = 0
    
    for rule in RULES:
        if rule['name'] in existing_names:
            print(f"[~] Skipped (already exists): {rule['name']}")
            skipped += 1
            continue
            
        result = create_qradar_rule(rule)
        if result:
            success += 1
        else:
            failed += 1
    
    print(f"\n[*] Deployment Complete!")
    print(f"[+] Success: {success}")
    print(f"[-] Failed: {failed}")
    print(f"[~] Skipped: {skipped}")

if __name__ == "__main__":
    main()
