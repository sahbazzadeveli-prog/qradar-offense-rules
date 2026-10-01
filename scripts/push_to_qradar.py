import requests
import json
import yaml
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# QRadar Configuration
QRADAR_HOST = "YOUR_QRADAR_IP"
QRADAR_TOKEN = "YOUR_API_TOKEN"
HEADERS = {
    "SEC": QRADAR_TOKEN,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

RULES_DIR = "../rules"

def load_yaml_rule(filepath):
    with open(filepath, 'r') as f:
        return yaml.safe_load(f)

def create_qradar_rule(rule_data):
    rule_name = rule_data['qradar']['rule_name']
    severity = rule_data['qradar']['severity']
    
    severity_map = {
        'critical': 10,
        'high': 8,
        'medium': 5,
        'low': 3
    }
    
    payload = {
        "name": rule_name,
        "type": "EVENT",
        "enabled": True,
        "owner": "admin",
        "notes": rule_data.get('description', ''),
        "groups": ["Default"],
    }
    
    url = f"https://{QRADAR_HOST}/api/analytics/rules"
    
    response = requests.post(
        url,
        headers=HEADERS,
        json=payload,
        verify=False
    )
    
    if response.status_code in [200, 201]:
        print(f"[+] Rule created: {rule_name}")
        return response.json()
    else:
        print(f"[-] Failed: {rule_name} - {response.status_code} - {response.text}")
        return None

def main():
    print("[*] Starting QRadar Rule Deployment...")
    
    success = 0
    failed = 0
    
    for category in ['sigma', 'owasp', 'custom']:
        category_path = os.path.join(RULES_DIR, category)
        
        if not os.path.exists(category_path):
            continue
            
        for filename in os.listdir(category_path):
            if filename.endswith('.yml'):
                filepath = os.path.join(category_path, filename)
                print(f"\n[*] Processing: {filename}")
                
                rule_data = load_yaml_rule(filepath)
                result = create_qradar_rule(rule_data)
                
                if result:
                    success += 1
                else:
                    failed += 1
    
    print(f"\n[*] Deployment Complete!")
    print(f"[+] Success: {success}")
    print(f"[-] Failed: {failed}")

if __name__ == "__main__":
    main()
