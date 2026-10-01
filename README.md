# QRadar Offense Rules

Professional QRadar SIEM Offense Rules deployed via API.

## Structure
- `rules/sigma/` - SIGMA-based detection rules
- `rules/owasp/` - OWASP Top 10 based rules
- `rules/custom/` - Custom SOC rules
- `scripts/` - API deployment scripts
- `docs/` - Documentation

## Rules List
### SIGMA Based
1. PowerShell Encoded Command Detection
2. Mimikatz Detection
3. Scheduled Task Creation

### OWASP Based
4. Broken Access Control
5. Cryptographic Failure
6. DNS Tunneling

### Custom Rules
7. New Local User Created
8. Admin Group Addition
9. Firewall Rule Added
10. Disabled Account Login Attempt

## Deployment
Rules are deployed to QRadar via API using `scripts/push_to_qradar.py`
