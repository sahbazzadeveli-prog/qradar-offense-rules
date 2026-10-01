# QRadar Offense Rules - Setup Guide

## Prerequisites
- QRadar 7.5
- Python 3.8+
- PyYAML library
- Requests library

## QRadar API Token almaq

1. QRadar-a admin ilə daxil ol
2. Admin → User Management → Users
3. İstifadəçini seç → User Details
4. **Authorized Services** bölməsinə get
5. **Add Authorized Service** bas
6. Token kopyala

## Installation

### 1. Python kitabxanalarını quraşdır
pip install requests pyyaml

### 2. Skripti konfiqurasiya et
scripts/push_to_qradar.py faylını aç və dəyişdir:
- QRADAR_HOST = "QRadar-ın IP ünvanı"
- QRADAR_TOKEN = "Aldığın API token"

### 3. Skripti işlət
cd scripts
python push_to_qradar.py

## Rule Yeniləmək
1. GitHub-da müvafiq .yml faylını dəyişdir
2. Skripti yenidən işlət
3. QRadar-da avtomatik yenilənəcək

## Rule Kateqoriyaları
- rules/sigma/ - SIGMA based rules
- rules/owasp/ - OWASP Top 10 rules  
- rules/custom/ - Custom SOC rules
