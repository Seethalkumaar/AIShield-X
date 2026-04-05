# AIShield-X
Behavior-Based Ransomware Detection and Response System
# AIShield-X 

AIShield-X is a behavior-based ransomware detection and response system that monitors file system activity in real time and detects suspicious encryption patterns.

Features:
- Real-time file monitoring
- Behavior-based ransomware detection
- Risk scoring & severity classification
- Automated mitigation (quarantine)
- Timeline tracking of attack progression
- Incident reporting & analytics dashboard

Architecture:

File Event → Feature Extraction → Risk Score → Severity → Response → Timeline → Report

Response System:
- HIGH  → File quarantined
- MEDIUM → Warning logged
- LOW → Ignored

Incident Reporting:
- Total events
- Alerts detected
- Severity breakdown
- Quarantine success rate

How to Run:
```bash
pip install -r requirements.txt
python app.py
