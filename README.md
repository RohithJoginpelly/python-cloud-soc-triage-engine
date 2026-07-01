# Python Cloud SOC Triage Engine

## Overview
This project is a Python-based Cloud SOC detection and triage lab. It reads AWS CloudTrail-style logs, detects suspicious activity, enriches alerts with user context, assigns severity scores, and creates a SOC-style incident queue and dashboard.

## Architecture
CloudTrail JSON Logs -> Parser -> Detection Rules -> Enrichment -> Severity Scoring -> CSV Incident Queue -> Streamlit Dashboard

## Dashboard Screenshot
![Cloud SOC Triage Dashboard](screenshots/dashboard.png)

## Features
- Parses CloudTrail-style JSON logs
- Detects failed logins followed by success
- Detects new IAM access key creation
- Detects possible IAM privilege escalation
- Detects CloudTrail logging tampering
- Detects AWS root account usage
- Detects possible public S3 bucket exposure
- Detects security groups opened to the internet
- Adds user role and department context
- Adds recommended analyst actions
- Creates CSV alert queue
- Shows alerts in a Streamlit dashboard
- Includes SOC playbooks and incident report template

## Detection Rules
AWS-AUTH-001: Multiple failed logins followed by success - High  
AWS-IAM-001: New IAM access key created - Medium  
AWS-IAM-002: Possible IAM privilege escalation - High  
AWS-LOG-001: CloudTrail logging modified or disabled - Critical  
AWS-ROOT-001: Root account console login detected - Critical  
AWS-S3-001: Possible public S3 bucket exposure - High  
AWS-NET-001: Security group opened to the internet - High  

## How to Run

1. Create and activate virtual environment:

python3 -m venv venv  
source venv/bin/activate

2. Install dependencies:

pip install -r requirements.txt

3. Run the detection engine:

python src/main.py

4. View generated alerts:

cat data/alerts/alerts.csv

5. Run the dashboard:

streamlit run dashboard/app.py

6. Open in browser:

http://localhost:8501

## Project Structure
- src/ contains the Python detection engine
- data/raw/ contains sample CloudTrail logs
- data/alerts/ contains generated alerts
- dashboard/ contains the Streamlit dashboard
- screenshots/ contains dashboard screenshots
- playbooks/ contains SOC response playbooks
- reports/ contains incident report templates

## SOC Playbooks
This project includes SOC-style playbooks for:

- Multiple failed logins followed by success
- New IAM access key creation
- IAM privilege escalation
- CloudTrail logging tampering
- Root account usage
- Public S3 bucket exposure
- Security group opened to the internet

Each playbook explains why the alert matters, what evidence to review, triage steps, containment actions, and closure criteria.

## Skills Demonstrated
- AWS CloudTrail log analysis
- Python automation
- SOC triage workflow
- Detection engineering
- IAM security monitoring
- Alert enrichment
- Severity scoring
- Dashboard development
- Incident response documentation

## Future Improvements
- Connect to real AWS CloudTrail logs
- Add IP reputation lookup
- Add geo-location enrichment
- Add Slack or email alerts
- Add EventBridge and SQS for near-real-time detection
- Add SQLite database for incident tracking

## Disclaimer
This project is for educational and portfolio purposes only.
