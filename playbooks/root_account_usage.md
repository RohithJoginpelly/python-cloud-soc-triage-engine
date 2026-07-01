# Playbook: Root Account Console Login Detected

## Alert Name
Root account console login detected

## Severity
Critical

## Why This Matters
The AWS root account has full control over the AWS account. Root account usage should be rare and closely monitored. A successful root login may indicate high-risk account access.

## Detection Logic
This alert is generated when a successful ConsoleLogin event is detected for a userIdentity type of Root.

## Evidence to Review
- eventTime
- sourceIPAddress
- awsRegion
- userIdentity.type
- responseElements.ConsoleLogin
- activity after root login

## Triage Steps
1. Confirm whether the root login was approved.
2. Verify whether MFA was used.
3. Identify the source IP address and determine whether it is expected.
4. Review all activity after the root login.
5. Check for IAM, billing, security, and logging changes.
6. Escalate immediately if the login was unauthorized.

## Containment Actions
- Change root account password if unauthorized.
- Verify and enforce MFA.
- Review and rotate sensitive credentials.
- Review CloudTrail activity after login.
- Notify account owner or security team.

## Closure Criteria
Close the case only after the root login is confirmed as authorized or the account has been secured and suspicious activity has been reviewed.
