# Playbook: Security Group Opened to the Internet

## Alert Name
Security group opened to the internet

## Severity
High

## Why This Matters
A security group rule allowing 0.0.0.0/0 exposes a service to the entire internet. If sensitive ports such as SSH, RDP, databases, or admin panels are exposed, attackers may attempt brute force or exploitation.

## Detection Logic
This alert is generated when an AuthorizeSecurityGroupIngress event allows inbound access from 0.0.0.0/0.

## Evidence to Review
- eventTime
- eventName
- sourceIPAddress
- userIdentity
- security group ID
- exposed port
- allowed CIDR range
- affected workload

## Triage Steps
1. Identify the security group that was changed.
2. Confirm whether the rule was approved.
3. Identify the exposed port and protocol.
4. Determine which EC2 instances or resources use the security group.
5. Check whether the source range is 0.0.0.0/0.
6. Escalate if the exposure is unauthorized.

## Containment Actions
- Remove the 0.0.0.0/0 rule if unauthorized.
- Restrict access to trusted IP addresses.
- Review exposed workloads for suspicious login attempts.
- Check for vulnerable services.
- Notify the cloud or network owner.

## Closure Criteria
Close the case only after the exposure is removed or approved with documented business justification.
