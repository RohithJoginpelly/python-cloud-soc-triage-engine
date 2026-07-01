# Playbook: Possible Public S3 Bucket Exposure

## Alert Name
Possible public S3 bucket exposure

## Severity
High

## Why This Matters
S3 buckets may contain sensitive files. Changes to bucket policies, ACLs, or public access block settings can accidentally or maliciously expose data to the internet.

## Detection Logic
This alert is generated when public-access-related S3 events are detected, such as:

- PutBucketAcl
- PutBucketPolicy
- DeletePublicAccessBlock

## Evidence to Review
- eventTime
- eventName
- sourceIPAddress
- userIdentity
- bucketName
- bucket policy or ACL changes
- public access block configuration

## Triage Steps
1. Identify the affected S3 bucket.
2. Confirm whether the public access change was approved.
3. Review the bucket policy and ACL.
4. Check if public access block settings were removed.
5. Determine whether sensitive data is stored in the bucket.
6. Escalate if public exposure was unauthorized.

## Containment Actions
- Restore public access block settings.
- Remove public bucket policies or ACLs.
- Restrict access to approved principals.
- Review object access logs if available.
- Notify the data owner.

## Closure Criteria
Close the case only after the bucket is confirmed private or the public access has been approved and documented.
