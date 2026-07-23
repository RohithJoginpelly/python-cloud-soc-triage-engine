# AI SOC Copilot v2.0.0 Release Notes

## Overview

Version 2.0.0 transforms the original Python Cloud SOC Triage Engine into a multi-source, evidence-grounded AI SOC Copilot for realistic blue-team investigation workflows.

## Core capabilities

- AWS CloudTrail, Wazuh, and Snort event ingestion and normalization
- Cross-source SSH attack correlation
- Deterministic risk scoring
- MITRE ATT&CK mapping
- Evidence-grounded Copilot summaries, investigation hypotheses, recommended next steps, and analyst-note drafts
- Deterministic fallback provider for offline demonstrations
- Persistent SQLite SOC case management
- Append-only case and identity audit trails
- Authenticated analyst dashboard
- Analyst, senior analyst, and administrator roles
- Password management, login lockout, account unlock, and server-side session revocation
- Structured request and security logging with request IDs
- Safe production error handling
- Rate limiting, trusted proxy handling, and request-body limits
- Liveness and readiness endpoints
- Protected operational metrics and safe configuration reporting
- Hardened non-root Docker deployment

## Security boundaries

The Copilot assists analysts but does not perform containment automatically. It does not disable accounts, revoke credentials, isolate endpoints, alter firewall rules, delete files, or close incidents without analyst approval.

Untrusted telemetry is treated as evidence, not instructions. Copilot output is grounded in the correlated evidence packet and clearly identifies missing context.

## Validation

The release passed:

- 413 automated tests
- Python bytecode compilation across `src` and `tests`
- Python dependency integrity checks
- Hardened container health checks
- Non-root runtime verification
- Read-only container filesystem smoke testing
- Secret and generated-file review

## Production container

The production image:

- Runs as UID/GID `10001:10001`
- Exposes port `8000`
- Uses one Uvicorn worker because metrics and rate-limit state are process-local
- Supports a read-only root filesystem
- Drops all Linux capabilities
- Enables `no-new-privileges`
- Applies CPU, memory, and PID limits through the production launcher
- Persists SQLite case data
- Mounts telemetry input read-only

## Demo

The deterministic offline demo uses:

- `data/test_events/sample_snort_ssh_recon.json`
- `data/test_events/sample_wazuh_ssh_compromise.json`
- the `fallback` Copilot provider

The verified demo produces five normalized events, one correlated finding, one saved SOC case, and append-only audit events without requiring an AWS account or external AI credentials.

## Upgrade note

The tracked V1 runtime SQLite database was removed from Git. Existing local copies remain untouched and future runtime database files are ignored.

## Known limitations

- SQLite, operational metrics, and rate limiting are process-local
- Production horizontal scaling requires shared services such as PostgreSQL and Redis
- Enterprise SSO and MFA are not yet included
- External SIEM forwarding and OpenTelemetry export remain future enhancements
