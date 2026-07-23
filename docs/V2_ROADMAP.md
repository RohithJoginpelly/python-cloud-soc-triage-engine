# AI-Powered SOC Copilot — Version 2 Roadmap

> **Release status:** Core roadmap completed for `v2.0.0`. Future enterprise scaling and external integrations remain optional enhancements.

## Objective

Transform the existing Python Cloud SOC Triage Engine into a multi-source,
evidence-grounded AI SOC investigation platform.

The existing AWS CloudTrail functionality will remain operational while
support is added for Wazuh, Snort, and OpenVAS.

## Supported Data Sources

1. AWS CloudTrail
2. Wazuh security alerts
3. Snort network alerts
4. OpenVAS vulnerability findings

## Processing Pipeline

1. Data ingestion
2. Input validation
3. Event normalization
4. Detection
5. Cross-source correlation
6. Threat and asset enrichment
7. Explainable risk scoring
8. MITRE ATT&CK mapping
9. AI-assisted triage
10. Case management
11. Analyst review
12. Audit logging

## Core Capabilities

- Multi-source security-event ingestion
- Common normalized event schema
- Rule-based security detections
- Cross-source event correlation
- IOC and asset enrichment
- Vulnerability context
- Explainable risk scoring
- MITRE ATT&CK mapping
- AI-generated alert summaries
- AI-generated investigation hypotheses
- Recommended investigation steps
- Draft analyst notes
- Case management
- Analyst feedback
- Audit logging
- AI accuracy evaluation

## AI Safety Boundaries

The AI copilot will assist analysts but will not replace deterministic
detection logic or human decision-making.

The AI will not:

- Automatically disable user accounts
- Revoke credentials
- Block IP addresses
- Isolate endpoints
- Delete files
- Modify firewall rules
- Close incidents without analyst approval
- Follow instructions found inside untrusted logs

Every factual AI claim must reference supporting evidence.

All containment and response actions require analyst approval.

## Development Phases

### Phase 1 — Version 2 Foundation

- Preserve Version 1
- Create the Version 2 branch
- Add modular project folders
- Document the architecture
- Keep existing AWS functionality operational

### Phase 2 — Common Event Schema

- Define a normalized security-event model
- Preserve the original raw event
- Validate required fields
- Generate deterministic event identifiers

### Phase 3 — Wazuh Integration

- Import Wazuh alert JSON
- Normalize endpoint and authentication alerts
- Display Wazuh alerts in the dashboard
- Add parser tests

### Phase 4 — Snort Integration

- Import Snort alerts
- Normalize network fields
- Correlate network and endpoint events

### Phase 5 — OpenVAS Enrichment

- Import vulnerability findings
- Associate vulnerabilities with assets
- Include vulnerability context in risk scoring

### Phase 6 — Cross-Source Correlation

- Correlate by source IP
- Correlate by destination asset
- Correlate by username
- Correlate events within configurable time windows

### Phase 7 — AI SOC Copilot

- Generate structured alert summaries
- Reference supporting evidence
- Suggest MITRE ATT&CK techniques
- Generate investigation hypotheses
- Generate investigation queries
- Draft analyst notes
- Report missing context and limitations

### Phase 8 — Evaluation and Security Hardening

- Create labeled test incidents
- Measure AI accuracy
- Measure unsupported claims
- Test prompt-injection resistance
- Add role-based access control
- Add complete audit logging
