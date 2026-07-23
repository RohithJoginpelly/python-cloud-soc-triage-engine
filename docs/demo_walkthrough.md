# AI SOC Copilot V2 Demo Walkthrough

This walkthrough demonstrates the Version 2 multi-source SOC investigation workflow using only local sample telemetry and the deterministic fallback Copilot provider.

## What the demo proves

The demo:

- Ingests one Snort SSH reconnaissance event
- Ingests four Wazuh SSH compromise events
- Correlates the five normalized events into one cross-source finding
- Applies deterministic risk scoring and MITRE ATT&CK mapping
- Generates evidence-grounded Copilot output without an external API key
- Saves one persistent SOC case
- Writes append-only audit events
- Presents the case in the authenticated analyst dashboard

## 1. Prepare a disposable demo database

Run the demo against `/tmp` so the repository's normal case database is not modified.

```bash
rm -f /tmp/ai-soc-v2-demo.db
```

## 2. Run the end-to-end V2 pipeline

```bash
python -m src.v2_cli \
  run-ssh-case \
  --snort data/test_events/sample_snort_ssh_recon.json \
  --wazuh data/test_events/sample_wazuh_ssh_compromise.json \
  --database /tmp/ai-soc-v2-demo.db \
  --provider fallback
```

Expected result characteristics:

```json
{
  "snort_event_count": 1,
  "wazuh_event_count": 4,
  "total_event_count": 5,
  "finding_count": 1,
  "saved_case_count": 1,
  "provider": "fallback"
}
```

The generated case ID is intentionally not fixed.

## 3. Create a demo administrator account

```bash
python -m src.identity.cli \
  --database /tmp/ai-soc-v2-demo.db \
  create \
  --email analyst@example.com \
  --name "SOC Administrator" \
  --role admin
```

Enter and confirm a demo password when prompted. The password is read securely and is not shown in the terminal.

Confirm the account:

```bash
python -m src.identity.cli \
  --database /tmp/ai-soc-v2-demo.db \
  list
```

## 4. Configure the local V2 API

Generate temporary values without printing them:

```bash
export SOC_API_KEY="$(
  python -c 'import secrets; print(secrets.token_urlsafe(48))'
)"

export SOC_SESSION_SECRET="$(
  python -c 'import secrets; print(secrets.token_urlsafe(64))'
)"
```

Configure the disposable database and local development settings:

```bash
export SOC_CASE_DATABASE=/tmp/ai-soc-v2-demo.db
export SOC_INPUT_ROOT=data/test_events
export SOC_DEPLOYMENT_MODE=development
export SOC_SESSION_HTTPS_ONLY=false
export SOC_ENABLE_HSTS=false
export SOC_LOG_FORMAT=text
export SOC_LOG_LEVEL=INFO
```

## 5. Start the API and analyst dashboard

```bash
python -m uvicorn src.api.main:app \
  --host 127.0.0.1 \
  --port 8000
```

Open:

```text
http://127.0.0.1:8000/dashboard
```

Sign in with:

```text
Email: analyst@example.com
Password: the demo password created in Step 3
```

## 6. Present the investigation

Open the generated case and demonstrate:

- Cross-source Snort and Wazuh evidence
- Correlated SSH attack sequence
- Explainable risk and severity
- MITRE ATT&CK mapping
- Evidence-grounded Copilot summary
- Investigation hypotheses and recommended next steps
- Draft analyst notes
- Case ownership and status workflow
- Append-only case and identity audit history
- Role-aware administrative controls

The fallback Copilot provider is deterministic and requires no external model credentials.

## 7. Show operational controls

In another terminal, verify the public health endpoints:

```bash
curl -i http://127.0.0.1:8000/health/live
curl -i http://127.0.0.1:8000/health/ready
```

The responses should include security headers and an `X-Request-ID`.

The protected operational endpoints are:

```text
GET /metrics
GET /configuration
```

They require the `X-SOC-API-Key` header.

## 8. Explain the architecture

Use this summary during the presentation:

```text
Snort and Wazuh telemetry
        |
        v
Input validation and normalization
        |
        v
Cross-source correlation
        |
        v
Risk scoring and MITRE ATT&CK mapping
        |
        v
Evidence-grounded Copilot assistance
        |
        v
Persistent SOC case and audit trail
        |
        v
Authenticated analyst investigation
```

## 9. Clean up

Stop Uvicorn with `Ctrl+C`, then remove temporary state:

```bash
rm -f /tmp/ai-soc-v2-demo.db
unset SOC_API_KEY
unset SOC_SESSION_SECRET
unset SOC_CASE_DATABASE
unset SOC_INPUT_ROOT
unset SOC_DEPLOYMENT_MODE
unset SOC_SESSION_HTTPS_ONLY
unset SOC_ENABLE_HSTS
unset SOC_LOG_FORMAT
unset SOC_LOG_LEVEL
```

No AWS account, paid service, production secret, or live containment action is required for this demo.
