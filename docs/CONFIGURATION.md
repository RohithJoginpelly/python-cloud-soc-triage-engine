# Runtime Configuration

## Deployment modes

The application supports three deployment modes:

- `development`
- `testing`
- `production`

Configure the mode with:

```bash
export SOC_DEPLOYMENT_MODE=production
```

Production mode refuses to start when required security settings are missing or unsafe.

## Required production secrets

### SOC API key

`SOC_API_KEY` protects machine-to-machine API routes such as `/cases`, `/metrics`, and `/configuration`.

Generate a random value:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### Session secret

`SOC_SESSION_SECRET` signs browser session data. It must be independent from the API key.

Generate a separate value:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Never commit either secret to Git or paste it into documentation.

## Required production transport settings

```bash
export SOC_SESSION_HTTPS_ONLY=true
export SOC_ENABLE_HSTS=true
```

These settings require HTTPS. Enable HSTS only after HTTPS works correctly for the deployment domain.

## Recommended production logging

```bash
export SOC_LOG_FORMAT=json
export SOC_LOG_LEVEL=INFO
```

JSON logs include request IDs and safe operational fields. Passwords, API keys, authorization headers, session IDs, and tokens are excluded.

## Core path settings

```bash
export SOC_CASE_DATABASE=data/cases/soc_cases.db
export SOC_INPUT_ROOT=data/test_events
```

The database and telemetry directories must be writable and available to the application process.

## Safe configuration status

The protected endpoint below returns a secret-free configuration report:

```bash
curl \
  -H "X-SOC-API-Key: $SOC_API_KEY" \
  https://soc.example.edu/configuration
```

The response includes deployment mode, validation status, issue codes, and warning or error counts. It never returns configured secret values.

## Startup behavior

Development and testing modes allow weak or missing optional settings but report warnings.

Production mode blocks startup for:

- Missing or weak API keys
- Missing or weak session secrets
- Reused API and session secrets
- Cookies without the HTTPS-only flag
- Disabled HSTS

Structured JSON logging is recommended in production and currently produces a warning rather than blocking startup.
