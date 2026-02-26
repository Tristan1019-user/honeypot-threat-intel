# Security

## Scope
This project publishes threat intelligence from an internet-exposed SSH honeypot.
It is intended for enrichment, triage, and defensive research — not sole-source blocking.

## Security posture
- API runtime uses PostgreSQL in production mode.
- PostgreSQL is not exposed on host ports (container-network only).
- Admin endpoints are restricted to direct LAN/localhost and support admin token auth.
- Internal/private IP topology is scrubbed from outward-facing payloads.
- Credentials are never intentionally exposed by API responses.

## Secret handling
- Do **not** commit secrets (API keys, passwords, tokens) to git.
- Use runtime env (`.env`) only.
- `.env` is gitignored; keep permissions restrictive (`chmod 600 .env`).
- Rotate leaked/posted keys immediately.

## Backups and recovery
- Nightly PostgreSQL backup: `/usr/local/sbin/oc_pg_backup.sh`
- Weekly restore drill: `/usr/local/sbin/oc_pg_restore_test.sh`
- Logs: `/var/log/oc_pg_backup.log`, `/var/log/oc_pg_restore_test.log`

## Operational checks
- Health: `/api/v1/health`
- Startup checks: `/api/v1/startup-check`
- DB diagnostics: `/api/v1/db`
- Pipeline quality/freshness: `/api/v1/quality`

## Reporting security issues
If you find a security issue, do not open a public issue with exploit details.
Report privately to the maintainer and include:
- affected endpoint/module
- reproduction steps
- observed impact
- suggested remediation
