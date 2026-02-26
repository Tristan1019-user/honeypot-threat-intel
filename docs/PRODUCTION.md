# Production Runbook

This runbook documents operational checks, deployment, rollback, and incident triage for the Threat Intel API.

## 1) Health checks

Core checks:

```bash
curl -fsS https://threat-intel.101904.xyz/api/v1/health | jq .
curl -fsS https://threat-intel.101904.xyz/api/v1/startup-check | jq .
curl -fsS https://threat-intel.101904.xyz/api/v1/quality | jq .
```

Interpretation:
- `health.status=ok`: API process is alive and can query DB stats
- `startup-check.status=ok`: required tables exist and `pipeline_state.json` is readable
- `quality.freshness`: pipeline heartbeat freshness (`fresh|stale|degraded`)
- `quality.pipeline.data_freshness`: recency of actual inserted data (can degrade when no new attacks occur)

## 2) Deploy

Use the reproducible script:

```bash
./scripts/deploy_ct103.sh
```

The script:
1. Packages all `app/**/*.py` files
2. Pushes them into CT103 stack path
3. Restarts `threat-intel-api`
4. Verifies `/api/v1/health` and `/api/v1/startup-check`

## 3) Rollback (fast path)

If a deployment introduces issues:

1. Identify previous known-good commit in GitHub
2. Checkout/reset locally to that commit
3. Re-run deploy script

```bash
git checkout <known-good-sha>
./scripts/deploy_ct103.sh
```

## 4) Incident triage checklist

1. API healthy?
   - Check `/api/v1/health`
2. Schema/state healthy?
   - Check `/api/v1/startup-check`
3. Pipeline stale?
   - Check `/api/v1/quality`
   - Validate `pipeline.last_run` and `pipeline.data_freshness`
4. Ingest path healthy?
   - Verify Cowrie log file is updating
   - Verify `pipeline_state.json` last_run changes after pipeline execution
5. Container/service healthy?
   - Restart `threat-intel-api` if needed

## 5) CI gate expectations

Current CI must pass before merge/deploy:
- Ruff lint
- Mypy (app scope)
- Pytest
- API smoke test

If CI fails, fix on branch and re-run before deploy.
