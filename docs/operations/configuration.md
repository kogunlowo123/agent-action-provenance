# Configuration reference

All settings are `PROVENANCE_*` environment variables (see
`src/agent_action_provenance/config.py`). The service refuses to start with
incomplete configuration.

| Variable | Required | Default | Description |
|---|---|---|---|
| `PROVENANCE_ENVIRONMENT` | no | `production` | `production` forbids ephemeral keys |
| `PROVENANCE_PUBLIC_URL` | yes | | Public base URL (A2A card, MCP host allow-list) |
| `PROVENANCE_DATABASE_URL` | yes | | SQLAlchemy async URL (`postgresql+asyncpg://…`) |
| `PROVENANCE_LOG_KEY_FILE` | yes* | | Ed25519 PEM that signs tree heads |
| `PROVENANCE_AUDIT_KEY_FILE` | yes* | | Ed25519 PEM for the audit chain; file stem is the audit key ID |
| `PROVENANCE_DEV_EPHEMERAL_KEYS` | no | `false` | In-memory keys, non-production only (replaces the * settings) |
| `PROVENANCE_AUDIT_LOG_PATH` | no | `/var/lib/agent-action-provenance/audit/audit.jsonl` | Audit chain file |
| `PROVENANCE_FABRIC_URL` | one of | | agent-identity-fabric base URL (introspection + authorization) |
| `PROVENANCE_AGENT_ISSUER`, `_AGENT_AUDIENCE`, `_AGENT_JWKS_URL` | one of | audience `agent-platform` | Local verification of agent credentials when the fabric URL is unset |
| `PROVENANCE_ACCESS_POLICY_FILE` | no | `policies/provenance-access.yaml` | Local agent access policy |
| `PROVENANCE_AUDITOR_ISSUER`, `_AUDITOR_AUDIENCE`, `_AUDITOR_JWKS_URL` | yes | | Enterprise OIDC for auditors |
| `PROVENANCE_AUDITOR_ROLES_CLAIM` | no | `roles` | Claim carrying auditor roles |
| `PROVENANCE_EXPORT_POLICY_FILE` | no | `policies/evidence-export.yaml` | Export governance |
| `PROVENANCE_EXPORT_MAX_RECORDS` | no | `1000` | 1–10000 |
| `PROVENANCE_BATCH_MAX_SIZE` | no | `256` | Records per group commit (1–10000) |
| `PROVENANCE_BATCH_MAX_WAIT_MS` | no | `50` | Wait for more records after the first (0–5000) |
| `PROVENANCE_ARCHIVE_BACKEND` | no | `filesystem` | `filesystem` or `s3` (the Helm chart defaults to `s3`) |
| `PROVENANCE_ARCHIVE_DIR` | no | `/var/lib/agent-action-provenance/archive` | Filesystem archive root |
| `PROVENANCE_ARCHIVE_BUCKET` | for s3 | | Object Lock bucket |
| `PROVENANCE_ARCHIVE_PREFIX` | no | `agent-action-provenance` | Key prefix |
| `PROVENANCE_ARCHIVE_REGION` | no | | S3 region (default from the environment) |
| `PROVENANCE_ARCHIVE_LOCK_MODE` | no | `COMPLIANCE` | `COMPLIANCE` or `GOVERNANCE` |
| `PROVENANCE_ARCHIVE_RETENTION_DAYS` | no | `2555` | Per-object retain-until |
| `PROVENANCE_ARCHIVE_INTERVAL_S` | no | `30` | Archive sweep interval (also woken by every sealed batch) |
| `PROVENANCE_MONITOR_INTERVAL_S` | no | `60` | Integrity self-check interval |
| `PROVENANCE_MCP_ALLOWED_HOSTS` | no | `[]` | JSON list of extra Host headers accepted by `/mcp` |
| `PROVENANCE_LOG_LEVEL` | no | `INFO` | |
| `PROVENANCE_OTLP_ENDPOINT` | no | | OTLP gRPC endpoint for traces |
| `PROVENANCE_HOST` / `PROVENANCE_PORT` | no | `127.0.0.1` / `8080` | The container image sets host `0.0.0.0` |
| `PROVENANCE_FORWARDED_ALLOW_IPS` | no | `127.0.0.1` | Proxies trusted for `X-Forwarded-*` |
