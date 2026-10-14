# Observability

## Metrics (`/metrics`, Prometheus text format, own registry)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `provenance_http_request_duration_seconds` | histogram | method, route, status | Request latency and outcome |
| `provenance_records_total` | counter | status, compliant | Records sealed |
| `provenance_governance_findings_total` | counter | code, severity | Governance findings |
| `provenance_batch_size` | histogram | | Records per group commit |
| `provenance_batch_seal_seconds` | histogram | | Append + sign duration |
| `provenance_batch_failures_total` | counter | | Batches that failed to commit |
| `provenance_log_tree_size` | gauge | | Leaves under the latest signed head |
| `provenance_archive_backlog` | gauge | | Sealed batches not yet in WORM storage |
| `provenance_archive_failures_total` | counter | | Failed archive sweeps |
| `provenance_integrity_checks_total` | counter | result | Self-monitoring outcomes |
| `provenance_authorization_decisions_total` | counter | action, decision | Caller authorization outcomes |
| `provenance_exports_total` | counter | status | Export requests and approvals |

Recording rule and alerts: `configs/prometheus/alerts.yaml`. Dashboard:
`configs/grafana/agent-action-provenance.json`.

## Traces

OpenTelemetry via agentic-core `configure_telemetry`; FastAPI server spans
(health, readiness and metrics excluded) exported over OTLP gRPC. The local
collector config (`deployments/docker/otel-collector.yaml`) strips
`Authorization` headers before export.

## Logs

JSON on stdout (structlog via agentic-core) with `service`, `environment`,
`correlation_id`; sensitive keys are redacted. Key events: `startup`,
`batch_commit_failed`, `batch_conflict_retrying_individually`,
`log_integrity_failure`, `archive_failed`, `integrity_check_failed`.

## Audit

Per-replica signed audit chains (`audit/<pod>.jsonl`), verifiable with
`provenance-verify audit-chain`. Actions: `provenance.record`,
`provenance:*` authorization denials, `export.request`, `export.approve`,
`export.download`, `archive.put`, `log.integrity`, `mcp.<tool>`, `a2a.<skill>`.
