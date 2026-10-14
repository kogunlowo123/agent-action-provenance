# Runbook: monitoring

## Signals

| Signal | Source | Normal |
|---|---|---|
| `provenance:record_errors:ratio_5m` | Recording rule | < 0.001 |
| p99 `POST /v1/records` | `provenance_http_request_duration_seconds` | < 500 ms |
| `provenance_integrity_checks_total{result="failed"}` | Self-monitoring | 0, ever |
| `provenance_archive_backlog` | Archiver | 0–2 |
| `provenance_batch_size` median | Sequencer | Grows with load; 1 at low traffic |
| `provenance_governance_findings_total{severity="violation"}` | Records | Each one triaged |
| External monitor report | `provenance-verify monitor` | `valid: true` every run |

## Latency

1. Dashboard "p99 latency by route": is it `/v1/records` only?
2. Compare with "Batch size and seal latency". High seal latency with large
   batches: database write latency (check RDS write IOPS and locks). High
   seal latency with small batches: lock contention or a slow commit; check
   `pg_stat_activity` for waits on `log_state`.
3. Recording latency includes `batch_max_wait_ms` by design; lowering it
   trades throughput for latency.
4. `/v1/records` slow but seal fast: identity fabric introspection or
   authorization latency; check the fabric's own dashboard.

## Self-monitoring

`ProvenanceIntegrityChecksStopped` means no replica has run a check for 15
minutes: confirm pods are running (`kubectl get pods`), then look for
`integrity_check_failed` in logs (database errors). Checks resume
automatically.

## Tracing a request

Every response carries `X-Correlation-ID`. Search logs and audit chains:
`jq 'select(.correlation_id=="<id>")' <pod>.jsonl`. The `provenance.record`
event holds the record ID, leaf index and signed root.
