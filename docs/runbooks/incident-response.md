# Runbook: incident response

## Integrity failure

`ProvenanceLogIntegrityFailure` or an external monitor reporting
`valid: false` is a security incident (possible tampering).

1. Page Security Ops; do not restart or "repair" anything yet.
2. Preserve state: snapshot the RDS instance; copy every replica's audit chain;
   save the failing monitor report and the last good monitor state file.
3. Identify the problem from the `log.integrity` audit event and the
   `log_integrity_failure` log line:
   - *leaf does not match its leaf hash*: a record row was edited. The WORM
     archive holds the original bytes (`batches/<tree_size>.json`).
   - *stored tree does not reproduce the signed root*: node rows were edited.
   - *tree head signature invalid*: a head row was replaced; check who could
     write to `tree_heads`.
   - *log shrank / not append-only*: rows were deleted or the database was
     restored from an older backup without the runbook (see disaster recovery).
4. Verify the WORM copy independently of the database:
   `aws s3 sync s3://<archive_bucket>/agent-action-provenance ./archive-copy`
   then `provenance-verify archive ./archive-copy --public-key log.pub.pem`.
   It replays every archived record into a fresh tree and checks each signed
   root; the result tells you the last trustworthy tree size.
5. Review database audit logs (RDS `postgresql` log export) and IAM activity
   for the window between the last good and first failed check.
6. Recovery is the disaster-recovery procedure "rebuild from archive"; the
   signing key must be rotated if there is any sign it was accessed.

## Record failures

`ProvenanceErrorBudgetBurnFast` / `ProvenanceBatchCommitFailures`:

1. `kubectl -n agent-provenance get pods`; `/readyz` reports
   `database unavailable` or `sequencer stopped`.
2. Database: check RDS events, connections, storage. Agents and the gateway
   retry with the same `action_id`; retries are idempotent, so no evidence is
   lost once the database recovers.
3. `temporarily_unavailable` responses with a healthy database: the identity
   fabric is unreachable or erroring (fail closed). Escalate to the fabric
   on-call.

## Archive backlog

`ProvenanceArchiveBacklog`: sealed batches are safe in PostgreSQL but not yet
in WORM storage.

1. Logs: `archive_failed` with the S3 error. Typical causes: IRSA role
   annotation missing, KMS key policy, bucket policy, S3 endpoint egress
   blocked by NetworkPolicy (port 443).
2. `archive_conflict` means an object already exists with different content
   under the same key: treat as an integrity incident (above).
3. Once fixed, the backlog drains automatically (oldest first).

## Governance violation

`ProvenanceGovernanceViolations{code=…}`: an agent executed an action that
broke a rule (for example `executed_despite_deny`, `approval_missing`,
`classification_downgrade`).

1. Find the records: `GET /v1/records?compliant=false&since=…` (auditor).
2. Trace impact: `GET /v1/lineage/<output digest>`.
3. Notify the agent's business owner (from its mandate in
   agent-identity-fabric) and, for `executed_despite_deny`, ask Security to
   suspend the agent at the fabric (`POST /v1/suspend`).
4. Export evidence for the investigation (`POST /v1/exports`).

## Deny spike

`ProvenanceAuthorizationDenySpike`: callers are being refused. Check the
`action` label: `provenance:record:write` denials usually mean agents lack the
scope after a fabric policy change; `provenance:record:delegate` denials mean
a gateway credential is delegated or missing the scope.

## Replicas down

`ProvenanceNotReady`: fewer than two replicas scraped. Check node pressure,
PVC binding (`kubectl describe pod`), and image pull. Recording continues on
any single ready replica.
