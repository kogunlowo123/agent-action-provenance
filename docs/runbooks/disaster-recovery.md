# Runbook: disaster recovery

| Target | Value |
|---|---|
| RPO (sealed records) | 0 for committed records with Multi-AZ; ≤ 5 min with PITR; 0 for archived batches |
| RTO | 1 hour |

## Zone or instance failure

Multi-AZ RDS fails over automatically; replicas reconnect (`pool_pre_ping`).
Recording returns 503 during failover; clients retry with the same
`action_id`.

## Region loss or database loss: restore

1. Restore the latest RDS snapshot or PITR to a new instance; update the
   `agent-action-provenance-database-url` secret; restart the StatefulSet.
2. **Prove the restored log is consistent with what the world has seen.**
   Run `provenance-verify monitor` with the external monitor's saved state.
   If the restored log is *smaller* than the last head monitors saw (PITR lost
   the newest batches), the monitor reports `log shrank`. Proceed to step 3;
   do not sign new heads over the gap.
3. Verify the archive copy first (`provenance-verify archive <dir>
   --public-key log.pub.pem`), then rebuild the missing tail from it: every
   `batches/<tree_size>.json` after the restored size contains the signed head
   and the exact record bytes. Re-append those records in order with the
   ledger (`SqlLedger.append_batch`) using the *same* log key; the recomputed
   roots must equal the archived signed roots for each batch. Verify with the
   monitor before reopening traffic.
4. Audit chains: per-replica chains on lost volumes are recovered from the
   `audit-chains/` prefix in the bucket.

## Restore drill (quarterly)

Restore a snapshot into a scratch environment, run step 2 against a copy of
the monitor state, rebuild one archived batch, and record the elapsed time
against the RTO.

## Key loss

If the log key is lost (not compromised), the existing log stays verifiable
with the published public key. Start a new log: generate a new key, deploy it
as a new `logKeyFile`, and record the hand-over (old log ID, final tree head,
new log ID) in the change record; publish the new public key to monitors.
