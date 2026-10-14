# ADR-0002: Group commit with a single row-locked sequencer in PostgreSQL

- Status: Accepted
- Date: 2026-10-14

## Context

A Merkle log has exactly one valid order. With three or more replicas behind
a load balancer, appends must be serialized or the tree forks. Signing a tree
head and committing a transaction per record would make the signature and
fsync the throughput ceiling. Options considered:

1. Single-replica writer (leader election): adds a coordination system and a
   failover gap.
2. Per-replica trees merged later: complicates proofs and auditing.
3. Serialize appends in the database every replica already shares.

## Decision

Option 3. `append_batch` runs in one transaction that takes
`SELECT tree_size FROM log_state WHERE id = 1 FOR UPDATE`, reads the
frontier nodes, computes the new leaves, completed perfect subtrees and root,
signs the tree head, and inserts everything before committing. Each replica
batches concurrent requests (up to `PROVENANCE_BATCH_MAX_SIZE` records or
`PROVENANCE_BATCH_MAX_WAIT_MS`) so one lock acquisition, one signature and
one commit serve the whole batch. The ledger also returns every record's
audit path, computed from nodes already in memory, so the receipt needs no
extra reads.

Duplicates of the same `(agent_id, action_id)` in a batch collapse onto the
first; a unique-constraint failure (a concurrent replica appended the same
action) retries the batch record by record and resolves the duplicate as an
idempotent retry.

## Consequences

- No forks: proven by the PostgreSQL integration test with two engines
  appending concurrently.
- Write throughput is bounded by one transaction at a time; batching
  amortizes it. Sizing guidance is in `docs/operations/cost-and-scalability.md`.
- Request latency includes up to `batch_max_wait_ms` (default 50 ms).
- A database outage stops recording (fail closed, readiness 503), which is the
  intended behaviour for an evidence system.
