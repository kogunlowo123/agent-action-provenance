# ADR-0006: StatefulSet with one signed audit chain per replica

- Status: Accepted
- Date: 2026-10-14

## Context

The agentic-core audit chain is append-serialized within a process. A single
chain shared by all replicas would need a distributed lock on every audit
write, on top of the ledger's row lock. The transparency log itself is shared
state in PostgreSQL and needs no per-replica storage.

## Decision

Run the engine as a StatefulSet (the portfolio standard reserves StatefulSets
for per-replica state). Each replica writes its own chain to its own
persistent volume (`audit/<pod-name>.jsonl`), signed with the shared audit
key. The platform log shipper (for example Fluent Bit's S3 output) copies
chains to the `audit-chains/` prefix of the Object Lock bucket, for which the
IRSA role already has write permission. Each audit event for a record carries
its leaf index and the signed root, so every chain is anchored to the shared
Merkle log, and correlation IDs connect events across chains.

## Consequences

- No cross-replica coordination for audit writes.
- Scaling down leaves a chain on a retained PVC that has already been shipped.
- Auditors verify N chains (`provenance-verify audit-chain` per file).
