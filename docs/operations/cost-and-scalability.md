# Cost and scalability

## Write path

All replicas append through one row lock, so write throughput is that of a
single serialized PostgreSQL transaction stream. Group commit makes each
transaction carry up to `batch_max_size` records, so the lock, the Ed25519
signature and the commit are paid once per batch. Per-batch work:

- reads: one row lock, frontier nodes (`O(log n)` rows, one query);
- writes: `b` leaves, `b` records, about `b` new nodes (a batch of `b` leaves
  completes at most `b + log n` perfect subtrees), lineage links, one tree head.

The in-repository performance test sustains more than 40 records per second
on SQLite on a shared CI runner (300 concurrent submissions). PostgreSQL on
dedicated instances is substantially faster; measure with
`tests/performance/locustfile.py` against staging before committing to a
figure. If a single log becomes the bottleneck, run one log per business
domain (separate databases and log keys): proofs stay per log and monitors
track each log.

## Read path

Proofs need `O(log n)` node rows fetched with one indexed query; replicas
scale reads horizontally (HPA on CPU). Tree heads and proofs are cacheable by
`(tree_size)` at an ingress or CDN because they never change.

## Storage growth (per million records, order of magnitude)

| Item | Size |
|---|---|
| Records (canonical JSON with PROV) | about 6.5 KB for one evidence item and one output (measured), growing with evidence count; about 6.5 GB |
| Leaves and nodes | about 200 bytes per leaf including indexes, about 0.2 GB |
| Lineage links | about 0.3 GB |
| WORM archive | same as records, plus one tree head per batch |

## Cost drivers (AWS reference)

| Component | Driver |
|---|---|
| RDS PostgreSQL Multi-AZ (`db.r6g.large` default) | Instance hours, storage, PITR |
| EKS pods (3–10 replicas) | CPU for JSON canonicalization, hashing, JWT verification |
| S3 Object Lock | Stored GB for the retention period (7 years default); objects cannot be expired early, so size retention deliberately |
| KMS | Requests (bucket keys enabled to reduce them) |
| Secrets Manager | Three secrets |

Retention is the dominant long-term cost: COMPLIANCE mode prevents deleting
objects before their retain-until date. Choose `archive_retention_days`
from the regulatory requirement, not as a default.

## Availability

Three replicas across zones, PDB `minAvailable: 2`, Multi-AZ database.
Recording is unavailable during a database failover (seconds to a minute);
agents and gateways retry with the same `action_id`, which is idempotent.
