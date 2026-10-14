# ADR-0004: S3 Object Lock archive plus continuous self-monitoring

- Status: Accepted
- Date: 2026-10-14

## Context

A Merkle log detects tampering only if someone compares against a previously
seen signed head. The database is mutable by its administrators. Regulators
(SEC 17a-4(f), FINRA 4511, 21 CFR Part 11) expect records on non-rewriteable,
non-erasable storage.

## Decision

1. **Archive every sealed batch** as one self-verifying object (signed tree
   head, log public key, every record in the batch) to S3 with Object Lock in
   COMPLIANCE mode, per-object retain-until date, `If-None-Match: *`
   conditional create and an S3-verified SHA-256 checksum. A retry with
   identical bytes is idempotent; different bytes under the same key fail
   loudly. Archival is asynchronous (outbox: `tree_heads.archived_at`), so a
   storage outage delays archiving but never loses data; the backlog is a
   metric and pages after 15 minutes. Azure and GCP deployments use the
   write-once filesystem archive on the replica volume, replicated to an
   immutable blob container or retention-locked bucket provisioned by
   Terraform.
2. **Self-monitor** in every replica: verify the latest head's signature,
   recompute its root from stored nodes, re-hash the latest batch's records,
   and prove consistency with the last head this replica verified. Failures
   are audited, counted and page security.
3. **External monitors** run `provenance-verify monitor` with the pinned
   public key, outside the platform's trust boundary.

## Consequences

- Rewriting history requires the log key *and* deleting COMPLIANCE-locked
  objects, which no principal can do before retention expires.
- The engine needs only `s3:PutObject`, `s3:PutObjectRetention` and
  `s3:GetObject` on its prefix; the bucket policy denies governance bypass.
- Self-monitoring cannot detect an attacker who holds the log key and
  rewrites the database consistently; the WORM archive and external monitors
  can.
