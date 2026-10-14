# ADR-0005: Public log reads, governed record exports

- Status: Accepted
- Date: 2026-10-14

## Context

Two audiences need different things. Monitors need tree heads and proofs,
often from outside the agent platform and without enterprise credentials.
Auditors need record content, which can describe PHI-bearing evidence (by
URI and digest), approvers and decisions.

## Decision

- `/v1/log/*` (tree heads, proofs, leaf hashes, public key) is unauthenticated.
  It reveals only SHA-256 hashes of records that include random record IDs and
  timestamps, so content cannot be brute-forced from leaf hashes.
- Record content, lineage and exports require enterprise OIDC with
  `provenance-auditor`; approvals require `provenance-approver`.
- Exports freeze the record selection at request time and are evaluated by
  `policies/evidence-export.yaml`: RESTRICTED data or more than 500 records
  require approval by a different person; non-auditors fall through to the
  default deny. Only the requester can download the bundle.
- Bundles embed proofs against the latest signed head and the log public key,
  but the verifier always checks against a key pinned out of band.

## Consequences

- Anyone can monitor the log; nobody can read records without a role.
- Two-person control on sensitive evidence is enforced in code and policy, and
  every request, approval and download is in the signed audit chain.
- MCP and A2A read tools still require an agent credential, because they also
  serve verification and lineage, which reveal record metadata.
