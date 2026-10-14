# Agent specification

The provenance engine is a platform agent in its own right: it acts on behalf
of the enterprise's audit function, holds signing keys and decides who may
take evidence out of the system. This document states its mandate in the
same terms agent-identity-fabric requires of every registered agent.

## Role and mission

- **Purpose:** be the system of record for what AI agents did, why, and under
  which authorization, in a form that cannot be altered without detection.
- **Business objective:** make agent actions as accountable as human actions
  for internal audit, SOX, HIPAA, GxP and incident response, without trusting
  the operators of the agent platform.
- **Protected resources:** sealed records, the transparency log and its signing
  key, the audit chain and its key, export approvals.
- **Operating boundaries:** records and proves; never executes or blocks agent
  actions itself (policy enforcement happens before the action, in the
  identity fabric and gateway); never stores evidence content, only digests.
- **Delegated responsibility:** export governance is delegated to the
  versioned `policies/evidence-export.yaml`, owned by the audit function.

## Delegated scope

| Allowed | Disallowed | Risk | Escalation |
|---|---|---|---|
| Accept records from agents for their own actions | Record on behalf of another agent without `provenance:record:delegate` | MODERATE | Denials audited; deny-spike alert |
| Accept records from an authenticated gateway | Accept gateway records under a delegated credential | MODERATE | Policy deny `deny-delegated-recording-by-delegates` |
| Record governance violations | Refuse to record an action because it violates governance | LOW | Violations alert (`ProvenanceGovernanceViolations`) |
| Release CONFIDENTIAL evidence to an auditor | Release RESTRICTED evidence or >500 records without a second person | HIGH | `require_approval`; requester cannot approve |
| Sign tree heads | Sign a head that does not extend the previous one | CRITICAL | Integrity alert pages security |
| Archive sealed batches | Overwrite or delete archived objects | CRITICAL | S3 COMPLIANCE lock; conditional create |

## Objectives

| Type | Definition | Target |
|---|---|---|
| SLO availability | Non-5xx share of `POST /v1/records` | 99.9% over 30 days |
| SLO latency | p99 `POST /v1/records` (includes group-commit wait) | < 500 ms |
| SLO durability | Sealed batch in WORM storage | < 15 min (archive backlog alert) |
| SLO integrity | Failed self-monitoring checks | 0 |
| SLI | `provenance:record_errors:ratio_5m`, latency histograms, `provenance_archive_backlog`, `provenance_integrity_checks_total` | Prometheus |
| KPI | Share of consequential agent actions with a sealed record | 100% for agents behind the gateway |
| KPI | Records with governance violations, by code | Trending to zero; every one triaged |
| KPI | Time to answer an auditor's "show me" request | Minutes (export + offline verification) |
| Completion | A record is complete when its leaf is under a signed tree head and its audit event is written | Enforced: receipt returned only after both |

## Permissions

| Mechanism | Use |
|---|---|
| Agent identity | SPIFFE IDs issued by agent-identity-fabric; the submitting credential's subject is recorded as `recorded_by` |
| OAuth 2.0 | Agent bearer credentials; RFC 7662 introspection and `/v1/authorize` at the fabric |
| ABAC | Action `provenance:record:write` (own actions) or `provenance:record:delegate` (gateway), resource attributes `own_action`, `agent_id`, classification; local `policies/provenance-access.yaml` when the fabric is not configured |
| RBAC | Auditor roles `provenance-auditor`, `provenance-approver` from the enterprise IdP (OIDC) |
| Two-person rule | Export approver must differ from the requester |
| Workload identity | IRSA / Azure Workload ID / GKE Workload Identity for archive writes; no static cloud keys |

## Inputs and outputs

| Contract | Schema |
|---|---|
| Action submission | `schemas/action-submission.request.schema.json` |
| Record receipt | `schemas/record-receipt.response.schema.json` |
| Sealed record (Merkle leaf) | `schemas/provenance-record.schema.json` |
| Signed tree head, inclusion and consistency proofs | `schemas/signed-tree-head.schema.json`, `inclusion-proof`, `consistency-proof` |
| Export criteria, export, bundle, bundle verification | `schemas/export-criteria.request`, `export.response`, `evidence-bundle`, `bundle-verification` |
| Verification report, lineage graph | `schemas/verification-report.response`, `lineage-graph.response` |

### Validation

- Inputs reject unknown fields; digests must be `sha256:<64 hex>`; agent IDs
  must be SPIFFE URIs; action names match `^[a-z0-9][a-z0-9_.:*-]{0,199}$`;
  `ended_at >= started_at`; evidence and output digests are unique and disjoint.
- Bounded sizes: 256 evidence items, 256 outputs, 10 principals in the
  delegation chain, 8,000-character rationale.
- The generated PROV document must satisfy referential integrity, unique
  generation, acyclic derivation and time ordering, or the submission is
  rejected with `invalid_record` (422) and nothing is sealed.

### Provenance and audit metadata

Every record carries `record_id`, `recorded_at`, `recorded_by`,
`submission_digest`, the PROV document, governance findings, and (in the
receipt) leaf index, leaf hash, signed tree head and audit path. Every
recording, authorization denial, export request, approval, download, archive
write and integrity failure produces an agentic-core audit event with actor,
action, resource, outcome, correlation ID and details, hash-chained and
Ed25519-signed.
