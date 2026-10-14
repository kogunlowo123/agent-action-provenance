# ADR-0003: Record governance violations; never refuse evidence

- Status: Accepted
- Date: 2026-10-14

## Context

Some submitted actions break governance rules: executed despite a deny,
executed without the approval policy required, approved by the agent itself,
outputs labelled below their inputs. Refusing such submissions would look
strict, but the action has already happened; refusing to record it destroys
exactly the evidence an investigation needs and gives a misbehaving agent an
incentive to submit bad records so they are dropped.

## Decision

Validation that protects the integrity of the record itself (schema, digests,
SPIFFE IDs, PROV constraints such as acyclic derivation) rejects the
submission with 422 and seals nothing. Governance rules never reject: they
produce findings with a severity (`info`, `warning`, `violation`) that are
part of the sealed record (and therefore of the Merkle leaf), are counted in
`provenance_governance_findings_total`, mark the record `compliant: false`
and raise `ProvenanceGovernanceViolations`. Offline verification recomputes
the findings from the submission, so the recorder cannot under-report them.

Enforcement before the action remains the job of the identity fabric and the
gateway; this engine is the after-the-fact, tamper-evident witness.

## Consequences

- Investigations start from complete evidence, including bad actions.
- Findings are deterministic and versioned with the code. Any change to a
  rule, or to the PROV mapping, must bump `RECORD_SCHEMA_VERSION`
  (`aap-record/v1` today) so verifiers know which rule set to re-derive with;
  records already sealed are never re-assessed.
