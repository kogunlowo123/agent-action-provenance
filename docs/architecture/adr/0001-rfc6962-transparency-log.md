# ADR-0001: RFC 6962 Merkle transparency log on top of the agentic-core audit chain

- Status: Accepted
- Date: 2026-10-14

## Context

agentic-core already provides a hash-chained, Ed25519-signed audit log
(agentic-core ADR-0004). A hash chain proves that a sequence was not altered,
but proving that *one* record is in the chain requires the whole chain, and
proving that today's chain extends last month's requires replaying it. An
auditor holding a single record, or a monitor checking the log hourly, needs
logarithmic proofs. Agent volumes also make "send the whole chain" untenable.

## Decision

Seal every provenance record as a leaf of a Merkle tree with RFC 6962
hashing (`0x00` leaf prefix, `0x01` node prefix, split at the largest power
of two smaller than `n`), sign tree heads with Ed25519, and serve RFC 6962
inclusion and consistency proofs verified with the RFC 9162 algorithms.
Keep the agentic-core audit chain for *who did what to the engine*
(recording, exports, approvals, archive writes, integrity failures) and
reference the leaf index and root from each audit event, so the two chains
cross-anchor.

Implement the algorithms in `domain/merkle.py` rather than depending on a
third-party CT library: the code is short, the CT test vectors and a direct
transcription of the RFC definitions are in the test suite, and the database
layer needs the planning/assembly split (`inclusion_ranges` → `nodes_for` →
`assemble`) that general libraries do not expose.

## Consequences

- Inclusion and consistency proofs are `O(log n)` hashes; verification needs
  only the leaf, the proof and a signed root.
- Domain separation prevents second-preimage attacks (interior node presented
  as a leaf); covered by tests.
- Signed tree heads are the trust anchor: the log key is CRITICAL (see
  key-rotation runbook) and monitors must pin it.
- Any compatible verifier (for example CT tooling, given the leaf bytes) can
  check proofs; the leaf format is documented in `schemas/provenance-record`.
