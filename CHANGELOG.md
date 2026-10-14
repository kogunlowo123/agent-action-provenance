# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-14

### Added

- Action submission model covering decision, evidence, authorization (with approval) and outputs.
- W3C PROV-JSON document per action, with PROV constraint validation.
- Deterministic governance checks sealed into every record.
- RFC 6962 / RFC 9162 Merkle transparency log on PostgreSQL with perfect-subtree node
  storage, group commit and Ed25519 signed tree heads.
- Inclusion and consistency proofs (REST, MCP, A2A) and RFC 9162 verification.
- agentic-core signed audit chain for records, decisions, exports and archive writes.
- Log self-monitoring: signed-root recomputation, leaf re-hashing, append-only proof.
- Governed auditor exports with second-person approval and self-verifying bundles.
- `provenance-verify` CLI: bundle, consistency, monitor, archive replay, audit-chain, keygen.
- WORM archival to S3 Object Lock or write-once files.
- Agent authorization through agent-identity-fabric or local JWKS plus policy.
- MCP server (six tools) and A2A Agent Card with JSON-RPC `message/send`.
- Artifact lineage queries.
- Helm chart, Kubernetes namespace and secret sync, Terraform for AWS, Azure and GCP.
- CI: lint, types, SAST, contract drift, tests (unit, security, chaos, performance, e2e,
  PostgreSQL integration), Helm/kubeconform, Terraform validate, Trivy, Syft, Grype,
  Semgrep, container smoke test.
