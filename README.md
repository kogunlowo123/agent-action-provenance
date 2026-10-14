# Agent Action Provenance

Tamper-evident provenance for every action an AI agent takes. When an agent
writes a FHIR task, changes infrastructure or releases a batch record, it (or
the gateway in front of it) submits what it decided, the evidence it relied
on and the authorization it acted under. The engine turns that into a W3C
PROV record, checks it against governance rules, seals it into an
append-only Merkle transparency log (RFC 6962 hashing, signed tree heads),
writes a signed audit event, and returns an inclusion proof. Auditors export
self-verifying evidence bundles and check them offline; independent monitors
prove the log was never rewritten.

```
Decision ─▶ Evidence ─▶ Authorization ─▶ Audit Record
   │            │              │               │
   └── W3C PROV document ──────┴── governance ─┴─▶ Merkle leaf ─▶ signed tree head
                                                     │                 │
                                     inclusion proof ◀┘   consistency proof, WORM archive
```

## Capabilities

| Capability | Implementation |
|---|---|
| Provenance records | W3C PROV-JSON per action: decide / authorize / act activities, evidence and output entities, `used`, `wasGeneratedBy`, `wasDerivedFrom`, `wasAssociatedWith` (with the policy as `prov:Plan`), `wasAttributedTo`, `actedOnBehalfOf` for the delegation chain, `wasInformedBy` |
| PROV validation | Referential integrity, unique generation, acyclic derivation, activity time ordering |
| Governance checks | Executed without authorization, executed despite deny, approval missing / after execution / self-approval, authorization after execution, evidence after action, high-risk on untrusted or no evidence, classification downgrade |
| Transparency log | RFC 6962 / RFC 9162 Merkle tree in PostgreSQL; perfect-subtree node store, `O(log n)` proofs from one query; group commit batches records under one Ed25519 signed tree head |
| Proofs | Inclusion (audit path) and consistency proofs, verified exactly as RFC 9162 sections 2.1.3.2 and 2.1.4.2 specify; tested against the Certificate Transparency vectors and tamper cases |
| Signed evidence chain | agentic-core hash-chained, Ed25519-signed audit events for every record, decision, export and archive write |
| Self-monitoring | Recomputes the signed root from stored nodes, re-hashes the latest batch's records, proves append-only growth since the last check; detects edits, forged heads and rollbacks |
| Auditor export | Frozen record selection, policy-governed (RESTRICTED data or bulk exports need a second approver), self-verifying bundle |
| Verification CLI | `provenance-verify bundle / consistency / monitor / archive / audit-chain / keygen`, all against a pinned public key |
| WORM storage | S3 Object Lock (COMPLIANCE, conditional create, SHA-256 checksum) or write-once files shipped to immutable blob storage |
| Agent identity | Agents authorized through agent-identity-fabric (`/oauth2/introspect`, `/v1/authorize`); local JWKS verification plus policy when the fabric URL is not configured; never "allow all" |
| MCP | Six tools over streamable HTTP at `/mcp` (official `mcp` SDK), typed schemas, per-tool authorization and audit |
| A2A | Agent Card at `/.well-known/agent-card.json`; JSON-RPC `message/send` at `/a2a` |
| Lineage | Which actions, agents and evidence produced an artifact, transitively, by content digest |

Shared controls (policy engine, audit chain, logging, telemetry, canonical
JSON) come from [agentic-core](https://github.com/kogunlowo123/agentic-core).

## Quick start (local)

Requires Docker. No API keys or cloud credentials are needed.

```bash
docker compose up --build
curl -s localhost:8080/v1/log/tree-head | jq
curl -s localhost:8080/.well-known/agent-card.json | jq .skills[].id
```

The compose stack runs PostgreSQL, an OIDC provider standing in for both the
agent credential issuer and the auditors' IdP, and an OpenTelemetry collector.

## Development

```bash
uv sync
make check        # ruff, black, mypy --strict, bandit, contracts, tests (coverage >= 90%)
make integration  # PostgreSQL concurrency test (needs PROVENANCE_TEST_DATABASE_URL)
make helm terraform audit-deps
```

Test suites: `tests/unit` (Merkle tree against RFC 6962 vectors and a direct
transcription of the RFC definitions, PROV, governance, verification,
adapters, CLI), `tests/security` (tampering, forged heads, rollback,
credential attacks), `tests/chaos` (database, sequencer, identity fabric,
audit sink and archive failures), `tests/performance` (proof and group-commit
budgets; `locustfile.py` for load), `tests/e2e` (REST, MCP and A2A lifecycle,
offline bundle verification, property-based OpenAPI contract test),
`tests/integration` (two replicas appending concurrently to PostgreSQL).

## API

| Endpoint | Caller | Purpose |
|---|---|---|
| `POST /v1/records` | Agent or gateway (agent credential) | Seal an action; returns receipt, signed tree head, inclusion proof |
| `GET /v1/log/tree-head[?tree_size=]` | Anyone | Latest (or historical) signed tree head |
| `GET /v1/log/proof/inclusion?leaf_index=&tree_size=` | Anyone | RFC 6962 audit path |
| `GET /v1/log/proof/consistency?first=&second=` | Anyone | RFC 6962 consistency proof |
| `GET /v1/log/entries?start=&end=` | Anyone | Leaf hashes and record IDs |
| `GET /v1/log/public-key` | Anyone | Log ID and Ed25519 public key |
| `GET /v1/records`, `/v1/records/{id}`, `/v1/records/{id}/verification` | Auditor (`provenance-auditor`) | Search, read, verify |
| `GET /v1/lineage/{sha256:...}` | Auditor | Artifact lineage |
| `POST /v1/exports`, `GET /v1/exports/{id}`, `POST /v1/exports/{id}/approve`, `GET /v1/exports/{id}/bundle` | Auditor, approver (`provenance-approver`) | Governed evidence export |
| `POST /mcp` | Agents | MCP tools: `record_action`, `get_tree_head`, `get_inclusion_proof`, `get_consistency_proof`, `verify_record`, `trace_lineage` |
| `GET /.well-known/agent-card.json`, `POST /a2a` | Agents | A2A skills: `record-action`, `verify-record`, `inclusion-proof`, `consistency-proof` |

Log reads are unauthenticated by design: they reveal hashes only, and a
transparency log is only useful if anyone can check it. Full contract:
[docs/api/openapi.json](docs/api/openapi.json); JSON Schemas in [schemas/](schemas/).

## Verifying evidence offline

```bash
provenance-verify bundle bundle.json --public-key log.pub.pem
provenance-verify monitor --url "$PROVENANCE_URL" \
  --public-key log.pub.pem --state monitor-state.json   # run on a schedule
```

## Deployment

| Layer | Location |
|---|---|
| Container image | `Dockerfile` (non-root uid 10001, read-only root filesystem compatible) |
| Helm chart | `deployments/helm/agent-action-provenance` (StatefulSet, PDB, HPA, NetworkPolicy, ServiceMonitor, Ingress) |
| Namespace and secret sync | `deployments/kubernetes` (restricted Pod Security, default-deny, External Secrets) |
| Cloud infrastructure | `deployments/terraform/{aws,azure,gcp}`: managed PostgreSQL, KMS, secret store, WORM archive, workload identity. AWS is the reference deployment |

See the [startup runbook](docs/runbooks/startup.md).

## Documentation

- [Architecture](docs/architecture/overview.md), [agent specification](docs/architecture/agent-specification.md), [integrations: identity, MCP, A2A](docs/architecture/integrations.md), [acceptance criteria](docs/architecture/acceptance-criteria.md)
- [ADRs](docs/architecture/adr/)
- [Threat model and risk register](docs/security/threat-model.md)
- [Compliance control mapping](docs/compliance/control-mapping.md)
- Runbooks: [startup](docs/runbooks/startup.md), [monitoring](docs/runbooks/monitoring.md), [incident response](docs/runbooks/incident-response.md), [key rotation](docs/runbooks/key-rotation.md), [rollback](docs/runbooks/rollback.md), [disaster recovery](docs/runbooks/disaster-recovery.md)
- [Configuration reference](docs/operations/configuration.md), [observability](docs/operations/observability.md), [cost and scalability](docs/operations/cost-and-scalability.md)

## License

Apache-2.0
