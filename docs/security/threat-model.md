# Threat model

## Assets

| Asset | Impact if compromised |
|---|---|
| Log signing key | Forge tree heads; with database access, rewrite history undetectably until compared with the WORM archive or a monitor's pinned head |
| Sealed records and Merkle state | Loss of evidence integrity; false exoneration or false blame |
| Audit-chain key | Forge or hide activity on the engine (exports, approvals) |
| Export approvals | Sensitive evidence leaves without two-person control |
| Recording path | Agents act without leaving evidence |

## Trust boundaries

1. Agents and gateways → engine API (network; credentials from agent-identity-fabric).
2. Auditors → engine API (enterprise OIDC).
3. Engine → identity fabric, IdP JWKS.
4. Engine → PostgreSQL (administrators of the database are *not* trusted with integrity).
5. Engine → WORM archive.
6. Independent monitors → public log endpoints.

## STRIDE

| ID | Threat | Category | Control | Test |
|---|---|---|---|---|
| T1 | DBA edits a sealed record | Tampering | Leaf = hash of exact record bytes; `verify_record`; integrity monitor re-hashes the latest batch; WORM copy | `tests/security::test_t1_edited_record_is_detected` |
| T2 | DBA rewrites Merkle nodes to hide an edit | Tampering | Monitor recomputes the root from nodes against the signed head | `test_t2_rewritten_tree_node_is_detected` |
| T3 | Forged or altered tree head | Spoofing / tampering | Ed25519 signature over canonical head; `log_id` bound to key | `test_t3_forged_tree_head_is_detected`, `TestSigningAndVerification` |
| T4 | Rollback / truncation of the log | Tampering / repudiation | Monitor proves append-only growth; external monitor detects shrink; consistency proofs | `test_t4_rollback_is_detected`, `TestCli::test_consistency_and_monitor` |
| T5 | Fork: different views to different verifiers | Tampering | Consistency proofs, pinned key, WORM archive of every head | `TestConsistency::test_detects_a_forked_log` |
| T6 | Second-preimage (node presented as leaf) | Tampering | RFC 6962 domain separation | `test_leaf_hash_is_not_accepted_as_node` |
| T7 | `alg: none`, forged or tampered agent credential | Spoofing | JWKS verification, fixed algorithm set, issuer and audience checks, or fabric introspection | `test_t6_alg_none_and_garbage`, `test_t7_*`, `test_t8_payload_tampering` |
| T8 | Agent records actions as another agent | Spoofing / repudiation | `own_action` attribute; delegate recording only with scope and not under delegation; `recorded_by` sealed | `test_t9_agent_cannot_impersonate_or_read_as_auditor`, `TestAuthorization` |
| T9 | Credentials or secrets leak into audit/records | Information disclosure | Only digests and URIs recorded; tokens never logged | `test_t5_audit_chain_carries_no_credentials` |
| T10 | Bulk or RESTRICTED evidence exfiltration by one insider | Information disclosure | Export policy, two-person approval, requester-only download, audit | `test_t10_export_requires_role_and_second_person`, `TestExports` |
| T11 | Oversized or malformed submissions | DoS / tampering | Bounded collections, `extra="forbid"`, digest patterns, paging limits | `test_t11_oversized_and_unknown_fields_rejected`, schemathesis |
| T12 | DNS rebinding against `/mcp` | Spoofing | Host allow-list (MCP transport security) | `test_t12_mcp_rejects_dns_rebinding` |
| T13 | Record silently dropped when audit or DB fails | Repudiation | Receipt only after commit and audit; failures surface; retries idempotent | `tests/chaos` |
| T14 | Recorder under-reports governance violations | Repudiation | Findings sealed; verifiers recompute them | `test_semantic_tampering_with_consistent_hashes` |
| T15 | Identity fabric outage leads to unauthenticated writes | Elevation | Fail closed (503) | `test_identity_fabric_outage_fails_closed` |

## MITRE ATT&CK (Enterprise)

| Technique | Mitigation |
|---|---|
| T1565.001 Data Manipulation: Stored Data Manipulation | Merkle leaves, signed heads, monitors, WORM |
| T1070 Indicator Removal (incl. T1070.002 Clear Linux or Mac System Logs) | Append-only log, COMPLIANCE object lock, rollback detection |
| T1485 Data Destruction | Object Lock, RDS backups and PITR, multi-AZ |
| T1078.004 Valid Accounts: Cloud Accounts | Workload identity, least-privilege IAM, no static keys |
| T1552 Unsecured Credentials | Keys in secret manager, mounted read-only, never in Terraform state |
| T1530 Data from Cloud Storage | Private bucket, TLS-only policy, KMS encryption |

## MITRE ATLAS (AI-specific)

| Technique | Relevance | Control |
|---|---|---|
| AML.T0051 LLM Prompt Injection | An injected agent may try to hide what it did | The agent cannot edit sealed records; gateway-side recording does not depend on the agent's cooperation |
| AML.T0048 External Harms | Disputed agent actions | Evidence of decision, inputs (digests), policy and approval |
| AML.T0054 LLM Jailbreak | Agent acts outside mandate | Governance findings (`executed_despite_deny`, `approval_missing`) alert |

## OWASP Top 10 for LLM Applications (2025)

| Risk | Control |
|---|---|
| LLM06 Excessive Agency | After-the-fact evidence of every action and its authorization; violations alert |
| LLM01 Prompt Injection | Records capture prompt and response digests, so injected inputs can be traced through lineage |
| LLM02 Sensitive Information Disclosure | No evidence content stored; classification-downgrade finding; governed exports |
| LLM05 Improper Output Handling | Outputs linked to their sources (`wasDerivedFrom`) for review |
| LLM09 Misinformation | Decision rationale and evidence trust levels recorded; high-risk-on-untrusted-evidence finding |

## OWASP API Security Top 10 (2023)

| Risk | Control |
|---|---|
| API1 BOLA | Agents record only their own actions (or as authorized gateway); records readable only by auditors |
| API2 Broken Authentication | JWKS-verified tokens or fabric introspection; issuer/audience checks |
| API3 Broken Object Property Level Authorization | `extra="forbid"`; responses are explicit view models |
| API4 Unrestricted Resource Consumption | Paging limits (≤500 records, ≤1000 entries), bounded submissions, export cap, HPA |
| API5 Broken Function Level Authorization | Separate auditor and approver roles; two-person rule |
| API8 Security Misconfiguration | Production refuses ephemeral keys; Helm `required`; restricted Pod Security; default-deny NetworkPolicy |
| API10 Unsafe Consumption of APIs | Fabric responses validated; malformed or unavailable responses fail closed |

## Risk register

| ID | Risk | Likelihood | Impact | Owner | Treatment | Residual |
|---|---|---|---|---|---|---|
| R1 | Log key exfiltrated and database rewritten | Low | Critical | Security Ops | Key in secret manager + KMS, rotation runbook, WORM archive, external monitors | Low |
| R2 | Agents bypass recording | Medium | High | Platform | Record at the MCP/A2A gateway, not only in agents; KPI on coverage | Medium |
| R3 | Export policy misconfiguration | Medium | High | Internal Audit | CODEOWNERS on `policies/`, policy digest audited with every decision, tests | Low |
| R4 | PostgreSQL outage stops recording | Medium | High | Platform | Multi-AZ, readiness probe, agents retry with the same `action_id` | Low |
| R5 | Archive outage | Medium | Medium | Platform | Outbox with backlog alert; data safe in PostgreSQL | Low |
| R6 | Write throughput ceiling of a single sequenced log | Low | Medium | Platform | Group commit; shard by business domain if needed (cost-and-scalability) | Low |
