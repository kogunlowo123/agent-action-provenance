# Acceptance criteria

Each criterion names the automated test that demonstrates it. All run in CI
for every change; the CI run for a release tag is the acceptance evidence.

| # | Criterion | Evidence |
|---|---|---|
| AC1 | Merkle roots match the Certificate Transparency test vectors for sizes 1–8 and a direct transcription of RFC 6962 MTH for every size up to 67 | `tests/unit/test_merkle.py::TestHashing` |
| AC2 | Inclusion and consistency proofs equal RFC 6962 `PATH`/`PROOF` for every (m, n) up to 67 and verify with the RFC 9162 algorithms; property tests up to 300 leaves | `TestInclusion`, `TestConsistency` |
| AC3 | Altered, truncated, extended, reordered or wrong-length proofs, wrong indices, sizes or roots, interior nodes presented as leaves and forked logs all fail verification | `test_tampered_*`, `test_modified_*`, `test_leaf_hash_is_not_accepted_as_node`, `test_detects_a_forked_log` |
| AC4 | A submitted action returns a receipt whose inclusion proof verifies against a signed tree head over the exact sealed bytes | `tests/unit/test_service.py::TestRecording`, `tests/e2e::test_agent_records_and_monitor_verifies` |
| AC5 | Every record carries a valid W3C PROV document; derivation cycles are rejected and nothing is sealed | `TestProvDocument`, `test_derivation_cycle_is_rejected` |
| AC6 | Governance violations are recorded, not refused, and each rule is detected | `TestGovernance`, `test_violations_are_recorded_not_refused` |
| AC7 | Retries are idempotent; reusing an `action_id` with different content is a conflict; concurrent duplicates collapse | `test_idempotent_retry_and_conflicting_reuse`, `test_duplicates_in_one_batch_collapse` |
| AC8 | Concurrent replicas never fork the log on PostgreSQL | `tests/integration/test_postgres.py` |
| AC9 | Agents cannot record for others; gateways can with scope but not under delegation; credentials are verified or introspected; outages fail closed | `TestAuthorization`, `tests/security::TestCredentialAttacks`, `test_identity_fabric_outage_fails_closed` |
| AC10 | Edited records, rewritten nodes, forged heads and rollbacks are detected by self-monitoring | `tests/security::TestTamperEvidence` |
| AC11 | RESTRICTED or bulk exports need a second person; bundles verify offline against a pinned key and any edit fails | `TestExports`, `test_auditor_review_export_and_offline_verification`, `test_bundle_tampering_is_detected` |
| AC12 | Sealed batches reach write-once storage; archive outages create a backlog that drains on recovery | `test_archive_writes_self_verifying_worm_objects`, `TestS3ObjectLockArchive`, `test_archive_outage_builds_backlog_then_drains` |
| AC13 | MCP tools and A2A skills work end to end with typed schemas, authorization and audit | `test_mcp_tools`, `test_a2a_agent_card_and_message_send` |
| AC14 | No generated API input causes a 5xx | `tests/e2e/test_api_contract.py` |
| AC15 | Proofs cost under 2 ms in memory and 50 ms through SQLite; group commit sustains 40 records/s on a CI runner with SQLite | `tests/performance` |
| AC16 | Published JSON Schemas and OpenAPI match the code | `test_committed_contracts_are_current`, CI contract step |
