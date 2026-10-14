# Runbook: rollback

The schema is additive within a minor version (`schema_version` table) and
the record format is versioned (`aap-record/v1`), so application rollback
within 0.x.y does not require database changes. Never roll back the
*database* to undo an application problem: deleting sealed records is
indistinguishable from tampering and will (correctly) fail integrity checks.

```bash
helm -n agent-provenance history provenance
helm -n agent-provenance rollback provenance <revision> --wait
kubectl -n agent-provenance rollout status statefulset/provenance-agent-action-provenance
curl -sf "$PROVENANCE/readyz"
provenance-verify monitor --url "$PROVENANCE" --public-key log.pub.pem --state monitor-state.json
```

Policy-only regressions: revert the commit touching `policies/*.yaml`,
release, and confirm the `policy_digest` in new `export.request` audit events
matches the reverted file.

A rollback that changes the governance rules or PROV mapping must also roll
back `RECORD_SCHEMA_VERSION`; records sealed by the newer release keep
verifying with the newer verifier (ADR-0003).
