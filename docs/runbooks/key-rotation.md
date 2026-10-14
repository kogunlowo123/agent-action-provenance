# Runbook: key rotation

Two Ed25519 keys: the **log key** (signs tree heads; its SHA-256 SPKI digest
is the log ID) and the **audit key** (signs agentic-core audit events; the
file stem is the key ID). Rotation is a CRITICAL change: change-managed,
two-person, performed from an administrator workstation.

## Audit key (routine, every 90 days)

1. Generate and store: `uv run provenance-verify keygen 2> audit-<kid>.pub.pem |
   aws secretsmanager create-secret --name agent-action-provenance-audit-key-<kid> …`
2. Set `secrets.auditKeyFile: audit-<kid>.pem`, `helm upgrade`.
3. New events carry the new `key_id`; verify old chain files with the old
   public key and new ones with the new key.

## Log key (planned, at least yearly, or immediately on suspected compromise)

The log ID changes with the key, so a rotation starts a new log segment.

1. Record the final signed tree head of the current log (`GET /v1/log/tree-head`)
   and archive it with the change record.
2. Generate the new key (`provenance-verify keygen`), store it as
   `agent-action-provenance-log-key-<kid>`, publish the public key to monitors
   and auditors through the independent channel.
3. Provision a new database (or schema) for the new log segment, update the
   database URL secret, set `secrets.logKeyFile: log-<kid>.pem`, `helm upgrade`.
4. The new segment starts with a genesis head signed by the new key. Monitors
   add the new log (new state file, new public key) and keep the old one's
   final head for verification of historical bundles.
5. The old database stays read-only for the retention period so historical
   proofs remain available; archived batches remain the durable copy.

## Suspected compromise

Treat as an integrity incident first (incident-response runbook), then rotate
the log key as above. Heads signed after the suspected compromise time that
are not in the WORM archive or in a monitor's state must be treated as
untrusted.
