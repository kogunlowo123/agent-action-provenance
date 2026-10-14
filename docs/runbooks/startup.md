# Runbook: first deployment and startup

## Prerequisites

- Kubernetes ≥ 1.27 with External Secrets Operator and a `ClusterSecretStore`
  named `platform-secrets` bound to the cloud secret manager.
- agent-identity-fabric deployed (or its JWKS reachable for local mode), with
  agents and the MCP gateway granted `provenance:record:write` /
  `provenance:record:delegate` scopes.
- Enterprise IdP app registration exposing roles `provenance-auditor` and
  `provenance-approver`.

## 1. Provision cloud resources

```bash
cd deployments/terraform/aws        # or azure / gcp
terraform init                      # configure an encrypted remote backend first
terraform apply -var-file=<environment>.tfvars
```

Record the outputs: `service_account_role_arn`, `database_url_secret_name`,
`kms_key_arn`, `archive_bucket`.

## 2. Key ceremony (log key and audit key)

Generate keys on an administrator workstation; private keys go straight to
the secret manager and are never written to disk or Terraform state.

```bash
uv run provenance-verify keygen 2> log-2026-10.pub.pem \
  | aws secretsmanager create-secret --name agent-action-provenance-log-key-2026-10 \
      --kms-key-id <kms_key_arn> --secret-string file:///dev/stdin

uv run provenance-verify keygen 2> audit-2026-10.pub.pem \
  | aws secretsmanager create-secret --name agent-action-provenance-audit-key-2026-10 \
      --kms-key-id <kms_key_arn> --secret-string file:///dev/stdin
```

Publish `log-2026-10.pub.pem` to auditors and monitors through a channel
independent of the platform (for example the audit team's repository); it is
the trust anchor every verification pins. Azure: `az keyvault secret set
--vault-name <vault> --name … --file /dev/stdin`. GCP: `gcloud secrets create
… --data-file=-`.

## 3. Namespace and secret sync

```bash
kubectl apply -k deployments/kubernetes
kubectl -n agent-provenance get externalsecret   # all READY=True
```

## 4. Install the chart

Create `<environment>.yaml` with every value marked REQUIRED in `values.yaml`
(`provenance.publicUrl`, `provenance.fabricUrl` or `provenance.agent.*`,
`provenance.auditor.*`, `provenance.archive.bucket`, `secrets.logKeyFile:
log-2026-10.pem`, `secrets.auditKeyFile: audit-2026-10.pem`) and the
workload-identity annotation from Terraform:

```bash
helm upgrade --install provenance oci://ghcr.io/kogunlowo123/charts/agent-action-provenance \
  --version 0.1.0 -n agent-provenance -f <environment>.yaml --wait
```

## 5. Verify

```bash
kubectl -n agent-provenance rollout status statefulset/provenance-agent-action-provenance
kubectl -n agent-provenance port-forward svc/provenance-agent-action-provenance 8080:80
curl -sf localhost:8080/readyz
curl -s localhost:8080/v1/log/public-key | jq -r .public_key_pem | diff - log-2026-10.pub.pem
provenance-verify monitor --url http://localhost:8080 --public-key log-2026-10.pub.pem \
  --state monitor-state.json
```

Expected: `{"status":"ready"}`, no diff between the served and the published
public key, and a valid monitor report for the genesis tree head (size 0).
Schedule the monitor (outside the platform) every 15 minutes. Prometheus
target `agent-action-provenance` is up; the Grafana dashboard shows the log
size.
