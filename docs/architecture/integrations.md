# Integrations: identity, MCP and A2A

## agent-identity-fabric

`integrations/identity_fabric.py` is a typed client for
[agent-identity-fabric](https://github.com/kogunlowo123/agent-identity-fabric):

| Call | Used for |
|---|---|
| `POST /oauth2/introspect` (RFC 7662) | Is the presented agent credential active (signature, expiry, revocation, suspension epoch)? Subject, scopes and the RFC 8693 `act` delegation chain |
| `POST /v1/authorize` (bearer = the agent's credential) | Policy decision for `provenance:record:write`, `provenance:record:delegate`, `provenance:log:read`, `provenance:lineage:read` with resource attributes (`own_action`, `agent_id`, classification) |
| `POST /oauth2/token` (RFC 7523 jwt-bearer) | Exchanging a workload token for an agent credential. Implemented and tested in the client; v0.1.0 makes no outbound calls that need the engine's own credential, so it is not on any request path yet |

The decision must name the same subject the introspection returned, or the
request is rejected. Every transport error, non-200 status or malformed body
raises `temporarily_unavailable` (503): the engine fails closed.

When `PROVENANCE_FABRIC_URL` is not set, credentials are verified locally
against the fabric's JWKS (`PROVENANCE_AGENT_ISSUER`, `_AUDIENCE`,
`_JWKS_URL`) and `policies/provenance-access.yaml` is evaluated by the
agentic-core PolicyEngine with the same subject attributes the fabric uses.
With neither configured the service refuses to start.

## MCP

The engine exposes its tools through the official `mcp` Python SDK
(`MCPServer`, stateless streamable HTTP, JSON responses) mounted at `/mcp` in
the same ASGI app.

| Tool | Input | Output | Authorization |
|---|---|---|---|
| `record_action` | `submission: ActionSubmission` | `RecordReceipt` | `provenance:record:write` / `:delegate` |
| `get_tree_head` | `tree_size?` | `SignedTreeHead` | `provenance:log:read` |
| `get_inclusion_proof` | `leaf_index`, `tree_size?` | `InclusionProof` | `provenance:log:read` |
| `get_consistency_proof` | `first`, `second` | `ConsistencyProof` | `provenance:log:read` |
| `verify_record` | `record_id` | `VerificationReport` | `provenance:log:read` |
| `trace_lineage` | `digest`, `max_depth` | `LineageGraph` | `provenance:lineage:read` |

Input and output schemas are generated from the Pydantic models and published
in `tools/list`. Each call reads the bearer credential from the HTTP
`Authorization` header, authorizes the specific action, and writes an audit
event (`mcp.<tool>`, or `provenance.record` for `record_action`). Domain
errors reach the caller as tool errors (`isError: true`, `code: message`).
DNS-rebinding protection accepts only the configured public host, the
in-cluster service names and loopback.

Typical use: an MCP gateway calls `record_action` after every tool invocation
it brokers, attaching the policy decision it enforced; agents keep the
receipt and can later prove inclusion with `get_inclusion_proof`.

## A2A

- **Agent Card** at `/.well-known/agent-card.json`: protocol version 0.3.0,
  `url` = `<public_url>/a2a`, `preferredTransport: JSONRPC`, capabilities
  (no streaming or push), skills (`record-action`, `verify-record`,
  `inclusion-proof`, `consistency-proof`), `securitySchemes.agentCredential`
  (HTTP bearer JWT issued by agent-identity-fabric) and `security`.
- **`POST /a2a`** accepts JSON-RPC 2.0 `message/send`. The message carries a
  `data` part `{"skill": "<id>", "input": {...}}` (the skill may also be given
  in `message.metadata.skill`). The reply is a Task:
  - `completed` with one artifact holding the skill output,
  - `rejected` when authorization denies or requires approval,
  - `failed` for domain errors (for example an unknown record).
- HTTP authentication happens before JSON-RPC processing (401 with
  `WWW-Authenticate: Bearer`). Envelope errors use JSON-RPC codes `-32700`,
  `-32600`, `-32601`, `-32602`.

## Observability integration

Metrics on `/metrics` (own Prometheus registry), OpenTelemetry traces via
OTLP gRPC (`PROVENANCE_OTLP_ENDPOINT`, FastAPI instrumentation), JSON logs on
stdout with the correlation ID from `X-Correlation-ID` (generated when
absent and echoed on every response). See
[observability](../operations/observability.md).
