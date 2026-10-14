"""MCP server: provenance tools for agents, over streamable HTTP at ``/mcp``.

Built on the official ``mcp`` Python SDK (``MCPServer``, stateless streamable
HTTP with JSON responses). Every tool:

* has typed input and output schemas (Pydantic models),
* authenticates the caller's bearer credential and authorizes the specific
  tool action through the same authorizer as the REST API,
* writes an audit event.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from typing import Annotated, Any

from agentic_core.policy import Resource
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field
from starlette.applications import Starlette

from agent_action_provenance import __version__
from agent_action_provenance.application.views import (
    LineageGraph,
    RecordReceipt,
    VerificationReport,
)
from agent_action_provenance.domain.errors import ProvenanceError, UnauthorizedError
from agent_action_provenance.domain.log import ConsistencyProof, InclusionProof, SignedTreeHead
from agent_action_provenance.domain.models import ActionSubmission
from agent_action_provenance.runtime.container import Container

INSTRUCTIONS = (
    "Record every consequential agent action with record_action after it completes "
    "(or is blocked), including the evidence relied on and the authorization decision. "
    "Keep the returned receipt: its inclusion proof and signed tree head let anyone "
    "verify later that the record is in the append-only log."
)

ContainerGetter = Callable[[], Container]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Index = Annotated[int, Field(ge=0, le=2**62)]


def _token(ctx: Context[Any, Any]) -> str:
    headers = ctx.headers or {}
    value = headers.get("authorization") or headers.get("Authorization") or ""
    if not value.lower().startswith("bearer ") or not value[7:].strip():
        raise UnauthorizedError("agent bearer token required")
    return value[7:].strip()


@contextlib.contextmanager
def _tool_errors() -> Iterator[None]:
    """Surface domain errors (denials, not-found) to the calling agent as tool errors."""
    try:
        yield
    except ProvenanceError as exc:
        raise ToolError(f"{exc.code}: {exc.message}") from exc


def build_mcp(get: ContainerGetter) -> MCPServer:
    server: MCPServer = MCPServer(
        "agent-action-provenance",
        title="Agent Action Provenance",
        instructions=INSTRUCTIONS,
        version=__version__,
        log_level="WARNING",
    )

    async def read(ctx: Context[Any, Any], action: str, resource: str, tool: str) -> Container:
        c = get()
        token = _token(ctx)
        auth = await c.service.authorize_agent(
            token, action=action, resource=Resource(type=resource, id="*")
        )
        await c.service.audit_tool_call(auth.principal.subject, tool)
        return c

    @server.tool(
        title="Record an agent action",
        description=(
            "Seal an agent action (decision, evidence, authorization, outputs) into the "
            "provenance log. Returns the record ID, governance findings, signed tree head "
            "and inclusion proof."
        ),
    )
    async def record_action(submission: ActionSubmission, ctx: Context[Any, Any]) -> RecordReceipt:
        with _tool_errors():
            return await get().service.record(_token(ctx), submission)

    @server.tool(
        title="Signed tree head",
        description="Latest signed tree head of the transparency log, or the head for a size.",
    )
    async def get_tree_head(
        ctx: Context[Any, Any], tree_size: Index | None = None
    ) -> SignedTreeHead:
        with _tool_errors():
            c = await read(ctx, "provenance:log:read", "transparency-log", "get_tree_head")
            if tree_size is None:
                return await c.service.latest_tree_head()
            return await c.service.tree_head(tree_size)

    @server.tool(
        title="Inclusion proof",
        description="RFC 6962 audit path proving a leaf is in the tree of the given size.",
    )
    async def get_inclusion_proof(
        leaf_index: Index, ctx: Context[Any, Any], tree_size: Index | None = None
    ) -> InclusionProof:
        with _tool_errors():
            c = await read(ctx, "provenance:log:read", "transparency-log", "get_inclusion_proof")
            return await c.service.inclusion_proof(leaf_index, tree_size)

    @server.tool(
        title="Consistency proof",
        description=(
            "RFC 6962 proof that the tree of size `second` extends the tree of size `first`."
        ),
    )
    async def get_consistency_proof(
        first: Index, second: Index, ctx: Context[Any, Any]
    ) -> ConsistencyProof:
        with _tool_errors():
            c = await read(ctx, "provenance:log:read", "transparency-log", "get_consistency_proof")
            return await c.service.consistency_proof(first, second)

    @server.tool(
        title="Verify a record",
        description=(
            "Recompute a record's leaf hash and PROV document and check its inclusion "
            "against the latest signed tree head."
        ),
    )
    async def verify_record(
        record_id: Annotated[str, Field(max_length=64)], ctx: Context[Any, Any]
    ) -> VerificationReport:
        with _tool_errors():
            c = await read(ctx, "provenance:log:read", "transparency-log", "verify_record")
            return await c.service.verify_record(record_id)

    @server.tool(
        title="Trace lineage",
        description="Actions, agents and evidence that produced an artifact, by content digest.",
    )
    async def trace_lineage(
        digest: Digest,
        ctx: Context[Any, Any],
        max_depth: Annotated[int, Field(ge=1, le=32)] = 8,
    ) -> LineageGraph:
        with _tool_errors():
            c = await read(ctx, "provenance:lineage:read", "provenance-lineage", "trace_lineage")
            return await c.service.lineage(digest, max_depth=max_depth)

    return server


def mcp_http_app(server: MCPServer, allowed_hosts: list[str]) -> Starlette:
    return server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=[],
        ),
    )
