"""A2A (Agent2Agent) interface: Agent Card and JSON-RPC ``message/send``.

Other agents delegate provenance work by sending a message whose data part
names a skill and carries its input::

    {"jsonrpc": "2.0", "id": 1, "method": "message/send",
     "params": {"message": {"role": "user", "messageId": "...",
                "parts": [{"kind": "data", "data": {"skill": "record-action",
                                                    "input": {...ActionSubmission...}}}]}}}

The reply is a completed Task whose artifact holds the skill output. HTTP
authentication (bearer agent credential) is checked before JSON-RPC
processing; authorization denials produce a ``rejected`` task.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from agentic_core.domain.identifiers import new_id
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from agent_action_provenance import __version__
from agent_action_provenance.api.routes import Deps, bearer
from agent_action_provenance.domain.errors import (
    ApprovalRequiredError,
    ForbiddenError,
    ProvenanceError,
    UnauthorizedError,
)
from agent_action_provenance.domain.models import ActionSubmission
from agent_action_provenance.runtime.container import Container

PROTOCOL_VERSION = "0.3.0"
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602

SKILLS: list[dict[str, Any]] = [
    {
        "id": "record-action",
        "name": "Record agent action",
        "description": (
            "Seal an agent action with its decision, evidence and authorization into the "
            "provenance log; returns a receipt with a signed tree head and inclusion proof."
        ),
        "tags": ["provenance", "audit", "w3c-prov", "transparency-log"],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
    {
        "id": "verify-record",
        "name": "Verify a record",
        "description": "Check a record's integrity and inclusion against the latest signed head.",
        "tags": ["verification", "merkle"],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
    {
        "id": "inclusion-proof",
        "name": "Inclusion proof",
        "description": "RFC 6962 audit path for a leaf in a tree of a given size.",
        "tags": ["merkle", "rfc6962"],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
    {
        "id": "consistency-proof",
        "name": "Consistency proof",
        "description": "RFC 6962 proof that a later tree extends an earlier one.",
        "tags": ["merkle", "rfc6962"],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
]

router = APIRouter()


class _VerifyInput(BaseModel):
    record_id: str


class _InclusionInput(BaseModel):
    leaf_index: int
    tree_size: int | None = None


class _ConsistencyInput(BaseModel):
    first: int
    second: int


def agent_card(c: Container) -> dict[str, Any]:
    base = c.settings.public_base
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "name": "agent-action-provenance",
        "description": (
            "Provenance engine for agent actions: W3C PROV records, signed evidence chain, "
            "RFC 6962 transparency log with inclusion and consistency proofs."
        ),
        "url": f"{base}/a2a",
        "preferredTransport": "JSONRPC",
        "version": __version__,
        "provider": {
            "organization": "kogunlowo123",
            "url": "https://github.com/kogunlowo123/agent-action-provenance",
        },
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": SKILLS,
        "securitySchemes": {
            "agentCredential": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Agent credential issued by agent-identity-fabric",
            }
        },
        "security": [{"agentCredential": []}],
    }


@router.get("/.well-known/agent-card.json", tags=["a2a"])
async def card(c: Deps) -> dict[str, Any]:
    return agent_card(c)


def _error(rpc_id: Any, code: int, message: str, data: Any = None) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": error})


def _task(
    message: dict[str, Any], skill: str, state: str, output: Any, note: str | None
) -> dict[str, Any]:
    status: dict[str, Any] = {"state": state, "timestamp": datetime.now(UTC).isoformat()}
    if note:
        status["message"] = {
            "kind": "message",
            "role": "agent",
            "messageId": new_id(),
            "parts": [{"kind": "text", "text": note}],
        }
    task: dict[str, Any] = {
        "kind": "task",
        "id": new_id(),
        "contextId": message.get("contextId") or new_id(),
        "status": status,
        "history": [message],
    }
    if output is not None:
        task["artifacts"] = [
            {"artifactId": new_id(), "name": skill, "parts": [{"kind": "data", "data": output}]}
        ]
    return task


async def _run(c: Container, token: str, skill: str, data: Any) -> Any:
    service = c.service
    if skill == "record-action":
        receipt = await service.record(token, ActionSubmission.model_validate(data))
        return receipt.model_dump(mode="json")
    auth = await service.authorize_log_read(token)
    await service.audit_tool_call(auth.principal.subject, skill, channel="a2a")
    if skill == "verify-record":
        report = await service.verify_record(_VerifyInput.model_validate(data).record_id)
        return report.model_dump(mode="json")
    if skill == "inclusion-proof":
        inc = _InclusionInput.model_validate(data)
        return (await service.inclusion_proof(inc.leaf_index, inc.tree_size)).model_dump(
            mode="json"
        )
    con = _ConsistencyInput.model_validate(data)
    return (await service.consistency_proof(con.first, con.second)).model_dump(mode="json")


def _skill_input(message: dict[str, Any]) -> tuple[str | None, Any]:
    metadata = message.get("metadata") if isinstance(message.get("metadata"), dict) else {}
    for part in message.get("parts") or []:
        if (
            isinstance(part, dict)
            and part.get("kind") == "data"
            and isinstance(part.get("data"), dict)
        ):
            data = part["data"]
            skill = data.get("skill") or (metadata or {}).get("skill")
            return (skill if isinstance(skill, str) else None), data.get("input", {})
    return None, None


class _RpcError(Exception):
    def __init__(self, rpc_id: Any, code: int, message: str) -> None:
        super().__init__(message)
        self.response = _error(rpc_id, code, message)


def _envelope(body: Any) -> tuple[Any, dict[str, Any], str, Any]:
    """Validate the JSON-RPC envelope; returns id, message, skill and skill input."""
    if (
        not isinstance(body, dict)
        or body.get("jsonrpc") != "2.0"
        or not isinstance(body.get("method"), str)
    ):
        rpc_id = body.get("id") if isinstance(body, dict) else None
        raise _RpcError(rpc_id, INVALID_REQUEST, "invalid request")
    rpc_id = body.get("id")
    if body["method"] != "message/send":
        raise _RpcError(rpc_id, METHOD_NOT_FOUND, f"method {body['method']} not found")
    params = body.get("params")
    message = params.get("message") if isinstance(params, dict) else None
    if not isinstance(message, dict):
        raise _RpcError(rpc_id, INVALID_PARAMS, "params.message is required")
    skill, data = _skill_input(message)
    if skill is None or skill not in {s["id"] for s in SKILLS}:
        raise _RpcError(rpc_id, INVALID_PARAMS, f"unknown or missing skill {skill!r}")
    return rpc_id, message, skill, data


def _result(rpc_id: Any, task: dict[str, Any]) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": task})


@router.post("/a2a", tags=["a2a"])
async def message_send(
    request: Request, c: Deps, token: Annotated[str, Depends(bearer)]
) -> JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return _error(None, PARSE_ERROR, "invalid JSON")
    try:
        rpc_id, message, skill, data = _envelope(body)
    except _RpcError as exc:
        return exc.response
    try:
        output = await _run(c, token, skill, data)
    except ValidationError as exc:
        details = exc.errors(include_url=False, include_context=False, include_input=False)
        return _error(rpc_id, INVALID_PARAMS, "skill input failed validation", details)
    except UnauthorizedError:
        raise
    except (ForbiddenError, ApprovalRequiredError) as exc:
        return _result(rpc_id, _task(message, skill, "rejected", None, exc.message))
    except ProvenanceError as exc:
        return _result(rpc_id, _task(message, skill, "failed", None, exc.message))
    return _result(rpc_id, _task(message, skill, "completed", output, None))
