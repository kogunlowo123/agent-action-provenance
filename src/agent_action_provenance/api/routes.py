"""HTTP routes.

* ``/v1/records`` (POST): agents, or the gateway acting for them, submit
  actions. Authorized through agent-identity-fabric or the local policy.
* ``/v1/log/*``: the transparency log. Tree heads, proofs and leaf hashes are
  public by design so independent monitors and auditors can check the log
  without credentials; they reveal hashes only.
* ``/v1/records`` (GET), ``/v1/lineage``, ``/v1/exports``: human auditors with
  enterprise OIDC roles.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel
from sqlalchemy import text

from agent_action_provenance.application.views import (
    ExportView,
    LineageGraph,
    RecordPage,
    RecordReceipt,
    RecordView,
    VerificationReport,
)
from agent_action_provenance.domain.errors import UnauthorizedError
from agent_action_provenance.domain.exports import ExportCriteria
from agent_action_provenance.domain.log import (
    ConsistencyProof,
    InclusionProof,
    LogEntry,
    LogPublicKey,
    SignedTreeHead,
)
from agent_action_provenance.domain.models import ActionSubmission
from agent_action_provenance.domain.ports import RecordFilter
from agent_action_provenance.domain.verification import EvidenceBundle
from agent_action_provenance.runtime.container import Container
from agent_action_provenance.security.authorization import (
    AuditorPrincipal,
    AuditorRole,
    require_role,
)

MAX_INDEX = 2**62
router = APIRouter()


def container(request: Request) -> Container:
    value: Container = request.app.state.container
    return value


def bearer(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise UnauthorizedError("agent bearer token required")
    token = authorization[7:].strip()
    if not token:
        raise UnauthorizedError("agent bearer token required")
    return token


async def auditor(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> AuditorPrincipal:
    return await container(request).auditors.authenticate(authorization)


Deps = Annotated[Container, Depends(container)]
Auditor = Annotated[AuditorPrincipal, Depends(auditor)]
Token = Annotated[str, Depends(bearer)]
Index = Annotated[int, Query(ge=0, le=MAX_INDEX)]


class EntryPage(BaseModel):
    entries: list[LogEntry]


# -------------------------------------------------------------------- records


@router.post("/v1/records", status_code=201, tags=["records"])
async def submit_record(body: ActionSubmission, c: Deps, token: Token) -> RecordReceipt:
    """Seal an agent action: PROV document, governance checks, log inclusion, audit."""
    return await c.service.record(token, body)


@router.get("/v1/records", tags=["records"])
async def list_records(
    *,
    c: Deps,
    who: Auditor,
    agent_id: Annotated[str | None, Query(max_length=512)] = None,
    correlation_id: Annotated[str | None, Query(max_length=128)] = None,
    action: Annotated[str | None, Query(max_length=200)] = None,
    compliant: bool | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=MAX_INDEX)] = 0,
) -> RecordPage:
    require_role(who, AuditorRole.AUDITOR)
    criteria = RecordFilter(
        agent_id=agent_id,
        correlation_id=correlation_id,
        action=action,
        compliant=compliant,
        since=since,
        until=until,
    )
    items = await c.service.search(criteria, limit=limit, offset=offset)
    return RecordPage(items=items, limit=limit, offset=offset)


@router.get("/v1/records/{record_id}", tags=["records"])
async def get_record(
    c: Deps, who: Auditor, record_id: Annotated[str, Path(max_length=64)]
) -> RecordView:
    require_role(who, AuditorRole.AUDITOR)
    return await c.service.get_record(record_id)


@router.get("/v1/records/{record_id}/verification", tags=["records"])
async def verify_record(
    c: Deps, who: Auditor, record_id: Annotated[str, Path(max_length=64)]
) -> VerificationReport:
    require_role(who, AuditorRole.AUDITOR)
    return await c.service.verify_record(record_id)


@router.get("/v1/lineage/{digest}", tags=["records"])
async def lineage(
    c: Deps,
    who: Auditor,
    digest: Annotated[str, Path(pattern=r"^sha256:[0-9a-f]{64}$")],
    max_depth: Annotated[int, Query(ge=1, le=32)] = 8,
) -> LineageGraph:
    """Which actions, agents and evidence produced an artifact, transitively."""
    require_role(who, AuditorRole.AUDITOR)
    return await c.service.lineage(digest, max_depth=max_depth)


# ------------------------------------------------------------ transparency log


@router.get("/v1/log/tree-head", tags=["log"])
async def tree_head(c: Deps, tree_size: Index | None = None) -> SignedTreeHead:
    if tree_size is None:
        return await c.service.latest_tree_head()
    return await c.service.tree_head(tree_size)


@router.get("/v1/log/public-key", tags=["log"])
async def public_key(c: Deps) -> LogPublicKey:
    return c.service.public_key()


@router.get("/v1/log/proof/inclusion", tags=["log"])
async def inclusion_proof(
    c: Deps, leaf_index: Index, tree_size: Index | None = None
) -> InclusionProof:
    return await c.service.inclusion_proof(leaf_index, tree_size)


@router.get("/v1/log/proof/consistency", tags=["log"])
async def consistency_proof(c: Deps, first: Index, second: Index) -> ConsistencyProof:
    return await c.service.consistency_proof(first, second)


@router.get("/v1/log/entries", tags=["log"])
async def entries(c: Deps, start: Index, end: Index) -> EntryPage:
    return EntryPage(entries=await c.service.entries(start, end))


# -------------------------------------------------------------------- exports


@router.post("/v1/exports", status_code=201, tags=["exports"])
async def request_export(body: ExportCriteria, c: Deps, who: Auditor) -> ExportView:
    """Freeze a record selection for audit; policy may hold it for a second approver."""
    return await c.service.request_export(who, body)


@router.get("/v1/exports/{export_id}", tags=["exports"])
async def get_export(
    c: Deps, who: Auditor, export_id: Annotated[str, Path(max_length=64)]
) -> ExportView:
    return await c.service.get_export(who, export_id)


@router.post("/v1/exports/{export_id}/approve", tags=["exports"])
async def approve_export(
    c: Deps, who: Auditor, export_id: Annotated[str, Path(max_length=64)]
) -> ExportView:
    return await c.service.approve_export(who, export_id)


@router.get("/v1/exports/{export_id}/bundle", tags=["exports"])
async def export_bundle(
    c: Deps, who: Auditor, export_id: Annotated[str, Path(max_length=64)]
) -> EvidenceBundle:
    """Self-verifying bundle: records, inclusion proofs, signed tree head, log key."""
    return await c.service.export_bundle(who, export_id)


# ----------------------------------------------------------------- operations


@router.get("/healthz", tags=["operations"], include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["operations"], include_in_schema=False)
async def readyz(c: Deps, response: Response) -> dict[str, str]:
    try:
        async with c.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        response.status_code = 503
        return {"status": "database unavailable"}
    if not c.sequencer.running:
        response.status_code = 503
        return {"status": "sequencer stopped"}
    return {"status": "ready"}


@router.get("/metrics", tags=["operations"], include_in_schema=False)
async def metrics(c: Deps) -> Response:
    return Response(generate_latest(c.metrics.registry), media_type=CONTENT_TYPE_LATEST)
