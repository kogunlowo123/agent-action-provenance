"""Use-case results returned by the application layer and published as contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent_action_provenance.domain.exports import ExportRequest
from agent_action_provenance.domain.log import InclusionProof, SignedTreeHead
from agent_action_provenance.domain.models import GovernanceAssessment


class RecordReceipt(BaseModel):
    """Returned when a record is sealed: everything needed to verify inclusion later."""

    model_config = ConfigDict(frozen=True)

    record_id: str
    leaf_index: int
    leaf_hash: str
    record_digest: str
    submission_digest: str
    duplicate: bool = Field(description="True when an identical action was already recorded")
    governance: GovernanceAssessment
    tree_head: SignedTreeHead
    inclusion_proof: InclusionProof


class RecordView(BaseModel):
    model_config = ConfigDict(frozen=True)

    record_id: str
    leaf_index: int
    leaf_hash: str
    record: dict[str, Any] = Field(description="The sealed ProvenanceRecord, byte-exact JSON")


class RecordPage(BaseModel):
    items: list[RecordView]
    limit: int
    offset: int


class VerificationReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    record_id: str
    leaf_index: int
    tree_size: int
    root_hash: str
    valid: bool
    problems: tuple[str, ...]


class LineageRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    record_id: str
    leaf_index: int
    agent_id: str
    action: str
    status: str
    compliant: bool
    recorded_at: datetime


class LineageEdge(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    relation: str = Field(description="wasGeneratedBy | used | wasDerivedFrom")


class LineageGraph(BaseModel):
    model_config = ConfigDict(frozen=True)

    root: str
    depth: int
    truncated: bool
    records: tuple[LineageRecord, ...]
    edges: tuple[LineageEdge, ...]


class IntegrityReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    ok: bool
    tree_size: int
    checked_from: int
    problems: tuple[str, ...]


class ExportView(BaseModel):
    model_config = ConfigDict(frozen=True)

    export_id: str
    status: str
    requested_by: str
    created_at: datetime
    record_count: int
    max_classification: int
    policy_decision: str
    matched_rules: tuple[str, ...]
    approved_by: str | None
    approved_at: datetime | None

    @classmethod
    def of(cls, request: ExportRequest) -> ExportView:
        return cls(
            export_id=request.export_id,
            status=request.status.value,
            requested_by=request.requested_by,
            created_at=request.created_at,
            record_count=len(request.record_ids),
            max_classification=int(request.max_classification),
            policy_decision=request.policy.decision.value,
            matched_rules=request.policy.matched_rules,
            approved_by=request.approved_by,
            approved_at=request.approved_at,
        )
