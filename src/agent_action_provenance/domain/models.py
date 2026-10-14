"""Provenance record model.

An agent action is captured along the flow
Decision -> Evidence -> Authorization -> Audit Record:

* ``DecisionRecord``: what the agent decided and why (optionally which model).
* ``EvidenceItem``: every input the decision relied on, identified by digest.
* ``AuthorizationRecord``: the policy decision that permitted (or did not
  permit) the action, including any human approval.
* ``ProvenanceRecord``: the sealed record. Its canonical JSON encoding is the
  Merkle leaf, so every field below is covered by the transparency log.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from agentic_core.domain.classification import (
    DataClassification,
    Decision,
    RiskLevel,
    TrustLevel,
)
from agentic_core.domain.identifiers import AgentId
from agentic_core.domain.provenance import canonical_json
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

RECORD_SCHEMA_VERSION = "aap-record/v1"

Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


def _spiffe(value: str) -> str:
    AgentId.parse(value)
    return value


AgentUri = Annotated[str, Field(max_length=512), AfterValidator(_spiffe)]
Principal = Annotated[str, Field(min_length=3, max_length=512)]
_FROZEN = ConfigDict(frozen=True, extra="forbid")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class EvidenceKind(StrEnum):
    DOCUMENT = "document"
    RETRIEVAL = "retrieval"
    TOOL_OUTPUT = "tool_output"
    MODEL_OUTPUT = "model_output"
    HUMAN_INPUT = "human_input"
    RECORD = "record"


class EvidenceItem(BaseModel):
    """An input the decision relied on. Content is referenced, never embedded."""

    model_config = _FROZEN

    uri: str = Field(min_length=1, max_length=2048)
    digest: Digest
    kind: EvidenceKind
    media_type: str = Field(default="application/octet-stream", max_length=255)
    trust: TrustLevel
    classification: DataClassification
    retrieved_at: datetime
    derived_from: tuple[Digest, ...] = Field(default=(), max_length=64)


class OutputArtifact(BaseModel):
    """Something the action produced or changed."""

    model_config = _FROZEN

    uri: str = Field(min_length=1, max_length=2048)
    digest: Digest
    media_type: str = Field(default="application/octet-stream", max_length=255)
    classification: DataClassification
    derived_from: tuple[Digest, ...] = Field(default=(), max_length=64)


class ModelInvocation(BaseModel):
    model_config = _FROZEN

    provider: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=200)
    prompt_digest: Digest
    response_digest: Digest


class DecisionRecord(BaseModel):
    model_config = _FROZEN

    summary: str = Field(min_length=1, max_length=2000)
    rationale: str = Field(default="", max_length=8000)
    model: ModelInvocation | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class ApprovalRecord(BaseModel):
    model_config = _FROZEN

    approver: Principal
    approved_at: datetime
    reference: str = Field(min_length=1, max_length=200, description="Ticket or change ID")


class AuthorizationRecord(BaseModel):
    model_config = _FROZEN

    decision: Decision
    authorizer: str = Field(min_length=1, max_length=512)
    policy_name: str = Field(min_length=1, max_length=200)
    policy_version: str = Field(min_length=1, max_length=100)
    policy_digest: Digest
    matched_rules: tuple[str, ...] = Field(default=(), max_length=64)
    decided_at: datetime
    approval: ApprovalRecord | None = None


class ActionStatus(StrEnum):
    EXECUTED = "executed"
    BLOCKED = "blocked"
    PENDING_APPROVAL = "pending_approval"
    FAILED = "failed"


class ActionDetails(BaseModel):
    model_config = _FROZEN

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_.:*-]{0,199}$", description="e.g. fhir:write:task")
    tool: str | None = Field(default=None, max_length=200, description="MCP tool or API invoked")
    target: str = Field(min_length=1, max_length=2048, description="Resource acted upon")
    risk: RiskLevel
    status: ActionStatus
    started_at: datetime
    ended_at: datetime

    @model_validator(mode="after")
    def _interval(self) -> ActionDetails:
        if self.ended_at < self.started_at:
            raise ValueError("ended_at precedes started_at")
        return self


class ActionSubmission(BaseModel):
    """What an agent (or the gateway acting for it) submits after an action."""

    model_config = _FROZEN

    action_id: str = Field(
        pattern=r"^[A-Za-z0-9._:-]{8,128}$",
        description="Client-chosen idempotency key, unique per agent",
    )
    agent_id: AgentUri
    on_behalf_of: tuple[Principal, ...] = Field(
        default=(), max_length=10, description="Delegation chain, nearest principal first"
    )
    action: ActionDetails
    decision: DecisionRecord
    evidence: tuple[EvidenceItem, ...] = Field(default=(), max_length=256)
    outputs: tuple[OutputArtifact, ...] = Field(default=(), max_length=256)
    authorization: AuthorizationRecord | None = None
    correlation_id: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _distinct(self) -> ActionSubmission:
        digests = [e.digest for e in self.evidence]
        if len(digests) != len(set(digests)):
            raise ValueError("evidence digests must be unique")
        produced = [o.digest for o in self.outputs]
        if len(produced) != len(set(produced)):
            raise ValueError("output digests must be unique")
        if set(digests) & set(produced):
            raise ValueError("an artifact cannot be both evidence and output of one action")
        return self

    def digest(self) -> str:
        return sha256_digest(canonical_json(self.model_dump(mode="json")))

    @property
    def max_classification(self) -> DataClassification:
        levels = [e.classification for e in self.evidence] + [
            o.classification for o in self.outputs
        ]
        return max(levels, default=DataClassification.PUBLIC)


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    VIOLATION = "violation"


class GovernanceFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    severity: Severity
    detail: str


class GovernanceAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    compliant: bool
    findings: tuple[GovernanceFinding, ...]


class ProvenanceRecord(BaseModel):
    """The sealed record. ``leaf_bytes`` is exactly what the Merkle leaf hashes."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = RECORD_SCHEMA_VERSION
    record_id: str
    recorded_at: datetime
    recorded_by: str
    submission: ActionSubmission
    submission_digest: Digest
    prov: dict[str, Any]
    governance: GovernanceAssessment

    def leaf_bytes(self) -> bytes:
        return canonical_json(self.model_dump(mode="json"))

    def digest(self) -> str:
        return sha256_digest(self.leaf_bytes())
