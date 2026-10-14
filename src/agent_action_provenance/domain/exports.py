"""Auditor evidence exports.

The record selection is frozen when the export is requested, so an approver
signs off on exactly the records that will leave the system.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from agentic_core.domain.classification import DataClassification, Decision
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExportStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    READY = "ready"


class ExportCriteria(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str | None = Field(default=None, max_length=512)
    correlation_id: str | None = Field(default=None, max_length=128)
    action: str | None = Field(default=None, max_length=200)
    compliant: bool | None = None
    since: datetime | None = None
    until: datetime | None = None
    record_ids: tuple[str, ...] = Field(default=(), max_length=1000)
    purpose: str = Field(min_length=5, max_length=500, description="Audit purpose, recorded")

    @model_validator(mode="after")
    def _window(self) -> ExportCriteria:
        if self.since and self.until and self.until <= self.since:
            raise ValueError("until must be after since")
        return self


class PolicyOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    matched_rules: tuple[str, ...]
    policy_version: str
    policy_digest: str
    reason: str


class ExportRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    export_id: str
    status: ExportStatus
    criteria: ExportCriteria
    requested_by: str
    created_at: datetime
    record_ids: tuple[str, ...]
    max_classification: DataClassification
    policy: PolicyOutcome
    approved_by: str | None = None
    approved_at: datetime | None = None
