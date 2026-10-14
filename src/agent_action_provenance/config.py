"""Runtime settings, read from PROVENANCE_* environment variables."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, HttpUrl, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PROVENANCE_", env_nested_delimiter="__")

    environment: str = "production"
    public_url: HttpUrl = Field(description="Public base URL; used in the A2A agent card")
    database_url: str = Field(description="SQLAlchemy async URL, e.g. postgresql+asyncpg://...")

    log_key_file: Path | None = Field(default=None, description="Ed25519 PEM signing tree heads")
    audit_key_file: Path | None = Field(default=None, description="Ed25519 PEM for audit events")
    audit_log_path: Path = Path("/var/lib/agent-action-provenance/audit/audit.jsonl")
    dev_ephemeral_keys: bool = Field(
        default=False,
        description="Generate in-memory keys at start-up. Refused when environment=production.",
    )

    # Agent callers: identity fabric (preferred) or local verification + policy.
    fabric_url: HttpUrl | None = None
    agent_issuer: str | None = None
    agent_audience: str | None = None
    agent_jwks_url: str | None = None
    access_policy_file: Path = Path("policies/provenance-access.yaml")

    # Human auditors: enterprise OIDC.
    auditor_issuer: str
    auditor_audience: str
    auditor_jwks_url: str
    auditor_roles_claim: str = "roles"
    export_policy_file: Path = Path("policies/evidence-export.yaml")
    export_max_records: int = Field(default=1000, ge=1, le=10000)

    batch_max_size: int = Field(default=256, ge=1, le=10000)
    batch_max_wait_ms: int = Field(default=50, ge=0, le=5000)

    archive_backend: Literal["filesystem", "s3"] = "filesystem"
    archive_dir: Path = Path("/var/lib/agent-action-provenance/archive")
    archive_bucket: str | None = None
    archive_prefix: str = "agent-action-provenance"
    archive_region: str | None = None
    archive_lock_mode: Literal["COMPLIANCE", "GOVERNANCE"] = "COMPLIANCE"
    archive_retention_days: int = Field(default=2555, ge=1, le=36500)
    archive_interval_s: float = Field(default=30.0, gt=0)
    monitor_interval_s: float = Field(default=60.0, gt=0)

    mcp_allowed_hosts: list[str] = Field(
        default_factory=list, description="Extra Host header values accepted by the MCP endpoint"
    )

    log_level: str = "INFO"
    otlp_endpoint: str | None = None

    @model_validator(mode="after")
    def _complete(self) -> Settings:
        if self.dev_ephemeral_keys:
            if self.environment == "production":
                raise ValueError("dev_ephemeral_keys cannot be used in production")
        else:
            missing = [
                name
                for name, value in (
                    ("PROVENANCE_LOG_KEY_FILE", self.log_key_file),
                    ("PROVENANCE_AUDIT_KEY_FILE", self.audit_key_file),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"signing configuration incomplete: {missing}")
        if self.fabric_url is None and not (
            self.agent_issuer and self.agent_audience and self.agent_jwks_url
        ):
            raise ValueError(
                "configure PROVENANCE_FABRIC_URL, or PROVENANCE_AGENT_ISSUER, "
                "PROVENANCE_AGENT_AUDIENCE and PROVENANCE_AGENT_JWKS_URL for local verification"
            )
        if self.archive_backend == "s3" and not self.archive_bucket:
            raise ValueError("PROVENANCE_ARCHIVE_BUCKET is required for the s3 archive")
        return self

    @property
    def batch_max_wait(self) -> float:
        return self.batch_max_wait_ms / 1000

    @property
    def archive_retention(self) -> timedelta:
        return timedelta(days=self.archive_retention_days)

    @property
    def public_base(self) -> str:
        return str(self.public_url).rstrip("/")

    @property
    def mcp_hosts(self) -> list[str]:
        """Host header values the MCP endpoint accepts (DNS-rebinding protection)."""
        hosts = {"127.0.0.1:*", "localhost:*"}
        for name in (urlparse(self.public_base).hostname or "", *self.mcp_allowed_hosts):
            if name:
                hosts |= {name} if ":" in name else {name, f"{name}:*"}
        return sorted(hosts)
