"""Shared fixtures: in-process identity providers, a service wired to SQLite, and an app."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
from agentic_core.domain.classification import (
    DataClassification,
    Decision,
    RiskLevel,
    TrustLevel,
)
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from agent_action_provenance.api.app import create_app
from agent_action_provenance.application.service import ProvenanceService
from agent_action_provenance.config import Settings
from agent_action_provenance.domain.models import (
    ActionDetails,
    ActionStatus,
    ActionSubmission,
    ApprovalRecord,
    AuthorizationRecord,
    DecisionRecord,
    EvidenceItem,
    EvidenceKind,
    ModelInvocation,
    OutputArtifact,
)
from agent_action_provenance.runtime.container import Container, build_container
from agent_action_provenance.security.jwks import StaticJwks

ROOT = Path(__file__).resolve().parents[1]
AGENT_ISSUER = "https://identity.corp.test"
AGENT_AUDIENCE = "agent-platform"
AUDITOR_ISSUER = "https://login.corp.test/tenant"
AUDITOR_AUDIENCE = "agent-action-provenance"
TRUST_DOMAIN = "agents.corp.test"
AGENT = f"spiffe://{TRUST_DOMAIN}/agent/clinical/care-coordinator"
GATEWAY = f"spiffe://{TRUST_DOMAIN}/agent/platform/mcp-gateway"
RECORD_SCOPE = "provenance:record:write provenance:log:read provenance:lineage:read"
POLICY_DIGEST = "sha256:" + "b" * 64


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def agent_uri(name: str, namespace: str = "clinical") -> str:
    return f"spiffe://{TRUST_DOMAIN}/agent/{namespace}/{name}"


@dataclass
class FakeIdp:
    """Minimal OIDC issuer: ES256 keypair plus JWKS."""

    issuer: str
    kid: str = "k1"
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig"})
        return {"keys": [jwk]}

    def mint(self, *, sub: str, aud: str, ttl: int = 300, **extra: Any) -> str:
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl}
        claims.update(extra)
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": self.kid})


@dataclass
class FakeClock:
    current: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


@pytest.fixture
def agent_idp() -> FakeIdp:
    return FakeIdp(AGENT_ISSUER, kid="fabric-1")


@pytest.fixture
def auditor_idp() -> FakeIdp:
    return FakeIdp(AUDITOR_ISSUER, kid="idp-1")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    db = os.environ.get(
        "PROVENANCE_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'provenance.db'}"
    )
    return Settings(
        environment="test",
        public_url="https://provenance.corp.test",
        database_url=db,
        dev_ephemeral_keys=True,
        audit_log_path=tmp_path / "audit" / "audit.jsonl",
        agent_issuer=AGENT_ISSUER,
        agent_audience=AGENT_AUDIENCE,
        agent_jwks_url="https://identity.corp.test/.well-known/jwks.json",
        access_policy_file=ROOT / "policies" / "provenance-access.yaml",
        auditor_issuer=AUDITOR_ISSUER,
        auditor_audience=AUDITOR_AUDIENCE,
        auditor_jwks_url="https://login.corp.test/jwks",
        export_policy_file=ROOT / "policies" / "evidence-export.yaml",
        archive_dir=tmp_path / "archive",
        batch_max_wait_ms=5,
        archive_interval_s=3600,
        monitor_interval_s=3600,
    )


async def make_container(
    settings: Settings, agent_idp: FakeIdp, auditor_idp: FakeIdp, clock: FakeClock, **kw: Any
) -> Container:
    return await build_container(
        settings,
        agent_resolver=StaticJwks(agent_idp.jwks()),
        auditor_resolver=StaticJwks(auditor_idp.jwks()),
        clock=clock,
        **kw,
    )


@pytest.fixture
async def container(
    settings: Settings, agent_idp: FakeIdp, auditor_idp: FakeIdp, clock: FakeClock
) -> AsyncIterator[Container]:
    built = await make_container(settings, agent_idp, auditor_idp, clock)
    yield built
    await built.aclose()


@pytest.fixture
def service(container: Container) -> ProvenanceService:
    return container.service


def agent_token(idp: FakeIdp, sub: str = AGENT, *, scope: str = RECORD_SCOPE, **extra: Any) -> str:
    return idp.mint(sub=sub, aud=AGENT_AUDIENCE, scope=scope, **extra)


def auditor_token(idp: FakeIdp, *roles: str, sub: str = "alice@corp.test") -> str:
    return idp.mint(sub=sub, aud=AUDITOR_AUDIENCE, roles=list(roles))


def auditor_headers(idp: FakeIdp, *roles: str, sub: str = "alice@corp.test") -> dict[str, str]:
    return {"Authorization": f"Bearer {auditor_token(idp, *roles, sub=sub)}"}


def authorization(
    now: datetime,
    *,
    decision: Decision = Decision.ALLOW,
    approval: ApprovalRecord | None = None,
    decided_offset: float = -15,
) -> AuthorizationRecord:
    return AuthorizationRecord(
        decision=decision,
        authorizer="https://identity.corp.test",
        policy_name="agent-authorization",
        policy_version="2026.10.0",
        policy_digest=POLICY_DIGEST,
        matched_rules=("allow-scoped-actions",),
        decided_at=now + timedelta(seconds=decided_offset),
        approval=approval,
    )


def submission(
    now: datetime,
    action_id: str = "act-00000001",
    *,
    agent: str = AGENT,
    status: ActionStatus = ActionStatus.EXECUTED,
    risk: RiskLevel = RiskLevel.MODERATE,
    auth: AuthorizationRecord | bool | None = True,
    evidence: tuple[EvidenceItem, ...] | None = None,
    outputs: tuple[OutputArtifact, ...] | None = None,
    on_behalf_of: tuple[str, ...] = ("nurse.jones@hospital.test",),
    correlation_id: str | None = "corr-0001",
    action: str = "fhir:write:task",
) -> ActionSubmission:
    if evidence is None:
        evidence = (
            EvidenceItem(
                uri="https://fhir.hospital.test/Patient/123/$everything",
                digest=digest(f"{action_id}-chart"),
                kind=EvidenceKind.RETRIEVAL,
                media_type="application/fhir+json",
                trust=TrustLevel.VERIFIED,
                classification=DataClassification.RESTRICTED,
                retrieved_at=now - timedelta(seconds=20),
            ),
        )
    if outputs is None:
        outputs = (
            OutputArtifact(
                uri="https://fhir.hospital.test/Task/987",
                digest=digest(f"{action_id}-task"),
                media_type="application/fhir+json",
                classification=DataClassification.RESTRICTED,
                derived_from=tuple(e.digest for e in evidence),
            ),
        )
    resolved: AuthorizationRecord | None
    if auth is True:
        resolved = authorization(now)
    elif auth is False:
        resolved = None
    else:
        resolved = auth
    return ActionSubmission(
        action_id=action_id,
        agent_id=agent,
        on_behalf_of=on_behalf_of,
        action=ActionDetails(
            name=action,
            tool="fhir.create_task",
            target="https://fhir.hospital.test/Task",
            risk=risk,
            status=status,
            started_at=now - timedelta(seconds=10),
            ended_at=now - timedelta(seconds=5),
        ),
        decision=DecisionRecord(
            summary="Create a follow-up task for the discharged patient",
            rationale="Discharge summary lists a cardiology follow-up within 7 days.",
            model=ModelInvocation(
                provider="bedrock",
                model="amazon.nova-pro-v1:0",
                prompt_digest=digest(f"{action_id}-prompt"),
                response_digest=digest(f"{action_id}-response"),
            ),
            confidence=0.92,
        ),
        evidence=evidence,
        outputs=outputs,
        authorization=resolved,
        correlation_id=correlation_id,
    )


@pytest.fixture
def client(
    settings: Settings, agent_idp: FakeIdp, auditor_idp: FakeIdp, clock: FakeClock
) -> Iterator[TestClient]:
    """App whose container is built inside the app's own event loop by its lifespan."""

    async def factory() -> Container:
        return await make_container(settings, agent_idp, auditor_idp, clock)

    app = create_app(factory, mcp_allowed_hosts=["testserver"])
    with TestClient(app) as test_client:
        yield test_client
