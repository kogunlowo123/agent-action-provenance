"""Dependency container built once per process from Settings."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

import boto3
import httpx
from agentic_core.audit import AuditLog, JsonlAuditSink
from agentic_core.policy import PolicyEngine, PolicySet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncEngine

from agent_action_provenance.application.sequencer import BatchSequencer
from agent_action_provenance.application.service import ProvenanceService
from agent_action_provenance.config import Settings
from agent_action_provenance.domain.ports import Clock, SealedBatch
from agent_action_provenance.infrastructure.archive import (
    EvidenceArchive,
    FilesystemWormArchive,
    S3ObjectLockArchive,
)
from agent_action_provenance.infrastructure.database import SystemClock, create_schema, make_engine
from agent_action_provenance.infrastructure.exports import SqlExportRepository
from agent_action_provenance.infrastructure.ledger import SqlLedger
from agent_action_provenance.integrations.identity_fabric import IdentityFabricClient
from agent_action_provenance.observability.metrics import ProvenanceMetrics
from agent_action_provenance.security.authorization import (
    AgentAuthorizer,
    AuditorAuthenticator,
    FabricAuthorizer,
    LocalPolicyAuthorizer,
)
from agent_action_provenance.security.jwks import KeyResolver, RemoteJwks
from agent_action_provenance.security.keys import load_private_key
from agent_action_provenance.security.signing import TreeHeadSigner

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client


@dataclass
class Container:
    settings: Settings
    service: ProvenanceService
    sequencer: BatchSequencer
    auditors: AuditorAuthenticator
    metrics: ProvenanceMetrics
    engine: AsyncEngine
    http: httpx.AsyncClient
    archive_due: asyncio.Event

    async def aclose(self) -> None:
        await self.sequencer.aclose()
        await self.http.aclose()
        await self.engine.dispose()


def _keys(settings: Settings) -> tuple[Ed25519PrivateKey, Ed25519PrivateKey, str]:
    if settings.dev_ephemeral_keys:
        return Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), "audit-ephemeral"
    if settings.log_key_file is None or settings.audit_key_file is None:
        raise ValueError("signing keys are not configured")  # pragma: no cover - validated
    return (
        load_private_key(settings.log_key_file),
        load_private_key(settings.audit_key_file),
        settings.audit_key_file.stem,
    )


def _archive(settings: Settings, s3_client: S3Client | None) -> EvidenceArchive:
    if settings.archive_backend == "s3":
        if settings.archive_bucket is None:
            raise ValueError("archive bucket is not configured")  # pragma: no cover - validated
        client = s3_client or boto3.client("s3", region_name=settings.archive_region)
        return S3ObjectLockArchive(
            client,
            bucket=settings.archive_bucket,
            prefix=settings.archive_prefix,
            mode=settings.archive_lock_mode,
        )
    return FilesystemWormArchive(settings.archive_dir)


def _authorizer(
    settings: Settings, http: httpx.AsyncClient, agent_resolver: KeyResolver | None
) -> AgentAuthorizer:
    if settings.fabric_url is not None:
        url = str(settings.fabric_url)
        return FabricAuthorizer(IdentityFabricClient(url, client=http), fabric_url=url)
    if not (settings.agent_issuer and settings.agent_audience and settings.agent_jwks_url):
        raise ValueError("agent verification is not configured")  # pragma: no cover - validated
    return LocalPolicyAuthorizer(
        agent_resolver or RemoteJwks(settings.agent_jwks_url, client=http),
        PolicyEngine(PolicySet.from_file(settings.access_policy_file)),
        issuer=settings.agent_issuer,
        audience=settings.agent_audience,
    )


async def build_container(
    settings: Settings,
    *,
    agent_resolver: KeyResolver | None = None,
    auditor_resolver: KeyResolver | None = None,
    clock: Clock | None = None,
    http: httpx.AsyncClient | None = None,
    s3_client: S3Client | None = None,
) -> Container:
    http = http or httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    log_key, audit_key, audit_kid = _keys(settings)
    engine = make_engine(settings.database_url)
    await create_schema(engine)

    metrics = ProvenanceMetrics()
    ledger = SqlLedger(engine)
    archive_due = asyncio.Event()

    def sealed(_: SealedBatch) -> None:
        archive_due.set()

    signer = TreeHeadSigner(log_key)
    clock = clock or SystemClock()
    sequencer = BatchSequencer(
        ledger,
        signer.sealer(clock.now),
        metrics,
        max_batch=settings.batch_max_size,
        max_wait_s=settings.batch_max_wait,
        on_sealed=sealed,
    )
    service = ProvenanceService(
        ledger=ledger,
        exports=SqlExportRepository(engine),
        sequencer=sequencer,
        signer=signer,
        authorizer=_authorizer(settings, http, agent_resolver),
        export_policy=PolicyEngine(PolicySet.from_file(settings.export_policy_file)),
        archive=_archive(settings, s3_client),
        audit=AuditLog(JsonlAuditSink(settings.audit_log_path), audit_key, key_id=audit_kid),
        metrics=metrics,
        clock=clock,
        export_max_records=settings.export_max_records,
        archive_retention=settings.archive_retention,
    )
    head = await service.latest_tree_head()
    metrics.tree_size.set(head.tree_size)
    sequencer.start()
    auditors = AuditorAuthenticator(
        auditor_resolver or RemoteJwks(settings.auditor_jwks_url, client=http),
        issuer=settings.auditor_issuer,
        audience=settings.auditor_audience,
        roles_claim=settings.auditor_roles_claim,
    )
    return Container(
        settings=settings,
        service=service,
        sequencer=sequencer,
        auditors=auditors,
        metrics=metrics,
        engine=engine,
        http=http,
        archive_due=archive_due,
    )
