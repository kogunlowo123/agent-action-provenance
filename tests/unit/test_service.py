"""Provenance service use cases against SQLite through the production SQL code."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from agentic_core.audit import JsonlAuditSink, verify_chain
from agentic_core.domain.classification import DataClassification, TrustLevel
from agentic_core.policy import PolicyEngine, PolicySet, Resource

from agent_action_provenance.application.service import ProvenanceService
from agent_action_provenance.domain import merkle
from agent_action_provenance.domain.errors import (
    ApprovalRequiredError,
    ConflictError,
    ForbiddenError,
    InvalidRecordError,
    NotFoundError,
)
from agent_action_provenance.domain.exports import ExportCriteria
from agent_action_provenance.domain.log import verify_tree_head
from agent_action_provenance.domain.models import EvidenceItem, EvidenceKind, OutputArtifact
from agent_action_provenance.domain.verification import (
    verify_bundle,
    verify_consistency_proof,
    verify_inclusion_proof,
)
from agent_action_provenance.runtime.container import Container
from agent_action_provenance.security.authorization import AuditorPrincipal, AuditorRole
from tests.conftest import (
    AGENT,
    GATEWAY,
    FakeClock,
    FakeIdp,
    agent_token,
    agent_uri,
    digest,
    submission,
)

AUDITOR = AuditorPrincipal(subject="alice@corp.test", roles=frozenset({AuditorRole.AUDITOR}))
APPROVER = AuditorPrincipal(subject="bob@corp.test", roles=frozenset({AuditorRole.APPROVER}))


async def record_n(
    service: ProvenanceService, idp: FakeIdp, clock: FakeClock, n: int, prefix: str = "act"
) -> list[str]:
    token = agent_token(idp)
    receipts = await asyncio.gather(
        *(service.record(token, submission(clock.now(), f"{prefix}-{i:08d}")) for i in range(n))
    )
    return [r.record_id for r in receipts]


class TestRecording:
    async def test_receipt_proves_inclusion_under_a_signed_head(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        receipt = await service.record(agent_token(agent_idp), submission(clock.now()))
        assert receipt.leaf_index == 0
        assert not receipt.duplicate
        assert receipt.tree_head.tree_size == 1
        assert verify_tree_head(receipt.tree_head, service._signer.public_key)
        stored = await service.ledger.get(receipt.record_id)
        assert stored is not None
        assert not verify_inclusion_proof(
            receipt.inclusion_proof, stored.leaf_bytes, receipt.tree_head
        )
        assert receipt.record_digest == stored.record.digest()
        assert receipt.governance.compliant

    async def test_prov_document_and_audit_event(
        self, container: Container, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        service = container.service
        receipt = await service.record(agent_token(agent_idp), submission(clock.now()))
        view = await service.get_record(receipt.record_id)
        document = view.record["prov"]
        assert {
            "entity",
            "activity",
            "agent",
            "used",
            "wasGeneratedBy",
            "wasDerivedFrom",
            "wasAssociatedWith",
            "actedOnBehalfOf",
            "wasInformedBy",
        } <= set(document)
        events = [e async for e in JsonlAuditSink(container.settings.audit_log_path).read()]
        recorded = [e for e in events if e.action == "provenance.record"]
        assert recorded[0].details["record_digest"] == receipt.record_digest
        assert verify_chain(events, {events[0].key_id: service._audit._signer.public_key()}) == len(
            events
        )

    async def test_concurrent_submissions_are_group_committed(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        ids = await record_n(service, agent_idp, clock, 40)
        head = await service.latest_tree_head()
        assert head.tree_size == 40
        assert len(set(ids)) == 40
        # far fewer signed heads than records: batching shared the signature
        heads = [await service.ledger.tree_head(n) for n in range(1, 41)]
        assert sum(h is not None for h in heads) < 40
        tree = merkle.MerkleTree()
        for index, document in await service.ledger.leaves_between(0, 40):
            assert tree.append(document) == index
        assert tree.root().hex() == head.root_hash

    async def test_idempotent_retry_and_conflicting_reuse(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        token = agent_token(agent_idp)
        first = await service.record(token, submission(clock.now()))
        again = await service.record(token, submission(clock.now()))
        assert again.duplicate
        assert again.record_id == first.record_id
        assert again.leaf_index == first.leaf_index
        changed = submission(clock.now(), action="fhir:write:careplan")
        with pytest.raises(ConflictError, match="different content"):
            await service.record(token, changed)

    async def test_duplicates_in_one_batch_collapse(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        token = agent_token(agent_idp)
        same = submission(clock.now())
        results = await asyncio.gather(*(service.record(token, same) for _ in range(5)))
        assert len({r.record_id for r in results}) == 1
        assert (await service.latest_tree_head()).tree_size == 1
        assert sum(not r.duplicate for r in results) == 1

    async def test_derivation_cycle_is_rejected(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        a, b = digest("a"), digest("b")
        outputs = (
            OutputArtifact(
                uri="x:a", digest=a, classification=DataClassification.INTERNAL, derived_from=(b,)
            ),
            OutputArtifact(
                uri="x:b", digest=b, classification=DataClassification.INTERNAL, derived_from=(a,)
            ),
        )
        with pytest.raises(InvalidRecordError, match="cycle"):
            await service.record(agent_token(agent_idp), submission(clock.now(), outputs=outputs))
        assert (await service.latest_tree_head()).tree_size == 0

    async def test_violations_are_recorded_not_refused(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        receipt = await service.record(agent_token(agent_idp), submission(clock.now(), auth=False))
        assert not receipt.governance.compliant
        assert [f.code for f in receipt.governance.findings] == ["authorization_missing"]


class TestAuthorization:
    async def test_agent_cannot_record_for_another_agent(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        other = agent_token(agent_idp, agent_uri("scheduler"))
        with pytest.raises(ForbiddenError, match="denied"):
            await service.record(other, submission(clock.now()))

    async def test_scope_is_required(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        with pytest.raises(ForbiddenError):
            await service.record(
                agent_token(agent_idp, scope="fhir:read:*"), submission(clock.now())
            )

    async def test_gateway_records_for_agents_it_fronts(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        gateway = agent_token(agent_idp, GATEWAY, scope="provenance:record:delegate")
        receipt = await service.record(gateway, submission(clock.now()))
        stored = await service.ledger.get(receipt.record_id)
        assert stored is not None
        assert stored.record.recorded_by == GATEWAY

    async def test_delegated_gateway_credential_cannot_record_for_others(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        token = agent_token(
            agent_idp,
            GATEWAY,
            scope="provenance:record:delegate",
            act={"sub": agent_uri("orchestrator")},
        )
        with pytest.raises(ForbiddenError):
            await service.record(token, submission(clock.now()))

    async def test_require_approval_outcome_is_raised(
        self, container: Container, agent_idp: FakeIdp
    ) -> None:
        policy = PolicyEngine(
            PolicySet.model_validate(
                {
                    "name": "t",
                    "version": "1",
                    "rules": [
                        {"id": "hold", "effect": "require_approval", "actions": ["*"]},
                    ],
                }
            )
        )
        container.service._authorizer._policy = policy  # type: ignore[attr-defined]
        with pytest.raises(ApprovalRequiredError, match="approval"):
            await container.service.authorize_agent(
                agent_token(agent_idp),
                action="provenance:log:read",
                resource=Resource(type="transparency-log"),
            )


class TestLogQueries:
    async def test_inclusion_and_consistency_across_heads(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        await record_n(service, agent_idp, clock, 3, "first")
        old = await service.latest_tree_head()
        await record_n(service, agent_idp, clock, 9, "second")
        new = await service.latest_tree_head()
        proof = await service.consistency_proof(old.tree_size, new.tree_size)
        assert verify_consistency_proof(proof, old, new) == []
        for index in range(new.tree_size):
            inclusion = await service.inclusion_proof(index)
            assert verify_inclusion_proof(inclusion, None, new) == []
        assert await service.tree_head(old.tree_size) == old

    async def test_query_bounds(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        await record_n(service, agent_idp, clock, 2)
        with pytest.raises(NotFoundError):
            await service.inclusion_proof(0, 5)
        with pytest.raises(NotFoundError):
            await service.inclusion_proof(3)
        with pytest.raises(NotFoundError):
            await service.consistency_proof(1, 7)
        with pytest.raises(InvalidRecordError):
            await service.consistency_proof(2, 1)
        with pytest.raises(NotFoundError):
            await service.tree_head(99)
        with pytest.raises(InvalidRecordError):
            await service.entries(5, 2)
        with pytest.raises(NotFoundError):
            await service.get_record("missing")
        with pytest.raises(NotFoundError):
            await service.verify_record("missing")
        entries = await service.entries(0, 10)
        assert [e.leaf_index for e in entries] == [0, 1]

    async def test_verify_record(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        (record_id,) = await record_n(service, agent_idp, clock, 1)
        report = await service.verify_record(record_id)
        assert report.valid
        assert report.problems == ()

    async def test_search_filters(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        token = agent_token(agent_idp)
        await service.record(token, submission(clock.now(), "act-a0000001", correlation_id="c-1"))
        await service.record(token, submission(clock.now(), "act-a0000002", auth=False))
        from agent_action_provenance.domain.ports import RecordFilter

        assert (
            len(await service.search(RecordFilter(correlation_id="c-1"), limit=10, offset=0)) == 1
        )
        assert len(await service.search(RecordFilter(compliant=False), limit=10, offset=0)) == 1
        assert (
            len(
                await service.search(
                    RecordFilter(
                        agent_id=AGENT,
                        action="fhir:write:task",
                        since=clock.now().replace(year=2000),
                        until=clock.now().replace(year=2100),
                    ),
                    limit=10,
                    offset=0,
                )
            )
            == 2
        )


class TestLineage:
    async def test_traces_artifact_back_through_actions(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        token = agent_token(agent_idp)
        now = clock.now()
        source = EvidenceItem(
            uri="s3://lab/raw.csv",
            digest=digest("raw"),
            kind=EvidenceKind.DOCUMENT,
            trust=TrustLevel.VERIFIED,
            classification=DataClassification.CONFIDENTIAL,
            retrieved_at=now,
        )
        summary = OutputArtifact(
            uri="s3://lab/summary.json",
            digest=digest("summary"),
            classification=DataClassification.CONFIDENTIAL,
            derived_from=(source.digest,),
        )
        first = await service.record(
            token, submission(now, "act-l0000001", evidence=(source,), outputs=(summary,))
        )
        as_evidence = EvidenceItem(
            uri=summary.uri,
            digest=summary.digest,
            kind=EvidenceKind.RECORD,
            trust=TrustLevel.VERIFIED,
            classification=DataClassification.CONFIDENTIAL,
            retrieved_at=now,
        )
        report = OutputArtifact(
            uri="s3://lab/report.pdf",
            digest=digest("report"),
            classification=DataClassification.CONFIDENTIAL,
            derived_from=(summary.digest,),
        )
        second = await service.record(
            token, submission(now, "act-l0000002", evidence=(as_evidence,), outputs=(report,))
        )
        graph = await service.lineage(report.digest)
        assert {r.record_id for r in graph.records} == {first.record_id, second.record_id}
        relations = {(e.source, e.target, e.relation) for e in graph.edges}
        assert (report.digest, second.record_id, "wasGeneratedBy") in relations
        assert (summary.digest, source.digest, "wasDerivedFrom") in relations
        assert (first.record_id, source.digest, "used") in relations
        assert not graph.truncated
        shallow = await service.lineage(report.digest, max_depth=1)
        assert shallow.truncated
        assert shallow.depth == 1
        capped = await service.lineage(report.digest, max_records=0)
        assert capped.truncated


class TestExports:
    async def test_confidential_export_is_ready_and_verifies(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        now = clock.now()
        evidence = (
            EvidenceItem(
                uri="doc:1",
                digest=digest("doc1"),
                kind=EvidenceKind.DOCUMENT,
                trust=TrustLevel.VERIFIED,
                classification=DataClassification.CONFIDENTIAL,
                retrieved_at=now,
            ),
        )
        receipt = await service.record(
            agent_token(agent_idp), submission(now, evidence=evidence, outputs=())
        )
        view = await service.request_export(
            AUDITOR, ExportCriteria(record_ids=(receipt.record_id,), purpose="SOX quarterly review")
        )
        assert view.status == "ready"
        assert view.record_count == 1
        bundle = await service.export_bundle(AUDITOR, view.export_id)
        result = verify_bundle(bundle, service._signer.public_key)
        assert result.valid, result
        assert (await service.get_export(APPROVER, view.export_id)).export_id == view.export_id

    async def test_restricted_export_requires_a_second_person(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        await record_n(service, agent_idp, clock, 2)
        view = await service.request_export(
            AUDITOR, ExportCriteria(agent_id=AGENT, purpose="HIPAA access review")
        )
        assert view.status == "pending_approval"
        assert view.matched_rules == ("approve-restricted-evidence",)
        with pytest.raises(ApprovalRequiredError):
            await service.export_bundle(AUDITOR, view.export_id)
        dual = AuditorPrincipal(
            subject=AUDITOR.subject, roles=frozenset({AuditorRole.AUDITOR, AuditorRole.APPROVER})
        )
        with pytest.raises(ForbiddenError, match="own export"):
            await service.approve_export(dual, view.export_id)
        approved = await service.approve_export(APPROVER, view.export_id)
        assert approved.status == "ready"
        assert approved.approved_by == APPROVER.subject
        with pytest.raises(ConflictError):
            await service.approve_export(APPROVER, view.export_id)
        bundle = await service.export_bundle(AUDITOR, view.export_id)
        assert len(bundle.entries) == 2
        other = AuditorPrincipal(subject="carol@corp.test", roles=frozenset({AuditorRole.AUDITOR}))
        with pytest.raises(ForbiddenError, match="requesting auditor"):
            await service.export_bundle(other, view.export_id)

    async def test_export_rules(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        with pytest.raises(NotFoundError):
            await service.request_export(
                AUDITOR, ExportCriteria(agent_id=AGENT, purpose="none yet")
            )
        await record_n(service, agent_idp, clock, 3)
        nobody = AuditorPrincipal(subject="eve@corp.test", roles=frozenset())
        with pytest.raises(ForbiddenError, match="denied"):
            await service.request_export(nobody, ExportCriteria(agent_id=AGENT, purpose="curious"))
        service._export_max = 2
        with pytest.raises(InvalidRecordError, match="narrow"):
            await service.request_export(
                AUDITOR, ExportCriteria(agent_id=AGENT, purpose="all of it")
            )
        with pytest.raises(NotFoundError):
            await service.approve_export(APPROVER, "missing")
        with pytest.raises(ForbiddenError):
            await service.approve_export(AUDITOR, "missing")


class TestIntegrityAndArchive:
    async def test_monitor_accepts_honest_growth(
        self, service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        first = await service.check_integrity()
        assert first.ok
        assert first.tree_size == 0
        await record_n(service, agent_idp, clock, 5)
        second = await service.check_integrity()
        assert second.ok
        assert second.tree_size == 5
        assert second.checked_from == 0
        await record_n(service, agent_idp, clock, 4, "more")
        third = await service.check_integrity()
        assert third.ok
        assert third.checked_from == 5

    async def test_archive_writes_self_verifying_worm_objects(
        self, container: Container, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        service = container.service
        await record_n(service, agent_idp, clock, 3)
        archived = await service.archive_pending()
        assert archived >= 2  # genesis head plus at least one batch
        assert await service.archive_pending() == 0
        root: Path = container.settings.archive_dir
        files = sorted((root / "batches").iterdir())
        latest = json.loads(files[-1].read_bytes())
        assert latest["tree_head"]["tree_size"] == 3
        tree = merkle.MerkleTree()
        for _, document in await service.ledger.leaves_between(0, 3):
            tree.append(document)
        assert latest["tree_head"]["root_hash"] == tree.root().hex()
        assert container.metrics.archive_backlog._value.get() == 0
