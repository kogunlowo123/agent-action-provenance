"""Group-commit sequencer edge cases, the verification CLI and published contracts."""

from __future__ import annotations

import asyncio
import io
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from agentic_core.audit import AuditLog, JsonlAuditSink
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.exc import IntegrityError

from agent_action_provenance import cli
from agent_action_provenance.application.sequencer import BatchSequencer
from agent_action_provenance.application.service import ProvenanceService
from agent_action_provenance.contracts import main as contracts_main
from agent_action_provenance.domain import governance, prov
from agent_action_provenance.domain.errors import ConflictError, UpstreamUnavailableError
from agent_action_provenance.domain.models import ProvenanceRecord
from agent_action_provenance.domain.ports import SealedBatch, Sealer
from agent_action_provenance.observability.metrics import ProvenanceMetrics
from agent_action_provenance.runtime.container import Container
from agent_action_provenance.security.authorization import AuditorPrincipal, AuditorRole
from agent_action_provenance.security.keys import public_pem
from agent_action_provenance.security.signing import TreeHeadSigner
from tests.conftest import AGENT, ROOT, FakeClock, FakeIdp, agent_token, submission

NOW = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)


def record(action_id: str, record_id: str) -> ProvenanceRecord:
    s = submission(NOW, action_id)
    return ProvenanceRecord(
        record_id=record_id,
        recorded_at=NOW,
        recorded_by=AGENT,
        submission=s,
        submission_digest=s.digest(),
        prov=prov.build_document(record_id, s, recorded_by=AGENT, recorded_at=NOW),
        governance=governance.assess(s),
    )


class FakeLedger:
    """Ledger double that fails in scripted ways."""

    def __init__(self, failures: list[BaseException | None]) -> None:
        self.failures = failures
        self.batches: list[list[str]] = []
        self.signer = TreeHeadSigner(Ed25519PrivateKey.generate())

    async def append_batch(self, batch: Sequence[ProvenanceRecord], seal: Sealer) -> SealedBatch:
        failure = self.failures.pop(0) if self.failures else None
        if failure is not None:
            raise failure
        start = sum(len(b) for b in self.batches)
        self.batches.append([r.record_id for r in batch])
        head = self.signer.sign(tree_size=start + len(batch), root_hash=b"\0" * 32, timestamp_ms=0)
        return SealedBatch(start=start, tree_head=head, leaf_hashes=tuple("0" * 64 for _ in batch))


def integrity() -> IntegrityError:
    return IntegrityError("insert", {}, Exception("unique"))


class TestSequencer:
    async def test_not_running_and_close_fails_pending(self) -> None:
        sequencer = BatchSequencer(FakeLedger([]), lambda s, r: None, ProvenanceMetrics())  # type: ignore[arg-type,return-value]
        with pytest.raises(UpstreamUnavailableError, match="not running"):
            await sequencer.submit(record("act-00000001", "r1"))
        sequencer.start()
        sequencer.start()  # idempotent
        await sequencer.aclose()
        assert not sequencer.running
        # a request queued but never collected is failed on close
        sequencer._worker = asyncio.create_task(asyncio.sleep(3600))
        pending = asyncio.create_task(sequencer.submit(record("act-00000002", "r2")))
        await asyncio.sleep(0)
        await sequencer.aclose()
        with pytest.raises(UpstreamUnavailableError, match="stopped"):
            await pending

    async def test_conflicting_batch_is_retried_record_by_record(self) -> None:
        ledger = FakeLedger([integrity(), None, integrity(), RuntimeError("disk")])
        sequencer = BatchSequencer(
            ledger,
            lambda s, r: None,
            ProvenanceMetrics(),  # type: ignore[arg-type,return-value]
            max_wait_s=0.05,
        )
        sequencer.start()
        try:
            results = await asyncio.gather(
                *(sequencer.submit(record(f"act-0000000{i}", f"r{i}")) for i in range(3)),
                return_exceptions=True,
            )
        finally:
            await sequencer.aclose()
        assert results[0].leaf_index == 0  # type: ignore[union-attr]
        assert isinstance(results[1], ConflictError)
        assert isinstance(results[2], RuntimeError)

    async def test_batch_failure_reaches_every_waiter_then_recovers(self) -> None:
        metrics = ProvenanceMetrics()
        ledger = FakeLedger([OSError("db down")])
        sequencer = BatchSequencer(ledger, lambda s, r: None, metrics, max_wait_s=0.05)  # type: ignore[arg-type,return-value]
        sequencer.start()
        try:
            failed = await asyncio.gather(
                *(sequencer.submit(record(f"act-1000000{i}", f"f{i}")) for i in range(3)),
                return_exceptions=True,
            )
            assert all(isinstance(r, OSError) for r in failed)
            ok = await sequencer.submit(record("act-20000001", "ok"))
            assert ok.record_id == "ok"
        finally:
            await sequencer.aclose()
        assert metrics.batch_failures._value.get() == 1

    async def test_batch_size_limit(self) -> None:
        ledger = FakeLedger([])
        sequencer = BatchSequencer(
            ledger,
            lambda s, r: None,
            ProvenanceMetrics(),  # type: ignore[arg-type,return-value]
            max_batch=2,
            max_wait_s=0.0,
        )
        sequencer.start()
        try:
            await asyncio.gather(
                *(sequencer.submit(record(f"act-3000000{i}", f"b{i}")) for i in range(5))
            )
        finally:
            await sequencer.aclose()
        assert all(len(b) <= 2 for b in ledger.batches)
        assert sum(map(len, ledger.batches)) == 5


async def make_bundle(service: ProvenanceService, idp: FakeIdp, clock: FakeClock) -> dict[str, Any]:
    receipt = await service.record(agent_token(idp), submission(clock.now(), outputs=()))
    from agent_action_provenance.domain.exports import ExportCriteria

    auditor = AuditorPrincipal(subject="a@corp.test", roles=frozenset({AuditorRole.AUDITOR}))
    approver = AuditorPrincipal(subject="b@corp.test", roles=frozenset({AuditorRole.APPROVER}))
    view = await service.request_export(
        auditor, ExportCriteria(record_ids=(receipt.record_id,), purpose="annual audit")
    )
    await service.approve_export(approver, view.export_id)
    return (await service.export_bundle(auditor, view.export_id)).model_dump(mode="json")


def run(argv: list[str], transport: httpx.BaseTransport | None = None) -> tuple[int, Any, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, transport=transport, stdout=out, stderr=err)
    text = out.getvalue()
    try:
        parsed: Any = json.loads(text)
    except ValueError:
        parsed = text
    return code, parsed, err.getvalue()


class TestCli:
    async def test_bundle_verification(
        self, container: Container, agent_idp: FakeIdp, clock: FakeClock, tmp_path: Path
    ) -> None:
        service = container.service
        bundle = await make_bundle(service, agent_idp, clock)
        key = tmp_path / "log.pub.pem"
        key.write_bytes(public_pem(service._signer.public_key))
        path = tmp_path / "bundle.json"
        path.write_text(json.dumps(bundle))
        code, report, _ = run(["bundle", str(path), "--public-key", str(key)])
        assert code == 0
        assert report["valid"]
        bundle["entries"][0]["record"]["recorded_by"] = "spiffe://agents.corp.test/agent/x/y"
        path.write_text(json.dumps(bundle))
        code, report, _ = run(["bundle", str(path), "--public-key", str(key)])
        assert code == 1
        assert not report["valid"]
        code, _, err = run(["bundle", str(tmp_path / "missing.json"), "--public-key", str(key)])
        assert code == 2
        assert "error" in err

    async def test_consistency_and_monitor(
        self, container: Container, agent_idp: FakeIdp, clock: FakeClock, tmp_path: Path
    ) -> None:
        service = container.service
        token = agent_token(agent_idp)
        await service.record(token, submission(clock.now(), "act-c0000001"))
        old = await service.latest_tree_head()
        await service.record(token, submission(clock.now(), "act-c0000002"))
        await service.record(token, submission(clock.now(), "act-c0000003"))
        new = await service.latest_tree_head()
        proof = await service.consistency_proof(old.tree_size, new.tree_size)
        key = tmp_path / "log.pub.pem"
        key.write_bytes(public_pem(service._signer.public_key))
        files = {}
        for name, model in (("old", old), ("new", new), ("proof", proof)):
            files[name] = tmp_path / f"{name}.json"
            files[name].write_text(model.model_dump_json())
        args = [
            "consistency",
            "--old",
            str(files["old"]),
            "--new",
            str(files["new"]),
            "--proof",
            str(files["proof"]),
            "--public-key",
            str(key),
        ]
        assert run(args)[0] == 0
        files["old"].write_text(new.model_dump_json())
        files["new"].write_text(old.model_dump_json())
        code, report, _ = run(args)
        assert code == 1
        assert "the log shrank" in " ".join(report["problems"])

        heads = [old, new]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/log/tree-head":
                return httpx.Response(200, json=heads[0].model_dump(mode="json"))
            return httpx.Response(200, json=proof.model_dump(mode="json"))

        transport = httpx.MockTransport(handler)
        state = tmp_path / "state.json"
        monitor = [
            "monitor",
            "--url",
            "https://provenance.corp.test/",
            "--public-key",
            str(key),
            "--state",
            str(state),
        ]
        code, report, _ = run(monitor, transport)
        assert code == 0
        assert report["previous_size"] is None
        assert state.exists()
        heads.pop(0)
        code, report, _ = run(monitor, transport)
        assert code == 0
        assert report["previous_size"] == old.tree_size
        heads[0] = old  # the log now claims to be smaller: a rollback
        code, report, _ = run(monitor, transport)
        assert code == 1
        assert "shrank" in report["problems"][0]
        state.unlink()
        heads[0] = new.model_copy(update={"root_hash": "00" * 32})
        code, report, _ = run(monitor, transport)
        assert code == 1
        assert report["problems"] == ["tree head signature is invalid"]

    async def test_archive_replay(
        self, container: Container, agent_idp: FakeIdp, clock: FakeClock, tmp_path: Path
    ) -> None:
        service = container.service
        token = agent_token(agent_idp)
        for i in range(3):
            await service.record(token, submission(clock.now(), f"act-arch{i:04d}"))
            await service.archive_pending()
        key = tmp_path / "log.pub.pem"
        key.write_bytes(public_pem(service._signer.public_key))
        root = container.settings.archive_dir
        code, report, _ = run(["archive", str(root), "--public-key", str(key)])
        assert code == 0, report
        assert report["tree_size"] == 3
        assert report["root_hash"] == (await service.latest_tree_head()).root_hash

        last = sorted((root / "batches").glob("*.json"))[-1]
        last.chmod(0o644)
        document = json.loads(last.read_bytes())
        document["entries"][0]["record"]["recorded_by"] = "spiffe://agents.corp.test/agent/x/y"
        last.write_text(json.dumps(document))
        code, report, _ = run(["archive", str(root), "--public-key", str(key)])
        assert code == 1
        assert "replayed root differs" in report["problems"][0]
        document["entries"][0]["leaf_index"] = 7
        last.write_text(json.dumps(document))
        code, report, _ = run(["archive", str(root), "--public-key", str(key)])
        assert "expected leaf 2" in report["problems"][0]
        other = tmp_path / "other.pem"
        other.write_bytes(public_pem(Ed25519PrivateKey.generate().public_key()))
        code, report, _ = run(["archive", str(root), "--public-key", str(other)])
        assert "signature is invalid" in report["problems"][0]
        code, report, _ = run(["archive", str(tmp_path / "empty"), "--public-key", str(key)])
        assert code == 1
        assert report["problems"] == ["no archived batches found under batches/"]

    async def test_audit_chain_and_keygen(self, tmp_path: Path) -> None:
        key = Ed25519PrivateKey.generate()
        chain = tmp_path / "audit.jsonl"
        audit = AuditLog(JsonlAuditSink(chain), key, key_id="audit-2026-10")
        for i in range(3):
            await audit.record(actor="a", action="x", resource=f"r{i}", outcome="success")
        pub = tmp_path / "audit.pub.pem"
        pub.write_bytes(public_pem(key.public_key()))
        code, report, _ = run(["audit-chain", str(chain), "--public-key", str(pub)])
        assert code == 0
        assert report == {"valid": True, "events": 3}
        lines = chain.read_text().splitlines()
        tampered = json.loads(lines[1])
        tampered["outcome"] = "failure"
        lines[1] = json.dumps(tampered)
        chain.write_text("\n".join(lines) + "\n")
        code, report, _ = run(
            ["audit-chain", str(chain), "--public-key", str(pub), "--key-id", "audit-2026-10"]
        )
        assert code == 1
        assert report["sequence"] == 1

        out, err = io.StringIO(), io.StringIO()
        assert cli.main(["keygen"], stdout=out, stderr=err) == 0
        assert "PRIVATE KEY" in out.getvalue()
        assert "PUBLIC KEY" in err.getvalue()


class TestContracts:
    def test_committed_contracts_are_current(self) -> None:
        assert contracts_main(["--check"], root=ROOT) == 0

    def test_export_and_check_round_trip(self, tmp_path: Path) -> None:
        assert contracts_main(["--check"], root=tmp_path) == 1
        assert contracts_main([], root=tmp_path) == 0
        assert contracts_main(["--check"], root=tmp_path) == 0
        assert (tmp_path / "schemas" / "action-submission.request.schema.json").is_file()
        assert (tmp_path / "docs" / "api" / "openapi.json").is_file()
