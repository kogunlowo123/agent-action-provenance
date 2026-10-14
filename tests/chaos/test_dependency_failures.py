"""Fault injection: the engine fails closed, reports unreadiness and recovers without loss."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from agent_action_provenance.api.app import archive_forever, monitor_forever
from agent_action_provenance.domain.errors import UpstreamUnavailableError
from agent_action_provenance.infrastructure.archive import ArchiveReceipt
from agent_action_provenance.infrastructure.database import make_engine
from agent_action_provenance.infrastructure.ledger import SqlLedger
from agent_action_provenance.integrations.identity_fabric import IdentityFabricClient
from agent_action_provenance.runtime.container import Container
from agent_action_provenance.security.authorization import FabricAuthorizer
from tests.conftest import FakeClock, FakeIdp, agent_token, submission

pytestmark = pytest.mark.chaos

BROKEN_DB = "sqlite+aiosqlite:////nonexistent/dir/provenance.sqlite"


def test_database_outage_flips_readiness(client: TestClient) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    assert client.get("/readyz").status_code == 200
    healthy = container.engine
    container.engine = make_engine(BROKEN_DB)
    try:
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200  # liveness unaffected
    finally:
        container.engine = healthy


def test_stopped_sequencer_fails_closed(
    client: TestClient, agent_idp: FakeIdp, clock: FakeClock
) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    client.portal.call(container.sequencer.aclose)  # type: ignore[union-attr]
    assert client.get("/readyz").json() == {"status": "sequencer stopped"}
    response = client.post(
        "/v1/records",
        json=submission(clock.now()).model_dump(mode="json"),
        headers={"Authorization": f"Bearer {agent_token(agent_idp)}"},
    )
    assert response.status_code == 503
    assert response.json()["error"] == "temporarily_unavailable"


async def test_ledger_outage_fails_requests_then_recovers(
    container: Container, agent_idp: FakeIdp, clock: FakeClock
) -> None:
    service = container.service
    token = agent_token(agent_idp)
    healthy = service._ledger
    service._sequencer._ledger = SqlLedger(make_engine(BROKEN_DB))
    with pytest.raises(Exception):  # noqa: B017, PT011 - driver error surfaces unchanged
        await service.record(token, submission(clock.now(), "act-chaos001"))
    assert container.metrics.batch_failures._value.get() == 1
    service._sequencer._ledger = healthy
    receipt = await service.record(token, submission(clock.now(), "act-chaos001"))
    assert receipt.leaf_index == 0
    assert not receipt.duplicate


async def test_audit_failure_after_commit_is_recoverable_by_retry(
    container: Container, agent_idp: FakeIdp, clock: FakeClock
) -> None:
    """Evidence that cannot be audited fails the request; the retry is idempotent."""
    service = container.service
    token = agent_token(agent_idp)
    sink = service._audit._sink
    original = sink.append

    async def broken(_: object) -> None:
        raise OSError("audit volume full")

    sink.append = broken  # type: ignore[method-assign]
    with pytest.raises(OSError, match="audit volume full"):
        await service.record(token, submission(clock.now()))
    sink.append = original  # type: ignore[method-assign]
    retry = await service.record(token, submission(clock.now()))
    assert retry.duplicate
    assert retry.leaf_index == 0
    assert (await service.latest_tree_head()).tree_size == 1


async def test_identity_fabric_outage_fails_closed(
    container: Container, agent_idp: FakeIdp, clock: FakeClock
) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timeout", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(down)) as http:
        container.service._authorizer = FabricAuthorizer(
            IdentityFabricClient("https://identity.corp.test", client=http),
            fabric_url="https://identity.corp.test",
        )
        with pytest.raises(UpstreamUnavailableError):
            await container.service.record(agent_token(agent_idp), submission(clock.now()))
    assert (await container.service.latest_tree_head()).tree_size == 0


async def test_archive_outage_builds_backlog_then_drains(
    container: Container, agent_idp: FakeIdp, clock: FakeClock
) -> None:
    service = container.service
    await service.record(agent_token(agent_idp), submission(clock.now()))
    working = service._archive

    class Offline:
        async def put(self, key: str, body: bytes, *, retain_until: datetime) -> ArchiveReceipt:
            raise OSError("bucket unreachable")

    service._archive = Offline()
    with pytest.raises(OSError, match="unreachable"):
        await service.archive_pending()
    assert container.metrics.archive_backlog._value.get() >= 1
    assert container.metrics.archive_failures._value.get() == 1
    service._archive = working
    assert await service.archive_pending() >= 1
    assert container.metrics.archive_backlog._value.get() == 0


async def test_background_loops_survive_failures(container: Container) -> None:
    calls = {"monitor": 0, "archive": 0}

    async def failing_check() -> Any:
        calls["monitor"] += 1
        raise RuntimeError("transient")

    async def failing_archive(limit: int = 50) -> int:
        calls["archive"] += 1
        raise RuntimeError("transient")

    container.service.check_integrity = failing_check  # type: ignore[method-assign]
    container.service.archive_pending = failing_archive  # type: ignore[method-assign]

    async def stop_after_two(_: float) -> None:
        if calls["monitor"] >= 2:
            raise asyncio.CancelledError
        await asyncio.sleep(0)

    with pytest.raises(asyncio.CancelledError):
        await monitor_forever(container, 0.0, sleep=stop_after_two)
    assert calls["monitor"] == 2

    task = asyncio.create_task(archive_forever(container, 0.01))
    container.archive_due.set()
    for _ in range(50):
        if calls["archive"] >= 2:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls["archive"] >= 2
