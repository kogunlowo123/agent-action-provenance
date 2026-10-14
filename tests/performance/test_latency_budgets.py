"""Latency and throughput budgets for hot paths. Loose enough for shared CI runners."""

from __future__ import annotations

import asyncio
import time

import pytest

from agent_action_provenance.application.service import ProvenanceService
from agent_action_provenance.domain import merkle
from tests.conftest import FakeClock, FakeIdp, agent_token, submission

pytestmark = pytest.mark.performance


def test_merkle_append_and_proof_budget() -> None:
    tree = merkle.MerkleTree()
    started = time.perf_counter()
    for i in range(20_000):
        tree.append(i.to_bytes(8, "big"))
    append_us = (time.perf_counter() - started) * 1e6 / 20_000
    assert append_us < 250

    root = tree.root()
    started = time.perf_counter()
    for index in range(0, 20_000, 40):
        proof = tree.inclusion_proof(index)
        assert merkle.verify_inclusion(
            merkle.leaf_hash(index.to_bytes(8, "big")), index, 20_000, proof, root
        )
    per_proof_ms = (time.perf_counter() - started) * 1000 / 500
    assert per_proof_ms < 2
    assert len(tree.inclusion_proof(12_345)) <= 15  # O(log n)


async def test_group_commit_beats_sequential_commits(
    service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
) -> None:
    """Batching must raise throughput relative to one-at-a-time commits on the same machine."""
    token = agent_token(agent_idp)
    started = time.perf_counter()
    for i in range(30):
        await service.record(token, submission(clock.now(), f"act-seq{i:05d}"))
    sequential_rate = 30 / (time.perf_counter() - started)

    submissions = [submission(clock.now(), f"act-perf{i:05d}") for i in range(300)]
    started = time.perf_counter()
    receipts = await asyncio.gather(*(service.record(token, s) for s in submissions))
    concurrent_rate = 300 / (time.perf_counter() - started)

    assert len({r.leaf_index for r in receipts}) == 300
    assert concurrent_rate > 1.5 * sequential_rate, (concurrent_rate, sequential_rate)
    assert concurrent_rate > 15  # absolute floor, SQLite on a loaded shared runner


async def test_proof_query_budget(
    service: ProvenanceService, agent_idp: FakeIdp, clock: FakeClock
) -> None:
    token = agent_token(agent_idp)
    await asyncio.gather(
        *(service.record(token, submission(clock.now(), f"act-q{i:07d}")) for i in range(64))
    )
    started = time.perf_counter()
    for index in range(64):
        await service.inclusion_proof(index)
    per_proof_ms = (time.perf_counter() - started) * 1000 / 64
    assert per_proof_ms < 50
