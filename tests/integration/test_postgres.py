"""Ledger behaviour against a real PostgreSQL (CI service container).

Runs when PROVENANCE_TEST_DATABASE_URL points at PostgreSQL, e.g.
postgresql+asyncpg://provenance:provenance@localhost:5432/provenance
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_action_provenance.domain import governance, merkle, prov
from agent_action_provenance.domain.models import ProvenanceRecord
from agent_action_provenance.infrastructure.database import create_schema, make_engine
from agent_action_provenance.infrastructure.ledger import SqlLedger
from agent_action_provenance.security.signing import TreeHeadSigner
from tests.conftest import AGENT, submission

URL = os.environ.get("PROVENANCE_TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL.startswith("postgresql"), reason="PostgreSQL not configured"),
]


def record(tag: str) -> ProvenanceRecord:
    now = datetime.now(UTC)
    rid = uuid.uuid4().hex
    s = submission(now, f"act-{tag}")
    return ProvenanceRecord(
        record_id=rid,
        recorded_at=now,
        recorded_by=AGENT,
        submission=s,
        submission_digest=s.digest(),
        prov=prov.build_document(rid, s, recorded_by=AGENT, recorded_at=now),
        governance=governance.assess(s),
    )


async def test_concurrent_replicas_never_fork_the_log() -> None:
    signer = TreeHeadSigner(Ed25519PrivateKey.generate())
    seal = signer.sealer(lambda: datetime.now(UTC))
    engines = [make_engine(URL), make_engine(URL)]
    await create_schema(engines[0])
    await create_schema(engines[1])  # idempotent, as on every replica start
    replicas = [SqlLedger(e) for e in engines]
    await replicas[0].ensure_genesis(seal)
    await replicas[1].ensure_genesis(seal)
    before = await replicas[0].tree_size()
    run = uuid.uuid4().hex[:8]

    async def writer(ledger: SqlLedger, name: str) -> list[int]:
        starts = []
        for batch in range(10):
            sealed = await ledger.append_batch(
                [record(f"{run}-{name}-{batch}-{i}") for i in range(5)], seal
            )
            starts.append(sealed.start)
        return starts

    a, b = await asyncio.gather(writer(replicas[0], "a"), writer(replicas[1], "b"))
    after = await replicas[0].tree_size()
    assert after - before == 100
    assert len(set(a) | set(b)) == 20  # every batch got a distinct, contiguous range

    tree = merkle.MerkleTree()
    for index, document in await replicas[1].leaves_between(0, after):
        assert tree.append(document) == index
    head = await replicas[1].latest_tree_head()
    assert head is not None
    assert head.tree_size == after
    assert tree.root().hex() == head.root_hash
    last = (await replicas[0].leaves_between(after - 1, after))[0][1]
    ranges = merkle.inclusion_ranges(after - 1, after)
    path = merkle.assemble(ranges, await replicas[0].nodes(merkle.nodes_for(ranges)))
    assert path == tree.inclusion_proof(after - 1)
    assert merkle.verify_inclusion(merkle.leaf_hash(last), after - 1, after, path, tree.root())
    for engine in engines:
        await engine.dispose()
