"""SQL-backed transparency log and record store.

``append_batch`` is the only writer. It runs in one transaction that locks
the single ``log_state`` row (``SELECT ... FOR UPDATE`` on PostgreSQL;
SQLite serializes writers), so any number of replicas can append without
forking the tree. Inside the transaction it:

1. reads the current size and the frontier (perfect subtrees of the tree),
2. hashes each record into a leaf and computes the perfect subtrees the
   appends complete (``merkle.append_nodes``),
3. computes the new root and asks the sealer to sign the tree head,
4. writes leaves, nodes, records, lineage links and the tree head.

Either the whole batch and its signed tree head commit, or nothing does.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import and_, insert, select, tuple_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from agent_action_provenance.domain import merkle
from agent_action_provenance.domain.log import LogEntry, SignedTreeHead
from agent_action_provenance.domain.merkle import NodeId
from agent_action_provenance.domain.models import ProvenanceRecord
from agent_action_provenance.domain.ports import (
    PendingArchive,
    RecordFilter,
    SealedBatch,
    Sealer,
    StoredRecord,
)
from agent_action_provenance.infrastructure.database import (
    aware,
    derivations,
    entity_links,
    leaves,
    log_state,
    nodes,
    records,
    tree_heads,
)

_IN_CHUNK = 500


def _chunks(values: Sequence[Any]) -> Iterable[Sequence[Any]]:
    for i in range(0, len(values), _IN_CHUNK):
        yield values[i : i + _IN_CHUNK]


class SqlLedger:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    # ------------------------------------------------------------------ writes

    async def append_batch(self, batch: Sequence[ProvenanceRecord], seal: Sealer) -> SealedBatch:
        if not batch:
            raise ValueError("cannot append an empty batch")
        async with self._engine.begin() as conn:
            size = int(
                (
                    await conn.execute(
                        select(log_state.c.tree_size).where(log_state.c.id == 1).with_for_update()
                    )
                ).scalar_one()
            )
            known = await self._fetch_nodes(conn, merkle.perfect_subtrees(0, size) if size else [])
            created: dict[NodeId, bytes] = {}

            def lookup(node: NodeId) -> bytes:
                return created[node] if node in created else known[node]

            leaf_rows: list[dict[str, Any]] = []
            record_rows: list[dict[str, Any]] = []
            link_rows: list[dict[str, Any]] = []
            derivation_rows: list[dict[str, Any]] = []
            for offset, record in enumerate(batch):
                index = size + offset
                data = record.leaf_bytes()
                digest = merkle.leaf_hash(data)
                created.update(merkle.append_nodes(index, digest, lookup))
                leaf_rows.append(
                    {"leaf_index": index, "leaf_hash": digest.hex(), "record_id": record.record_id}
                )
                record_rows.append(self._record_row(record, index, data))
                link_rows += self._links(record)
                derivation_rows += self._derivations(record)

            new_size = size + len(batch)
            tree = {**known, **created}
            root = merkle.range_hash(0, new_size, tree)
            head = seal(new_size, root)
            paths = tuple(
                tuple(h.hex() for h in merkle.assemble(merkle.inclusion_ranges(i, new_size), tree))
                for i in range(size, new_size)
            )

            await conn.execute(insert(leaves), leaf_rows)
            await conn.execute(
                insert(nodes),
                [{"level": n.level, "idx": n.index, "hash": h.hex()} for n, h in created.items()],
            )
            await conn.execute(insert(records), record_rows)
            if link_rows:
                await conn.execute(insert(entity_links), link_rows)
            if derivation_rows:
                await conn.execute(insert(derivations), derivation_rows)
            await conn.execute(
                insert(tree_heads).values(
                    tree_size=new_size, batch_start=size, document=head.model_dump_json()
                )
            )
            await conn.execute(
                update(log_state).where(log_state.c.id == 1).values(tree_size=new_size)
            )
        return SealedBatch(
            start=size,
            tree_head=head,
            leaf_hashes=tuple(r["leaf_hash"] for r in leaf_rows),
            audit_paths=paths,
        )

    @staticmethod
    def _record_row(record: ProvenanceRecord, index: int, data: bytes) -> dict[str, Any]:
        s = record.submission
        return {
            "record_id": record.record_id,
            "leaf_index": index,
            "agent_id": s.agent_id,
            "action_id": s.action_id,
            "action": s.action.name,
            "status": s.action.status.value,
            "compliant": record.governance.compliant,
            "max_classification": int(s.max_classification),
            "correlation_id": s.correlation_id,
            "recorded_at": record.recorded_at,
            "document": data.decode("ascii"),
        }

    @staticmethod
    def _links(record: ProvenanceRecord) -> list[dict[str, Any]]:
        rid = record.record_id
        rows = [
            {"digest": e.digest, "role": "used", "record_id": rid}
            for e in record.submission.evidence
        ]
        rows += [
            {"digest": o.digest, "role": "generated", "record_id": rid}
            for o in record.submission.outputs
        ]
        return rows

    @staticmethod
    def _derivations(record: ProvenanceRecord) -> list[dict[str, Any]]:
        s = record.submission
        pairs = {(e.digest, p) for e in s.evidence for p in e.derived_from}
        pairs |= {(o.digest, p) for o in s.outputs for p in o.derived_from}
        return [{"child": c, "parent": p, "record_id": record.record_id} for c, p in sorted(pairs)]

    async def ensure_genesis(self, seal: Sealer) -> SignedTreeHead:
        """Sign the empty tree once so a signed head exists before the first append."""
        existing = await self.tree_head(0)
        if existing is not None:
            return existing
        head = seal(0, merkle.EMPTY_ROOT)
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    insert(tree_heads).values(
                        tree_size=0, batch_start=0, document=head.model_dump_json()
                    )
                )
        except IntegrityError:
            stored = await self.tree_head(0)
            if stored is None:  # pragma: no cover - insert conflicted, so a row exists
                raise
            return stored
        return head

    async def mark_archived(self, tree_size: int, key: str, at: datetime) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                update(tree_heads)
                .where(tree_heads.c.tree_size == tree_size)
                .values(archived_at=at, archive_key=key)
            )

    # ------------------------------------------------------------------- reads

    @staticmethod
    async def _fetch_nodes(conn: AsyncConnection, ids: Iterable[NodeId]) -> dict[NodeId, bytes]:
        wanted = sorted(set(ids))
        found: dict[NodeId, bytes] = {}
        for chunk in _chunks(wanted):
            rows = await conn.execute(
                select(nodes.c.level, nodes.c.idx, nodes.c.hash).where(
                    tuple_(nodes.c.level, nodes.c.idx).in_([(n.level, n.index) for n in chunk])
                )
            )
            for level, idx, value in rows:
                found[NodeId(int(level), int(idx))] = bytes.fromhex(value)
        return found

    async def nodes(self, ids: Iterable[NodeId]) -> dict[NodeId, bytes]:
        async with self._engine.connect() as conn:
            return await self._fetch_nodes(conn, ids)

    async def tree_size(self) -> int:
        async with self._engine.connect() as conn:
            return int(
                (
                    await conn.execute(select(log_state.c.tree_size).where(log_state.c.id == 1))
                ).scalar_one()
            )

    async def latest_tree_head(self) -> SignedTreeHead | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(tree_heads.c.document).order_by(tree_heads.c.tree_size.desc()).limit(1)
                )
            ).first()
        return SignedTreeHead.model_validate_json(row[0]) if row else None

    async def tree_head(self, tree_size: int) -> SignedTreeHead | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(tree_heads.c.document).where(tree_heads.c.tree_size == tree_size)
                )
            ).first()
        return SignedTreeHead.model_validate_json(row[0]) if row else None

    async def batch_start(self, tree_size: int) -> int | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(tree_heads.c.batch_start).where(tree_heads.c.tree_size == tree_size)
                )
            ).first()
        return int(row[0]) if row else None

    async def leaf_hash(self, index: int) -> bytes | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(leaves.c.leaf_hash).where(leaves.c.leaf_index == index))
            ).first()
        return bytes.fromhex(row[0]) if row else None

    async def entries(self, start: int, end: int) -> list[LogEntry]:
        async with self._engine.connect() as conn:
            rows = await conn.execute(
                select(leaves.c.leaf_index, leaves.c.leaf_hash, leaves.c.record_id)
                .where(and_(leaves.c.leaf_index >= start, leaves.c.leaf_index < end))
                .order_by(leaves.c.leaf_index)
            )
            return [LogEntry(leaf_index=int(i), leaf_hash=h, record_id=r) for i, h, r in rows.all()]

    async def _stored(self, condition: Any) -> StoredRecord | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(records.c.document, records.c.leaf_index, leaves.c.leaf_hash)
                    .join(leaves, leaves.c.leaf_index == records.c.leaf_index)
                    .where(condition)
                )
            ).first()
        return self._to_stored(row) if row else None

    @staticmethod
    def _to_stored(row: Any) -> StoredRecord:
        document, index, digest = row
        data = document.encode("ascii")
        return StoredRecord(
            record=ProvenanceRecord.model_validate_json(data),
            leaf_index=int(index),
            leaf_hash=digest,
            leaf_bytes=data,
        )

    async def get(self, record_id: str) -> StoredRecord | None:
        return await self._stored(records.c.record_id == record_id)

    async def find_action(self, agent_id: str, action_id: str) -> StoredRecord | None:
        return await self._stored(
            and_(records.c.agent_id == agent_id, records.c.action_id == action_id)
        )

    async def search(
        self, criteria: RecordFilter, *, limit: int, offset: int = 0
    ) -> list[StoredRecord]:
        query = (
            select(records.c.document, records.c.leaf_index, leaves.c.leaf_hash)
            .join(leaves, leaves.c.leaf_index == records.c.leaf_index)
            .order_by(records.c.leaf_index)
            .limit(limit)
            .offset(offset)
        )
        if criteria.agent_id is not None:
            query = query.where(records.c.agent_id == criteria.agent_id)
        if criteria.correlation_id is not None:
            query = query.where(records.c.correlation_id == criteria.correlation_id)
        if criteria.action is not None:
            query = query.where(records.c.action == criteria.action)
        if criteria.compliant is not None:
            query = query.where(records.c.compliant == criteria.compliant)
        if criteria.since is not None:
            query = query.where(records.c.recorded_at >= aware(criteria.since))
        if criteria.until is not None:
            query = query.where(records.c.recorded_at < aware(criteria.until))
        if criteria.record_ids:
            query = query.where(records.c.record_id.in_(criteria.record_ids))
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [self._to_stored(r) for r in rows]

    async def generators(self, digests: Iterable[str]) -> list[tuple[str, str]]:
        wanted = sorted(set(digests))
        out: list[tuple[str, str]] = []
        async with self._engine.connect() as conn:
            for chunk in _chunks(wanted):
                rows = await conn.execute(
                    select(entity_links.c.digest, entity_links.c.record_id).where(
                        and_(entity_links.c.role == "generated", entity_links.c.digest.in_(chunk))
                    )
                )
                out += [(d, r) for d, r in rows.all()]
        return sorted(out)

    async def derivations(self, digests: Iterable[str]) -> list[tuple[str, str, str]]:
        wanted = sorted(set(digests))
        out: list[tuple[str, str, str]] = []
        async with self._engine.connect() as conn:
            for chunk in _chunks(wanted):
                rows = await conn.execute(
                    select(
                        derivations.c.child, derivations.c.parent, derivations.c.record_id
                    ).where(derivations.c.child.in_(chunk))
                )
                out += [(c, p, r) for c, p, r in rows.all()]
        return sorted(out)

    async def inputs(self, record_ids: Iterable[str]) -> list[tuple[str, str]]:
        wanted = sorted(set(record_ids))
        out: list[tuple[str, str]] = []
        async with self._engine.connect() as conn:
            for chunk in _chunks(wanted):
                rows = await conn.execute(
                    select(entity_links.c.record_id, entity_links.c.digest).where(
                        and_(entity_links.c.role == "used", entity_links.c.record_id.in_(chunk))
                    )
                )
                out += [(r, d) for r, d in rows.all()]
        return sorted(out)

    async def pending_archive(self, limit: int) -> list[PendingArchive]:
        async with self._engine.connect() as conn:
            rows = await conn.execute(
                select(tree_heads.c.document, tree_heads.c.batch_start)
                .where(tree_heads.c.archived_at.is_(None))
                .order_by(tree_heads.c.tree_size)
                .limit(limit)
            )
            return [
                PendingArchive(
                    tree_head=SignedTreeHead.model_validate_json(doc), batch_start=int(start)
                )
                for doc, start in rows.all()
            ]

    async def leaves_between(self, start: int, end: int) -> list[tuple[int, bytes]]:
        async with self._engine.connect() as conn:
            rows = await conn.execute(
                select(records.c.leaf_index, records.c.document)
                .where(and_(records.c.leaf_index >= start, records.c.leaf_index < end))
                .order_by(records.c.leaf_index)
            )
            return [(int(i), doc.encode("ascii")) for i, doc in rows.all()]
