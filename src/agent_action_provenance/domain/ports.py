"""Ports the application layer depends on. Adapters live in infrastructure."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from agent_action_provenance.domain.log import LogEntry, SignedTreeHead
from agent_action_provenance.domain.merkle import NodeId
from agent_action_provenance.domain.models import ProvenanceRecord

Sealer = Callable[[int, bytes], SignedTreeHead]


class Clock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True)
class StoredRecord:
    record: ProvenanceRecord
    leaf_index: int
    leaf_hash: str
    leaf_bytes: bytes


@dataclass(frozen=True)
class SealedBatch:
    """A committed batch. ``audit_paths[i]`` proves leaf ``start + i`` under ``tree_head``.

    Every node those paths need is either on the pre-batch frontier or was
    created by the batch, so the ledger computes them without extra reads.
    """

    start: int
    tree_head: SignedTreeHead
    leaf_hashes: tuple[str, ...]
    audit_paths: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True)
class RecordFilter:
    agent_id: str | None = None
    correlation_id: str | None = None
    action: str | None = None
    compliant: bool | None = None
    since: datetime | None = None
    until: datetime | None = None
    record_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class PendingArchive:
    tree_head: SignedTreeHead
    batch_start: int


class Ledger(Protocol):
    async def append_batch(
        self, records: Sequence[ProvenanceRecord], seal: Sealer
    ) -> SealedBatch: ...

    async def ensure_genesis(self, seal: Sealer) -> SignedTreeHead: ...

    async def tree_size(self) -> int: ...

    async def latest_tree_head(self) -> SignedTreeHead | None: ...

    async def tree_head(self, tree_size: int) -> SignedTreeHead | None: ...

    async def nodes(self, ids: Iterable[NodeId]) -> dict[NodeId, bytes]: ...

    async def batch_start(self, tree_size: int) -> int | None: ...

    async def leaf_hash(self, index: int) -> bytes | None: ...

    async def entries(self, start: int, end: int) -> list[LogEntry]: ...

    async def get(self, record_id: str) -> StoredRecord | None: ...

    async def find_action(self, agent_id: str, action_id: str) -> StoredRecord | None: ...

    async def search(
        self, criteria: RecordFilter, *, limit: int, offset: int = 0
    ) -> list[StoredRecord]: ...

    async def generators(self, digests: Iterable[str]) -> list[tuple[str, str]]: ...

    async def derivations(self, digests: Iterable[str]) -> list[tuple[str, str, str]]: ...

    async def inputs(self, record_ids: Iterable[str]) -> list[tuple[str, str]]: ...

    async def pending_archive(self, limit: int) -> list[PendingArchive]: ...

    async def leaves_between(self, start: int, end: int) -> list[tuple[int, bytes]]: ...

    async def mark_archived(self, tree_size: int, key: str, at: datetime) -> None: ...
