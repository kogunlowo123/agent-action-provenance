"""Group commit of records into the transparency log.

Requests submit sealed records and await the commit of the batch that
contains them. A batch closes when it reaches ``max_batch`` records or
``max_wait_s`` after its first record arrived, whichever comes first. One
transaction appends the whole batch and signs one tree head, so the signing
and fsync cost is shared by every record in the batch, and every caller gets
an inclusion proof against a signed root as soon as its request returns.

Duplicate (agent, action_id) pairs in one batch are collapsed onto the first
occurrence. If a batch fails on a uniqueness conflict (a concurrent replica
appended the same action), it is retried record by record so one duplicate
cannot fail unrelated requests.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from agentic_core.observability import get_logger
from sqlalchemy.exc import IntegrityError

from agent_action_provenance.domain.errors import ConflictError, UpstreamUnavailableError
from agent_action_provenance.domain.models import ProvenanceRecord
from agent_action_provenance.domain.ports import Ledger, SealedBatch, Sealer
from agent_action_provenance.observability.metrics import ProvenanceMetrics

log = get_logger("agent_action_provenance.sequencer")


@dataclass(frozen=True)
class Placement:
    """Where a submitted record landed."""

    record_id: str
    leaf_index: int
    batch: SealedBatch


@dataclass
class _Pending:
    record: ProvenanceRecord
    future: asyncio.Future[Placement]
    followers: list[asyncio.Future[Placement]] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        return self.record.submission.agent_id, self.record.submission.action_id


class BatchSequencer:
    def __init__(
        self,
        ledger: Ledger,
        seal: Sealer,
        metrics: ProvenanceMetrics,
        *,
        max_batch: int = 256,
        max_wait_s: float = 0.05,
        on_sealed: Callable[[SealedBatch], None] | None = None,
    ) -> None:
        self._ledger = ledger
        self._seal = seal
        self._metrics = metrics
        self._max_batch = max_batch
        self._max_wait = max_wait_s
        self._on_sealed = on_sealed
        self._queue: asyncio.Queue[_Pending] = asyncio.Queue()
        self._worker: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        return self._worker is not None and not self._worker.done()

    def start(self) -> None:
        if not self.running:
            self._worker = asyncio.create_task(self._run(), name="provenance-sequencer")

    async def aclose(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._worker
            self._worker = None
        while not self._queue.empty():
            pending = self._queue.get_nowait()
            self._fail(pending, UpstreamUnavailableError("sequencer stopped"))

    async def submit(self, record: ProvenanceRecord) -> Placement:
        if not self.running:
            raise UpstreamUnavailableError("sequencer is not running")
        future: asyncio.Future[Placement] = asyncio.get_running_loop().create_future()
        await self._queue.put(_Pending(record, future))
        return await future

    async def _collect(self) -> list[_Pending]:
        first = await self._queue.get()
        batch = [first]
        deadline = time.monotonic() + self._max_wait
        while len(batch) < self._max_batch:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                while len(batch) < self._max_batch and not self._queue.empty():
                    batch.append(self._queue.get_nowait())
                break
            try:
                batch.append(await asyncio.wait_for(self._queue.get(), remaining))
            except TimeoutError:
                break
        return batch

    async def _run(self) -> None:
        while True:
            batch = await self._collect()
            await self.flush(batch)

    async def flush(self, batch: Sequence[_Pending]) -> None:
        unique: dict[tuple[str, str], _Pending] = {}
        for pending in batch:
            leader = unique.get(pending.key)
            if leader is None:
                unique[pending.key] = pending
            else:
                leader.followers.append(pending.future)
        leaders = list(unique.values())
        try:
            await self._commit(leaders)
        except IntegrityError:
            log.warning("batch_conflict_retrying_individually", size=len(leaders))
            for pending in leaders:
                try:
                    await self._commit([pending])
                except IntegrityError:
                    self._fail(pending, ConflictError("action already recorded concurrently"))
                except Exception as exc:
                    self._fail(pending, exc)
        except Exception as exc:
            self._metrics.batch_failures.inc()
            log.error("batch_commit_failed", error=type(exc).__name__, size=len(leaders))
            for pending in leaders:
                self._fail(pending, exc)

    async def _commit(self, leaders: Sequence[_Pending]) -> None:
        started = time.perf_counter()
        sealed = await self._ledger.append_batch([p.record for p in leaders], self._seal)
        self._metrics.seal_seconds.observe(time.perf_counter() - started)
        self._metrics.batch_size.observe(len(leaders))
        self._metrics.tree_size.set(sealed.tree_head.tree_size)
        for offset, pending in enumerate(leaders):
            placement = Placement(pending.record.record_id, sealed.start + offset, sealed)
            for future in (pending.future, *pending.followers):
                if not future.done():
                    future.set_result(placement)
        if self._on_sealed is not None:
            self._on_sealed(sealed)

    @staticmethod
    def _fail(pending: _Pending, exc: BaseException) -> None:
        for future in (pending.future, *pending.followers):
            if not future.done():
                future.set_exception(exc)
