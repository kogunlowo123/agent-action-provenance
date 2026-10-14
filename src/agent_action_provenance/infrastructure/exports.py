"""Persistence for auditor export requests."""

from __future__ import annotations

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from agent_action_provenance.domain.errors import ConflictError, NotFoundError
from agent_action_provenance.domain.exports import ExportRequest, ExportStatus
from agent_action_provenance.infrastructure.database import exports


class SqlExportRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, request: ExportRequest) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(exports).values(
                    export_id=request.export_id,
                    status=request.status.value,
                    requested_by=request.requested_by,
                    created_at=request.created_at,
                    document=request.model_dump_json(),
                )
            )

    async def get(self, export_id: str) -> ExportRequest | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(exports.c.document).where(exports.c.export_id == export_id)
                )
            ).first()
        return ExportRequest.model_validate_json(row[0]) if row else None

    async def transition(self, request: ExportRequest, expected: ExportStatus) -> None:
        """Compare-and-set so two approvers cannot both act on one request."""
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(exports)
                .where(exports.c.export_id == request.export_id)
                .where(exports.c.status == expected.value)
                .values(status=request.status.value, document=request.model_dump_json())
            )
        if result.rowcount == 0:
            if await self.get(request.export_id) is None:
                raise NotFoundError(f"export {request.export_id} not found")
            raise ConflictError(f"export {request.export_id} is no longer {expected.value}")
