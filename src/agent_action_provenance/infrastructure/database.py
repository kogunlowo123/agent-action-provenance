"""SQLAlchemy Core schema and engine. PostgreSQL in production; SQLite in tests."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    SmallInteger,
    String,
    Table,
    Text,
    UniqueConstraint,
    insert,
    select,
)
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

metadata = MetaData()

log_state = Table(
    "log_state",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=False),
    Column("tree_size", BigInteger, nullable=False),
)

leaves = Table(
    "leaves",
    metadata,
    Column("leaf_index", BigInteger, primary_key=True, autoincrement=False),
    Column("leaf_hash", String(64), nullable=False),
    Column("record_id", String(64), nullable=False, unique=True),
)

nodes = Table(
    "merkle_nodes",
    metadata,
    Column("level", SmallInteger, nullable=False),
    Column("idx", BigInteger, nullable=False),
    Column("hash", String(64), nullable=False),
    PrimaryKeyConstraint("level", "idx"),
)

records = Table(
    "records",
    metadata,
    Column("record_id", String(64), primary_key=True),
    Column("leaf_index", BigInteger, nullable=False, unique=True),
    Column("agent_id", String(512), nullable=False),
    Column("action_id", String(128), nullable=False),
    Column("action", String(200), nullable=False),
    Column("status", String(32), nullable=False),
    Column("compliant", Boolean, nullable=False),
    Column("max_classification", SmallInteger, nullable=False),
    Column("correlation_id", String(128)),
    Column("recorded_at", DateTime(timezone=True), nullable=False),
    Column("document", Text, nullable=False),
    UniqueConstraint("agent_id", "action_id", name="uq_records_agent_action"),
    Index("ix_records_agent", "agent_id", "recorded_at"),
    Index("ix_records_correlation", "correlation_id"),
    Index("ix_records_recorded_at", "recorded_at"),
)

entity_links = Table(
    "entity_links",
    metadata,
    Column("digest", String(71), nullable=False),
    Column("role", String(16), nullable=False),
    Column("record_id", String(64), nullable=False),
    PrimaryKeyConstraint("digest", "role", "record_id"),
    Index("ix_entity_links_record", "record_id", "role"),
)

derivations = Table(
    "derivations",
    metadata,
    Column("child", String(71), nullable=False),
    Column("parent", String(71), nullable=False),
    Column("record_id", String(64), nullable=False),
    PrimaryKeyConstraint("child", "parent", "record_id"),
)

tree_heads = Table(
    "tree_heads",
    metadata,
    Column("tree_size", BigInteger, primary_key=True, autoincrement=False),
    Column("batch_start", BigInteger, nullable=False),
    Column("document", Text, nullable=False),
    Column("archived_at", DateTime(timezone=True)),
    Column("archive_key", String(255)),
    Index("ix_tree_heads_unarchived", "archived_at"),
)

exports = Table(
    "exports",
    metadata,
    Column("export_id", String(64), primary_key=True),
    Column("status", String(32), nullable=False),
    Column("requested_by", String(512), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("document", Text, nullable=False),
    Index("ix_exports_status", "status"),
)

schema_version = Table(
    "schema_version",
    metadata,
    Column("version", Integer, primary_key=True),
)

SCHEMA_VERSION = 1


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


async def create_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        if (await conn.execute(select(schema_version.c.version))).scalar() is None:
            await conn.execute(insert(schema_version).values(version=SCHEMA_VERSION))
        if (await conn.execute(select(log_state.c.tree_size))).scalar() is None:
            await conn.execute(insert(log_state).values(id=1, tree_size=0))


def aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
