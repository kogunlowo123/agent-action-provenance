"""Write-once evidence archives.

Each sealed batch is archived as one self-verifying object: the signed tree
head plus every record in the batch. Objects are never overwritten; writing
the same key again succeeds only when the content is byte-identical (an
idempotent retry) and fails loudly otherwise.

* ``S3ObjectLockArchive``: S3 Object Lock in COMPLIANCE mode with a retain-
  until date, conditional create (``If-None-Match: *``) and a SHA-256 checksum
  verified by S3. Primary production adapter (AWS reference deployment).
* ``FilesystemWormArchive``: exclusive-create, read-only files on a volume
  that a shipper replicates to immutable blob storage (Azure immutable
  containers, GCS retention-locked buckets) or for local development.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from botocore.exceptions import ClientError

from agent_action_provenance.domain.errors import ArchiveConflictError

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

_KEY = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,100}(/[a-z0-9][a-z0-9_.-]{0,100}){0,4}$")


def validate_key(key: str) -> str:
    if not _KEY.fullmatch(key) or ".." in key:
        raise ValueError(f"invalid archive key {key!r}")
    return key


@dataclass(frozen=True)
class ArchiveReceipt:
    key: str
    sha256: str
    location: str
    already_present: bool


class EvidenceArchive(Protocol):
    async def put(self, key: str, body: bytes, *, retain_until: datetime) -> ArchiveReceipt: ...


class FilesystemWormArchive:
    def __init__(self, root: Path) -> None:
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)

    async def put(self, key: str, body: bytes, *, retain_until: datetime) -> ArchiveReceipt:
        return await asyncio.to_thread(self._put, validate_key(key), body)

    def _put(self, key: str, body: bytes) -> ArchiveReceipt:
        digest = hashlib.sha256(body).hexdigest()
        path = self._root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("xb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            existing = hashlib.sha256(path.read_bytes()).hexdigest()
            if existing != digest:
                raise ArchiveConflictError(f"{key} exists with different content") from None
            return ArchiveReceipt(key, digest, str(path), already_present=True)
        path.chmod(0o444)
        return ArchiveReceipt(key, digest, str(path), already_present=False)


class S3ObjectLockArchive:
    def __init__(
        self, client: S3Client, *, bucket: str, prefix: str = "", mode: str = "COMPLIANCE"
    ) -> None:
        if mode not in {"COMPLIANCE", "GOVERNANCE"}:
            raise ValueError("object lock mode must be COMPLIANCE or GOVERNANCE")
        self._client = client
        self._bucket = bucket
        self._prefix = prefix.strip("/")
        self._mode = mode

    def _object_key(self, key: str) -> str:
        return f"{self._prefix}/{key}" if self._prefix else key

    async def put(self, key: str, body: bytes, *, retain_until: datetime) -> ArchiveReceipt:
        return await asyncio.to_thread(self._put, validate_key(key), body, retain_until)

    def _put(self, key: str, body: bytes, retain_until: datetime) -> ArchiveReceipt:
        raw = hashlib.sha256(body).digest()
        checksum = base64.b64encode(raw).decode()
        object_key = self._object_key(key)
        location = f"s3://{self._bucket}/{object_key}"
        try:
            self._client.put_object(
                Bucket=self._bucket,
                Key=object_key,
                Body=body,
                ContentType="application/json",
                ChecksumSHA256=checksum,
                IfNoneMatch="*",
                ObjectLockMode=self._mode,  # type: ignore[arg-type]
                ObjectLockRetainUntilDate=retain_until,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in {"PreconditionFailed", "412"}:
                raise
            head = self._client.head_object(
                Bucket=self._bucket, Key=object_key, ChecksumMode="ENABLED"
            )
            if head.get("ChecksumSHA256") != checksum:
                raise ArchiveConflictError(f"{location} exists with different content") from exc
            return ArchiveReceipt(key, raw.hex(), location, already_present=True)
        return ArchiveReceipt(key, raw.hex(), location, already_present=False)
