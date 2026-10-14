"""Transparency log value objects: signed tree heads and proofs."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Annotated

from agentic_core.domain.provenance import canonical_json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

STH_VERSION = "aap-sth/v1"

HexHash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class SignedTreeHead(BaseModel):
    """Ed25519 signature over the canonical JSON of the unsigned fields."""

    model_config = ConfigDict(frozen=True)

    version: str = STH_VERSION
    log_id: str = Field(pattern=r"^[0-9a-f]{64}$", description="SHA-256 of the log key SPKI")
    tree_size: int = Field(ge=0)
    root_hash: HexHash
    timestamp: int = Field(ge=0, description="Milliseconds since the Unix epoch")
    signature: str = Field(description="Base64 Ed25519 signature")

    def signed_body(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})


class InclusionProof(BaseModel):
    model_config = ConfigDict(frozen=True)

    leaf_index: int = Field(ge=0)
    tree_size: int = Field(ge=1)
    leaf_hash: HexHash
    audit_path: tuple[str, ...]


class ConsistencyProof(BaseModel):
    model_config = ConfigDict(frozen=True)

    first: int = Field(ge=0)
    second: int = Field(ge=0)
    proof: tuple[str, ...]


class LogEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    leaf_index: int
    leaf_hash: str
    record_id: str


class LogPublicKey(BaseModel):
    model_config = ConfigDict(frozen=True)

    log_id: str
    algorithm: str = "Ed25519"
    public_key_pem: str


def key_id(key: Ed25519PublicKey) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo, as RFC 6962 derives a log ID."""
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def verify_tree_head(sth: SignedTreeHead, public_key: Ed25519PublicKey) -> bool:
    """True when the signature is valid and the log ID matches the key."""
    if sth.version != STH_VERSION or sth.log_id != key_id(public_key):
        return False
    try:
        signature = base64.b64decode(sth.signature, validate=True)
        public_key.verify(signature, canonical_json(sth.signed_body()))
    except (InvalidSignature, binascii.Error, ValueError):
        return False
    return True
