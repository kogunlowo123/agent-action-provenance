"""Signed tree heads.

The log key signs ``canonical_json`` of the unsigned STH fields. The log ID
is the SHA-256 of the key's SubjectPublicKeyInfo, so a verifier that pins the
public key also pins the log identity.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import datetime

from agentic_core.domain.provenance import canonical_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_action_provenance.domain.log import STH_VERSION, LogPublicKey, SignedTreeHead, key_id
from agent_action_provenance.security.keys import public_pem


class TreeHeadSigner:
    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key
        self.public_key = key.public_key()
        self.log_id = key_id(self.public_key)

    def sign(self, *, tree_size: int, root_hash: bytes, timestamp_ms: int) -> SignedTreeHead:
        body = {
            "version": STH_VERSION,
            "log_id": self.log_id,
            "tree_size": tree_size,
            "root_hash": root_hash.hex(),
            "timestamp": timestamp_ms,
        }
        signature = base64.b64encode(self._key.sign(canonical_json(body))).decode()
        return SignedTreeHead.model_validate({**body, "signature": signature})

    def sealer(self, now: Callable[[], datetime]) -> Callable[[int, bytes], SignedTreeHead]:
        """Bind the signer to a clock; the ledger calls the result inside its transaction."""

        def seal(tree_size: int, root_hash: bytes) -> SignedTreeHead:
            timestamp = int(now().timestamp() * 1000)
            return self.sign(tree_size=tree_size, root_hash=root_hash, timestamp_ms=timestamp)

        return seal

    def describe(self) -> LogPublicKey:
        return LogPublicKey(log_id=self.log_id, public_key_pem=public_pem(self.public_key).decode())
