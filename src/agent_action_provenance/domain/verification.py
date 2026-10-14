"""Offline verification of records, proofs and auditor evidence bundles.

Everything here is pure: a verifier needs only the bundle and the log's
public key (obtained out of band and pinned), never the running service.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agentic_core.domain.provenance import canonical_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agent_action_provenance.domain import governance, merkle, prov
from agent_action_provenance.domain.log import (
    ConsistencyProof,
    InclusionProof,
    LogPublicKey,
    SignedTreeHead,
    key_id,
    verify_tree_head,
)
from agent_action_provenance.domain.models import ProvenanceRecord

BUNDLE_FORMAT = "aap-evidence-bundle/v1"


class BundleEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    leaf_index: int = Field(ge=0)
    record: dict[str, Any] = Field(description="ProvenanceRecord exactly as sealed in the log")
    inclusion_proof: InclusionProof


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(frozen=True)

    format: str = BUNDLE_FORMAT
    export_id: str
    generated_at: datetime
    criteria: dict[str, Any]
    log: LogPublicKey
    tree_head: SignedTreeHead
    entries: tuple[BundleEntry, ...]


class EntryVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    record_id: str | None
    leaf_index: int
    valid: bool
    problems: tuple[str, ...]


class BundleVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    valid: bool
    tree_size: int
    root_hash: str
    problems: tuple[str, ...]
    entries: tuple[EntryVerification, ...]


def _unhex(values: tuple[str, ...]) -> list[bytes] | None:
    try:
        return [bytes.fromhex(v) for v in values]
    except ValueError:
        return None


def verify_inclusion_proof(
    proof: InclusionProof, leaf_data: bytes | None, sth: SignedTreeHead
) -> list[str]:
    problems: list[str] = []
    expected_leaf = merkle.leaf_hash(leaf_data) if leaf_data is not None else None
    if expected_leaf is not None and expected_leaf.hex() != proof.leaf_hash:
        problems.append("leaf hash does not match record content")
    if proof.tree_size != sth.tree_size:
        problems.append("proof is for a different tree size than the tree head")
    path = _unhex(proof.audit_path)
    if path is None:
        problems.append("audit path is not hex")
        return problems
    if not merkle.verify_inclusion(
        bytes.fromhex(proof.leaf_hash),
        proof.leaf_index,
        proof.tree_size,
        path,
        bytes.fromhex(sth.root_hash),
    ):
        problems.append("inclusion proof does not reproduce the signed root")
    return problems


def verify_consistency_proof(
    proof: ConsistencyProof, old: SignedTreeHead, new: SignedTreeHead
) -> list[str]:
    if (proof.first, proof.second) != (old.tree_size, new.tree_size):
        return ["proof sizes do not match the tree heads"]
    path = _unhex(proof.proof)
    if path is None:
        return ["consistency proof is not hex"]
    if not merkle.verify_consistency(
        old.tree_size,
        new.tree_size,
        bytes.fromhex(old.root_hash),
        bytes.fromhex(new.root_hash),
        path,
    ):
        return ["consistency proof failed: the log was rewritten or forked"]
    return []


def verify_record_semantics(record: ProvenanceRecord) -> list[str]:
    """Re-derive what the recorder derived and compare."""
    problems = [f"prov: {p}" for p in prov.validate_document(record.prov)]
    if record.submission.digest() != record.submission_digest:
        problems.append("submission digest mismatch")
    rebuilt = prov.build_document(
        record.record_id,
        record.submission,
        recorded_by=record.recorded_by,
        recorded_at=record.recorded_at,
    )
    if canonical_json(rebuilt) != canonical_json(record.prov):
        problems.append("PROV document is not derived from the submission")
    if governance.assess(record.submission) != record.governance:
        problems.append("governance assessment does not match the submission")
    return problems


def verify_bundle(bundle: EvidenceBundle, trusted_key: Ed25519PublicKey) -> BundleVerification:
    problems: list[str] = []
    if bundle.format != BUNDLE_FORMAT:
        problems.append(f"unsupported bundle format {bundle.format!r}")
    if bundle.log.log_id != key_id(trusted_key):
        problems.append("bundle was produced by a different log than the trusted key")
    sth = bundle.tree_head
    if not verify_tree_head(sth, trusted_key):
        problems.append("tree head signature is invalid for the trusted key")

    entries: list[EntryVerification] = []
    seen: set[int] = set()
    for entry in bundle.entries:
        entry_problems: list[str] = []
        record_id = entry.record.get("record_id")
        if entry.leaf_index in seen:
            entry_problems.append("duplicate leaf index in bundle")
        seen.add(entry.leaf_index)
        if entry.inclusion_proof.leaf_index != entry.leaf_index:
            entry_problems.append("proof leaf index does not match entry")
        data = canonical_json(entry.record)
        entry_problems += verify_inclusion_proof(entry.inclusion_proof, data, sth)
        try:
            record = ProvenanceRecord.model_validate(entry.record)
        except ValidationError as exc:
            entry_problems.append(f"record does not match the schema: {exc.error_count()} errors")
        else:
            entry_problems += verify_record_semantics(record)
        entries.append(
            EntryVerification(
                record_id=record_id if isinstance(record_id, str) else None,
                leaf_index=entry.leaf_index,
                valid=not entry_problems,
                problems=tuple(entry_problems),
            )
        )
    valid = not problems and all(e.valid for e in entries)
    return BundleVerification(
        valid=valid,
        tree_size=sth.tree_size,
        root_hash=sth.root_hash,
        problems=tuple(problems),
        entries=tuple(entries),
    )
