"""Verification CLI for auditors and independent log monitors.

    provenance-verify bundle BUNDLE.json --public-key log.pem
    provenance-verify consistency --old OLD_STH.json --new NEW_STH.json \
                                  --proof PROOF.json --public-key log.pem
    provenance-verify monitor --url "$PROVENANCE_URL" --public-key log.pem \
                              --state monitor-state.json
    provenance-verify archive ./archive --public-key log.pem
    provenance-verify audit-chain audit.jsonl --public-key audit.pub.pem --key-id audit-2026-10
    provenance-verify keygen > key.pem 2> key.pub.pem

Every command verifies against a public key the operator pinned out of band;
nothing in the material being verified is trusted to identify its own key.
Exit status: 0 verified, 1 verification failed, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

import httpx
from agentic_core.audit import AuditEvent, verify_chain
from agentic_core.domain.errors import AuditIntegrityError
from agentic_core.domain.provenance import canonical_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from agent_action_provenance.domain.log import ConsistencyProof, SignedTreeHead, verify_tree_head
from agent_action_provenance.domain.merkle import MerkleTree
from agent_action_provenance.domain.verification import (
    EvidenceBundle,
    verify_bundle,
    verify_consistency_proof,
)
from agent_action_provenance.security.keys import load_public_key, private_pem, public_pem

OK, FAILED, USAGE = 0, 1, 2


def _emit(out: IO[str], report: dict[str, Any]) -> None:
    out.write(json.dumps(report, indent=2, sort_keys=True) + "\n")


def _key(path: Path) -> Ed25519PublicKey:
    return load_public_key(path.read_bytes())


def _bundle(args: argparse.Namespace, out: IO[str]) -> int:
    bundle = EvidenceBundle.model_validate_json(Path(args.bundle).read_bytes())
    result = verify_bundle(bundle, _key(args.public_key))
    _emit(out, result.model_dump(mode="json"))
    return OK if result.valid else FAILED


def _check_pair(
    old: SignedTreeHead, new: SignedTreeHead, proof: ConsistencyProof, key: Ed25519PublicKey
) -> list[str]:
    problems: list[str] = []
    if not verify_tree_head(old, key):
        problems.append("old tree head signature is invalid")
    if not verify_tree_head(new, key):
        problems.append("new tree head signature is invalid")
    if new.tree_size < old.tree_size:
        problems.append("new tree head is smaller than the old one: the log shrank")
    problems += verify_consistency_proof(proof, old, new)
    return problems


def _consistency(args: argparse.Namespace, out: IO[str]) -> int:
    old = SignedTreeHead.model_validate_json(Path(args.old).read_bytes())
    new = SignedTreeHead.model_validate_json(Path(args.new).read_bytes())
    proof = ConsistencyProof.model_validate_json(Path(args.proof).read_bytes())
    problems = _check_pair(old, new, proof, _key(args.public_key))
    _emit(
        out,
        {
            "valid": not problems,
            "first": old.tree_size,
            "second": new.tree_size,
            "problems": problems,
        },
    )
    return FAILED if problems else OK


def _monitor(args: argparse.Namespace, out: IO[str], transport: httpx.BaseTransport | None) -> int:
    key = _key(args.public_key)
    state_path = Path(args.state)
    base = args.url.rstrip("/")
    with httpx.Client(transport=transport, timeout=10.0) as client:
        response = client.get(f"{base}/v1/log/tree-head")
        response.raise_for_status()
        new = SignedTreeHead.model_validate(response.json())
        problems: list[str] = []
        previous: SignedTreeHead | None = None
        if state_path.exists():
            previous = SignedTreeHead.model_validate_json(state_path.read_bytes())
            if new.tree_size < previous.tree_size:
                problems.append("log shrank since the last observation")
            else:
                proof_response = client.get(
                    f"{base}/v1/log/proof/consistency",
                    params={"first": previous.tree_size, "second": new.tree_size},
                )
                proof_response.raise_for_status()
                proof = ConsistencyProof.model_validate(proof_response.json())
                problems += _check_pair(previous, new, proof, key)
        elif not verify_tree_head(new, key):
            problems.append("tree head signature is invalid")
    if not problems:
        state_path.write_text(new.model_dump_json(), encoding="utf-8")
    _emit(
        out,
        {
            "valid": not problems,
            "previous_size": previous.tree_size if previous else None,
            "tree_size": new.tree_size,
            "root_hash": new.root_hash,
            "problems": problems,
        },
    )
    return FAILED if problems else OK


def _archive(args: argparse.Namespace, out: IO[str]) -> int:
    """Replay every archived batch into a fresh tree and check each signed root."""
    key = _key(args.public_key)
    files = sorted(Path(args.directory).glob("batches/*.json"))
    tree = MerkleTree()
    problems: list[str] = []
    for path in files:
        document = json.loads(path.read_bytes())
        head = SignedTreeHead.model_validate(document["tree_head"])
        if not verify_tree_head(head, key):
            problems.append(f"{path.name}: tree head signature is invalid")
        for entry in document["entries"]:
            if entry["leaf_index"] != tree.size:
                problems.append(
                    f"{path.name}: expected leaf {tree.size}, found {entry['leaf_index']}"
                )
                break
            tree.append(canonical_json(entry["record"]))
        if head.tree_size != tree.size:
            problems.append(
                f"{path.name}: head covers {head.tree_size} leaves, replay has {tree.size}"
            )
        elif tree.root().hex() != head.root_hash:
            problems.append(f"{path.name}: replayed root differs from the signed root")
    if not files:
        problems.append("no archived batches found under batches/")
    _emit(
        out,
        {
            "valid": not problems,
            "batches": len(files),
            "tree_size": tree.size,
            "root_hash": tree.root().hex(),
            "problems": problems,
        },
    )
    return FAILED if problems else OK


def _audit_chain(args: argparse.Namespace, out: IO[str]) -> int:
    lines = Path(args.chain).read_text(encoding="utf-8").splitlines()
    events = [AuditEvent.model_validate_json(line) for line in lines if line.strip()]
    key_id = args.key_id or (events[0].key_id if events else "")
    try:
        count = verify_chain(events, {key_id: _key(args.public_key)})
    except AuditIntegrityError as exc:
        _emit(out, {"valid": False, "sequence": exc.sequence, "problem": str(exc)})
        return FAILED
    _emit(out, {"valid": True, "events": count})
    return OK


def _keygen(out: IO[str], err: IO[str]) -> int:
    key = Ed25519PrivateKey.generate()
    out.write(private_pem(key).decode())
    err.write(public_pem(key.public_key()).decode())
    return OK


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="provenance-verify", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    b = sub.add_parser("bundle", help="verify an auditor evidence bundle offline")
    b.add_argument("bundle")
    b.add_argument("--public-key", required=True, type=Path)
    c = sub.add_parser("consistency", help="verify two tree heads and a consistency proof")
    c.add_argument("--old", required=True)
    c.add_argument("--new", required=True)
    c.add_argument("--proof", required=True)
    c.add_argument("--public-key", required=True, type=Path)
    m = sub.add_parser("monitor", help="observe a live log and prove it only grew")
    m.add_argument("--url", required=True)
    m.add_argument("--public-key", required=True, type=Path)
    m.add_argument("--state", required=True)
    r = sub.add_parser("archive", help="replay a WORM archive copy and check every signed root")
    r.add_argument("directory")
    r.add_argument("--public-key", required=True, type=Path)
    a = sub.add_parser("audit-chain", help="verify a signed agentic-core audit chain")
    a.add_argument("chain")
    a.add_argument("--public-key", required=True, type=Path)
    a.add_argument("--key-id")
    sub.add_parser("keygen", help="print a new Ed25519 private key (public key on stderr)")
    return p


def main(
    argv: list[str] | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    args = parser().parse_args(argv)
    handlers: dict[str, Callable[[], int]] = {
        "bundle": lambda: _bundle(args, out),
        "consistency": lambda: _consistency(args, out),
        "monitor": lambda: _monitor(args, out, transport),
        "archive": lambda: _archive(args, out),
        "audit-chain": lambda: _audit_chain(args, out),
        "keygen": lambda: _keygen(out, err),
    }
    try:
        return handlers[args.command]()
    except (OSError, ValueError, ValidationError, httpx.HTTPError) as exc:
        err.write(f"error: {exc}\n")
        return USAGE


if __name__ == "__main__":
    raise SystemExit(main())
