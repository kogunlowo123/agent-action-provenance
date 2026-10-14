"""Merkle tree hashing, proof construction and proof verification.

Hashing follows RFC 6962 section 2.1 (and RFC 9162 section 2.1):

    leaf hash  = SHA-256(0x00 || leaf data)
    node hash  = SHA-256(0x01 || left || right)
    MTH({})    = SHA-256("")

The tree over ``n`` leaves splits at ``k``, the largest power of two smaller
than ``n``; the left subtree is always perfect. Every subtree that appears in
an RFC 6962 audit path or consistency proof is therefore a left-to-right
sequence of *perfect, aligned* subtrees. Storing the hash of every perfect
aligned subtree (``NodeId(level, index)`` covers leaves
``[index * 2**level, (index + 1) * 2**level)``) lets any root or proof be
assembled from ``O(log n)`` stored nodes without rehashing leaves.

Proof construction is split into *planning* (which ranges are needed) and
*assembly* (hash the ranges from stored nodes), so a database-backed log can
fetch every node for a proof in a single query.

Verification implements the algorithms of RFC 9162 sections 2.1.3.2
(inclusion) and 2.1.4.2 (consistency) verbatim.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
HASH_SIZE = 32
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def split_point(n: int) -> int:
    """Largest power of two strictly smaller than ``n`` (``n >= 2``)."""
    if n < 2:
        raise ValueError("split point is defined for n >= 2")
    return 1 << ((n - 1).bit_length() - 1)


@dataclass(frozen=True, order=True)
class NodeId:
    """Perfect subtree of height ``level`` covering ``2**level`` leaves."""

    level: int
    index: int

    @property
    def start(self) -> int:
        return self.index << self.level

    @property
    def end(self) -> int:
        return (self.index + 1) << self.level


Range = tuple[int, int]


def perfect_subtrees(start: int, end: int) -> list[NodeId]:
    """Decompose ``[start, end)`` into perfect aligned subtrees, left to right.

    For every range produced by RFC 6962 tree splitting, folding these
    subtrees from the right with ``node_hash`` yields MTH of the range.
    """
    if not 0 <= start < end:
        raise ValueError(f"invalid range [{start}, {end})")
    nodes: list[NodeId] = []
    while start < end:
        size = 1 << ((end - start).bit_length() - 1)
        if start % size:
            raise ValueError(f"range [{start}, {end}) is not aligned to the tree structure")
        level = size.bit_length() - 1
        nodes.append(NodeId(level, start >> level))
        start += size
    return nodes


def nodes_for(ranges: Iterable[Range]) -> set[NodeId]:
    needed: set[NodeId] = set()
    for start, end in ranges:
        needed.update(perfect_subtrees(start, end))
    return needed


def range_hash(start: int, end: int, lookup: Mapping[NodeId, bytes]) -> bytes:
    """MTH of leaves ``[start, end)`` from stored perfect-subtree hashes."""
    nodes = perfect_subtrees(start, end)
    acc = lookup[nodes[-1]]
    for node in reversed(nodes[:-1]):
        acc = node_hash(lookup[node], acc)
    return acc


def root_ranges(size: int) -> list[Range]:
    return [(0, size)] if size else []


def inclusion_ranges(index: int, size: int) -> list[Range]:
    """Ranges whose hashes form the RFC 6962 audit path ``PATH(index, D[size])``.

    Ordered from the leaf's sibling up to the root's child, as required by
    the RFC 9162 verification algorithm.
    """
    if not 0 <= index < size:
        raise ValueError(f"leaf index {index} is outside a tree of size {size}")
    out: list[Range] = []

    def path(m: int, start: int, end: int) -> None:
        n = end - start
        if n == 1:
            return
        k = split_point(n)
        if m < k:
            path(m, start, start + k)
            out.append((start + k, end))
        else:
            path(m - k, start + k, end)
            out.append((start, start + k))

    path(index, 0, size)
    return out


def consistency_ranges(first: int, second: int) -> list[Range]:
    """Ranges whose hashes form ``PROOF(first, D[second])`` (RFC 6962 section 2.1.2)."""
    if not 0 <= first <= second:
        raise ValueError(f"cannot prove consistency from {first} to {second}")
    if first in (0, second):
        return []
    out: list[Range] = []

    def subproof(m: int, start: int, end: int, whole: bool) -> None:
        n = end - start
        if m == n:
            if not whole:
                out.append((start, end))
            return
        k = split_point(n)
        if m <= k:
            subproof(m, start, start + k, whole)
            out.append((start + k, end))
        else:
            subproof(m - k, start + k, end, False)
            out.append((start, start + k))

    subproof(first, 0, second, True)
    return out


def assemble(ranges: Sequence[Range], lookup: Mapping[NodeId, bytes]) -> list[bytes]:
    return [range_hash(start, end, lookup) for start, end in ranges]


def append_nodes(
    size: int, leaf: bytes, lookup: Callable[[NodeId], bytes]
) -> list[tuple[NodeId, bytes]]:
    """Nodes completed by appending ``leaf`` as leaf number ``size``.

    ``lookup`` must return the left siblings, which are always perfect
    subtrees of the tree before the append (its "frontier").
    """
    created = [(NodeId(0, size), leaf)]
    current, index, level = leaf, size, 0
    while index & 1:
        current = node_hash(lookup(NodeId(level, index - 1)), current)
        level += 1
        index >>= 1
        created.append((NodeId(level, index), current))
    return created


# ------------------------------------------------------------------ verification


def _lsb(value: int) -> bool:
    return bool(value & 1)


def root_from_inclusion_proof(
    leaf: bytes, index: int, size: int, proof: Sequence[bytes]
) -> bytes | None:
    """RFC 9162 2.1.3.2 steps 1-5; returns the computed root or ``None``."""
    if index >= size or index < 0:
        return None
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if len(p) != HASH_SIZE or sn == 0:
            return None
        if _lsb(fn) or fn == sn:
            r = node_hash(p, r)
            if not _lsb(fn):
                while not _lsb(fn) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def verify_inclusion(
    leaf: bytes, index: int, size: int, proof: Sequence[bytes], root: bytes
) -> bool:
    computed = root_from_inclusion_proof(leaf, index, size, proof)
    return computed is not None and computed == root


def verify_consistency(
    first: int, second: int, first_root: bytes, second_root: bytes, proof: Sequence[bytes]
) -> bool:
    """RFC 9162 2.1.4.2. An empty tree is consistent with every later tree."""
    if first < 0 or first > second:
        return False
    if first == second:
        return not proof and first_root == second_root
    if first == 0:
        return not proof and first_root == EMPTY_ROOT
    if not proof or any(len(p) != HASH_SIZE for p in proof):
        return False
    path = list(proof)
    if first & (first - 1) == 0:  # exact power of two
        path.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while _lsb(fn):
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if _lsb(fn) or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not _lsb(fn):
                while not _lsb(fn) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# ------------------------------------------------------------- in-memory tree


class MerkleTree:
    """Append-only tree keeping every perfect subtree hash in memory.

    Used for offline verification, test oracles and small logs. The SQL
    ledger uses the same planning functions over stored nodes.
    """

    def __init__(self) -> None:
        self._nodes: dict[NodeId, bytes] = {}
        self._size = 0

    @property
    def size(self) -> int:
        return self._size

    def append(self, data: bytes) -> int:
        return self.append_hash(leaf_hash(data))

    def append_hash(self, leaf: bytes) -> int:
        index = self._size
        for node, value in append_nodes(index, leaf, self._nodes.__getitem__):
            self._nodes[node] = value
        self._size += 1
        return index

    def _check(self, size: int) -> None:
        if not 0 <= size <= self._size:
            raise ValueError(f"tree size {size} is outside 0..{self._size}")

    def root(self, size: int | None = None) -> bytes:
        size = self._size if size is None else size
        self._check(size)
        return range_hash(0, size, self._nodes) if size else EMPTY_ROOT

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        size = self._size if size is None else size
        self._check(size)
        return assemble(inclusion_ranges(index, size), self._nodes)

    def consistency_proof(self, first: int, second: int | None = None) -> list[bytes]:
        second = self._size if second is None else second
        self._check(second)
        return assemble(consistency_ranges(first, second), self._nodes)
