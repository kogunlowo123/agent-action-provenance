"""RFC 6962 / RFC 9162 Merkle tree: hashing, proofs, verification and tamper cases."""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agent_action_provenance.domain import merkle
from agent_action_provenance.domain.merkle import MerkleTree, NodeId

# Test vectors from the Certificate Transparency reference implementation
# (RFC 6962 hashing of these eight leaves; roots for tree sizes 1..8).
CT_LEAVES = [
    bytes.fromhex(h)
    for h in [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ]
]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def reference_mth(leaves: list[bytes]) -> bytes:
    """RFC 6962 section 2.1 MTH, written directly from the definition."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = merkle.split_point(len(leaves))
    return hashlib.sha256(b"\x01" + reference_mth(leaves[:k]) + reference_mth(leaves[k:])).digest()


def reference_path(m: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = merkle.split_point(len(leaves))
    if m < k:
        return [*reference_path(m, leaves[:k]), reference_mth(leaves[k:])]
    return [*reference_path(m - k, leaves[k:]), reference_mth(leaves[:k])]


def reference_subproof(m: int, leaves: list[bytes], whole: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if whole else [reference_mth(leaves)]
    k = merkle.split_point(n)
    if m <= k:
        return [*reference_subproof(m, leaves[:k], whole), reference_mth(leaves[k:])]
    return [*reference_subproof(m - k, leaves[k:], False), reference_mth(leaves[:k])]


def tree_of(leaves: list[bytes]) -> MerkleTree:
    tree = MerkleTree()
    for leaf in leaves:
        tree.append(leaf)
    return tree


@pytest.fixture(scope="module")
def big() -> tuple[list[bytes], MerkleTree]:
    leaves = [f"leaf-{i}".encode() for i in range(67)]
    return leaves, tree_of(leaves)


class TestHashing:
    def test_empty_tree_root(self) -> None:
        assert MerkleTree().root() == hashlib.sha256(b"").digest() == merkle.EMPTY_ROOT

    @pytest.mark.parametrize("size", range(1, 9))
    def test_certificate_transparency_vectors(self, size: int) -> None:
        assert tree_of(CT_LEAVES).root(size).hex() == CT_ROOTS[size - 1]

    def test_domain_separation(self) -> None:
        a, b = b"a" * 32, b"b" * 32
        assert merkle.leaf_hash(a + b) != merkle.node_hash(a, b)

    def test_split_point(self) -> None:
        assert [merkle.split_point(n) for n in (2, 3, 4, 5, 8, 9)] == [1, 2, 2, 4, 4, 8]
        with pytest.raises(ValueError, match="n >= 2"):
            merkle.split_point(1)

    def test_roots_match_reference_for_every_size(
        self, big: tuple[list[bytes], MerkleTree]
    ) -> None:
        leaves, tree = big
        for n in range(len(leaves) + 1):
            assert tree.root(n) == reference_mth(leaves[:n])


class TestStructure:
    def test_perfect_subtrees(self) -> None:
        assert merkle.perfect_subtrees(0, 7) == [NodeId(2, 0), NodeId(1, 2), NodeId(0, 6)]
        assert merkle.perfect_subtrees(8, 12) == [NodeId(2, 2)]
        assert NodeId(2, 1).start == 4
        assert NodeId(2, 1).end == 8

    @pytest.mark.parametrize(("start", "end"), [(3, 3), (5, 2), (-1, 4), (1, 3)])
    def test_rejects_invalid_or_unaligned_ranges(self, start: int, end: int) -> None:
        with pytest.raises(ValueError, match="range"):
            merkle.perfect_subtrees(start, end)

    def test_append_nodes_completes_parents(self) -> None:
        tree = tree_of([b"a", b"b", b"c"])
        created = merkle.append_nodes(3, merkle.leaf_hash(b"d"), tree._nodes.__getitem__)
        assert [n for n, _ in created] == [NodeId(0, 3), NodeId(1, 1), NodeId(2, 0)]
        assert created[-1][1] == reference_mth([b"a", b"b", b"c", b"d"])

    def test_size_bounds(self) -> None:
        tree = tree_of([b"a"])
        with pytest.raises(ValueError, match="outside"):
            tree.root(2)
        with pytest.raises(ValueError, match="outside"):
            tree.inclusion_proof(1, 1)
        with pytest.raises(ValueError, match="cannot prove"):
            tree.consistency_proof(2, 1)
        assert merkle.root_ranges(0) == []
        assert merkle.root_ranges(3) == [(0, 3)]


class TestInclusion:
    def test_matches_rfc_path_for_every_leaf(self, big: tuple[list[bytes], MerkleTree]) -> None:
        leaves, tree = big
        for n in range(1, len(leaves) + 1):
            root = tree.root(n)
            for m in range(n):
                proof = tree.inclusion_proof(m, n)
                assert proof == reference_path(m, leaves[:n])
                assert merkle.verify_inclusion(merkle.leaf_hash(leaves[m]), m, n, proof, root)

    def test_single_leaf_tree(self) -> None:
        tree = tree_of([b"only"])
        assert tree.inclusion_proof(0) == []
        assert merkle.verify_inclusion(merkle.leaf_hash(b"only"), 0, 1, [], tree.root())

    def test_tampered_leaf_fails(self, big: tuple[list[bytes], MerkleTree]) -> None:
        _, tree = big
        proof = tree.inclusion_proof(5, 40)
        assert not merkle.verify_inclusion(merkle.leaf_hash(b"forged"), 5, 40, proof, tree.root(40))

    def test_wrong_index_fails(self, big: tuple[list[bytes], MerkleTree]) -> None:
        leaves, tree = big
        proof = tree.inclusion_proof(5, 40)
        leaf = merkle.leaf_hash(leaves[5])
        assert not merkle.verify_inclusion(leaf, 6, 40, proof, tree.root(40))
        assert not merkle.verify_inclusion(leaf, 40, 40, proof, tree.root(40))
        assert not merkle.verify_inclusion(leaf, -1, 40, proof, tree.root(40))

    def test_wrong_tree_size_or_root_fails(self, big: tuple[list[bytes], MerkleTree]) -> None:
        leaves, tree = big
        proof = tree.inclusion_proof(5, 40)
        leaf = merkle.leaf_hash(leaves[5])
        assert not merkle.verify_inclusion(leaf, 5, 41, proof, tree.root(41))
        assert not merkle.verify_inclusion(leaf, 5, 40, proof, tree.root(39))

    def test_modified_truncated_extended_and_reordered_paths_fail(
        self, big: tuple[list[bytes], MerkleTree]
    ) -> None:
        leaves, tree = big
        proof = tree.inclusion_proof(13, 50)
        leaf, root = merkle.leaf_hash(leaves[13]), tree.root(50)
        flipped = [proof[0][:-1] + bytes([proof[0][-1] ^ 1]), *proof[1:]]
        variants = [
            flipped,
            proof[:-1],
            [*proof, proof[-1]],
            list(reversed(proof)),
            [proof[0][:16], *proof[1:]],  # wrong hash length
        ]
        for variant in variants:
            assert not merkle.verify_inclusion(leaf, 13, 50, variant, root)

    def test_leaf_hash_is_not_accepted_as_node(self) -> None:
        """Second-preimage attack: an interior node presented as a leaf must fail."""
        leaves = [b"a", b"b", b"c", b"d"]
        tree = tree_of(leaves)
        interior = merkle.node_hash(merkle.leaf_hash(b"a"), merkle.leaf_hash(b"b"))
        proof = [tree.inclusion_proof(0, 4)[-1]]
        assert not merkle.verify_inclusion(interior, 0, 4, proof, tree.root())
        assert not merkle.verify_inclusion(merkle.leaf_hash(interior), 0, 2, proof, tree.root())

    @settings(max_examples=60, deadline=None)
    @given(st.integers(min_value=1, max_value=300), st.data())
    def test_property_random_trees(self, size: int, data: st.DataObject) -> None:
        leaves = [i.to_bytes(4, "big") for i in range(size)]
        tree = tree_of(leaves)
        index = data.draw(st.integers(min_value=0, max_value=size - 1))
        proof = tree.inclusion_proof(index)
        assert merkle.verify_inclusion(
            merkle.leaf_hash(leaves[index]), index, size, proof, tree.root()
        )


class TestConsistency:
    def test_matches_rfc_subproof(self, big: tuple[list[bytes], MerkleTree]) -> None:
        leaves, tree = big
        for n in range(1, len(leaves) + 1):
            for m in range(n + 1):
                proof = tree.consistency_proof(m, n)
                if 0 < m < n:
                    assert proof == reference_subproof(m, leaves[:n], True)
                assert merkle.verify_consistency(m, n, tree.root(m), tree.root(n), proof)

    def test_equal_sizes_require_empty_proof_and_equal_roots(self) -> None:
        tree = tree_of([b"a", b"b", b"c"])
        root = tree.root()
        assert merkle.verify_consistency(3, 3, root, root, [])
        assert not merkle.verify_consistency(3, 3, root, tree.root(2), [])
        assert not merkle.verify_consistency(3, 3, root, root, [root])

    def test_empty_tree_is_consistent_with_everything(self) -> None:
        tree = tree_of([b"a", b"b"])
        assert merkle.verify_consistency(0, 2, merkle.EMPTY_ROOT, tree.root(), [])
        assert not merkle.verify_consistency(0, 2, b"\x01" * 32, tree.root(), [])
        assert not merkle.verify_consistency(0, 2, merkle.EMPTY_ROOT, tree.root(), [tree.root()])

    def test_rejects_bad_sizes(self) -> None:
        root = tree_of([b"a"]).root()
        assert not merkle.verify_consistency(2, 1, root, root, [root])
        assert not merkle.verify_consistency(-1, 1, root, root, [])
        assert not merkle.verify_consistency(1, 2, root, root, [])

    def test_tampered_proofs_fail(self, big: tuple[list[bytes], MerkleTree]) -> None:
        _, tree = big
        for m, n in [(1, 2), (3, 7), (4, 8), (6, 8), (13, 50), (32, 67)]:
            proof = tree.consistency_proof(m, n)
            old, new = tree.root(m), tree.root(n)
            flipped = [p[:-1] + bytes([p[-1] ^ 1]) for p in proof]
            for variant in (flipped, proof[:-1], [*proof, proof[0]], [b"\x00" * 31, *proof[1:]]):
                assert not merkle.verify_consistency(m, n, old, new, variant)
            assert not merkle.verify_consistency(m, n, old, tree.root(n - 1), proof)
            assert not merkle.verify_consistency(
                m, n, tree.root(m - 1) if m > 1 else new, new, proof
            )

    def test_detects_a_forked_log(self) -> None:
        """A log that rewrote history cannot prove consistency with an earlier head."""
        honest = tree_of([f"e{i}".encode() for i in range(10)])
        forked = tree_of([f"e{i}".encode() for i in range(6)] + [b"rewritten"] + [b"x"] * 5)
        old_root = honest.root(8)
        proof = forked.consistency_proof(8, 12)
        assert not merkle.verify_consistency(8, 12, old_root, forked.root(12), proof)

    @settings(max_examples=60, deadline=None)
    @given(st.integers(min_value=1, max_value=200), st.data())
    def test_property_random_pairs(self, second: int, data: st.DataObject) -> None:
        tree = tree_of([i.to_bytes(4, "big") for i in range(second)])
        first = data.draw(st.integers(min_value=0, max_value=second))
        proof = tree.consistency_proof(first, second)
        assert merkle.verify_consistency(first, second, tree.root(first), tree.root(second), proof)

    def test_verifier_returns_none_on_overlong_path(self) -> None:
        assert merkle.root_from_inclusion_proof(b"\x00" * 32, 0, 1, [b"\x00" * 32]) is None
