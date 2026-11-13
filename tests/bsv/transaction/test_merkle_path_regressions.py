import hashlib

import pytest

from bsv import merkle_path
from bsv.merkle_path import MerklePath


def _h(i: int) -> str:
    return hashlib.sha256(str(i).encode()).hexdigest()


def _reference_root(leaves: list[str]) -> str:
    """Bitcoin merkle root of display-order hex hashes, duplicating the last odd node."""
    level = [bytes.fromhex(h)[::-1] for h in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(hashlib.sha256(level[i] + level[i + 1]).digest()).digest() for i in range(0, len(level), 2)
        ]
    return level[0][::-1].hex()


class _CountingLevel(list):
    """A path level that counts how many times it is scanned."""

    scans = 0

    def __iter__(self):
        self.scans += 1
        return super().__iter__()


class TestSingleTransactionOffset:
    """A lone level-0 leaf is the block root only at offset 0 (TS assertSingleTransactionOffset).

    At any other offset the txid is returned as the block root, and verify() also skips the
    coinbase maturity check, which keys off offset 0.
    """

    def test_offset_zero_is_the_root(self):
        txid = _h(0)
        mp = MerklePath(800000, [[{"offset": 0, "hash_str": txid, "txid": True}]])
        assert mp.compute_root(txid) == txid

    @pytest.mark.parametrize("offset", [1, 5, 1024])
    def test_other_offsets_are_rejected(self, offset):
        txid = _h(offset)
        with pytest.raises(ValueError, match=f"Missing hash for index {offset} at height 0"):
            MerklePath(800000, [[{"offset": offset, "hash_str": txid, "txid": True}]])


class TestLevelZeroOnlyPath:
    """A compound BUMP may carry every txid at level 0; computing its root must stay cheap.

    Before the sibling subtrees were memoized this cost quadratic hashing plus cubic list scans:
    512 leaves took 1.7s, 2,048 took 90s, and a few thousand leaves from an untrusted BEEF hung
    the parser (a DoS vector).
    """

    @pytest.mark.parametrize("n", [3, 4, 7, 16, 33])
    def test_root_matches_reference(self, n):
        hashes = [_h(i) for i in range(n)]
        leaves = [{"offset": i, "hash_str": h, "txid": True} for i, h in enumerate(hashes)]
        mp = MerklePath(800000, [leaves])
        expected = _reference_root(hashes)
        for i, h in enumerate(hashes):
            assert mp.compute_root(h) == expected, f"leaf {i} of {n}"

    @pytest.mark.parametrize("native", [True, False])
    @pytest.mark.parametrize("shape", ["level0", "empty_uppers", "one_node_per_upper", "all_upper_nodes"])
    def test_validation_work_is_not_quadratic(self, monkeypatch, native, shape):
        """Counts work, not seconds: O(n log n) hashes and a constant number of level-0 scans.

        Padding a level-0-only path with upper levels used to route validation through
        compute_root() once per leaf, which rescanned level 0 every time and stayed quadratic
        with or without the C extension (whose hashing the hash counter cannot see).
        """
        if native and not merkle_path._USE_NATIVE:
            pytest.skip("C extension not built")
        monkeypatch.setattr(merkle_path, "_USE_NATIVE", native)

        n = 256
        tree = [[_h(i) for i in range(n)]]
        while len(tree[-1]) > 1:
            below = tree[-1]
            tree.append([merkle_path._hash_pair(below[i + 1], below[i]) for i in range(0, len(below), 2)])
        uppers = tree[1:-1]
        level0 = _CountingLevel({"offset": i, "hash_str": h, "txid": True} for i, h in enumerate(tree[0]))
        path = [level0]
        if shape == "empty_uppers":
            path += [[] for _ in uppers]
        elif shape == "one_node_per_upper":
            path += [[{"offset": 1, "hash_str": level[1]}] for level in uppers]
        elif shape == "all_upper_nodes":
            path += [[{"offset": i, "hash_str": h} for i, h in enumerate(level)] for level in uppers]

        calls = 0
        real_hash_pair = merkle_path._hash_pair

        def counting_hash_pair(left, right):
            nonlocal calls
            calls += 1
            return real_hash_pair(left, right)

        with monkeypatch.context() as counting:
            counting.setattr(merkle_path, "_hash_pair", counting_hash_pair)
            mp = MerklePath(800000, path, legal_offsets_only=False)
        # n walks of log2(n) hashes plus at most n memoized nodes; the quadratic walk needed n*(n-1).
        assert calls <= n * (len(tree) - 1) + n, f"{shape}: {calls} hashes for {n} leaves"
        assert level0.scans <= 8, f"{shape}: level 0 scanned {level0.scans} times for {n} leaves"
        assert mp.compute_root(tree[0][0]) == tree[-1][0] == _reference_root(tree[0])


@pytest.mark.parametrize("native", [True, False])
class TestDuplicateMarker:
    """A duplicate marker has no hash of its own; validation must not walk from it."""

    @pytest.fixture(autouse=True)
    def _backend(self, monkeypatch, native):
        if native and not merkle_path._USE_NATIVE:
            pytest.skip("C extension not built")
        monkeypatch.setattr(merkle_path, "_USE_NATIVE", native)

    def test_level_zero_only_path(self):
        hashes = [_h(i) for i in range(3)]
        leaves = [{"offset": i, "hash_str": h, "txid": True} for i, h in enumerate(hashes)]
        mp = MerklePath(800000, [[*leaves, {"offset": 3, "duplicate": True}]])
        assert mp.compute_root(hashes[2]) == _reference_root(hashes)

    def test_path_with_upper_levels(self):
        hashes = [_h(i) for i in range(3)]
        left = merkle_path._hash_pair(hashes[1], hashes[0])
        path = [
            [{"offset": 2, "hash_str": hashes[2], "txid": True}, {"offset": 3, "duplicate": True}],
            [{"offset": 0, "hash_str": left}],
        ]
        assert MerklePath(800000, path).compute_root(hashes[2]) == _reference_root(hashes)

    def test_empty_hash_is_not_treated_as_a_marker(self):
        with pytest.raises(ValueError, match="Missing hash for index 0 at height 0"):
            MerklePath(800000, [[{"offset": 0, "hash_str": ""}, {"offset": 2, "hash_str": _h(2)}]])

    def test_only_duplicate_markers_is_rejected(self):
        with pytest.raises(ValueError, match="No valid leaf found"):
            MerklePath(800000, [[{"offset": 0, "duplicate": True}, {"offset": 1, "duplicate": True}]])


class TestNativeAgreesWithValidation:
    """compute_root() must return the root the constructor validated, on either backend.

    The C walk indexes with a C long, so trees it cannot index (64+ levels, or an offset
    that overflows a long) must take the Python walk instead of returning another root.
    """

    A, B, C = "11" * 32, "22" * 32, "33" * 32

    def _leaf(self, offset, hash_str):
        return {"offset": offset, "hash_str": hash_str}

    def test_path_taller_than_a_c_long(self):
        path = (
            [[self._leaf(0, self.A), self._leaf(1, self.B)]]
            + [[self._leaf(1, self.C)] for _ in range(63)]
            + [[self._leaf(0, self.B), self._leaf(1, self.C)]]
        )
        mp = MerklePath(800000, path, legal_offsets_only=False)
        assert mp.compute_root(self.A) == mp.compute_root(self.B)

    def test_upper_level_offset_overflowing_a_c_long(self):
        path = [
            [self._leaf(0, self.A), self._leaf(1, self.B)],
            [self._leaf(2**63, self.A), self._leaf(1, self.C)],
        ]
        mp = MerklePath(800000, path, legal_offsets_only=False)
        assert mp.compute_root(self.A) == mp.compute_root(self.B)


def test_sparse_offsets_do_not_descend_into_empty_subtrees():
    """Two leaves at a huge offset used to memoize a miss per (height, offset): O(bits^2)."""
    a, b = _h(0), _h(1)
    mp = MerklePath(800000, [[{"offset": 2**900, "hash_str": a}, {"offset": 2**900 + 1, "hash_str": b}]])
    levels, memo = mp._offset_index(), {}
    mp._compute_root_from(b, 2**900 + 1, levels, memo, 2**900 + 1, 901)
    assert len(memo) <= 901
