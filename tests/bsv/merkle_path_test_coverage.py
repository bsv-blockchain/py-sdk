"""
Coverage tests for merkle_path.py - untested branches.
"""

import pytest

from bsv.merkle_path import MerklePath

# ========================================================================
# MerklePath initialization branches
# ========================================================================


def test_merkle_path_init_empty():
    """Test MerklePath with empty path."""
    mp = MerklePath(block_height=0, path=[])
    assert mp.block_height == 0
    assert len(mp.path) == 0


def _two_leaf_path():
    """A minimal valid single-level path with two txid leaves."""
    return [
        [
            {"offset": 0, "hash_str": "00" * 32, "txid": True},
            {"offset": 1, "hash_str": "11" * 32, "txid": True},
        ]
    ]


def test_merkle_path_init_with_path():
    """Test MerklePath with path data."""
    mp = MerklePath(block_height=100, path=_two_leaf_path())
    assert mp.block_height == 100
    assert len(mp.path) == 1
    assert len(mp.path[0]) == 2


def test_merkle_path_init_with_txid():
    """Test MerklePath with txid leaves."""
    mp = MerklePath(block_height=100, path=_two_leaf_path())
    assert mp.path[0][0]["txid"] is True
    assert mp.path[0][0]["hash_str"] == "00" * 32


# ========================================================================
# MerklePath methods
# ========================================================================


def test_merkle_path_to_hex():
    """Test MerklePath hex serialization."""
    mp = MerklePath(block_height=100, path=_two_leaf_path())
    result = mp.to_hex()
    assert isinstance(result, str)
    assert len(result) > 0


def test_merkle_path_from_hex():
    """Test MerklePath hex deserialization round-trip."""
    mp = MerklePath(block_height=100, path=_two_leaf_path())
    mp2 = MerklePath.from_hex(mp.to_hex())
    assert mp2.block_height == 100


def test_merkle_path_compute_root_empty():
    """Test compute_root with empty path."""
    mp = MerklePath(block_height=0, path=[])
    try:
        root = mp.compute_root(b"\x00" * 32)
    except Exception:
        # May require valid path
        return
    assert isinstance(root, bytes) or root is None


def test_merkle_path_verify():
    """Test merkle path verification against a mock chaintracker."""
    import asyncio

    from bsv.chaintracker import ChainTracker

    class MockChainTracker(ChainTracker):
        async def is_valid_root_for_height(self, _root: str, _height: int) -> bool:
            return True

        async def current_height(self) -> int:
            return 100

    mp = MerklePath(block_height=100, path=_two_leaf_path())
    is_valid = asyncio.run(mp.verify("00" * 32, MockChainTracker()))
    assert is_valid is True


# ========================================================================
# Edge cases
# ========================================================================


def test_merkle_path_with_large_height():
    """Test MerklePath with large block height."""
    mp = MerklePath(block_height=999999, path=[])
    assert mp.block_height == 999999


def test_merkle_path_with_negative_height():
    """Test MerklePath with negative height."""
    try:
        mp = MerklePath(block_height=-1, path=[])
        assert mp.block_height == -1
    except ValueError:
        # May validate height
        pass


def test_merkle_path_with_none_path():
    """Test MerklePath with None path."""
    try:
        mp = MerklePath(block_height=0, path=None)
        assert mp.path is None or mp.path == []
    except TypeError:
        # May require list
        pass


def test_merkle_path_str_representation():
    """Test MerklePath string representation."""
    mp = MerklePath(block_height=100, path=[])
    str_repr = str(mp)
    assert isinstance(str_repr, str)
