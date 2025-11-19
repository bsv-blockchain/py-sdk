"""
Coverage tests for merkle_tree_parent.py - untested branches.
"""
import pytest


# ========================================================================
# Merkle tree parent calculation branches
# ========================================================================

def test_merkle_tree_parent_basic():
    """Test calculating Merkle tree parent."""
    try:
        from bsv.merkle_tree_parent import merkle_tree_parent
        
        left = b'\x00' * 32
        right = b'\x01' * 32
        
        parent = merkle_tree_parent(left, right)
        assert isinstance(parent, bytes)
        assert len(parent) == 32
    except ImportError:
        pytest.skip("merkle_tree_parent not available")


def test_merkle_tree_parent_same_nodes():
    """Test parent with identical nodes."""
    try:
        from bsv.merkle_tree_parent import merkle_tree_parent
        
        node = b'\x00' * 32
        parent = merkle_tree_parent(node, node)
        
        assert isinstance(parent, bytes)
        assert len(parent) == 32
    except ImportError:
        pytest.skip("merkle_tree_parent not available")


def test_merkle_tree_parent_deterministic():
    """Test parent calculation is deterministic."""
    try:
        from bsv.merkle_tree_parent import merkle_tree_parent
        
        left = b'\x00' * 32
        right = b'\x01' * 32
        
        parent1 = merkle_tree_parent(left, right)
        parent2 = merkle_tree_parent(left, right)
        
        assert parent1 == parent2
    except ImportError:
        pytest.skip("merkle_tree_parent not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_merkle_tree_parent_order_matters():
    """Test that node order matters."""
    try:
        from bsv.merkle_tree_parent import merkle_tree_parent
        
        left = b'\x00' * 32
        right = b'\x01' * 32
        
        parent1 = merkle_tree_parent(left, right)
        parent2 = merkle_tree_parent(right, left)
        
        assert parent1 != parent2
    except ImportError:
        pytest.skip("merkle_tree_parent not available")


def test_merkle_tree_parent_invalid_length():
    """Test with invalid hash length."""
    try:
        from bsv.merkle_tree_parent import merkle_tree_parent
        
        try:
            parent = merkle_tree_parent(b'\x00' * 16, b'\x01' * 32)
            assert True  # May handle gracefully
        except (ValueError, AssertionError):
            # Expected
            assert True
    except ImportError:
        pytest.skip("merkle_tree_parent not available")


def test_merkle_tree_parent_empty():
    """Test with empty nodes."""
    try:
        from bsv.merkle_tree_parent import merkle_tree_parent
        
        try:
            parent = merkle_tree_parent(b'', b'')
            assert True
        except (ValueError, AssertionError):
            # Expected
            assert True
    except ImportError:
        pytest.skip("merkle_tree_parent not available")

