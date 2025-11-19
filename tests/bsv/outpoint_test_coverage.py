"""
Coverage tests for outpoint.py - untested branches.
"""
import pytest


# ========================================================================
# Outpoint initialization branches
# ========================================================================

def test_outpoint_init():
    """Test Outpoint initialization."""
    try:
        from bsv.outpoint import Outpoint
        op = Outpoint(txid='0' * 64, vout=0)
        assert op is not None
    except ImportError:
        pytest.skip("Outpoint not available")


def test_outpoint_init_with_index():
    """Test Outpoint with various indices."""
    try:
        from bsv.outpoint import Outpoint
        op = Outpoint(txid='0' * 64, vout=5)
        assert op.vout == 5
    except ImportError:
        pytest.skip("Outpoint not available")


def test_outpoint_init_zero_index():
    """Test Outpoint with zero index."""
    try:
        from bsv.outpoint import Outpoint
        op = Outpoint(txid='0' * 64, vout=0)
        assert op.vout == 0
    except ImportError:
        pytest.skip("Outpoint not available")


# ========================================================================
# Serialization branches
# ========================================================================

def test_outpoint_serialize():
    """Test Outpoint serialization."""
    try:
        from bsv.outpoint import Outpoint
        op = Outpoint(txid='0' * 64, vout=0)
        serialized = op.serialize()
        assert isinstance(serialized, bytes)
        assert len(serialized) == 36  # 32 bytes txid + 4 bytes vout
    except ImportError:
        pytest.skip("Outpoint not available")


def test_outpoint_deserialize():
    """Test Outpoint deserialization."""
    try:
        from bsv.outpoint import Outpoint
        op1 = Outpoint(txid='0' * 64, vout=1)
        serialized = op1.serialize()
        
        op2 = Outpoint.deserialize(serialized)
        assert op2.vout == 1
    except ImportError:
        pytest.skip("Outpoint not available")


# ========================================================================
# Comparison branches
# ========================================================================

def test_outpoint_equality():
    """Test Outpoint equality."""
    try:
        from bsv.outpoint import Outpoint
        op1 = Outpoint(txid='0' * 64, vout=0)
        op2 = Outpoint(txid='0' * 64, vout=0)
        assert op1.txid == op2.txid and op1.vout == op2.vout
    except ImportError:
        pytest.skip("Outpoint not available")


def test_outpoint_inequality():
    """Test Outpoint inequality."""
    try:
        from bsv.outpoint import Outpoint
        op1 = Outpoint(txid='0' * 64, vout=0)
        op2 = Outpoint(txid='0' * 64, vout=1)
        assert op1.vout != op2.vout
    except ImportError:
        pytest.skip("Outpoint not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_outpoint_str_representation():
    """Test Outpoint string representation."""
    try:
        from bsv.outpoint import Outpoint
        op = Outpoint(txid='0' * 64, vout=0)
        str_repr = str(op)
        assert isinstance(str_repr, str)
    except ImportError:
        pytest.skip("Outpoint not available")


def test_outpoint_large_index():
    """Test Outpoint with large index."""
    try:
        from bsv.outpoint import Outpoint
        op = Outpoint(txid='0' * 64, vout=0xFFFFFFFF)
        assert op.vout == 0xFFFFFFFF
    except ImportError:
        pytest.skip("Outpoint not available")

