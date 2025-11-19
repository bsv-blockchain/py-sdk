"""
Coverage tests for primitives.py - untested branches.
"""
import pytest


# ========================================================================
# Primitives branches
# ========================================================================

def test_primitives_hash256():
    """Test hash256 function."""
    try:
        from bsv.primitives import hash256
        result = hash256(b'test')
        assert isinstance(result, bytes)
        assert len(result) == 32
    except ImportError:
        pytest.skip("Primitives not available")


def test_primitives_hash160():
    """Test hash160 function."""
    try:
        from bsv.primitives import hash160
        result = hash160(b'test')
        assert isinstance(result, bytes)
        assert len(result) == 20
    except ImportError:
        pytest.skip("Primitives not available")


def test_primitives_sha256():
    """Test sha256 function."""
    try:
        from bsv.primitives import sha256
        result = sha256(b'test')
        assert isinstance(result, bytes)
        assert len(result) == 32
    except ImportError:
        pytest.skip("Primitives not available")


def test_primitives_ripemd160():
    """Test ripemd160 function."""
    try:
        from bsv.primitives import ripemd160
        result = ripemd160(b'test')
        assert isinstance(result, bytes)
        assert len(result) == 20
    except ImportError:
        pytest.skip("Primitives not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_hash256_empty():
    """Test hash256 with empty data."""
    try:
        from bsv.primitives import hash256
        result = hash256(b'')
        assert isinstance(result, bytes)
        assert len(result) == 32
    except ImportError:
        pytest.skip("Primitives not available")


def test_hash160_empty():
    """Test hash160 with empty data."""
    try:
        from bsv.primitives import hash160
        result = hash160(b'')
        assert isinstance(result, bytes)
        assert len(result) == 20
    except ImportError:
        pytest.skip("Primitives not available")


def test_hash256_large_data():
    """Test hash256 with large data."""
    try:
        from bsv.primitives import hash256
        large_data = b'x' * 10000
        result = hash256(large_data)
        assert isinstance(result, bytes)
        assert len(result) == 32
    except ImportError:
        pytest.skip("Primitives not available")

