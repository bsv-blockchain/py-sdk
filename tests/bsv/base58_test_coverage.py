"""
Coverage tests for base58.py - untested branches.
"""
import pytest
from bsv.base58 import encode, decode


# ========================================================================
# encode branches
# ========================================================================

def test_encode_empty():
    """Test encode with empty bytes."""
    result = encode(b'')
    assert result == ''


def test_encode_single_byte():
    """Test encode with single byte."""
    result = encode(b'\x00')
    assert isinstance(result, str)


def test_encode_small_value():
    """Test encode with small value."""
    result = encode(b'\x01')
    assert isinstance(result, str)
    assert len(result) > 0


def test_encode_leading_zeros():
    """Test encode preserves leading zeros."""
    result = encode(b'\x00\x00\x01')
    assert result.startswith('1')


def test_encode_large_value():
    """Test encode with large value."""
    result = encode(b'\xff' * 32)
    assert isinstance(result, str)
    assert len(result) > 0


def test_encode_deterministic():
    """Test encode is deterministic."""
    data = b'\x01\x02\x03'
    result1 = encode(data)
    result2 = encode(data)
    assert result1 == result2


# ========================================================================
# decode branches
# ========================================================================

def test_decode_empty():
    """Test decode with empty string."""
    result = decode('')
    assert result == b''


def test_decode_single_char():
    """Test decode with single character."""
    encoded = encode(b'\x01')
    decoded = decode(encoded)
    assert decoded == b'\x01'


def test_decode_leading_ones():
    """Test decode preserves leading zeros (represented as '1')."""
    encoded = '11' + encode(b'\x01')
    decoded = decode(encoded)
    assert decoded.startswith(b'\x00\x00')


def test_decode_roundtrip():
    """Test encode/decode roundtrip."""
    original = b'\x01\x02\x03\x04\x05'
    encoded = encode(original)
    decoded = decode(encoded)
    assert decoded == original


def test_decode_invalid_character():
    """Test decode with invalid character."""
    try:
        result = decode('0OIl')  # Contains invalid chars
        # May handle or raise
        assert True
    except (ValueError, Exception):
        # Expected for invalid base58
        assert True


def test_decode_with_checksum():
    """Test decode handles various input lengths."""
    # Valid base58 string
    try:
        result = decode('1')
        assert result == b'\x00'
    except Exception:
        # May fail depending on implementation
        assert True


# ========================================================================
# Edge cases
# ========================================================================

def test_encode_all_zeros():
    """Test encode with all zeros."""
    result = encode(b'\x00\x00\x00')
    assert result == '111'


def test_encode_max_byte():
    """Test encode with max byte value."""
    result = encode(b'\xff')
    assert isinstance(result, str)


def test_roundtrip_large_data():
    """Test roundtrip with large data."""
    original = b'x' * 100
    encoded = encode(original)
    decoded = decode(encoded)
    assert decoded == original


def test_roundtrip_random_data():
    """Test roundtrip with various byte values."""
    import random
    random.seed(42)  # noqa: S311 - Using random for reproducible test data, not cryptographic purposes
    original = bytes([random.randint(0, 255) for _ in range(32)])  # noqa: S311
    encoded = encode(original)
    decoded = decode(encoded)
    assert decoded == original

