"""
Coverage tests for hash.py - untested branches.
"""
import pytest
from bsv.hash import hash256, hash160, sha256, ripemd160, hmac_sha256


# ========================================================================
# hash256 branches
# ========================================================================

def test_hash256_empty():
    """Test hash256 with empty input."""
    result = hash256(b'')
    assert len(result) == 32


def test_hash256_small_input():
    """Test hash256 with small input."""
    result = hash256(b'\x01')
    assert len(result) == 32


def test_hash256_large_input():
    """Test hash256 with large input."""
    result = hash256(b'x' * 10000)
    assert len(result) == 32


def test_hash256_deterministic():
    """Test hash256 is deterministic."""
    data = b'test data'
    result1 = hash256(data)
    result2 = hash256(data)
    assert result1 == result2


# ========================================================================
# hash160 branches
# ========================================================================

def test_hash160_empty():
    """Test hash160 with empty input."""
    result = hash160(b'')
    assert len(result) == 20


def test_hash160_small_input():
    """Test hash160 with small input."""
    result = hash160(b'\x01')
    assert len(result) == 20


def test_hash160_deterministic():
    """Test hash160 is deterministic."""
    data = b'test data'
    result1 = hash160(data)
    result2 = hash160(data)
    assert result1 == result2


# ========================================================================
# sha256 branches
# ========================================================================

def test_sha256_empty():
    """Test sha256 with empty input."""
    result = sha256(b'')
    assert len(result) == 32


def test_sha256_with_data():
    """Test sha256 with data."""
    result = sha256(b'test')
    assert len(result) == 32


# ========================================================================
# ripemd160 branches
# ========================================================================

def test_ripemd160_empty():
    """Test ripemd160 with empty input."""
    result = ripemd160(b'')
    assert len(result) == 20


def test_ripemd160_with_data():
    """Test ripemd160 with data."""
    result = ripemd160(b'test')
    assert len(result) == 20


# ========================================================================
# hmac_sha256 branches
# ========================================================================

def test_hmac_sha256_empty_key():
    """Test hmac_sha256 with empty key."""
    result = hmac_sha256(b'', b'data')
    assert len(result) == 32


def test_hmac_sha256_empty_data():
    """Test hmac_sha256 with empty data."""
    result = hmac_sha256(b'key', b'')
    assert len(result) == 32


def test_hmac_sha256_both_empty():
    """Test hmac_sha256 with both empty."""
    result = hmac_sha256(b'', b'')
    assert len(result) == 32


def test_hmac_sha256_with_data():
    """Test hmac_sha256 with key and data."""
    result = hmac_sha256(b'secret_key', b'message')
    assert len(result) == 32


def test_hmac_sha256_deterministic():
    """Test hmac_sha256 is deterministic."""
    key = b'key'
    data = b'data'
    result1 = hmac_sha256(key, data)
    result2 = hmac_sha256(key, data)
    assert result1 == result2


def test_hmac_sha256_different_keys():
    """Test hmac_sha256 with different keys produces different results."""
    data = b'data'
    result1 = hmac_sha256(b'key1', data)
    result2 = hmac_sha256(b'key2', data)
    assert result1 != result2

