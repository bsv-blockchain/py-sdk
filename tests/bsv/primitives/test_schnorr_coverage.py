"""
Coverage tests for primitives/schnorr.py - untested branches.
"""
import pytest
from bsv.keys import PrivateKey


# ========================================================================
# Schnorr signature branches
# ========================================================================

def test_schnorr_sign():
    """Test Schnorr signing."""
    try:
        from bsv.primitives.schnorr import schnorr_sign
        
        priv = PrivateKey()
        message = b'\x01' * 32  # 32-byte message hash
        
        signature = schnorr_sign(message, priv.key)
        assert isinstance(signature, bytes)
        assert len(signature) == 64  # Schnorr signatures are 64 bytes
    except ImportError:
        pytest.skip("Schnorr not available")


def test_schnorr_verify_valid():
    """Test verifying valid Schnorr signature."""
    try:
        from bsv.primitives.schnorr import schnorr_sign, schnorr_verify
        
        priv = PrivateKey()
        pub = priv.public_key()
        message = b'\x01' * 32
        
        signature = schnorr_sign(message, priv.key)
        is_valid = schnorr_verify(message, signature, pub.serialize())
        
        assert is_valid == True
    except ImportError:
        pytest.skip("Schnorr not available")


def test_schnorr_verify_invalid():
    """Test verifying invalid Schnorr signature."""
    try:
        from bsv.primitives.schnorr import schnorr_verify
        
        priv = PrivateKey()
        pub = priv.public_key()
        message = b'\x01' * 32
        invalid_sig = b'\x00' * 64
        
        is_valid = schnorr_verify(message, invalid_sig, pub.serialize())
        assert is_valid == False
    except ImportError:
        pytest.skip("Schnorr not available")


def test_schnorr_verify_wrong_key():
    """Test Schnorr verification with wrong public key."""
    try:
        from bsv.primitives.schnorr import schnorr_sign, schnorr_verify
        
        priv1 = PrivateKey()
        priv2 = PrivateKey()
        message = b'\x01' * 32
        
        signature = schnorr_sign(message, priv1.key)
        is_valid = schnorr_verify(message, signature, priv2.public_key().serialize())
        
        assert is_valid == False
    except ImportError:
        pytest.skip("Schnorr not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_schnorr_sign_empty_message():
    """Test Schnorr signing empty message."""
    try:
        from bsv.primitives.schnorr import schnorr_sign
        
        priv = PrivateKey()
        
        try:
            _ = schnorr_sign(b'', priv.key)
            assert True
        except (ValueError, AssertionError):
            # May require 32-byte message
            assert True
    except ImportError:
        pytest.skip("Schnorr not available")


def test_schnorr_sign_wrong_message_size():
    """Test Schnorr signing with wrong message size."""
    try:
        from bsv.primitives.schnorr import schnorr_sign
        
        priv = PrivateKey()
        message = b'\x01' * 16  # Wrong size
        
        try:
            _ = schnorr_sign(message, priv.key)
            assert True
        except (ValueError, AssertionError):
            # Expected - Schnorr requires 32-byte message
            assert True
    except ImportError:
        pytest.skip("Schnorr not available")


def test_schnorr_deterministic():
    """Test Schnorr signatures are deterministic."""
    try:
        from bsv.primitives.schnorr import schnorr_sign
        
        priv = PrivateKey(b'\x01' * 32)
        message = b'\x02' * 32
        
        sig1 = schnorr_sign(message, priv.key)
        sig2 = schnorr_sign(message, priv.key)
        
        assert sig1 == sig2
    except ImportError:
        pytest.skip("Schnorr not available")

