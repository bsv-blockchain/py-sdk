"""
Coverage tests for signed_message.py - untested branches.
"""
import pytest
from bsv.keys import PrivateKey


# ========================================================================
# Signed message creation branches
# ========================================================================

def test_sign_message_basic():
    """Test signing a message."""
    try:
        from bsv.signed_message import sign_message
        
        priv = PrivateKey()
        message = "test message"
        
        signed = sign_message(message, priv)
        assert signed is not None
        assert isinstance(signed, (str, bytes))
    except ImportError:
        pytest.skip("sign_message not available")


def test_sign_message_empty():
    """Test signing empty message."""
    try:
        from bsv.signed_message import sign_message
        
        priv = PrivateKey()
        signed = sign_message("", priv)
        assert signed is not None
    except ImportError:
        pytest.skip("sign_message not available")


def test_sign_message_long():
    """Test signing long message."""
    try:
        from bsv.signed_message import sign_message
        
        priv = PrivateKey()
        long_message = "x" * 10000
        
        signed = sign_message(long_message, priv)
        assert signed is not None
    except ImportError:
        pytest.skip("sign_message not available")


# ========================================================================
# Signed message verification branches
# ========================================================================

def test_verify_message_valid():
    """Test verifying valid signed message."""
    try:
        from bsv.signed_message import sign_message, verify_message
        
        priv = PrivateKey()
        message = "test"
        
        signed = sign_message(message, priv)
        is_valid = verify_message(message, signed, priv.public_key())
        
        assert is_valid == True
    except ImportError:
        pytest.skip("sign_message not available")


def test_verify_message_invalid():
    """Test verifying invalid signature."""
    try:
        from bsv.signed_message import verify_message
        
        priv = PrivateKey()
        message = "test"
        invalid_sig = "invalid"
        
        is_valid = verify_message(message, invalid_sig, priv.public_key())
        assert is_valid == False
    except ImportError:
        pytest.skip("verify_message not available")


def test_verify_message_wrong_key():
    """Test verifying with wrong public key."""
    try:
        from bsv.signed_message import sign_message, verify_message
        
        priv1 = PrivateKey()
        priv2 = PrivateKey()
        message = "test"
        
        signed = sign_message(message, priv1)
        is_valid = verify_message(message, signed, priv2.public_key())
        
        assert is_valid == False
    except ImportError:
        pytest.skip("sign_message not available")


def test_verify_message_modified():
    """Test verifying modified message."""
    try:
        from bsv.signed_message import sign_message, verify_message
        
        priv = PrivateKey()
        original = "original"
        modified = "modified"
        
        signed = sign_message(original, priv)
        is_valid = verify_message(modified, signed, priv.public_key())
        
        assert is_valid == False
    except ImportError:
        pytest.skip("sign_message not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_sign_message_unicode():
    """Test signing Unicode message."""
    try:
        from bsv.signed_message import sign_message
        
        priv = PrivateKey()
        unicode_msg = "Hello 世界 🌍"
        
        signed = sign_message(unicode_msg, priv)
        assert signed is not None
    except ImportError:
        pytest.skip("sign_message not available")


def test_sign_message_deterministic():
    """Test signing is deterministic."""
    try:
        from bsv.signed_message import sign_message
        
        priv = PrivateKey(b'\x01' * 32)
        message = "test"
        
        sig1 = sign_message(message, priv)
        sig2 = sign_message(message, priv)
        
        assert sig1 == sig2
    except ImportError:
        pytest.skip("sign_message not available")

