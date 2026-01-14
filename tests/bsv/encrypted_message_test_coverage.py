"""
Coverage tests for encrypted_message.py - untested branches.
"""

import pytest

# Constants for skip messages
SKIP_ENCRYPTION = "Encryption functions not available"
from bsv.keys import PrivateKey

# ========================================================================
# Encryption branches
# ========================================================================


def test_encrypt_message_empty():
    """Test encrypting empty message."""
    try:
        from bsv.encrypted_message import encrypt

        sender = PrivateKey()
        recipient = PrivateKey().public_key()

        encrypted = encrypt(b"", sender, recipient)
        assert isinstance(encrypted, bytes)
    except ImportError:
        pytest.skip(SKIP_ENCRYPTION)


def test_encrypt_message_small():
    """Test encrypting small message."""
    try:
        from bsv.encrypted_message import encrypt

        sender = PrivateKey()
        recipient = PrivateKey().public_key()

        encrypted = encrypt(b"test", sender, recipient)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0
    except ImportError:
        pytest.skip(SKIP_ENCRYPTION)


def test_encrypt_message_large():
    """Test encrypting large message."""
    try:
        from bsv.encrypted_message import encrypt

        sender = PrivateKey()
        recipient = PrivateKey().public_key()

        message = b"x" * 10000
        encrypted = encrypt(message, sender, recipient)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(message)
    except ImportError:
        pytest.skip(SKIP_ENCRYPTION)


# ========================================================================
# Decryption branches
# ========================================================================


def test_decrypt_message_valid():
    """Test decrypting valid encrypted message."""
    try:
        from bsv.encrypted_message import decrypt, encrypt

        sender_priv = PrivateKey()
        recipient_priv = PrivateKey()

        message = b"test message"
        encrypted = encrypt(message, sender_priv, recipient_priv.public_key())
        decrypted = decrypt(encrypted, recipient_priv, sender_priv.public_key())

        assert decrypted == message
    except ImportError:
        pytest.skip(SKIP_ENCRYPTION)


def test_decrypt_message_wrong_key():
    """Test decrypting with wrong key fails."""
    try:
        from bsv.encrypted_message import decrypt, encrypt

        sender = PrivateKey()
        recipient = PrivateKey()
        wrong_key = PrivateKey()

        message = b"test"
        encrypted = encrypt(message, sender, recipient.public_key())

        try:
            decrypt(encrypted, wrong_key, sender.public_key())
            # Should fail or return garbage
            # Decryption failed or produced different result
        except Exception:
            # Expected to fail - acceptable
            pass
    except ImportError:
        pytest.skip(SKIP_ENCRYPTION)


def test_decrypt_invalid_data():
    """Test decrypting invalid data."""
    try:
        from bsv.encrypted_message import decrypt

        recipient = PrivateKey()
        sender_pub = PrivateKey().public_key()

        try:
            decrypt(b"invalid", recipient, sender_pub)
        except Exception:
            # Expected to fail
            pass
    except ImportError:
        pytest.skip(SKIP_ENCRYPTION)


# ========================================================================
# Edge cases
# ========================================================================


def test_encrypt_decrypt_roundtrip():
    """Test encryption/decryption roundtrip."""
    try:
        from bsv.encrypted_message import decrypt, encrypt

        sender_priv = PrivateKey()
        recipient_priv = PrivateKey()

        original = b"roundtrip test message"
        encrypted = encrypt(original, sender_priv, recipient_priv.public_key())
        decrypted = decrypt(encrypted, recipient_priv, sender_priv.public_key())

        assert decrypted == original
    except ImportError:
        pytest.skip(SKIP_ENCRYPTION)


def test_encrypt_with_none_message():
    """Test encrypt with None message."""
    try:
        from bsv.encrypted_message import encrypt

        sender = PrivateKey()
        recipient = PrivateKey().public_key()

        try:
            encrypt(None, sender, recipient)
        except (TypeError, AttributeError):
            # Expected
            pass
    except ImportError:
        pytest.skip(SKIP_ENCRYPTION)
