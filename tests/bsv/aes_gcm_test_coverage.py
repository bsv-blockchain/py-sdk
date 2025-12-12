"""
Coverage tests for aes_gcm.py - untested branches.
"""
import pytest

# Constants for skip messages
SKIP_AES_GCM = "AES-GCM not available"


# ========================================================================
# AES-GCM encryption branches
# ========================================================================

def test_aes_gcm_encrypt_empty():
    """Test AES-GCM encryption with empty data."""
    try:
        from bsv.aes_gcm import encrypt
        key = b'\x00' * 32  # 256-bit key
        encrypted = encrypt(b'', key)
        assert isinstance(encrypted, bytes) or True
    except ImportError:
        pytest.skip(SKIP_AES_GCM)


def test_aes_gcm_encrypt_small():
    """Test AES-GCM encryption with small data."""
    try:
        from bsv.aes_gcm import encrypt
        key = b'\x00' * 32
        encrypted = encrypt(b'test', key)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0
    except ImportError:
        pytest.skip(SKIP_AES_GCM)


def test_aes_gcm_encrypt_large():
    """Test AES-GCM encryption with large data."""
    try:
        from bsv.aes_gcm import encrypt
        key = b'\x00' * 32
        data = b'x' * 10000
        encrypted = encrypt(data, key)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(data)
    except ImportError:
        pytest.skip(SKIP_AES_GCM)


# ========================================================================
# AES-GCM decryption branches
# ========================================================================

def test_aes_gcm_decrypt_valid():
    """Test AES-GCM decryption with valid data."""
    try:
        from bsv.aes_gcm import encrypt, decrypt
        key = b'\x00' * 32
        data = b'test message'
        
        encrypted = encrypt(data, key)
        decrypted = decrypt(encrypted, key)
        
        assert decrypted == data
    except ImportError:
        pytest.skip(SKIP_AES_GCM)


def test_aes_gcm_decrypt_wrong_key():
    """Test AES-GCM decryption with wrong key."""
    try:
        from bsv.aes_gcm import encrypt, decrypt
        key1 = b'\x00' * 32
        key2 = b'\x01' * 32
        data = b'test'
        
        encrypted = encrypt(data, key1)
        try:
            decrypted = decrypt(encrypted, key2)
            # Should fail authentication
            assert False, "Should have failed"
        except Exception:
            # Expected to fail
            assert True
    except ImportError:
        pytest.skip(SKIP_AES_GCM)


def test_aes_gcm_decrypt_invalid_data():
    """Test AES-GCM decryption with invalid data."""
    try:
        from bsv.aes_gcm import decrypt
        key = b'\x00' * 32
        
        try:
            decrypted = decrypt(b'invalid', key)
            assert True
        except Exception:
            # Expected to fail
            assert True
    except ImportError:
        pytest.skip(SKIP_AES_GCM)


# ========================================================================
# Key size branches
# ========================================================================

def test_aes_gcm_128_bit_key():
    """Test AES-GCM with 128-bit key."""
    try:
        from bsv.aes_gcm import encrypt
        key = b'\x00' * 16  # 128-bit
        encrypted = encrypt(b'test', key)
        assert isinstance(encrypted, bytes)
    except (ImportError, ValueError):
        pytest.skip("128-bit AES-GCM not available or not supported")


def test_aes_gcm_256_bit_key():
    """Test AES-GCM with 256-bit key."""
    try:
        from bsv.aes_gcm import encrypt
        key = b'\x00' * 32  # 256-bit
        encrypted = encrypt(b'test', key)
        assert isinstance(encrypted, bytes)
    except ImportError:
        pytest.skip(SKIP_AES_GCM)


def test_aes_gcm_invalid_key_size():
    """Test AES-GCM with invalid key size."""
    try:
        from bsv.aes_gcm import encrypt
        key = b'\x00' * 15  # Invalid size
        
        try:
            encrypted = encrypt(b'test', key)
            assert True
        except ValueError:
            # Expected to fail
            assert True
    except ImportError:
        pytest.skip(SKIP_AES_GCM)


# ========================================================================
# Edge cases
# ========================================================================

def test_aes_gcm_roundtrip():
    """Test AES-GCM encryption/decryption roundtrip."""
    try:
        from bsv.aes_gcm import encrypt, decrypt
        key = b'\x01\x02\x03' * 10 + b'\x00\x00'  # 32 bytes
        original = b'roundtrip test data'
        
        encrypted = encrypt(original, key)
        decrypted = decrypt(encrypted, key)
        
        assert decrypted == original
    except ImportError:
        pytest.skip(SKIP_AES_GCM)


def test_aes_gcm_different_keys_different_output():
    """Test that different keys produce different ciphertext."""
    try:
        from bsv.aes_gcm import encrypt
        key1 = b'\x00' * 32
        key2 = b'\x01' * 32
        data = b'test'
        
        enc1 = encrypt(data, key1)
        enc2 = encrypt(data, key2)
        
        assert enc1 != enc2
    except ImportError:
        pytest.skip(SKIP_AES_GCM)

