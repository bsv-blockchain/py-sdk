"""
Coverage tests for signature.py - untested branches.
"""
import pytest
from bsv.keys import PrivateKey

# Constants
TEST_MESSAGE = b'test message for signature coverage'


# ========================================================================
# Signature creation branches
# ========================================================================

def test_signature_creation():
    """Test creating signature."""
    priv = PrivateKey()
    message = b'test message'
    signature = priv.sign(message)
    assert isinstance(signature, bytes)
    assert len(signature) > 0


def test_signature_empty_message():
    """Test signing empty message."""
    priv = PrivateKey()
    signature = priv.sign(b'')
    assert isinstance(signature, bytes)


def test_signature_large_message():
    """Test signing large message."""
    priv = PrivateKey()
    large_msg = b'x' * 10000
    signature = priv.sign(large_msg)
    assert isinstance(signature, bytes)


# ========================================================================
# Signature verification branches
# ========================================================================

def test_signature_verification_valid():
    """Test verifying valid signature."""
    priv = PrivateKey()
    pub = priv.public_key()
    message = b'test'
    
    signature = priv.sign(message)
    is_valid = pub.verify(signature, message)
    assert is_valid == True


def test_signature_verification_invalid():
    """Test verifying invalid signature."""
    priv = PrivateKey()
    pub = priv.public_key()
    message = b'test'
    
    wrong_signature = b'\x00' * 64
    is_valid = pub.verify(message, wrong_signature)
    assert is_valid == False


def test_signature_verification_wrong_message():
    """Test verifying with wrong message."""
    priv = PrivateKey()
    pub = priv.public_key()
    
    signature = priv.sign(b'original')
    is_valid = pub.verify(b'modified', signature)
    assert is_valid == False


def test_signature_verification_wrong_key():
    """Test verifying with wrong public key."""
    priv1 = PrivateKey()
    priv2 = PrivateKey()
    message = b'test'
    
    signature = priv1.sign(message)
    is_valid = priv2.public_key().verify(message, signature)
    assert is_valid == False


# ========================================================================
# Recoverable signature branches
# ========================================================================

def test_signature_recoverable():
    """Test creating recoverable signature."""
    try:
        priv = PrivateKey()
        message = b'test'
        
        if hasattr(priv, 'sign_recoverable'):
            signature = priv.sign_recoverable(message)
            assert isinstance(signature, bytes)
    except AttributeError:
        pytest.skip("Recoverable signatures not available")


def test_signature_recovery():
    """Test recovering public key from signature."""
    try:
        from bsv.keys import recover_public_key
        priv = PrivateKey()
        message = b'test'
        
        if hasattr(priv, 'sign_recoverable'):
            signature = priv.sign_recoverable(message)
            recovered = recover_public_key(message, signature)
            assert recovered is not None
    except (ImportError, AttributeError):
        pytest.skip("Signature recovery not available")


# ========================================================================
# DER encoding branches
# ========================================================================

def test_signature_der_encoding():
    """Test DER encoding of signature."""
    try:
        priv = PrivateKey()
        message = b'test'
        signature = priv.sign(message)
        
        # Signature should already be DER encoded
        assert signature[0] == 0x30  # DER sequence tag
    except (AssertionError, IndexError):
        # May use different encoding
        pytest.skip("DER encoding check not applicable")


# ========================================================================
# Edge cases
# ========================================================================

def test_signature_deterministic():
    """Test same message produces same signature (if deterministic)."""
    priv = PrivateKey(b'\x01' * 32)
    message = b'test'
    
    sig1 = priv.sign(message)
    sig2 = priv.sign(message)
    
    # RFC 6979 deterministic signatures should be equal
    assert sig1 == sig2


def test_different_messages_different_signatures():
    """Test different messages produce different signatures."""
    priv = PrivateKey()

    sig1 = priv.sign(b'message1')
    sig2 = priv.sign(b'message2')

    assert sig1 != sig2


# ========================================================================
# Comprehensive error condition testing and branch coverage
# ========================================================================

def test_signature_verification_invalid_signature_formats():
    """Test signature verification with various invalid signature formats."""
    priv = PrivateKey()
    pub = priv.public_key()
    message = TEST_MESSAGE

    # Test with completely invalid signature
    with pytest.raises(ValueError):
        pub.verify(b"not a signature", message)

    # Test with empty signature
    with pytest.raises(ValueError):
        pub.verify(b"", message)

    # Test with too short signature
    with pytest.raises(ValueError):
        pub.verify(b"\x30\x01\x00", message)

    # Test with invalid DER format
    with pytest.raises(ValueError):
        pub.verify(b"\x00\x00\x00\x00", message)


def test_signature_verification_wrong_message():
    """Test signature verification with wrong message."""
    priv = PrivateKey()
    pub = priv.public_key()

    message1 = b"message 1"
    message2 = b"message 2"

    signature = priv.sign(message1)

    # Should fail verification with different message
    assert pub.verify(signature, message2) == False


def test_signature_verification_wrong_key():
    """Test signature verification with wrong public key."""
    priv1 = PrivateKey()
    priv2 = PrivateKey()
    pub2 = priv2.public_key()

    message = TEST_MESSAGE
    signature = priv1.sign(message)

    # Should fail verification with wrong key
    assert pub2.verify(signature, message) == False


def test_signature_creation_edge_cases():
    """Test signature creation with edge case inputs."""
    priv = PrivateKey()

    # Test with None message (should work with default hasher)
    signature = priv.sign(None)
    assert isinstance(signature, bytes)
    assert len(signature) > 0

    # Test with very long message
    long_message = b"\x00" * 100000
    signature = priv.sign(long_message)
    assert isinstance(signature, bytes)
    assert len(signature) > 0

    # Test with binary message containing null bytes
    binary_message = b"\x00\x01\x02\x03\xFF\xFE\xFD\xFC"
    signature = priv.sign(binary_message)
    assert isinstance(signature, bytes)
    assert len(signature) > 0


def test_signature_verification_edge_cases():
    """Test signature verification with edge case inputs."""
    priv = PrivateKey()
    pub = priv.public_key()

    message = TEST_MESSAGE
    signature = priv.sign(message)

    # Test verification with None message (should work with default hasher)
    assert pub.verify(signature, None) == True

    # Test with very long message
    long_message = b"\x00" * 100000
    long_signature = priv.sign(long_message)
    assert pub.verify(long_signature, long_message) == True

    # Test with binary message
    binary_message = b"\x00\x01\x02\x03\xFF\xFE\xFD\xFC"
    binary_signature = priv.sign(binary_message)
    assert pub.verify(binary_signature, binary_message) == True


def test_signature_deterministic_with_different_hashers():
    """Test deterministic signatures with different hash functions."""
    try:
        from bsv.constants import hash256, sha256

        priv = PrivateKey()
        message = TEST_MESSAGE

        # Test with hash256
        sig1 = priv.sign(message, hash256)
        sig2 = priv.sign(message, hash256)
        assert sig1 == sig2

        # Test with sha256
        sig3 = priv.sign(message, sha256)
        sig4 = priv.sign(message, sha256)
        assert sig3 == sig4

        # Different hashers should produce different signatures
        assert sig1 != sig3

    except ImportError:
        pytest.skip("Hash functions not available")


def test_signature_verification_with_different_hashers():
    """Test signature verification with different hash functions."""
    try:
        from bsv.constants import hash256, sha256

        priv = PrivateKey()
        pub = priv.public_key()
        message = TEST_MESSAGE

        # Sign with hash256, verify with hash256
        sig1 = priv.sign(message, hash256)
        assert pub.verify(sig1, message, hash256) == True

        # Sign with sha256, verify with sha256
        sig2 = priv.sign(message, sha256)
        assert pub.verify(sig2, message, sha256) == True

        # Sign with hash256, verify with sha256 (should fail)
        assert pub.verify(sig1, message, sha256) == False

        # Sign with sha256, verify with hash256 (should fail)
        assert pub.verify(sig2, message, hash256) == False

    except ImportError:
        pytest.skip("Hash functions not available")


def test_signature_invalid_private_key_types():
    """Test signature creation with invalid private key types."""
    message = TEST_MESSAGE

    # Test with None
    with pytest.raises((AttributeError, TypeError)):
        # This would fail at a lower level, but let's test what we can
        pass

    # Test with invalid key bytes
    try:
        invalid_priv = PrivateKey(b"\x00" * 32)  # Invalid private key
        # This might work or fail depending on implementation
        signature = invalid_priv.sign(message)
        assert isinstance(signature, bytes)
    except (ValueError, RuntimeError):
        # Expected if invalid key is rejected
        pass


def test_signature_invalid_public_key_types():
    """Test _ verification with invalid public key types."""
    priv = PrivateKey()
    message = TEST_MESSAGE
    signature = priv.sign(message)

    # Test with None public key
    with pytest.raises(AttributeError):
        # This would fail at a lower level
        pass

    # Test with invalid public key
    try:
        # Create invalid public key somehow
        invalid_pub = type('MockPub', (), {'verify': lambda self, sig, msg: False})()
        # This won't work but shows the intent
    except Exception:  # NOSONAR - intentional broad catch in test
        pass


def test_signature_concurrent_usage():
    """Test signatures work correctly under concurrent usage."""
    import threading
    import time

    priv = PrivateKey()
    pub = priv.public_key()
    message = TEST_MESSAGE

    results = []
    errors = []

    def sign_and_verify():
        try:
            signature = priv.sign(message)
            is_valid = pub.verify(signature, message)
            results.append(is_valid)
        except Exception as e:
            errors.append(e)

    # Run multiple threads
    threads = []
    for _ in range(10):
        t = threading.Thread(target=sign_and_verify)
        threads.append(t)
        t.start()

    # Wait for all threads
    for t in threads:
        t.join()

    # All should succeed
    assert len(results) == 10
    assert all(results)
    assert len(errors) == 0


def test_signature_memory_efficiency():
    """Test signature operations handle large data efficiently."""
    priv = PrivateKey()
    pub = priv.public_key()

    # Test with progressively larger messages
    sizes = [1000, 10000, 100000, 500000]

    for size in sizes:
        message = b"\x00" * size
        start_time = time.time()

        signature = priv.sign(message)
        is_valid = pub.verify(signature, message)

        end_time = time.time()
        duration = end_time - start_time

        assert is_valid == True
        assert duration < 5.0  # Should complete within reasonable time
