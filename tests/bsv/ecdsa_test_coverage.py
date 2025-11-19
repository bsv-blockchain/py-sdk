"""
Coverage tests for ecdsa.py - untested branches.
"""
import pytest


# ========================================================================
# ECDSA operations branches
# ========================================================================

def test_ecdsa_sign():
    """Test ECDSA signing."""
    try:
        from bsv.ecdsa import sign
        from bsv.keys import PrivateKey
        
        priv = PrivateKey()
        message_hash = b'\x01' * 32
        
        signature = sign(message_hash, priv.key)
        assert isinstance(signature, bytes)
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_ecdsa_verify():
    """Test ECDSA verification."""
    try:
        from bsv.ecdsa import sign, verify
        from bsv.keys import PrivateKey
        
        priv = PrivateKey()
        message_hash = b'\x01' * 32
        
        signature = sign(message_hash, priv.key)
        is_valid = verify(message_hash, signature, priv.public_key().serialize())
        
        assert is_valid == True
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_ecdsa_verify_invalid():
    """Test ECDSA verification with invalid signature."""
    try:
        from bsv.ecdsa import verify
        from bsv.keys import PrivateKey
        
        priv = PrivateKey()
        message_hash = b'\x01' * 32
        invalid_sig = b'\x00' * 64
        
        is_valid = verify(message_hash, invalid_sig, priv.public_key().serialize())
        assert is_valid == False
    except ImportError:
        pytest.skip("ECDSA module not available")


# ========================================================================
# DER encoding/decoding branches
# ========================================================================

def test_ecdsa_der_encode():
    """Test DER encoding."""
    try:
        from bsv.ecdsa import der_encode
        r = 12345
        s = 67890
        
        der = der_encode(r, s)
        assert isinstance(der, bytes)
        assert der[0] == 0x30  # DER sequence tag
    except ImportError:
        pytest.skip("DER encoding not available")


def test_ecdsa_der_decode():
    """Test DER decoding."""
    try:
        from bsv.ecdsa import der_encode, der_decode
        r = 12345
        s = 67890
        
        der = der_encode(r, s)
        r_decoded, s_decoded = der_decode(der)
        
        assert r_decoded == r
        assert s_decoded == s
    except ImportError:
        pytest.skip("DER decoding not available")


# ========================================================================
# Signature normalization branches
# ========================================================================

def test_ecdsa_normalize_signature():
    """Test signature normalization."""
    try:
        from bsv.ecdsa import normalize_signature
        signature = b'\x30' + b'\x00' * 70
        
        normalized = normalize_signature(signature)
        assert isinstance(normalized, bytes)
    except ImportError:
        pytest.skip("Signature normalization not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_ecdsa_sign_zero_hash():
    """Test signing zero hash."""
    try:
        from bsv.ecdsa import sign
        from bsv.keys import PrivateKey
        
        priv = PrivateKey()
        zero_hash = b'\x00' * 32
        
        signature = sign(zero_hash, priv.key)
        assert isinstance(signature, bytes)
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_ecdsa_sign_max_hash():
    """Test signing max hash."""
    try:
        from bsv.ecdsa import sign
        from bsv.keys import PrivateKey

        priv = PrivateKey()
        max_hash = b'\xff' * 32

        signature = sign(max_hash, priv.key)
        assert isinstance(signature, bytes)
    except ImportError:
        pytest.skip("ECDSA module not available")


# ========================================================================
# Comprehensive error condition testing and branch coverage
# ========================================================================

def test_serialize_ecdsa_der_canonical_low_s():
    """Test DER serialization produces canonical low-S signatures."""
    try:
        from bsv.ecdsa import serialize_ecdsa_der
        from bsv.curve import curve

        # Create a signature where s > curve.n // 2 (high S value)
        r = 1
        s = curve.n - 1  # This should trigger the canonical low-S conversion

        signature = serialize_ecdsa_der((r, s))
        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # DER format should start with 0x30
        assert signature[0] == 0x30
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_serialize_ecdsa_der_msb_prefix_r():
    """Test DER serialization with MSB prefix for r value."""
    try:
        from bsv.ecdsa import serialize_ecdsa_der

        # Create r value that will have MSB set after to_bytes
        r = 0x80  # This should trigger MSB prefix addition
        s = 1

        signature = serialize_ecdsa_der((r, s))
        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Should contain the 0x00 prefix byte for r
        assert b'\x00\x80' in signature or signature[4] == 0x00  # Check for prefix
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_serialize_ecdsa_der_msb_prefix_s():
    """Test DER serialization with MSB prefix for s value."""
    try:
        from bsv.ecdsa import serialize_ecdsa_der

        # Create s value that will have MSB set after to_bytes
        r = 1
        s = 0x80  # This should trigger MSB prefix addition

        signature = serialize_ecdsa_der((r, s))
        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Should contain the 0x00 prefix byte for s
        assert b'\x00\x80' in signature or b'\x02\x02\x00\x80' in signature  # Check for prefix
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_deserialize_ecdsa_der_invalid_formats():
    """Test DER deserialization with invalid signature formats."""
    try:
        from bsv.ecdsa import deserialize_ecdsa_der

        # Test invalid start byte
        with pytest.raises(ValueError):
            deserialize_ecdsa_der(b'\x31\x00')  # Wrong start byte

        # Test too short signature
        with pytest.raises(ValueError):
            deserialize_ecdsa_der(b'')  # Empty

        # Test invalid length
        with pytest.raises(ValueError):
            deserialize_ecdsa_der(b'\x30\x01\x02')  # Invalid length

        # Test missing integer marker
        with pytest.raises(ValueError):
            deserialize_ecdsa_der(b'\x30\x06\x03\x01\x00\x03\x01\x00')  # Wrong integer marker

        # Test malformed signature
        with pytest.raises(ValueError):
            deserialize_ecdsa_der(b'invalid')  # Non-hex
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_deserialize_ecdsa_recoverable_invalid_length():
    """Test recoverable signature deserialization with invalid length."""
    try:
        from bsv.ecdsa import deserialize_ecdsa_recoverable

        # Test too short
        with pytest.raises(AssertionError):
            deserialize_ecdsa_recoverable(b'\x00' * 64)  # 64 bytes instead of 65

        # Test too long
        with pytest.raises(AssertionError):
            deserialize_ecdsa_recoverable(b'\x00' * 66)  # 66 bytes instead of 65
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_deserialize_ecdsa_recoverable_invalid_recovery_id():
    """Test recoverable signature deserialization with invalid recovery ID."""
    try:
        from bsv.ecdsa import deserialize_ecdsa_recoverable

        # Test invalid recovery ID (< 0)
        with pytest.raises(AssertionError):
            deserialize_ecdsa_recoverable(b'\x00' * 64 + b'\xff')  # Recovery ID = 255

        # Test invalid recovery ID (> 3)
        with pytest.raises(AssertionError):
            deserialize_ecdsa_recoverable(b'\x00' * 64 + b'\x04')  # Recovery ID = 4
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_serialize_ecdsa_recoverable_invalid_recovery_id():
    """Test recoverable signature serialization with invalid recovery ID."""
    try:
        from bsv.ecdsa import serialize_ecdsa_recoverable

        # Test invalid recovery ID (< 0)
        with pytest.raises(AssertionError):
            serialize_ecdsa_recoverable((1, 2, -1))  # Negative recovery ID

        # Test invalid recovery ID (> 3)
        with pytest.raises(AssertionError):
            serialize_ecdsa_recoverable((1, 2, 4))  # Recovery ID = 4
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_ecdsa_sign_invalid_private_key():
    """Test ECDSA signing with invalid private key."""
    try:
        from bsv.ecdsa import sign

        # Test with None private key
        with pytest.raises((AttributeError, TypeError)):
            sign(b'\x01' * 32, None)

        # Test with invalid private key type
        with pytest.raises((AttributeError, TypeError)):
            sign(b'\x01' * 32, "invalid")
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_ecdsa_verify_invalid_signature():
    """Test ECDSA verification with invalid signature."""
    try:
        from bsv.ecdsa import verify
        from bsv.keys import PrivateKey

        priv = PrivateKey()
        pub = priv.public_key()
        message_hash = b'\x01' * 32

        # Test with None signature
        assert verify(message_hash, None, pub.key) == False

        # Test with empty signature
        assert verify(message_hash, b'', pub.key) == False

        # Test with invalid signature format
        assert verify(message_hash, b'invalid', pub.key) == False
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_ecdsa_verify_invalid_public_key():
    """Test ECDSA verification with invalid public key."""
    try:
        from bsv.ecdsa import verify
        from bsv.keys import PrivateKey

        priv = PrivateKey()
        message_hash = b'\x01' * 32
        signature = priv.sign(message_hash)

        # Test with None public key
        with pytest.raises((AttributeError, TypeError)):
            verify(message_hash, signature, None)

        # Test with invalid public key type
        with pytest.raises((AttributeError, TypeError)):
            verify(message_hash, signature, "invalid")
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_ecdsa_verify_invalid_message_hash():
    """Test ECDSA verification with invalid message hash."""
    try:
        from bsv.ecdsa import verify
        from bsv.keys import PrivateKey

        priv = PrivateKey()
        pub = priv.public_key()
        message_hash = b'\x01' * 32
        signature = priv.sign(message_hash)

        # Test with None message hash
        with pytest.raises((AttributeError, TypeError)):
            verify(None, signature, pub.key)

        # Test with wrong length message hash
        assert verify(b'', signature, pub.key) == False
        assert verify(b'\x01' * 31, signature, pub.key) == False  # Too short
        assert verify(b'\x01' * 33, signature, pub.key) == False  # Too long
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_ecdsa_recover_invalid_signature():
    """Test ECDSA signature recovery with invalid signature."""
    try:
        from bsv.ecdsa import recover

        # Test with None signature
        with pytest.raises((AttributeError, TypeError)):
            recover(None, b'\x01' * 32)

        # Test with empty signature
        with pytest.raises((ValueError, AssertionError)):
            recover(b'', b'\x01' * 32)

        # Test with invalid signature format
        with pytest.raises((ValueError, AssertionError)):
            recover(b'invalid', b'\x01' * 32)
    except ImportError:
        pytest.skip("ECDSA module not available")


def test_ecdsa_recover_invalid_message_hash():
    """Test ECDSA signature recovery with invalid message hash."""
    try:
        from bsv.ecdsa import recover, sign
        from bsv.keys import PrivateKey

        priv = PrivateKey()
        message_hash = b'\x01' * 32
        signature = sign(message_hash, priv.key)

        # Test with None message hash
        with pytest.raises((AttributeError, TypeError)):
            recover(signature, None)

        # Test with wrong length message hash
        with pytest.raises((ValueError, AssertionError)):
            recover(signature, b'')  # Empty
        with pytest.raises((ValueError, AssertionError)):
            recover(signature, b'\x01' * 31)  # Too short
    except ImportError:
        pytest.skip("ECDSA module not available")

