"""
Test ECDSA signature serialization functions in bsv/utils.py
"""

import pytest
from bsv.utils import (
    deserialize_ecdsa_der, serialize_ecdsa_der,
    deserialize_ecdsa_recoverable, serialize_ecdsa_recoverable,
    stringify_ecdsa_recoverable, unstringify_ecdsa_recoverable
)
from bsv.constants import NUMBER_BYTE_LENGTH


class TestECDSADER:
    """Test ECDSA DER serialization and deserialization."""
    
    def test_serialize_ecdsa_der_simple(self):
        """Test serializing a simple ECDSA signature to DER."""
        r = 0x123456789abcdef
        s = 0x987654321fedcba
        signature = (r, s)
        
        der = serialize_ecdsa_der(signature)
        assert isinstance(der, bytes)
        assert der[0] == 0x30  # DER sequence tag
        assert der[2] == 0x02  # Integer tag for r
    
    def test_deserialize_ecdsa_der_simple(self):
        """Test deserializing a simple DER signature."""
        # Create a simple DER signature
        signature = (0x123456789abcdef, 0x987654321fedcba)
        der = serialize_ecdsa_der(signature)
        
        r, s = deserialize_ecdsa_der(der)
        assert isinstance(r, int)
        assert isinstance(s, int)
        assert r > 0
        assert s > 0
    
    def test_ecdsa_der_round_trip(self):
        """Test DER encoding and decoding round trip."""
        original_r = 0x123456789abcdef0123456789abcdef
        original_s = 0xfedcba9876543210fedcba987654321
        original = (original_r, original_s)
        
        # Serialize to DER
        der = serialize_ecdsa_der(original)
        
        # Deserialize back
        r, s = deserialize_ecdsa_der(der)
        
        # Note: high s values are normalized to low s
        assert r == original_r
        # s might be normalized (flipped if > n/2)
        assert s <= original_s
    
    def test_serialize_ecdsa_der_high_s_normalized(self):
        """Test that high S values are normalized to low S."""
        from bsv.curve import curve
        
        r = 12345
        s_high = curve.n - 1  # Very high S value
        signature = (r, s_high)
        
        der = serialize_ecdsa_der(signature)
        r_decoded, s_decoded = deserialize_ecdsa_der(der)
        
        assert r_decoded == r
        # High S should be flipped to low S
        assert s_decoded == 1  # curve.n - s_high
    
    def test_serialize_ecdsa_der_leading_zero_padding(self):
        """Test that high bit causes leading zero padding."""
        # Value with high bit set requires padding
        r = 0x80000000
        s = 0x70000000
        signature = (r, s)
        
        der = serialize_ecdsa_der(signature)
        
        # Check that r is padded (high bit set)
        r_start = 4  # After 0x30 <len> 0x02 <r_len>
        assert der[r_start] == 0x00  # Padding byte
    
    def test_deserialize_ecdsa_der_invalid_tag_raises(self):
        """Test that invalid sequence tag raises ValueError."""
        invalid_der = b'\x31\x06\x02\x01\x01\x02\x01\x01'  # Wrong tag 0x31
        with pytest.raises(ValueError, match="invalid DER"):
            deserialize_ecdsa_der(invalid_der)
    
    def test_deserialize_ecdsa_der_invalid_length_raises(self):
        """Test that invalid length raises ValueError."""
        invalid_der = b'\x30\xFF\x02\x01\x01\x02\x01\x01'  # Wrong length
        with pytest.raises(ValueError, match="invalid DER"):
            deserialize_ecdsa_der(invalid_der)
    
    def test_deserialize_ecdsa_der_truncated_raises(self):
        """Test that truncated DER raises ValueError."""
        invalid_der = b'\x30\x06\x02\x01'  # Incomplete
        with pytest.raises(ValueError, match="invalid DER"):
            deserialize_ecdsa_der(invalid_der)
    
    def test_deserialize_ecdsa_der_empty_raises(self):
        """Test that empty bytes raises ValueError."""
        with pytest.raises(ValueError, match="invalid DER"):
            deserialize_ecdsa_der(b'')
    
    @pytest.mark.parametrize("r,s", [
        (1, 1),
        (100, 200),
        (2**32, 2**32),
        (2**128, 2**128),
    ])
    def test_ecdsa_der_various_values(self, r, s):
        """Test DER encoding with various r,s values."""
        signature = (r, s)
        der = serialize_ecdsa_der(signature)
        r_decoded, _ = deserialize_ecdsa_der(der)
        
        assert r_decoded == r


class TestECDSARecoverable:
    """Test recoverable ECDSA signature serialization."""
    
    def test_serialize_recoverable_simple(self):
        """Test serializing recoverable signature."""
        r = 12345
        s = 67890
        rec_id = 0
        signature = (r, s, rec_id)
        
        serialized = serialize_ecdsa_recoverable(signature)
        assert isinstance(serialized, bytes)
        assert len(serialized) == 65  # 32 + 32 + 1
    
    def test_deserialize_recoverable_simple(self):
        """Test deserializing recoverable signature."""
        # Create 65-byte signature
        r_bytes = b'\x00' * NUMBER_BYTE_LENGTH
        s_bytes = b'\x01' * NUMBER_BYTE_LENGTH
        rec_id_byte = b'\x00'
        signature_bytes = r_bytes + s_bytes + rec_id_byte
        
        r, s, rec_id = deserialize_ecdsa_recoverable(signature_bytes)
        assert r == 0
        assert s == int.from_bytes(s_bytes, 'big')
        assert rec_id == 0
    
    def test_recoverable_round_trip(self):
        """Test recoverable signature encoding and decoding round trip."""
        original_r = 123456789
        original_s = 987654321
        original_rec_id = 1
        original = (original_r, original_s, original_rec_id)
        
        serialized = serialize_ecdsa_recoverable(original)
        r, s, rec_id = deserialize_ecdsa_recoverable(serialized)
        
        assert r == original_r
        assert s == original_s
        assert rec_id == original_rec_id
    
    @pytest.mark.parametrize("rec_id", [0, 1, 2, 3])
    def test_serialize_recoverable_valid_rec_ids(self, rec_id):
        """Test that all valid recovery IDs (0-3) work."""
        signature = (12345, 67890, rec_id)
        serialized = serialize_ecdsa_recoverable(signature)
        
        _, _, decoded_rec_id = deserialize_ecdsa_recoverable(serialized)
        assert decoded_rec_id == rec_id
    
    def test_serialize_recoverable_invalid_rec_id_raises(self):
        """Test that invalid recovery ID raises AssertionError."""
        signature = (12345, 67890, 4)  # Invalid: must be 0-3
        with pytest.raises(AssertionError, match="invalid recovery id"):
            serialize_ecdsa_recoverable(signature)
    
    def test_serialize_recoverable_negative_rec_id_raises(self):
        """Test that negative recovery ID raises AssertionError."""
        signature = (12345, 67890, -1)
        with pytest.raises(AssertionError, match="invalid recovery id"):
            serialize_ecdsa_recoverable(signature)
    
    def test_deserialize_recoverable_invalid_length_raises(self):
        """Test that wrong length raises AssertionError."""
        with pytest.raises(AssertionError, match="invalid length"):
            deserialize_ecdsa_recoverable(b'\x00' * 64)  # Too short
    
    def test_deserialize_recoverable_too_long_raises(self):
        """Test that too long signature raises AssertionError."""
        with pytest.raises(AssertionError, match="invalid length"):
            deserialize_ecdsa_recoverable(b'\x00' * 66)
    
    def test_deserialize_recoverable_invalid_rec_id_raises(self):
        """Test that invalid recovery ID in data raises AssertionError."""
        invalid_sig = b'\x00' * 64 + b'\x04'  # rec_id = 4 (invalid)
        with pytest.raises(AssertionError, match="invalid recovery id"):
            deserialize_ecdsa_recoverable(invalid_sig)
    
    def test_serialize_recoverable_large_values(self):
        """Test serializing large r and s values."""
        r = 2**255
        s = 2**255 - 1
        rec_id = 2
        signature = (r, s, rec_id)
        
        serialized = serialize_ecdsa_recoverable(signature)
        assert len(serialized) == 65
        
        r_decoded, s_decoded, rec_id_decoded = deserialize_ecdsa_recoverable(serialized)
        assert r_decoded == r
        assert s_decoded == s
        assert rec_id_decoded == rec_id


class TestStringifyRecoverable:
    """Test stringify and unstringify recoverable signatures."""
    
    def test_stringify_recoverable_compressed(self):
        """Test stringifying with compressed flag."""
        # Create a simple recoverable signature
        signature = serialize_ecdsa_recoverable((12345, 67890, 1))
        
        stringified = stringify_ecdsa_recoverable(signature, compressed=True)
        assert isinstance(stringified, str)
        # Check it's valid base64
        import base64
        decoded = base64.b64decode(stringified)
        assert len(decoded) == 65
    
    def test_stringify_recoverable_uncompressed(self):
        """Test stringifying with uncompressed flag."""
        signature = serialize_ecdsa_recoverable((12345, 67890, 1))
        
        stringified = stringify_ecdsa_recoverable(signature, compressed=False)
        assert isinstance(stringified, str)
        import base64
        decoded = base64.b64decode(stringified)
        assert len(decoded) == 65
    
    def test_unstringify_recoverable_compressed(self):
        """Test unstringifying compressed signature."""
        original_sig = serialize_ecdsa_recoverable((12345, 67890, 1))
        stringified = stringify_ecdsa_recoverable(original_sig, compressed=True)
        
        unstringified, compressed = unstringify_ecdsa_recoverable(stringified)
        assert isinstance(unstringified, bytes)
        assert len(unstringified) == 65
        assert compressed is True
    
    def test_unstringify_recoverable_uncompressed(self):
        """Test unstringifying uncompressed signature."""
        original_sig = serialize_ecdsa_recoverable((12345, 67890, 1))
        stringified = stringify_ecdsa_recoverable(original_sig, compressed=False)
        
        unstringified, compressed = unstringify_ecdsa_recoverable(stringified)
        assert isinstance(unstringified, bytes)
        assert len(unstringified) == 65
        assert compressed is False
    
    def test_stringify_unstringify_round_trip_compressed(self):
        """Test round trip for compressed signature."""
        original_sig = serialize_ecdsa_recoverable((99999, 88888, 2))
        stringified = stringify_ecdsa_recoverable(original_sig, compressed=True)
        unstringified, compressed = unstringify_ecdsa_recoverable(stringified)
        
        assert compressed is True
        # Compare the signature data (excluding the added prefix)
        r_orig, s_orig, rec_orig = deserialize_ecdsa_recoverable(original_sig)
        r_new, s_new, rec_new = deserialize_ecdsa_recoverable(unstringified)
        
        assert r_orig == r_new
        assert s_orig == s_new
        assert rec_orig == rec_new
    
    def test_stringify_unstringify_round_trip_uncompressed(self):
        """Test round trip for uncompressed signature."""
        original_sig = serialize_ecdsa_recoverable((99999, 88888, 2))
        stringified = stringify_ecdsa_recoverable(original_sig, compressed=False)
        unstringified, compressed = unstringify_ecdsa_recoverable(stringified)
        
        assert compressed is False
        r_orig, s_orig, rec_orig = deserialize_ecdsa_recoverable(original_sig)
        r_new, s_new, rec_new = deserialize_ecdsa_recoverable(unstringified)
        
        assert r_orig == r_new
        assert s_orig == s_new
        assert rec_orig == rec_new
    
    def test_unstringify_invalid_length_raises(self):
        """Test that invalid length base64 raises AssertionError."""
        import base64
        invalid_b64 = base64.b64encode(b'\x00' * 64).decode('ascii')  # Too short
        with pytest.raises(AssertionError, match="invalid length"):
            unstringify_ecdsa_recoverable(invalid_b64)
    
    def test_unstringify_invalid_prefix_raises(self):
        """Test that invalid prefix raises AssertionError."""
        import base64
        # Create signature with invalid prefix (< 27 or >= 35)
        invalid_sig = b'\x00' + b'\x00' * 64
        invalid_b64 = base64.b64encode(invalid_sig).decode('ascii')
        with pytest.raises(AssertionError, match="invalid recoverable ECDSA signature prefix"):
            unstringify_ecdsa_recoverable(invalid_b64)
    
    def test_unstringify_invalid_base64_raises(self):
        """Test that invalid base64 raises exception."""
        with pytest.raises(Exception):
            unstringify_ecdsa_recoverable("not-valid-base64!!!")
    
    @pytest.mark.parametrize("rec_id", [0, 1, 2, 3])
    @pytest.mark.parametrize("compressed", [True, False])
    def test_stringify_recovery_id_preservation(self, rec_id, compressed):
        """Test that recovery ID is preserved through stringify/unstringify."""
        original_sig = serialize_ecdsa_recoverable((12345, 67890, rec_id))
        stringified = stringify_ecdsa_recoverable(original_sig, compressed=compressed)
        unstringified, comp_flag = unstringify_ecdsa_recoverable(stringified)
        
        _, _, recovered_rec_id = deserialize_ecdsa_recoverable(unstringified)
        assert recovered_rec_id == rec_id
        assert comp_flag == compressed

