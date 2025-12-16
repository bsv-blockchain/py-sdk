"""
Comprehensive tests for bsv/wallet/serializer/relinquish_certificate.py

Tests serialization and deserialization of relinquish_certificate operations.
"""

import pytest
from bsv.wallet.serializer.relinquish_certificate import (
    serialize_relinquish_certificate_args,
    deserialize_relinquish_certificate_args,
    serialize_relinquish_certificate_result,
    deserialize_relinquish_certificate_result,
)


class TestSerializeRelinquishCertificateArgs:
    """Test serialize_relinquish_certificate_args function."""
    
    def test_serialize_minimal_args(self):
        """Test serializing minimal arguments."""
        args = {}
        result = serialize_relinquish_certificate_args(args)
        assert isinstance(result, bytes)
        assert len(result) == 0  # Empty dict produces 0 bytes
    
    def test_serialize_with_type(self):
        """Test serializing with type."""
        args = {"type": b"\x01" * 32}
        result = serialize_relinquish_certificate_args(args)
        assert isinstance(result, bytes)
        assert len(result) == 32  # Only type field, no padding
    
    def test_serialize_with_serial_number(self):
        """Test serializing with serialNumber."""
        args = {"serialNumber": b"\x02" * 32}
        result = serialize_relinquish_certificate_args(args)
        assert isinstance(result, bytes)
        assert len(result) == 32  # Only serialNumber field, no padding
    
    def test_serialize_with_certifier(self):
        """Test serializing with certifier."""
        args = {"certifier": b"\x03" * 33}
        result = serialize_relinquish_certificate_args(args)
        assert isinstance(result, bytes)
        assert len(result) == 33  # Only certifier field, no padding
    
    def test_serialize_with_all_fields(self):
        """Test serializing with all fields."""
        args = {
            "type": b"\x01" * 32,
            "serialNumber": b"\x02" * 32,
            "certifier": b"\x03" * 33
        }
        result = serialize_relinquish_certificate_args(args)
        assert isinstance(result, bytes)
        assert len(result) == 97
    
    def test_serialize_with_partial_fields(self):
        """Test serializing with partial fields."""
        args = {
            "type": b"\xAA" * 32,
            "serialNumber": b"\xBB" * 32
        }
        result = serialize_relinquish_certificate_args(args)
        assert isinstance(result, bytes)
        assert len(result) == 64  # type (32) + serialNumber (32) = 64 bytes


class TestDeserializeRelinquishCertificateArgs:
    """Test deserialize_relinquish_certificate_args function."""
    
    def test_deserialize_minimal(self):
        """Test deserializing minimal data."""
        args = {
            "type": b"\x00" * 32,
            "serialNumber": b"\x00" * 32,
            "certifier": b"\x00" * 33
        }
        serialized = serialize_relinquish_certificate_args(args)
        deserialized = deserialize_relinquish_certificate_args(serialized)
        
        assert "type" in deserialized
        assert "serialNumber" in deserialized
        assert "certifier" in deserialized
        assert len(deserialized["type"]) == 32
        assert len(deserialized["serialNumber"]) == 32
        assert len(deserialized["certifier"]) == 33
    
    def test_deserialize_with_all_fields(self):
        """Test deserializing with all fields."""
        type_bytes = b"\x11" * 32
        serial_bytes = b"\x22" * 32
        certifier_bytes = b"\x33" * 33
        
        args = {
            "type": type_bytes,
            "serialNumber": serial_bytes,
            "certifier": certifier_bytes
        }
        serialized = serialize_relinquish_certificate_args(args)
        deserialized = deserialize_relinquish_certificate_args(serialized)
        
        assert deserialized["type"] == type_bytes
        assert deserialized["serialNumber"] == serial_bytes
        assert deserialized["certifier"] == certifier_bytes
    
    def test_deserialize_preserves_values(self):
        """Test that values are preserved correctly."""
        args = {
            "type": b"\xFF" * 32,
            "serialNumber": b"\xAA" * 32,
            "certifier": b"\xBB" * 33
        }
        serialized = serialize_relinquish_certificate_args(args)
        deserialized = deserialize_relinquish_certificate_args(serialized)
        
        assert deserialized["type"] == b"\xFF" * 32
        assert deserialized["serialNumber"] == b"\xAA" * 32
        assert deserialized["certifier"] == b"\xBB" * 33


class TestRelinquishCertificateRoundTrip:
    """Test round-trip serialization/deserialization."""
    
    @pytest.mark.parametrize("type_val,serial_val,certifier_val", [
        (b"\x00" * 32, b"\x00" * 32, b"\x00" * 33),
        (b"\xFF" * 32, b"\xFF" * 32, b"\xFF" * 33),
        (b"\x12" * 32, b"\x34" * 32, b"\x56" * 33),
        (b"\xAB" * 32, b"\xCD" * 32, b"\xEF" * 33),
    ])
    def test_round_trip_various_inputs(self, type_val, serial_val, certifier_val):
        """Test round trip with various input combinations."""
        args = {
            "type": type_val,
            "serialNumber": serial_val,
            "certifier": certifier_val
        }
        
        serialized = serialize_relinquish_certificate_args(args)
        deserialized = deserialize_relinquish_certificate_args(serialized)
        
        assert deserialized["type"] == type_val
        assert deserialized["serialNumber"] == serial_val
        assert deserialized["certifier"] == certifier_val
    
    def test_round_trip_with_defaults(self):
        """Test round trip with default empty values."""
        # For round-trip testing, we need complete args since deserializer expects exactly 97 bytes
        args = {
            "type": b"\x00" * 32,  # 32 bytes of zeros
            "serialNumber": b"\x00" * 32,  # 32 bytes of zeros
            "certifier": b"\x00" * 33  # 33 bytes of zeros
        }
        serialized = serialize_relinquish_certificate_args(args)
        deserialized = deserialize_relinquish_certificate_args(serialized)

        # After round-trip, we get back the zero-filled bytes we serialized
        assert deserialized["type"] == b"\x00" * 32
        assert deserialized["serialNumber"] == b"\x00" * 32
        assert deserialized["certifier"] == b"\x00" * 33


class TestSerializeRelinquishCertificateResult:
    """Test serialize_relinquish_certificate_result function."""
    
    def test_serialize_result_returns_empty(self):
        """Test that serialize result returns empty bytes."""
        result = serialize_relinquish_certificate_result({})
        assert result == b""
    
    def test_serialize_result_with_data_returns_empty(self):
        """Test that serialize result ignores input and returns empty."""
        result = serialize_relinquish_certificate_result({"key": "value"})
        assert result == b""
    
    def test_serialize_result_with_none_returns_empty(self):
        """Test that serialize result handles None input."""
        result = serialize_relinquish_certificate_result(None)
        assert result == b""


class TestDeserializeRelinquishCertificateResult:
    """Test deserialize_relinquish_certificate_result function."""
    
    def test_deserialize_result_returns_empty_dict(self):
        """Test that deserialize result returns empty dict."""
        result = deserialize_relinquish_certificate_result(b"")
        assert result == {}
    
    def test_deserialize_result_with_data_returns_empty_dict(self):
        """Test that deserialize result ignores input and returns empty dict."""
        result = deserialize_relinquish_certificate_result(b"some_data")
        assert result == {}
    
    def test_deserialize_result_with_none_returns_empty_dict(self):
        """Test that deserialize result handles None input."""
        from typing import cast, Any
        result = deserialize_relinquish_certificate_result(cast(Any, None))
        assert result == {}


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_serialize_missing_keys_uses_defaults(self):
        """Test serializing when keys are missing uses defaults."""
        args = {}
        result = serialize_relinquish_certificate_args(args)
        assert isinstance(result, bytes)
        assert len(result) == 0  # Empty dict produces 0 bytes

        # Cannot deserialize 0 bytes as deserializer expects exactly 97 bytes
        # This test verifies that missing keys result in empty serialization
    
    def test_serialize_with_partial_keys(self):
        """Test serializing with only some keys."""
        args = {"type": b"\x11" * 32}
        result = serialize_relinquish_certificate_args(args)
        assert isinstance(result, bytes)
        assert len(result) == 32  # Only type field

        # Cannot do round-trip with partial args since deserializer expects exactly 97 bytes
    
    def test_multiple_serializations_same_data(self):
        """Test that multiple serializations produce same result."""
        args = {
            "type": b"\xAB" * 32,
            "serialNumber": b"\xCD" * 32,
            "certifier": b"\xEF" * 33
        }
        
        result1 = serialize_relinquish_certificate_args(args)
        result2 = serialize_relinquish_certificate_args(args)
        
        assert result1 == result2
    
    def test_deserialize_exact_length(self):
        """Test that deserialization requires exact length."""
        # Create data with exact expected length
        args = {
            "type": b"\x01" * 32,
            "serialNumber": b"\x02" * 32,
            "certifier": b"\x03" * 33
        }
        serialized = serialize_relinquish_certificate_args(args)
        assert len(serialized) == 97
        
        deserialized = deserialize_relinquish_certificate_args(serialized)
        assert len(deserialized["type"]) == 32
        assert len(deserialized["serialNumber"]) == 32
        assert len(deserialized["certifier"]) == 33

