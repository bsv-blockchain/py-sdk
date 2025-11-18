"""
Comprehensive tests for bsv/wallet/serializer/relinquish_output.py

Tests serialization and deserialization of relinquish_output operations.
"""

import pytest
from bsv.wallet.serializer.relinquish_output import (
    serialize_relinquish_output_args,
    deserialize_relinquish_output_args,
    serialize_relinquish_output_result,
    deserialize_relinquish_output_result,
)


class TestSerializeRelinquishOutputArgs:
    """Test serialize_relinquish_output_args function."""
    
    def test_serialize_minimal_args(self):
        """Test serializing minimal arguments."""
        args = {}
        result = serialize_relinquish_output_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 0
    
    def test_serialize_with_basket(self):
        """Test serializing with basket."""
        args = {"basket": "default"}
        result = serialize_relinquish_output_args(args)
        assert isinstance(result, bytes)
        assert b"default" in result
    
    def test_serialize_with_empty_basket(self):
        """Test serializing with empty basket."""
        args = {"basket": ""}
        result = serialize_relinquish_output_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_outpoint(self):
        """Test serializing with output/outpoint."""
        args = {
            "basket": "test",
            "output": {
                "txid": b"\x01" * 32,
                "index": 0
            }
        }
        result = serialize_relinquish_output_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 32  # At least txid + index
    
    def test_serialize_with_outpoint_non_zero_index(self):
        """Test serializing with non-zero index."""
        args = {
            "basket": "basket",
            "output": {
                "txid": b"\xFF" * 32,
                "index": 5
            }
        }
        result = serialize_relinquish_output_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_long_basket_name(self):
        """Test serializing with long basket name."""
        args = {
            "basket": "very_long_basket_name_" * 10,
            "output": {
                "txid": b"\x00" * 32,
                "index": 0
            }
        }
        result = serialize_relinquish_output_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_large_index(self):
        """Test serializing with large output index."""
        args = {
            "basket": "test",
            "output": {
                "txid": b"\xAB" * 32,
                "index": 999999
            }
        }
        result = serialize_relinquish_output_args(args)
        assert isinstance(result, bytes)


class TestDeserializeRelinquishOutputArgs:
    """Test deserialize_relinquish_output_args function."""
    
    def test_deserialize_minimal(self):
        """Test deserializing minimal data."""
        args = {"basket": "", "output": {"txid": b"\x00" * 32, "index": 0}}
        serialized = serialize_relinquish_output_args(args)
        deserialized = deserialize_relinquish_output_args(serialized)
        
        assert "basket" in deserialized
        assert "output" in deserialized
        assert "txid" in deserialized["output"]
        assert "index" in deserialized["output"]
    
    def test_deserialize_with_basket(self):
        """Test deserializing with basket."""
        args = {"basket": "test_basket"}
        serialized = serialize_relinquish_output_args(args)
        deserialized = deserialize_relinquish_output_args(serialized)
        
        assert deserialized["basket"] == "test_basket"
    
    def test_deserialize_with_outpoint(self):
        """Test deserializing with outpoint."""
        txid = b"\x12" * 32
        args = {
            "basket": "basket",
            "output": {"txid": txid, "index": 3}
        }
        serialized = serialize_relinquish_output_args(args)
        deserialized = deserialize_relinquish_output_args(serialized)
        
        assert deserialized["output"]["txid"] == txid
        assert deserialized["output"]["index"] == 3
    
    def test_deserialize_preserves_basket_name(self):
        """Test that basket name is preserved."""
        args = {"basket": "my_custom_basket"}
        serialized = serialize_relinquish_output_args(args)
        deserialized = deserialize_relinquish_output_args(serialized)
        
        assert deserialized["basket"] == "my_custom_basket"


class TestRelinquishOutputRoundTrip:
    """Test round-trip serialization/deserialization."""
    
    @pytest.mark.parametrize("basket,txid,index", [
        ("", b"\x00" * 32, 0),
        ("default", b"\xFF" * 32, 1),
        ("custom", b"\x12\x34" * 16, 100),
        ("test_basket", b"\xAB\xCD" * 16, 255),
    ])
    def test_round_trip_various_inputs(self, basket, txid, index):
        """Test round trip with various input combinations."""
        args = {
            "basket": basket,
            "output": {"txid": txid, "index": index}
        }
        
        serialized = serialize_relinquish_output_args(args)
        deserialized = deserialize_relinquish_output_args(serialized)
        
        assert deserialized["basket"] == basket
        assert deserialized["output"]["txid"] == txid
        assert deserialized["output"]["index"] == index
    
    def test_round_trip_empty_basket(self):
        """Test round trip with empty basket."""
        args = {
            "basket": "",
            "output": {"txid": b"\x00" * 32, "index": 0}
        }
        
        serialized = serialize_relinquish_output_args(args)
        deserialized = deserialize_relinquish_output_args(serialized)
        
        assert deserialized["basket"] == ""
    
    def test_round_trip_unicode_basket(self):
        """Test round trip with unicode basket name."""
        args = {
            "basket": "basket_世界",
            "output": {"txid": b"\x11" * 32, "index": 0}
        }
        
        serialized = serialize_relinquish_output_args(args)
        deserialized = deserialize_relinquish_output_args(serialized)
        
        assert deserialized["basket"] == "basket_世界"
    
    def test_round_trip_large_index(self):
        """Test round trip with large index value."""
        args = {
            "basket": "test",
            "output": {"txid": b"\xFF" * 32, "index": 0xFFFFFFFF}
        }
        
        serialized = serialize_relinquish_output_args(args)
        deserialized = deserialize_relinquish_output_args(serialized)
        
        assert deserialized["output"]["index"] == 0xFFFFFFFF


class TestSerializeRelinquishOutputResult:
    """Test serialize_relinquish_output_result function."""
    
    def test_serialize_result_returns_empty(self):
        """Test that serialize result returns empty bytes."""
        result = serialize_relinquish_output_result({})
        assert result == b""
    
    def test_serialize_result_with_data_returns_empty(self):
        """Test that serialize result ignores input and returns empty."""
        result = serialize_relinquish_output_result({"key": "value"})
        assert result == b""
    
    def test_serialize_result_with_none_returns_empty(self):
        """Test that serialize result handles None input."""
        result = serialize_relinquish_output_result(None)
        assert result == b""


class TestDeserializeRelinquishOutputResult:
    """Test deserialize_relinquish_output_result function."""
    
    def test_deserialize_result_returns_empty_dict(self):
        """Test that deserialize result returns empty dict."""
        result = deserialize_relinquish_output_result(b"")
        assert result == {}
    
    def test_deserialize_result_with_data_returns_empty_dict(self):
        """Test that deserialize result ignores input and returns empty dict."""
        result = deserialize_relinquish_output_result(b"some_data")
        assert result == {}
    
    def test_deserialize_result_with_none_returns_empty_dict(self):
        """Test that deserialize result handles None input."""
        result = deserialize_relinquish_output_result(None)
        assert result == {}


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_serialize_missing_output_key(self):
        """Test serializing when output key is missing."""
        args = {"basket": "test"}
        # Should handle missing 'output' key gracefully
        result = serialize_relinquish_output_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_special_characters_in_basket(self):
        """Test serializing basket name with special characters."""
        args = {
            "basket": "test@#$%^&*()",
            "output": {"txid": b"\x00" * 32, "index": 0}
        }
        result = serialize_relinquish_output_args(args)
        assert isinstance(result, bytes)
        
        deserialized = deserialize_relinquish_output_args(result)
        assert deserialized["basket"] == "test@#$%^&*()"
    
    def test_serialize_with_whitespace_in_basket(self):
        """Test serializing basket name with whitespace."""
        args = {
            "basket": "  spaces  around  ",
            "output": {"txid": b"\x00" * 32, "index": 0}
        }
        result = serialize_relinquish_output_args(args)
        deserialized = deserialize_relinquish_output_args(result)
        
        assert deserialized["basket"] == "  spaces  around  "
    
    def test_multiple_serializations_same_data(self):
        """Test that multiple serializations produce same result."""
        args = {
            "basket": "consistent",
            "output": {"txid": b"\xAB" * 32, "index": 42}
        }
        
        result1 = serialize_relinquish_output_args(args)
        result2 = serialize_relinquish_output_args(args)
        
        assert result1 == result2

