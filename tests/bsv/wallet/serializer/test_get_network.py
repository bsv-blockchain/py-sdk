"""
Comprehensive tests for bsv/wallet/serializer/get_network.py

Tests serialization and deserialization of network information operations.
"""

import pytest
from bsv.wallet.serializer.get_network import (
    serialize_get_network_args,
    deserialize_get_network_result,
    serialize_get_network_result,
    serialize_get_version_args,
    deserialize_get_version_result,
    serialize_get_version_result,
    serialize_get_height_args,
    deserialize_get_height_result,
    serialize_get_height_result,
    serialize_get_header_args,
    deserialize_get_header_args,
    deserialize_get_header_result,
    serialize_get_header_result,
)


class TestGetNetworkSerialization:
    """Test get_network serialization functions."""
    
    def test_serialize_get_network_args_empty(self):
        """Test that serialize args returns empty bytes."""
        result = serialize_get_network_args({})
        assert result == b""
    
    def test_serialize_get_network_args_none(self):
        """Test serialize args with None."""
        result = serialize_get_network_args(None)
        assert result == b""
    
    def test_serialize_get_network_args_with_data(self):
        """Test serialize args ignores input data."""
        result = serialize_get_network_args({"key": "value"})
        assert result == b""
    
    def test_deserialize_network_result_mainnet(self):
        """Test deserializing mainnet result."""
        result_data = {"network": "mainnet"}
        serialized = serialize_get_network_result(result_data)
        deserialized = deserialize_get_network_result(serialized)
        
        assert deserialized["network"] == "mainnet"
    
    def test_deserialize_network_result_testnet(self):
        """Test deserializing testnet result."""
        result_data = {"network": "testnet"}
        serialized = serialize_get_network_result(result_data)
        deserialized = deserialize_get_network_result(serialized)
        
        assert deserialized["network"] == "testnet"
    
    def test_deserialize_network_result_empty(self):
        """Test deserializing empty result."""
        deserialized = deserialize_get_network_result(b"")
        assert deserialized["network"] == ""
    
    def test_serialize_network_result_empty(self):
        """Test serializing empty network result."""
        result = serialize_get_network_result({})
        assert isinstance(result, bytes)
    
    def test_serialize_network_result_missing_key(self):
        """Test serializing when network key is missing."""
        result = serialize_get_network_result({"other": "value"})
        deserialized = deserialize_get_network_result(result)
        assert deserialized["network"] == ""
    
    def test_network_round_trip(self):
        """Test network result round trip."""
        for network in ["mainnet", "testnet", "regtest", "stn"]:
            result_data = {"network": network}
            serialized = serialize_get_network_result(result_data)
            deserialized = deserialize_get_network_result(serialized)
            assert deserialized["network"] == network


class TestGetVersionSerialization:
    """Test get_version serialization functions."""
    
    def test_serialize_get_version_args_empty(self):
        """Test that serialize version args returns empty bytes."""
        result = serialize_get_version_args({})
        assert result == b""
    
    def test_serialize_get_version_args_none(self):
        """Test serialize version args with None."""
        result = serialize_get_version_args(None)
        assert result == b""
    
    def test_deserialize_version_result(self):
        """Test deserializing version result."""
        result_data = {"version": "1.0.0"}
        serialized = serialize_get_version_result(result_data)
        deserialized = deserialize_get_version_result(serialized)
        
        assert deserialized["version"] == "1.0.0"
    
    def test_deserialize_version_result_empty(self):
        """Test deserializing empty version result."""
        deserialized = deserialize_get_version_result(b"")
        assert deserialized["version"] == ""
    
    def test_serialize_version_result_empty(self):
        """Test serializing empty version result."""
        result = serialize_get_version_result({})
        assert isinstance(result, bytes)
    
    def test_version_round_trip(self):
        """Test version result round trip."""
        for version in ["1.0.0", "2.1.3", "0.9.9-beta", "1.2.3-rc1"]:
            result_data = {"version": version}
            serialized = serialize_get_version_result(result_data)
            deserialized = deserialize_get_version_result(serialized)
            assert deserialized["version"] == version


class TestGetHeightSerialization:
    """Test get_height serialization functions."""
    
    def test_serialize_get_height_args_empty(self):
        """Test that serialize height args returns empty bytes."""
        result = serialize_get_height_args({})
        assert result == b""
    
    def test_serialize_get_height_args_none(self):
        """Test serialize height args with None."""
        result = serialize_get_height_args(None)
        assert result == b""
    
    def test_deserialize_height_result_zero(self):
        """Test deserializing height result with zero."""
        result_data = {"height": 0}
        serialized = serialize_get_height_result(result_data)
        deserialized = deserialize_get_height_result(serialized)
        
        assert deserialized["height"] == 0
    
    def test_deserialize_height_result_positive(self):
        """Test deserializing height result with positive number."""
        result_data = {"height": 123456}
        serialized = serialize_get_height_result(result_data)
        deserialized = deserialize_get_height_result(serialized)
        
        assert deserialized["height"] == 123456
    
    def test_deserialize_height_result_empty(self):
        """Test deserializing empty height result."""
        deserialized = deserialize_get_height_result(b"")
        assert deserialized["height"] == 0
    
    def test_serialize_height_result_empty(self):
        """Test serializing empty height result."""
        result = serialize_get_height_result({})
        assert isinstance(result, bytes)
    
    def test_height_round_trip(self):
        """Test height result round trip."""
        for height in [0, 1, 100, 1000, 100000, 1000000, 0xFFFFFFFF]:
            result_data = {"height": height}
            serialized = serialize_get_height_result(result_data)
            deserialized = deserialize_get_height_result(serialized)
            assert deserialized["height"] == height


class TestGetHeaderSerialization:
    """Test get_header serialization functions."""
    
    def test_serialize_get_header_args_zero(self):
        """Test serializing header args with zero height."""
        args = {"height": 0}
        result = serialize_get_header_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_get_header_args_positive(self):
        """Test serializing header args with positive height."""
        args = {"height": 12345}
        result = serialize_get_header_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 0
    
    def test_serialize_get_header_args_empty(self):
        """Test serializing header args with empty dict."""
        args = {}
        result = serialize_get_header_args(args)
        assert isinstance(result, bytes)
    
    def test_deserialize_get_header_args(self):
        """Test deserializing header args."""
        args = {"height": 5000}
        serialized = serialize_get_header_args(args)
        deserialized = deserialize_get_header_args(serialized)
        
        assert deserialized["height"] == 5000
    
    def test_deserialize_get_header_args_empty(self):
        """Test deserializing empty header args."""
        deserialized = deserialize_get_header_args(b"")
        assert deserialized["height"] == 0
    
    def test_header_args_round_trip(self):
        """Test header args round trip."""
        for height in [0, 1, 100, 10000, 1000000]:
            args = {"height": height}
            serialized = serialize_get_header_args(args)
            deserialized = deserialize_get_header_args(serialized)
            assert deserialized["height"] == height
    
    def test_deserialize_header_result_empty(self):
        """Test deserializing empty header result."""
        # Empty data would cause EOFError when reading varint
        # Need to serialize an empty header properly
        result_data = {"header": b""}
        serialized = serialize_get_header_result(result_data)
        deserialized = deserialize_get_header_result(serialized)
        assert deserialized["header"] == b""
    
    def test_deserialize_header_result_with_data(self):
        """Test deserializing header result with data."""
        header_data = b"\x01\x02\x03\x04" * 20  # 80 bytes (typical block header)
        result_data = {"header": header_data}
        serialized = serialize_get_header_result(result_data)
        deserialized = deserialize_get_header_result(serialized)
        
        assert deserialized["header"] == header_data
    
    def test_serialize_header_result_empty(self):
        """Test serializing empty header result."""
        result = serialize_get_header_result({})
        assert isinstance(result, bytes)
    
    def test_header_result_round_trip(self):
        """Test header result round trip."""
        header_data = b"\xAB\xCD\xEF" * 27  # 81 bytes
        result_data = {"header": header_data}
        serialized = serialize_get_header_result(result_data)
        deserialized = deserialize_get_header_result(serialized)
        
        assert deserialized["header"] == header_data


class TestEdgeCasesAndErrors:
    """Test edge cases and error handling."""
    
    def test_serialize_network_result_with_none_value(self):
        """Test serializing network result with None value."""
        result_data = {"network": None}
        serialized = serialize_get_network_result(result_data)
        assert isinstance(serialized, bytes)
    
    def test_serialize_version_result_with_integer(self):
        """Test serializing version result with integer."""
        result_data = {"version": 123}
        serialized = serialize_get_version_result(result_data)
        deserialized = deserialize_get_version_result(serialized)
        
        assert deserialized["version"] == "123"
    
    def test_serialize_height_result_with_string(self):
        """Test serializing height result with string."""
        result_data = {"height": "999"}
        serialized = serialize_get_height_result(result_data)
        deserialized = deserialize_get_height_result(serialized)
        
        assert deserialized["height"] == 999
    
    def test_serialize_header_args_with_string_height(self):
        """Test serializing header args with string height."""
        args = {"height": "100"}
        serialized = serialize_get_header_args(args)
        deserialized = deserialize_get_header_args(serialized)
        
        assert deserialized["height"] == 100
    
    def test_network_result_with_unicode(self):
        """Test network result with unicode characters."""
        result_data = {"network": "test_网络"}
        serialized = serialize_get_network_result(result_data)
        deserialized = deserialize_get_network_result(serialized)
        
        assert deserialized["network"] == "test_网络"
    
    def test_version_result_with_special_chars(self):
        """Test version result with special characters."""
        result_data = {"version": "1.0.0-alpha+build.123"}
        serialized = serialize_get_version_result(result_data)
        deserialized = deserialize_get_version_result(serialized)
        
        assert deserialized["version"] == "1.0.0-alpha+build.123"
    
    def test_header_result_with_empty_header(self):
        """Test header result with empty header bytes."""
        result_data = {"header": b""}
        serialized = serialize_get_header_result(result_data)
        deserialized = deserialize_get_header_result(serialized)
        
        assert deserialized["header"] == b""
    
    def test_header_result_with_large_header(self):
        """Test header result with large header data."""
        large_header = b"\xFF" * 1000
        result_data = {"header": large_header}
        serialized = serialize_get_header_result(result_data)
        deserialized = deserialize_get_header_result(serialized)
        
        assert deserialized["header"] == large_header


class TestConsistency:
    """Test consistency across multiple serializations."""
    
    def test_multiple_network_serializations(self):
        """Test that multiple serializations produce same result."""
        result_data = {"network": "mainnet"}
        
        s1 = serialize_get_network_result(result_data)
        s2 = serialize_get_network_result(result_data)
        s3 = serialize_get_network_result(result_data)
        
        assert s1 == s2 == s3
    
    def test_multiple_height_serializations(self):
        """Test that multiple height serializations produce same result."""
        result_data = {"height": 12345}
        
        s1 = serialize_get_height_result(result_data)
        s2 = serialize_get_height_result(result_data)
        
        assert s1 == s2
    
    def test_multiple_header_args_serializations(self):
        """Test that multiple header args serializations produce same result."""
        args = {"height": 999}
        
        s1 = serialize_get_header_args(args)
        s2 = serialize_get_header_args(args)
        
        assert s1 == s2

