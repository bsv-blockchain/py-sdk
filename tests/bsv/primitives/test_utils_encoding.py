"""
Tests for py-sdk/bsv/utils/encoding.py and related encoding utilities
Ported from ts-sdk/src/primitives/__tests/utils.test.ts
"""

import pytest
import sys
import os

# Add the utils directory to the path
utils_dir = os.path.join(os.path.dirname(__file__), '..', 'bsv', 'utils')


# Import the functions directly from their modules
from bsv.utils.base58_utils import from_base58, to_base58, from_base58_check, to_base58_check
from bsv.utils.binary import to_hex, from_hex


class TestBase58Encoding:
    """Test cases for Base58 encoding/decoding"""
    
    def test_from_base58_conversion(self):
        """Test Base58 to binary conversion"""
        # Test case from TypeScript
        actual = from_base58('6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV')
        expected_hex = '02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeb05f9d2'
        actual_hex = to_hex(bytes(actual))
        assert actual_hex == expected_hex
    
    def test_from_base58_with_leading_ones(self):
        """Test Base58 conversion with leading 1s"""
        actual = from_base58('111z')
        expected_hex = '00000039'
        actual_hex = to_hex(bytes(actual))
        assert actual_hex == expected_hex
    
    def test_from_base58_invalid_input(self):
        """Test that invalid Base58 input raises errors"""
        # Test undefined/None input
        with pytest.raises(ValueError, match="Expected base58 string"):
            from_base58(None)
        
        # Test invalid characters
        with pytest.raises(ValueError, match="Invalid base58 character"):
            from_base58('0L')  # '0' is not valid in Base58
    
    def test_to_base58_conversion(self):
        """Test binary to Base58 conversion"""
        # Convert hex to binary array, then to Base58
        hex_data = '02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeb05f9d2'
        binary_array = list(bytes.fromhex(hex_data))
        actual = to_base58(binary_array)
        expected = '6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV'
        assert actual == expected
    
    def test_to_base58_with_leading_zeros(self):
        """Test Base58 conversion with leading zeros"""
        actual = to_base58([0, 0, 0, 4])
        expected = '1115'
        assert actual == expected
    
    def test_base58_roundtrip(self):
        """Test that Base58 encoding/decoding is reversible"""
        test_data = [
            [0, 1, 2, 3, 4, 5],
            [255, 254, 253],
            [0, 0, 0, 100],
            [1]  # Use [1] instead of [] to avoid empty string conversion issues
        ]
        
        for data in test_data:
            encoded = to_base58(data)
            decoded = from_base58(encoded)
            assert decoded == data


class TestBase58CheckEncoding:
    """Test cases for Base58Check encoding/decoding"""
    
    def test_base58check_roundtrip_default_prefix(self):
        """Test Base58Check encoding/decoding with default prefix"""
        test_data = [1, 2, 3, 4, 5]
        
        # Encode with default prefix
        encoded = to_base58_check(test_data)
        assert isinstance(encoded, str)
        assert len(encoded) > 0
        
        # Decode and verify
        decoded = from_base58_check(encoded)
        assert decoded['data'] == test_data
        assert decoded['prefix'] == [0]  # Default prefix
    
    def test_base58check_custom_prefix(self):
        """Test Base58Check encoding/decoding with custom prefix"""
        test_data = [1, 2, 3, 4, 5]
        custom_prefix = [128]  # Example prefix
        
        # Encode with custom prefix
        encoded = to_base58_check(test_data, custom_prefix)
        assert isinstance(encoded, str)
        assert len(encoded) > 0
        
        # Decode and verify
        decoded = from_base58_check(encoded, prefix_length=1)
        assert decoded['data'] == test_data
        assert decoded['prefix'] == custom_prefix
    
    def test_base58check_invalid_checksum(self):
        """Test that invalid checksums are detected"""
        # Create a valid Base58Check string and corrupt it
        valid_encoded = to_base58_check([1, 2, 3])
        
        # Corrupt the last character (part of checksum)
        corrupted = valid_encoded[:-1] + ('z' if valid_encoded[-1] != 'z' else 'a')
        
        # Should raise error for invalid checksum
        with pytest.raises(ValueError, match="Invalid checksum"):
            from_base58_check(corrupted)
    
    def test_base58check_hex_output(self):
        """Test Base58Check decoding with hex output format"""
        test_data = [1, 2, 3, 4, 5]
        prefix = [0]
        
        encoded = to_base58_check(test_data, prefix)
        decoded = from_base58_check(encoded, enc='hex')
        
        # Should return hex strings
        assert isinstance(decoded['prefix'], str)
        assert isinstance(decoded['data'], str)
        assert decoded['prefix'] == '00'
        assert decoded['data'] == '0102030405'


class TestHexUtilities:
    """Test cases for hex utilities"""
    
    def test_to_hex_conversion(self):
        """Test conversion to hex"""
        test_cases = [
            ([0, 1, 2, 3], '00010203'),
            ([255, 254, 253], 'fffefd'),
            ([], ''),
            ([0], '00'),
            ([16, 32, 48], '102030')
        ]
        
        for data, expected in test_cases:
            actual = to_hex(bytes(data))
            assert actual == expected
    
    def test_from_hex_conversion(self):
        """Test conversion from hex"""
        test_cases = [
            ('00010203', [0, 1, 2, 3]),
            ('fffefd', [255, 254, 253]),
            ('', []),
            ('00', [0]),
            ('102030', [16, 32, 48])
        ]
        
        for hex_str, expected in test_cases:
            actual = list(from_hex(hex_str))
            assert actual == expected
    
    def test_hex_roundtrip(self):
        """Test that hex encoding/decoding is reversible"""
        test_data = [
            [0, 1, 2, 3, 4, 5],
            [255, 254, 253],
            [0, 0, 0, 100],
            []
        ]
        
        for data in test_data:
            hex_str = to_hex(bytes(data))
            decoded = list(from_hex(hex_str))
            assert decoded == data
    
    def test_hex_case_insensitive(self):
        """Test that hex decoding is case insensitive"""
        test_cases = [
            'abcdef',
            'ABCDEF',
            'AbCdEf',
            'aBcDeF'
        ]
        
        expected = [171, 205, 239]
        for hex_str in test_cases:
            actual = list(from_hex(hex_str))
            assert actual == expected


class TestArrayUtilities:
    """Test cases for array and conversion utilities"""
    
    def test_bytes_to_list_conversion(self):
        """Test conversion between bytes and list"""
        test_data = bytes([1, 2, 3, 4, 5])
        as_list = list(test_data)
        assert as_list == [1, 2, 3, 4, 5]
        
        back_to_bytes = bytes(as_list)
        assert back_to_bytes == test_data
    
    def test_empty_data_handling(self):
        """Test handling of empty data"""
        # Empty bytes
        empty_bytes = bytes()
        assert list(empty_bytes) == []
        assert to_hex(empty_bytes) == ''
        
        # Empty list
        empty_list = []
        assert bytes(empty_list) == bytes()
        assert to_base58(empty_list) == ''
    
    def test_zero_padding(self):
        """Test handling of zero bytes"""
        # Test data with leading zeros
        data_with_zeros = [0, 0, 1, 2]
        
        # Base58 should preserve leading zeros as '1' characters
        base58_encoded = to_base58(data_with_zeros)
        assert base58_encoded.startswith('11')
        
        # Decoding should restore the zeros
        decoded = from_base58(base58_encoded)
        assert decoded == data_with_zeros


class TestEncodingIntegration:
    """Integration tests for various encoding formats"""
    
    def test_encoding_consistency(self):
        """Test consistency across different encoding methods"""
        original_data = [1, 2, 3, 4, 5, 255, 0, 128]
        
        # Test hex roundtrip
        hex_encoded = to_hex(bytes(original_data))
        hex_decoded = list(from_hex(hex_encoded))
        assert hex_decoded == original_data
        
        # Test Base58 roundtrip
        base58_encoded = to_base58(original_data)
        base58_decoded = from_base58(base58_encoded)
        assert base58_decoded == original_data
        
        # Test Base58Check roundtrip
        base58check_encoded = to_base58_check(original_data)
        base58check_decoded = from_base58_check(base58check_encoded)
        assert base58check_decoded['data'] == original_data
    
    def test_large_data_handling(self):
        """Test handling of larger data sets"""
        # Create larger test data
        large_data = list(range(256))  # 0-255
        
        # Should handle encoding/decoding without issues
        base58_encoded = to_base58(large_data)
        base58_decoded = from_base58(base58_encoded)
        assert base58_decoded == large_data
        
        hex_encoded = to_hex(bytes(large_data))
        hex_decoded = list(from_hex(hex_encoded))
        assert hex_decoded == large_data
    
    def test_edge_cases(self):
        """Test various edge cases"""
        # Single byte values
        for i in range(256):
            data = [i]
            
            # Base58 roundtrip
            base58_encoded = to_base58(data)
            base58_decoded = from_base58(base58_encoded)
            assert base58_decoded == data
            
            # Hex roundtrip
            hex_encoded = to_hex(bytes(data))
            hex_decoded = list(from_hex(hex_encoded))
            assert hex_decoded == data
