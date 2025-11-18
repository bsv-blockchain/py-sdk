"""
Comprehensive tests for bsv/utils/binary.py

Tests all binary utility functions including varint conversions.
"""

import pytest
from bsv.utils.binary import (
    unsigned_to_varint,
    varint_to_unsigned,
    unsigned_to_bytes,
    to_hex,
    from_hex,
    to_bytes,
    to_utf8,
    encode,
    to_base64,
)


class TestVarintToUnsigned:
    """Test varint_to_unsigned function."""
    
    def test_decode_empty_data_raises(self):
        """Test that empty data raises ValueError."""
        with pytest.raises(ValueError, match="Empty data"):
            varint_to_unsigned(b"")
    
    def test_decode_single_byte(self):
        """Test decoding single byte varint."""
        value, consumed = varint_to_unsigned(b"\x00")
        assert value == 0
        assert consumed == 1
        
        value, consumed = varint_to_unsigned(b"\xfc")
        assert value == 252
        assert consumed == 1
    
    def test_decode_two_byte_varint(self):
        """Test decoding 2-byte varint (0xfd prefix)."""
        data = b"\xfd\x00\x01"
        value, consumed = varint_to_unsigned(data)
        assert value == 256
        assert consumed == 3
    
    def test_decode_two_byte_varint_insufficient_data(self):
        """Test that insufficient data for 2-byte varint raises."""
        with pytest.raises(ValueError, match="Insufficient data for 2-byte"):
            varint_to_unsigned(b"\xfd\x00")
    
    def test_decode_four_byte_varint(self):
        """Test decoding 4-byte varint (0xfe prefix)."""
        data = b"\xfe\x00\x00\x01\x00"
        value, consumed = varint_to_unsigned(data)
        assert value == 65536
        assert consumed == 5
    
    def test_decode_four_byte_varint_insufficient_data(self):
        """Test that insufficient data for 4-byte varint raises."""
        with pytest.raises(ValueError, match="Insufficient data for 4-byte"):
            varint_to_unsigned(b"\xfe\x00\x00\x00")
    
    def test_decode_eight_byte_varint(self):
        """Test decoding 8-byte varint (0xff prefix)."""
        data = b"\xff\x00\x00\x00\x00\x01\x00\x00\x00"
        value, consumed = varint_to_unsigned(data)
        assert value == 0x100000000
        assert consumed == 9
    
    def test_decode_eight_byte_varint_insufficient_data(self):
        """Test that insufficient data for 8-byte varint raises."""
        with pytest.raises(ValueError, match="Insufficient data for 8-byte"):
            varint_to_unsigned(b"\xff\x00\x00\x00\x00\x00\x00\x00")
    
    def test_decode_with_extra_data(self):
        """Test decoding varint with extra data after."""
        data = b"\xfd\x34\x12extra_data"
        value, consumed = varint_to_unsigned(data)
        assert value == 0x1234
        assert consumed == 3


class TestUnsignedToBytes:
    """Test unsigned_to_bytes function."""
    
    def test_unsigned_to_bytes_zero(self):
        """Test converting zero to bytes."""
        result = unsigned_to_bytes(0)
        assert result == b"\x00"
    
    def test_unsigned_to_bytes_small_number_big_endian(self):
        """Test converting small number to bytes (big endian)."""
        result = unsigned_to_bytes(255, 'big')
        assert result == b"\xff"
    
    def test_unsigned_to_bytes_small_number_little_endian(self):
        """Test converting small number to bytes (little endian)."""
        result = unsigned_to_bytes(255, 'little')
        assert result == b"\xff"
    
    def test_unsigned_to_bytes_multi_byte_big_endian(self):
        """Test converting multi-byte number (big endian)."""
        result = unsigned_to_bytes(0x1234, 'big')
        assert result == b"\x12\x34"
    
    def test_unsigned_to_bytes_multi_byte_little_endian(self):
        """Test converting multi-byte number (little endian)."""
        result = unsigned_to_bytes(0x1234, 'little')
        assert result == b"\x34\x12"
    
    def test_unsigned_to_bytes_large_number(self):
        """Test converting large number to bytes."""
        result = unsigned_to_bytes(0x123456789ABCDEF, 'big')
        assert len(result) == 8
        assert result[0] == 0x01


class TestFromHex:
    """Test from_hex function."""
    
    def test_from_hex_simple(self):
        """Test converting simple hex string to bytes."""
        result = from_hex("48656c6c6f")
        assert result == b"Hello"
    
    def test_from_hex_with_whitespace(self):
        """Test converting hex string with whitespace."""
        result = from_hex("48 65 6c 6c 6f")
        assert result == b"Hello"
    
    def test_from_hex_odd_length(self):
        """Test converting odd-length hex string (prepends 0)."""
        result = from_hex("123")
        assert result == b"\x01\x23"
    
    def test_from_hex_empty_string(self):
        """Test converting empty hex string."""
        result = from_hex("")
        assert result == b""
    
    def test_from_hex_case_insensitive(self):
        """Test that hex conversion is case insensitive."""
        result1 = from_hex("ABCDEF")
        result2 = from_hex("abcdef")
        assert result1 == result2


class TestToBytesFunction:
    """Test to_bytes function."""
    
    def test_to_bytes_from_bytes(self):
        """Test that bytes input returns unchanged."""
        data = b"test"
        result = to_bytes(data)
        assert result == data
    
    def test_to_bytes_empty_string(self):
        """Test converting empty string."""
        result = to_bytes("")
        assert result == b""
    
    def test_to_bytes_utf8_string(self):
        """Test converting string to UTF-8 bytes."""
        result = to_bytes("hello")
        assert result == b"hello"
    
    def test_to_bytes_utf8_unicode(self):
        """Test converting unicode string to UTF-8."""
        result = to_bytes("hello 世界", enc=None)
        assert result == "hello 世界".encode('utf-8')
    
    def test_to_bytes_hex_encoding(self):
        """Test converting hex-encoded string."""
        result = to_bytes("48656c6c6f", enc='hex')
        assert result == b"Hello"
    
    def test_to_bytes_hex_with_non_alnum(self):
        """Test hex conversion filters non-alphanumeric."""
        result = to_bytes("48:65:6c-6c 6f", enc='hex')
        assert result == b"Hello"
    
    def test_to_bytes_hex_odd_length(self):
        """Test hex conversion with odd length."""
        result = to_bytes("123", enc='hex')
        assert result == b"\x01\x23"
    
    def test_to_bytes_base64_encoding(self):
        """Test converting base64-encoded string."""
        result = to_bytes("SGVsbG8=", enc='base64')
        assert result == b"Hello"
    
    def test_to_bytes_list_input(self):
        """Test converting list input to bytes."""
        result = to_bytes([72, 101, 108, 108, 111])
        assert result == b"Hello"


class TestToUtf8:
    """Test to_utf8 function."""
    
    def test_to_utf8_simple(self):
        """Test converting byte list to UTF-8 string."""
        result = to_utf8([72, 101, 108, 108, 111])
        assert result == "Hello"
    
    def test_to_utf8_empty(self):
        """Test converting empty list."""
        result = to_utf8([])
        assert result == ""
    
    def test_to_utf8_unicode(self):
        """Test converting unicode bytes."""
        # "世界" in UTF-8
        result = to_utf8([228, 184, 150, 231, 149, 140])
        assert result == "世界"


class TestEncode:
    """Test encode function."""
    
    def test_encode_no_encoding(self):
        """Test encode with no encoding returns original."""
        arr = [72, 101, 108, 108, 111]
        result = encode(arr)
        assert result == arr
    
    def test_encode_hex(self):
        """Test encode to hex."""
        arr = [72, 101, 108, 108, 111]
        result = encode(arr, enc='hex')
        assert result == "48656c6c6f"
    
    def test_encode_utf8(self):
        """Test encode to UTF-8."""
        arr = [72, 101, 108, 108, 111]
        result = encode(arr, enc='utf8')
        assert result == "Hello"
    
    def test_encode_empty_list(self):
        """Test encoding empty list."""
        result = encode([])
        assert result == []


class TestToBase64:
    """Test to_base64 function."""
    
    def test_to_base64_simple(self):
        """Test converting bytes to base64."""
        result = to_base64([72, 101, 108, 108, 111])
        assert result == "SGVsbG8="
    
    def test_to_base64_empty(self):
        """Test converting empty list."""
        result = to_base64([])
        assert result == ""
    
    def test_to_base64_binary_data(self):
        """Test converting binary data."""
        result = to_base64([0, 1, 2, 3, 4, 5])
        import base64
        expected = base64.b64encode(bytes([0, 1, 2, 3, 4, 5])).decode('ascii')
        assert result == expected


class TestRoundTripConversions:
    """Test round-trip conversions."""
    
    def test_varint_round_trip(self):
        """Test varint encode/decode round trip."""
        for num in [0, 1, 100, 252, 253, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF]:
            encoded = unsigned_to_varint(num)
            decoded, _ = varint_to_unsigned(encoded)
            assert decoded == num
    
    def test_hex_round_trip(self):
        """Test hex encode/decode round trip."""
        original = b"Hello World"
        hex_str = to_hex(original)
        decoded = from_hex(hex_str)
        assert decoded == original
    
    def test_utf8_round_trip(self):
        """Test UTF-8 encode/decode round trip."""
        original = "Hello 世界"
        byte_list = list(original.encode('utf-8'))
        decoded = to_utf8(byte_list)
        assert decoded == original
    
    def test_base64_round_trip(self):
        """Test base64 encode/decode round trip."""
        original = [72, 101, 108, 108, 111]
        encoded = to_base64(original)
        decoded = to_bytes(encoded, enc='base64')
        assert decoded == bytes(original)

