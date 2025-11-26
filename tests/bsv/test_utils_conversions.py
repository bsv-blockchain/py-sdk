"""
Test conversion functions in bsv/utils.py
"""

import pytest
from bsv.utils import (
    unsigned_to_bytes, bytes_to_bits, bits_to_bytes, randbytes,
    to_hex, to_bytes, to_utf8, encode, to_base64,
    from_base58, to_base58, to_base58_check, from_base58_check,
    reverse_hex_byte_order
)


class TestUnsignedToBytes:
    """Test unsigned_to_bytes() function."""
    
    def test_unsigned_to_bytes_zero(self):
        """Test converting zero."""
        result = unsigned_to_bytes(0)
        assert result == b'\x00'
    
    def test_unsigned_to_bytes_one(self):
        """Test converting one."""
        result = unsigned_to_bytes(1)
        assert result == b'\x01'
    
    def test_unsigned_to_bytes_255(self):
        """Test converting 255 (single byte max)."""
        result = unsigned_to_bytes(255)
        assert result == b'\xff'
    
    def test_unsigned_to_bytes_256(self):
        """Test converting 256 (two bytes)."""
        result = unsigned_to_bytes(256)
        assert len(result) == 2
    
    def test_unsigned_to_bytes_big_endian(self):
        """Test big endian byte order."""
        result = unsigned_to_bytes(0x1234, byteorder='big')
        assert result == b'\x12\x34'
    
    def test_unsigned_to_bytes_little_endian(self):
        """Test little endian byte order."""
        result = unsigned_to_bytes(0x1234, byteorder='little')
        assert result == b'\x34\x12'
    
    def test_unsigned_to_bytes_large_number(self):
        """Test converting large number."""
        result = unsigned_to_bytes(2**32)
        assert len(result) == 5
        assert int.from_bytes(result, 'big') == 2**32
    
    @pytest.mark.parametrize("value,expected_min_bytes", [
        (0, 1),
        (255, 1),
        (256, 2),
        (65535, 2),
        (65536, 3),
        (2**32-1, 4),
    ])
    def test_unsigned_to_bytes_minimal_length(self, value, expected_min_bytes):
        """Test that function uses minimal bytes."""
        result = unsigned_to_bytes(value)
        assert len(result) == expected_min_bytes


class TestBytesAndBits:
    """Test bytes_to_bits() and bits_to_bytes() functions."""
    
    def test_bytes_to_bits_simple(self):
        """Test converting bytes to bits."""
        result = bytes_to_bits(b'\x00')
        assert result == '00000000'
    
    def test_bytes_to_bits_all_ones(self):
        """Test converting all ones byte."""
        result = bytes_to_bits(b'\xff')
        assert result == '11111111'
    
    def test_bytes_to_bits_pattern(self):
        """Test converting specific pattern."""
        result = bytes_to_bits(b'\xaa')  # 10101010
        assert result == '10101010'
    
    def test_bytes_to_bits_multiple_bytes(self):
        """Test converting multiple bytes."""
        result = bytes_to_bits(b'\x01\x02')
        assert result == '0000000100000010'
    
    def test_bytes_to_bits_from_hex_string(self):
        """Test converting from hex string."""
        result = bytes_to_bits('ff00')
        assert result == '1111111100000000'
    
    def test_bytes_to_bits_preserves_leading_zeros(self):
        """Test that leading zeros are preserved."""
        result = bytes_to_bits(b'\x00\x01')
        assert result == '0000000000000001'
        assert len(result) == 16
    
    def test_bits_to_bytes_simple(self):
        """Test converting bits to bytes."""
        result = bits_to_bytes('00000000')
        assert result == b'\x00'
    
    def test_bits_to_bytes_all_ones(self):
        """Test converting all ones."""
        result = bits_to_bytes('11111111')
        assert result == b'\xff'
    
    def test_bits_to_bytes_pattern(self):
        """Test converting specific pattern."""
        result = bits_to_bytes('10101010')
        assert result == b'\xaa'
    
    def test_bits_to_bytes_multiple_bytes(self):
        """Test converting multiple bytes worth of bits."""
        result = bits_to_bytes('0000000100000010')
        assert result == b'\x01\x02'
    
    def test_bits_to_bytes_padding(self):
        """Test that partial bytes are padded."""
        result = bits_to_bytes('1111')
        assert isinstance(result, bytes)
        assert len(result) == 1
    
    @pytest.mark.parametrize("data", [
        b'\x00',
        b'\xff',
        b'\x01\x02\x03',
        b'Hello',
        bytes(range(256)),
    ])
    def test_bytes_bits_round_trip(self, data):
        """Test round trip conversion."""
        bits = bytes_to_bits(data)
        result = bits_to_bytes(bits)
        assert result == data
    
    def test_bytes_bits_empty_special_case(self):
        """Test that empty bytes is a special case (becomes b'\\x00')."""
        # Empty bytes through bits conversion results in minimal byte representation
        bits = bytes_to_bits(b'')
        result = bits_to_bytes(bits)
        # Empty input becomes b'\x00' (minimal representation)
        assert result == b'\x00' or result == b''


class TestRandomBytes:
    """Test randbytes() function."""
    
    def test_randbytes_length(self):
        """Test that randbytes returns correct length."""
        result = randbytes(32)
        assert len(result) == 32
    
    def test_randbytes_zero_length(self):
        """Test randbytes with zero length."""
        result = randbytes(0)
        assert result == b''
    
    def test_randbytes_one_byte(self):
        """Test randbytes with one byte."""
        result = randbytes(1)
        assert len(result) == 1
    
    def test_randbytes_uniqueness(self):
        """Test that randbytes generates different values."""
        result1 = randbytes(32)
        result2 = randbytes(32)
        # Extremely unlikely to be equal
        assert result1 != result2
    
    @pytest.mark.parametrize("length", [1, 16, 32, 64, 128, 256])
    def test_randbytes_various_lengths(self, length):
        """Test randbytes with various lengths."""
        result = randbytes(length)
        assert len(result) == length
        assert isinstance(result, bytes)


class TestHexAndBytesConversions:
    """Test to_hex(), to_bytes(), and related functions."""
    
    def test_to_hex_simple(self):
        """Test converting bytes to hex."""
        result = to_hex(b'Hello')
        assert result == '48656c6c6f'
    
    def test_to_hex_empty(self):
        """Test converting empty bytes."""
        result = to_hex(b'')
        assert result == ''
    
    def test_to_hex_special_chars(self):
        """Test converting bytes with special chars."""
        result = to_hex(b'\x00\xff')
        assert result == '00ff'
    
    def test_to_bytes_from_bytes(self):
        """Test to_bytes with bytes input."""
        result = to_bytes(b'Hello')
        assert result == b'Hello'
    
    def test_to_bytes_from_string_utf8(self):
        """Test to_bytes from string with UTF-8."""
        result = to_bytes('Hello')
        assert result == b'Hello'
    
    def test_to_bytes_from_hex_string(self):
        """Test to_bytes from hex string."""
        result = to_bytes('48656c6c6f', enc='hex')
        assert result == b'Hello'
    
    def test_to_bytes_from_base64(self):
        """Test to_bytes from base64 string."""
        import base64
        b64_str = base64.b64encode(b'Hello').decode('ascii')
        result = to_bytes(b64_str, enc='base64')
        assert result == b'Hello'
    
    def test_to_bytes_empty_string(self):
        """Test to_bytes with empty string."""
        result = to_bytes('')
        assert result == b''
    
    def test_to_bytes_hex_odd_length(self):
        """Test to_bytes with odd length hex (auto-pads)."""
        result = to_bytes('123', enc='hex')
        assert result == b'\x01\x23'
    
    def test_to_bytes_hex_with_spaces(self):
        """Test to_bytes with hex containing spaces (filtered)."""
        result = to_bytes('48 65 6c 6c 6f', enc='hex')
        assert result == b'Hello'
    
    def test_reverse_hex_byte_order(self):
        """Test reversing hex byte order."""
        result = reverse_hex_byte_order('0102030405')
        assert result == '0504030201'
    
    def test_reverse_hex_byte_order_empty(self):
        """Test reversing empty hex."""
        result = reverse_hex_byte_order('')
        assert result == ''
    
    def test_reverse_hex_byte_order_single_byte(self):
        """Test reversing single byte."""
        result = reverse_hex_byte_order('ff')
        assert result == 'ff'


class TestUTF8Encoding:
    """Test to_utf8() and encode() functions."""
    
    def test_to_utf8_simple(self):
        """Test converting int array to UTF-8."""
        arr = [72, 101, 108, 108, 111]  # 'Hello'
        result = to_utf8(arr)
        assert result == 'Hello'
    
    def test_to_utf8_empty(self):
        """Test converting empty array."""
        result = to_utf8([])
        assert result == ''
    
    def test_to_utf8_special_chars(self):
        """Test converting UTF-8 special characters."""
        arr = [0xc2, 0xa9]  # © symbol
        result = to_utf8(arr)
        assert result == '©'
    
    def test_encode_no_encoding(self):
        """Test encode with no encoding specified."""
        arr = [1, 2, 3]
        result = encode(arr, enc=None)
        assert result == arr
    
    def test_encode_to_hex(self):
        """Test encode to hex."""
        arr = [0x48, 0x65, 0x6c, 0x6c, 0x6f]
        result = encode(arr, enc='hex')
        assert result == '48656c6c6f'
    
    def test_encode_to_utf8(self):
        """Test encode to UTF-8."""
        arr = [72, 101, 108, 108, 111]
        result = encode(arr, enc='utf8')
        assert result == 'Hello'
    
    def test_to_base64_simple(self):
        """Test converting to base64."""
        arr = [72, 101, 108, 108, 111]  # 'Hello'
        result = to_base64(arr)
        import base64
        expected = base64.b64encode(b'Hello').decode('ascii')
        assert result == expected
    
    def test_to_base64_empty(self):
        """Test converting empty array to base64."""
        result = to_base64([])
        assert result == ''


class TestBase58:
    """Test base58 encoding and decoding functions."""
    
    def test_from_base58_simple(self):
        """Test decoding simple base58 string."""
        result = from_base58('111')
        assert result == [0, 0, 0]
    
    def test_to_base58_simple(self):
        """Test encoding simple binary to base58."""
        result = to_base58([0, 0, 0])
        assert result == '111'
    
    def test_base58_round_trip(self):
        """Test base58 encode/decode round trip."""
        original = [1, 2, 3, 4, 5]
        encoded = to_base58(original)
        decoded = from_base58(encoded)
        assert decoded == original
    
    def test_from_base58_leading_zeros(self):
        """Test that leading zeros are preserved."""
        # '1' in base58 represents 0
        result = from_base58('1111A')
        assert result[:3] == [0, 0, 0]
    
    def test_from_base58_invalid_char_raises(self):
        """Test that invalid character raises ValueError."""
        with pytest.raises(ValueError, match="Invalid base58 character"):
            from_base58('123O456')  # 'O' is invalid
    
    def test_from_base58_zero_char_raises(self):
        """Test that '0' character raises ValueError."""
        with pytest.raises(ValueError, match="Invalid base58 character"):
            from_base58('1230456')
    
    def test_from_base58_I_char_raises(self):  # NOSONAR - Testing Base58 exclusion of 'I' character
        """Test that 'I' character raises ValueError."""
        with pytest.raises(ValueError, match="Invalid base58 character"):
            from_base58('123I456')
    
    def test_from_base58_l_char_raises(self):
        """Test that 'l' character raises ValueError."""
        with pytest.raises(ValueError, match="Invalid base58 character"):
            from_base58('123l456')
    
    def test_from_base58_empty_raises(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="Expected base58 string"):
            from_base58('')
    
    def test_from_base58_none_raises(self):
        """Test that None raises ValueError."""
        with pytest.raises(ValueError, match="Expected base58 string"):
            from_base58(None)
    
    def test_to_base58_empty(self):
        """Test encoding empty binary."""
        result = to_base58([])
        assert result == ''
    
    def test_to_base58_leading_zeros(self):
        """Test that leading zeros become '1's."""
        result = to_base58([0, 0, 0, 1])
        assert result.startswith('111')
    
    @pytest.mark.parametrize("data", [
        [0],
        [1],
        [255],
        [0, 0, 1],
        [1, 2, 3, 4, 5],
        list(range(10)),
    ])
    def test_base58_round_trip_various(self, data):
        """Test base58 round trip with various data."""
        encoded = to_base58(data)
        decoded = from_base58(encoded)
        assert decoded == data


class TestBase58Check:
    """Test base58check encoding and decoding functions."""
    
    def test_to_base58_check_simple(self):
        """Test encoding to base58check."""
        data = [1, 2, 3]
        result = to_base58_check(data)
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_to_base58_check_with_prefix(self):
        """Test encoding with custom prefix."""
        data = [1, 2, 3]
        prefix = [128]
        result = to_base58_check(data, prefix=prefix)
        assert isinstance(result, str)
    
    def test_from_base58_check_simple(self):
        """Test decoding from base58check."""
        data = [1, 2, 3]
        encoded = to_base58_check(data)
        decoded = from_base58_check(encoded)
        assert decoded['data'] == data
        assert decoded['prefix'] == [0]
    
    def test_base58_check_round_trip(self):
        """Test base58check encode/decode round trip."""
        original_data = [10, 20, 30, 40, 50]
        encoded = to_base58_check(original_data)
        decoded = from_base58_check(encoded)
        assert decoded['data'] == original_data
    
    def test_base58_check_round_trip_with_prefix(self):
        """Test round trip with custom prefix."""
        original_data = [10, 20, 30]
        prefix = [128]
        encoded = to_base58_check(original_data, prefix=prefix)
        decoded = from_base58_check(encoded, prefix_length=1)
        assert decoded['data'] == original_data
        assert decoded['prefix'] == prefix
    
    def test_from_base58_check_hex_encoding(self):
        """Test decoding with hex encoding."""
        data = [0xAA, 0xBB, 0xCC]
        encoded = to_base58_check(data)
        decoded = from_base58_check(encoded, enc='hex')
        assert decoded['data'] == 'aabbcc'
    
    def test_from_base58_check_invalid_checksum_raises(self):
        """Test that invalid checksum raises ValueError."""
        # Create valid base58check and corrupt it
        data = [1, 2, 3]
        encoded = to_base58_check(data)
        # Corrupt by changing last character
        corrupted = encoded[:-1] + ('2' if encoded[-1] != '2' else '3')
        with pytest.raises(ValueError, match="Invalid checksum"):
            from_base58_check(corrupted)
    
    def test_from_base58_check_custom_prefix_length(self):
        """Test decoding with custom prefix length."""
        data = [10, 20, 30]
        prefix = [1, 2]  # 2-byte prefix
        encoded = to_base58_check(data, prefix=prefix)
        decoded = from_base58_check(encoded, prefix_length=2)
        assert decoded['data'] == data
        assert decoded['prefix'] == prefix

