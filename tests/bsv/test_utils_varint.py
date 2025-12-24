"""
Test varint encoding and decoding functions in bsv/utils.py
"""

import pytest
from bsv.utils import unsigned_to_varint, Reader


class TestVarintEncoding:
    """Test unsigned_to_varint() function."""
    
    def test_varint_encode_zero(self):
        """Test encoding zero."""
        assert unsigned_to_varint(0) == b'\x00'
    
    def test_varint_encode_one(self):
        """Test encoding one."""
        assert unsigned_to_varint(1) == b'\x01'
    
    def test_varint_encode_single_byte_max(self):
        """Test encoding maximum single byte value (252)."""
        assert unsigned_to_varint(252) == b'\xfc'
    
    def test_varint_encode_fd_prefix(self):
        """Test encoding value that needs fd prefix (253)."""
        result = unsigned_to_varint(253)
        assert result == b'\xfd\xfd\x00'
        assert len(result) == 3
    
    def test_varint_encode_two_byte_value(self):
        """Test encoding two-byte value."""
        assert unsigned_to_varint(1000) == b'\xfd\xe8\x03'
    
    def test_varint_encode_two_byte_max(self):
        """Test encoding maximum two-byte value (65535)."""
        result = unsigned_to_varint(65535)
        assert result == b'\xfd\xff\xff'
        assert len(result) == 3
    
    def test_varint_encode_fe_prefix(self):
        """Test encoding value that needs fe prefix (65536)."""
        result = unsigned_to_varint(65536)
        assert result[:1] == b'\xfe'
        assert len(result) == 5
    
    def test_varint_encode_four_byte_value(self):
        """Test encoding four-byte value."""
        result = unsigned_to_varint(1000000)
        assert result[:1] == b'\xfe'
        assert len(result) == 5
    
    def test_varint_encode_four_byte_max(self):
        """Test encoding maximum four-byte value."""
        result = unsigned_to_varint(4294967295)
        assert result == b'\xfe\xff\xff\xff\xff'
        assert len(result) == 5
    
    def test_varint_encode_ff_prefix(self):
        """Test encoding value that needs ff prefix."""
        result = unsigned_to_varint(4294967296)
        assert result[:1] == b'\xff'
        assert len(result) == 9
    
    def test_varint_encode_eight_byte_value(self):
        """Test encoding eight-byte value."""
        result = unsigned_to_varint(2**40)
        assert result[:1] == b'\xff'
        assert len(result) == 9
    
    def test_varint_encode_eight_byte_max(self):
        """Test encoding maximum eight-byte value."""
        result = unsigned_to_varint(18446744073709551615)
        assert result == b'\xff\xff\xff\xff\xff\xff\xff\xff\xff'
        assert len(result) == 9
    
    # Boundary tests
    @pytest.mark.parametrize("value,expected_length,prefix", [
        (0, 1, None),
        (252, 1, None),
        (253, 3, b'\xfd'),
        (65535, 3, b'\xfd'),
        (65536, 5, b'\xfe'),
        (4294967295, 5, b'\xfe'),
        (4294967296, 9, b'\xff'),
    ])
    def test_varint_boundaries(self, value, expected_length, prefix):
        """Test varint encoding at boundary values."""
        result = unsigned_to_varint(value)
        assert len(result) == expected_length
        if prefix:
            assert result[:1] == prefix
    
    # Negative tests
    def test_varint_encode_negative_raises(self):
        """Test that negative values raise OverflowError."""
        with pytest.raises(OverflowError, match="can't convert"):
            unsigned_to_varint(-1)
    
    def test_varint_encode_large_negative_raises(self):
        """Test that large negative values raise OverflowError."""
        with pytest.raises(OverflowError, match="can't convert"):
            unsigned_to_varint(-1000000)
    
    def test_varint_encode_overflow_raises(self):
        """Test that values > max uint64 raise OverflowError."""
        with pytest.raises(OverflowError, match="can't convert"):
            unsigned_to_varint(2**64)
    
    def test_varint_encode_large_overflow_raises(self):
        """Test that very large values raise OverflowError."""
        with pytest.raises(OverflowError, match="can't convert"):
            unsigned_to_varint(2**128)


class TestVarintDecoding:
    """Test varint decoding via Reader.read_var_int_num()."""
    
    def test_varint_decode_zero(self):
        """Test decoding zero."""
        reader = Reader(b'\x00')
        assert reader.read_var_int_num() == 0
    
    def test_varint_decode_one(self):
        """Test decoding one."""
        reader = Reader(b'\x01')
        assert reader.read_var_int_num() == 1
    
    def test_varint_decode_single_byte_max(self):
        """Test decoding 252."""
        reader = Reader(b'\xfc')
        assert reader.read_var_int_num() == 252
    
    def test_varint_decode_fd_prefix(self):
        """Test decoding value with fd prefix."""
        reader = Reader(b'\xfd\xfd\x00')
        assert reader.read_var_int_num() == 253
    
    def test_varint_decode_two_byte(self):
        """Test decoding two-byte value."""
        reader = Reader(b'\xfd\xe8\x03')
        assert reader.read_var_int_num() == 1000
    
    def test_varint_decode_two_byte_max(self):
        """Test decoding 65535."""
        reader = Reader(b'\xfd\xff\xff')
        assert reader.read_var_int_num() == 65535
    
    def test_varint_decode_fe_prefix(self):
        """Test decoding value with fe prefix."""
        reader = Reader(b'\xfe\x00\x00\x01\x00')
        assert reader.read_var_int_num() == 65536
    
    def test_varint_decode_four_byte(self):
        """Test decoding four-byte value."""
        reader = Reader(unsigned_to_varint(1000000))
        assert reader.read_var_int_num() == 1000000
    
    def test_varint_decode_four_byte_max(self):
        """Test decoding maximum four-byte value."""
        reader = Reader(b'\xfe\xff\xff\xff\xff')
        assert reader.read_var_int_num() == 4294967295
    
    def test_varint_decode_ff_prefix(self):
        """Test decoding value with ff prefix."""
        reader = Reader(unsigned_to_varint(4294967296))
        assert reader.read_var_int_num() == 4294967296
    
    def test_varint_decode_eight_byte_max(self):
        """Test decoding maximum eight-byte value."""
        reader = Reader(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff')
        assert reader.read_var_int_num() == 18446744073709551615
    
    def test_varint_decode_empty_returns_none(self):
        """Test decoding empty data returns None."""
        reader = Reader(b'')
        assert reader.read_var_int_num() is None
    
    def test_varint_decode_truncated_fd_returns_partial(self):
        """Test decoding truncated fd returns partial result."""
        reader = Reader(b'\xfd\x00')
        # Reader returns partial data when truncated (0 from reading 1 byte)
        assert reader.read_var_int_num() == 0
    
    def test_varint_decode_truncated_fe_returns_partial(self):
        """Test decoding truncated fe returns partial result."""
        reader = Reader(b'\xfe\x00\x00')
        # Reader returns partial data when truncated
        assert reader.read_var_int_num() == 0
    
    def test_varint_decode_truncated_ff_returns_partial(self):
        """Test decoding truncated ff returns partial result."""
        reader = Reader(b'\xff\x00\x00\x00')
        # Reader returns partial data when truncated
        assert reader.read_var_int_num() == 0


class TestVarintRoundTrip:
    """Test varint encoding and decoding round trips."""
    
    @pytest.mark.parametrize("value", [
        0, 1, 127, 252,           # Single byte range
        253, 1000, 65535,         # Two byte range
        65536, 1000000, 4294967295,  # Four byte range
        4294967296, 2**40, 2**63 - 1,  # Eight byte range
    ])
    def test_varint_round_trip(self, value):
        """Test that encode -> decode returns original value."""
        encoded = unsigned_to_varint(value)
        reader = Reader(encoded)
        decoded = reader.read_var_int_num()
        assert decoded == value
    
    def test_varint_round_trip_multiple_values(self):
        """Test encoding and decoding multiple values in sequence."""
        values = [0, 252, 253, 65535, 65536, 2**32]
        
        # Encode all values
        encoded = b''.join(unsigned_to_varint(v) for v in values)
        
        # Decode all values
        reader = Reader(encoded)
        decoded = [reader.read_var_int_num() for _ in values]
        
        assert decoded == values
    
    def test_varint_read_var_int_bytes(self):
        """Test reading raw varint bytes."""
        test_values = [
            (0, b'\x00'),
            (252, b'\xfc'),
            (253, b'\xfd\xfd\x00'),
            (65536, b'\xfe\x00\x00\x01\x00'),
        ]
        
        for value, expected_bytes in test_values:
            encoded = unsigned_to_varint(value)
            reader = Reader(encoded)
            raw_bytes = reader.read_var_int()
            assert raw_bytes == expected_bytes

