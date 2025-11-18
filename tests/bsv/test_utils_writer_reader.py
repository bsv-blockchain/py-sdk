"""
Test Writer and Reader classes in bsv/utils.py
"""

import pytest
import struct
from bsv.utils import Writer, Reader


class TestWriter:
    """Test Writer class."""
    
    def test_writer_init(self):
        """Test Writer initialization."""
        writer = Writer()
        assert writer.to_bytes() == b''
    
    def test_write_bytes(self):
        """Test writing bytes."""
        writer = Writer()
        writer.write(b'Hello')
        assert writer.to_bytes() == b'Hello'
    
    def test_write_chaining(self):
        """Test method chaining."""
        writer = Writer()
        result = writer.write(b'Hello').write(b'World')
        assert result is writer
        assert writer.to_bytes() == b'HelloWorld'
    
    def test_write_reverse(self):
        """Test writing bytes in reverse."""
        writer = Writer()
        writer.write_reverse(b'\x01\x02\x03')
        assert writer.to_bytes() == b'\x03\x02\x01'
    
    def test_write_uint8(self):
        """Test writing uint8."""
        writer = Writer()
        writer.write_uint8(255)
        assert writer.to_bytes() == b'\xff'
    
    def test_write_int8(self):
        """Test writing int8."""
        writer = Writer()
        writer.write_int8(-1)
        assert writer.to_bytes() == b'\xff'
    
    def test_write_uint16_be(self):
        """Test writing uint16 big endian."""
        writer = Writer()
        writer.write_uint16_be(0x0102)
        assert writer.to_bytes() == b'\x01\x02'
    
    def test_write_int16_be(self):
        """Test writing int16 big endian."""
        writer = Writer()
        writer.write_int16_be(-1)
        assert writer.to_bytes() == b'\xff\xff'
    
    def test_write_uint16_le(self):
        """Test writing uint16 little endian."""
        writer = Writer()
        writer.write_uint16_le(0x0102)
        assert writer.to_bytes() == b'\x02\x01'
    
    def test_write_int16_le(self):
        """Test writing int16 little endian."""
        writer = Writer()
        writer.write_int16_le(-1)
        assert writer.to_bytes() == b'\xff\xff'
    
    def test_write_uint32_be(self):
        """Test writing uint32 big endian."""
        writer = Writer()
        writer.write_uint32_be(0x01020304)
        assert writer.to_bytes() == b'\x01\x02\x03\x04'
    
    def test_write_int32_be(self):
        """Test writing int32 big endian."""
        writer = Writer()
        writer.write_int32_be(-1)
        assert writer.to_bytes() == b'\xff\xff\xff\xff'
    
    def test_write_uint32_le(self):
        """Test writing uint32 little endian."""
        writer = Writer()
        writer.write_uint32_le(0x01020304)
        assert writer.to_bytes() == b'\x04\x03\x02\x01'
    
    def test_write_int32_le(self):
        """Test writing int32 little endian."""
        writer = Writer()
        writer.write_int32_le(-1)
        assert writer.to_bytes() == b'\xff\xff\xff\xff'
    
    def test_write_uint64_be(self):
        """Test writing uint64 big endian."""
        writer = Writer()
        writer.write_uint64_be(0x0102030405060708)
        assert writer.to_bytes() == b'\x01\x02\x03\x04\x05\x06\x07\x08'
    
    def test_write_uint64_le(self):
        """Test writing uint64 little endian."""
        writer = Writer()
        writer.write_uint64_le(0x0102030405060708)
        assert writer.to_bytes() == b'\x08\x07\x06\x05\x04\x03\x02\x01'
    
    def test_write_var_int_num_small(self):
        """Test writing small varint."""
        writer = Writer()
        writer.write_var_int_num(0)
        assert writer.to_bytes() == b'\x00'
    
    def test_write_var_int_num_medium(self):
        """Test writing medium varint."""
        writer = Writer()
        writer.write_var_int_num(253)
        assert writer.to_bytes() == b'\xfd\xfd\x00'
    
    def test_write_var_int_num_large(self):
        """Test writing large varint."""
        writer = Writer()
        writer.write_var_int_num(65536)
        assert len(writer.to_bytes()) == 5
    
    def test_write_multiple_operations(self):
        """Test multiple write operations."""
        writer = Writer()
        writer.write_uint8(1)
        writer.write_uint16_le(0x0203)
        writer.write_uint32_be(0x04050607)
        result = writer.to_bytes()
        assert result == b'\x01\x03\x02\x04\x05\x06\x07'
    
    def test_var_int_num_static_method(self):
        """Test static var_int_num method."""
        result = Writer.var_int_num(252)
        assert result == b'\xfc'
    
    @pytest.mark.parametrize("value", [0, 127, 255])
    def test_write_uint8_values(self, value):
        """Test writing various uint8 values."""
        writer = Writer()
        writer.write_uint8(value)
        assert len(writer.to_bytes()) == 1
    
    @pytest.mark.parametrize("value", [-128, -1, 0, 1, 127])
    def test_write_int8_values(self, value):
        """Test writing various int8 values."""
        writer = Writer()
        writer.write_int8(value)
        assert len(writer.to_bytes()) == 1


class TestReader:
    """Test Reader class."""
    
    def test_reader_init(self):
        """Test Reader initialization."""
        data = b'Hello'
        reader = Reader(data)
        assert not reader.eof()
    
    def test_read_bytes(self):
        """Test reading bytes."""
        reader = Reader(b'Hello')
        result = reader.read(5)
        assert result == b'Hello'
    
    def test_read_bytes_with_length(self):
        """Test reading specific number of bytes."""
        reader = Reader(b'HelloWorld')
        result = reader.read_bytes(5)
        assert result == b'Hello'
    
    def test_read_bytes_empty_returns_empty(self):
        """Test reading from empty reader returns empty bytes."""
        reader = Reader(b'')
        result = reader.read_bytes(5)
        assert result == b''
    
    def test_read_reverse(self):
        """Test reading bytes in reverse."""
        reader = Reader(b'\x01\x02\x03')
        result = reader.read_reverse(3)
        assert result == b'\x03\x02\x01'
    
    def test_read_reverse_empty_returns_none(self):
        """Test reading reverse from empty returns None."""
        reader = Reader(b'')
        result = reader.read_reverse(3)
        assert result is None
    
    def test_read_uint8(self):
        """Test reading uint8."""
        reader = Reader(b'\xff')
        assert reader.read_uint8() == 255
    
    def test_read_uint8_empty_returns_none(self):
        """Test reading uint8 from empty returns None."""
        reader = Reader(b'')
        assert reader.read_uint8() is None
    
    def test_read_int8(self):
        """Test reading int8."""
        reader = Reader(b'\xff')
        assert reader.read_int8() == -1
    
    def test_read_int8_empty_returns_none(self):
        """Test reading int8 from empty returns None."""
        reader = Reader(b'')
        assert reader.read_int8() is None
    
    def test_read_uint16_be(self):
        """Test reading uint16 big endian."""
        reader = Reader(b'\x01\x02')
        assert reader.read_uint16_be() == 0x0102
    
    def test_read_int16_be(self):
        """Test reading int16 big endian."""
        reader = Reader(b'\xff\xff')
        assert reader.read_int16_be() == -1
    
    def test_read_uint16_le(self):
        """Test reading uint16 little endian."""
        reader = Reader(b'\x02\x01')
        assert reader.read_uint16_le() == 0x0102
    
    def test_read_int16_le(self):
        """Test reading int16 little endian."""
        reader = Reader(b'\xff\xff')
        assert reader.read_int16_le() == -1
    
    def test_read_uint32_be(self):
        """Test reading uint32 big endian."""
        reader = Reader(b'\x01\x02\x03\x04')
        assert reader.read_uint32_be() == 0x01020304
    
    def test_read_int32_be(self):
        """Test reading int32 big endian."""
        reader = Reader(b'\xff\xff\xff\xff')
        assert reader.read_int32_be() == -1
    
    def test_read_uint32_le(self):
        """Test reading uint32 little endian."""
        reader = Reader(b'\x04\x03\x02\x01')
        assert reader.read_uint32_le() == 0x01020304
    
    def test_read_int32_le(self):
        """Test reading int32 little endian."""
        reader = Reader(b'\xff\xff\xff\xff')
        assert reader.read_int32_le() == -1
    
    def test_read_int(self):
        """Test read_int method."""
        reader = Reader(b'\x01\x02')
        result = reader.read_int(2, byteorder='big')
        assert result == 0x0102
    
    def test_read_int_little_endian(self):
        """Test read_int with little endian."""
        reader = Reader(b'\x01\x02')
        result = reader.read_int(2, byteorder='little')
        assert result == 0x0201
    
    def test_read_int_empty_returns_none(self):
        """Test read_int from empty returns None."""
        reader = Reader(b'')
        result = reader.read_int(2)
        assert result is None
    
    def test_eof_initially_false(self):
        """Test eof is False initially."""
        reader = Reader(b'data')
        assert not reader.eof()
    
    def test_eof_after_reading_all(self):
        """Test eof is True after reading all data."""
        reader = Reader(b'data')
        reader.read(4)
        assert reader.eof()
    
    def test_eof_partial_read(self):
        """Test eof after partial read."""
        reader = Reader(b'data')
        reader.read(2)
        assert not reader.eof()
        reader.read(2)
        assert reader.eof()
    
    def test_read_none_returns_none(self):
        """Test read with None length."""
        reader = Reader(b'Hello')
        result = reader.read(None)
        assert result == b'Hello'
    
    def test_read_var_int_simple(self):
        """Test reading simple varint."""
        reader = Reader(b'\x01')
        result = reader.read_var_int()
        assert result == b'\x01'
    
    def test_read_var_int_fd(self):
        """Test reading varint with fd prefix."""
        reader = Reader(b'\xfd\x01\x02')
        result = reader.read_var_int()
        assert result == b'\xfd\x01\x02'
    
    def test_read_var_int_fe(self):
        """Test reading varint with fe prefix."""
        reader = Reader(b'\xfe\x01\x02\x03\x04')
        result = reader.read_var_int()
        assert result == b'\xfe\x01\x02\x03\x04'
    
    def test_read_var_int_ff(self):
        """Test reading varint with ff prefix."""
        reader = Reader(b'\xff\x01\x02\x03\x04\x05\x06\x07\x08')
        result = reader.read_var_int()
        assert result == b'\xff\x01\x02\x03\x04\x05\x06\x07\x08'
    
    def test_read_var_int_empty_returns_none(self):
        """Test reading varint from empty returns None."""
        reader = Reader(b'')
        result = reader.read_var_int()
        assert result is None
    
    def test_read_var_int_truncated_fd(self):
        """Test reading truncated fd varint."""
        reader = Reader(b'\xfd\x01')
        result = reader.read_var_int()
        # Should return what it can
        assert result == b'\xfd\x01'
    
    def test_read_multiple_operations(self):
        """Test multiple read operations."""
        data = Writer()
        data.write_uint8(1)
        data.write_uint16_le(0x0203)
        data.write_uint32_be(0x04050607)
        
        reader = Reader(data.to_bytes())
        assert reader.read_uint8() == 1
        assert reader.read_uint16_le() == 0x0203
        assert reader.read_uint32_be() == 0x04050607


class TestWriterReaderRoundTrip:
    """Test round-trip encoding and decoding."""
    
    def test_round_trip_uint8(self):
        """Test uint8 round trip."""
        writer = Writer()
        writer.write_uint8(123)
        reader = Reader(writer.to_bytes())
        assert reader.read_uint8() == 123
    
    def test_round_trip_int8(self):
        """Test int8 round trip."""
        writer = Writer()
        writer.write_int8(-42)
        reader = Reader(writer.to_bytes())
        assert reader.read_int8() == -42
    
    def test_round_trip_uint16_le(self):
        """Test uint16 LE round trip."""
        writer = Writer()
        writer.write_uint16_le(0x1234)
        reader = Reader(writer.to_bytes())
        assert reader.read_uint16_le() == 0x1234
    
    def test_round_trip_uint32_be(self):
        """Test uint32 BE round trip."""
        writer = Writer()
        writer.write_uint32_be(0x12345678)
        reader = Reader(writer.to_bytes())
        assert reader.read_uint32_be() == 0x12345678
    
    def test_round_trip_uint64_le(self):
        """Test uint64 LE round trip."""
        writer = Writer()
        writer.write_uint64_le(0x123456789ABCDEF0)
        reader = Reader(writer.to_bytes())
        # Read as 8 bytes little endian
        result = reader.read_int(8, byteorder='little')
        assert result == 0x123456789ABCDEF0
    
    def test_round_trip_var_int(self):
        """Test varint round trip."""
        for value in [0, 252, 253, 65535, 65536]:
            writer = Writer()
            writer.write_var_int_num(value)
            reader = Reader(writer.to_bytes())
            assert reader.read_var_int_num() == value
    
    def test_round_trip_mixed_types(self):
        """Test round trip with mixed data types."""
        writer = Writer()
        writer.write_uint8(1)
        writer.write_uint16_be(0x0203)
        writer.write_uint32_le(0x04050607)
        writer.write_var_int_num(1000)
        writer.write(b'Hello')
        
        reader = Reader(writer.to_bytes())
        assert reader.read_uint8() == 1
        assert reader.read_uint16_be() == 0x0203
        assert reader.read_uint32_le() == 0x04050607
        assert reader.read_var_int_num() == 1000
        assert reader.read_bytes(5) == b'Hello'
    
    def test_round_trip_reverse(self):
        """Test round trip with reverse operations."""
        original = b'\x01\x02\x03\x04'
        writer = Writer()
        writer.write_reverse(original)
        reader = Reader(writer.to_bytes())
        result = reader.read_reverse(4)
        assert result == original
    
    @pytest.mark.parametrize("values", [
        [0, 127, 255],
        [1, 2, 3, 4, 5],
        list(range(100)),
    ])
    def test_round_trip_multiple_uint8(self, values):
        """Test round trip with multiple uint8 values."""
        writer = Writer()
        for v in values:
            writer.write_uint8(v)
        
        reader = Reader(writer.to_bytes())
        result = [reader.read_uint8() for _ in values]
        assert result == values

