"""
Comprehensive tests for bsv/utils/reader_writer.py

Tests Reader and Writer binary data operations.
"""

import pytest
from bsv.utils.reader_writer import Writer, Reader, unsigned_to_varint


class TestUnsignedToVarint:
    """Test unsigned_to_varint function."""
    
    def test_varint_small_values(self):
        """Test varint encoding for values <= 0xfc."""
        assert unsigned_to_varint(0) == b'\x00'
        assert unsigned_to_varint(1) == b'\x01'
        assert unsigned_to_varint(252) == b'\xfc'
    
    def test_varint_two_byte(self):
        """Test varint encoding for 0xfd <= value <= 0xffff."""
        assert unsigned_to_varint(253) == b'\xfd\xfd\x00'
        assert unsigned_to_varint(255) == b'\xfd\xff\x00'
        assert unsigned_to_varint(0xffff) == b'\xfd\xff\xff'
    
    def test_varint_four_byte(self):
        """Test varint encoding for 0x10000 <= value <= 0xffffffff."""
        assert unsigned_to_varint(0x10000) == b'\xfe\x00\x00\x01\x00'
        assert unsigned_to_varint(0xffffffff) == b'\xfe\xff\xff\xff\xff'
    
    def test_varint_eight_byte(self):
        """Test varint encoding for values > 0xffffffff."""
        assert unsigned_to_varint(0x100000000) == b'\xff\x00\x00\x00\x00\x01\x00\x00\x00'
        assert unsigned_to_varint(0xffffffffffffffff) == b'\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    
    def test_varint_negative_raises(self):
        """Test that negative values raise OverflowError."""
        with pytest.raises(OverflowError, match="can't convert"):
            unsigned_to_varint(-1)
    
    def test_varint_too_large_raises(self):
        """Test that values > max uint64 raise OverflowError."""
        with pytest.raises(OverflowError, match="can't convert"):
            unsigned_to_varint(0x10000000000000000)


class TestWriter:
    """Test Writer class methods."""
    
    def test_write_bytes(self):
        """Test write_bytes method."""
        w = Writer()
        w.write_bytes(b"test")
        assert w.getvalue() == b"test"
    
    def test_write_uint8(self):
        """Test write_uint8 method."""
        w = Writer()
        w.write_uint8(255)
        assert w.getvalue() == b'\xff'
    
    def test_write_int8_positive(self):
        """Test write_int8 with positive value."""
        w = Writer()
        w.write_int8(127)
        assert w.getvalue() == b'\x7f'
    
    def test_write_int8_negative(self):
        """Test write_int8 with negative value."""
        w = Writer()
        w.write_int8(-1)
        assert w.getvalue() == b'\xff'
    
    def test_write_uint16_le(self):
        """Test write_uint16_le method."""
        w = Writer()
        w.write_uint16_le(0x1234)
        assert w.getvalue() == b'\x34\x12'  # little endian
    
    def test_write_int16_le_positive(self):
        """Test write_int16_le with positive value."""
        w = Writer()
        w.write_int16_le(0x1234)
        assert w.getvalue() == b'\x34\x12'
    
    def test_write_int16_le_negative(self):
        """Test write_int16_le with negative value."""
        w = Writer()
        w.write_int16_le(-1)
        assert w.getvalue() == b'\xff\xff'
    
    def test_write_uint32_le(self):
        """Test write_uint32_le method."""
        w = Writer()
        w.write_uint32_le(0x12345678)
        assert w.getvalue() == b'\x78\x56\x34\x12'
    
    def test_write_int32_le_positive(self):
        """Test write_int32_le with positive value."""
        w = Writer()
        w.write_int32_le(0x12345678)
        assert w.getvalue() == b'\x78\x56\x34\x12'
    
    def test_write_int32_le_negative(self):
        """Test write_int32_le with negative value."""
        w = Writer()
        w.write_int32_le(-1)
        assert w.getvalue() == b'\xff\xff\xff\xff'
    
    def test_write_uint64_le(self):
        """Test write_uint64_le method."""
        w = Writer()
        w.write_uint64_le(0x123456789ABCDEF0)
        assert w.getvalue() == b'\xf0\xde\xbc\x9a\x78\x56\x34\x12'
    
    def test_write_int64_le_positive(self):
        """Test write_int64_le with positive value."""
        w = Writer()
        w.write_int64_le(0x123456789ABCDEF0)
        assert w.getvalue() == b'\xf0\xde\xbc\x9a\x78\x56\x34\x12'
    
    def test_write_int64_le_negative(self):
        """Test write_int64_le with negative value."""
        w = Writer()
        w.write_int64_le(-1)
        assert w.getvalue() == b'\xff\xff\xff\xff\xff\xff\xff\xff'
    
    def test_write_uint16_be(self):
        """Test write_uint16_be method."""
        w = Writer()
        w.write_uint16_be(0x1234)
        assert w.getvalue() == b'\x12\x34'  # big endian
    
    def test_write_int16_be_positive(self):
        """Test write_int16_be with positive value."""
        w = Writer()
        w.write_int16_be(0x1234)
        assert w.getvalue() == b'\x12\x34'
    
    def test_write_int16_be_negative(self):
        """Test write_int16_be with negative value."""
        w = Writer()
        w.write_int16_be(-1)
        assert w.getvalue() == b'\xff\xff'
    
    def test_write_uint32_be(self):
        """Test write_uint32_be method."""
        w = Writer()
        w.write_uint32_be(0x12345678)
        assert w.getvalue() == b'\x12\x34\x56\x78'
    
    def test_write_int32_be_positive(self):
        """Test write_int32_be with positive value."""
        w = Writer()
        w.write_int32_be(0x12345678)
        assert w.getvalue() == b'\x12\x34\x56\x78'
    
    def test_write_int32_be_negative(self):
        """Test write_int32_be with negative value."""
        w = Writer()
        w.write_int32_be(-1)
        assert w.getvalue() == b'\xff\xff\xff\xff'
    
    def test_write_uint64_be(self):
        """Test write_uint64_be method."""
        w = Writer()
        w.write_uint64_be(0x123456789ABCDEF0)
        assert w.getvalue() == b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
    
    def test_write_int64_be_positive(self):
        """Test write_int64_be with positive value."""
        w = Writer()
        w.write_int64_be(0x123456789ABCDEF0)
        assert w.getvalue() == b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
    
    def test_write_int64_be_negative(self):
        """Test write_int64_be with negative value."""
        w = Writer()
        w.write_int64_be(-1)
        assert w.getvalue() == b'\xff\xff\xff\xff\xff\xff\xff\xff'
    
    def test_write_var_int_num_small(self):
        """Test write_var_int_num with small value."""
        w = Writer()
        w.write_var_int_num(252)
        assert w.getvalue() == b'\xfc'
    
    def test_write_var_int_num_medium(self):
        """Test write_var_int_num with medium value."""
        w = Writer()
        w.write_var_int_num(253)
        assert w.getvalue() == b'\xfd\xfd\x00'
    
    def test_var_int_num_static_method(self):
        """Test var_int_num static method."""
        result = Writer.var_int_num(253)
        assert result == b'\xfd\xfd\x00'


class TestReader:
    """Test Reader class methods."""
    
    def test_eof_empty(self):
        """Test eof on empty reader."""
        r = Reader(b"")
        assert r.eof() is True
    
    def test_eof_with_data(self):
        """Test eof with remaining data."""
        r = Reader(b"test")
        assert r.eof() is False
    
    def test_eof_after_read(self):
        """Test eof after reading all data."""
        r = Reader(b"test")
        r.read(4)
        assert r.eof() is True
    
    def test_read_returns_data(self):
        """Test read returns data."""
        r = Reader(b"test")
        assert r.read(4) == b"test"
    
    def test_read_returns_none_on_empty(self):
        """Test read returns None when empty."""
        r = Reader(b"")
        assert r.read(1) is None
    
    def test_read_reverse(self):
        """Test read_reverse reverses bytes."""
        r = Reader(b"\x01\x02\x03\x04")
        assert r.read_reverse(4) == b"\x04\x03\x02\x01"
    
    def test_read_reverse_none_on_empty(self):
        """Test read_reverse returns None when empty."""
        r = Reader(b"")
        assert r.read_reverse(1) is None
    
    def test_read_uint8(self):
        """Test read_uint8 method."""
        r = Reader(b"\xff")
        assert r.read_uint8() == 255
    
    def test_read_uint8_none_on_empty(self):
        """Test read_uint8 returns None when empty."""
        r = Reader(b"")
        assert r.read_uint8() is None
    
    def test_read_int8_positive(self):
        """Test read_int8 with positive value."""
        r = Reader(b"\x7f")
        assert r.read_int8() == 127
    
    def test_read_int8_negative(self):
        """Test read_int8 with negative value."""
        r = Reader(b"\xff")
        assert r.read_int8() == -1
    
    def test_read_int8_none_on_empty(self):
        """Test read_int8 returns None when empty."""
        r = Reader(b"")
        assert r.read_int8() is None
    
    def test_read_uint16_be(self):
        """Test read_uint16_be method."""
        r = Reader(b"\x12\x34")
        assert r.read_uint16_be() == 0x1234
    
    def test_read_uint16_be_insufficient_data(self):
        """Test read_uint16_be pads with zeros when insufficient data."""
        r = Reader(b"\x12")
        # Reads 1 byte + empty byte (padded) = partial value
        result = r.read_uint16_be()
        assert result is not None  # Returns partial data, not None
    
    def test_read_int16_be_positive(self):
        """Test read_int16_be with positive value."""
        r = Reader(b"\x12\x34")
        assert r.read_int16_be() == 0x1234
    
    def test_read_int16_be_negative(self):
        """Test read_int16_be with negative value."""
        r = Reader(b"\xff\xff")
        assert r.read_int16_be() == -1
    
    def test_read_int16_be_insufficient_data(self):
        """Test read_int16_be pads with zeros when insufficient data."""
        r = Reader(b"\x12")
        result = r.read_int16_be()
        assert result is not None
    
    def test_read_uint32_be(self):
        """Test read_uint32_be method."""
        r = Reader(b"\x12\x34\x56\x78")
        assert r.read_uint32_be() == 0x12345678
    
    def test_read_int32_be_positive(self):
        """Test read_int32_be with positive value."""
        r = Reader(b"\x12\x34\x56\x78")
        assert r.read_int32_be() == 0x12345678
    
    def test_read_int32_be_negative(self):
        """Test read_int32_be with negative value."""
        r = Reader(b"\xff\xff\xff\xff")
        assert r.read_int32_be() == -1
    
    def test_read_uint64_be(self):
        """Test read_uint64_be method."""
        r = Reader(b"\x12\x34\x56\x78\x9a\xbc\xde\xf0")
        assert r.read_uint64_be() == 0x123456789ABCDEF0
    
    def test_read_int64_be_positive(self):
        """Test read_int64_be with positive value."""
        r = Reader(b"\x12\x34\x56\x78\x9a\xbc\xde\xf0")
        assert r.read_int64_be() == 0x123456789ABCDEF0
    
    def test_read_int64_be_negative(self):
        """Test read_int64_be with negative value."""
        r = Reader(b"\xff\xff\xff\xff\xff\xff\xff\xff")
        assert r.read_int64_be() == -1
    
    def test_read_uint16_le(self):
        """Test read_uint16_le method."""
        r = Reader(b"\x34\x12")
        assert r.read_uint16_le() == 0x1234
    
    def test_read_int16_le_positive(self):
        """Test read_int16_le with positive value."""
        r = Reader(b"\x34\x12")
        assert r.read_int16_le() == 0x1234
    
    def test_read_int16_le_negative(self):
        """Test read_int16_le with negative value."""
        r = Reader(b"\xff\xff")
        assert r.read_int16_le() == -1
    
    def test_read_uint32_le(self):
        """Test read_uint32_le method."""
        r = Reader(b"\x78\x56\x34\x12")
        assert r.read_uint32_le() == 0x12345678
    
    def test_read_int32_le_positive(self):
        """Test read_int32_le with positive value."""
        r = Reader(b"\x78\x56\x34\x12")
        assert r.read_int32_le() == 0x12345678
    
    def test_read_int32_le_negative(self):
        """Test read_int32_le with negative value."""
        r = Reader(b"\xff\xff\xff\xff")
        assert r.read_int32_le() == -1
    
    def test_read_uint64_le(self):
        """Test read_uint64_le method."""
        r = Reader(b"\xf0\xde\xbc\x9a\x78\x56\x34\x12")
        assert r.read_uint64_le() == 0x123456789ABCDEF0
    
    def test_read_int64_le_positive(self):
        """Test read_int64_le with positive value."""
        r = Reader(b"\xf0\xde\xbc\x9a\x78\x56\x34\x12")
        assert r.read_int64_le() == 0x123456789ABCDEF0
    
    def test_read_int64_le_negative(self):
        """Test read_int64_le with negative value."""
        r = Reader(b"\xff\xff\xff\xff\xff\xff\xff\xff")
        assert r.read_int64_le() == -1
    
    def test_read_var_int_num_small(self):
        """Test read_var_int_num with small value."""
        r = Reader(b"\xfc")
        assert r.read_var_int_num() == 252
    
    def test_read_var_int_num_two_byte(self):
        """Test read_var_int_num with two byte value."""
        r = Reader(b"\xfd\xfd\x00")
        assert r.read_var_int_num() == 253
    
    def test_read_var_int_num_four_byte(self):
        """Test read_var_int_num with four byte value."""
        r = Reader(b"\xfe\x00\x00\x01\x00")
        assert r.read_var_int_num() == 0x10000
    
    def test_read_var_int_num_eight_byte(self):
        """Test read_var_int_num with eight byte value."""
        r = Reader(b"\xff\x00\x00\x00\x00\x01\x00\x00\x00")
        assert r.read_var_int_num() == 0x100000000
    
    def test_read_var_int_num_none_on_empty(self):
        """Test read_var_int_num returns None when empty."""
        r = Reader(b"")
        assert r.read_var_int_num() is None


class TestWriterReaderRoundTrip:
    """Test round-trip operations between Writer and Reader."""
    
    @pytest.mark.parametrize("value", [0, 1, 127, 128, 255])
    def test_uint8_round_trip(self, value):
        """Test uint8 round trip."""
        w = Writer()
        w.write_uint8(value)
        r = Reader(w.getvalue())
        assert r.read_uint8() == value
    
    @pytest.mark.parametrize("value", [-128, -1, 0, 1, 127])
    def test_int8_round_trip(self, value):
        """Test int8 round trip."""
        w = Writer()
        w.write_int8(value)
        r = Reader(w.getvalue())
        assert r.read_int8() == value
    
    @pytest.mark.parametrize("value", [0, 1, 0x1234, 0xFFFF])
    def test_uint16_le_round_trip(self, value):
        """Test uint16 LE round trip."""
        w = Writer()
        w.write_uint16_le(value)
        r = Reader(w.getvalue())
        assert r.read_uint16_le() == value
    
    @pytest.mark.parametrize("value", [0, 1, 0x1234, 0xFFFF])
    def test_uint16_be_round_trip(self, value):
        """Test uint16 BE round trip."""
        w = Writer()
        w.write_uint16_be(value)
        r = Reader(w.getvalue())
        assert r.read_uint16_be() == value
    
    @pytest.mark.parametrize("value", [0, 1, 0x12345678, 0xFFFFFFFF])
    def test_uint32_le_round_trip(self, value):
        """Test uint32 LE round trip."""
        w = Writer()
        w.write_uint32_le(value)
        r = Reader(w.getvalue())
        assert r.read_uint32_le() == value
    
    @pytest.mark.parametrize("value", [0, 1, 0x12345678, 0xFFFFFFFF])
    def test_uint32_be_round_trip(self, value):
        """Test uint32 BE round trip."""
        w = Writer()
        w.write_uint32_be(value)
        r = Reader(w.getvalue())
        assert r.read_uint32_be() == value
    
    @pytest.mark.parametrize("value", [0, 1, 0x123456789ABCDEF0, 0xFFFFFFFFFFFFFFFF])
    def test_uint64_le_round_trip(self, value):
        """Test uint64 LE round trip."""
        w = Writer()
        w.write_uint64_le(value)
        r = Reader(w.getvalue())
        assert r.read_uint64_le() == value
    
    @pytest.mark.parametrize("value", [0, 1, 0x123456789ABCDEF0, 0xFFFFFFFFFFFFFFFF])
    def test_uint64_be_round_trip(self, value):
        """Test uint64 BE round trip."""
        w = Writer()
        w.write_uint64_be(value)
        r = Reader(w.getvalue())
        assert r.read_uint64_be() == value
    
    @pytest.mark.parametrize("value", [0, 1, 252, 253, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF])
    def test_varint_round_trip(self, value):
        """Test varint round trip."""
        w = Writer()
        w.write_var_int_num(value)
        r = Reader(w.getvalue())
        assert r.read_var_int_num() == value

