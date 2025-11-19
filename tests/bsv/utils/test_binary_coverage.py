"""
Coverage tests for utils/binary.py - untested branches.
"""
import pytest
from bsv.utils.binary import (
    unsigned_to_varint, varint_to_unsigned, unsigned_to_bytes,
    to_hex, from_hex, to_bytes, to_utf8, encode, to_base64
)


# ========================================================================
# unsigned_to_varint branches
# ========================================================================

def test_unsigned_to_varint_small():
    """Test unsigned_to_varint with small value (< 0xfd)."""
    result = unsigned_to_varint(100)
    assert result == b'd'


def test_unsigned_to_varint_boundary_fc():
    """Test unsigned_to_varint with boundary value 0xfc."""
    result = unsigned_to_varint(0xfc)
    assert result == b'\xfc'
    assert len(result) == 1


def test_unsigned_to_varint_boundary_fd():
    """Test unsigned_to_varint with boundary value 0xfd."""
    result = unsigned_to_varint(0xfd)
    assert result[0] == 0xfd
    assert len(result) == 3


def test_unsigned_to_varint_medium():
    """Test unsigned_to_varint with medium value."""
    result = unsigned_to_varint(0xffff)
    assert result[0] == 0xfd


def test_unsigned_to_varint_large():
    """Test unsigned_to_varint with large value."""
    result = unsigned_to_varint(0x10000)
    assert result[0] == 0xfe


def test_unsigned_to_varint_very_large():
    """Test unsigned_to_varint with very large value."""
    result = unsigned_to_varint(0x100000000)
    assert result[0] == 0xff


def test_unsigned_to_varint_negative():
    """Test unsigned_to_varint with negative value."""
    with pytest.raises(OverflowError):
        unsigned_to_varint(-1)


def test_unsigned_to_varint_too_large():
    """Test unsigned_to_varint with value too large."""
    with pytest.raises(OverflowError):
        unsigned_to_varint(0x10000000000000000)


# ========================================================================
# varint_to_unsigned branches
# ========================================================================

def test_varint_to_unsigned_small():
    """Test varint_to_unsigned with small value."""
    value, consumed = varint_to_unsigned(b'\x42')
    assert value == 0x42
    assert consumed == 1


def test_varint_to_unsigned_empty():
    """Test varint_to_unsigned with empty data."""
    with pytest.raises(ValueError):
        varint_to_unsigned(b'')


def test_varint_to_unsigned_fd_prefix():
    """Test varint_to_unsigned with fd prefix."""
    value, consumed = varint_to_unsigned(b'\xfd\x00\x01')
    assert value == 0x100
    assert consumed == 3


def test_varint_to_unsigned_fd_insufficient():
    """Test varint_to_unsigned with fd prefix but insufficient data."""
    with pytest.raises(ValueError):
        varint_to_unsigned(b'\xfd\x00')


def test_varint_to_unsigned_fe_prefix():
    """Test varint_to_unsigned with fe prefix."""
    value, consumed = varint_to_unsigned(b'\xfe\x00\x00\x01\x00')
    assert value == 0x10000
    assert consumed == 5


def test_varint_to_unsigned_fe_insufficient():
    """Test varint_to_unsigned with fe prefix but insufficient data."""
    with pytest.raises(ValueError):
        varint_to_unsigned(b'\xfe\x00\x00')


def test_varint_to_unsigned_ff_prefix():
    """Test varint_to_unsigned with ff prefix."""
    value, consumed = varint_to_unsigned(b'\xff\x00\x00\x00\x00\x01\x00\x00\x00')
    assert value == 0x100000000
    assert consumed == 9


def test_varint_to_unsigned_ff_insufficient():
    """Test varint_to_unsigned with ff prefix but insufficient data."""
    with pytest.raises(ValueError):
        varint_to_unsigned(b'\xff\x00\x00')


# ========================================================================
# unsigned_to_bytes branches
# ========================================================================

def test_unsigned_to_bytes_zero():
    """Test unsigned_to_bytes with zero."""
    result = unsigned_to_bytes(0)
    assert result == b'\x00'


def test_unsigned_to_bytes_small():
    """Test unsigned_to_bytes with small value."""
    result = unsigned_to_bytes(255)
    assert result == b'\xff'


def test_unsigned_to_bytes_big_endian():
    """Test unsigned_to_bytes with big endian."""
    result = unsigned_to_bytes(0x1234, 'big')
    assert result == b'\x12\x34'


def test_unsigned_to_bytes_little_endian():
    """Test unsigned_to_bytes with little endian."""
    result = unsigned_to_bytes(0x1234, 'little')
    assert result == b'\x34\x12'


# ========================================================================
# to_hex / from_hex branches
# ========================================================================

def test_to_hex_empty():
    """Test to_hex with empty bytes."""
    result = to_hex(b'')
    assert result == ''


def test_to_hex_value():
    """Test to_hex with value."""
    result = to_hex(b'\x01\x02\x03')
    assert result == '010203'


def test_from_hex_empty():
    """Test from_hex with empty string."""
    result = from_hex('')
    assert result == b''


def test_from_hex_value():
    """Test from_hex with value."""
    result = from_hex('010203')
    assert result == b'\x01\x02\x03'


def test_from_hex_whitespace():
    """Test from_hex with whitespace."""
    result = from_hex('01 02 03')
    assert result == b'\x01\x02\x03'


# ========================================================================
# to_bytes branches
# ========================================================================

def test_to_bytes_with_bytes():
    """Test to_bytes with bytes input."""
    result = to_bytes(b'test')
    assert result == b'test'


def test_to_bytes_with_string():
    """Test to_bytes with string input."""
    result = to_bytes('test')
    assert result == b'test'


def test_to_bytes_with_hex():
    """Test to_bytes with hex encoding."""
    result = to_bytes('0102', 'hex')
    assert result == b'\x01\x02'


def test_to_bytes_with_base64():
    """Test to_bytes with base64 encoding."""
    result = to_bytes('dGVzdA==', 'base64')
    assert result == b'test'


# ========================================================================
# Edge cases
# ========================================================================

def test_to_utf8():
    """Test to_utf8 conversion."""
    result = to_utf8([116, 101, 115, 116])
    assert result == 'test'


def test_encode_utf8():
    """Test encode with utf8."""
    result = encode([116, 101, 115, 116], 'utf8')
    assert result == 'test'


def test_encode_hex():
    """Test encode with hex."""
    result = encode([1, 2, 3], 'hex')
    assert result == '010203'


def test_to_base64():
    """Test to_base64 conversion."""
    result = to_base64([116, 101, 115, 116])
    assert result == 'dGVzdA=='

