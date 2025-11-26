"""
Coverage tests for wallet/substrates/serializer.py - untested branches.
"""
import pytest
from unittest.mock import Mock
from bsv.wallet.substrates.serializer import (
    Writer, Reader,
    serialize_create_action_args, deserialize_create_action_args,
    serialize_sign_action_args, deserialize_sign_action_args,
    serialize_list_actions_args, deserialize_list_actions_args,
    serialize_encrypt_args, deserialize_encrypt_args,
    serialize_decrypt_args, deserialize_decrypt_args,
    encode_outpoint, decode_outpoint,
    encode_privileged_params
)


# ========================================================================
# Writer branches
# ========================================================================

def test_writer_write_byte():
    """Test Writer write_byte."""
    w = Writer()
    w.write_byte(42)
    assert w.buf[0] == 42


def test_writer_write_bytes():
    """Test Writer write_bytes."""
    w = Writer()
    w.write_bytes(b'\x01\x02')
    assert w.buf == bytearray(b'\x01\x02')


def test_writer_write_varint_small():
    """Test Writer write_varint with small value."""
    w = Writer()
    w.write_varint(100)
    assert w.buf[0] == 100


def test_writer_write_varint_large():
    """Test Writer write_varint with large value."""
    w = Writer()
    w.write_varint(0x10000)
    assert w.buf[0] == 0xfe


def test_writer_write_optional_uint32_none():
    """Test Writer write_optional_uint32 with None."""
    w = Writer()
    w.write_optional_uint32(None)
    assert w.buf[0] == 0xff


def test_writer_write_optional_uint32_value():
    """Test Writer write_optional_uint32 with value."""
    w = Writer()
    w.write_optional_uint32(42)
    assert w.buf[0] == 42


def test_writer_write_optional_bytes_none():
    """Test Writer write_optional_bytes with None."""
    w = Writer()
    w.write_optional_bytes(None)
    assert w.buf[0] == 0xff


def test_writer_write_optional_bytes_value():
    """Test Writer write_optional_bytes with value."""
    w = Writer()
    w.write_optional_bytes(b'\x01\x02')
    assert w.buf[0] == 2


def test_writer_write_optional_bool_none():
    """Test Writer write_optional_bool with None."""
    w = Writer()
    w.write_optional_bool(None)
    assert w.buf[0] == 0xff


def test_writer_write_optional_bool_true():
    """Test Writer write_optional_bool with True."""
    w = Writer()
    w.write_optional_bool(True)
    assert w.buf[0] == 1


def test_writer_write_optional_bool_false():
    """Test Writer write_optional_bool with False."""
    w = Writer()
    w.write_optional_bool(False)
    assert w.buf[0] == 0


# ========================================================================
# Reader branches
# ========================================================================

def test_reader_read_byte():
    """Test Reader read_byte."""
    r = Reader(b'\x42')
    assert r.read_byte() == 0x42


def test_reader_read_bytes():
    """Test Reader read_bytes."""
    r = Reader(b'\x01\x02\x03')
    assert r.read_bytes(2) == b'\x01\x02'


def test_reader_read_varint_small():
    """Test Reader read_varint with small value."""
    r = Reader(b'\x42')
    assert r.read_varint() == 0x42


def test_reader_read_varint_large():
    """Test Reader read_varint with ff prefix."""
    r = Reader(b'\xff\x00\x00\x00\x00\x01\x00\x00\x00')
    assert r.read_varint() == 0x100000000


def test_reader_read_optional_uint32_nil():
    """Test Reader read_optional_uint32 with nil marker."""
    # Nil marker is a full varint of 0xFFFFFFFFFFFFFFFF
    r = Reader(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff')
    assert r.read_optional_uint32() is None


def test_reader_read_optional_uint32_value():
    """Test Reader read_optional_uint32 with value."""
    r = Reader(b'\x42')
    assert r.read_optional_uint32() == 0x42


def test_reader_read_optional_bytes_nil():
    """Test Reader read_optional_bytes with nil marker."""
    # Nil marker is a full varint of 0xFFFFFFFFFFFFFFFF
    r = Reader(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff')
    assert r.read_optional_bytes() is None


def test_reader_read_optional_bytes_value():
    """Test Reader read_optional_bytes with value."""
    r = Reader(b'\x02\x01\x02')
    result = r.read_optional_bytes()
    assert result == b'\x01\x02'


def test_reader_read_optional_bool_nil():
    """Test Reader read_optional_bool with nil marker."""
    r = Reader(b'\xff')
    assert r.read_optional_bool() is None


def test_reader_read_optional_bool_true():
    """Test Reader read_optional_bool with True."""
    r = Reader(b'\x01')
    assert r.read_optional_bool() is True


def test_reader_read_optional_bool_false():
    """Test Reader read_optional_bool with False."""
    r = Reader(b'\x00')
    assert r.read_optional_bool() is False


def test_reader_eof():
    """Test Reader EOF detection."""
    r = Reader(b'\x01')
    r.read_byte()
    assert r.is_complete()


# ========================================================================
# encode_outpoint branches
# ========================================================================

def test_encode_outpoint_string():
    """Test encode_outpoint with string txid.vout format."""
    result = encode_outpoint("abc123.0")
    assert isinstance(result, bytes)


def test_encode_outpoint_dict():
    """Test encode_outpoint with dict format."""
    result = encode_outpoint({"txid": "abc123", "vout": 0})
    assert isinstance(result, bytes)


def test_encode_outpoint_bytes():
    """Test encode_outpoint with raw bytes."""
    result = encode_outpoint(b'\x00' * 36)
    assert isinstance(result, bytes)


# ========================================================================
# serialize/deserialize roundtrips
# ========================================================================

def test_create_action_roundtrip():
    """Test serialize/deserialize create_action_args roundtrip."""
    args = {"description": "test", "outputs": []}
    serialized = serialize_create_action_args(args)
    deserialized = deserialize_create_action_args(serialized)
    assert "description" in deserialized


@pytest.mark.skip(reason="serialize_sign_action_args not yet implemented")
def test_sign_action_roundtrip():
    """Test serialize/deserialize sign_action_args roundtrip."""
    args = {"spends": {}}
    serialized = serialize_sign_action_args(args)
    deserialized = deserialize_sign_action_args(serialized)
    assert "spends" in deserialized


@pytest.mark.skip(reason="serialize_list_actions_args not yet implemented")
def test_list_actions_roundtrip():
    """Test serialize/deserialize list_actions_args roundtrip."""
    args = {}
    serialized = serialize_list_actions_args(args)
    deserialized = deserialize_list_actions_args(serialized)
    assert isinstance(deserialized, dict)


def test_encrypt_roundtrip():
    """Test serialize/deserialize encrypt_args roundtrip."""
    args = {"plaintext": b'test', "protocolID": [0, "test"], "keyID": "key1"}
    serialized = serialize_encrypt_args(args)
    deserialized = deserialize_encrypt_args(serialized)
    assert "plaintext" in deserialized


def test_decrypt_roundtrip():
    """Test serialize/deserialize decrypt_args roundtrip."""
    args = {"ciphertext": b'test', "protocolID": [0, "test"], "keyID": "key1"}
    serialized = serialize_decrypt_args(args)
    deserialized = deserialize_decrypt_args(serialized)
    assert "ciphertext" in deserialized


# ========================================================================
# Edge cases
# ========================================================================

def test_encode_privileged_params_true():
    """Test encode_privileged_params with True."""
    result = encode_privileged_params(True, "test reason")
    assert isinstance(result, bytes)


def test_encode_privileged_params_false():
    """Test encode_privileged_params with False."""
    result = encode_privileged_params(False, "test reason")
    assert isinstance(result, bytes)


def test_encode_privileged_params_none():
    """Test encode_privileged_params with None."""
    result = encode_privileged_params(None, "")
    assert isinstance(result, bytes)


def test_decode_outpoint():
    """Test decode_outpoint."""
    w = Writer()
    w.write_bytes(b'\x00' * 32)
    w.write_varint(0)
    r = Reader(w.to_bytes())
    result = decode_outpoint(r)
    assert isinstance(result, str)

