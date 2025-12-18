"""
Coverage tests for PushDrop parsing, lock positions, and edge cases.
"""
import pytest

from bsv.transaction.pushdrop import (
    build_pushdrop_locking_script,
    parse_pushdrop_locking_script,
    parse_identity_reveal,
    build_lock_before_pushdrop,
    create_minimally_encoded_script_chunk,
    _create_lock_chunks,
    _create_pushdrop_chunks,
    _arrange_chunks_by_position,
    _convert_chunks_to_bytes
)


def test_parse_pushdrop_locking_script_basic():
    """Test basic PushDrop parsing."""
    fields = [b"field1", b"field2"]
    script = build_pushdrop_locking_script(fields)

    parsed = parse_pushdrop_locking_script(script)
    assert parsed == fields


def test_parse_pushdrop_locking_script_empty():
    """Test parsing empty PushDrop script."""
    script = build_pushdrop_locking_script([])
    parsed = parse_pushdrop_locking_script(script)

    assert parsed == []


def test_parse_pushdrop_locking_script_invalid():
    """Test parsing invalid PushDrop script."""
    # Script without OP_TRUE at end
    invalid_script = b'\x00\x75'  # OP_0 OP_DROP (no OP_TRUE)
    parsed = parse_pushdrop_locking_script(invalid_script)

    assert parsed == []


def test_parse_identity_reveal_success():
    """Test parse_identity_reveal with valid data."""
    fields = [b"identity.reveal", b"name", b"John Doe", b"email", b"john@example.com"]
    script = build_pushdrop_locking_script(fields)

    parsed_script = parse_pushdrop_locking_script(script)
    result = parse_identity_reveal(parsed_script)

    expected = [("name", "John Doe"), ("email", "john@example.com")]
    assert result == expected


def test_parse_identity_reveal_wrong_prefix():
    """Test parse_identity_reveal with wrong prefix."""
    fields = [b"wrong.prefix", b"name", b"John Doe"]
    script = build_pushdrop_locking_script(fields)

    parsed_script = parse_pushdrop_locking_script(script)
    result = parse_identity_reveal(parsed_script)

    assert result == []


def test_parse_identity_reveal_empty():
    """Test parse_identity_reveal with empty fields."""
    fields = []
    result = parse_identity_reveal(fields)

    assert result == []


def test_parse_identity_reveal_odd_fields():
    """Test parse_identity_reveal with odd number of fields after prefix."""
    fields = [b"identity.reveal", b"name"]  # Missing value
    result = parse_identity_reveal(fields)

    assert result == []


def test_parse_identity_reveal_non_utf8():
    """Test parse_identity_reveal with non-UTF-8 data."""
    fields = [b"identity.reveal", b'\xff\xfe', b'value']  # Invalid UTF-8
    result = parse_identity_reveal(fields)

    # Should handle the exception gracefully
    assert result == []


def test_build_lock_before_pushdrop_lock_before():
    """Test build_lock_before_pushdrop with lock_position='before'."""
    fields = [b"data1", b"data2"]
    pubkey = b'\x02' + b'\x00' * 32  # Compressed pubkey

    script = build_lock_before_pushdrop(fields, pubkey, lock_position="before")

    # Should contain OP_CHECKSIG before the pushdrop data
    assert 'ac' in script  # OP_CHECKSIG
    assert len(script) > 0


def test_build_lock_before_pushdrop_lock_after():
    """Test build_lock_before_pushdrop with lock_position='after'."""
    fields = [b"data1", b"data2"]
    pubkey = b'\x02' + b'\x00' * 32

    script = build_lock_before_pushdrop(fields, pubkey, lock_position="after")

    # Should contain OP_CHECKSIG at the end
    assert script.endswith('ac')  # OP_CHECKSIG
    assert len(script) > 0


def test_build_lock_before_pushdrop_with_signature():
    """Test build_lock_before_pushdrop with signature included."""
    fields = [b"data1"]
    pubkey = b'\x02' + b'\x00' * 32
    signature = b'signature_data'

    script = build_lock_before_pushdrop(
        fields, pubkey, include_signature=True, signature=signature
    )

    # Should be longer due to signature
    assert len(script) > 0


def test_create_minimally_encoded_script_chunk_empty():
    """Test create_minimally_encoded_script_chunk with empty data."""
    result = create_minimally_encoded_script_chunk(b'')
    assert result == '00'  # OP_0


def test_create_minimally_encoded_script_chunk_single_byte():
    """Test create_minimally_encoded_script_chunk with single byte."""
    # Test OP_0 for 0x00
    result = create_minimally_encoded_script_chunk(b'\x00')
    assert result == '00'  # OP_0

    # Test OP_1NEGATE for 0x81
    result = create_minimally_encoded_script_chunk(b'\x81')
    assert result == '4f'  # OP_1NEGATE

    # Test OP_1 to OP_16
    result = create_minimally_encoded_script_chunk(b'\x01')
    assert result == '51'  # OP_1


def test_create_minimally_encoded_script_chunk_large():
    """Test create_minimally_encoded_script_chunk with large data."""
    data = b'x' * 100
    result = create_minimally_encoded_script_chunk(data)

    # Should use OP_PUSHDATA
    assert len(result) > len(data) * 2  # Hex encoding + overhead


def test_parse_pushdrop_invalid_pushdata():
    """Test parsing PushDrop with invalid pushdata."""
    # Create script with invalid pushdata length
    script = b'\x4c\x05\x00\x00'  # OP_PUSHDATA1 with length 5 but only 2 bytes
    parsed = parse_pushdrop_locking_script(script)

    assert parsed == []


def test_build_lock_before_pushdrop_empty_fields():
    """Test build_lock_before_pushdrop with empty fields."""
    pubkey = b'\x02' + b'\x00' * 32
    script = build_lock_before_pushdrop([], pubkey)

    assert len(script) > 0


def test_arrange_chunks_by_position_before():
    """Test _arrange_chunks_by_position with 'before'."""
    lock_chunks = [b'lock']
    pushdrop_chunks = [b'data1', b'data2']

    result = _arrange_chunks_by_position(lock_chunks, pushdrop_chunks, "before")

    assert result == [b'lock', b'data1', b'data2']


def test_arrange_chunks_by_position_after():
    """Test _arrange_chunks_by_position with 'after'."""
    lock_chunks = [b'lock']
    pushdrop_chunks = [b'data1', b'data2']

    result = _arrange_chunks_by_position(lock_chunks, pushdrop_chunks, "after")

    assert result == [b'data1', b'data2', b'lock']


def test_convert_chunks_to_bytes_mixed():
    """Test _convert_chunks_to_bytes with mixed chunk types."""
    from bsv.constants import OpCode

    chunks = [b'data', OpCode.OP_DROP, b'more_data']

    result = _convert_chunks_to_bytes(chunks)

    assert isinstance(result, list)
    assert len(result) == 3
    assert result[0] == b'data'
    assert result[1] == OpCode.OP_DROP
    assert result[2] == b'more_data'


def test_create_pushdrop_chunks_with_signature():
    """Test _create_pushdrop_chunks with signature."""
    fields = [b'data1']
    signature = b'sig'

    result = _create_pushdrop_chunks(fields, True, signature)

    # Should include signature and proper DROP operations
    assert len(result) > 0


def test_create_lock_chunks():
    """Test _create_lock_chunks."""
    pubkey = b'\x02' + b'\x00' * 32

    result = _create_lock_chunks(pubkey)

    assert len(result) == 2  # pubkey + OP_CHECKSIG
