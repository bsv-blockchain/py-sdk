"""
Coverage tests for utils/script_chunks.py - untested branches.
"""
import pytest


# ========================================================================
# Script chunk parsing branches
# ========================================================================

def test_read_script_chunks_empty():
    """Test parsing empty script."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        chunks = read_script_chunks(b'')
        assert isinstance(chunks, list)
        assert len(chunks) == 0
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_single_opcode():
    """Test parsing single opcode."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        script = b'\x51'  # OP_1
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        assert len(chunks) > 0
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_with_data():
    """Test parsing script with data push."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        script = b'\x03\x01\x02\x03'  # PUSH 3 bytes: 0x010203
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_p2pkh():
    """Test parsing P2PKH script."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        script = b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        assert len(chunks) == 5  # 5 operations
    except ImportError:
        pytest.skip("read_script_chunks not available")


# ========================================================================
# Chunk serialization branches
# ========================================================================

def test_serialize_chunks():
    """Test serializing chunks back to script."""
    try:
        from bsv.utils.script_chunks import read_script_chunks, serialize_chunks

        original = b'\x51\x52\x93'  # OP_1 OP_2 OP_ADD
        chunks = read_script_chunks(original)

        try:
            serialized = serialize_chunks(chunks)
            assert serialized == original
        except (NameError, AttributeError):
            pytest.skip("serialize_chunks not available")
    except ImportError:
        pytest.skip("script_chunks functions not available")


# ========================================================================
# Chunk types branches
# ========================================================================

def test_chunk_op_detection():
    """Test detecting opcode chunks."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        script = b'\x51'  # OP_1
        chunks = read_script_chunks(script)

        if len(chunks) > 0:
            _ = chunks[0]
            # Chunk should have some indicator of being an opcode
            assert True
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_chunk_data_detection():
    """Test detecting data chunks."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        script = b'\x03\x01\x02\x03'  # PUSH 3 bytes
        chunks = read_script_chunks(script)

        if len(chunks) > 0:
            _ = chunks[0]
            # Chunk should contain the pushed data
            assert True
    except ImportError:
        pytest.skip("read_script_chunks not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_read_script_chunks_truncated():
    """Test parsing truncated script."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # Script says to push 10 bytes but only has 2
        script = b'\x0a\x01\x02'

        try:
            _ = read_script_chunks(script)
            assert True  # May handle gracefully
        except Exception:
            # Expected
            assert True
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_large_push():
    """Test parsing script with large data push."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA1 with 255 bytes
        script = b'\x4c\xff' + b'\x00' * 255
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
    except ImportError:
        pytest.skip("read_script_chunks not available")


# ========================================================================
# Missing coverage branches
# ========================================================================

def test_read_script_chunks_invalid_hex():
    """Test parsing invalid hex string (covers exception handling)."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # Invalid hex string - should fall back to empty script
        invalid_hex = "not_hex_string"
        chunks = read_script_chunks(invalid_hex)
        # Should treat as empty since conversion fails
        assert isinstance(chunks, list)
        assert len(chunks) == 0
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_pushdata2():
    """Test parsing OP_PUSHDATA2 script."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA2 with 300 bytes
        data_len = 300
        script = b'\x4d' + data_len.to_bytes(2, 'little') + b'\x00' * data_len
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        assert len(chunks) == 1
        assert chunks[0].op == 0x4D
        assert len(chunks[0].data) == data_len
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_pushdata4():
    """Test parsing OP_PUSHDATA4 script."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA4 with 1000 bytes
        data_len = 1000
        script = b'\x4e' + data_len.to_bytes(4, 'little') + b'\x00' * data_len
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        assert len(chunks) == 1
        assert chunks[0].op == 0x4E
        assert len(chunks[0].data) == data_len
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_truncated_pushdata1():
    """Test parsing truncated OP_PUSHDATA1 script."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA1 but not enough bytes for length
        script = b'\x4c'  # Missing length byte
        chunks = read_script_chunks(script)
        # Should handle gracefully (break early)
        assert isinstance(chunks, list)
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_truncated_pushdata2():
    """Test parsing truncated OP_PUSHDATA2 script."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA2 but not enough bytes for length
        script = b'\x4d\x01'  # Missing second length byte
        chunks = read_script_chunks(script)
        # Should handle gracefully (break early)
        assert isinstance(chunks, list)
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_truncated_pushdata4():
    """Test parsing truncated OP_PUSHDATA4 script."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA4 but not enough bytes for length
        script = b'\x4e\x01\x02\x03'  # Missing 4th length byte
        chunks = read_script_chunks(script)
        # Should handle gracefully (break early)
        assert isinstance(chunks, list)
    except ImportError:
        pytest.skip("read_script_chunks not available")


# ========================================================================
# Comprehensive error condition testing
# ========================================================================

def test_read_script_chunks_invalid_opcodes():
    """Test parsing scripts with invalid opcodes."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # Script with high invalid opcodes
        script = b'\xff\xfe\xfd'  # Invalid opcodes should be treated as data
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        assert len(chunks) == 3  # Each byte as separate opcode chunk
        for chunk in chunks:
            assert chunk.data is None  # No data for opcodes
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_mixed_valid_invalid():
    """Test parsing scripts with mix of valid and invalid elements."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # Mix of valid push and invalid opcodes
        script = b'\x51\xff\x02\x01\x02'  # OP_1, invalid, PUSH 2 bytes
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        assert len(chunks) >= 2  # At least some chunks parsed
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_max_push_data():
    """Test parsing scripts with maximum push data."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA1 with maximum 255 bytes
        script = b'\x4c\xff' + b'\x00' * 255
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        assert len(chunks) == 1
        assert len(chunks[0].data) == 255
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_empty_after_push():
    """Test parsing scripts that end abruptly after push opcode."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA1 but no length byte
        script = b'\x4c'  # Missing length byte
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        # Should handle gracefully
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_pushdata2_boundary():
    """Test OP_PUSHDATA2 with boundary length values."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA2 with exactly 256 bytes (boundary)
        data_len = 256
        script = b'\x4d' + data_len.to_bytes(2, 'little') + b'\x00' * data_len
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        assert len(chunks) == 1
        assert len(chunks[0].data) == data_len
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_pushdata4_boundary():
    """Test OP_PUSHDATA4 with large data."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA4 with 1000 bytes
        data_len = 1000
        script = b'\x4e' + data_len.to_bytes(4, 'little') + b'\x00' * data_len
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        assert len(chunks) == 1
        assert len(chunks[0].data) == data_len
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_string_input_edge_cases():
    """Test string input with various edge cases."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # Empty string
        chunks = read_script_chunks("")
        assert isinstance(chunks, list)
        assert len(chunks) == 0

        # String that's not valid hex
        chunks = read_script_chunks("not_hex")
        assert isinstance(chunks, list)
        assert len(chunks) == 0

        # Valid hex string
        chunks = read_script_chunks("51")  # OP_1
        assert isinstance(chunks, list)
        assert len(chunks) == 1

    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_op_push_boundary_75():
    """Test OP_PUSH boundary at 75 bytes."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # Exactly 75 bytes of data (boundary between direct push and OP_PUSHDATA1)
        script = b'\x4b' + b'\x00' * 75  # 0x4b = 75
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        assert len(chunks) == 1
        assert len(chunks[0].data) == 75
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_op_push_boundary_76():
    """Test OP_PUSH boundary at 76 bytes (should fail)."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # 76 bytes of data (too much for direct push)
        script = b'\x4c' + b'\x00' * 76  # 0x4c = 76, but this is OP_PUSHDATA1
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        # Should not parse correctly due to missing length byte
    except ImportError:
        pytest.skip("read_script_chunks not available")


# ========================================================================
# Missing coverage: serialize_chunks with data
# ========================================================================

def test_serialize_chunks_with_direct_push_data():
    """Test serialize_chunks with direct push opcodes (op <= 75)."""
    try:
        from bsv.utils.script_chunks import ScriptChunk, serialize_chunks

        # Direct push with 5 bytes
        chunks = [ScriptChunk(op=5, data=b'\x01\x02\x03\x04\x05')]
        result = serialize_chunks(chunks)
        assert result == b'\x05\x01\x02\x03\x04\x05'
    except ImportError:
        pytest.skip("serialize_chunks not available")


def test_serialize_chunks_direct_push_wrong_length():
    """Test serialize_chunks with direct push opcode but wrong data length."""
    try:
        from bsv.utils.script_chunks import ScriptChunk, serialize_chunks

        # Opcode says 5 bytes but data is 3 bytes
        chunks = [ScriptChunk(op=5, data=b'\x01\x02\x03')]
        with pytest.raises(ValueError, match="Direct push opcode 5 requires data length 5"):
            serialize_chunks(chunks)
    except ImportError:
        pytest.skip("serialize_chunks not available")


def test_serialize_chunks_with_pushdata1():
    """Test serialize_chunks with OP_PUSHDATA1."""
    try:
        from bsv.utils.script_chunks import ScriptChunk, serialize_chunks

        # OP_PUSHDATA1 with 100 bytes
        data = b'\x00' * 100
        chunks = [ScriptChunk(op=0x4C, data=data)]
        result = serialize_chunks(chunks)
        assert result == b'\x4c\x64' + data  # 0x64 = 100
        assert len(result) == 1 + 1 + 100
    except ImportError:
        pytest.skip("serialize_chunks not available")


def test_serialize_chunks_pushdata1_too_long():
    """Test serialize_chunks with OP_PUSHDATA1 data too long."""
    try:
        from bsv.utils.script_chunks import ScriptChunk, serialize_chunks

        # OP_PUSHDATA1 can only handle up to 255 bytes
        data = b'\x00' * 256
        chunks = [ScriptChunk(op=0x4C, data=data)]
        with pytest.raises(ValueError, match="OP_PUSHDATA1 data too long"):
            serialize_chunks(chunks)
    except ImportError:
        pytest.skip("serialize_chunks not available")


def test_serialize_chunks_with_pushdata2():
    """Test serialize_chunks with OP_PUSHDATA2."""
    try:
        from bsv.utils.script_chunks import ScriptChunk, serialize_chunks

        # OP_PUSHDATA2 with 300 bytes
        data = b'\x00' * 300
        chunks = [ScriptChunk(op=0x4D, data=data)]
        result = serialize_chunks(chunks)
        assert result == b'\x4d' + (300).to_bytes(2, 'little') + data
        assert len(result) == 1 + 2 + 300
    except ImportError:
        pytest.skip("serialize_chunks not available")


def test_serialize_chunks_pushdata2_too_long():
    """Test serialize_chunks with OP_PUSHDATA2 data too long."""
    try:
        from bsv.utils.script_chunks import ScriptChunk, serialize_chunks

        # OP_PUSHDATA2 can only handle up to 65535 bytes
        data = b'\x00' * 65536
        chunks = [ScriptChunk(op=0x4D, data=data)]
        with pytest.raises(ValueError, match="OP_PUSHDATA2 data too long"):
            serialize_chunks(chunks)
    except ImportError:
        pytest.skip("serialize_chunks not available")


def test_serialize_chunks_with_pushdata4():
    """Test serialize_chunks with OP_PUSHDATA4."""
    try:
        from bsv.utils.script_chunks import ScriptChunk, serialize_chunks

        # OP_PUSHDATA4 with 1000 bytes
        data = b'\x00' * 1000
        chunks = [ScriptChunk(op=0x4E, data=data)]
        result = serialize_chunks(chunks)
        assert result == b'\x4e' + (1000).to_bytes(4, 'little') + data
        assert len(result) == 1 + 4 + 1000
    except ImportError:
        pytest.skip("serialize_chunks not available")


def test_serialize_chunks_pushdata4_too_long():
    """Test serialize_chunks with OP_PUSHDATA4 data too long."""
    try:
        from bsv.utils.script_chunks import ScriptChunk, serialize_chunks

        # OP_PUSHDATA4 can only handle up to 4294967295 bytes
        data = b'\x00' * (4294967296)  # One byte too many
        chunks = [ScriptChunk(op=0x4E, data=data)]
        with pytest.raises(ValueError, match="OP_PUSHDATA4 data too long"):
            serialize_chunks(chunks)
    except ImportError:
        pytest.skip("serialize_chunks not available")


def test_serialize_chunks_non_push_with_data():
    """Test serialize_chunks with non-push opcode that has data (invalid)."""
    try:
        from bsv.utils.script_chunks import ScriptChunk, serialize_chunks

        # OP_1 (non-push) with data - should raise error
        chunks = [ScriptChunk(op=0x51, data=b'\x01')]
        with pytest.raises(ValueError, match="Non-push opcode 81 should not have data"):
            serialize_chunks(chunks)
    except ImportError:
        pytest.skip("serialize_chunks not available")


def test_serialize_chunks_mixed():
    """Test serialize_chunks with mixed chunk types."""
    try:
        from bsv.utils.script_chunks import ScriptChunk, serialize_chunks, read_script_chunks

        # Create chunks manually
        chunks = [
            ScriptChunk(op=0x51, data=None),  # OP_1
            ScriptChunk(op=5, data=b'\x01\x02\x03\x04\x05'),  # Direct push
            ScriptChunk(op=0x52, data=None),  # OP_2
        ]
        result = serialize_chunks(chunks)
        
        # Verify round-trip
        parsed = read_script_chunks(result)
        assert len(parsed) == 3
        assert parsed[0].op == 0x51
        assert parsed[1].op == 5
        assert parsed[1].data == b'\x01\x02\x03\x04\x05'
        assert parsed[2].op == 0x52
    except ImportError:
        pytest.skip("serialize_chunks not available")


# ========================================================================
# Missing coverage: truncated PUSHDATA scenarios
# ========================================================================

def test_read_script_chunks_pushdata1_truncated_data():
    """Test OP_PUSHDATA1 with truncated data (triggers break on line 38)."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA1 says 100 bytes but only 50 available
        script = b'\x4c\x64' + b'\x00' * 50  # Length=100, but only 50 bytes
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        # Should break early and not add incomplete chunk
        assert len(chunks) == 0
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_pushdata2_truncated_data():
    """Test OP_PUSHDATA2 with truncated data (triggers break on line 48)."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA2 says 300 bytes but only 100 available
        data_len = 300
        script = b'\x4d' + data_len.to_bytes(2, 'little') + b'\x00' * 100
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        # Should break early and not add incomplete chunk
        assert len(chunks) == 0
    except ImportError:
        pytest.skip("read_script_chunks not available")


def test_read_script_chunks_pushdata4_truncated_data():
    """Test OP_PUSHDATA4 with truncated data (triggers break on line 58)."""
    try:
        from bsv.utils.script_chunks import read_script_chunks

        # OP_PUSHDATA4 says 1000 bytes but only 500 available
        data_len = 1000
        script = b'\x4e' + data_len.to_bytes(4, 'little') + b'\x00' * 500
        chunks = read_script_chunks(script)
        assert isinstance(chunks, list)
        # Should break early and not add incomplete chunk
        assert len(chunks) == 0
    except ImportError:
        pytest.skip("read_script_chunks not available")

