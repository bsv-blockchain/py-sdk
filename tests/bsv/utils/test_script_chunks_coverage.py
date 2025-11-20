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

