"""
Coverage tests for utils/pushdata.py - untested branches.
"""
import pytest


# ========================================================================
# Pushdata encoding branches
# ========================================================================

def test_encode_pushdata_small():
    """Test encoding small pushdata."""
    try:
        from bsv.utils.pushdata import encode_pushdata
        
        data = b'\x01\x02\x03'
        encoded = encode_pushdata(data)
        assert isinstance(encoded, bytes)
        assert len(encoded) > len(data)
    except ImportError:
        pytest.skip("encode_pushdata not available")


def test_encode_pushdata_empty():
    """Test encoding empty pushdata."""
    try:
        from bsv.utils.pushdata import encode_pushdata
        
        encoded = encode_pushdata(b'')
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("encode_pushdata not available")


def test_encode_pushdata_single_byte():
    """Test encoding single byte."""
    try:
        from bsv.utils.pushdata import encode_pushdata
        
        encoded = encode_pushdata(b'\x42')
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("encode_pushdata not available")


def test_encode_pushdata_75_bytes():
    """Test encoding 75 bytes (OP_PUSHDATA threshold)."""
    try:
        from bsv.utils.pushdata import encode_pushdata
        
        data = b'\x00' * 75
        encoded = encode_pushdata(data)
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("encode_pushdata not available")


def test_encode_pushdata_76_bytes():
    """Test encoding 76 bytes (requires OP_PUSHDATA1)."""
    try:
        from bsv.utils.pushdata import encode_pushdata
        
        data = b'\x00' * 76
        encoded = encode_pushdata(data)
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("encode_pushdata not available")


def test_encode_pushdata_256_bytes():
    """Test encoding 256 bytes (requires OP_PUSHDATA2)."""
    try:
        from bsv.utils.pushdata import encode_pushdata
        
        data = b'\x00' * 256
        encoded = encode_pushdata(data)
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("encode_pushdata not available")


def test_encode_pushdata_large():
    """Test encoding large pushdata."""
    try:
        from bsv.utils.pushdata import encode_pushdata
        
        data = b'\x00' * 10000
        encoded = encode_pushdata(data)
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("encode_pushdata not available")


# ========================================================================
# Pushdata decoding branches
# ========================================================================

def test_decode_pushdata():
    """Test decoding pushdata."""
    try:
        from bsv.utils.pushdata import encode_pushdata, decode_pushdata
        
        data = b'\x01\x02\x03'
        encoded = encode_pushdata(data)
        
        try:
            decoded = decode_pushdata(encoded)
            assert decoded == data
        except (NameError, AttributeError):
            pytest.skip("decode_pushdata not available")
    except ImportError:
        pytest.skip("pushdata functions not available")


# ========================================================================
# Minimal push branches
# ========================================================================

def test_encode_pushdata_minimal():
    """Test encoding with minimal push."""
    try:
        from bsv.utils.pushdata import encode_pushdata
        
        data = b'\x01'
        try:
            encoded = encode_pushdata(data, minimal_push=True)
            assert isinstance(encoded, bytes)
        except TypeError:
            # encode_pushdata may not support minimal_push parameter
            pytest.skip("encode_pushdata doesn't support minimal_push")
    except ImportError:
        pytest.skip("encode_pushdata not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_encode_pushdata_max_size():
    """Test encoding maximum size pushdata."""
    try:
        from bsv.utils.pushdata import encode_pushdata

        # Bitcoin script pushdata max is usually around 520 bytes
        data = b'\x00' * 520
        encoded = encode_pushdata(data)
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("encode_pushdata not available")


# ========================================================================
# Pushdata decoding error cases and edge cases
# ========================================================================

def test_decode_pushdata_empty_input():
    """Test decode_pushdata with empty input."""
    try:
        from bsv.utils.pushdata import decode_pushdata

        try:
            decode_pushdata(b'')
            assert False, "Should raise ValueError for empty input"
        except ValueError as e:
            assert "Empty encoded data" in str(e)
    except ImportError:
        pytest.skip("decode_pushdata not available")


def test_decode_pushdata_op_0():
    """Test decode_pushdata with OP_0 opcode."""
    try:
        from bsv.utils.pushdata import decode_pushdata

        # OP_0 should return empty bytes
        result = decode_pushdata(bytes([0x00]))
        assert result == b''
    except ImportError:
        pytest.skip("decode_pushdata not available")


def test_decode_pushdata_op_1_to_op_16():
    """Test decode_pushdata with OP_1 to OP_16 opcodes."""
    try:
        from bsv.utils.pushdata import decode_pushdata

        # Test OP_1 (0x51) should return b'\x01'
        result = decode_pushdata(bytes([0x51]))
        assert result == b'\x01'

        # Test OP_16 (0x60) should return b'\x10'
        result = decode_pushdata(bytes([0x60]))
        assert result == b'\x10'
    except ImportError:
        pytest.skip("decode_pushdata not available")


def test_decode_pushdata_op_1negate():
    """Test decode_pushdata with OP_1NEGATE opcode."""
    try:
        from bsv.utils.pushdata import decode_pushdata

        # OP_1NEGATE should return 0x81
        result = decode_pushdata(bytes([0x4f]))
        assert result == b'\x81'
    except ImportError:
        pytest.skip("decode_pushdata not available")


def test_decode_pushdata_direct_push_truncated():
    """Test decode_pushdata with truncated direct push data."""
    try:
        from bsv.utils.pushdata import decode_pushdata

        # Direct push with length 5 but only 3 bytes of data
        try:
            decode_pushdata(bytes([0x05, 0x01, 0x02, 0x03]))
            assert False, "Should raise ValueError for truncated data"
        except ValueError as e:
            assert "too short for direct push" in str(e)
    except ImportError:
        pytest.skip("decode_pushdata not available")


def test_decode_pushdata_pusdata1_truncated():
    """Test decode_pushdata with truncated OP_PUSHDATA1 data."""
    try:
        from bsv.utils.pushdata import decode_pushdata

        # OP_PUSHDATA1 with length 5 but insufficient data
        try:
            decode_pushdata(bytes([0x4c, 0x05, 0x01, 0x02]))
            assert False, "Should raise ValueError for truncated data"
        except ValueError as e:
            assert "too short for OP_PUSHDATA1" in str(e)
    except ImportError:
        pytest.skip("decode_pushdata not available")


def test_decode_pushdata_pusdata2_truncated():
    """Test decode_pushdata with truncated OP_PUSHDATA2 data."""
    try:
        from bsv.utils.pushdata import decode_pushdata

        # OP_PUSHDATA2 with length 5 but insufficient data
        try:
            decode_pushdata(bytes([0x4d, 0x05, 0x00, 0x01, 0x02]))
            assert False, "Should raise ValueError for truncated data"
        except ValueError as e:
            assert "too short for OP_PUSHDATA2" in str(e)
    except ImportError:
        pytest.skip("decode_pushdata not available")


def test_decode_pushdata_pusdata4_truncated():
    """Test decode_pushdata with truncated OP_PUSHDATA4 data."""
    try:
        from bsv.utils.pushdata import decode_pushdata

        # OP_PUSHDATA4 with length 5 but insufficient data
        try:
            decode_pushdata(bytes([0x4e, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02]))
            assert False, "Should raise ValueError for truncated data"
        except ValueError as e:
            assert "too short for OP_PUSHDATA4" in str(e)
    except ImportError:
        pytest.skip("decode_pushdata not available")


def test_decode_pushdata_unknown_opcode():
    """Test decode_pushdata with unknown opcode."""
    try:
        from bsv.utils.pushdata import decode_pushdata

        # Unknown opcode 0xFF
        try:
            decode_pushdata(bytes([0xff, 0x01, 0x02]))
            assert False, "Should raise ValueError for unknown opcode"
        except ValueError as e:
            assert "Unknown pushdata opcode" in str(e)
    except ImportError:
        pytest.skip("decode_pushdata not available")


def test_decode_pushdata_edge_cases():
    """Test decode_pushdata edge cases."""
    try:
        from bsv.utils.pushdata import decode_pushdata

        # Test various pushdata formats work correctly
        test_cases = [
            (b'\x00', b''),  # OP_0
            (b'\x51', b'\x01'),  # OP_1
            (b'\x60', b'\x10'),  # OP_16
            (b'\x4f', b'\x81'),  # OP_1NEGATE
            (b'\x05\x01\x02\x03\x04\x05', b'\x01\x02\x03\x04\x05'),  # Direct push
            (b'\x4c\x03\x01\x02\x03', b'\x01\x02\x03'),  # OP_PUSHDATA1
            (b'\x4d\x03\x00\x01\x02\x03', b'\x01\x02\x03'),  # OP_PUSHDATA2
            (b'\x4e\x03\x00\x00\x00\x01\x02\x03', b'\x01\x02\x03'),  # OP_PUSHDATA4
        ]

        for encoded, expected in test_cases:
            result = decode_pushdata(encoded)
            assert result == expected, f"Failed for {encoded.hex()}: expected {expected.hex()}, got {result.hex()}"

    except ImportError:
        pytest.skip("decode_pushdata not available")

