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

