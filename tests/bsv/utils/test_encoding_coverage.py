"""
Coverage tests for utils/encoding.py - untested branches.
"""
import pytest


# ========================================================================
# Encoding/decoding branches
# ========================================================================

def test_hex_encode_empty():
    """Test hex encoding empty bytes."""
    try:
        from bsv.utils.encoding import to_hex
        result = to_hex(b'')
        assert result == ""
    except ImportError:
        pytest.skip("Encoding functions not available")


def test_hex_encode_value():
    """Test hex encoding value."""
    try:
        from bsv.utils.encoding import to_hex
        result = to_hex(b'\x01\x02\x03')
        assert result == "010203"
    except ImportError:
        pytest.skip("Encoding functions not available")


def test_hex_decode_empty():
    """Test hex decoding empty string."""
    try:
        from bsv.utils.encoding import from_hex
        result = from_hex("")
        assert result == b''
    except ImportError:
        pytest.skip("Encoding functions not available")


def test_hex_decode_value():
    """Test hex decoding value."""
    try:
        from bsv.utils.encoding import from_hex
        result = from_hex("010203")
        assert result == b'\x01\x02\x03'
    except ImportError:
        pytest.skip("Encoding functions not available")


def test_hex_decode_uppercase():
    """Test hex decoding uppercase."""
    try:
        from bsv.utils.encoding import from_hex
        result = from_hex("ABCDEF")
        assert result == b'\xab\xcd\xef'
    except ImportError:
        pytest.skip("Encoding functions not available")


def test_hex_decode_mixed_case():
    """Test hex decoding mixed case."""
    try:
        from bsv.utils.encoding import from_hex
        result = from_hex("AbCdEf")
        assert result == b'\xab\xcd\xef'
    except ImportError:
        pytest.skip("Encoding functions not available")


def test_hex_decode_invalid():
    """Test hex decoding invalid input."""
    try:
        from bsv.utils.encoding import from_hex
        try:
            _ = from_hex("gg")
            assert False, "Should raise error"
        except ValueError:
            assert True
    except ImportError:
        pytest.skip("Encoding functions not available")


# ========================================================================
# Base64 branches
# ========================================================================

def test_base64_encode_empty():
    """Test base64 encoding empty bytes."""
    try:
        from bsv.utils.encoding import to_base64
        result = to_base64(b'')
        assert result == ""
    except ImportError:
        pytest.skip("Base64 functions not available")


def test_base64_encode_value():
    """Test base64 encoding value."""
    try:
        from bsv.utils.encoding import to_base64
        result = to_base64(b'test')
        assert len(result) > 0
    except ImportError:
        pytest.skip("Base64 functions not available")


def test_base64_decode_empty():
    """Test base64 decoding empty string."""
    try:
        from bsv.utils.encoding import from_base64
        result = from_base64("")
        assert result == b''
    except ImportError:
        pytest.skip("Base64 functions not available")


def test_base64_decode_value():
    """Test base64 decoding value."""
    try:
        from bsv.utils.encoding import from_base64
        result = from_base64("dGVzdA==")
        assert result == b'test'
    except ImportError:
        pytest.skip("Base64 functions not available")

