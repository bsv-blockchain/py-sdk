"""
Coverage tests for script/interpreter/number.py - untested branches.
"""
import pytest


# ========================================================================
# Number encoding branches
# ========================================================================

def test_encode_number_zero():
    """Test encoding zero."""
    try:
        from bsv.script.interpreter.number import encode_number
        encoded = encode_number(0)
        assert encoded == b'' or encoded == b'\x00'
    except ImportError:
        pytest.skip("Number encoding not available")


def test_encode_number_positive():
    """Test encoding positive number."""
    try:
        from bsv.script.interpreter.number import encode_number
        encoded = encode_number(1)
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0
    except ImportError:
        pytest.skip("Number encoding not available")


def test_encode_number_negative():
    """Test encoding negative number."""
    try:
        from bsv.script.interpreter.number import encode_number
        encoded = encode_number(-1)
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0
    except ImportError:
        pytest.skip("Number encoding not available")


def test_encode_number_large():
    """Test encoding large number."""
    try:
        from bsv.script.interpreter.number import encode_number
        encoded = encode_number(1000000)
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("Number encoding not available")


# ========================================================================
# Number decoding branches
# ========================================================================

def test_decode_number_empty():
    """Test decoding empty bytes."""
    try:
        from bsv.script.interpreter.number import decode_number
        decoded = decode_number(b'')
        assert decoded == 0
    except ImportError:
        pytest.skip("Number decoding not available")


def test_decode_number_roundtrip():
    """Test encode/decode roundtrip."""
    try:
        from bsv.script.interpreter.number import encode_number, decode_number
        
        for value in [0, 1, -1, 127, -127, 32767, -32767]:
            encoded = encode_number(value)
            decoded = decode_number(encoded)
            assert decoded == value
    except ImportError:
        pytest.skip("Number encoding not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_encode_number_min_int():
    """Test encoding minimum integer."""
    try:
        from bsv.script.interpreter.number import encode_number
        encoded = encode_number(-2147483647)
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("Number encoding not available")


def test_encode_number_max_int():
    """Test encoding maximum integer."""
    try:
        from bsv.script.interpreter.number import encode_number
        encoded = encode_number(2147483647)
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("Number encoding not available")

