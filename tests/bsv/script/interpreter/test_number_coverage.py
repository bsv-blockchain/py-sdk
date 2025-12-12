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
        from bsv.script.interpreter.number import ScriptNumber
        num = ScriptNumber(0)
        encoded = num.bytes()
        assert encoded == b'' or encoded == b'\x00'
    except ImportError:
        pytest.skip("ScriptNumber not available")


def test_encode_number_positive():
    """Test encoding positive number."""
    try:
        from bsv.script.interpreter.number import ScriptNumber
        num = ScriptNumber(1)
        encoded = num.bytes()
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0
    except ImportError:
        pytest.skip("ScriptNumber not available")


def test_encode_number_negative():
    """Test encoding negative number."""
    try:
        from bsv.script.interpreter.number import ScriptNumber
        num = ScriptNumber(-1)
        encoded = num.bytes()
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0
    except ImportError:
        pytest.skip("ScriptNumber not available")


def test_encode_number_large():
    """Test encoding large number."""
    try:
        from bsv.script.interpreter.number import ScriptNumber
        num = ScriptNumber(1000000)
        encoded = num.bytes()
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("ScriptNumber not available")


# ========================================================================
# Number decoding branches
# ========================================================================

def test_decode_number_empty():
    """Test decoding empty bytes."""
    try:
        from bsv.script.interpreter.number import ScriptNumber
        decoded = ScriptNumber.from_bytes(b'')
        assert decoded.value == 0
    except ImportError:
        pytest.skip("ScriptNumber not available")


def test_decode_number_roundtrip():
    """Test encode/decode roundtrip."""
    try:
        from bsv.script.interpreter.number import ScriptNumber

        for value in [0, 1, -1, 127, -127, 32767, -32767]:
            num = ScriptNumber(value)
            encoded = num.bytes()
            decoded = ScriptNumber.from_bytes(encoded)
            assert decoded.value == value
    except ImportError:
        pytest.skip("ScriptNumber not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_encode_number_min_int():
    """Test encoding minimum integer."""
    try:
        from bsv.script.interpreter.number import ScriptNumber
        num = ScriptNumber(-2147483647)
        encoded = num.bytes()
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("ScriptNumber not available")


def test_encode_number_max_int():
    """Test encoding maximum integer."""
    try:
        from bsv.script.interpreter.number import ScriptNumber
        num = ScriptNumber(2147483647)
        encoded = num.bytes()
        assert isinstance(encoded, bytes)
    except ImportError:
        pytest.skip("ScriptNumber not available")

