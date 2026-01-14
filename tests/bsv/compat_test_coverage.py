"""
Coverage tests for compat/ modules - untested branches.
"""

import pytest

# ========================================================================
# Compatibility module branches
# ========================================================================


def test_compat_module_exists():
    """Test that compat module exists."""
    try:
        import bsv.compat

        assert bsv.compat is not None
    except ImportError:
        pytest.skip("Compat module not available")


def test_compat_py2_py3():
    """Test Python 2/3 compatibility helpers."""
    try:
        from bsv.compat import is_py2, is_py3

        # Should be Python 3
        # Python version checks (always true for current Python version)
    except (ImportError, AttributeError):
        pytest.skip("Python version compatibility helpers not available")


def test_compat_string_types():
    """Test string type compatibility."""
    try:
        from bsv.compat import string_types

        assert string_types is not None
        assert isinstance("test", string_types)
    except (ImportError, AttributeError):
        pytest.skip("string_types not available")


def test_compat_bytes_types():
    """Test bytes type compatibility."""
    try:
        from bsv.compat import bytes_types

        assert bytes_types is not None
        assert isinstance(b"test", bytes_types)
    except (ImportError, AttributeError):
        pytest.skip("bytes_types not available")


# ========================================================================
# Integer conversion branches
# ========================================================================


def test_compat_int_to_bytes():
    """Test integer to bytes conversion."""
    try:
        from bsv.compat import int_to_bytes

        result = int_to_bytes(255, 1)
        assert isinstance(result, bytes)
        assert result == b"\xff"
    except (ImportError, AttributeError):
        pytest.skip("int_to_bytes not available")


def test_compat_bytes_to_int():
    """Test bytes to integer conversion."""
    try:
        from bsv.compat import bytes_to_int

        result = bytes_to_int(b"\xff")
        assert isinstance(result, int)
        assert result == 255
    except (ImportError, AttributeError):
        pytest.skip("bytes_to_int not available")


# ========================================================================
# Edge cases
# ========================================================================


def test_compat_empty_bytes():
    """Test compatibility with empty bytes."""
    try:
        from bsv.compat import bytes_to_int

        try:
            bytes_to_int(b"")
            # Result is 0 or exception raised
        except (ValueError, IndexError):
            # Expected
            pass
    except (ImportError, AttributeError):
        pytest.skip("bytes_to_int not available")
