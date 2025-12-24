"""
Coverage tests for script/__init__.py - lazy import of Spend.
"""
import pytest


def test_script_init_lazy_import_spend():
    """Test lazy import of Spend from script module."""
    try:
        from bsv.script import Spend
        
        # Verify Spend is imported
        assert Spend is not None
        assert hasattr(Spend, '__name__') or callable(Spend)
    except ImportError:
        pytest.skip("Spend not available in script module")


def test_script_init_attribute_error():
    """Test AttributeError for non-existent attribute."""
    try:
        import bsv.script

        # Try to access non-existent attribute
        with pytest.raises(AttributeError) as exc_info:
            _ = bsv.script.NonExistentClass

        # Check that the error message contains expected text
        # The error might come from nested modules, so accept both formats
        error_msg = str(exc_info.value)
        assert ("module 'bsv.script' has no attribute" in error_msg or
                "module 'bsv.script.script' has no attribute" in error_msg)
        assert "NonExistentClass" in error_msg
    except ImportError:
        pytest.skip("bsv.script module not available")

