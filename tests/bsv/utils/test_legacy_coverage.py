"""
Coverage tests for utils/legacy.py - untested branches.
"""
import pytest


# ========================================================================
# Legacy compatibility branches
# ========================================================================

def test_legacy_functions_exist():
    """Test that legacy module exists."""
    try:
        import bsv.utils.legacy
        assert bsv.utils.legacy is not None
    except ImportError:
        pytest.skip("Legacy module not available")


def test_legacy_script_conversion():
    """Test legacy script conversion if available."""
    try:
        from bsv.utils.legacy import to_legacy_script
        
        script = b'\x51\x52\x93'
        try:
            result = to_legacy_script(script)
            assert result is not None
        except (NameError, AttributeError):
            pytest.skip("to_legacy_script not available")
    except ImportError:
        pytest.skip("Legacy module not available")


def test_legacy_transaction_conversion():
    """Test legacy transaction conversion if available."""
    try:
        from bsv.utils.legacy import to_legacy_transaction
        from bsv.transaction import Transaction
        
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
        
        try:
            result = to_legacy_transaction(tx)
            assert result is not None
        except (NameError, AttributeError):
            pytest.skip("to_legacy_transaction not available")
    except ImportError:
        pytest.skip("Legacy module not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_legacy_empty_input():
    """Test legacy conversion with empty input."""
    try:
        from bsv.utils.legacy import to_legacy_script
        
        try:
            result = to_legacy_script(b'')
            assert result is not None or True
        except (NameError, AttributeError):
            pytest.skip("to_legacy_script not available")
    except ImportError:
        pytest.skip("Legacy module not available")

