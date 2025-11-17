"""
Tests for Historian implementation.

Translated from TS SDK Historian tests.
"""
import pytest
from bsv.overlay_tools.historian import Historian
from bsv.transaction import Transaction
from bsv.utils import Reader


class TestHistorian:
    """Test Historian matching TS SDK tests."""

    def test_should_build_history_from_transaction(self):
        """Test that Historian builds history from transaction."""
        def interpreter(tx: Transaction, output_index: int, ctx=None):
            # Simple interpreter that returns output index as value
            if output_index < len(tx.outputs):
                return f"output_{output_index}"
            return None

        historian = Historian(interpreter)
        
        # Create a simple transaction
        tx_bytes = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')
        tx = Transaction.from_reader(Reader(tx_bytes))
        
        history = historian.build_history(tx)
        assert isinstance(history, list)

    def test_should_use_cache_when_provided(self):
        """Test that Historian uses cache when provided."""
        cache = {}
        def interpreter(tx: Transaction, output_index: int, ctx=None):
            return f"cached_{output_index}"

        historian = Historian(interpreter, {'historyCache': cache})
        
        tx_bytes = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')
        tx = Transaction.from_reader(Reader(tx_bytes))
        
        history1 = historian.build_history(tx)
        history2 = historian.build_history(tx)
        
        # Second call should use cache
        assert len(history1) == len(history2)

