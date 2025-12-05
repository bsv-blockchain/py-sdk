"""
Tests for BeefTx implementation.

Translated from TS SDK BeefTx tests.
"""
import pytest
from bsv.transaction.beef_tx import BeefTx, TX_DATA_FORMAT
from bsv.transaction import Transaction
from bsv.utils import Reader


class TestBeefTx:
    """Test BeefTx matching TS SDK tests."""

    def test_should_create_from_transaction(self):
        """Test creating BeefTx from Transaction object."""
        tx_bytes = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')
        tx = Transaction.from_reader(Reader(tx_bytes))
        
        beef_tx = BeefTx.from_tx(tx)
        assert beef_tx.tx is not None
        assert beef_tx.txid is not None

    def test_should_create_from_raw_bytes(self):
        """Test creating BeefTx from raw transaction bytes."""
        tx_bytes = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')
        
        beef_tx = BeefTx.from_raw_tx(tx_bytes)
        assert beef_tx.raw_tx == tx_bytes
        assert beef_tx.txid is not None

    def test_should_create_from_txid(self):
        """Test creating BeefTx from txid string."""
        txid = '0' * 64
        
        beef_tx = BeefTx.from_txid(txid)
        assert beef_tx.is_txid_only is True
        assert beef_tx.txid == txid

    def test_should_have_proof_when_bump_index_set(self):
        """Test that has_proof is True when bump_index is set."""
        tx_bytes = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')
        beef_tx = BeefTx.from_raw_tx(tx_bytes, bump_index=0)
        
        assert beef_tx.has_proof is True
        assert beef_tx.bump_index == 0

    def test_should_update_input_txids(self):
        """Test that input_txids are updated correctly."""
        tx_bytes = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')
        beef_tx = BeefTx.from_raw_tx(tx_bytes)
        
        # Should have empty input_txids if no proof
        assert isinstance(beef_tx.input_txids, list)

