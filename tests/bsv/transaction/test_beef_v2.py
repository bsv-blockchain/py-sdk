"""
Tests for BEEF_V2 format support.

Translated from TS SDK BEEF_V2 tests.
"""
import pytest
from bsv.transaction.beef import Beef, BEEF_V1, BEEF_V2
from bsv.transaction.beef_tx import BeefTx, TX_DATA_FORMAT
from bsv.transaction import Transaction
from bsv.utils import Reader


class TestBEEFV2Support:
    """Test BEEF_V2 format support matching TS SDK tests."""

    def test_should_create_beef_v2_instance(self):
        """Test that BEEF_V2 constant exists and can be used."""
        assert BEEF_V2 == 4022206466
        beef = Beef(BEEF_V2)
        assert beef.version == BEEF_V2

    def test_should_serialize_beef_v2_with_transactions(self):
        """Test serializing BEEF_V2 with transactions."""
        tx_bytes = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')
        
        beef = Beef(BEEF_V2)
        beef.merge_raw_tx(tx_bytes)
        
        binary = beef.to_binary()
        assert len(binary) > 0
        # Should start with BEEF_V2 magic number
        assert binary[:4] == BEEF_V2.to_bytes(4, 'little')

    def test_should_support_tx_data_format_rawtx(self):
        """Test TX_DATA_FORMAT.RAWTX."""
        assert TX_DATA_FORMAT.RAWTX == 0

    def test_should_support_tx_data_format_rawtx_and_bump_index(self):
        """Test TX_DATA_FORMAT.RAWTX_AND_BUMP_INDEX."""
        assert TX_DATA_FORMAT.RAWTX_AND_BUMP_INDEX == 1

    def test_should_create_beef_tx_with_bump_index(self):
        """Test creating BeefTx with bump index."""
        tx_bytes = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')
        
        beef_tx = BeefTx.from_raw_tx(tx_bytes, bump_index=0)
        assert beef_tx.has_proof is True
        assert beef_tx.bump_index == 0

    def test_should_build_beef_v2_from_raw_hexes(self):
        """Test building BEEF_V2 from raw hex strings."""
        from bsv.beef.builder import build_beef_v2_from_raw_hexes
        
        tx_hexes = [
            '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000'
        ]
        
        beef_bytes = build_beef_v2_from_raw_hexes(tx_hexes)
        assert len(beef_bytes) > 0
        # Should start with BEEF_V2 magic
        assert beef_bytes[:4] == BEEF_V2.to_bytes(4, 'little')

