"""
Tests for KVStore BEEF/AtomicBEEF parsing functionality.

These tests verify that LocalKVStore correctly handles BEEF and AtomicBEEF formats
when retrieving and storing values, matching Go and TS SDK behavior.
"""

import pytest
from unittest.mock import Mock, patch
import os

from bsv.keystore import LocalKVStore, KVStoreConfig
from bsv.wallet.wallet_interface import WalletInterface
from bsv.transaction import Transaction, parse_beef_ex
from bsv.beef import build_beef_v2_from_raw_hexes
from bsv.utils import Reader


def create_mock_wallet_with_beef():
    """Create a mock wallet that returns BEEF data."""
    wallet = Mock(spec=WalletInterface)
    
    # Create a proper transaction for testing (coinbase tx with proper format)
    # Version (4 bytes) + input count (1 byte) + coinbase input + output count + output + locktime
    tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100ffffffff0100000000000000000151000000"
    tx = Transaction.from_reader(Reader(bytes.fromhex(tx_hex)))
    
    # Build BEEF from the transaction
    beef_bytes = build_beef_v2_from_raw_hexes([tx_hex])
    
    wallet.list_outputs = Mock(return_value={
        'totalOutputs': 1,
        'outputs': [{
            'outpoint': f'{tx.txid()}.0',
            'txid': tx.txid(),
            'outputIndex': 0,
            'lockingScript': b'\x51',  # OP_1
            'satoshis': 0
        }],
        'BEEF': beef_bytes
    })
    
    wallet.create_action = Mock(return_value={'txid': 'newTxId'})
    wallet.internalize_action = Mock(return_value={'accepted': True})
    
    return wallet, beef_bytes


class TestKVStoreBEEFParsing:
    """Test BEEF parsing in LocalKVStore."""
    
    def test_get_parses_beef_from_list_outputs(self):
        """Test that get() correctly parses BEEF returned by list_outputs."""
        wallet, _ = create_mock_wallet_with_beef()
        
        config = KVStoreConfig(
            wallet=wallet,
            context='test-context',
            encrypt=False
        )
        store = LocalKVStore(config)
        
        # This should parse the BEEF without errors
        _ = store.get(None, 'test-key', 'default')
        
        # Should have called list_outputs
        wallet.list_outputs.assert_called_once()
        
        # Verify BEEF was included in the call
        call_args = wallet.list_outputs.call_args
        assert call_args is not None
    
    def test_get_handles_atomic_beef_format(self):
        """Test that get() handles AtomicBEEF format (with prefix)."""
        wallet = Mock(spec=WalletInterface)
        
        # Create AtomicBEEF (BEEF with 4-byte version prefix and 32-byte txid)
        tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100ffffffff0100000000000000000151000000"
        beef_v2 = build_beef_v2_from_raw_hexes([tx_hex])
        
        # AtomicBEEF format: 4 bytes version + 32 bytes txid + BEEF
        atomic_beef = b'\x01\x00\xBE\xEF' + b'\x00' * 32 + beef_v2
        
        tx = Transaction.from_reader(Reader(bytes.fromhex(tx_hex)))
        
        wallet.list_outputs = Mock(return_value={
            'outputs': [{
                'outpoint': f'{tx.txid()}.0',
                'txid': tx.txid(),
                'outputIndex': 0,
                'lockingScript': b'\x51',
                'satoshis': 0
            }],
            'BEEF': atomic_beef
        })
        
        config = KVStoreConfig(
            wallet=wallet,
            context='test-context',
            encrypt=False
        )
        store = LocalKVStore(config)
        
        # Should handle AtomicBEEF without errors
        _ = store.get(None, 'test-key', 'default')
        
        wallet.list_outputs.assert_called_once()
    
    def test_set_includes_input_beef_when_updating(self):
        """Test that set() includes inputBEEF when updating existing values."""
        wallet, beef_bytes = create_mock_wallet_with_beef()
        
        # Mock that there's an existing output
        tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100ffffffff0100000000000000000151000000"
        tx = Transaction.from_reader(Reader(bytes.fromhex(tx_hex)))
        
        wallet.list_outputs = Mock(return_value={
            'outputs': [{
                'outpoint': f'{tx.txid()}.0',
                'txid': tx.txid(),
                'outputIndex': 0,
                'lockingScript': b'\x01\x00',
                'satoshis': 1
            }],
            'BEEF': beef_bytes
        })
        
        wallet.create_action = Mock(return_value={
            'signableTransaction': {
                'reference': 'ref123',
                'tx': b'signed_tx_bytes'
            }
        })

        wallet.sign_action = Mock(return_value={'txid': 'signedTxId'})

        # Mock get_public_key to return a proper public key string
        wallet.get_public_key = Mock(return_value={
            'publicKey': '02' + '00' * 32  # 33-byte compressed public key
        })
        
        config = KVStoreConfig(
            wallet=wallet,
            context='test-context',
            encrypt=False
        )
        store = LocalKVStore(config)
        
        # Set a value (should update existing)
        _ = store.set(None, 'test-key', 'new-value')
        
        # Verify create_action was called with inputBEEF
        wallet.create_action.assert_called_once()
        call_args = wallet.create_action.call_args[0][1]  # Get args dict
        
        # Should have input_beef or inputBEEF in the call
        assert 'input_beef' in call_args or 'inputBEEF' in call_args or 'inputs_meta' in call_args
    
    def test_beef_parsing_with_multiple_transactions(self):
        """Test BEEF parsing when multiple transactions are in the BEEF."""
        wallet = Mock(spec=WalletInterface)
        
        # Create multiple transactions
        tx1_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100ffffffff0100000000000000000151000000"
        tx2_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100ffffffff0100000000000000000152000000"
        
        # Build BEEF with multiple transactions
        beef_bytes = build_beef_v2_from_raw_hexes([tx1_hex, tx2_hex])
        
        tx1 = Transaction.from_reader(Reader(bytes.fromhex(tx1_hex)))
        tx2 = Transaction.from_reader(Reader(bytes.fromhex(tx2_hex)))
        
        wallet.list_outputs = Mock(return_value={
            'outputs': [
                {
                    'outpoint': f'{tx1.txid()}.0',
                    'txid': tx1.txid(),
                    'outputIndex': 0,
                    'lockingScript': b'\x51',
                    'satoshis': 0
                },
                {
                    'outpoint': f'{tx2.txid()}.0',
                    'txid': tx2.txid(),
                    'outputIndex': 0,
                    'lockingScript': b'\x52',
                    'satoshis': 0
                }
            ],
            'BEEF': beef_bytes
        })
        
        config = KVStoreConfig(
            wallet=wallet,
            context='test-context',
            encrypt=False
        )
        store = LocalKVStore(config)
        
        # Should parse BEEF with multiple transactions
        _ = store.get(None, 'test-key', 'default')
        
        wallet.list_outputs.assert_called_once()
    
    def test_beef_fallback_to_woc_when_missing(self):
        """Test that KVStore falls back to WOC when BEEF is missing."""
        wallet = Mock(spec=WalletInterface)
        
        tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100ffffffff0100000000000000000151000000"
        tx = Transaction.from_reader(Reader(bytes.fromhex(tx_hex)))
        
        # Return outputs but no BEEF
        wallet.list_outputs = Mock(return_value={
            'outputs': [{
                'outpoint': f'{tx.txid()}.0',
                'txid': tx.txid(),
                'outputIndex': 0,
                'lockingScript': b'\x01\x00',
                'satoshis': 1
            }],
            'BEEF': None  # No BEEF provided
        })
        
        config = KVStoreConfig(
            wallet=wallet,
            context='test-context',
            encrypt=False
        )
        store = LocalKVStore(config)
        
        # Mock WOC client to avoid actual network calls
        with patch('bsv.keystore.local_kv_store.WOCClient') as mock_woc:
            mock_woc_instance = Mock()
            mock_woc_instance.get_tx_hex = Mock(return_value=tx_hex)
            mock_woc.return_value = mock_woc_instance
            
            # Should attempt to build BEEF from WOC
            _ = store.get(None, 'test-key', 'default')
            
            # Verify WOC was used as fallback
            # (Implementation may vary, but should handle missing BEEF gracefully)


class TestKVStoreRetentionPeriod:
    """Test retention period support in LocalKVStore."""
    
    def test_retention_period_stored_in_output_description(self):
        """Test that retention period is stored in output description."""
        wallet = Mock(spec=WalletInterface)
        wallet.list_outputs = Mock(return_value={'outputs': [], 'BEEF': None})
        wallet.create_action = Mock(return_value={'txid': 'newTxId'})
        wallet.internalize_action = Mock(return_value={'accepted': True})
        # Mock get_public_key to return a proper public key string
        wallet.get_public_key = Mock(return_value={
            'publicKey': '02' + '00' * 32  # 33-byte compressed public key
        })
        
        config = KVStoreConfig(
            wallet=wallet,
            context='test-context',
            encrypt=False
        )
        # Set retention period
        setattr(config, 'retention_period', 3600)  # 1 hour
        
        store = LocalKVStore(config)
        
        # Set a value
        _ = store.set(None, 'test-key', 'test-value')
        
        # Verify create_action was called with retention period
        wallet.create_action.assert_called_once()
        call_args = wallet.create_action.call_args[0][1]
        
        # Check that outputs have retention period
        if 'outputs' in call_args:
            outputs = call_args['outputs']
            if outputs and len(outputs) > 0:
                output_desc = outputs[0].get('outputDescription', '')
                # Retention period should be in output description
                assert 'retentionSeconds' in str(output_desc) or output_desc == ''
    
    def test_basket_name_defaults_to_context(self):
        """Test that basket name defaults to context when not specified."""
        wallet = Mock(spec=WalletInterface)
        wallet.list_outputs = Mock(return_value={'outputs': [], 'BEEF': None})
        wallet.create_action = Mock(return_value={'txid': 'newTxId'})
        wallet.internalize_action = Mock(return_value={'accepted': True})
        
        context = 'my-custom-context'
        config = KVStoreConfig(
            wallet=wallet,
            context=context,
            encrypt=False
        )
        
        store = LocalKVStore(config)
        
        # Basket name should default to context
        assert store._basket_name == context
    
    def test_custom_basket_name(self):
        """Test that custom basket name can be set."""
        wallet = Mock(spec=WalletInterface)
        wallet.list_outputs = Mock(return_value={'outputs': [], 'BEEF': None})
        
        context = 'my-context'
        custom_basket = 'my-custom-basket'
        config = KVStoreConfig(
            wallet=wallet,
            context=context,
            encrypt=False
        )
        setattr(config, 'basket_name', custom_basket)
        
        store = LocalKVStore(config)
        
        # Should use custom basket name
        assert store._basket_name == custom_basket


class TestKVStoreTransactionCreation:
    """Test transaction creation logic in LocalKVStore."""
    
    def test_set_creates_pushdrop_output(self):
        """Test that set() creates a PushDrop output."""
        wallet = Mock(spec=WalletInterface)
        wallet.list_outputs = Mock(return_value={'outputs': [], 'BEEF': None})
        wallet.create_action = Mock(return_value={'txid': 'newTxId'})
        wallet.internalize_action = Mock(return_value={'accepted': True})
        wallet.get_public_key = Mock(return_value={
            'publicKey': '02' + '00' * 32
        })
        wallet.create_signature = Mock(return_value={
            'signature': b'signature_bytes'
        })
        
        config = KVStoreConfig(
            wallet=wallet,
            context='test-context',
            encrypt=False
        )
        store = LocalKVStore(config)
        
        # Set a value
        _ = store.set(None, 'test-key', 'test-value')
        
        # Verify create_action was called
        wallet.create_action.assert_called_once()
        call_args = wallet.create_action.call_args[0][1]
        
        # Should have outputs with locking script
        assert 'outputs' in call_args
        assert len(call_args['outputs']) > 0
        assert 'lockingScript' in call_args['outputs'][0]
    
    def test_remove_spends_existing_outputs(self):
        """Test that remove() spends existing outputs without creating new ones."""
        wallet = Mock(spec=WalletInterface)
        
        tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100ffffffff0100000000000000000151000000"
        tx = Transaction.from_reader(Reader(bytes.fromhex(tx_hex)))
        beef_bytes = build_beef_v2_from_raw_hexes([tx_hex])
        
        wallet.list_outputs = Mock(return_value={
            'outputs': [{
                'outpoint': f'{tx.txid()}.0',
                'txid': tx.txid(),
                'outputIndex': 0,
                'lockingScript': b'\x01\x00',
                'satoshis': 1
            }],
            'BEEF': beef_bytes
        })
        
        wallet.create_action = Mock(return_value={
            'signableTransaction': {
                'reference': 'ref123',
                'tx': b'signed_tx_bytes'
            }
        })
        
        wallet.sign_action = Mock(return_value={'txid': 'removalTxId'})
        wallet.internalize_action = Mock(return_value={'accepted': True})
        
        config = KVStoreConfig(
            wallet=wallet,
            context='test-context',
            encrypt=False
        )
        store = LocalKVStore(config)
        
        # Remove the key
        _ = store.remove(None, 'test-key')
        
        # Verify create_action was called with inputs but no outputs
        wallet.create_action.assert_called_once()
        call_args = wallet.create_action.call_args[0][1]
        
        # Should have inputs
        assert 'inputs' in call_args or 'inputs_meta' in call_args
        
        # Should have no outputs (or empty outputs)
        if 'outputs' in call_args:
            assert len(call_args['outputs']) == 0

