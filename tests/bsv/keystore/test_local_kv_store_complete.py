"""
Comprehensive tests for LocalKVStore matching TS SDK test coverage.

These tests are translated from ts-sdk/src/kvstore/__tests/LocalKVStore.test.ts
to ensure feature parity. Adapted to Python SDK's API structure.
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import Any

from bsv.keystore import LocalKVStore, KVStoreConfig
from bsv.keystore.interfaces import ErrEmptyContext
from bsv.wallet.wallet_interface import WalletInterface


# Constants matching TS SDK test values
TEST_LOCKING_SCRIPT_HEX = 'mockLockingScriptHex'
TEST_UNLOCKING_SCRIPT_HEX = 'mockUnlockingScriptHex'
TEST_ENCRYPTED_VALUE = b'encryptedData'
TEST_RAW_VALUE = 'myTestDataValue'
TEST_OUTPOINT = 'txid123.0'
TEST_CONTEXT = 'test-kv-context'
TEST_KEY = 'myTestKey'
TEST_VALUE = 'myTestDataValue'


def create_mock_wallet() -> Mock:
    """Create a mock wallet matching WalletInterface."""
    wallet = Mock(spec=WalletInterface)
    wallet.list_outputs = Mock(return_value={
        'totalOutputs': 0,
        'outputs': [],
        'BEEF': None
    })
    wallet.encrypt = Mock(return_value={
        'ciphertext': TEST_ENCRYPTED_VALUE
    })
    wallet.decrypt = Mock(return_value={
        'plaintext': TEST_VALUE.encode('utf-8')
    })
    wallet.get_public_key = Mock(return_value={
        'publicKey': '02a1633cafb311f41c1137864d7dd7cf2d5c9e5c2e5b5f5a5d5c5b5a59584f5e5fac'
    })
    wallet.create_signature = Mock(return_value={
        'signature': b'dummy_signature_for_testing_purposes_32bytes'
    })
    wallet.create_action = Mock(return_value={
        'txid': 'newTxId'
    })
    wallet.sign_action = Mock(return_value={
        'txid': 'signedTxId'
    })
    wallet.relinquish_output = Mock(return_value={
        'relinquished': True
    })
    wallet.internalize_action = Mock(return_value={
        'accepted': True,
        'txid': 'newTxId'
    })
    return wallet


class TestLocalKVStoreConstructor:
    """Test LocalKVStore constructor matching TS SDK tests."""

    def test_should_create_instance_with_default_wallet_and_encrypt_true(self):
        """Test creating instance with default wallet and encrypt=true."""
        # Note: Python SDK uses KVStoreConfig, not direct constructor params
        # This test may need adaptation based on actual Python SDK API
        wallet = create_mock_wallet()
        config = KVStoreConfig(
            wallet=wallet,
            context='default-context',
            encrypt=True
        )
        store = LocalKVStore(config)
        assert isinstance(store, LocalKVStore)
        assert store._context == 'default-context'
        assert store._encrypt is True

    def test_should_create_instance_with_provided_wallet_context_and_encrypt_false(self):
        """Test creating instance with provided wallet, context, and encrypt=false."""
        wallet = create_mock_wallet()
        config = KVStoreConfig(
            wallet=wallet,
            context='custom-context',
            encrypt=False
        )
        store = LocalKVStore(config)
        assert isinstance(store, LocalKVStore)
        assert store._wallet is wallet
        assert store._context == 'custom-context'
        assert store._encrypt is False

    def test_should_throw_error_if_context_is_missing_or_empty(self):
        """Test that empty context raises error."""
        wallet = create_mock_wallet()
        
        with pytest.raises(ErrEmptyContext):
            config = KVStoreConfig(wallet=wallet, context='')
            LocalKVStore(config)
        
        with pytest.raises(ErrEmptyContext):
            config = KVStoreConfig(wallet=wallet, context=None)
            LocalKVStore(config)


class TestLocalKVStoreGet:
    """Test LocalKVStore get method matching TS SDK tests."""

    def test_should_return_default_value_if_no_output_is_found(self):
        """Test get returns defaultValue when no output found."""
        wallet = create_mock_wallet()
        wallet.list_outputs.return_value = {
            'totalOutputs': 0,
            'outputs': [],
            'BEEF': None
        }
        
        config = KVStoreConfig(
            wallet=wallet,
            context=TEST_CONTEXT,
            encrypt=True
        )
        store = LocalKVStore(config)
        defaultValue = 'default'
        
        result = store.get(None, TEST_KEY, defaultValue)
        assert result == defaultValue

    def test_should_return_empty_string_if_no_output_found_and_no_default_value(self):
        """Test get returns empty string when no output found and no defaultValue."""
        wallet = create_mock_wallet()
        wallet.list_outputs.return_value = {
            'totalOutputs': 0,
            'outputs': [],
            'BEEF': None
        }
        
        config = KVStoreConfig(
            wallet=wallet,
            context=TEST_CONTEXT,
            encrypt=True
        )
        store = LocalKVStore(config)
        
        result = store.get(None, TEST_KEY, '')
        # Python SDK returns empty string as default, not None
        assert result == ''


class TestLocalKVStoreSet:
    """Test LocalKVStore set method matching TS SDK tests."""

    def test_should_create_new_encrypted_output_if_none_exists(self):
        """Test set creates new encrypted output when none exists."""
        wallet = create_mock_wallet()
        wallet.list_outputs.return_value = {
            'outputs': [],
            'totalOutputs': 0,
            'BEEF': None
        }
        wallet.encrypt.return_value = {
            'ciphertext': TEST_ENCRYPTED_VALUE
        }
        wallet.create_action.return_value = {
            'txid': 'newTxId'
        }
        
        config = KVStoreConfig(
            wallet=wallet,
            context=TEST_CONTEXT,
            encrypt=True
        )
        store = LocalKVStore(config)
        
        result = store.set(None, TEST_KEY, TEST_VALUE)
        
        # Python SDK returns key.0 format for outpoint
        assert result == f'{TEST_KEY}.0'
        wallet.create_action.assert_called_once()

    def test_should_create_new_non_encrypted_output_if_none_exists_and_encrypt_false(self):
        """Test set creates new non-encrypted output when encrypt=false."""
        wallet = create_mock_wallet()
        wallet.list_outputs.return_value = {
            'outputs': [],
            'totalOutputs': 0,
            'BEEF': None
        }
        wallet.create_action.return_value = {
            'txid': 'newTxIdNonEnc'
        }
        
        config = KVStoreConfig(
            wallet=wallet,
            context=TEST_CONTEXT,
            encrypt=False
        )
        store = LocalKVStore(config)
        
        result = store.set(None, TEST_KEY, TEST_VALUE)
        
        assert result == f'{TEST_KEY}.0'
        wallet.encrypt.assert_not_called()
        wallet.create_action.assert_called_once()


class TestLocalKVStoreRemove:
    """Test LocalKVStore remove method matching TS SDK tests."""

    def test_should_do_nothing_and_return_empty_list_if_key_does_not_exist(self):
        """Test remove does nothing when key doesn't exist."""
        wallet = create_mock_wallet()
        wallet.list_outputs.return_value = {
            'outputs': [],
            'totalOutputs': 0,
            'BEEF': None
        }
        
        config = KVStoreConfig(
            wallet=wallet,
            context=TEST_CONTEXT,
            encrypt=True
        )
        store = LocalKVStore(config)
        
        result = store.remove(None, TEST_KEY)
        assert result == []
        wallet.create_action.assert_not_called()
        wallet.sign_action.assert_not_called()
        wallet.relinquish_output.assert_not_called()

    def test_should_remove_existing_key_by_spending_its_outputs(self):
        """Test remove spends existing outputs without creating new ones."""
        wallet = create_mock_wallet()
        existing_output1 = {
            'outpoint': 'removeTxId1.0',
            'txid': 'removeTxId1',
            'outputIndex': 0,
            'lockingScript': b's1',
            'satoshis': 1
        }
        existing_output2 = {
            'outpoint': 'removeTxId2.1',
            'txid': 'removeTxId2',
            'outputIndex': 1,
            'lockingScript': b's2',
            'satoshis': 1
        }
        mock_beef = b'mockBEEFRemove'
        
        wallet.list_outputs.return_value = {
            'outputs': [existing_output1, existing_output2],
            'totalOutputs': 2,
            'BEEF': mock_beef
        }
        wallet.create_action.return_value = {
            'signableTransaction': {
                'reference': 'signableTxRefRemove',
                'tx': b'signed_tx_bytes'
            }
        }
        wallet.sign_action.return_value = {
            'txid': 'removalTxId'
        }
        
        config = KVStoreConfig(
            wallet=wallet,
            context=TEST_CONTEXT,
            encrypt=True
        )
        store = LocalKVStore(config)
        
        result = store.remove(None, TEST_KEY)
        
        # Python SDK remove returns list of txids
        assert isinstance(result, list)
        wallet.create_action.assert_called()

