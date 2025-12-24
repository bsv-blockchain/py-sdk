"""
Comprehensive error handling tests for LocalKVStore
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from bsv.keystore.local_kv_store import LocalKVStore
from bsv.keystore.interfaces import (
    KVStoreConfig,
    ErrEmptyContext,
    ErrInvalidWallet,
    ErrInvalidKey,
    ErrInvalidValue,
)


class TestLocalKVStoreErrorHandling:
    """Test error handling in LocalKVStore."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_wallet = Mock()
        self.valid_config = KVStoreConfig(
            wallet=self.mock_wallet,
            context="test_context",
            originator="test_originator"
        )

    def test_set_invalid_key_types(self):
        """Test set with various invalid key types."""
        store = LocalKVStore(self.valid_config)

        # Test None key (this will fail before validation)
        with pytest.raises((ErrInvalidKey, TypeError)):
            store.set(None, None, "value")

        # Test empty string key
        with pytest.raises(ErrInvalidKey):
            store.set(None, "", "value")

        # Note: whitespace-only keys are allowed by current validation

    def test_set_invalid_value_types(self):
        """Test set with invalid value types."""
        store = LocalKVStore(self.valid_config)

        # Test None value (this will fail before validation)
        with pytest.raises((ErrInvalidValue, TypeError)):
            store.set(None, "key", None)

        # Test empty string value
        with pytest.raises(ErrInvalidValue):
            store.set(None, "key", "")

        # Note: whitespace-only values are allowed by current validation

    def test_get_invalid_key_types(self):
        """Test get with various invalid key types."""
        store = LocalKVStore(self.valid_config)

        # Test None key (this will fail before validation)
        with pytest.raises((ErrInvalidKey, TypeError)):
            store.get(None, None)

        # Test empty string key
        with pytest.raises(ErrInvalidKey):
            store.get(None, "")

        # Note: whitespace-only keys are allowed by current validation


    def test_get_wallet_operation_failure(self):
        """Test get when wallet operations fail."""
        store = LocalKVStore(self.valid_config)

        # Mock _lookup_outputs_for_get to raise exception
        with patch.object(store, '_lookup_outputs_for_get', side_effect=Exception("Wallet lookup failed")):
            with pytest.raises(Exception, match="Wallet lookup failed"):
                store.get(None, "test_key")

    def test_encryption_config(self):
        """Test encryption configuration handling."""
        config = KVStoreConfig(
            wallet=self.mock_wallet,
            context="test_context",
            originator="test_originator",
            encrypt=True
        )
        store = LocalKVStore(config)
        assert store._encrypt is True

    def test_context_validation_errors(self):
        """Test various context validation failures."""
        # Test None context
        config = KVStoreConfig(
            wallet=self.mock_wallet,
            context=None,
            originator="test_originator"
        )
        with pytest.raises(ErrEmptyContext):
            LocalKVStore(config)

        # Test empty context
        config = KVStoreConfig(
            wallet=self.mock_wallet,
            context="",
            originator="test_originator"
        )
        with pytest.raises(ErrEmptyContext):
            LocalKVStore(config)

    def test_wallet_validation_errors(self):
        """Test wallet validation failures."""
        # Test None wallet
        config = KVStoreConfig(
            wallet=None,
            context="test_context",
            originator="test_originator"
        )
        with pytest.raises(ErrInvalidWallet):
            LocalKVStore(config)

    def test_empty_outputs_handling(self):
        """Test handling when no outputs are found."""
        store = LocalKVStore(self.valid_config)

        # Mock empty outputs
        with patch.object(store, '_lookup_outputs_for_get', return_value=([], b"")):
            result = store.get(None, "nonexistent_key", "default")
            assert result == "default"

    def test_remove_nonexistent_key(self):
        """Test remove operation on nonexistent key."""
        store = LocalKVStore(self.valid_config)

        # Mock empty outputs for remove (needs 3-tuple: outputs, beef, total)
        with patch.object(store, '_lookup_outputs_for_remove', return_value=([], b"", 0)):
            result = store.remove(None, "nonexistent_key")
            assert result == []  # Should return empty list
