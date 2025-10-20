import pytest

from types import SimpleNamespace
from bsv.keystore import LocalKVStore, KVStoreConfig
from bsv.keystore.interfaces import ErrInvalidKey, ErrInvalidValue


class DummyWallet(SimpleNamespace):
    """Mock wallet with required methods for LocalKVStore testing."""
    
    def __init__(self):
        super().__init__()
        self.kv_storage = {}  # Simple in-memory storage for testing
    
    def list_outputs(self, ctx, args, originator):
        """Mock list_outputs method that returns mock KV outputs."""
        # Simulate finding a KV output for the requested key
        tags = args.get("tags", [])
        if tags and len(tags) > 0:
            key = tags[0]  # First tag is the key
            # Only return data for keys that have been "set" (simulate storage)
            if hasattr(self, 'kv_storage') and key in self.kv_storage:
                value = self.kv_storage[key]
                # Create a locking script that contains the value
                value_hex = value.encode('utf-8').hex()
                locking_script_hex = f"2102a1633cafb311f41c1137864d7dd7cf2d5c9e5c2e5b5f5a5d5c5b5a59584f5e5fac{len(value_hex)//2:02x}{value_hex}2c64756d6d795f7369676e61747572655f666f725f74657374696e675f707572706f7365735f333262797465736d"
                return {
                    "outputs": [{
                        "outputIndex": 0,
                        "satoshis": 1,
                        "lockingScript": bytes.fromhex(locking_script_hex),
                        "spendable": True,
                        "outputDescription": "KV set (local)",
                        "basket": args.get("basket", "test"),
                        "tags": ["kv", "set"],
                        "txid": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                    }],
                    "beef": b"mock_beef_data_for_testing"
                }
        return {"outputs": [], "beef": b""}
    
    def create_action(self, ctx, args, originator):
        """Mock create_action method."""
        # Extract key and value from the action description for KV operations
        description = args.get("description", "")
        if "kvstore set" in description:
            # Extract key from description like "kvstore set foo"
            parts = description.split()
            if len(parts) >= 3:
                key = parts[2]
                # Find the value from outputs (this is a simplified approach)
                outputs = args.get("outputs", [])
                if outputs and len(outputs) > 0:
                    # In a real implementation, we'd parse the locking script
                    # For testing, we'll use a simple approach
                    pass
        elif "kvstore remove" in description:
            # Extract key from description like "kvstore remove k1"
            parts = description.split()
            if len(parts) >= 3:
                key = parts[2]
                if hasattr(self, 'kv_storage') and key in self.kv_storage:
                    del self.kv_storage[key]
        
        return {
            "tx": "0100000001abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789000000006a473044022012345678901234567890123456789012345678901234567890123456789012340220abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab012103a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789affffffff0100e1f505000000001976a914abcdefabcdefabcdefabcdefabcdefabcdefabcdef88ac00000000",
            "txid": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
            "outputs": [{"vout": 0, "satoshis": 100000000}]
        }
    
    def get_public_key(self, ctx, args, originator):
        """Mock get_public_key method."""
        return {"publicKey": "02a1633cafb311f41c1137864d7dd7cf2d5c9e5c2e5b5f5a5d5c5b5a59584f5e5f"}
    
    def create_signature(self, ctx, args, originator):
        """Mock create_signature method."""
        return {"signature": b"dummy_signature_for_testing_purposes_32bytes"}
    
    def verify_signature(self, ctx, args, originator):
        """Mock verify_signature method."""
        return {"valid": True}
    
    def internalize_action(self, ctx, args, originator):
        """Mock internalize_action method."""
        # This is called after create_action, so we can extract the key-value from the transaction
        # For testing purposes, we'll use a simple approach to track set operations
        tx_bytes = args.get("tx")
        if tx_bytes and hasattr(self, '_pending_kv_operation'):
            key, value = self._pending_kv_operation
            self.kv_storage[key] = value
            delattr(self, '_pending_kv_operation')
        return {"accepted": True, "txid": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"}
    
    def sign_action(self, ctx, args, originator):
        """Mock sign_action method."""
        return {"tx": "signed_transaction_bytes", "txid": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"}


def make_store(context: str = "test") -> LocalKVStore:
    wallet = DummyWallet()
    cfg = KVStoreConfig(wallet=wallet, context=context)
    store = LocalKVStore(cfg)
    # Hook into the store to track set operations
    original_set = store.set
    def patched_set(ctx, key, value, ca_args=None):
        result = original_set(ctx, key, value, ca_args)
        # Store the key-value pair in our mock wallet for later retrieval
        wallet.kv_storage[key] = value
        return result
    store.set = patched_set
    return store


def test_set_and_get():
    store = make_store()
    outpoint = store.set(None, "foo", "bar")
    assert outpoint == "foo.0"
    assert store.get(None, "foo") == "bar"


def test_get_default_value():
    store = make_store()
    assert store.get(None, "missing", default_value="default") == "default"


def test_remove_key():
    store = make_store()
    store.set(None, "k1", "v1")
    txids = store.remove(None, "k1")
    assert txids == ["removed:k1"]
    assert store.get(None, "k1", "") == ""


def test_invalid_key_errors():
    store = make_store()
    with pytest.raises(ErrInvalidKey):
        store.set(None, "", "value")
    with pytest.raises(ErrInvalidKey):
        store.get(None, "")
    with pytest.raises(ErrInvalidKey):
        store.remove(None, "")


def test_invalid_value_errors():
    store = make_store()
    with pytest.raises(ErrInvalidValue):
        store.set(None, "foo", "")

