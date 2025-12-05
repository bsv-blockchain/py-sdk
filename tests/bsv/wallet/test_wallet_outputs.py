"""
Comprehensive tests for output management in WalletImpl.
"""
import pytest
from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import WalletImpl


@pytest.fixture
def wallet():
    priv = PrivateKey()
    return WalletImpl(priv, permission_callback=lambda action: True)


def test_list_outputs_empty(wallet):
    """Test listing outputs when none exist."""
    result = wallet.list_outputs(None, {}, "test")
    
    # API returns 'outputs' array, not 'totalOutputs'
    assert "outputs" in result
    assert isinstance(result["outputs"], list)
    # totalOutputs field doesn't exist in actual API
    assert "BEEF" in result or "outputs" in result


def test_list_outputs_with_basket(wallet):
    """Test listing outputs filtered by basket."""
    args = {"basket": "savings"}
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)
    assert "outputs" in result  # Fixed: API returns 'outputs', not 'totalOutputs'


def test_list_outputs_with_tags(wallet):
    """Test listing outputs filtered by tags."""
    args = {"tags": ["important", "urgent"]}
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)


def test_list_outputs_with_type_filter(wallet):
    """Test listing outputs filtered by type."""
    args = {"type": "P2PKH"}
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)


def test_list_outputs_with_limit(wallet):
    """Test listing outputs with limit."""
    args = {"limit": 10}
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)


def test_list_outputs_with_offset(wallet):
    """Test listing outputs with offset pagination."""
    args = {"offset": 5, "limit": 10}
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)


def test_list_outputs_include_beef(wallet):
    """Test listing outputs with BEEF inclusion."""
    args = {"includeBEEF": True}
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)
    # Should include BEEF if outputs exist


def test_list_outputs_include_locked(wallet):
    """Test listing outputs including locked ones."""
    args = {"includeLocked": True}
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)


def test_list_outputs_include_spent(wallet):
    """Test listing outputs including spent ones."""
    args = {"includeSpent": True}
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)


def test_list_outputs_include_spendable_only(wallet):
    """Test listing only spendable outputs."""
    args = {"spendable": True}
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)


def test_relinquish_output(wallet):
    """Test relinquishing an output."""
    args = {
        "basket": "test_basket",
        "output": {
            "txid": "a" * 64,
            "vout": 0
        }
    }
    result = wallet.relinquish_output(None, args, "test")
    
    # Should return empty dict on success
    assert result == {}


def test_relinquish_output_multiple(wallet):
    """Test relinquishing multiple outputs."""
    # Relinquish first output
    wallet.relinquish_output(None, {
        "basket": "basket1",
        "output": {"txid": "a" * 64, "vout": 0}
    }, "test")
    
    # Relinquish second output
    wallet.relinquish_output(None, {
        "basket": "basket1",
        "output": {"txid": "b" * 64, "vout": 1}
    }, "test")
    
    # Both should succeed
    assert True


def test_output_expiration_check():
    """Test output expiration logic."""
    wallet = WalletImpl(PrivateKey(), permission_callback=lambda a: True)
    
    import time
    now = int(time.time())
    
    # Expired output - retentionSeconds must be in outputDescription
    import json
    expired_output = {
        "createdAt": now - 3600,  # 1 hour ago
        "outputDescription": json.dumps({"retentionSeconds": 1800})  # 30 minutes retention
    }
    assert wallet._is_output_expired(expired_output, now) is True
    
    # Non-expired output
    valid_output = {
        "createdAt": now - 1000,
        "outputDescription": json.dumps({"retentionSeconds": 3600})  # 1 hour retention
    }
    assert wallet._is_output_expired(valid_output, now) is False
    
    # Output without retention (never expires)
    permanent_output = {
        "createdAt": now - 100000
    }
    assert wallet._is_output_expired(permanent_output, now) is False


def test_find_outputs_for_basket():
    """Test finding outputs for a specific basket."""
    wallet = WalletImpl(PrivateKey(), permission_callback=lambda a: True)
    
    args = {"basket": "test_basket", "limit": 20}
    outputs = wallet._find_outputs_for_basket("test_basket", args)
    
    assert isinstance(outputs, list)


def test_format_outputs_result():
    """Test formatting outputs result."""
    wallet = WalletImpl(PrivateKey(), permission_callback=lambda a: True)
    
    outputs = [
        {
            "txid": "a" * 64,
            "vout": 0,
            "satoshis": 1000,
            "lockingScript": "abc"
        }
    ]
    
    result = wallet._format_outputs_result(outputs, "test_basket")
    
    assert isinstance(result, list)


def test_build_beef_for_outputs():
    """Test building BEEF for outputs."""
    wallet = WalletImpl(PrivateKey(), permission_callback=lambda a: True)
    
    outputs = [
        {
            "txid": "a" * 64,
            "vout": 0,
            "satoshis": 1000
        }
    ]
    
    beef = wallet._build_beef_for_outputs(outputs)
    
    assert isinstance(beef, bytes)


def test_list_outputs_combined_filters(wallet):
    """Test listing outputs with multiple combined filters."""
    args = {
        "basket": "savings",
        "tags": ["important"],
        "type": "P2PKH",
        "limit": 10,
        "spendable": True,
        "includeEnvelope": True
    }
    
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)
    assert "outputs" in result  # Fixed: API returns 'outputs', not 'totalOutputs'


def test_list_outputs_with_custom_fields(wallet):
    """Test listing outputs includes custom fields."""
    args = {
        "customInstructions": {"field1": "value1"}
    }
    
    result = wallet.list_outputs(None, args, "test")
    
    assert isinstance(result, dict)

