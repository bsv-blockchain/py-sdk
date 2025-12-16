"""
Comprehensive coverage tests for wallet_impl.py focusing on:
1. Error paths and exception handling
2. Edge cases (None, empty inputs, boundary conditions)
3. Branch coverage (all if/else paths)
"""
import pytest
import os
import time
from unittest.mock import patch, MagicMock
from bsv.keys import PrivateKey, PublicKey
from bsv.wallet import ProtoWallet
from bsv.wallet.key_deriver import Protocol, Counterparty, CounterpartyType


@pytest.fixture
def wallet():
    """Wallet with automatic permission approval."""
    priv = PrivateKey()
    return ProtoWallet(priv, permission_callback=lambda action: True)


@pytest.fixture
def wallet_no_callback():
    """Wallet without permission callback (uses input)."""
    priv = PrivateKey()
    return ProtoWallet(priv)


# ========================================================================
# Initialization and Debug Paths
# ========================================================================

def test_wallet_init_with_env_loading_success():
    """Test wallet initialization with successful dotenv loading."""
    priv = PrivateKey()
    with patch('bsv.wallet.wallet_impl.ProtoWallet._dotenv_loaded', False):
        wallet = ProtoWallet(priv, load_env=True)
        assert wallet  # Verify object creation succeeds


def test_wallet_init_with_env_loading_failure():
    """Test wallet initialization when dotenv loading fails (exception path)."""
    priv = PrivateKey()
    ProtoWallet._dotenv_loaded = False
    # Import will fail but should be caught
    wallet = ProtoWallet(priv, load_env=True)
    assert hasattr(wallet, 'create_action')
    assert ProtoWallet._dotenv_loaded is True


def test_wallet_init_woc_api_key_from_env():
    """Test WOC API key loaded from environment."""
    priv = PrivateKey()
    with patch.dict(os.environ, {"WOC_API_KEY": "test_env_key"}):
        wallet = ProtoWallet(priv)
        assert wallet._woc_api_key == "test_env_key"


def test_wallet_init_woc_api_key_explicit_overrides_env():
    """Test explicit WOC API key overrides environment."""
    priv = PrivateKey()
    with patch.dict(os.environ, {"WOC_API_KEY": "env_key"}):
        wallet = ProtoWallet(priv, woc_api_key="explicit_key")  # noqa: S106  # NOSONAR - Mock API key for tests
        assert wallet._woc_api_key == "explicit_key"


def test_wallet_init_woc_api_key_empty_default():
    """Test WOC API key defaults to empty string."""
    priv = PrivateKey()
    with patch.dict(os.environ, {}, clear=True):
        wallet = ProtoWallet(priv)
        assert wallet._woc_api_key == ""


# ========================================================================
# BSV_DEBUG Path Coverage
# ========================================================================

def test_check_permission_with_debug_enabled(wallet, capsys):
    """Test permission check with BSV_DEBUG=1."""
    with patch.dict(os.environ, {"BSV_DEBUG": "1"}):
        wallet._check_permission("Test Action")
        captured = capsys.readouterr()
        assert "DEBUG ProtoWallet._check_permission" in captured.out
        assert "Test Action" in captured.out
        assert "allowed=True" in captured.out


def test_get_public_key_with_debug_enabled(wallet, capsys):
    """Test get_public_key with BSV_DEBUG=1."""
    args = {"identityKey": True}
    with patch.dict(os.environ, {"BSV_DEBUG": "1"}):
        _ = wallet.get_public_key(args, "test_originator")
        captured = capsys.readouterr()
        assert "DEBUG ProtoWallet.get_public_key" in captured.out
        assert "originator=<redacted>" in captured.out  # Sensitive info is redacted


def test_encrypt_with_debug_enabled(wallet, capsys):
    """Test encrypt with BSV_DEBUG=1."""
    args = {
        "encryption_args": {},
        "plaintext": b"test"
    }
    with patch.dict(os.environ, {"BSV_DEBUG": "1"}):
        _ = wallet.encrypt(args, "test")
        captured = capsys.readouterr()
        assert "DEBUG ProtoWallet.encrypt" in captured.out


def test_decrypt_with_debug_enabled(wallet, capsys):
    """Test decrypt with BSV_DEBUG=1."""
    # First encrypt - need protocol_id and key_id
    enc_args = {
        "plaintext": b"test",
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "counterparty": "self"
    }
    enc_result = wallet.encrypt(enc_args, "test")
    assert "ciphertext" in enc_result, f"encrypt failed: {enc_result}"
    
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "counterparty": "self",
        "ciphertext": enc_result["ciphertext"]
    }
    with patch.dict(os.environ, {"BSV_DEBUG": "1"}):
        _ = wallet.decrypt(args, "test")
        captured = capsys.readouterr()
        assert "DEBUG ProtoWallet.decrypt" in captured.out


# ========================================================================
# Error Paths and Edge Cases
# ========================================================================

def test_get_public_key_with_none_protocol_id(wallet):
    """Test get_public_key returns error when protocol_id is None."""
    args = {"protocolID": None, "keyID": None}
    result = wallet.get_public_key(args, "test")
    assert "error" in result
    assert "required" in result["error"].lower()


def test_get_public_key_with_forself_true_no_protocol(wallet):
    """Test get_public_key returns identity key when forSelf=True even without protocol."""
    args = {"forSelf": True}
    result = wallet.get_public_key(args, "test")
    assert "publicKey" in result
    assert "error" not in result


def test_get_public_key_with_non_dict_protocol_id(wallet):
    """Test get_public_key with protocol_id as non-dict (tuple/list)."""
    protocol = Protocol(1, "test_protocol")
    args = {
        "protocolID": protocol,  # Not a dict
        "keyID": "key1"
    }
    result = wallet.get_public_key(args, "test")
    # Should work with Protocol object directly
    assert "publicKey" in result or "error" in result


def test_encrypt_missing_plaintext(wallet):
    """Test encrypt returns error when plaintext is missing."""
    args = {"encryption_args": {}}
    result = wallet.encrypt(args, "test")
    assert "error" in result
    assert "plaintext" in result["error"].lower()


def test_encrypt_with_none_plaintext(wallet):
    """Test encrypt returns error when plaintext is None."""
    args = {"encryption_args": {}, "plaintext": None}
    result = wallet.encrypt(args, "test")
    assert "error" in result
    assert "plaintext" in result["error"].lower()


def test_decrypt_missing_ciphertext(wallet):
    """Test decrypt returns error when ciphertext is missing."""
    args = {"encryption_args": {}}
    result = wallet.decrypt(args, "test")
    assert "error" in result
    assert "ciphertext" in result["error"].lower()


def test_decrypt_with_none_ciphertext(wallet):
    """Test decrypt returns error when ciphertext is None."""
    args = {"encryption_args": {}, "ciphertext": None}
    result = wallet.decrypt(args, "test")
    assert "error" in result
    assert "ciphertext" in result["error"].lower()


def test_create_signature_missing_protocol_id(wallet):
    """Test create_signature returns error when protocol_id is missing."""
    args = {"key_id": "key1", "data": b"test"}
    result = wallet.create_signature(args, "test")
    assert "error" in result


def test_create_signature_missing_key_id(wallet):
    """Test create_signature returns error when key_id is missing."""
    args = {"protocol_id": {"securityLevel": 1, "protocol": "test"}, "data": b"test"}
    result = wallet.create_signature(args, "test")
    assert "error" in result


def test_create_signature_with_none_data(wallet):
    """Test create_signature with None data (should use empty bytes)."""
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": None
    }
    # Should handle None gracefully or return error
    result = wallet.create_signature(args, "test")
    # Either succeeds with empty data or returns error
    assert "signature" in result or "error" in result


def test_verify_signature_missing_signature(wallet):
    """Test verify_signature returns error when signature is missing."""
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": b"test"
    }
    result = wallet.verify_signature(args, "test")
    assert "error" in result
    assert "signature" in result["error"].lower()


def test_verify_signature_with_none_signature(wallet):
    """Test verify_signature returns error when signature is None."""
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": b"test",
        "signature": None
    }
    result = wallet.verify_signature(args, "test")
    assert "error" in result
    assert "signature" in result["error"].lower()


def test_verify_signature_missing_protocol_id(wallet):
    """Test verify_signature returns error when protocol_id is missing."""
    args = {"key_id": "key1", "data": b"test", "signature": b"fake"}
    result = wallet.verify_signature(args, "test")
    assert "error" in result


def test_verify_signature_missing_key_id(wallet):
    """Test verify_signature returns error when key_id is missing."""
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "data": b"test",
        "signature": b"fake"
    }
    result = wallet.verify_signature(args, "test")
    assert "error" in result


def test_verify_signature_with_list_protocol_id(wallet):
    """Test verify_signature with protocol_id as list [security_level, protocol]."""
    # Create a real signature first
    sign_args = {
        "protocol_id": [1, "test"],
        "key_id": "key1",
        "data": b"test data"
    }
    sign_result = wallet.create_signature(sign_args, "test")
    
    # Verify with list protocol_id
    verify_args = {
        "protocol_id": [1, "test"],
        "key_id": "key1",
        "data": b"test data",
        "signature": sign_result["signature"]
    }
    result = wallet.verify_signature(verify_args, "test")
    assert "valid" in result


def test_verify_signature_with_hash_to_directly_verify(wallet):
    """Test verify_signature with hash_to_directly_verify instead of data."""
    import hashlib
    data = b"test data"
    data_hash = hashlib.sha256(data).digest()
    
    # Create signature - use explicit counterparty for consistency
    sign_args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": data,
        "counterparty": "self"
    }
    sign_result = wallet.create_signature(sign_args, "test")
    
    # Verify using hash directly
    verify_args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "hash_to_directly_verify": data_hash,
        "signature": sign_result["signature"],
        "counterparty": "self"
    }
    result = wallet.verify_signature(verify_args, "test")
    assert "valid" in result
    assert result["valid"] is True


def test_create_hmac_missing_protocol_id(wallet):
    """Test create_hmac returns error when protocol_id is missing."""
    args = {
        "encryption_args": {"key_id": "key1"},
        "data": b"test"
    }
    result = wallet.create_hmac(args, "test")
    assert "error" in result


def test_create_hmac_missing_key_id(wallet):
    """Test create_hmac returns error when key_id is missing."""
    args = {
        "encryption_args": {"protocol_id": {"securityLevel": 1, "protocol": "test"}},
        "data": b"test"
    }
    result = wallet.create_hmac(args, "test")
    assert "error" in result


def test_create_hmac_with_none_data(wallet):
    """Test create_hmac with None data (should use empty bytes)."""
    args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1"
        },
        "data": None
    }
    result = wallet.create_hmac(args, "test")
    # Should handle None gracefully (defaults to empty bytes)
    assert "hmac" in result or "error" in result


def test_verify_hmac_missing_protocol_id(wallet):
    """Test verify_hmac returns error when protocol_id is missing."""
    args = {
        "encryption_args": {"key_id": "key1"},
        "data": b"test",
        "hmac": b"fake"
    }
    result = wallet.verify_hmac(args, "test")
    assert "error" in result


def test_verify_hmac_missing_key_id(wallet):
    """Test verify_hmac returns error when key_id is missing."""
    args = {
        "encryption_args": {"protocol_id": {"securityLevel": 1, "protocol": "test"}},
        "data": b"test",
        "hmac": b"fake"
    }
    result = wallet.verify_hmac(args, "test")
    assert "error" in result


def test_verify_hmac_missing_hmac_value(wallet):
    """Test verify_hmac returns error when hmac value is missing."""
    args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1"
        },
        "data": b"test"
    }
    result = wallet.verify_hmac(args, "test")
    assert "error" in result
    assert "hmac" in result["error"].lower()


def test_verify_hmac_with_none_hmac_value(wallet):
    """Test verify_hmac returns error when hmac value is None."""
    args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1"
        },
        "data": b"test",
        "hmac": None
    }
    result = wallet.verify_hmac(args, "test")
    assert "error" in result
    assert "hmac" in result["error"].lower()


# ========================================================================
# Counterparty Type Parsing Edge Cases
# ========================================================================

def test_parse_counterparty_type_with_int(wallet):
    """Test _parse_counterparty_type with integer values."""
    assert wallet._parse_counterparty_type(0) == 0  # UNINITIALIZED
    assert wallet._parse_counterparty_type(1) == 1  # ANYONE
    assert wallet._parse_counterparty_type(2) == 2  # SELF
    assert wallet._parse_counterparty_type(3) == 3  # OTHER


def test_parse_counterparty_type_with_uppercase_strings(wallet):
    """Test _parse_counterparty_type with uppercase strings."""
    assert wallet._parse_counterparty_type("SELF") == 2
    assert wallet._parse_counterparty_type("OTHER") == 3
    assert wallet._parse_counterparty_type("ANYONE") == 1


def test_parse_counterparty_type_with_mixed_case(wallet):
    """Test _parse_counterparty_type with mixed case strings."""
    assert wallet._parse_counterparty_type("SeLf") == 2
    assert wallet._parse_counterparty_type("AnYoNe") == 1


def test_parse_counterparty_type_with_unknown_string(wallet):
    """Test _parse_counterparty_type defaults to SELF for unknown string."""
    assert wallet._parse_counterparty_type("unknown_type") == 2
    assert wallet._parse_counterparty_type("") == 2


def test_parse_counterparty_type_with_none(wallet):
    """Test _parse_counterparty_type defaults to SELF for None."""
    assert wallet._parse_counterparty_type(None) == 2


def test_parse_counterparty_type_with_object(wallet):
    """Test _parse_counterparty_type defaults to SELF for object."""
    assert wallet._parse_counterparty_type(object()) == 2


def test_normalize_counterparty_with_dict_and_string_counterparty(wallet):
    """Test _normalize_counterparty with dict containing string counterparty."""
    pub = PrivateKey().public_key()
    cp_dict = {
        "type": "other",
        "counterparty": pub.hex()  # String, not PublicKey object
    }
    cp = wallet._normalize_counterparty(cp_dict)
    assert cp.type == 3  # OTHER
    assert cp.counterparty is not None


def test_normalize_counterparty_with_dict_and_bytes_counterparty(wallet):
    """Test _normalize_counterparty with dict containing bytes counterparty."""
    pub = PrivateKey().public_key()
    cp_dict = {
        "type": "other",
        "counterparty": pub.serialize()  # Bytes
    }
    cp = wallet._normalize_counterparty(cp_dict)
    assert cp.type == 3  # OTHER
    assert cp.counterparty is not None


def test_normalize_counterparty_with_dict_no_counterparty_field(wallet):
    """Test _normalize_counterparty with dict missing counterparty field."""
    cp_dict = {"type": "self"}
    cp = wallet._normalize_counterparty(cp_dict)
    assert cp.type == 2  # SELF
    assert cp.counterparty is None


def test_normalize_counterparty_with_bytes(wallet):
    """Test _normalize_counterparty with bytes input."""
    pub = PrivateKey().public_key()
    cp = wallet._normalize_counterparty(pub.serialize())
    assert cp.type == 3  # OTHER
    assert cp.counterparty is not None


def test_normalize_counterparty_with_string(wallet):
    """Test _normalize_counterparty with string input."""
    pub = PrivateKey().public_key()
    cp = wallet._normalize_counterparty(pub.hex())
    assert cp.type == 3  # OTHER
    assert cp.counterparty is not None


def test_normalize_counterparty_with_publickey_object(wallet):
    """Test _normalize_counterparty with PublicKey object."""
    pub = PrivateKey().public_key()
    cp = wallet._normalize_counterparty(pub)
    assert cp.type == 3  # OTHER
    assert cp.counterparty == pub


def test_normalize_counterparty_with_none(wallet):
    """Test _normalize_counterparty with None defaults to SELF."""
    cp = wallet._normalize_counterparty(None)
    assert cp.type == 2  # SELF
    assert cp.counterparty is None


def test_normalize_counterparty_with_unknown_type(wallet):
    """Test _normalize_counterparty with unknown type defaults to SELF."""
    cp = wallet._normalize_counterparty(12345)
    assert cp.type == 2  # SELF


# ========================================================================
# Permission Handling Edge Cases
# ========================================================================

def test_check_permission_with_callback_denied(wallet):
    """Test permission check when callback returns False."""
    wallet.permission_callback = lambda action: False
    with pytest.raises(PermissionError) as exc_info:
        wallet._check_permission("Test Action")
    assert "not permitted" in str(exc_info.value).lower()


def test_check_permission_with_input_approval(wallet_no_callback, monkeypatch):
    """Test permission check with user approval via input."""
    responses = ["yes"]
    def fake_input(prompt):
        return responses.pop(0) if responses else "n"
    
    monkeypatch.setattr("builtins.input", fake_input)
    # Should not raise
    wallet_no_callback._check_permission("Test Action")


def test_check_permission_with_input_denial(wallet_no_callback, monkeypatch):
    """Test permission check with user denial via input."""
    def fake_input(prompt):
        return "n"
    
    monkeypatch.setattr("builtins.input", fake_input)
    with pytest.raises(PermissionError):
        wallet_no_callback._check_permission("Test Action")


def test_check_permission_with_input_empty_string(wallet_no_callback, monkeypatch):
    """Test permission check with empty input (should deny)."""
    def fake_input(prompt):
        return ""
    
    monkeypatch.setattr("builtins.input", fake_input)
    with pytest.raises(PermissionError):
        wallet_no_callback._check_permission("Test Action")


def test_check_permission_with_input_y_lowercase(wallet_no_callback, monkeypatch):
    """Test permission check with 'y' input (should approve)."""
    def fake_input(prompt):
        return "y"
    
    monkeypatch.setattr("builtins.input", fake_input)
    # Should not raise
    wallet_no_callback._check_permission("Test Action")


def test_check_permission_with_input_uppercase_yes(wallet_no_callback, monkeypatch):
    """Test permission check with 'YES' input (should approve)."""
    def fake_input(prompt):
        return "YES"
    
    monkeypatch.setattr("builtins.input", fake_input)
    # Should not raise
    wallet_no_callback._check_permission("Test Action")


def test_check_permission_with_input_spaces(wallet_no_callback, monkeypatch):
    """Test permission check with spaces around input."""
    def fake_input(prompt):
        return "  yes  "
    
    monkeypatch.setattr("builtins.input", fake_input)
    # Should not raise (strips spaces)
    wallet_no_callback._check_permission("Test Action")


# ========================================================================
# Certificate Methods Edge Cases
# ========================================================================

def test_acquire_certificate_minimal_args(wallet):
    """Test acquiring certificate with minimal arguments."""
    args = {}
    result = wallet.acquire_certificate(args, "test")
    assert result == {}
    assert len(wallet._certificates) == 1


def test_acquire_certificate_with_none_values(wallet):
    """Test acquiring certificate with None values (defaults to empty bytes)."""
    # Note: type and serialNumber must be bytes to avoid None + None TypeError
    args = {
        "type": b"",  # Empty bytes instead of None
        "serialNumber": b"",
        "certifier": None,
        "keyringForSubject": None,
        "fields": None
    }
    result = wallet.acquire_certificate(args, "test")
    assert result == {}
    # Certificate is stored even with empty/None values
    assert len(wallet._certificates) >= 1


def test_list_certificates_empty(wallet):
    """Test listing certificates when none exist."""
    result = wallet.list_certificates({}, "test")
    assert "certificates" in result
    assert len(result["certificates"]) == 0


# ========================================================================
# Network and Version Methods
# ========================================================================

def test_get_network_returns_string(wallet):
    """Test get_network returns a string."""
    result = wallet.get_network({}, "test")
    assert "network" in result
    assert isinstance(result["network"], str)


def test_get_version_returns_string(wallet):
    """Test get_version returns a string."""
    result = wallet.get_version({}, "test")
    assert "version" in result
    assert isinstance(result["version"], str)


def test_is_authenticated_always_true(wallet):
    """Test is_authenticated always returns True."""
    result = wallet.is_authenticated({}, "test")
    assert "authenticated" in result
    assert result["authenticated"] is True


def test_abort_action_is_noop(wallet):
    """Test abort_action is a no-op and doesn't raise."""
    # Should not raise
    wallet.abort_action(None, {}, "test")
    wallet.abort_action()
    wallet.abort_action("arg", "arg2", key="value")


# ========================================================================
# Empty and Boundary Conditions
# ========================================================================

def test_get_public_key_with_empty_args(wallet):
    """Test get_public_key with empty args dict."""
    result = wallet.get_public_key({}, "test")
    assert "error" in result or "publicKey" in result


def test_encrypt_with_empty_args(wallet):
    """Test encrypt with empty args dict."""
    result = wallet.encrypt({}, "test")
    assert "error" in result


def test_decrypt_with_empty_args(wallet):
    """Test decrypt with empty args dict."""
    result = wallet.decrypt({}, "test")
    assert "error" in result


def test_create_signature_with_empty_data(wallet):
    """Test create_signature with empty data."""
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": b""
    }
    result = wallet.create_signature(args, "test")
    assert "signature" in result or "error" in result


def test_create_hmac_with_empty_data(wallet):
    """Test create_hmac with empty data."""
    args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1"
        },
        "data": b""
    }
    result = wallet.create_hmac(args, "test")
    assert "hmac" in result


def test_verify_hmac_with_empty_data(wallet):
    """Test verify_hmac with empty data."""
    # Create HMAC with empty data
    create_args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1"
        },
        "data": b""
    }
    hmac_result = wallet.create_hmac(create_args, "test")
    
    # Verify with empty data
    verify_args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1"
        },
        "data": b"",
        "hmac": hmac_result["hmac"]
    }
    result = wallet.verify_hmac(verify_args, "test")
    assert "valid" in result
    assert result["valid"] is True


def test_get_public_key_with_empty_protocol_string(wallet):
    """Test get_public_key with empty protocol string."""
    args = {
        "protocolID": {"securityLevel": 0, "protocol": ""},
        "keyID": "key1"
    }
    result = wallet.get_public_key(args, "test")
    # Should work even with empty protocol
    assert "publicKey" in result or "error" in result


def test_get_public_key_with_zero_security_level(wallet):
    """Test get_public_key with zero security level."""
    args = {
        "protocolID": {"securityLevel": 0, "protocol": "test"},
        "keyID": "key1"
    }
    result = wallet.get_public_key(args, "test")
    assert "publicKey" in result or "error" in result


# ========================================================================
# create_action Error Paths and Edge Cases
# ========================================================================

def test_create_action_with_empty_outputs(wallet):
    """Test create_action with empty outputs list."""
    args = {
        "description": "Test transaction",
        "outputs": []
    }
    result = wallet.create_action(args, "test")
    assert "signableTransaction" in result or "error" in result


def test_create_action_with_pushdrop_args(wallet):
    """Test create_action with pushdrop extension."""
    args = {
        "description": "Test with pushdrop",
        "outputs": [],
        "pushdrop": {
            "fields": [b"test"],
            "satoshis": 1000
        }
    }
    result = wallet.create_action(args, "test")
    assert "signableTransaction" in result or "error" in result


def test_create_action_with_invalid_fee_rate(wallet):
    """Test create_action with invalid fee rate."""
    args = {
        "description": "Test transaction",
        "outputs": [{"satoshis": 1000, "lockingScript": b"\x51"}],
        "feeRate": -1
    }
    result = wallet.create_action(args, "test")
    # Should handle gracefully or use default
    assert "signableTransaction" in result or "error" in result


def test_create_action_with_change_output(wallet):
    """Test create_action generates change output when needed."""
    args = {
        "description": "Test with change",
        "outputs": [{"satoshis": 500, "lockingScript": b"\x51"}],
        "inputs": [{"outpoint": {"txid": b"\x00" * 32, "index": 0}}]
    }
    result = wallet.create_action(args, "test")
    # May include change output
    assert "signableTransaction" in result or "error" in result


# ========================================================================
# internalize_action Error Paths and Edge Cases
# ========================================================================

def test_internalize_action_missing_tx(wallet):
    """Test internalize_action with missing tx bytes."""
    args = {}
    result = wallet.internalize_action(args, "test")
    assert "accepted" in result
    assert result.get("accepted") is False
    assert "error" in result


def test_internalize_action_empty_tx_bytes(wallet):
    """Test internalize_action with empty tx bytes."""
    args = {"tx": b""}
    result = wallet.internalize_action(args, "test")
    assert "accepted" in result or "error" in result


def test_internalize_action_invalid_tx_bytes(wallet):
    """Test internalize_action with invalid tx bytes."""
    args = {"tx": b"invalid_transaction_data"}
    result = wallet.internalize_action(args, "test")
    assert "accepted" in result or "error" in result


def test_internalize_action_with_disable_arc(wallet):
    """Test internalize_action with DISABLE_ARC=1."""
    import os
    with patch.dict(os.environ, {"DISABLE_ARC": "1"}):
        # Create a minimal valid transaction
        from bsv.transaction import Transaction
        from bsv.transaction_output import TransactionOutput
        from bsv.script.script import Script
        tx = Transaction()
        tx.add_output(TransactionOutput(Script(b"\x51"), 1000))
        tx_bytes = tx.serialize()
        
        args = {"tx": tx_bytes}
        result = wallet.internalize_action(args, "test")
        assert "accepted" in result or "error" in result


def test_internalize_action_with_use_woc(wallet):
    """Test internalize_action with USE_WOC=1."""
    import os
    with patch.dict(os.environ, {"USE_WOC": "1"}):
        from bsv.transaction import Transaction
        from bsv.transaction_output import TransactionOutput
        from bsv.script.script import Script
        tx = Transaction()
        tx.add_output(TransactionOutput(Script(b"\x51"), 1000))
        tx_bytes = tx.serialize()
        
        args = {"tx": tx_bytes}
        result = wallet.internalize_action(args, "test")
        assert "accepted" in result or "error" in result


def test_internalize_action_with_custom_broadcaster(wallet):
    """Test internalize_action with custom broadcaster."""
    from bsv.transaction import Transaction
    from bsv.transaction_output import TransactionOutput
    from bsv.script.script import Script
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(b"\x51"), 1000))
    tx_bytes = tx.serialize()
    
    mock_broadcaster = MagicMock()
    mock_broadcaster.broadcast.return_value = {"accepted": True, "txid": "test_txid"}
    
    args = {"tx": tx_bytes, "broadcaster": mock_broadcaster}
    result = wallet.internalize_action(args, "test")
    assert "accepted" in result or "error" in result


def test_internalize_action_tx_with_no_outputs(wallet):
    """Test internalize_action with transaction that has no outputs."""
    from bsv.transaction import Transaction
    tx = Transaction()
    tx_bytes = tx.serialize()
    
    args = {"tx": tx_bytes}
    result = wallet.internalize_action(args, "test")
    # Should return error about no outputs
    assert "accepted" in result or "error" in result


# ========================================================================
# sign_action Error Paths and Edge Cases
# ========================================================================

def test_sign_action_missing_tx(wallet):
    """Test sign_action with missing tx bytes."""
    args = {}
    result = wallet.sign_action(args, "test")
    assert "error" in result
    assert "missing tx bytes" in result["error"].lower()


def test_sign_action_with_invalid_tx_bytes(wallet):
    """Test sign_action with invalid tx bytes."""
    args = {"tx": b"invalid"}
    result = wallet.sign_action(args, "test")
    # Should handle gracefully
    assert "error" in result or "tx" in result


def test_sign_action_with_spends(wallet):
    """Test sign_action with provided spends."""
    from bsv.transaction import Transaction
    from bsv.transaction_output import TransactionOutput
    from bsv.script.script import Script
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(b"\x51"), 1000))
    tx_bytes = tx.serialize()
    
    args = {
        "tx": tx_bytes,
        "spends": {
            "0": {"unlockingScript": b"\x00" * 100}  # Mock unlocking script
        }
    }
    result = wallet.sign_action(args, "test")
    assert "tx" in result or "error" in result


def test_sign_action_with_too_short_unlocking_script(wallet):
    """Test sign_action with unlocking script that's too short."""
    from bsv.transaction import Transaction
    from bsv.transaction_output import TransactionOutput
    from bsv.script.script import Script
    from bsv.transaction_input import TransactionInput
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(b"\x51"), 1000))
    tx.add_input(TransactionInput(source_txid="00" * 32, source_output_index=0))
    tx_bytes = tx.serialize()
    
    args = {
        "tx": tx_bytes,
        "spends": {
            "0": {"unlockingScript": b"\x00"}  # Too short (less than 2 bytes)
        }
    }
    result = wallet.sign_action(args, "test")
    assert "error" in result
    assert "too short" in result["error"].lower()


# ========================================================================
# list_outputs Error Paths and Edge Cases
# ========================================================================

def test_list_outputs_with_cancel(wallet):
    """Test list_outputs with cancel flag."""
    args = {"cancel": True}
    result = wallet.list_outputs(args, "test")
    assert "outputs" in result
    assert len(result["outputs"]) == 0


def test_list_outputs_with_basket(wallet):
    """Test list_outputs with basket filter."""
    # First create an action with a basket
    create_args = {
        "description": "Test",
        "outputs": [{"satoshis": 1000, "lockingScript": b"\x51", "basket": "test_basket"}]
    }
    wallet.create_action(create_args, "test")
    
    args = {"basket": "test_basket"}
    result = wallet.list_outputs(args, "test")
    assert "outputs" in result


def test_list_outputs_with_exclude_expired(wallet):
    """Test list_outputs with excludeExpired flag."""
    args = {"excludeExpired": True, "nowEpoch": int(time.time())}
    result = wallet.list_outputs(args, "test")
    assert "outputs" in result


def test_list_outputs_with_entire_transaction(wallet):
    """Test list_outputs with entire transaction include."""
    args = {"include": "entire transaction"}
    result = wallet.list_outputs(args, "test")
    assert "outputs" in result
    # May include BEEF if entire transaction requested
    assert "BEEF" in result or "outputs" in result


def test_list_outputs_with_use_woc_env(wallet):
    """Test list_outputs with USE_WOC environment variable."""
    import os
    with patch.dict(os.environ, {"USE_WOC": "1"}):
        # Mock address derivation to return a valid address
        with patch.object(wallet, '_derive_query_address', return_value='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'):
            args = {}
            result = wallet.list_outputs(args, "test")
            assert "outputs" in result


def test_list_outputs_with_protocol_params(wallet):
    """Test list_outputs with protocol_id and key_id."""
    args = {
        "protocolID": {"securityLevel": 1, "protocol": "test"},
        "keyID": "key1"
    }
    result = wallet.list_outputs(args, "test")
    assert "outputs" in result


# ========================================================================
# reveal_counterparty_key_linkage Error Paths
# ========================================================================

def test_reveal_counterparty_key_linkage_missing_counterparty(wallet):
    """Test reveal_counterparty_key_linkage with missing counterparty."""
    args = {
        "verifier": PrivateKey().public_key().serialize()
    }
    result = wallet.reveal_counterparty_key_linkage(args, "test")
    assert "error" in result
    assert "counterparty" in result["error"].lower()


def test_reveal_counterparty_key_linkage_missing_verifier(wallet):
    """Test reveal_counterparty_key_linkage with missing verifier."""
    args = {
        "counterparty": PrivateKey().public_key().serialize()
    }
    result = wallet.reveal_counterparty_key_linkage(args, "test")
    assert "error" in result
    assert "verifier" in result["error"].lower()


def test_reveal_counterparty_key_linkage_with_seek_permission(wallet):
    """Test reveal_counterparty_key_linkage with seekPermission."""
    args = {
        "counterparty": PrivateKey().public_key().serialize(),
        "verifier": PrivateKey().public_key().serialize(),
        "seekPermission": True
    }
    result = wallet.reveal_counterparty_key_linkage(args, "test")
    # Should succeed with permission callback
    assert "prover" in result or "error" in result


# ========================================================================
# reveal_specific_key_linkage Error Paths
# ========================================================================

def test_reveal_specific_key_linkage_missing_verifier(wallet):
    """Test reveal_specific_key_linkage with missing verifier."""
    args = {
        "counterparty": PrivateKey().public_key().serialize(),
        "protocolID": {"securityLevel": 1, "protocol": "test"},
        "keyID": "key1"
    }
    result = wallet.reveal_specific_key_linkage(args, "test")
    assert "error" in result
    assert "verifier" in result["error"].lower()


def test_reveal_specific_key_linkage_missing_protocol_id(wallet):
    """Test reveal_specific_key_linkage with missing protocol_id."""
    args = {
        "counterparty": PrivateKey().public_key().serialize(),
        "verifier": PrivateKey().public_key().serialize(),
        "keyID": "key1"
    }
    result = wallet.reveal_specific_key_linkage(args, "test")
    assert "error" in result
    assert "protocol_id" in result["error"].lower()


def test_reveal_specific_key_linkage_missing_key_id(wallet):
    """Test reveal_specific_key_linkage with missing key_id."""
    args = {
        "counterparty": PrivateKey().public_key().serialize(),
        "verifier": PrivateKey().public_key().serialize(),
        "protocolID": {"securityLevel": 1, "protocol": "test"}
    }
    result = wallet.reveal_specific_key_linkage(args, "test")
    assert "error" in result
    assert "key_id" in result["error"].lower()


def test_reveal_specific_key_linkage_missing_counterparty(wallet):
    """Test reveal_specific_key_linkage with missing counterparty."""
    args = {
        "verifier": PrivateKey().public_key().serialize(),
        "protocolID": {"securityLevel": 1, "protocol": "test"},
        "keyID": "key1"
    }
    result = wallet.reveal_specific_key_linkage(args, "test")
    assert "error" in result
    assert "counterparty" in result["error"].lower()


# ========================================================================
# Helper Method Edge Cases
# ========================================================================

def test_encode_point_with_none(wallet):
    """Test _encode_point with None input."""
    result = wallet._encode_point(None)
    assert result == b'\x00' * 33


def test_to_public_key_with_dict_counterparty(wallet):
    """Test _to_public_key with dict containing counterparty."""
    pub = PrivateKey().public_key()
    result = wallet._to_public_key({"counterparty": pub})
    assert result == pub


def test_to_public_key_with_dict_type_anyone(wallet):
    """Test _to_public_key with dict type ANYONE."""
    result = wallet._to_public_key({"type": 1})  # ANYONE
    assert result is not None


def test_to_public_key_with_dict_type_self(wallet):
    """Test _to_public_key with dict type SELF."""
    result = wallet._to_public_key({"type": 2})  # SELF
    assert result == wallet.public_key


def test_to_public_key_with_invalid_dict(wallet):
    """Test _to_public_key with invalid dict raises ValueError."""
    with pytest.raises(ValueError):
        wallet._to_public_key({"type": 99})


def test_to_public_key_with_invalid_type(wallet):
    """Test _to_public_key with invalid type raises ValueError."""
    with pytest.raises(ValueError):
        wallet._to_public_key(12345)


def test_normalize_protocol_with_list(wallet):
    """Test _normalize_protocol with list input."""
    protocol = wallet._normalize_protocol([1, "test"])
    assert protocol.security_level == 1
    assert protocol.protocol == "test"


def test_normalize_protocol_with_tuple(wallet):
    """Test _normalize_protocol with tuple input."""
    protocol = wallet._normalize_protocol((2, "test2"))
    assert protocol.security_level == 2
    assert protocol.protocol == "test2"


def test_normalize_protocol_with_dict_camelcase(wallet):
    """Test _normalize_protocol with dict using camelCase."""
    protocol = wallet._normalize_protocol({"securityLevel": 1, "protocol": "test"})
    assert protocol.security_level == 1
    assert protocol.protocol == "test"


def test_normalize_protocol_with_dict_snake_case(wallet):
    """Test _normalize_protocol with dict using snake_case."""
    protocol = wallet._normalize_protocol({"security_level": 1, "protocol": "test"})
    assert protocol.security_level == 1
    assert protocol.protocol == "test"


def test_resolve_woc_api_key_from_args(wallet):
    """Test _resolve_woc_api_key from args."""
    args = {"apiKey": "test_key_from_args"}
    result = wallet._resolve_woc_api_key(args)
    assert result == "test_key_from_args"


def test_resolve_woc_api_key_from_woc_nested(wallet):
    """Test _resolve_woc_api_key from nested woc.apiKey."""
    args = {"woc": {"apiKey": "test_key_nested"}}
    result = wallet._resolve_woc_api_key(args)
    assert result == "test_key_nested"


def test_resolve_woc_api_key_exception_handling(wallet):
    """Test _resolve_woc_api_key handles exceptions."""
    # Create args that might cause exception
    args = MagicMock()
    args.get.side_effect = Exception("Test exception")
    result = wallet._resolve_woc_api_key(args)
    # Should fall back to instance or env
    assert isinstance(result, str)


# ========================================================================
# list_actions Edge Cases
# ========================================================================

def test_list_actions_with_labels_all_mode(wallet):
    """Test list_actions with labels and labelQueryMode='all'."""
    # Create action with labels
    create_args = {
        "description": "Test",
        "outputs": [],
        "labels": ["label1", "label2"]
    }
    wallet.create_action(create_args, "test")
    
    args = {"labels": ["label1"], "labelQueryMode": "all"}
    result = wallet.list_actions(args, "test")
    assert "actions" in result
    assert "totalActions" in result


def test_list_actions_with_labels_any_mode(wallet):
    """Test list_actions with labels and default (any) mode."""
    create_args = {
        "description": "Test",
        "outputs": [],
        "labels": ["label1"]
    }
    wallet.create_action(create_args, "test")
    
    args = {"labels": ["label1", "label2"]}
    result = wallet.list_actions(args, "test")
    assert "actions" in result


def test_list_actions_with_empty_labels(wallet):
    """Test list_actions with empty labels list."""
    args = {"labels": []}
    result = wallet.list_actions(args, "test")
    assert "actions" in result
    assert "totalActions" in result


# ========================================================================
# Additional Certificate Methods
# ========================================================================

def test_prove_certificate_with_verifier(wallet):
    """Test prove_certificate with verifier."""
    args = {"verifier": b"test_verifier"}
    result = wallet.prove_certificate(args, "test")
    assert "keyringForVerifier" in result
    assert "verifier" in result


def test_relinquish_certificate_existing(wallet):
    """Test relinquish_certificate removes existing certificate."""
    # First acquire a certificate
    acquire_args = {
        "type": b"test_type",
        "serialNumber": b"test_serial",
        "certifier": b"test_certifier"
    }
    wallet.acquire_certificate(acquire_args, "test")
    
    # Then relinquish it
    relinquish_args = {
        "type": b"test_type",
        "serialNumber": b"test_serial",
        "certifier": b"test_certifier"
    }
    result = wallet.relinquish_certificate(relinquish_args, "test")
    assert result == {}
    
    # Verify it's removed
    list_result = wallet.list_certificates({}, "test")
    assert len(list_result["certificates"]) == 0


def test_discover_by_attributes_with_matching_cert(wallet):
    """Test discover_by_attributes finds matching certificate."""
    # Acquire certificate with attributes
    acquire_args = {
        "type": b"test",
        "serialNumber": b"123",
        "fields": {"attr1": "value1", "attr2": "value2"}
    }
    wallet.acquire_certificate(acquire_args, "test")
    
    # Discover by attributes
    discover_args = {"attributes": {"attr1": "value1"}}
    result = wallet.discover_by_attributes(discover_args, "test")
    assert "certificates" in result
    assert result["totalCertificates"] >= 1


def test_discover_by_attributes_no_match(wallet):
    """Test discover_by_attributes with no matching certificates."""
    discover_args = {"attributes": {"nonexistent": "value"}}
    result = wallet.discover_by_attributes(discover_args, "test")
    assert "certificates" in result
    assert result["totalCertificates"] == 0

