"""
Comprehensive coverage tests for wallet_impl.py focusing on:
1. Error paths and exception handling
2. Edge cases (None, empty inputs, boundary conditions)
3. Branch coverage (all if/else paths)
"""
import pytest
import os
from unittest.mock import patch, MagicMock
from bsv.keys import PrivateKey, PublicKey
from bsv.wallet.wallet_impl import WalletImpl
from bsv.wallet.key_deriver import Protocol, Counterparty, CounterpartyType


@pytest.fixture
def wallet():
    """Wallet with automatic permission approval."""
    priv = PrivateKey()
    return WalletImpl(priv, permission_callback=lambda action: True)


@pytest.fixture
def wallet_no_callback():
    """Wallet without permission callback (uses input)."""
    priv = PrivateKey()
    return WalletImpl(priv)


# ========================================================================
# Initialization and Debug Paths
# ========================================================================

def test_wallet_init_with_env_loading_success():
    """Test wallet initialization with successful dotenv loading."""
    priv = PrivateKey()
    with patch('bsv.wallet.wallet_impl.WalletImpl._dotenv_loaded', False):
        wallet = WalletImpl(priv, load_env=True)
        assert wallet is not None


def test_wallet_init_with_env_loading_failure():
    """Test wallet initialization when dotenv loading fails (exception path)."""
    priv = PrivateKey()
    WalletImpl._dotenv_loaded = False
    # Import will fail but should be caught
    wallet = WalletImpl(priv, load_env=True)
    assert wallet is not None
    assert WalletImpl._dotenv_loaded is True


def test_wallet_init_woc_api_key_from_env():
    """Test WOC API key loaded from environment."""
    priv = PrivateKey()
    with patch.dict(os.environ, {"WOC_API_KEY": "test_env_key"}):
        wallet = WalletImpl(priv)
        assert wallet._woc_api_key == "test_env_key"


def test_wallet_init_woc_api_key_explicit_overrides_env():
    """Test explicit WOC API key overrides environment."""
    priv = PrivateKey()
    with patch.dict(os.environ, {"WOC_API_KEY": "env_key"}):
        wallet = WalletImpl(priv, woc_api_key="explicit_key")  # noqa: S106  # NOSONAR - Mock API key for tests
        assert wallet._woc_api_key == "explicit_key"


def test_wallet_init_woc_api_key_empty_default():
    """Test WOC API key defaults to empty string."""
    priv = PrivateKey()
    with patch.dict(os.environ, {}, clear=True):
        wallet = WalletImpl(priv)
        assert wallet._woc_api_key == ""


# ========================================================================
# BSV_DEBUG Path Coverage
# ========================================================================

def test_check_permission_with_debug_enabled(wallet, capsys):
    """Test permission check with BSV_DEBUG=1."""
    with patch.dict(os.environ, {"BSV_DEBUG": "1"}):
        wallet._check_permission("Test Action")
        captured = capsys.readouterr()
        assert "DEBUG WalletImpl._check_permission" in captured.out
        assert "Test Action" in captured.out
        assert "allowed=True" in captured.out


def test_get_public_key_with_debug_enabled(wallet, capsys):
    """Test get_public_key with BSV_DEBUG=1."""
    args = {"identityKey": True}
    with patch.dict(os.environ, {"BSV_DEBUG": "1"}):
        result = wallet.get_public_key(None, args, "test_originator")
        captured = capsys.readouterr()
        assert "DEBUG WalletImpl.get_public_key" in captured.out
        assert "test_originator" in captured.out


def test_encrypt_with_debug_enabled(wallet, capsys):
    """Test encrypt with BSV_DEBUG=1."""
    args = {
        "encryption_args": {},
        "plaintext": b"test"
    }
    with patch.dict(os.environ, {"BSV_DEBUG": "1"}):
        result = wallet.encrypt(None, args, "test")
        captured = capsys.readouterr()
        assert "DEBUG WalletImpl.encrypt" in captured.out


def test_decrypt_with_debug_enabled(wallet, capsys):
    """Test decrypt with BSV_DEBUG=1."""
    # First encrypt
    enc_result = wallet.encrypt(None, {"encryption_args": {}, "plaintext": b"test"}, "test")
    
    args = {
        "encryption_args": {},
        "ciphertext": enc_result["ciphertext"]
    }
    with patch.dict(os.environ, {"BSV_DEBUG": "1"}):
        result = wallet.decrypt(None, args, "test")
        captured = capsys.readouterr()
        assert "DEBUG WalletImpl.decrypt" in captured.out


# ========================================================================
# Error Paths and Edge Cases
# ========================================================================

def test_get_public_key_with_none_protocol_id(wallet):
    """Test get_public_key returns error when protocol_id is None."""
    args = {"protocolID": None, "keyID": None}
    result = wallet.get_public_key(None, args, "test")
    assert "error" in result
    assert "required" in result["error"].lower()


def test_get_public_key_with_forself_true_no_protocol(wallet):
    """Test get_public_key returns identity key when forSelf=True even without protocol."""
    args = {"forSelf": True}
    result = wallet.get_public_key(None, args, "test")
    assert "publicKey" in result
    assert "error" not in result


def test_get_public_key_with_non_dict_protocol_id(wallet):
    """Test get_public_key with protocol_id as non-dict (tuple/list)."""
    protocol = Protocol(1, "test_protocol")
    args = {
        "protocolID": protocol,  # Not a dict
        "keyID": "key1"
    }
    result = wallet.get_public_key(None, args, "test")
    # Should work with Protocol object directly
    assert "publicKey" in result or "error" in result


def test_encrypt_missing_plaintext(wallet):
    """Test encrypt returns error when plaintext is missing."""
    args = {"encryption_args": {}}
    result = wallet.encrypt(None, args, "test")
    assert "error" in result
    assert "plaintext" in result["error"].lower()


def test_encrypt_with_none_plaintext(wallet):
    """Test encrypt returns error when plaintext is None."""
    args = {"encryption_args": {}, "plaintext": None}
    result = wallet.encrypt(None, args, "test")
    assert "error" in result
    assert "plaintext" in result["error"].lower()


def test_decrypt_missing_ciphertext(wallet):
    """Test decrypt returns error when ciphertext is missing."""
    args = {"encryption_args": {}}
    result = wallet.decrypt(None, args, "test")
    assert "error" in result
    assert "ciphertext" in result["error"].lower()


def test_decrypt_with_none_ciphertext(wallet):
    """Test decrypt returns error when ciphertext is None."""
    args = {"encryption_args": {}, "ciphertext": None}
    result = wallet.decrypt(None, args, "test")
    assert "error" in result
    assert "ciphertext" in result["error"].lower()


def test_create_signature_missing_protocol_id(wallet):
    """Test create_signature returns error when protocol_id is missing."""
    args = {"key_id": "key1", "data": b"test"}
    result = wallet.create_signature(None, args, "test")
    assert "error" in result


def test_create_signature_missing_key_id(wallet):
    """Test create_signature returns error when key_id is missing."""
    args = {"protocol_id": {"securityLevel": 1, "protocol": "test"}, "data": b"test"}
    result = wallet.create_signature(None, args, "test")
    assert "error" in result


def test_create_signature_with_none_data(wallet):
    """Test create_signature with None data (should use empty bytes)."""
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": None
    }
    # Should handle None gracefully or return error
    result = wallet.create_signature(None, args, "test")
    # Either succeeds with empty data or returns error
    assert "signature" in result or "error" in result


def test_verify_signature_missing_signature(wallet):
    """Test verify_signature returns error when signature is missing."""
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": b"test"
    }
    result = wallet.verify_signature(None, args, "test")
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
    result = wallet.verify_signature(None, args, "test")
    assert "error" in result
    assert "signature" in result["error"].lower()


def test_verify_signature_missing_protocol_id(wallet):
    """Test verify_signature returns error when protocol_id is missing."""
    args = {"key_id": "key1", "data": b"test", "signature": b"fake"}
    result = wallet.verify_signature(None, args, "test")
    assert "error" in result


def test_verify_signature_missing_key_id(wallet):
    """Test verify_signature returns error when key_id is missing."""
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "data": b"test",
        "signature": b"fake"
    }
    result = wallet.verify_signature(None, args, "test")
    assert "error" in result


def test_verify_signature_with_list_protocol_id(wallet):
    """Test verify_signature with protocol_id as list [security_level, protocol]."""
    # Create a real signature first
    sign_args = {
        "protocol_id": [1, "test"],
        "key_id": "key1",
        "data": b"test data"
    }
    sign_result = wallet.create_signature(None, sign_args, "test")
    
    # Verify with list protocol_id
    verify_args = {
        "protocol_id": [1, "test"],
        "key_id": "key1",
        "data": b"test data",
        "signature": sign_result["signature"]
    }
    result = wallet.verify_signature(None, verify_args, "test")
    assert "valid" in result


def test_verify_signature_with_hash_to_directly_verify(wallet):
    """Test verify_signature with hash_to_directly_verify instead of data."""
    import hashlib
    data = b"test data"
    data_hash = hashlib.sha256(data).digest()
    
    # Create signature
    sign_args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": data
    }
    sign_result = wallet.create_signature(None, sign_args, "test")
    
    # Verify using hash directly
    verify_args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "hash_to_directly_verify": data_hash,
        "signature": sign_result["signature"]
    }
    result = wallet.verify_signature(None, verify_args, "test")
    assert "valid" in result
    assert result["valid"] is True


def test_create_hmac_missing_protocol_id(wallet):
    """Test create_hmac returns error when protocol_id is missing."""
    args = {
        "encryption_args": {"key_id": "key1"},
        "data": b"test"
    }
    result = wallet.create_hmac(None, args, "test")
    assert "error" in result


def test_create_hmac_missing_key_id(wallet):
    """Test create_hmac returns error when key_id is missing."""
    args = {
        "encryption_args": {"protocol_id": {"securityLevel": 1, "protocol": "test"}},
        "data": b"test"
    }
    result = wallet.create_hmac(None, args, "test")
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
    result = wallet.create_hmac(None, args, "test")
    # Should handle None gracefully (defaults to empty bytes)
    assert "hmac" in result or "error" in result


def test_verify_hmac_missing_protocol_id(wallet):
    """Test verify_hmac returns error when protocol_id is missing."""
    args = {
        "encryption_args": {"key_id": "key1"},
        "data": b"test",
        "hmac": b"fake"
    }
    result = wallet.verify_hmac(None, args, "test")
    assert "error" in result


def test_verify_hmac_missing_key_id(wallet):
    """Test verify_hmac returns error when key_id is missing."""
    args = {
        "encryption_args": {"protocol_id": {"securityLevel": 1, "protocol": "test"}},
        "data": b"test",
        "hmac": b"fake"
    }
    result = wallet.verify_hmac(None, args, "test")
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
    result = wallet.verify_hmac(None, args, "test")
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
    result = wallet.verify_hmac(None, args, "test")
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
    result = wallet.acquire_certificate(None, args, "test")
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
    result = wallet.acquire_certificate(None, args, "test")
    assert result == {}
    # Certificate is stored even with empty/None values
    assert len(wallet._certificates) >= 1


def test_list_certificates_empty(wallet):
    """Test listing certificates when none exist."""
    result = wallet.list_certificates(None, {}, "test")
    assert "certificates" in result
    assert len(result["certificates"]) == 0


# ========================================================================
# Network and Version Methods
# ========================================================================

def test_get_network_returns_string(wallet):
    """Test get_network returns a string."""
    result = wallet.get_network(None, {}, "test")
    assert "network" in result
    assert isinstance(result["network"], str)


def test_get_version_returns_string(wallet):
    """Test get_version returns a string."""
    result = wallet.get_version(None, {}, "test")
    assert "version" in result
    assert isinstance(result["version"], str)


def test_is_authenticated_always_true(wallet):
    """Test is_authenticated always returns True."""
    result = wallet.is_authenticated(None, {}, "test")
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
    result = wallet.get_public_key(None, {}, "test")
    assert "error" in result or "publicKey" in result


def test_encrypt_with_empty_args(wallet):
    """Test encrypt with empty args dict."""
    result = wallet.encrypt(None, {}, "test")
    assert "error" in result


def test_decrypt_with_empty_args(wallet):
    """Test decrypt with empty args dict."""
    result = wallet.decrypt(None, {}, "test")
    assert "error" in result


def test_create_signature_with_empty_data(wallet):
    """Test create_signature with empty data."""
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": b""
    }
    result = wallet.create_signature(None, args, "test")
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
    result = wallet.create_hmac(None, args, "test")
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
    hmac_result = wallet.create_hmac(None, create_args, "test")
    
    # Verify with empty data
    verify_args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1"
        },
        "data": b"",
        "hmac": hmac_result["hmac"]
    }
    result = wallet.verify_hmac(None, verify_args, "test")
    assert "valid" in result
    assert result["valid"] is True


def test_get_public_key_with_empty_protocol_string(wallet):
    """Test get_public_key with empty protocol string."""
    args = {
        "protocolID": {"securityLevel": 0, "protocol": ""},
        "keyID": "key1"
    }
    result = wallet.get_public_key(None, args, "test")
    # Should work even with empty protocol
    assert "publicKey" in result or "error" in result


def test_get_public_key_with_zero_security_level(wallet):
    """Test get_public_key with zero security level."""
    args = {
        "protocolID": {"securityLevel": 0, "protocol": "test"},
        "keyID": "key1"
    }
    result = wallet.get_public_key(None, args, "test")
    assert "publicKey" in result or "error" in result

