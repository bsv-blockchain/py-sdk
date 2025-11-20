import os
from pathlib import Path

import pytest
from bsv.keys import PrivateKey, PublicKey
from bsv.wallet.wallet_impl import WalletImpl
from bsv.wallet.key_deriver import Protocol


# Load environment variables from .env.local
def load_env_file():
    """Load environment variables from .env.local file if it exists."""
    env_file = Path(__file__).parent.parent.parent / '.env.local'
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()


load_env_file()

# Test credentials - these are only for testing purposes, not real credentials
TEST_PASSPHRASE = "test"  # NOSONAR - Test passphrase for unit tests only

@pytest.fixture
def wallet():
    priv = PrivateKey()
    return WalletImpl(priv, permission_callback=lambda action: True)

@pytest.fixture
def counterparty():
    return PrivateKey().public_key()

@pytest.mark.parametrize("plain", [b"hello", b"test123", "秘密".encode("utf-8")])
def test_encrypt_decrypt_identity(wallet, plain):
    # identityKeyで暗号化・復号
    args = {
        "encryption_args": {},
        "plaintext": plain
    }
    enc = wallet.encrypt(None, args, TEST_PASSPHRASE)
    dec = wallet.decrypt(None, {"encryption_args": {}, "ciphertext": enc["ciphertext"]}, TEST_PASSPHRASE)
    assert dec["plaintext"] == plain


def test_get_public_key_identity(wallet):
    """Test retrieving identity public key from wallet with format validation."""
    args = {"identityKey": True}
    pub = wallet.get_public_key(None, args, TEST_PASSPHRASE)
    
    # Verify response structure
    assert "publicKey" in pub, "Response should contain 'publicKey' field"
    assert isinstance(pub["publicKey"], str), f"publicKey should be string, got {type(pub['publicKey'])}"
    
    # Verify hex format and length (compressed=66 or uncompressed=130 hex chars)
    pk_hex = pub["publicKey"]
    assert len(pk_hex) in (66, 130), f"Public key should be 66 or 130 hex chars, got {len(pk_hex)}"
    assert all(c in '0123456789abcdefABCDEF' for c in pk_hex), "Public key should be valid hex"
    
    # Verify key is deterministic (same args return same key)
    pub2 = wallet.get_public_key(None, args, TEST_PASSPHRASE)
    assert pub2["publicKey"] == pub["publicKey"], "Same args should return same public key"


def test_encrypt_decrypt_with_protocol_two_parties():
    # Encrypt with Alice for Bob; decrypt with Bob
    alice = WalletImpl(PrivateKey(1001), permission_callback=lambda a: True)
    bob = WalletImpl(PrivateKey(1002), permission_callback=lambda a: True)
    protocol = Protocol(1, "testprotocol")
    key_id = "key1"
    plain = b"abcxyz"

    enc_args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "testprotocol"},
            "key_id": key_id,
            "counterparty": bob.public_key.hex(),
        },
        "plaintext": plain,
    }
    enc = alice.encrypt(None, enc_args, TEST_PASSPHRASE)

    dec_args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "testprotocol"},
            "key_id": key_id,
            "counterparty": alice.public_key.hex(),
        },
        "ciphertext": enc["ciphertext"],
    }
    dec = bob.decrypt(None, dec_args, TEST_PASSPHRASE)
    assert dec["plaintext"] == plain


def test_seek_permission_prompt(monkeypatch):
    """Test that wallet prompts for permission via input() when no callback is provided."""
    priv = PrivateKey()
    # permission_callback=None uses input() for permission
    wallet = WalletImpl(priv)
    called = {}
    
    def fake_input(prompt):
        called["prompt"] = prompt
        return "y"  # User approves
    
    monkeypatch.setattr("builtins.input", fake_input)
    args = {"seekPermission": True, "identityKey": True}
    pub = wallet.get_public_key(None, args, TEST_PASSPHRASE)
    
    # Verify operation succeeded
    assert "publicKey" in pub, "Should return public key when permission granted"
    assert "error" not in pub, "Should not have error when permission granted"
    
    # Verify prompt was shown with correct action
    assert "prompt" in called, "input() should have been called"
    assert "Allow Get public key?" in called["prompt"], \
        f"Prompt should mention action, got: {called['prompt']}"
    
    # Test denial
    called.clear()
    def fake_input_deny(prompt):
        called["prompt"] = prompt
        return "n"  # User denies
    monkeypatch.setattr("builtins.input", fake_input_deny)
    
    pub_denied = wallet.get_public_key(None, args, TEST_PASSPHRASE)
    assert "error" in pub_denied, "Should return error when permission denied via input"


def test_seek_permission_denied_returns_error_dict():
    """Test that wallet returns error dict when permission callback denies access."""
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda action: False)
    
    args = {"seekPermission": True, "identityKey": True}
    res = wallet.get_public_key(None, args, TEST_PASSPHRASE)
    
    # Verify error response structure
    assert "error" in res, "Should return error dict when permission denied"
    assert "not permitted" in res["error"].lower() or "denied" in res["error"].lower(), \
        f"Error should mention permission denial, got: {res['error']}"
    assert "publicKey" not in res, "Should not return public key when permission denied"
    
    # Test with different action (encrypt)
    enc_args = {
        "seekPermission": True,
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1",
            "counterparty": "0" * 66,
        },
        "plaintext": "test"
    }
    res2 = wallet.encrypt(None, enc_args, TEST_PASSPHRASE)
    assert "error" in res2, "Encrypt should also be denied"


def test_get_public_key_with_protocol_and_keyid(wallet):
    """Test getting public key with protocol and keyID."""
    args = {
        "protocolID": {"securityLevel": 1, "protocol": "test"},  # Fixed: removed " protocol" suffix
        "keyID": "test key 1"
    }
    result = wallet.get_public_key(None, args, TEST_PASSPHRASE)
    
    # Should return a public key
    assert "publicKey" in result
    assert isinstance(result["publicKey"], str)
    assert len(result["publicKey"]) in (66, 130)


def test_get_public_key_missing_required_args(wallet):
    """Test get_public_key with missing required arguments."""
    # Missing keyID
    args = {"protocolID": [1, "test"]}
    result = wallet.get_public_key(None, args, TEST_PASSPHRASE)
    assert "error" in result
    
    # Missing protocolID
    args = {"keyID": "test_key"}
    result = wallet.get_public_key(None, args, TEST_PASSPHRASE)
    assert "error" in result


def test_get_public_key_with_counterparty(wallet, counterparty):
    """Test get_public_key with different counterparty types."""
    # Test with PublicKey counterparty
    args = {
        "protocolID": {"securityLevel": 1, "protocol": "test"},
        "keyID": "key1",
        "counterparty": counterparty.hex()
    }
    result = wallet.get_public_key(None, args, TEST_PASSPHRASE)
    assert "publicKey" in result
    
    # Test with dict counterparty
    args = {
        "protocolID": {"securityLevel": 1, "protocol": "test"},
        "keyID": "key1",
        "counterparty": {"type": "other", "counterparty": counterparty.hex()}
    }
    result = wallet.get_public_key(None, args, TEST_PASSPHRASE)
    assert "publicKey" in result


def test_create_signature_basic(wallet):
    """Test creating a signature."""
    data = b"test data to sign"
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": data
    }
    result = wallet.create_signature(None, args, TEST_PASSPHRASE)
    
    assert "signature" in result
    assert "error" not in result
    assert isinstance(result["signature"], bytes)
    assert len(result["signature"]) > 0


def test_create_signature_missing_args(wallet):
    """Test create_signature with missing arguments."""
    # Missing protocol_id
    args = {"key_id": "key1", "data": b"test"}
    result = wallet.create_signature(None, args, TEST_PASSPHRASE)
    assert "error" in result
    
    # Missing key_id
    args = {"protocol_id": {"securityLevel": 1, "protocol": "test"}, "data": b"test"}
    result = wallet.create_signature(None, args, TEST_PASSPHRASE)
    assert "error" in result


def test_create_and_verify_signature(wallet):
    """Test creating and verifying a signature."""
    data = b"important message"
    protocol_id = {"securityLevel": 1, "protocol": "test"}  # Fixed: removed " protocol" suffix
    key_id = "signing key 1"
    
    # Create signature
    sign_args = {
        "protocol_id": protocol_id,
        "key_id": key_id,
        "data": data
    }
    sign_result = wallet.create_signature(None, sign_args, TEST_PASSPHRASE)
    assert "signature" in sign_result
    
    # Verify signature
    verify_args = {
        "protocol_id": protocol_id,
        "key_id": key_id,
        "data": data,
        "signature": sign_result["signature"]
    }
    verify_result = wallet.verify_signature(None, verify_args, TEST_PASSPHRASE)
    assert "valid" in verify_result
    assert verify_result["valid"] is True


def test_verify_signature_with_invalid_data(wallet):
    """Test that signature verification fails with tampered data."""
    data = b"original message"
    tampered_data = b"tampered message"
    
    # Create signature
    sign_args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": data
    }
    sign_result = wallet.create_signature(None, sign_args, TEST_PASSPHRASE)
    
    # Try to verify with different data
    verify_args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": tampered_data,
        "signature": sign_result["signature"]
    }
    verify_result = wallet.verify_signature(None, verify_args, TEST_PASSPHRASE)
    assert verify_result["valid"] is False


def test_verify_signature_missing_args(wallet):
    """Test verify_signature with missing arguments."""
    # Missing signature
    args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1",
        "data": b"test"
    }
    result = wallet.verify_signature(None, args, TEST_PASSPHRASE)
    assert "error" in result
    
    # Missing protocol_id
    args = {"key_id": "key1", "data": b"test", "signature": b"fake"}
    result = wallet.verify_signature(None, args, TEST_PASSPHRASE)
    assert "error" in result


def test_create_and_verify_hmac(wallet):
    """Test creating and verifying HMAC."""
    data = b"test data for hmac"
    enc_args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "hmac_key_1"
    }
    
    # Create HMAC
    create_args = {"encryption_args": enc_args, "data": data}
    hmac_result = wallet.create_hmac(None, create_args, TEST_PASSPHRASE)
    assert "hmac" in hmac_result
    assert "error" not in hmac_result
    
    # Verify HMAC
    verify_args = {
        "encryption_args": enc_args,
        "data": data,
        "hmac": hmac_result["hmac"]
    }
    verify_result = wallet.verify_hmac(None, verify_args, TEST_PASSPHRASE)
    assert "valid" in verify_result
    assert verify_result["valid"] is True


def test_verify_hmac_with_tampered_data(wallet):
    """Test that HMAC verification fails with tampered data."""
    original_data = b"original data"
    tampered_data = b"tampered data"
    enc_args = {
        "protocol_id": {"securityLevel": 1, "protocol": "test"},
        "key_id": "key1"
    }
    
    # Create HMAC
    create_args = {"encryption_args": enc_args, "data": original_data}
    hmac_result = wallet.create_hmac(None, create_args, TEST_PASSPHRASE)
    
    # Try to verify with different data
    verify_args = {
        "encryption_args": enc_args,
        "data": tampered_data,
        "hmac": hmac_result["hmac"]
    }
    verify_result = wallet.verify_hmac(None, verify_args, TEST_PASSPHRASE)
    assert verify_result["valid"] is False


def test_create_hmac_missing_args(wallet):
    """Test create_hmac with missing arguments."""
    # Missing key_id
    args = {
        "encryption_args": {"protocol_id": {"securityLevel": 1, "protocol": "test"}},
        "data": b"test"
    }
    result = wallet.create_hmac(None, args, TEST_PASSPHRASE)
    assert "error" in result


def test_verify_hmac_missing_args(wallet):
    """Test verify_hmac with missing arguments."""
    # Missing hmac value
    args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1"
        },
        "data": b"test"
    }
    result = wallet.verify_hmac(None, args, TEST_PASSPHRASE)
    assert "error" in result


def test_normalize_counterparty_types(wallet):
    """Test _normalize_counterparty with various input types."""
    # Test with dict
    cp_dict = {"type": "self"}
    cp = wallet._normalize_counterparty(cp_dict)
    assert cp.type == 2  # SELF
    
    # Test with "other" type
    pub = PrivateKey().public_key()
    cp_dict = {"type": "other", "counterparty": pub.hex()}
    cp = wallet._normalize_counterparty(cp_dict)
    assert cp.type == 3  # OTHER
    
    # Test with hex string
    cp = wallet._normalize_counterparty(pub.hex())
    assert cp.type == 3  # OTHER
    
    # Test with PublicKey
    cp = wallet._normalize_counterparty(pub)
    assert cp.type == 3  # OTHER
    
    # Test with None
    cp = wallet._normalize_counterparty(None)
    assert cp.type == 2  # SELF


def test_parse_counterparty_type(wallet):
    """Test _parse_counterparty_type with various inputs."""
    # Test integers
    assert wallet._parse_counterparty_type(1) == 1  # ANYONE
    assert wallet._parse_counterparty_type(2) == 2  # SELF
    assert wallet._parse_counterparty_type(3) == 3  # OTHER
    
    # Test strings
    assert wallet._parse_counterparty_type("self") == 2
    assert wallet._parse_counterparty_type("me") == 2
    assert wallet._parse_counterparty_type("other") == 3
    assert wallet._parse_counterparty_type("counterparty") == 3
    assert wallet._parse_counterparty_type("anyone") == 1
    assert wallet._parse_counterparty_type("any") == 1
    
    # Test unknown/invalid input defaults to SELF
    assert wallet._parse_counterparty_type("unknown") == 2
    assert wallet._parse_counterparty_type(None) == 2


def test_acquire_certificate(wallet):
    """Test acquiring a certificate."""
    args = {
        "type": b"test_type",
        "serialNumber": b"12345",
        "certifier": "test_certifier",
        "keyringForSubject": {"test": "data"},
        "fields": {"field1": "value1"}
    }
    result = wallet.acquire_certificate(None, args, TEST_PASSPHRASE)
    
    # Should return empty dict on success
    assert result == {}
    
    # Certificate should be stored
    assert len(wallet._certificates) == 1
    cert = wallet._certificates[0]
    assert "certificateBytes" in cert
    assert "keyring" in cert
    assert "attributes" in cert


def test_list_certificates(wallet):
    """Test listing certificates."""
    # Add some certificates
    wallet.acquire_certificate(None, {
        "type": b"type1",
        "serialNumber": b"123",
        "certifier": "cert1",
        "fields": {"name": "cert1"}
    }, TEST_PASSPHRASE)
    
    wallet.acquire_certificate(None, {
        "type": b"type2",
        "serialNumber": b"456",
        "certifier": "cert2",
        "fields": {"name": "cert2"}
    }, TEST_PASSPHRASE)
    
    # List all certificates
    result = wallet.list_certificates(None, {}, TEST_PASSPHRASE)
    assert "certificates" in result
    assert len(result["certificates"]) == 2


def test_get_network(wallet):
    """Test get_network returns mocknet by default."""
    result = wallet.get_network(None, {}, TEST_PASSPHRASE)
    assert "network" in result
    # WalletImpl returns "mocknet" by default
    assert result["network"] in ["mocknet", "mainnet"]


def test_get_version(wallet):
    """Test get_version returns version string."""
    result = wallet.get_version(None, {}, TEST_PASSPHRASE)
    assert "version" in result
    assert isinstance(result["version"], str)


def test_is_authenticated(wallet):
    """Test is_authenticated returns True."""
    result = wallet.is_authenticated(None, {}, TEST_PASSPHRASE)
    assert "authenticated" in result
    assert result["authenticated"] is True


def test_abort_action(wallet):
    """Test abort_action doesn't raise errors."""
    # Should be a no-op and not raise
    wallet.abort_action(None, {}, TEST_PASSPHRASE)


def test_encrypt_decrypt_with_forself(wallet):
    """Test encryption/decryption with forSelf flag."""
    plain = b"self encrypted data"
    enc_args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1",
            "forSelf": True
        },
        "plaintext": plain
    }
    encrypted = wallet.encrypt(None, enc_args, TEST_PASSPHRASE)
    assert "ciphertext" in encrypted
    
    dec_args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "test"},
            "key_id": "key1",
            "forSelf": True
        },
        "ciphertext": encrypted["ciphertext"]
    }
    decrypted = wallet.decrypt(None, dec_args, TEST_PASSPHRASE)
    assert decrypted["plaintext"] == plain


def test_wallet_initialization_with_woc_api_key():
    """Test wallet initialization with WhatsOnChain API key."""
    priv = PrivateKey()
    api_key = os.getenv('WOC_API_KEY', 'test_woc_api_key_fallback')  # noqa: S105  # NOSONAR
    wallet = WalletImpl(priv, woc_api_key=api_key)
    assert wallet._woc_api_key == api_key


def test_wallet_initialization_with_load_env():
    """Test wallet initialization with load_env flag."""
    priv = PrivateKey()
    # Should not raise even if dotenv is not available
    wallet = WalletImpl(priv, load_env=True)
    assert wallet is not None
