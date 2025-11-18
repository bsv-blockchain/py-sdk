import pytest
from bsv.keys import PrivateKey, PublicKey
from bsv.wallet.wallet_impl import WalletImpl
from bsv.wallet.key_deriver import Protocol

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
    enc = wallet.encrypt(None, args, "test")
    dec = wallet.decrypt(None, {"encryption_args": {}, "ciphertext": enc["ciphertext"]}, "test")
    assert dec["plaintext"] == plain


def test_get_public_key_identity(wallet):
    """Test retrieving identity public key from wallet with format validation."""
    args = {"identityKey": True}
    pub = wallet.get_public_key(None, args, "test")
    
    # Verify response structure
    assert "publicKey" in pub, "Response should contain 'publicKey' field"
    assert isinstance(pub["publicKey"], str), f"publicKey should be string, got {type(pub['publicKey'])}"
    
    # Verify hex format and length (compressed=66 or uncompressed=130 hex chars)
    pk_hex = pub["publicKey"]
    assert len(pk_hex) in (66, 130), f"Public key should be 66 or 130 hex chars, got {len(pk_hex)}"
    assert all(c in '0123456789abcdefABCDEF' for c in pk_hex), "Public key should be valid hex"
    
    # Verify key is deterministic (same args return same key)
    pub2 = wallet.get_public_key(None, args, "test")
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
    enc = alice.encrypt(None, enc_args, "test")

    dec_args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "testprotocol"},
            "key_id": key_id,
            "counterparty": alice.public_key.hex(),
        },
        "ciphertext": enc["ciphertext"],
    }
    dec = bob.decrypt(None, dec_args, "test")
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
    pub = wallet.get_public_key(None, args, "test")
    
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
    
    pub_denied = wallet.get_public_key(None, args, "test")
    assert "error" in pub_denied, "Should return error when permission denied via input"


def test_seek_permission_denied_returns_error_dict():
    """Test that wallet returns error dict when permission callback denies access."""
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda action: False)
    
    args = {"seekPermission": True, "identityKey": True}
    res = wallet.get_public_key(None, args, "test")
    
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
    res2 = wallet.encrypt(None, enc_args, "test")
    assert "error" in res2, "Encrypt should also be denied"
