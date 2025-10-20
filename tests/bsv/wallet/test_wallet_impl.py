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
    args = {"identityKey": True}
    pub = wallet.get_public_key(None, args, "test")
    assert isinstance(pub["publicKey"], str)
    assert len(pub["publicKey"]) in (66, 130)  # compressed/uncompressed hex


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
    priv = PrivateKey()
    # permission_callback=None で input() を使う
    wallet = WalletImpl(priv)
    called = {}
    def fake_input(prompt):
        called["prompt"] = prompt
        return "y"
    monkeypatch.setattr("builtins.input", fake_input)
    args = {"seekPermission": True, "identityKey": True}
    pub = wallet.get_public_key(None, args, "test")
    assert "publicKey" in pub
    assert "Allow Get public key?" in called["prompt"]


def test_seek_permission_denied_returns_error_dict():
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda action: False)
    args = {"seekPermission": True, "identityKey": True}
    res = wallet.get_public_key(None, args, "test")
    assert "error" in res
    assert "not permitted" in res["error"]
