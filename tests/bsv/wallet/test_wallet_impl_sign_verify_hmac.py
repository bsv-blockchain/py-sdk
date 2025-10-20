import pytest

from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import WalletImpl


@pytest.fixture
def wallet():
    return WalletImpl(PrivateKey(123), permission_callback=lambda action: True)


def test_create_and_verify_signature_identity(wallet):
    data = b"sign me"
    args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 2, "protocol": "auth message signature"},
            "key_id": "identity",
            "counterparty": {"type": "self"},
        },
        "data": data,
    }
    sig = wallet.create_signature(None, args, "test")
    assert "signature" in sig and isinstance(sig["signature"], (bytes, bytearray))

    ver = wallet.verify_signature(None, {**args, "signature": sig["signature"]}, "test")
    assert ver.get("valid") is True


def test_create_and_verify_hmac_other_counterparty(wallet):
    # Use a counterparty public key derived from another private key
    # To satisfy KeyDeriver protocol name validation (>=5 chars, no dashes, no trailing " protocol")
    other_pub = PrivateKey(456).public_key()
    data = b"hmac this"
    args = {
        "encryption_args": {
            "protocol_id": {"securityLevel": 1, "protocol": "hmac test"},
            "key_id": "valid key id",
            "counterparty": {"type": "other", "counterparty": other_pub},
        },
        "data": data,
    }
    h = wallet.create_hmac(None, args, "test")
    assert "hmac" in h and isinstance(h["hmac"], (bytes, bytearray))

    ver = wallet.verify_hmac(None, {**args, "hmac": h["hmac"]}, "test")
    assert ver.get("valid") is True


