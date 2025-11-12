import pytest

from bsv.wallet.substrates.wallet_wire_processor import WalletWireProcessor
from bsv.wallet.substrates.wallet_wire_transceiver import WalletWireTransceiver
from bsv.wallet.wallet_impl import WalletImpl
from bsv.wallet.key_deriver import CounterpartyType
from bsv.keys import PrivateKey


@pytest.fixture
def transceiver():
    wallet = WalletImpl(PrivateKey(1234), permission_callback=lambda a: True)
    processor = WalletWireProcessor(wallet)
    return WalletWireTransceiver(processor)


def test_get_public_key_identity(transceiver):
    resp = transceiver.get_public_key(None, {"identityKey": True, "seekPermission": None}, "origin")
    assert isinstance(resp, dict)
    pub = resp.get("publicKey", b"")
    assert isinstance(pub, (bytes, bytearray)) and len(pub) == 33


def test_get_public_key_derived(transceiver):
    args = {
        "identityKey": False,
        "protocolID": {"securityLevel": 1, "protocol": "testprotocol"},
        "keyID": "kid",
        "counterparty": {"type": CounterpartyType.ANYONE},
        "privileged": None,
        "privilegedReason": "",
        "forSelf": None,
        "seekPermission": None,
    }
    resp = transceiver.get_public_key(None, args, "origin")
    assert isinstance(resp, dict)
    pub = resp.get("publicKey", b"")
    assert isinstance(pub, (bytes, bytearray)) and len(pub) == 33


def test_reveal_counterparty_key_linkage(transceiver):
    resp = transceiver.reveal_counterparty_key_linkage(None, {
        "privileged": None,
        "privilegedReason": "",
        "counterparty": PrivateKey(1).public_key().serialize(),
        "verifier": PrivateKey(2).public_key().serialize(),
    }, "origin")
    assert isinstance(resp, dict)


def test_reveal_specific_key_linkage(transceiver):
    resp = transceiver.reveal_specific_key_linkage(None, {
        "protocolID": {"securityLevel": 1, "protocol": "testprotocol"},
        "keyID": "kid",
        "counterparty": {"type": CounterpartyType.ANYONE},
        "privileged": None,
        "privilegedReason": "",
        "verifier": PrivateKey(2).public_key().serialize(),
    }, "origin")
    assert isinstance(resp, dict)


def test_get_public_key_error_frame_permission_denied():
    # permission denied triggers ERROR frame via PermissionError
    wallet = WalletImpl(PrivateKey(4321), permission_callback=lambda a: False)
    t = WalletWireTransceiver(WalletWireProcessor(wallet))
    with pytest.raises(RuntimeError):
        t.get_public_key(None, {"identityKey": True, "seekPermission": True}, "origin")


def test_reveal_counterparty_key_linkage_error_frame_permission_denied():
    wallet = WalletImpl(PrivateKey(4321), permission_callback=lambda a: False)
    t = WalletWireTransceiver(WalletWireProcessor(wallet))
    with pytest.raises(RuntimeError):
        t.reveal_counterparty_key_linkage(None, {
            "privileged": True,
            "privilegedReason": "need",
            "counterparty": PrivateKey(1).public_key().serialize(),
            "verifier": PrivateKey(2).public_key().serialize(),
            "seekPermission": True,
        }, "origin")
