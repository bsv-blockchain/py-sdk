import pytest

from bsv.wallet.substrates.wallet_wire import WalletWire
from bsv.wallet.substrates.wallet_wire_processor import WalletWireProcessor
from bsv.wallet.substrates.wallet_wire_transceiver import WalletWireTransceiver
from bsv.wallet.wallet_impl import WalletImpl
from bsv.keys import PrivateKey
from bsv.wallet.key_deriver import Protocol
from bsv.keys import PublicKey


@pytest.fixture
def transceiver():
    wallet = WalletImpl(PrivateKey(1001), permission_callback=lambda a: True)
    processor = WalletWireProcessor(wallet)
    return WalletWireTransceiver(processor)


def test_list_actions_e2e(transceiver):
    # minimal args
    resp = transceiver.list_actions(None, {
        "labels": ["a"],
        "labelQueryMode": "any",
        "includeLabels": True,
    }, "origin")
    assert isinstance(resp, dict)
    assert resp.get("totalActions") == 0


def test_internalize_action_e2e(transceiver):
    resp = transceiver.internalize_action(None, {
        "tx": b"\x00\x01",
        "outputs": [
            {
                "outputIndex": 0,
                "protocol": "wallet payment",
                "paymentRemittance": {
                    "senderIdentityKey": PrivateKey(1).public_key().serialize(),
                    "derivationPrefix": b"p",
                    "derivationSuffix": b"s",
                },
            }
        ],
        "labels": ["L"],
        "description": "d",
    }, "origin")
    assert isinstance(resp, dict)
    assert resp.get("accepted") is True


def test_list_certificates_e2e(transceiver):
    resp = transceiver.list_certificates(None, {
        "certifiers": [],
        "types": [],
        "limit": 10,
    }, "origin")
    assert isinstance(resp, dict)
    assert resp.get("totalCertificates") == 0


def test_discover_by_identity_key_e2e(transceiver):
    resp = transceiver.discover_by_identity_key(None, {
        "identityKey": PrivateKey(2).public_key().serialize(),
        "limit": 5,
    }, "origin")
    assert isinstance(resp, dict)
    assert resp.get("totalCertificates") == 0


def test_discover_by_attributes_e2e(transceiver):
    resp = transceiver.discover_by_attributes(None, {
        "attributes": {"name": "alice"},
        "limit": 5,
    }, "origin")
    assert isinstance(resp, dict)
    assert resp.get("totalCertificates") == 0


def test_actions_flow_e2e(transceiver):
    # Create action
    create_args = {
        "description": "test",
        "outputs": [{"lockingScript": b"\x51", "satoshis": 100, "outputDescription": "o"}],
        "labels": ["flow"],
    }
    resp_create = transceiver.create_action(None, create_args, "origin")
    assert isinstance(resp_create, dict)
    _ = resp_create.get("signableTransaction", {}).get("_", b"")
    ref = resp_create.get("signableTransaction", {}).get("reference", b"")
    # error optional
    # Sign action
    sign_args = {"spends": {"0": {"unlockingScript": b"\x51", "sequenceNumber": 0}}, "reference": ref}
    resp_sign = transceiver.sign_action(None, sign_args, "origin")
    assert isinstance(resp_sign, dict)
    assert isinstance(resp_sign.get("sendWithResults", []), list)
    assert len(resp_sign.get("sendWithResults", [])) == 0
    # Internalize
    resp_int = transceiver.internalize_action(None, {
        "tx": b"",
        "outputs": [],
        "labels": ["flow"],
        "description": "done",
    }, "origin")
    assert isinstance(resp_int, dict)
    assert resp_int.get("accepted") is True
    # List should include the created action
    resp_list = transceiver.list_actions(None, {"labels": ["flow"], "labelQueryMode": "any", "includeLabels": True}, "origin")
    assert isinstance(resp_list, dict)
    assert int(resp_list.get("totalActions", 0)) >= 1


def test_certificates_flow_e2e(transceiver):
    # Acquire (direct, minimal fake values)
    user_priv = PrivateKey(2001)
    cert_type = b"\x00" * 32
    certifier = user_priv.public_key().serialize()
    serial = b"\x01" * 32
    resp_acq = transceiver.acquire_certificate(None, {
        "type": cert_type,
        "certifier": certifier,
        "fields": {"name": "alice"},
        "privileged": None,
        "privilegedReason": "",
        "acquisitionProtocol": 1,
        "serialNumber": serial,
        "revocationOutpoint": {"txid": b"\x00" * 32, "index": 0},
        "signature": b"sig",
        "keyringRevealer": {"certifier": True},
        "keyringForSubject": {"k": "dmFsdWU="},
    }, "origin")
    assert isinstance(resp_acq, dict)
    # List
    resp_lc = transceiver.list_certificates(None, {"certifiers": [], "types": [], "limit": 10}, "origin")
    assert isinstance(resp_lc, dict)
    assert int(resp_lc.get("totalCertificates", 0)) >= 1
    # Prove (minimal inputs)
    resp_pc = transceiver.prove_certificate(None, {
        "certificate": {
            "type": cert_type,
            "subject": user_priv.public_key().serialize(),
            "serialNumber": serial,
            "certifier": certifier,
            "revocationOutpoint": {"txid": b"\x00" * 32, "index": 0},
            "signature": b"sig",
            "fields": {"name": "alice"},
        },
        "fieldsToReveal": ["name"],
        "verifier": user_priv.public_key().serialize(),
        "privileged": None,
        "privilegedReason": "",
    }, "origin")
    assert isinstance(resp_pc, dict)
    # Relinquish
    resp_rc = transceiver.relinquish_certificate(None, {"type": cert_type, "serialNumber": serial, "certifier": certifier}, "origin")
    assert isinstance(resp_rc, dict)
    # Discover by attributes
    resp_da = transceiver.discover_by_attributes(None, {"attributes": {"name": "alice"}, "limit": 5}, "origin")
    assert isinstance(resp_da, dict)
    _ = resp_da.get("totalCertificates", 0)
    # Discover by identity key
    resp_dk = transceiver.discover_by_identity_key(None, {"identityKey": user_priv.public_key().serialize(), "limit": 5}, "origin")
    assert isinstance(resp_dk, dict)
    _ = resp_dk.get("totalCertificates", 0)
