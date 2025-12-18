import base64
import json

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.session_manager import DefaultSessionManager
from bsv.auth.requested_certificate_set import RequestedCertificateSet, RequestedCertificateTypeIDAndFieldList
from bsv.keys import PrivateKey


class CaptureTransport:
    def on_data(self, cb):
        self._cb = cb
        return None

    def send(self, msg):
        return None


class WalletOK:
    def __init__(self, priv: PrivateKey):
        self._priv = priv
        self._pub = priv.public_key()

    def get_public_key(self, ctx, args, originator: str):
        class R:
            pass

        r = R()
        r.public_key = self._pub
        return r


def _make_peer() -> Peer:
    transport = CaptureTransport()
    wallet = WalletOK(PrivateKey(8001))
    session_manager = DefaultSessionManager()
    return Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))


def test_canonical_requested_certificates_json_golden():
    peer = _make_peer()

    # Prepare deterministic inputs
    cert_type_bytes = bytes.fromhex("aa" * 32)
    cert_type_b64 = base64.b64encode(cert_type_bytes).decode("ascii")
    fields = ["z", "a", "m"]  # intentionally unsorted
    pk1 = PrivateKey(9001).public_key()
    pk2 = PrivateKey(9002).public_key()

    # Input A: dict with hex key and unsorted certifiers
    req_a = {
        "certificate_types": {cert_type_bytes.hex(): fields},
        "certifiers": [pk2, pk1],
    }

    # Input B: RequestedCertificateSet instance with bytes key
    rmap = RequestedCertificateTypeIDAndFieldList({cert_type_bytes: list(fields)})
    req_b = RequestedCertificateSet(certifiers=[pk1, pk2], certificate_types=rmap)

    # Expected canonical dict
    expected = {
        "certifiers": sorted([pk1.hex(), pk2.hex()]),
        "certificateTypes": {cert_type_b64: sorted(fields)},
    }
    expected_json = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # Actual canonical serialization from both inputs
    can_a = peer._canonicalize_requested_certificates(req_a)
    can_b = peer._canonicalize_requested_certificates(req_b)
    ser_a = peer._serialize_for_signature(can_a)
    ser_b = peer._serialize_for_signature(can_b)

    assert ser_a == expected_json
    assert ser_b == expected_json


def test_canonical_certificate_response_json_golden():
    peer = _make_peer()

    # Two certificates with mixed encodings
    t1 = bytes.fromhex("aa" * 32)
    s1 = bytes.fromhex("bb" * 32)
    t1_b64 = base64.b64encode(t1).decode("ascii")
    s1_b64 = base64.b64encode(s1).decode("ascii")
    subj1 = PrivateKey(9101).public_key().hex()
    cert1 = PrivateKey(9102).public_key().hex()

    t2_b64 = base64.b64encode(bytes.fromhex("cc" * 32)).decode("ascii")
    s2_b64 = base64.b64encode(bytes.fromhex("dd" * 32)).decode("ascii")
    subj2 = PrivateKey(9103).public_key().hex()
    cert2 = PrivateKey(9104).public_key().hex()

    raw = [
        {
            "certificate": {
                "type": t1,
                "serialNumber": s1.hex(),
                "subject": subj1,
                "certifier": cert1,
                "fields": {"x": "y"},
            },
            "keyring": {"x": base64.b64encode(b"k").decode()},
            "signature": b"sig1",
        },
        {
            "certificate": {
                "type": t2_b64,
                "serialNumber": s2_b64,
                "subject": subj2,
                "certifier": cert2,
                "fields": {},
            },
        },
    ]

    # Expected canonical payload (ordering by type then serialNumber)
    expected_list = [
        {
            "type": t1_b64,
            "serialNumber": s1_b64,
            "subject": subj1,
            "certifier": cert1,
            "revocationOutpoint": None,
            "fields": {"x": "y"},
            "keyring": {"x": base64.b64encode(b"k").decode()},
            "signature": base64.b64encode(b"sig1").decode(),
        },
        {
            "type": t2_b64,
            "serialNumber": s2_b64,
            "subject": subj2,
            "certifier": cert2,
            "revocationOutpoint": None,
            "fields": {},
            "keyring": {},
            "signature": None,
        },
    ]

    # Sort expected deterministically to match implementation
    expected_list.sort(key=lambda x: (x.get("type", "") or "", x.get("serialNumber", "") or ""))
    expected_json = json.dumps(expected_list, sort_keys=True, separators=(",", ":")).encode("utf-8")

    can = peer._canonicalize_certificates_payload(raw)
    ser = peer._serialize_for_signature(can)
    assert ser == expected_json


