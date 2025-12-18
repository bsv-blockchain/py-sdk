import base64

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey


class DummyTransport:
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


def _make_peer():
    return Peer(PeerOptions(wallet=WalletOK(PrivateKey(7201)), transport=DummyTransport(), session_manager=DefaultSessionManager()))


def _make_cert(cert_type_b64: str, subject_hex: str, certifier_hex: str, fields: dict):
    return {
        "certificate": {
            "type": cert_type_b64,
            "serialNumber": base64.b64encode(b"S" * 32).decode(),
            "subject": subject_hex,
            "certifier": certifier_hex,
            "fields": fields,
        },
        "keyring": {},
        "signature": b"sig",
    }


def test_validate_certificates_unrequested_type():
    peer = _make_peer()
    t_req = base64.b64encode(b"A" * 32).decode()
    t_other = base64.b64encode(b"B" * 32).decode()
    subject = PrivateKey(7202).public_key().hex()
    certifier = PrivateKey(7203).public_key().hex()
    certs = [_make_cert(t_other, subject, certifier, {"f": "v"})]
    requested = {"types": {t_req: ["f"]}, "certifiers": [certifier]}
    ok = peer._validate_certificates(certs, requested, expected_subject=PrivateKey(7202).public_key())
    assert ok is False


def test_validate_certificates_missing_required_field():
    peer = _make_peer()
    t_req = base64.b64encode(b"A" * 32).decode()
    subject = PrivateKey(7212).public_key().hex()
    certifier = PrivateKey(7213).public_key().hex()
    certs = [_make_cert(t_req, subject, certifier, {"g": "v"})]
    requested = {"types": {t_req: ["f"]}, "certifiers": [certifier]}
    ok = peer._validate_certificates(certs, requested, expected_subject=PrivateKey(7212).public_key())
    assert ok is False


def test_validate_certificates_unrequested_certifier():
    peer = _make_peer()
    t_req = base64.b64encode(b"A" * 32).decode()
    subject = PrivateKey(7222).public_key().hex()
    certifier = PrivateKey(7223).public_key().hex()
    other_certifier = PrivateKey(7224).public_key().hex()
    certs = [_make_cert(t_req, subject, other_certifier, {"f": "v"})]
    requested = {"types": {t_req: ["f"]}, "certifiers": [certifier]}
    ok = peer._validate_certificates(certs, requested, expected_subject=PrivateKey(7222).public_key())
    assert ok is False


