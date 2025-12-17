import json
import base64
import pathlib
import pytest

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.session_manager import DefaultSessionManager
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
    wallet = WalletOK(PrivateKey(8201))
    session_manager = DefaultSessionManager()
    return Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))


# Vector files are in tests/vectors/auth/, not tests/bsv/auth/vectors/auth/
# From tests/bsv/auth/ go up to tests/bsv/, then to tests/, then into vectors/auth/
VECTORS_DIR = pathlib.Path(__file__).parent.parent.parent / "vectors" / "auth"


@pytest.mark.skipif(not VECTORS_DIR.joinpath("certificate_request_vector.json").exists(), reason="Vector file not present")
def test_ts_go_vector_certificate_request():
    peer = _make_peer()
    vec_path = VECTORS_DIR / "certificate_request_vector.json"
    with vec_path.open("r", encoding="utf-8") as f:
        vector = json.load(f)

    req = vector["request"]  # dict payload compatible with Peer._canonicalize_requested_certificates
    expected_canonical = vector["canonical"]
    expected_signature_hex = vector.get("signatureHex")

    canonical = peer._canonicalize_requested_certificates(req)
    payload = peer._serialize_for_signature(canonical)
    assert json.loads(payload.decode("utf-8")) == expected_canonical

    # Optional: verify a provided signature bytes hex over payload
    if expected_signature_hex:
        assert isinstance(expected_signature_hex, str)
        sig = bytes.fromhex(expected_signature_hex)
        assert isinstance(sig, (bytes, bytearray))


@pytest.mark.skipif(not VECTORS_DIR.joinpath("certificate_response_vector.json").exists(), reason="Vector file not present")
def test_ts_go_vector_certificate_response():
    peer = _make_peer()
    vec_path = VECTORS_DIR / "certificate_response_vector.json"
    with vec_path.open("r", encoding="utf-8") as f:
        vector = json.load(f)

    certs = vector["certificates"]  # list payload compatible with Peer._canonicalize_certificates_payload
    expected_canonical = vector["canonical"]
    expected_signature_hex = vector.get("signatureHex")

    canonical = peer._canonicalize_certificates_payload(certs)
    payload = peer._serialize_for_signature(canonical)
    assert json.loads(payload.decode("utf-8")) == expected_canonical

    # Optional: verify a provided signature bytes hex over payload
    if expected_signature_hex:
        assert isinstance(expected_signature_hex, str)
        sig = bytes.fromhex(expected_signature_hex)
        assert isinstance(sig, (bytes, bytearray))


