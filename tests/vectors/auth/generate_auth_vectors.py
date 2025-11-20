import json
import base64
from pathlib import Path

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey


class _CaptureTransport:
    def on_data(self, cb):
        self._cb = cb
        return None

    def send(self, _, _):
        return None


class _WalletOK:
    def __init__(self, priv: PrivateKey):
        self._priv = priv
        self._pub = priv.public_key()

    def get_public_key(self, _, _, _: str):
        class R:
            pass

        r = R()
        r.public_key = self._pub
        return r


def _make_peer() -> Peer:
    transport = _CaptureTransport()
    wallet = _WalletOK(PrivateKey(8301))
    session_manager = DefaultSessionManager()
    return Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))


def generate_certificate_request_vector(out_path: Path) -> None:
    peer = _make_peer()

    cert_type_bytes = bytes.fromhex("aa" * 32)
    _ = base64.b64encode(cert_type_bytes).decode("ascii")
    fields = ["z", "a", "m"]
    pk1 = PrivateKey(9001).public_key()
    pk2 = PrivateKey(9002).public_key()

    request_payload = {
        "certificate_types": {cert_type_bytes.hex(): fields},
        "certifiers": [pk2.hex(), pk1.hex()],
    }
    canonical = peer._canonicalize_requested_certificates(request_payload)

    vector = {
        "request": request_payload,
        "canonical": canonical,
    }
    out_path.write_text(json.dumps(vector, indent=2, sort_keys=True), encoding="utf-8")


def generate_certificate_response_vector(out_path: Path) -> None:
    peer = _make_peer()

    t1 = bytes.fromhex("aa" * 32)
    s1 = bytes.fromhex("bb" * 32)
    subj1 = PrivateKey(9101).public_key().hex()
    cert1 = PrivateKey(9102).public_key().hex()

    t2_b64 = base64.b64encode(bytes.fromhex("cc" * 32)).decode("ascii")
    s2_b64 = base64.b64encode(bytes.fromhex("dd" * 32)).decode("ascii")
    subj2 = PrivateKey(9103).public_key().hex()
    cert2 = PrivateKey(9104).public_key().hex()

    certificates_payload = [
        {
            "certificate": {
                "type": base64.b64encode(t1).decode("ascii"),
                "serial_number": s1.hex(),
                "subject": subj1,
                "certifier": cert1,
                "fields": {"x": "y"},
            },
            "keyring": {"x": base64.b64encode(b"k").decode()},
            "signature": base64.b64encode(b"sig1").decode("ascii"),
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

    canonical = peer._canonicalize_certificates_payload(certificates_payload)
    vector = {
        "certificates": certificates_payload,
        "canonical": canonical,
    }
    out_path.write_text(json.dumps(vector, indent=2, sort_keys=True), encoding="utf-8")


def main() -> None:
    base_dir = Path(__file__).parent
    base_dir.mkdir(parents=True, exist_ok=True)
    generate_certificate_request_vector(base_dir / "certificate_request_vector.json")
    generate_certificate_response_vector(base_dir / "certificate_response_vector.json")
    print("Generated vectors in:", base_dir)


if __name__ == "__main__":
    main()


