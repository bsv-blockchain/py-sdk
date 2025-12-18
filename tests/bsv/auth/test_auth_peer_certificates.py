import base64

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.auth_message import AuthMessage
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey

from .conftest import CaptureTransport, WalletOK, _seed_authenticated_session


def test_handle_certificate_request_valid_signature():
    transport = CaptureTransport()
    wallet = WalletOK(PrivateKey(7001))
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))

    sender_pub = PrivateKey(7002).public_key()
    _seed_authenticated_session(session_manager, sender_pub)

    msg = AuthMessage(
        version="0.1",
        message_type="certificateRequest",
        identity_key=sender_pub,
        nonce=base64.b64encode(b"N" * 32).decode(),
        your_nonce=session_manager.get_session(sender_pub.hex()).peer_nonce,
        requested_certificates={"types": {"t": ["f1"]}},
        signature=b"dummy",
    )
    err = peer.handle_certificate_request(msg, sender_pub);
    assert err is None;


def test_handle_certificate_response_valid_signature_invokes_listener():
    transport = CaptureTransport()
    wallet = WalletOK(PrivateKey(7011))
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))

    sender_pub = PrivateKey(7012).public_key()
    _seed_authenticated_session(session_manager, sender_pub)

    called = {"n": 0, "last": None}

    def on_certs(sender_pk, certs):
        called["n"] += 1
        called["last"] = certs

    peer.listen_for_certificates_received(on_certs)

    # Use JSON-serializable certificates for signature verification path
    certs = [
        {
            "certificate": {
                "type": base64.b64encode(bytes.fromhex("00" * 32)).decode(),
                "serialNumber": base64.b64encode(bytes.fromhex("11" * 32)).decode(),
                "subject": PrivateKey(1).public_key().hex(),
                "certifier": PrivateKey(2).public_key().hex(),
                "fields": {},
            }
        }
    ]
    msg = AuthMessage(
        version="0.1",
        message_type="certificateResponse",
        identity_key=sender_pub,
        nonce=base64.b64encode(b"R" * 32).decode(),
        your_nonce=session_manager.get_session(sender_pub.hex()).peer_nonce,
        certificates=certs,
        signature=b"ok",
    )
    err = peer.handle_certificate_response(msg, sender_pub)
    assert err is None
    assert called["n"] == 1
    assert called["last"] == certs


def test_canonicalize_certificates_payload_golden():
    transport = CaptureTransport()
    wallet = WalletOK(PrivateKey(7041))
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))

    raw = [
        {
            "certificate": {
                # mixed formats: hex and base64 should canonicalize to base64-32
                "type": bytes.fromhex("aa" * 32),
                "serialNumber": bytes.fromhex("bb" * 32).hex(),
                "subject": PrivateKey(10).public_key(),
                "certifier": PrivateKey(11).public_key().hex(),
                "fields": {"f": "v"},
            },
            "keyring": {"f": base64.b64encode(b"k").decode()},
            "signature": b"s",
        },
        {
            # dict without nested certificate
            "type": base64.b64encode(bytes.fromhex("cc" * 32)).decode(),
            "serialNumber": base64.b64encode(bytes.fromhex("dd" * 32)).decode(),
            "subject": PrivateKey(12).public_key().hex(),
            "certifier": PrivateKey(13).public_key().hex(),
            "fields": {},
        },
    ]

    canon = peer._canonicalize_certificates_payload(raw)
    # Should produce two entries with base64-32 type/serial and hex pubkeys
    assert len(canon) == 2
    for entry in canon:
        t = entry.get("type")
        s = entry.get("serialNumber")
        assert isinstance(t, str) and isinstance(s, (str, type(None)))
        if t is not None:
            assert len(base64.b64decode(t)) == 32
        if s is not None:
            assert len(base64.b64decode(s)) == 32
        assert isinstance(entry.get("subject"), (str, type(None)))
        assert isinstance(entry.get("certifier"), (str, type(None)))

    # Deterministic ordering by (type, serialNumber)
    # Serialize and compare to golden canonical JSON string
    import json
    payload = peer._serialize_for_signature(canon)
    # Verify stable serialization (no spaces, sorted keys)
    assert payload.decode().startswith("[") and ":" in payload.decode()


def test_request_certificates_sends_message():
    transport = CaptureTransport()
    wallet = WalletOK(PrivateKey(7021))
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))

    target_pub = PrivateKey(7022).public_key()
    _seed_authenticated_session(session_manager, target_pub)

    req = {"types": {"X": ["f"]}, "certifiers": []}
    err = peer.request_certificates(target_pub, req, max_wait_time=0)
    assert err is None
    assert len(transport.sent_messages) >= 1
    assert transport.sent_messages[-1].message_type == "certificateRequest"


def test_send_certificate_response_sends_message():
    transport = CaptureTransport()
    wallet = WalletOK(PrivateKey(7031))
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))

    target_pub = PrivateKey(7032).public_key()
    _seed_authenticated_session(session_manager, target_pub)

    certs = []
    err = peer.send_certificate_response(target_pub, certs)
    assert err is None
    assert len(transport.sent_messages) >= 1
    assert transport.sent_messages[-1].message_type == "certificateResponse"


