import base64

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.auth_message import AuthMessage
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey

from .conftest import CaptureTransport, WalletOK, _seed_authenticated_session


def test_handle_certificate_request_triggers_response_via_wallet_fallback():
    transport = CaptureTransport()
    wallet = WalletOK(PrivateKey(7101))
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))

    sender_pub = PrivateKey(7102).public_key()
    _seed_authenticated_session(session_manager, sender_pub)

    req = {
        "types": {
            base64.b64encode(b"T" * 32).decode(): ["f1", "f2"],
        },
        "certifiers": [PrivateKey(7103).public_key().hex()],
    }

    msg = AuthMessage(
        version="0.1",
        message_type="certificateRequest",
        identity_key=sender_pub,
        nonce=base64.b64encode(b"N" * 32).decode(),
        your_nonce=session_manager.get_session(sender_pub.hex()).peer_nonce,
        requested_certificates=req,
        signature=b"dummy",
    )
    err = peer.handle_certificate_request(msg, sender_pub)
    assert err is None
    # The last sent message should be a certificateResponse
    assert len(transport.sent_messages) >= 1
    assert transport.sent_messages[-1].message_type == "certificateResponse"


def test_handle_certificate_request_uses_callback_when_registered():
    transport = CaptureTransport()
    wallet = WalletOK(PrivateKey(7111))
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))

    sender_pub = PrivateKey(7112).public_key()
    _seed_authenticated_session(session_manager, sender_pub)

    called = {"n": 0}

    def on_request(pk, requested):
        called["n"] += 1
        # Return a prebuilt certificates list
        return [
            {
                "certificate": {
                    "type": base64.b64encode(b"X" * 32).decode(),
                    "serialNumber": base64.b64encode(b"Y" * 32).decode(),
                    "subject": wallet._pub.hex(),
                    "certifier": wallet._pub.hex(),
                    "fields": {},
                },
                "keyring": {},
                "signature": b"sig",
            }
        ]

    peer.listen_for_certificates_requested(on_request)

    req = {"types": {base64.b64encode(b"X" * 32).decode(): []}, "certifiers": []}
    msg = AuthMessage(
        version="0.1",
        message_type="certificateRequest",
        identity_key=sender_pub,
        nonce=base64.b64encode(b"N" * 32).decode(),
        your_nonce=session_manager.get_session(sender_pub.hex()).peer_nonce,
        requested_certificates=req,
        signature=b"dummy",
    )
    err = peer.handle_certificate_request(msg, sender_pub)
    assert err is None
    assert called["n"] == 1
    assert len(transport.sent_messages) >= 1
    assert transport.sent_messages[-1].message_type == "certificateResponse"


