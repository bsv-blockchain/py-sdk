import base64
import pytest
from typing import Any, Optional

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.auth_message import AuthMessage
from bsv.auth.peer_session import PeerSession
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey


class LocalTransport:
    def __init__(self):
        self._on_data_callback = None
        self.sent_messages: list[AuthMessage] = []

    def on_data(self, callback):
        self._on_data_callback = callback
        return None

    def send(self, ctx: Any, message: AuthMessage) -> Optional[Exception]:
        self.sent_messages.append(message)
        if self._on_data_callback is not None:
            return self._on_data_callback(ctx, message)
        return None


class GetPub:
    def __init__(self, pk):
        self.public_key = pk


class Sig:
    def __init__(self, signature: bytes):
        self.signature = signature


class Ver:
    def __init__(self, valid: bool):
        self.valid = valid


class MockWallet:
    def __init__(self, priv: PrivateKey):
        self._priv = priv
        self._pub = priv.public_key()

    def get_public_key(self, ctx: Any, args: dict, originator: str):
        return GetPub(self._pub)

    def create_signature(self, ctx: Any, args: dict, originator: str):
        data: bytes = args.get("data", b"")
        return Sig(self._priv.sign(data))

    def verify_signature(self, ctx: Any, args: dict, originator: str):
        data: bytes = args.get("data", b"")
        sig: bytes = args.get("signature")
        return Ver(self._pub.verify(sig, data))


def make_peer_pair():
    session_manager = DefaultSessionManager()
    transport = LocalTransport()
    wallet_priv = PrivateKey(222)
    peer = Peer(PeerOptions(wallet=MockWallet(wallet_priv), transport=transport, session_manager=session_manager))
    return peer, session_manager, transport, wallet_priv


class TestPeerBasic:
    def test_unknown_message_type(self):
        peer, *_ = make_peer_pair()
        other_pub = PrivateKey(9991).public_key()
        msg = AuthMessage(version="0.1", message_type="nope", identity_key=other_pub)
        err = peer.handle_incoming_message(None, msg);
        assert isinstance(err, Exception)
        assert 'unknown message type: nope' in str(err)

    def test_invalid_version(self):
        peer, *_ = make_peer_pair()
        other_pub = PrivateKey(9992).public_key()
        msg = AuthMessage(version="9.9", message_type="general", identity_key=other_pub)
        err = peer.handle_incoming_message(None, msg)
        assert isinstance(err, Exception)
        assert 'Invalid or unsupported message auth version! Received: 9.9, expected: 0.1' in str(err)

    def test_initial_request_missing_nonce(self):
        peer, *_ = make_peer_pair()
        other_pub = PrivateKey(333).public_key()
        msg = AuthMessage(version="0.1", message_type="initialRequest", identity_key=other_pub, initial_nonce="")
        err = peer.handle_initial_request(None, msg, other_pub)
        assert isinstance(err, Exception)
        assert 'Invalid nonce' in str(err)

    def test_to_peer_happy_path_with_seeded_session(self):
        peer, session_manager, transport, _ = make_peer_pair()
        other_pub = PrivateKey(444).public_key()

        session_nonce = base64.b64encode(b"A" * 32).decode()
        peer_nonce = base64.b64encode(b"B" * 32).decode()
        s = PeerSession(is_authenticated=True, session_nonce=session_nonce, peer_nonce=peer_nonce, peer_identity_key=other_pub, last_update=1)
        session_manager.add_session(s)

        err = peer.to_peer(None, b"hello", identity_key=other_pub, max_wait_time=0)
        assert err is None
        assert len(transport.sent_messages) >= 1
        m = transport.sent_messages[-1]
        assert m.message_type == "general"
        assert m.signature is not None



