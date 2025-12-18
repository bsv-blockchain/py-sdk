import pytest

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.peer_session import PeerSession
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey


class DummyTransport:
    def on_data(self, callback):
        # Return no error
        return None

    def send(self, message):
        # Do nothing; return no error
        return None


class MockWallet:
    def __init__(self, priv: PrivateKey):
        self._priv = priv
        self._pub = priv.public_key()

    def get_public_key(self, ctx, args, originator: str):
        class R:
            pass
        r = R()
        r.public_key = self._pub
        return r

    # For methods that may be invoked by Peer in some code paths
    def create_signature(self, ctx, args, originator: str):  # pragma: no cover
        class R:
            pass
        r = R()
        r.signature = self._priv.sign(args.get("data", b""))
        return r

    def verify_signature(self, ctx, args, originator: str):  # pragma: no cover
        class R:
            pass
        r = R()
        r.valid = self._pub.verify(args.get("signature"), args.get("data", b""))
        return r


def make_peer():
    wallet = MockWallet(PrivateKey(777))
    transport = DummyTransport()
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))
    return peer, session_manager, wallet


class TestPeerUnit:
    def test_verify_nonce_uniqueness(self):
        peer, *_ = make_peer()
        nonce = "n1"
        assert peer.verify_nonce(nonce) is True
        assert peer.verify_nonce(nonce) is False

    def test_listener_registration_and_removal(self):
        peer, *_ = make_peer()
        called = {"n": 0}

        def cb(sender, payload):
            called["n"] += 1

        lid = peer.listen_for_general_messages(cb)
        peer.stop_listening_for_general_messages(lid)
        # After removal, direct callback dictionary should not contain id
        assert lid not in peer.on_general_message_received_callbacks

    def test_event_on_emit(self):
        peer, *_ = make_peer()
        called = {"ok": False}

        def handler(x):
            called["ok"] = True

        peer.on("ready", handler)
        peer.emit("ready", 1)
        assert called["ok"] is True

    def test_get_authenticated_session_returns_existing(self):
        peer, session_manager, _ = make_peer()
        identity = PrivateKey(778).public_key()
        s = PeerSession(is_authenticated=True, session_nonce="s", peer_nonce="p", peer_identity_key=identity, last_update=1)
        session_manager.add_session(s)
        got = peer.get_authenticated_session(identity, 0)
        assert got is s
        # last_interacted_with_peer should be updated when auto_persist_last_session is True
        assert peer.last_interacted_with_peer == identity



