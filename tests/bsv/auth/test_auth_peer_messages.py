import base64
import pytest

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.auth_message import AuthMessage
from bsv.auth.peer_session import PeerSession
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey


class LocalTransport:
    def __init__(self):
        self._on_data_callback = None

    def on_data(self, callback):
        self._on_data_callback = callback
        return None

    def send(self, ctx, message: AuthMessage):
        # For these tests we directly call our own handler to emulate delivery
        if self._on_data_callback is None:
            return Exception("No handler")
        return self._on_data_callback(ctx, message)


class MockSigResult:
    def __init__(self, valid: bool):
        self.valid = valid


class MockWallet:
    def __init__(self, priv: PrivateKey, valid_verify: bool = False):
        self._priv = priv
        self._pub = priv.public_key()
        self._valid_verify = valid_verify

    def get_public_key(self, ctx, args, originator: str):
        class R:
            pass
        r = R()
        r.public_key = self._pub
        return r

    def verify_signature(self, ctx, args, originator: str):
        return MockSigResult(self._valid_verify)
    
    def verify_hmac(self, ctx, args, originator: str):
        # Always return valid for nonce verification to pass
        class HmacResult:
            def __init__(self):
                self.valid = True
        return HmacResult()


def test_initial_response_invalid_signature_returns_error():
    transport = LocalTransport()
    wallet = MockWallet(PrivateKey(9001), valid_verify=False)
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))

    # Seed a session for sender public key
    sender_pub = PrivateKey(9002).public_key()
    session_nonce = base64.b64encode(b"S" * 32).decode()
    s = PeerSession(is_authenticated=False, session_nonce=session_nonce, peer_identity_key=sender_pub, last_update=1)
    session_manager.add_session(s)

    # Craft an initialResponse message with bogus signature
    msg = AuthMessage(
        version="0.1",
        message_type="initialResponse",
        identity_key=sender_pub,
        your_nonce=session_nonce,
        initial_nonce=base64.b64encode(b"I" * 32).decode(),
        signature=b"\x30\x00",  # invalid DER
    )
    err = peer.handle_initial_response(msg, sender_pub)
    assert isinstance(err, Exception)
    assert "unable to verify signature" in str(err)


def test_general_message_invalid_signature_returns_error():
    transport = LocalTransport()
    wallet = MockWallet(PrivateKey(9011), valid_verify=False)
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager))

    # Seed authenticated session for sender
    sender_pub = PrivateKey(9012).public_key()
    session_nonce = base64.b64encode(b"A" * 32).decode()
    peer_nonce = base64.b64encode(b"B" * 32).decode()
    s = PeerSession(is_authenticated=True, session_nonce=session_nonce, peer_nonce=peer_nonce, peer_identity_key=sender_pub, last_update=1)
    session_manager.add_session(s)

    msg = AuthMessage(
        version="0.1",
        message_type="general",
        identity_key=sender_pub,
        nonce=base64.b64encode(b"N" * 32).decode(),
        your_nonce=peer_nonce,
        payload=b"hello",
        signature=b"\x30\x00",
    )
    err = peer.handle_general_message(msg, sender_pub)
    assert isinstance(err, Exception)
    assert "general message - invalid signature" in str(err)





