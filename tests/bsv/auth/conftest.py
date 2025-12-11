import base64

from bsv.auth.peer_session import PeerSession
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey


class CaptureTransport:
    def __init__(self):
        self._on_data_callback = None
        self.sent_messages = []

    def on_data(self, callback):
        self._on_data_callback = callback
        return None

    def send(self, message_or_ctx, message=None):
        # Handle both calling patterns:
        # - send(message) - peer.py calls it this way
        # - send(ctx, message) - interface defines it this way
        if message is None:
            # Called as send(message) - first arg is the message
            msg = message_or_ctx
        else:
            # Called as send(ctx, message) - first arg is ctx, second is message
            msg = message
        self.sent_messages.append(msg)
        return None


class MockSigResult:
    def __init__(self, valid: bool):
        self.valid = valid


class MockCreateSig:
    def __init__(self, signature: bytes):
        self.signature = signature


class WalletOK:
    def __init__(self, priv: PrivateKey):
        self._priv = priv
        self._pub = priv.public_key()

    def get_public_key(self, args=None, originator=None):
        class R:
            pass
        r = R()
        r.public_key = self._pub
        return r

    def verify_signature(self, args=None, originator=None):
        return MockSigResult(True)

    def create_signature(self, args=None, originator=None):
        return MockCreateSig(b"sig")

    # Optional stub for certificate acquisition
    def acquire_certificate(self, args=None, originator=None):
        # Return a simple dict-like certificate payload compatible with canonicalizer
        return {
            "certificate": {
                "type": args.get("cert_type") if args else None,
                "serialNumber": base64.b64encode(b"S" * 32).decode(),
                "subject": args.get("subject") if args else None,
                "certifier": args.get("certifiers", [self._pub.hex()])[0] if args and args.get("certifiers") else self._pub.hex(),
                "fields": dict.fromkeys(args.get("fields", []), "v") if args else {},
            },
            "keyring": {},
            "signature": b"sig",
        }


def _seed_authenticated_session(session_manager: DefaultSessionManager, peer_identity_key):
    session_nonce = base64.b64encode(b"S" * 32).decode()
    peer_nonce = base64.b64encode(b"P" * 32).decode()
    s = PeerSession(
        is_authenticated=True,
        session_nonce=session_nonce,
        peer_nonce=peer_nonce,
        peer_identity_key=peer_identity_key,
        last_update=1,
    )
    session_manager.add_session(s)
    return s


class LocalTransport:
    def __init__(self):
        self._on_data_callback = None
        self.sent_messages = []
        self.peer = None

    def connect(self, other: "LocalTransport"):
        self.peer = other
        other.peer = self

    def on_data(self, callback):
        self._on_data_callback = callback
        return None

    def send(self, message_or_ctx, message=None):
        # Handle both calling patterns:
        # - send(message) - peer.py calls it this way
        # - send(ctx, message) - interface defines it this way
        if message is None:
            # Called as send(message) - first arg is the message
            msg = message_or_ctx
        else:
            # Called as send(ctx, message) - first arg is ctx, second is message
            msg = message
        self.sent_messages.append(msg)
        # Note: peer.py callback expects (ctx, message)
        if self.peer and self.peer._on_data_callback:
            return self.peer._on_data_callback(None, msg)
        elif self._on_data_callback is not None:
            return self._on_data_callback(None, msg)
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

