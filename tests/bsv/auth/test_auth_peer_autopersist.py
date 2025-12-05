import base64

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.auth_message import AuthMessage
from bsv.auth.peer_session import PeerSession
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey


class CaptureTransport:
    def __init__(self):
        self._on_data_callback = None
        self.sent = []

    def on_data(self, callback):
        self._on_data_callback = callback
        return None

    def send(self, ctx, message: AuthMessage):
        self.sent.append(message)
        # loopback to update timestamps safely
        if self._on_data_callback is not None:
            return self._on_data_callback(ctx, message)
        return None


class Wallet:
    def __init__(self, priv: PrivateKey):
        self._priv = priv
        self._pub = priv.public_key()

    def get_public_key(self, ctx, args, originator: str):
        class R: pass
        r = R()
        r.public_key = self._pub
        return r

    def create_signature(self, ctx, args, originator: str):
        class R: pass
        r = R()
        r.signature = self._priv.sign(args.get("data", b""))
        return r


def _seed(session_manager: DefaultSessionManager, identity_key):
    s_nonce = base64.b64encode(b"S" * 32).decode()
    p_nonce = base64.b64encode(b"P" * 32).decode()
    s = PeerSession(True, s_nonce, p_nonce, identity_key, 1)
    session_manager.add_session(s)
    return s


def test_auto_persist_last_session_is_used_when_identity_none():
    transport = CaptureTransport()
    wallet = Wallet(PrivateKey(8080))
    session_manager = DefaultSessionManager()
    peer = Peer(PeerOptions(wallet=wallet, transport=transport, session_manager=session_manager, auto_persist_last_session=True))

    other = PrivateKey(8081).public_key()
    _seed(session_manager, other)

    # First send with explicit identity: should set last_interacted_with_peer
    err1 = peer.to_peer(b"first", identity_key=other, max_wait_time=0)
    assert err1 is None
    assert peer.last_interacted_with_peer == other

    # Next send without identity: should reuse last_interacted_with_peer
    n_before = len(transport.sent)
    err2 = peer.to_peer(b"second", identity_key=None, max_wait_time=0)
    assert err2 is None
    assert len(transport.sent) == n_before + 1
    last = transport.sent[-1]
    assert last.message_type == "general" and last.payload == b"second"


