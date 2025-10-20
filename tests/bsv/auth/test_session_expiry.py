import time
from bsv.auth.session_manager import DefaultSessionManager
from bsv.auth.peer_session import PeerSession
from bsv.keys import PrivateKey


def test_session_expiry_removes_old_sessions():
    sm = DefaultSessionManager()
    now_ms = int(time.time() * 1000)
    old = PeerSession(
        is_authenticated=True,
        session_nonce="old",
        peer_nonce="pn",
        peer_identity_key=PrivateKey(7301).public_key(),
        last_update=now_ms - 10_000,
    )
    fresh = PeerSession(
        is_authenticated=True,
        session_nonce="fresh",
        peer_nonce="pn2",
        peer_identity_key=PrivateKey(7302).public_key(),
        last_update=now_ms,
    )
    sm.add_session(old)
    sm.add_session(fresh)

    # Use Peer.expire_sessions with a very small max_age
    from bsv.auth.peer import Peer, PeerOptions

    class _DummyWallet:
        def get_public_key(self, *a, **kw):
            return None

    class _DummyTransport:
        def on_data(self, cb):
            return None
        def send(self, ctx, msg):
            return None

    p = Peer(PeerOptions(wallet=_DummyWallet(), transport=_DummyTransport(), session_manager=sm))
    p.expire_sessions(max_age_sec=1)  # 1s

    # Depending on timing this might or might not remove 'old' (set 10s old). Should be removed.
    assert sm.get_session("old") is None
    assert sm.get_session("fresh") is not None


