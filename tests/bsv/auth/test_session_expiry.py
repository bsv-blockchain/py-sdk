import time
import threading
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


def test_concurrent_session_expiration():
    """Test that session expiration works correctly when called concurrently"""
    sm = DefaultSessionManager()
    now_ms = int(time.time() * 1000)
    identity_key = PrivateKey(1).public_key()
    
    # Create multiple old sessions
    sessions = []
    for i in range(10):
        session = PeerSession(
            is_authenticated=True,
            session_nonce=f"old-{i}",
            peer_nonce=f"pn-{i}",
            peer_identity_key=identity_key,
            last_update=now_ms - 20_000,  # 20 seconds old
        )
        sm.add_session(session)
        sessions.append(session)
    
    # Create one fresh session
    fresh = PeerSession(
        is_authenticated=True,
        session_nonce="fresh",
        peer_nonce="pn-fresh",
        peer_identity_key=PrivateKey(2).public_key(),
        last_update=now_ms,
    )
    sm.add_session(fresh)
    
    # Expire sessions concurrently from multiple threads
    def expire_sessions():
        sm.expire_older_than(max_age_sec=1)
    
    threads = []
    for _ in range(5):
        t = threading.Thread(target=expire_sessions)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # All old sessions should be removed
    for session in sessions:
        assert sm.get_session(session.session_nonce) is None
    
    # Fresh session should remain
    assert sm.get_session("fresh") is not None


def test_expiration_during_active_operations():
    """Test that expiration works correctly even when sessions are being accessed"""
    sm = DefaultSessionManager()
    now_ms = int(time.time() * 1000)
    identity_key = PrivateKey(1).public_key()
    
    old_session = PeerSession(
        is_authenticated=True,
        session_nonce="old-active",
        peer_nonce="pn-old",
        peer_identity_key=identity_key,
        last_update=now_ms - 20_000,
    )
    sm.add_session(old_session)
    
    fresh_session = PeerSession(
        is_authenticated=True,
        session_nonce="fresh-active",
        peer_nonce="pn-fresh",
        peer_identity_key=PrivateKey(2).public_key(),
        last_update=now_ms,
    )
    sm.add_session(fresh_session)
    
    # Access sessions while expiring
    access_count = [0]
    def access_sessions():
        for _ in range(10):
            s1 = sm.get_session("old-active")
            s2 = sm.get_session("fresh-active")
            if s1:
                access_count[0] += 1
            if s2:
                access_count[0] += 1
            time.sleep(0.01)
    
    expire_thread = threading.Thread(target=lambda: sm.expire_older_than(max_age_sec=1))
    access_thread = threading.Thread(target=access_sessions)
    
    expire_thread.start()
    access_thread.start()
    
    expire_thread.join()
    access_thread.join()
    
    # Old session should be removed
    assert sm.get_session("old-active") is None
    # Fresh session should remain
    assert sm.get_session("fresh-active") is not None


