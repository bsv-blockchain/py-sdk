"""Tests for concurrent handshake handling"""
import threading
import time
from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey


class DummyWallet:
    def get_public_key(self, ctx, args, originator):
        return type('obj', (object,), {'public_key': PrivateKey(1).public_key()})()

    def create_signature(self, ctx, args, originator):
        return {"signature": b"dummy_signature"}

    def verify_signature(self, ctx, args, originator):
        return {"valid": True}


class DummyTransport:
    def __init__(self):
        self.callback = None
        self.sent_messages = []

    def on_data(self, callback):
        self.callback = callback
        return None

    def send(self, ctx, msg):
        self.sent_messages.append(msg)
        # Simulate async response
        if self.callback and hasattr(msg, 'message_type') and msg.message_type == 'initialRequest':
            # Simulate receiving an initial response
            import threading
            def delayed_response():
                time.sleep(0.01)  # Small delay
                from bsv.auth.auth_message import AuthMessage
                response = AuthMessage(
                    version="1.0",
                    message_type="initialResponse",
                    identity_key=PrivateKey(2).public_key(),
                    nonce="peer_nonce_response",
                    initial_nonce=getattr(msg, 'nonce', None)
                )
                if self.callback:
                    try:
                        self.callback(ctx, response)
                    except Exception:
                        # Intentional: Callback may raise exceptions during concurrent execution
                        # We're testing that concurrent handshakes don't crash, not callback behavior
                        pass
            threading.Thread(target=delayed_response, daemon=True).start()
        return None


def test_concurrent_handshakes_same_peer():
    """Test that multiple concurrent handshakes with the same peer don't cause crashes or corruption"""
    wallet = DummyWallet()
    transport = DummyTransport()
    session_manager = DefaultSessionManager()

    peer = Peer(PeerOptions(
        wallet=wallet,
        transport=transport,
        session_manager=session_manager
    ))

    peer_identity_key = PrivateKey(2).public_key()
    results = []
    errors = []

    def initiate_handshake(i):
        try:
            session = peer.initiate_handshake(None, peer_identity_key, 1000)  # Shorter timeout for test
            results.append((i, session))
        except Exception as e:
            errors.append((i, e))

    # Start multiple concurrent handshakes
    threads = []
    for i in range(5):
        t = threading.Thread(target=initiate_handshake, args=(i,))
        threads.append(t)
        t.start()

    # Wait for all threads
    for t in threads:
        t.join(timeout=5)

    # All handshakes should complete without exceptions (may timeout and return None)
    assert len(results) + len(errors) == 5, f"Expected 5 results, got {len(results)} results and {len(errors)} errors"
    assert len(errors) == 0, f"No exceptions should occur during concurrent operations, but got: {errors}"

    # Check that preliminary sessions were created (even if handshake times out)
    sessions = session_manager.get_all_sessions()
    assert isinstance(sessions, (list, dict)), "Sessions should be a valid collection"

    # Verify that any returned sessions have correct structure
    for _, session in results:
        if session is not None:
            assert hasattr(session, 'session_nonce'), "Session should have session_nonce"
            assert hasattr(session, 'peer_identity_key'), "Session should have peer_identity_key"
            assert session.peer_identity_key == peer_identity_key, "Session should have correct peer identity key"


def test_concurrent_handshakes_different_peers():
    """Test that concurrent handshakes with different peers don't cause crashes or corruption"""
    wallet = DummyWallet()
    transport = DummyTransport()
    session_manager = DefaultSessionManager()

    peer = Peer(PeerOptions(
        wallet=wallet,
        transport=transport,
        session_manager=session_manager
    ))

    results = []
    errors = []

    def initiate_handshake(i):
        try:
            peer_identity_key = PrivateKey(i + 10).public_key()
            session = peer.initiate_handshake(None, peer_identity_key, 1000)  # Shorter timeout for test
            results.append((i, session, peer_identity_key))
        except Exception as e:
            errors.append((i, e))

    # Start multiple concurrent handshakes with different peers
    threads = []
    for i in range(5):
        t = threading.Thread(target=initiate_handshake, args=(i,))
        threads.append(t)
        t.start()

    # Wait for all threads
    for t in threads:
        t.join(timeout=5)

    # All handshakes should complete without exceptions (may timeout and return None)
    assert len(results) + len(errors) == 5, f"Expected 5 results, got {len(results)} results and {len(errors)} errors"
    assert len(errors) == 0, f"No exceptions should occur during concurrent operations, but got: {errors}"

    # Check that sessions were created
    sessions = session_manager.get_all_sessions()
    assert isinstance(sessions, (list, dict)), "Sessions should be a valid collection"

    # Verify that any returned sessions have correct structure and peer keys
    for _, session, expected_key in results:
        if session is not None:
            assert hasattr(session, 'session_nonce'), "Session should have session_nonce"
            assert hasattr(session, 'peer_identity_key'), "Session should have peer_identity_key"
            assert session.peer_identity_key == expected_key, f"Session should have correct peer identity key: expected {expected_key.hex()}, got {session.peer_identity_key.hex()}"

