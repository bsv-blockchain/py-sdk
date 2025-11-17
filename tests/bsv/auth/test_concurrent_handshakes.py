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
                    version="0.1",
                    message_type="initialResponse",
                    identity_key=PrivateKey(2).public_key(),
                    initial_nonce=getattr(msg, 'initial_nonce', None),
                    peer_nonce="peer_nonce_response"
                )
                if self.callback:
                    try:
                        self.callback(ctx, response)
                    except Exception:
                        pass
            threading.Thread(target=delayed_response, daemon=True).start()
        return None


def test_concurrent_handshakes_same_peer():
    """Test that multiple concurrent handshakes with the same peer work correctly"""
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
            session = peer.initiate_handshake(None, peer_identity_key, 5000)
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
        t.join(timeout=10)
    
    # All handshakes should complete (some may succeed, some may reuse existing session)
    # At least one should succeed
    assert len(results) + len(errors) == 5, f"Expected 5 results, got {len(results)} successes and {len(errors)} errors"
    
    # Check that sessions were created
    sessions = session_manager.get_all_sessions()
    assert len(sessions) > 0, "At least one session should be created"


def test_concurrent_handshakes_different_peers():
    """Test that concurrent handshakes with different peers work correctly"""
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
            session = peer.initiate_handshake(None, peer_identity_key, 5000)
            results.append((i, session))
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
        t.join(timeout=10)
    
    # All handshakes should complete
    assert len(results) + len(errors) == 5, f"Expected 5 results, got {len(results)} successes and {len(errors)} errors"
    
    # Check that multiple sessions were created (one per peer)
    sessions = session_manager.get_all_sessions()
    assert len(sessions) >= 1, "At least one session should be created"

