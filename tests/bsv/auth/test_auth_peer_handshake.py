import base64
import threading
from typing import Optional

from bsv.auth.peer import Peer, PeerOptions
from bsv.auth.auth_message import AuthMessage
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey, PublicKey

from .conftest import LocalTransport, GetPub, Sig, Ver


class HandshakeWallet:
    def __init__(self, priv: PrivateKey):
        self._priv = priv
        self._pub = priv.public_key()

    def get_public_key(self, args=None, originator=None):
        return GetPub(self._pub)

    def create_signature(self, args=None, originator=None):
        data: bytes = args.get("data", b"")
        # Sign raw data
        return Sig(self._priv.sign(data))

    def verify_signature(self, args=None, originator=None):
        data: bytes = args.get("data", b"")
        sig: bytes = args.get("signature")
        # Support both nested (encryption_args) and top-level parameter formats
        enc = args.get("encryption_args", {})
        if not enc:
            # If no encryption_args, check for top-level parameters (direct format)
            enc = args
        cp = enc.get("counterparty")
        # Counterparty may be dict {type, counterparty}
        pub = None
        if isinstance(cp, dict):
            pub = cp.get("counterparty")
        elif isinstance(cp, PublicKey):
            pub = cp
        # Fallback to our own pub if not provided
        pub = pub or self._pub
        return Ver(pub.verify(sig, data))
    
    def verify_hmac(self, args=None, originator=None):
        # Always return valid for nonce verification to pass
        class HmacResult:
            def __init__(self):
                self.valid = True
        return HmacResult()


def test_mutual_authentication_and_general_message():  # NOSONAR - Protocol notation for peer handshake testing
    # Setup transports and connect
    tA = LocalTransport()  # NOSONAR - Protocol notation (transport A)
    tB = LocalTransport()  # NOSONAR - Protocol notation (transport B)
    tA.connect(tB)

    # Wallets
    wA = HandshakeWallet(PrivateKey(1111))  # NOSONAR - Protocol notation (wallet A)
    wB = HandshakeWallet(PrivateKey(2222))  # NOSONAR - Protocol notation (wallet B)

    # Peers
    pA = Peer(PeerOptions(wallet=wA, transport=tA, session_manager=DefaultSessionManager()))  # NOSONAR - Protocol notation (peer A)
    pB = Peer(PeerOptions(wallet=wB, transport=tB, session_manager=DefaultSessionManager()))  # NOSONAR - Protocol notation (peer B)

    # Ensure peers are started (transport callbacks registered)
    pA.start()
    pB.start()

    # Bob waits for general message then responds back
    got_from_alice = threading.Event()
    got_from_bob = threading.Event()

    def on_bob_general(sender_pk, payload):
        # Bob replies to Alice
        pB.to_peer(b"Hello Alice!", identity_key=sender_pk)
        got_from_bob.set()

    pB.listen_for_general_messages(on_bob_general)

    def on_alice_general(sender_pk, payload):
        got_from_alice.set()

    pA.listen_for_general_messages(on_alice_general)

    # Alice initiates communication; handshake should occur implicitly
    # Increase timeout to allow handshake to complete
    err = pA.to_peer(b"Hello Bob!", max_wait_time=5000)
    assert err is None

    # Wait for both directions
    assert got_from_bob.wait(timeout=5)
    assert got_from_alice.wait(timeout=5)


