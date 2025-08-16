# PeerSession.py - Ported from go-sdk/auth/types.go
from typing import Optional
from bsv.keys import PublicKey

class PeerSession:
    def __init__(self,
                 is_authenticated: bool = False,
                 session_nonce: str = '',
                 peer_nonce: str = '',
                 peer_identity_key: Optional[PublicKey] = None,
                 last_update: int = 0):
        self.is_authenticated = is_authenticated
        self.session_nonce = session_nonce
        self.peer_nonce = peer_nonce
        self.peer_identity_key = peer_identity_key
        self.last_update = last_update