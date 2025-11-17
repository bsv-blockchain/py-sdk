import threading
from typing import Dict, Optional
from bsv.auth.peer import PeerSession

class SessionManager:
    def add_session(self, session: PeerSession) -> None:
        raise NotImplementedError
    def update_session(self, session: PeerSession) -> None:
        raise NotImplementedError
    def get_session(self, identifier: str) -> Optional[PeerSession]:
        raise NotImplementedError
    def remove_session(self, session: PeerSession) -> None:
        raise NotImplementedError
    def has_session(self, identifier: str) -> bool:
        raise NotImplementedError

class DefaultSessionManager(SessionManager):
    def __init__(self):
        self.session_nonce_to_session: Dict[str, PeerSession] = {}
        self.identity_key_to_nonces: Dict[str, set] = {}
        self._lock = threading.RLock()  # Reentrant lock for thread safety

    def add_session(self, session: PeerSession) -> None:
        if not session.session_nonce:
            raise ValueError('invalid session: session_nonce is required to add a session')
        with self._lock:
            self.session_nonce_to_session[session.session_nonce] = session
            if session.peer_identity_key is not None:
                key_hex = session.peer_identity_key.hex()
                nonces = self.identity_key_to_nonces.get(key_hex)
                if nonces is None:
                    nonces = set()
                    self.identity_key_to_nonces[key_hex] = nonces
                nonces.add(session.session_nonce)

    def update_session(self, session: PeerSession) -> None:
        with self._lock:
            self.remove_session(session)
            self.add_session(session)

    def get_session(self, identifier: str) -> Optional[PeerSession]:
        with self._lock:
            # Try as session_nonce
            direct = self.session_nonce_to_session.get(identifier)
            if direct:
                return direct
            # Try as identity_key
            nonces = self.identity_key_to_nonces.get(identifier)
            if not nonces:
                return None
            best = None
            for nonce in nonces:
                s = self.session_nonce_to_session.get(nonce)
                if s:
                    if best is None:
                        best = s
                    elif s.last_update > best.last_update:
                        if s.is_authenticated or not best.is_authenticated:
                            best = s
                    elif s.is_authenticated and not best.is_authenticated:
                        best = s
            return best

    def remove_session(self, session: PeerSession) -> None:
        with self._lock:
            if session.session_nonce in self.session_nonce_to_session:
                del self.session_nonce_to_session[session.session_nonce]
            if session.peer_identity_key is not None:
                key_hex = session.peer_identity_key.hex()
                nonces = self.identity_key_to_nonces.get(key_hex)
                if nonces and session.session_nonce in nonces:
                    nonces.remove(session.session_nonce)
                    if not nonces:
                        del self.identity_key_to_nonces[key_hex]

    def has_session(self, identifier: str) -> bool:
        with self._lock:
            if identifier in self.session_nonce_to_session:
                return True
            nonces = self.identity_key_to_nonces.get(identifier)
            return bool(nonces)

    # Helpers for expiry/inspection
    def get_all_sessions(self):
        with self._lock:
            return list(self.session_nonce_to_session.values())

    def expire_older_than(self, max_age_sec: int) -> None:
        import time
        now = int(time.time() * 1000)
        with self._lock:
            sessions_to_remove = []
            for s in self.session_nonce_to_session.values():
                if hasattr(s, 'last_update') and now - s.last_update > max_age_sec * 1000:
                    sessions_to_remove.append(s)
            for s in sessions_to_remove:
                self.remove_session(s)