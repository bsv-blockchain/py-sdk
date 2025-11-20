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
            return self._find_best_session(nonces)

    def _find_best_session(self, nonces: set) -> Optional[PeerSession]:
        """Find the best session from a set of nonces, preferring authenticated and recent sessions."""
        best = None
        for nonce in nonces:
            session = self.session_nonce_to_session.get(nonce)
            if session:
                best = self._compare_sessions(best, session)
        return best

    def _compare_sessions(self, current_best: Optional[PeerSession], candidate: PeerSession) -> PeerSession:
        """Compare two sessions and return the better one."""
        if current_best is None:
            return candidate
        
        # Prefer more recent sessions if both have same auth status
        if candidate.last_update > current_best.last_update:
            if candidate.is_authenticated or not current_best.is_authenticated:
                return candidate
        
        # Prefer authenticated sessions over non-authenticated even if older
        if candidate.is_authenticated and not current_best.is_authenticated:
            return candidate
        
        return current_best

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