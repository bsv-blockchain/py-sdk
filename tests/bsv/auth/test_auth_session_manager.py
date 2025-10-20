import pytest
from bsv.auth.session_manager import DefaultSessionManager
from bsv.auth.peer_session import PeerSession
from bsv.keys import PrivateKey


class TestDefaultSessionManager:
    def setup_method(self):
        self.session_manager = DefaultSessionManager()
        self.identity_key = PrivateKey(1).public_key()

    def test_add_and_get_session_by_nonce_and_identity_key(self):
        session = PeerSession(
            is_authenticated=False,
            session_nonce="nonce-1",
            peer_identity_key=self.identity_key,
            last_update=1,
        )

        self.session_manager.add_session(session)

        # By session nonce
        assert self.session_manager.get_session("nonce-1") is session

        # By identity key
        key_hex = self.identity_key.hex()
        assert self.session_manager.get_session(key_hex) is session

    def test_add_session_missing_nonce_raises(self):
        session = PeerSession(
            is_authenticated=False,
            session_nonce="",
            peer_identity_key=self.identity_key,
            last_update=1,
        )

        with pytest.raises(ValueError) as exc:
            self.session_manager.add_session(session)
        assert "session_nonce is required" in str(exc.value)

    def test_add_session_missing_identity_key_is_allowed(self):
        session = PeerSession(
            is_authenticated=False,
            session_nonce="nonce-2",
            peer_identity_key=None,
            last_update=1,
        )

        # Should not raise
        self.session_manager.add_session(session)
        assert self.session_manager.get_session("nonce-2") is session

    def test_remove_session_removes_from_both_maps(self):
        session = PeerSession(
            is_authenticated=False,
            session_nonce="nonce-3",
            peer_identity_key=self.identity_key,
            last_update=1,
        )
        self.session_manager.add_session(session)

        self.session_manager.remove_session(session)

        # Removed by nonce
        assert self.session_manager.get_session("nonce-3") is None

        # Removed by identity key mapping
        key_hex = self.identity_key.hex()
        assert self.session_manager.get_session(key_hex) is None

    def test_remove_session_with_undefined_identifiers_is_noop(self):
        # Removing a session that was never added (or with empty nonce) should not raise
        session = PeerSession(
            is_authenticated=False,
            session_nonce="",
            peer_identity_key=None,
            last_update=1,
        )
        self.session_manager.remove_session(session)

    def test_has_session(self):
        session = PeerSession(
            is_authenticated=False,
            session_nonce="nonce-4",
            peer_identity_key=self.identity_key,
            last_update=1,
        )
        self.session_manager.add_session(session)

        assert self.session_manager.has_session("nonce-4") is True
        assert self.session_manager.has_session(self.identity_key.hex()) is True
        assert self.session_manager.has_session("non-existent") is False

    def test_get_session_by_identity_key_prefers_newer_when_same_auth_state(self):
        # Same identity key, two sessions; newer last_update should win when auth state is the same
        s_old = PeerSession(
            is_authenticated=False,
            session_nonce="nonce-old",
            peer_identity_key=self.identity_key,
            last_update=100,
        )
        s_new = PeerSession(
            is_authenticated=False,
            session_nonce="nonce-new",
            peer_identity_key=self.identity_key,
            last_update=200,
        )
        self.session_manager.add_session(s_old)
        self.session_manager.add_session(s_new)

        selected = self.session_manager.get_session(self.identity_key.hex())
        assert selected is s_new

    def test_get_session_by_identity_key_prefers_authenticated_even_if_older(self):
        # Authenticated older session should be preferred over newer unauthenticated
        s_unauth_new = PeerSession(
            is_authenticated=False,
            session_nonce="nonce-unauth",
            peer_identity_key=self.identity_key,
            last_update=300,
        )
        s_auth_old = PeerSession(
            is_authenticated=True,
            session_nonce="nonce-auth",
            peer_identity_key=self.identity_key,
            last_update=250,
        )
        self.session_manager.add_session(s_unauth_new)
        self.session_manager.add_session(s_auth_old)

        selected = self.session_manager.get_session(self.identity_key.hex())
        assert selected is s_auth_old


