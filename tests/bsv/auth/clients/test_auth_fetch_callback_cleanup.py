"""
Tests for auth_fetch callback cleanup mechanisms
"""
import pytest
import threading
import time
from unittest.mock import Mock, patch, MagicMock
from bsv.auth.clients.auth_fetch import AuthFetch, SimplifiedFetchRequestOptions


class TestAuthFetchCallbackCleanup:
    """Test callback cleanup mechanisms in AuthFetch."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_wallet = Mock()
        self.requested_certs = Mock()
        self.auth_fetch = AuthFetch(self.mock_wallet, self.requested_certs)

    def test_setup_callbacks_creates_proper_structure(self):
        """Test that _setup_callbacks creates proper callback structure."""
        request_nonce_b64 = "test_nonce"

        response_event, response_holder = self.auth_fetch._setup_callbacks(request_nonce_b64)

        # Check event and holder
        assert isinstance(response_event, threading.Event)
        assert response_holder == {'resp': None, 'err': None}

        # Check callbacks are registered
        assert request_nonce_b64 in self.auth_fetch.callbacks
        assert 'resolve' in self.auth_fetch.callbacks[request_nonce_b64]
        assert 'reject' in self.auth_fetch.callbacks[request_nonce_b64]

    def test_callback_resolve_sets_response(self):
        """Test callback resolve sets response and signals event."""
        request_nonce_b64 = "test_nonce"
        response_event, response_holder = self.auth_fetch._setup_callbacks(request_nonce_b64)

        mock_response = Mock()
        mock_response.status_code = 200

        # Call resolve callback
        self.auth_fetch.callbacks[request_nonce_b64]['resolve'](mock_response)

        # Check response is set and event is signaled
        assert response_holder['resp'] == mock_response
        assert response_holder['err'] is None
        assert response_event.is_set()

    def test_callback_reject_sets_error(self):
        """Test callback reject sets error and signals event."""
        request_nonce_b64 = "test_nonce"
        response_event, response_holder = self.auth_fetch._setup_callbacks(request_nonce_b64)

        test_error = Exception("Test error")

        # Call reject callback
        self.auth_fetch.callbacks[request_nonce_b64]['reject'](test_error)

        # Check error is set and event is signaled
        assert response_holder['err'] == test_error
        assert response_holder['resp'] is None
        assert response_event.is_set()

    @patch('bsv.auth.clients.auth_fetch.threading.Event')
    def test_callback_exception_handling(self, mock_event_class):
        """Test exception handling in callback lambdas."""
        mock_event = Mock()
        mock_event_class.return_value = mock_event

        request_nonce_b64 = "test_nonce"
        response_event, response_holder = self.auth_fetch._setup_callbacks(request_nonce_b64)

        # Test resolve callback with exception - should propagate (this is expected behavior)
        def failing_resolve(resp):
            raise Exception("Resolve failed")

        # Replace the lambda with failing version
        self.auth_fetch.callbacks[request_nonce_b64]['resolve'] = failing_resolve

        # This should raise an exception (expected behavior)
        with pytest.raises(Exception, match="Resolve failed"):
            self.auth_fetch.callbacks[request_nonce_b64]['resolve']("test_resp")

        # Test reject callback with exception - should propagate
        def failing_reject(err):
            raise Exception("Reject failed")

        self.auth_fetch.callbacks[request_nonce_b64]['reject'] = failing_reject

        # This should raise an exception (expected behavior)
        with pytest.raises(Exception, match="Reject failed"):
            self.auth_fetch.callbacks[request_nonce_b64]['reject']("test_err")

    def test_cleanup_and_get_response_success(self):
        """Test _cleanup_and_get_response with successful response."""
        # Create mock peer
        mock_peer = Mock()
        listener_id = "test_listener_id"
        request_nonce_b64 = "test_nonce"
        response_holder = {'resp': Mock(), 'err': None}

        # Set up callback
        self.auth_fetch.callbacks[request_nonce_b64] = {'resolve': Mock(), 'reject': Mock()}

        result = self.auth_fetch._cleanup_and_get_response(mock_peer, listener_id, request_nonce_b64, response_holder)

        # Verify cleanup
        mock_peer.peer.stop_listening_for_general_messages.assert_called_once_with(listener_id)
        assert request_nonce_b64 not in self.auth_fetch.callbacks
        assert result == response_holder['resp']

    def test_cleanup_and_get_response_error(self):
        """Test _cleanup_and_get_response with error response."""
        mock_peer = Mock()
        listener_id = "test_listener_id"
        request_nonce_b64 = "test_nonce"
        test_error = Exception("Test error")
        response_holder = {'resp': None, 'err': test_error}

        # Set up callback
        self.auth_fetch.callbacks[request_nonce_b64] = {'resolve': Mock(), 'reject': Mock()}

        with pytest.raises(RuntimeError, match="Test error"):
            self.auth_fetch._cleanup_and_get_response(mock_peer, listener_id, request_nonce_b64, response_holder)

        # Verify cleanup still happened
        mock_peer.peer.stop_listening_for_general_messages.assert_called_once_with(listener_id)
        assert request_nonce_b64 not in self.auth_fetch.callbacks

    def test_cleanup_and_get_response_with_none_listener_id(self):
        """Test _cleanup_and_get_response with None listener_id."""
        mock_peer = Mock()
        listener_id = None
        request_nonce_b64 = "test_nonce"
        response_holder = {'resp': Mock(), 'err': None}

        # Set up callback
        self.auth_fetch.callbacks[request_nonce_b64] = {'resolve': Mock(), 'reject': Mock()}

        result = self.auth_fetch._cleanup_and_get_response(mock_peer, listener_id, request_nonce_b64, response_holder)

        # Verify cleanup with None listener_id
        mock_peer.peer.stop_listening_for_general_messages.assert_called_once_with(None)
        assert request_nonce_b64 not in self.auth_fetch.callbacks
        assert result == response_holder['resp']

    def test_cleanup_and_get_response_missing_callback(self):
        """Test _cleanup_and_get_response with missing callback (should not crash)."""
        mock_peer = Mock()
        listener_id = "test_listener_id"
        request_nonce_b64 = "missing_nonce"
        response_holder = {'resp': Mock(), 'err': None}

        # Don't set up callback - it should handle missing gracefully
        result = self.auth_fetch._cleanup_and_get_response(mock_peer, listener_id, request_nonce_b64, response_holder)

        # Should still work and clean up listener
        mock_peer.peer.stop_listening_for_general_messages.assert_called_once_with(listener_id)
        assert result == response_holder['resp']

    def test_multiple_callbacks_cleanup(self):
        """Test cleanup with multiple pending callbacks."""
        # Set up multiple callbacks
        nonces = ["nonce1", "nonce2", "nonce3"]
        for nonce in nonces:
            self.auth_fetch._setup_callbacks(nonce)

        assert len(self.auth_fetch.callbacks) == 3

        # Clean up each one
        mock_peer = Mock()
        for nonce in nonces:
            response_holder = {'resp': Mock(), 'err': None}
            self.auth_fetch._cleanup_and_get_response(mock_peer, "listener_id", nonce, response_holder)

        # All callbacks should be cleaned up
        assert len(self.auth_fetch.callbacks) == 0
        assert mock_peer.peer.stop_listening_for_general_messages.call_count == 3

    @pytest.mark.parametrize("error_type", ["string_error", "exception_error", "dict_error"])
    def test_callback_error_types(self, error_type):
        """Test callback reject with different error types."""
        request_nonce_b64 = "test_nonce"
        response_event, response_holder = self.auth_fetch._setup_callbacks(request_nonce_b64)

        # Test different error types
        if error_type == "string_error":
            test_error = "String error"
        elif error_type == "exception_error":
            test_error = ValueError("Exception error")
        elif error_type == "dict_error":
            test_error = {"error": "Dict error"}

        self.auth_fetch.callbacks[request_nonce_b64]['reject'](test_error)

        assert response_holder['err'] == test_error
        assert response_event.is_set()

    def test_callback_thread_safety(self):
        """Test callback thread safety with concurrent access."""
        import concurrent.futures

        request_nonce_b64 = "test_nonce"
        response_event, response_holder = self.auth_fetch._setup_callbacks(request_nonce_b64)

        results = []

        def call_resolve():
            time.sleep(0.01)  # Small delay to ensure concurrent execution
            try:
                self.auth_fetch.callbacks[request_nonce_b64]['resolve']("test_response")
                results.append("resolve_success")
            except Exception as e:
                results.append(f"resolve_error: {e}")

        def call_cleanup():
            time.sleep(0.01)
            try:
                mock_peer = Mock()
                self.auth_fetch._cleanup_and_get_response(mock_peer, "listener_id", request_nonce_b64, response_holder)
                results.append("cleanup_success")
            except Exception as e:
                results.append(f"cleanup_error: {e}")

        # Run concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future1 = executor.submit(call_resolve)
            future2 = executor.submit(call_cleanup)

            future1.result()
            future2.result()

        # Should have at least one success (race condition, but no crashes)
        assert len(results) >= 1
        assert any("success" in r for r in results)

    def test_callback_timeout_scenario(self):
        """Test callback behavior in timeout scenario."""
        request_nonce_b64 = "test_nonce"
        response_event, response_holder = self.auth_fetch._setup_callbacks(request_nonce_b64)

        # Simulate timeout - event never gets set
        assert not response_event.is_set()
        assert response_holder['resp'] is None
        assert response_holder['err'] is None

        # Callback should still be registered
        assert request_nonce_b64 in self.auth_fetch.callbacks

        # Manual cleanup should work
        mock_peer = Mock()
        response_holder_timeout = {'resp': None, 'err': "timeout"}
        with pytest.raises(RuntimeError, match="timeout"):
            self.auth_fetch._cleanup_and_get_response(mock_peer, "listener_id", request_nonce_b64, response_holder_timeout)
