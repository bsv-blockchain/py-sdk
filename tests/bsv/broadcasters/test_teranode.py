"""
Tests for Teranode broadcaster.

Ported from TypeScript SDK.
"""

import pytest
import aiohttp
from unittest.mock import AsyncMock, patch
from bsv.broadcasters.teranode import Teranode
from bsv.broadcasters.broadcaster import BroadcastResponse, BroadcastFailure
from bsv.transaction import Transaction
from bsv.script.script import Script


class TestTeranode:
    """Test Teranode broadcaster."""

    def test_constructor(self):
        """Test Teranode constructor."""
        broadcaster = Teranode("https://api.teranode.com")
        assert broadcaster.URL == "https://api.teranode.com"

    @pytest.mark.asyncio
    async def test_broadcast_structure(self):
        """Test that broadcast method exists and can be called."""
        tx = Transaction()
        tx.version = 1
        tx.lock_time = 0

        broadcaster = Teranode("https://api.teranode.com")

        # Test that the method exists and returns the expected types
        # We expect it to fail due to network issues in test environment
        result = await broadcaster.broadcast(tx)

        # Should return some kind of response/failure
        assert result is not None
        assert hasattr(result, 'status')
        # In test environment, it will likely fail due to network
        assert result.status in ['success', 'error']

    @pytest.mark.asyncio
    async def test_broadcast_with_invalid_url(self):
        """Test broadcast with invalid URL."""
        tx = Transaction()
        tx.version = 1
        tx.lock_time = 0

        # Use an invalid URL to force network error
        broadcaster = Teranode("https://invalid.url.that.does.not.exist")

        result = await broadcaster.broadcast(tx)

        # Should return a failure due to network error
        assert isinstance(result, BroadcastFailure)
        assert result.status == "error"

    def test_url_property(self):
        """Test URL property is set correctly."""
        url = "https://teranode.example.com/api"
        broadcaster = Teranode(url)
        assert broadcaster.URL == url

    @pytest.mark.asyncio
    async def test_broadcast_http_error_response(self):
        """Test broadcast with HTTP error response."""
        from unittest.mock import AsyncMock, MagicMock, patch

        tx = Transaction()
        tx.version = 1
        tx.lock_time = 0

        broadcaster = Teranode("https://api.teranode.com")

        # Mock the aiohttp response
        mock_response = AsyncMock()
        mock_response.ok = False
        mock_response.status = 400
        mock_response.text = AsyncMock(return_value="Bad Request: Invalid transaction")

        # Create a proper async context manager for post
        class MockPostContext:
            def __init__(self, response):
                self.response = response
            async def __aenter__(self):
                return self.response
            async def __aexit__(self, *args):
                return None

        # Mock the session post method
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_session.post = MagicMock(return_value=MockPostContext(mock_response))
            mock_session_class.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await broadcaster.broadcast(tx)

            assert isinstance(result, BroadcastFailure)
            assert result.status == "error"
            assert result.code == "400"
            assert "Bad Request" in result.description

    @pytest.mark.asyncio
    async def test_broadcast_network_error(self):
        """Test broadcast with network error."""
        from unittest.mock import AsyncMock, patch, MagicMock
        tx = Transaction()
        tx.version = 1
        tx.lock_time = 0

        broadcaster = Teranode("https://api.teranode.com")

        # Mock network error - raise when post() is called
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            # Create a context manager that raises the error
            class MockPostContextError:
                async def __aenter__(self):
                    raise aiohttp.ClientError("Connection timeout")
                async def __aexit__(self, *args):
                    return None
            
            mock_session.post = MagicMock(return_value=MockPostContextError())
            mock_session_class.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await broadcaster.broadcast(tx)

            assert isinstance(result, BroadcastFailure)
            assert result.status == "error"
            assert result.code == "500"
            assert "Network error" in result.description

    @pytest.mark.asyncio
    async def test_broadcast_unexpected_error(self):
        """Test broadcast with unexpected error."""
        from unittest.mock import AsyncMock, patch, MagicMock
        tx = Transaction()
        tx.version = 1
        tx.lock_time = 0

        broadcaster = Teranode("https://api.teranode.com")

        # Mock unexpected error - raise when post() context is entered
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            # Create a context manager that raises the error
            class MockPostContextError:
                async def __aenter__(self):
                    raise ValueError("Unexpected error")
                async def __aexit__(self, *args):
                    return None
            
            mock_session.post = MagicMock(return_value=MockPostContextError())
            mock_session_class.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await broadcaster.broadcast(tx)

            assert isinstance(result, BroadcastFailure)
            assert result.status == "error"
            assert result.code == "500"
            assert "Unexpected error" in result.description

    @pytest.mark.asyncio
    async def test_broadcast_success_response(self):
        """Test broadcast with successful response."""
        from unittest.mock import AsyncMock, patch, MagicMock
        tx = Transaction()
        tx.version = 1
        tx.lock_time = 0
        # Mock the txid method
        tx.txid = lambda: "a" * 64

        broadcaster = Teranode("https://api.teranode.com")

        # Mock successful response
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_response = AsyncMock()
            mock_response.ok = True
            mock_response.status = 200

            # Create a proper async context manager for post
            class MockPostContext:
                def __init__(self, response):
                    self.response = response
                async def __aenter__(self):
                    return self.response
                async def __aexit__(self, *args):
                    return None
            
            mock_session = AsyncMock()
            mock_session.post = MagicMock(return_value=MockPostContext(mock_response))
            mock_session_class.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await broadcaster.broadcast(tx)

            assert isinstance(result, BroadcastResponse)
            assert result.status == "success"
            assert result.txid == "a" * 64
            assert result.message == "broadcast successful"

    @pytest.mark.asyncio
    async def test_broadcast_empty_error_text(self):
        """Test broadcast with HTTP error but empty error text."""
        from unittest.mock import AsyncMock, patch, MagicMock
        tx = Transaction()
        tx.version = 1
        tx.lock_time = 0

        broadcaster = Teranode("https://api.teranode.com")

        # Mock response with empty error text
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_response = AsyncMock()
            mock_response.ok = False
            mock_response.status = 404
            mock_response.text = AsyncMock(return_value="")

            # Create a proper async context manager for post
            class MockPostContext:
                def __init__(self, response):
                    self.response = response
                async def __aenter__(self):
                    return self.response
                async def __aexit__(self, *args):
                    return None
            
            mock_session = AsyncMock()
            mock_session.post = MagicMock(return_value=MockPostContext(mock_response))
            mock_session_class.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await broadcaster.broadcast(tx)

            assert isinstance(result, BroadcastFailure)
            assert result.status == "error"
            assert result.code == "404"
            assert "HTTP 404" in result.description
