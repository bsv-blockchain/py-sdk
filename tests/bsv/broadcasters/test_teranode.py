"""
Tests for Teranode broadcaster.

Ported from TypeScript SDK.
"""

import pytest
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
