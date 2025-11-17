"""
Tests for GullibleHeadersClient - a test-only chain tracker that accepts any merkle root.

WARNING: This client is for testing purposes only. It does NOT verify merkle roots
and should NEVER be used in production code.
"""

import pytest
from bsv.spv.gullible_headers_client import GullibleHeadersClient


class TestGullibleHeadersClient:
    """Test cases for GullibleHeadersClient ported from Go-SDK spv/scripts_only.go"""

    @pytest.mark.asyncio
    async def test_is_valid_root_for_height_always_returns_true(self):
        """Test that is_valid_root_for_height always returns True regardless of input."""
        client = GullibleHeadersClient()
        
        # Test with various inputs - all should return True
        assert await client.is_valid_root_for_height("any_root", 0) is True
        assert await client.is_valid_root_for_height("another_root", 100) is True
        assert await client.is_valid_root_for_height("", 999999) is True
        
        # Test with different root formats
        assert await client.is_valid_root_for_height(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            1
        ) is True

    @pytest.mark.asyncio
    async def test_current_height_returns_dummy_height(self):
        """Test that current_height returns a dummy height (800000) for testing."""
        client = GullibleHeadersClient()
        
        height = await client.current_height()
        assert height == 800000

    @pytest.mark.asyncio
    async def test_implements_chain_tracker_interface(self):
        """Test that GullibleHeadersClient implements ChainTracker interface."""
        from bsv.chaintracker import ChainTracker
        
        client = GullibleHeadersClient()
        assert isinstance(client, ChainTracker)
        
        # Verify both required methods exist and are callable
        assert hasattr(client, 'is_valid_root_for_height')
        assert hasattr(client, 'current_height')
        assert callable(client.is_valid_root_for_height)
        assert callable(client.current_height)

