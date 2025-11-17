"""
Tests for LivePolicy fee model.

Ported from TypeScript SDK.
"""

import time
import aiohttp
import pytest
from unittest.mock import AsyncMock, patch
from bsv.fee_models.live_policy import LivePolicy
from bsv.transaction import Transaction
from bsv.script.script import Script


class TestLivePolicy:
    """Test LivePolicy fee model."""

    def test_singleton_instance(self):
        """Test that get_instance returns the same instance."""
        instance1 = LivePolicy.get_instance()
        instance2 = LivePolicy.get_instance()

        assert instance1 is instance2
        assert isinstance(instance1, LivePolicy)

    def test_singleton_different_cache_validity(self):
        """Test that get_instance with different cache validity still returns same instance."""
        instance1 = LivePolicy.get_instance(300000)  # 5 minutes
        instance2 = LivePolicy.get_instance(600000)  # 10 minutes

        # Should return the same instance (first one created)
        assert instance1 is instance2

    @pytest.mark.asyncio
    async def test_compute_fee_with_cached_rate(self):
        """Test compute_fee uses cached rate when available."""
        policy = LivePolicy(60000)  # 1 minute cache
        policy.cached_rate = 150  # Set cached rate
        policy.cache_timestamp = time.time() * 1000  # Set recent timestamp

        # Create a simple transaction
        tx = Transaction()
        tx.version = 1
        tx.lock_time = 0

        # Mock the parent compute_fee method
        with patch('bsv.fee_models.satoshis_per_kilobyte.SatoshisPerKilobyte.compute_fee', return_value=1000) as mock_compute:
            result = await policy.compute_fee(tx)

            # Should use cached rate
            assert policy.value == 150
            mock_compute.assert_called_once_with(tx)
            assert result == 1000

    @pytest.mark.asyncio
    async def test_fetch_fee_rate_fallback_to_default(self):
        """Test that fetch_fee_rate falls back to default when API fails."""
        policy = LivePolicy()

        # Mock aiohttp to always fail
        with patch('aiohttp.ClientSession', side_effect=Exception("Network error")):
            rate = await policy.fetch_fee_rate()

            # Should fall back to default rate
            assert rate == 100

    @pytest.mark.asyncio
    async def test_fetch_fee_rate_uses_cache(self):
        """Test that cached rate is returned when available and not expired."""
        policy = LivePolicy()
        policy.cached_rate = 200
        policy.cache_timestamp = time.time() * 1000  # Recent timestamp

        # Should return cached rate without making API call
        rate = await policy.fetch_fee_rate()
        assert rate == 200

    @pytest.mark.asyncio
    async def test_compute_fee_updates_rate(self):
        """Test that compute_fee updates the rate property."""
        policy = LivePolicy()
        policy.cached_rate = 150  # Set cached rate
        policy.cache_timestamp = time.time() * 1000  # Ensure cache is not expired

        # Create a simple transaction
        tx = Transaction()
        tx.version = 1
        tx.lock_time = 0

        # Mock the parent compute_fee method
        with patch('bsv.fee_models.satoshis_per_kilobyte.SatoshisPerKilobyte.compute_fee', return_value=500) as mock_compute:
            result = await policy.compute_fee(tx)

            # Should use cached rate
            assert policy.value == 150
            mock_compute.assert_called_once_with(tx)
            assert result == 500

    def test_cache_expiry(self):
        """Test cache expiry logic."""
        policy = LivePolicy(1000)  # 1 second cache

        # Set cached values
        policy.cached_rate = 150
        policy.cache_timestamp = 1000  # Old timestamp

        # With current time much later, cache should be considered expired
        current_time = time.time() * 1000  # Convert to milliseconds

        # Cache should be expired
        assert (current_time - policy.cache_timestamp) >= policy.cache_validity_ms
