"""
Tests for LivePolicy fee model.

Aligned with TypeScript SDK design where only compute_fee() is public API.
"""

import time
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from bsv.fee_models.live_policy import LivePolicy
from bsv.transaction import Transaction
from bsv.transaction_output import TransactionOutput
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
        policy = LivePolicy(cache_ttl_ms=60000, fallback_sat_per_kb=100)  # 1 minute cache

        # Mock the HTTP client to return a valid response
        with patch('bsv.fee_models.live_policy.default_http_client') as mock_client:
            mock_response = MagicMock()
            mock_response.json_data = {
                'policy': {
                    'miningFee': {
                        'satoshis': 150,
                        'bytes': 1000
                    }
                }
            }
            mock_http = MagicMock()
            mock_http.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_http

            # Create a simple transaction with a mock size
            tx = Transaction()
            with patch('bsv.fee_models.satoshis_per_kilobyte.SatoshisPerKilobyte.compute_fee', return_value=1000):
                result = await policy.compute_fee(tx)
                assert result == 1000

    @pytest.mark.asyncio
    async def test_compute_fee_fallback_to_default(self):
        """Test that compute_fee falls back to default rate when API fails."""
        policy = LivePolicy(fallback_sat_per_kb=100)

        # Mock the HTTP client to fail
        with patch('bsv.fee_models.live_policy.default_http_client') as mock_client:
            mock_http = MagicMock()
            mock_http.get = AsyncMock(side_effect=Exception("Network error"))
            mock_client.return_value = mock_http

            # Create a simple transaction
            tx = Transaction()
            with patch('bsv.fee_models.satoshis_per_kilobyte.SatoshisPerKilobyte.compute_fee', return_value=500) as mock_compute:
                result = await policy.compute_fee(tx)
                # Should use fallback rate
                assert policy.value == 100
                assert result == 500

    @pytest.mark.asyncio
    async def test_compute_fee_uses_cache(self):
        """Test that compute_fee uses cached rate when available and not expired."""
        policy = LivePolicy(cache_ttl_ms=60000, fallback_sat_per_kb=100)

        # First call to populate cache
        with patch('bsv.fee_models.live_policy.default_http_client') as mock_client:
            mock_response = MagicMock()
            mock_response.json_data = {
                'policy': {
                    'miningFee': {
                        'satoshis': 200,
                        'bytes': 1000
                    }
                }
            }
            mock_http = MagicMock()
            mock_http.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_http

            # Create transaction
            tx = Transaction()
            with patch('bsv.fee_models.satoshis_per_kilobyte.SatoshisPerKilobyte.compute_fee', return_value=1000):
                # First call
                await policy.compute_fee(tx)
                assert policy.value == 200

                # Second call should use cache (no HTTP call should be made)
                mock_http.get.reset_mock()
                await policy.compute_fee(tx)
                mock_http.get.assert_not_called()
                assert policy.value == 200

    @pytest.mark.asyncio
    async def test_compute_fee_updates_rate(self):
        """Test that compute_fee updates the rate property."""
        policy = LivePolicy(cache_ttl_ms=60000, fallback_sat_per_kb=100)

        # Mock HTTP client to return rate
        with patch('bsv.fee_models.live_policy.default_http_client') as mock_client:
            mock_response = MagicMock()
            mock_response.json_data = {
                'policy': {
                    'miningFee': {
                        'satoshis': 150,
                        'bytes': 1000
                    }
                }
            }
            mock_http = MagicMock()
            mock_http.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_http

            # Create transaction
            tx = Transaction()
            with patch('bsv.fee_models.satoshis_per_kilobyte.SatoshisPerKilobyte.compute_fee', return_value=500) as mock_compute:
                result = await policy.compute_fee(tx)

                # Should update the value property with fetched rate
                assert policy.value == 150
                mock_compute.assert_called_once_with(tx)
                assert result == 500

    @pytest.mark.asyncio
    async def test_cache_expiry(self):
        """Test that cache expires after TTL."""
        policy = LivePolicy(cache_ttl_ms=100, fallback_sat_per_kb=100)  # 100ms cache

        # Mock HTTP client
        with patch('bsv.fee_models.live_policy.default_http_client') as mock_client:
            mock_response = MagicMock()
            mock_response.json_data = {
                'policy': {
                    'miningFee': {
                        'satoshis': 150,
                        'bytes': 1000
                    }
                }
            }
            mock_http = MagicMock()
            mock_http.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_http

            # Create transaction
            tx = Transaction()
            with patch('bsv.fee_models.satoshis_per_kilobyte.SatoshisPerKilobyte.compute_fee', return_value=500):
                # First call to populate cache
                await policy.compute_fee(tx)
                assert policy.value == 150

                # Wait for cache to expire
                time.sleep(0.15)  # 150ms

                # Second call should fetch again (cache expired)
                mock_http.get.reset_mock()
                mock_response.json_data['policy']['miningFee']['satoshis'] = 200  # Different rate
                await policy.compute_fee(tx)
                mock_http.get.assert_called_once()  # Should have made a new HTTP call
                assert policy.value == 200
