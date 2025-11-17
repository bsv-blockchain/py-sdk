"""
LivePolicy fee model that fetches current rates from ARC GorillaPool.

Ported from TypeScript SDK.
"""

import time
import aiohttp
from typing import Optional
from .satoshis_per_kilobyte import SatoshisPerKilobyte


class LivePolicy(SatoshisPerKilobyte):
    """
    Represents a live fee policy that fetches current rates from ARC GorillaPool.
    Extends SatoshisPerKilobyte to reuse transaction size calculation logic.
    """

    ARC_POLICY_URL = "https://arc.gorillapool.io/v1/policy"
    _instance: Optional['LivePolicy'] = None

    def __init__(self, cache_validity_ms: int = 5 * 60 * 1000):  # 5 minutes default
        """
        Constructs an instance of the live policy fee model.

        :param cache_validity_ms: How long to cache the fee rate in milliseconds (default: 5 minutes)
        """
        super().__init__(100)  # Initialize with dummy value, will be overridden by fetch_fee_rate
        self.cached_rate: Optional[float] = None
        self.cache_timestamp: float = 0
        self.cache_validity_ms = cache_validity_ms

    @classmethod
    def get_instance(cls, cache_validity_ms: int = 5 * 60 * 1000) -> 'LivePolicy':
        """
        Gets the singleton instance of LivePolicy to ensure cache sharing across the application.

        :param cache_validity_ms: How long to cache the fee rate in milliseconds (default: 5 minutes)
        :returns: The singleton LivePolicy instance
        """
        if cls._instance is None:
            cls._instance = cls(cache_validity_ms)
        return cls._instance

    async def fetch_fee_rate(self) -> float:
        """
        Fetches the current fee rate from ARC GorillaPool API.

        :returns: The current satoshis per kilobyte rate
        """
        now = time.time() * 1000  # Convert to milliseconds

        # Return cached rate if still valid
        if self.cached_rate is not None and (now - self.cache_timestamp) < self.cache_validity_ms:
            return self.cached_rate

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.ARC_POLICY_URL) as response:
                    if not response.ok:
                        raise aiohttp.ClientResponseError(
                            response.request_info,
                            response.history,
                            status=response.status,
                            message=response.reason,
                            headers=response.headers
                        )

                    response_data = await response.json()

                    if not response_data.get('policy', {}).get('miningFee') or \
                       not isinstance(response_data['policy']['miningFee'].get('satoshis'), (int, float)) or \
                       not isinstance(response_data['policy']['miningFee'].get('bytes'), (int, float)):
                        raise ValueError('Invalid policy response format')

                    # Convert to satoshis per kilobyte
                    rate = (response_data['policy']['miningFee']['satoshis'] /
                           response_data['policy']['miningFee']['bytes']) * 1000

                    # Cache the result
                    self.cached_rate = rate
                    self.cache_timestamp = now

                    return rate

        except Exception as error:
            # If we have a cached rate, use it as fallback
            if self.cached_rate is not None:
                print(f"Warning: Failed to fetch live fee rate, using cached value: {error}")
                return self.cached_rate

            # Otherwise, use a reasonable default (100 sat/kb)
            print(f"Warning: Failed to fetch live fee rate, using default 100 sat/kb: {error}")
            return 100.0

    async def compute_fee(self, tx) -> int:
        """
        Computes the fee for a given transaction using the current live rate.
        Overrides the parent method to use dynamic rate fetching.

        :param tx: The transaction for which a fee is to be computed.
        :returns: The fee in satoshis for the transaction.
        """
        rate = await self.fetch_fee_rate()
        # Update the value property so parent's compute_fee uses the live rate
        self.value = rate
        return super().compute_fee(tx)
