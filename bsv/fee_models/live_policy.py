from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from ..constants import HTTP_REQUEST_TIMEOUT, TRANSACTION_FEE_RATE
from ..http_client import default_http_client
from .satoshis_per_kilobyte import SatoshisPerKilobyte


logger = logging.getLogger(__name__)


_DEFAULT_ARC_POLICY_URL = os.getenv(
    "BSV_PY_SDK_ARC_POLICY_URL", "https://arc.gorillapool.io/v1/policy"
)
_DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000


@dataclass
class _CachedRate:
    value: int
    fetched_at_ms: float


class LivePolicy(SatoshisPerKilobyte):
    """Dynamic fee model that fetches the live ARC policy endpoint.

    The first successful response is cached for ``cache_ttl_ms`` milliseconds so repeated
    calls to :meth:`compute_fee` do not repeatedly query the remote API.  If a fetch fails,
    the model falls back to ``fallback_sat_per_kb`` and caches that value for the TTL so
    offline environments still return consistent fees.
    """

    _instance: Optional["LivePolicy"] = None
    _instance_lock = threading.Lock()

    def __init__(
        self,
        cache_ttl_ms: int = _DEFAULT_CACHE_TTL_MS,
        arc_policy_url: Optional[str] = None,
        fallback_sat_per_kb: int = TRANSACTION_FEE_RATE,
        request_timeout: Optional[int] = None,
        api_key: Optional[str] = None,
    ) -> None:
        """Create a policy that fetches rates from ARC.

        Args:
            cache_ttl_ms: Duration to keep a fetched rate before refreshing.
            arc_policy_url: Override for the ARC policy endpoint.
            fallback_sat_per_kb: Fee to use when live retrieval fails.
            request_timeout: Timeout passed to ``requests.get``.
            api_key: Optional token included as an ``Authorization`` header.
        """
        super().__init__(fallback_sat_per_kb)
        self.cache_ttl_ms = cache_ttl_ms
        self.arc_policy_url = (arc_policy_url or _DEFAULT_ARC_POLICY_URL).rstrip("/")
        self.fallback_sat_per_kb = max(1, int(fallback_sat_per_kb))
        self.request_timeout = request_timeout or HTTP_REQUEST_TIMEOUT
        self.api_key = api_key or os.getenv("BSV_PY_SDK_ARC_POLICY_API_KEY")
        self._cache: Optional[_CachedRate] = None
        self._cache_lock = threading.Lock()

    @classmethod
    def get_instance(
        cls,
        cache_ttl_ms: int = _DEFAULT_CACHE_TTL_MS,
        arc_policy_url: Optional[str] = None,
        fallback_sat_per_kb: int = TRANSACTION_FEE_RATE,
        request_timeout: Optional[int] = None,
        api_key: Optional[str] = None,
    ) -> "LivePolicy":
        """Return a singleton instance so callers share the cached rate."""

        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls(
                        cache_ttl_ms=cache_ttl_ms,
                        arc_policy_url=arc_policy_url,
                        fallback_sat_per_kb=fallback_sat_per_kb,
                        request_timeout=request_timeout,
                        api_key=api_key,
                    )
        return cls._instance

    async def compute_fee(self, tx) -> int:  # type: ignore[override]
        """Compute a fee for ``tx`` using the latest ARC rate."""
        rate = await self.current_rate_sat_per_kb()
        self.value = rate
        return super().compute_fee(tx)

    async def current_rate_sat_per_kb(self) -> int:
        """Return the cached sat/kB rate or fetch a new value from ARC."""
        cache = self._get_cache(allow_stale=True)
        if cache and self._cache_valid(cache):
            return cache.value

        rate, error = await self._fetch_sat_per_kb()
        if rate is not None:
            self._set_cache(rate)
            return rate

        if cache is not None:
            message = error if error is not None else "unknown error"
            logger.warning(
                "Failed to fetch live fee rate, using cached value: %s",
                message,
            )
            return cache.value

        message = error if error is not None else "unknown error"
        logger.warning(
            "Failed to fetch live fee rate, using fallback %d sat/kB: %s",
            self.fallback_sat_per_kb,
            message,
        )
        return self.fallback_sat_per_kb

    def _cache_valid(self, cache: _CachedRate) -> bool:
        """Return True if ``cache`` is still within the TTL window."""
        current_ms = time.time() * 1000
        return (current_ms - cache.fetched_at_ms) < self.cache_ttl_ms

    def _get_cache(self, allow_stale: bool = False) -> Optional[_CachedRate]:
        """Read the cached value optionally even when the TTL has expired."""
        with self._cache_lock:
            if self._cache is None:
                return None
            if allow_stale:
                return self._cache
            if self._cache_valid(self._cache):
                return self._cache
            return None

    def _set_cache(self, value: int) -> None:
        """Persist ``value`` as the most recent fetched sat/kB rate."""
        with self._cache_lock:
            self._cache = _CachedRate(value=value, fetched_at_ms=time.time() * 1000)

    async def _fetch_sat_per_kb(self) -> Tuple[Optional[int], Optional[Exception]]:
        """Fetch the latest fee policy from ARC and coerce it to sat/kB."""
        try:
            headers = {"Accept": "application/json"}
            if self.api_key:
                headers["Authorization"] = self.api_key

            http_client = default_http_client()
            response = await http_client.get(
                self.arc_policy_url,
                headers=headers,
                timeout=self.request_timeout,
            )
            payload = response.json_data
            if isinstance(payload, dict) and "data" in payload:
                data_section = payload.get("data")
                if isinstance(data_section, dict):
                    payload = data_section
        except Exception as exc:
            return None, exc

        rate = self._extract_rate(payload)
        if rate is None:
            return None, ValueError("Invalid policy response format")
        return rate, None

    @staticmethod
    def _extract_rate(payload: dict) -> Optional[int]:
        """Extract a sat/kB rate from the ARC policy payload."""
        policy = payload.get("policy") if isinstance(payload, dict) else None
        if not isinstance(policy, dict):
            return None

        # Primary structure: policy.fees.miningFee {'satoshis': x, 'bytes': y}
        mining_fee = None
        fees_section = policy.get("fees")
        if isinstance(fees_section, dict):
            mining_fee = fees_section.get("miningFee")
        if mining_fee is None:
            mining_fee = policy.get("miningFee")

        if isinstance(mining_fee, dict):
            satoshis = mining_fee.get("satoshis")
            bytes_ = mining_fee.get("bytes")
            if isinstance(satoshis, (int, float)) and isinstance(bytes_, (int, float)) and bytes_ > 0:
                sat_per_byte = float(satoshis) / float(bytes_)
                return max(1, int(round(sat_per_byte * 1000)))

        for key in ("satPerKb", "sat_per_kb", "satoshisPerKb"):
            value = policy.get(key)
            if isinstance(value, (int, float)) and value > 0:
                return max(1, int(round(value)))

        return None
