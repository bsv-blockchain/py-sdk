"""
HostReputationTracker implementation for tracking overlay host performance.

Translated from ts-sdk/src/overlay-tools/HostReputationTracker.ts
"""
from typing import Optional, Dict, List
from dataclasses import dataclass, field
import time
import json


DEFAULT_LATENCY_MS = 1500
LATENCY_SMOOTHING_FACTOR = 0.25
BASE_BACKOFF_MS = 1000
MAX_BACKOFF_MS = 60000
FAILURE_PENALTY_MS = 400
SUCCESS_BONUS_MS = 30
FAILURE_BACKOFF_GRACE = 2
STORAGE_KEY = 'bsvsdk_overlay_host_reputation_v1'


@dataclass
class HostReputationEntry:
    """Reputation entry for a host."""
    host: str
    total_successes: int = 0
    total_failures: int = 0
    consecutive_failures: int = 0
    avg_latency_ms: Optional[float] = None
    last_latency_ms: Optional[float] = None
    backoff_until: int = 0
    last_updated_at: int = field(default_factory=lambda: int(time.time() * 1000))
    last_error: Optional[str] = None


@dataclass
class RankedHost(HostReputationEntry):
    """Host entry with reputation score."""
    score: float = 0.0


class HostReputationTracker:
    """
    Tracks reputation and performance metrics for overlay hosts.
    
    Provides functionality to record successes/failures, calculate scores,
    and rank hosts by reputation.
    """

    def __init__(self, store: Optional[Dict[str, str]] = None):
        """
        Initialize HostReputationTracker.
        
        Args:
            store: Optional key-value store for persistence (dict-like interface)
        """
        self.stats: Dict[str, HostReputationEntry] = {}
        self.store = store if store is not None else {}
        self.load_from_storage()

    def reset(self) -> None:
        """Reset all reputation statistics."""
        self.stats.clear()
        self.save_to_storage()

    def record_success(self, host: str, latency_ms: float) -> None:
        """
        Record a successful request to a host.
        
        Args:
            host: Host identifier
            latency_ms: Request latency in milliseconds
        """
        entry = self._get_or_create(host)
        now = int(time.time() * 1000)
        safe_latency = latency_ms if latency_ms >= 0 and latency_ms != float('inf') else DEFAULT_LATENCY_MS

        if entry.avg_latency_ms is None:
            entry.avg_latency_ms = safe_latency
        else:
            entry.avg_latency_ms = (
                (1 - LATENCY_SMOOTHING_FACTOR) * entry.avg_latency_ms +
                LATENCY_SMOOTHING_FACTOR * safe_latency
            )

        entry.last_latency_ms = safe_latency
        entry.total_successes += 1
        entry.consecutive_failures = 0
        entry.backoff_until = 0
        entry.last_updated_at = now
        entry.last_error = None
        self.save_to_storage()

    def record_failure(self, host: str, reason: Optional[str] = None) -> None:
        """
        Record a failed request to a host.
        
        Args:
            host: Host identifier
            reason: Optional failure reason/error message
        """
        entry = self._get_or_create(host)
        now = int(time.time() * 1000)
        entry.total_failures += 1
        entry.consecutive_failures += 1

        msg = reason if isinstance(reason, str) else None
        immediate = (
            msg and (
                'ERR_NAME_NOT_RESOLVED' in msg or
                'ENOTFOUND' in msg or
                'getaddrinfo' in msg or
                'Failed to fetch' in msg
            )
        )

        if immediate and entry.consecutive_failures < FAILURE_BACKOFF_GRACE + 1:
            entry.consecutive_failures = FAILURE_BACKOFF_GRACE + 1

        penalty_level = max(entry.consecutive_failures - FAILURE_BACKOFF_GRACE, 0)
        if penalty_level == 0:
            entry.backoff_until = 0
        else:
            backoff_duration = min(
                MAX_BACKOFF_MS,
                BASE_BACKOFF_MS * (2 ** (penalty_level - 1))
            )
            entry.backoff_until = now + backoff_duration

        entry.last_updated_at = now
        entry.last_error = msg
        self.save_to_storage()

    def get_ranked_hosts(self, min_score: float = 0.0) -> List[RankedHost]:
        """
        Get hosts ranked by reputation score.
        
        Args:
            min_score: Minimum score threshold
            
        Returns:
            List of ranked hosts sorted by score (highest first)
        """
        now = int(time.time() * 1000)
        ranked = []

        for host, entry in self.stats.items():
            # Skip if in backoff period
            if entry.backoff_until > now:
                continue

            # Calculate score
            total_requests = entry.total_successes + entry.total_failures
            if total_requests == 0:
                score = 0.0
            else:
                success_rate = entry.total_successes / total_requests
                latency_factor = 1.0
                if entry.avg_latency_ms is not None:
                    latency_factor = max(0.1, 1.0 - (entry.avg_latency_ms / DEFAULT_LATENCY_MS))
                score = success_rate * latency_factor

            if score >= min_score:
                ranked_host = RankedHost(
                    host=entry.host,
                    total_successes=entry.total_successes,
                    total_failures=entry.total_failures,
                    consecutive_failures=entry.consecutive_failures,
                    avg_latency_ms=entry.avg_latency_ms,
                    last_latency_ms=entry.last_latency_ms,
                    backoff_until=entry.backoff_until,
                    last_updated_at=entry.last_updated_at,
                    last_error=entry.last_error,
                    score=score
                )
                ranked.append(ranked_host)

        # Sort by score (highest first)
        ranked.sort(key=lambda x: x.score, reverse=True)
        return ranked

    def _get_or_create(self, host: str) -> HostReputationEntry:
        """Get or create reputation entry for host."""
        if host not in self.stats:
            self.stats[host] = HostReputationEntry(host=host)
        return self.stats[host]

    def save_to_storage(self) -> None:
        """Save reputation data to storage."""
        if self.store is None or not hasattr(self.store, '__setitem__'):
            return
        data = {
            host: {
                'total_successes': entry.total_successes,
                'total_failures': entry.total_failures,
                'consecutive_failures': entry.consecutive_failures,
                'avg_latency_ms': entry.avg_latency_ms,
                'last_latency_ms': entry.last_latency_ms,
                'backoff_until': entry.backoff_until,
                'last_updated_at': entry.last_updated_at,
                'last_error': entry.last_error
            }
            for host, entry in self.stats.items()
        }
        self.store[STORAGE_KEY] = json.dumps(data)

    def load_from_storage(self) -> None:
        """Load reputation data from storage."""
        if self.store is None or not hasattr(self.store, 'get'):
            return
        stored = self.store.get(STORAGE_KEY)
        if stored:
            try:
                data = json.loads(stored)
                for host, entry_data in data.items():
                    self.stats[host] = HostReputationEntry(
                        host=host,
                        total_successes=entry_data.get('total_successes', 0),
                        total_failures=entry_data.get('total_failures', 0),
                        consecutive_failures=entry_data.get('consecutive_failures', 0),
                        avg_latency_ms=entry_data.get('avg_latency_ms'),
                        last_latency_ms=entry_data.get('last_latency_ms'),
                        backoff_until=entry_data.get('backoff_until', 0),
                        last_updated_at=entry_data.get('last_updated_at', int(time.time() * 1000)),
                        last_error=entry_data.get('last_error')
                    )
            except Exception:
                pass


# Global tracker instance (singleton)
_global_tracker = HostReputationTracker()


def get_overlay_host_reputation_tracker() -> HostReputationTracker:
    """
    Get the global overlay host reputation tracker instance.

    :returns: Global HostReputationTracker instance
    """
    return _global_tracker

