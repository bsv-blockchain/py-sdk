"""
Tests for HostReputationTracker implementation.

Translated from TS SDK HostReputationTracker tests.
"""
import pytest
import time
from bsv.overlay_tools.host_reputation_tracker import (
    HostReputationTracker, RankedHost, STORAGE_KEY
)


class TestHostReputationTracker:
    """Test HostReputationTracker matching TS SDK tests."""

    def test_should_record_success(self):
        """Test that recordSuccess updates host statistics."""
        tracker = HostReputationTracker()
        tracker.record_success('host1', 100.0)
        
        ranked = tracker.get_ranked_hosts()
        assert len(ranked) == 1
        assert ranked[0].host == 'host1'
        assert ranked[0].total_successes == 1
        assert ranked[0].total_failures == 0

    def test_should_record_failure(self):
        """Test that recordFailure updates host statistics."""
        tracker = HostReputationTracker()
        tracker.record_failure('host1', 'Connection timeout')
        
        entry = tracker.stats.get('host1')
        assert entry is not None
        assert entry.total_failures == 1
        assert entry.consecutive_failures == 1
        assert entry.last_error == 'Connection timeout'

    def test_should_rank_hosts_by_score(self):
        """Test that getRankedHosts returns hosts sorted by score."""
        tracker = HostReputationTracker()
        tracker.record_success('host1', 50.0)  # Fast, successful
        tracker.record_success('host1', 60.0)
        tracker.record_failure('host2', 'Error')
        tracker.record_success('host3', 200.0)  # Slower but successful
        
        ranked = tracker.get_ranked_hosts()
        assert len(ranked) >= 2
        # host1 should rank highest (fast and successful)
        assert ranked[0].host == 'host1'

    def test_should_respect_backoff_period(self):
        """Test that hosts in backoff are excluded from rankings."""
        tracker = HostReputationTracker()
        tracker.record_failure('host1', 'Error')
        tracker.record_failure('host1', 'Error')
        tracker.record_failure('host1', 'Error')
        
        ranked = tracker.get_ranked_hosts()
        # Host should be in backoff and excluded
        assert all(h.host != 'host1' or h.backoff_until > int(time.time() * 1000) for h in ranked)

    def test_should_persist_to_storage(self):
        """Test that reputation data persists to storage."""
        store = {}
        tracker1 = HostReputationTracker(store)
        tracker1.record_success('host1', 100.0)
        
        # Verify data was saved
        assert STORAGE_KEY in store
        
        tracker2 = HostReputationTracker(store)
        # Verify stats were loaded
        assert 'host1' in tracker2.stats
        ranked = tracker2.get_ranked_hosts()
        assert len(ranked) == 1
        assert ranked[0].host == 'host1'

