"""
Tests for HostReputationTracker.

Ported from TypeScript SDK.
"""

import math
from bsv.overlay_tools.host_reputation_tracker import (
    HostReputationTracker,
    RankedHost,
    get_overlay_host_reputation_tracker
)


class TestHostReputationTracker:
    """Test HostReputationTracker."""

    def test_get_overlay_host_reputation_tracker(self):
        """Test get_overlay_host_reputation_tracker returns a HostReputationTracker instance."""
        tracker = get_overlay_host_reputation_tracker()

        assert isinstance(tracker, HostReputationTracker)

    def test_get_overlay_host_reputation_tracker_singleton(self):
        """Test get_overlay_host_reputation_tracker returns the same instance."""
        tracker1 = get_overlay_host_reputation_tracker()
        tracker2 = get_overlay_host_reputation_tracker()

        assert tracker1 is tracker2

    def test_host_reputation_tracker_creation(self):
        """Test HostReputationTracker can be created."""
        tracker = HostReputationTracker()
        assert tracker  # Verify object creation succeeds

    def test_ranked_host_creation(self):
        """Test RankedHost can be created."""
        host = RankedHost(host="https://example.com")
        assert host.host == "https://example.com"
        assert math.isclose(host.score, 0.0, abs_tol=1e-9)