"""
Tests for overlay tools constants.

Ported from TypeScript SDK.
"""

from bsv.overlay_tools.constants import (
    DEFAULT_SLAP_TRACKERS,
    DEFAULT_TESTNET_SLAP_TRACKERS,
    MAX_TRACKER_WAIT_TIME
)


class TestOverlayConstants:
    """Test overlay tools constants."""

    def test_default_slap_trackers(self):
        """Test DEFAULT_SLAP_TRACKERS contains expected URLs."""
        assert isinstance(DEFAULT_SLAP_TRACKERS, list)
        assert len(DEFAULT_SLAP_TRACKERS) >= 4  # Should have multiple trackers

        # Check that all are HTTPS URLs
        for tracker in DEFAULT_SLAP_TRACKERS:
            assert tracker.startswith("https://")
            assert len(tracker) > 0

    def test_default_testnet_slap_trackers(self):
        """Test DEFAULT_TESTNET_SLAP_TRACKERS contains expected URLs."""
        assert isinstance(DEFAULT_TESTNET_SLAP_TRACKERS, list)
        assert len(DEFAULT_TESTNET_SLAP_TRACKERS) >= 1  # Should have at least one tracker

        # Check that all are HTTPS URLs
        for tracker in DEFAULT_TESTNET_SLAP_TRACKERS:
            assert tracker.startswith("https://")
            assert len(tracker) > 0

    def test_max_tracker_wait_time(self):
        """Test MAX_TRACKER_WAIT_TIME is a reasonable value."""
        assert isinstance(MAX_TRACKER_WAIT_TIME, int)
        assert MAX_TRACKER_WAIT_TIME > 0
        assert MAX_TRACKER_WAIT_TIME <= 30000  # Should be reasonable (30 seconds max)
