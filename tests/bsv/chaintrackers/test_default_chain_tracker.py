"""
Tests for default_chain_tracker function.

Ported from TypeScript SDK.
"""

from bsv.chaintrackers.default import default_chain_tracker
from bsv.chaintrackers.whatsonchain import WhatsOnChainTracker


class TestDefaultChainTracker:
    """Test default_chain_tracker function."""

    def test_default_chain_tracker(self):
        """Test default_chain_tracker creates WhatsOnChain tracker."""
        tracker = default_chain_tracker()

        # Should create a WhatsOnChain tracker
        assert isinstance(tracker, WhatsOnChainTracker)
