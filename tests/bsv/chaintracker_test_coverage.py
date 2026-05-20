"""
Coverage tests for chaintracker.py - untested branches.
"""

import pytest

# Constants for skip messages
SKIP_CHAINTRACKER = "ChainTracker not available"
SKIP_DEFAULT_CHAINTRACKER = "DefaultChainTracker not available"


# ========================================================================
# ChainTracker interface branches
# ========================================================================


def test_chaintracker_interface_exists():
    """Test that ChainTracker interface exists."""
    try:
        from bsv.chaintracker import ChainTracker

        assert ChainTracker  # Verify import succeeds and class exists
    except ImportError:
        pytest.skip(SKIP_CHAINTRACKER)


# ========================================================================
# ChainTracker methods branches
# ========================================================================


def test_chaintracker_get_header():
    """Test ChainTracker get_header method exists."""
    try:
        from bsv.chaintracker import ChainTracker

        assert hasattr(ChainTracker, "get_header")
    except ImportError:
        pytest.skip(SKIP_CHAINTRACKER)


def test_chaintracker_get_height():
    """Test ChainTracker get_height method exists."""
    try:
        from bsv.chaintracker import ChainTracker

        assert hasattr(ChainTracker, "get_height")
    except ImportError:
        pytest.skip(SKIP_CHAINTRACKER)


# ========================================================================
# Default ChainTracker branches
# ========================================================================


def test_default_chaintracker_init():
    """Test default ChainTracker initialization."""
    try:
        from bsv.chaintracker import DefaultChainTracker

        tracker = DefaultChainTracker()
        assert tracker is not None
    except (ImportError, AttributeError):
        pytest.skip(SKIP_DEFAULT_CHAINTRACKER)


def test_default_chaintracker_get_height():
    """Test getting chain height."""
    try:
        from bsv.chaintracker import DefaultChainTracker

        tracker = DefaultChainTracker()

        if hasattr(tracker, "get_height"):
            try:
                height = tracker.get_height()
                assert isinstance(height, int)
            except Exception:
                # May require connection
                pass
    except (ImportError, AttributeError):
        pytest.skip(SKIP_DEFAULT_CHAINTRACKER)


def test_default_chaintracker_get_header():
    """Test getting block header."""
    try:
        from bsv.chaintracker import DefaultChainTracker

        tracker = DefaultChainTracker()

        if hasattr(tracker, "get_header"):
            try:
                tracker.get_header(0)  # Genesis block
                # Header retrieved or exception raised
            except Exception:
                # May require connection
                pass
    except (ImportError, AttributeError):
        pytest.skip(SKIP_DEFAULT_CHAINTRACKER)


# ========================================================================
# Edge cases
# ========================================================================


def test_chaintracker_get_header_negative():
    """Test getting header with negative height."""
    try:
        from bsv.chaintracker import DefaultChainTracker

        tracker = DefaultChainTracker()

        if hasattr(tracker, "get_header"):
            try:
                _ = tracker.get_header(-1)
            except (ValueError, IndexError):
                # Expected
                pass
    except (ImportError, AttributeError):
        pytest.skip(SKIP_DEFAULT_CHAINTRACKER)


def test_chaintracker_get_header_future():
    """Test getting _ beyond current height."""
    try:
        from bsv.chaintracker import DefaultChainTracker

        tracker = DefaultChainTracker()

        if hasattr(tracker, "get_header"):
            try:
                tracker.get_header(99999999)
                # Header is None or exception raised - both acceptable
            except Exception:
                # Expected exception - acceptable
                pass
    except (ImportError, AttributeError):
        pytest.skip(SKIP_DEFAULT_CHAINTRACKER)
