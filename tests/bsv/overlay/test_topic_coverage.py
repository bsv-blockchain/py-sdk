"""
Coverage tests for overlay/topic.py - untested branches.
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch


# ========================================================================
# Overlay topic branches
# ========================================================================

def test_overlay_topic_init():
    """Test overlay topic initialization."""
    from bsv.overlay.topic import TopicBroadcaster, BroadcasterConfig

    config = BroadcasterConfig(network_preset='mainnet')
    topic = TopicBroadcaster(['test-topic'], config)
    assert topic is not None


def test_overlay_topic_subscribe():
    """Test subscribing to overlay topic."""
    from bsv.overlay.topic import TopicBroadcaster, BroadcasterConfig

    config = BroadcasterConfig(network_preset='mainnet')
    topic = TopicBroadcaster(['test-topic'], config)
    
    # TopicBroadcaster doesn't have subscribe method, only broadcast
    assert topic is not None
    assert hasattr(topic, 'broadcast')


def test_overlay_topic_publish():
    """Test publishing to overlay topic."""
    from bsv.overlay.topic import TopicBroadcaster, BroadcasterConfig

    config = BroadcasterConfig(network_preset='mainnet')
    topic = TopicBroadcaster(['test-topic'], config)
    
    # TopicBroadcaster has broadcast method, not publish
    assert topic is not None
    assert hasattr(topic, 'broadcast')


# ========================================================================
# Missing coverage tests
# ========================================================================

@pytest.mark.asyncio
async def test_topic_broadcast_async():
    """Test async broadcast method."""
    from bsv.overlay.topic import TopicBroadcaster, BroadcasterConfig
    from unittest.mock import AsyncMock

    config = BroadcasterConfig(network_preset='mainnet')
    topic = TopicBroadcaster(['test-topic'], config)
    
    # Mock the broadcaster's async broadcast method
    mock_tx = Mock()
    mock_response = {"status": "success", "txid": "abc123"}
    topic._broadcaster.broadcast = AsyncMock(return_value=mock_response)
    
    result = await topic.broadcast(mock_tx)
    assert result == mock_response
    topic._broadcaster.broadcast.assert_called_once_with(mock_tx)


def test_topic_sync_broadcast_with_method():
    """Test sync_broadcast when broadcaster has sync_broadcast method."""
    from bsv.overlay.topic import TopicBroadcaster, BroadcasterConfig
    from unittest.mock import Mock

    config = BroadcasterConfig(network_preset='mainnet')
    topic = TopicBroadcaster(['test-topic'], config)
    
    # Mock broadcaster with sync_broadcast method
    mock_tx = Mock()
    mock_response = {"status": "success", "txid": "abc123"}
    topic._broadcaster.sync_broadcast = Mock(return_value=mock_response)
    
    result = topic.sync_broadcast(mock_tx)
    assert result == mock_response
    topic._broadcaster.sync_broadcast.assert_called_once_with(mock_tx)


def test_topic_sync_broadcast_without_method():
    """Test sync_broadcast when broadcaster doesn't have sync_broadcast method."""
    from bsv.overlay.topic import TopicBroadcaster, BroadcasterConfig
    from unittest.mock import Mock, patch

    config = BroadcasterConfig(network_preset='mainnet')
    topic = TopicBroadcaster(['test-topic'], config)

    # Mock hasattr to return False for sync_broadcast method
    mock_tx = Mock()
    with patch('bsv.overlay.topic.hasattr') as mock_hasattr:
        mock_hasattr.return_value = False  # Pretend sync_broadcast doesn't exist
        result = topic.sync_broadcast(mock_tx)
        assert result == {"status": "noop"}


# ========================================================================
# Edge cases
# ========================================================================

def test_overlay_topic_empty_name():
    """Test overlay topic with empty name."""
    from bsv.overlay.topic import TopicBroadcaster, BroadcasterConfig

    config = BroadcasterConfig(network_preset='mainnet')
    # TopicBroadcaster accepts a list of topics, empty list is valid
    topic = TopicBroadcaster([], config)
    assert topic is not None

