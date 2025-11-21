import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from bsv.fee_models.live_policy import LivePolicy

# Reset the singleton instance before each test
def setup_function(_):
    LivePolicy._instance = None

# Reset the singleton instance after each test
def teardown_function(_):
    LivePolicy._instance = None

@patch("bsv.fee_models.live_policy.default_http_client", autospec=True)
def test_parses_mining_fee(mock_http_client_factory):
    # Prepare the mocked DefaultHttpClient instance
    mock_http_client = AsyncMock()
    mock_http_client_factory.return_value = mock_http_client

    # Set up a mock response
    mock_http_client.get.return_value.json_data = {
        "data": {
            "policy": {
                "fees": {
                    "miningFee": {"satoshis": 5, "bytes": 250}
                }
            }
        }
    }

    # Create the test instance
    policy = LivePolicy(
        cache_ttl_ms=60000,
        fallback_sat_per_kb=1,
        arc_policy_url="https://arc.mock/policy"
    )

    # Execute and verify the result
    rate = asyncio.run(policy._current_rate_sat_per_kb())
    assert rate == 20
    mock_http_client.get.assert_called_once()


@patch("bsv.fee_models.live_policy.default_http_client", autospec=True)
def test_cache_reused_when_valid(mock_http_client_factory):
    # Prepare the mocked DefaultHttpClient instance
    mock_http_client = AsyncMock()
    mock_http_client_factory.return_value = mock_http_client

    # Set up a mock response
    mock_http_client.get.return_value.json_data = {
        "data": {
            "policy": {"satPerKb": 50}
        }
    }

    policy = LivePolicy(
        cache_ttl_ms=60000,
        fallback_sat_per_kb=1,
        arc_policy_url="https://arc.mock/policy"
    )

    # Call multiple times within the cache validity period
    first_rate = asyncio.run(policy._current_rate_sat_per_kb())
    second_rate = asyncio.run(policy._current_rate_sat_per_kb())

    # Verify the results
    assert first_rate == 50
    assert second_rate == 50
    mock_http_client.get.assert_called_once()


@patch("bsv.fee_models.live_policy.default_http_client", autospec=True)
@patch("bsv.fee_models.live_policy.logger.warning")
def test_uses_cached_value_when_fetch_fails(mock_log, mock_http_client_factory):
    # Prepare the mocked DefaultHttpClient instance
    mock_http_client = AsyncMock()
    mock_http_client_factory.return_value = mock_http_client

    # Set up mock responses (success first, then failure)
    mock_http_client.get.side_effect = [
        AsyncMock(json_data={"data": {"policy": {"satPerKb": 75}}}),
        Exception("Network down")
    ]

    policy = LivePolicy(
        cache_ttl_ms=1,
        fallback_sat_per_kb=5,
        arc_policy_url="https://arc.mock/policy"
    )

    # The first execution succeeds
    first_rate = asyncio.run(policy._current_rate_sat_per_kb())
    assert first_rate == 75

    # Force invalidation of the cache
    with policy._cache_lock:
        policy._cache.fetched_at_ms -= 10

    # The second execution uses the cache
    second_rate = asyncio.run(policy._current_rate_sat_per_kb())
    assert second_rate == 75

    # Verify that a log is recorded for cache usage
    assert mock_log.call_count == 1
    args, _ = mock_log.call_args
    assert args[0] == "Failed to fetch live fee rate, using cached value: %s"
    mock_http_client.get.assert_called()


@patch("bsv.fee_models.live_policy.default_http_client", autospec=True)
@patch("bsv.fee_models.live_policy.logger.warning")
def test_falls_back_to_default_when_no_cache(mock_log, mock_http_client_factory):
    # Prepare the mocked DefaultHttpClient instance
    mock_http_client = AsyncMock()
    mock_http_client_factory.return_value = mock_http_client

    # Set up a mock response (always failing)
    mock_http_client.get.side_effect = Exception("Network failure")

    policy = LivePolicy(
        cache_ttl_ms=60000,
        fallback_sat_per_kb=9,
        arc_policy_url="https://arc.mock/policy"
    )

    # Fallback value is returned during execution
    rate = asyncio.run(policy._current_rate_sat_per_kb())
    assert rate == 9

    # Verify that a log is recorded
    assert mock_log.call_count == 1
    args, _ = mock_log.call_args
    assert args[0] == "Failed to fetch live fee rate, using fallback %d sat/kB: %s"
    assert args[1] == 9
    mock_http_client.get.assert_called()


@patch("bsv.fee_models.live_policy.default_http_client", autospec=True)
@patch("bsv.fee_models.live_policy.logger.warning")
def test_invalid_response_triggers_fallback(mock_log, mock_http_client_factory):
    # Prepare the mocked DefaultHttpClient instance
    mock_http_client = AsyncMock()
    mock_http_client_factory.return_value = mock_http_client

    # Set up an invalid response
    mock_http_client.get.return_value.json_data = {
        "data": {"policy": {"invalid": True}}
    }

    policy = LivePolicy(
        cache_ttl_ms=60000,
        fallback_sat_per_kb=3,
        arc_policy_url="https://arc.mock/policy"
    )

    # Fallback value is returned due to the invalid response
    rate = asyncio.run(policy._current_rate_sat_per_kb())
    assert rate == 3

    # Verify that a log is recorded
    assert mock_log.call_count == 1
    args, _ = mock_log.call_args
    assert args[0] == "Failed to fetch live fee rate, using fallback %d sat/kB: %s"
    assert args[1] == 3
    mock_http_client.get.assert_called()