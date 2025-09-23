from unittest.mock import MagicMock, patch

import requests

from bsv.fee_models.live_policy import LivePolicy


def setup_function(_):
    LivePolicy._instance = None


def teardown_function(_):
    LivePolicy._instance = None


def _mock_response(payload):
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


@patch("bsv.fee_models.live_policy.requests.get")
def test_parses_mining_fee(mock_get):
    payload = {
        "policy": {
            "fees": {
                "miningFee": {"satoshis": 5, "bytes": 250}
            }
        }
    }
    mock_get.return_value = _mock_response(payload)

    policy = LivePolicy(cache_ttl_ms=60000, fallback_sat_per_kb=1)

    assert policy.current_rate_sat_per_kb() == 20


@patch("bsv.fee_models.live_policy.requests.get")
def test_cache_reused_when_valid(mock_get):
    payload = {"policy": {"satPerKb": 50}}
    mock_get.return_value = _mock_response(payload)

    policy = LivePolicy(cache_ttl_ms=60000, fallback_sat_per_kb=1)

    first = policy.current_rate_sat_per_kb()
    second = policy.current_rate_sat_per_kb()

    assert first == 50
    assert second == 50
    mock_get.assert_called_once()


@patch("bsv.fee_models.live_policy.requests.get")
@patch("bsv.fee_models.live_policy.logger.warning")
def test_uses_cached_value_when_fetch_fails(mock_log, mock_get):
    payload = {"policy": {"satPerKb": 75}}
    mock_get.side_effect = [
        _mock_response(payload),
        requests.RequestException("Network down"),
    ]

    policy = LivePolicy(cache_ttl_ms=1, fallback_sat_per_kb=5)

    first = policy.current_rate_sat_per_kb()
    assert first == 75

    # Expire cache manually
    with policy._cache_lock:
        policy._cache.fetched_at_ms -= 10

    second = policy.current_rate_sat_per_kb()
    assert second == 75

    assert mock_log.call_count == 1
    args, _ = mock_log.call_args
    assert args[0] == "Failed to fetch live fee rate, using cached value: %s"
    assert isinstance(args[1], requests.RequestException)
    assert str(args[1]) == "Network down"


@patch("bsv.fee_models.live_policy.requests.get", side_effect=requests.RequestException("boom"))
@patch("bsv.fee_models.live_policy.logger.warning")
def test_falls_back_to_default_when_no_cache(mock_log, _mock_get):
    policy = LivePolicy(cache_ttl_ms=60000, fallback_sat_per_kb=9)

    assert policy.current_rate_sat_per_kb() == 9

    assert mock_log.call_count == 1
    args, _ = mock_log.call_args
    assert args[0] == "Failed to fetch live fee rate, using fallback %d sat/kB: %s"
    assert args[1] == 9
    assert isinstance(args[2], requests.RequestException)
    assert str(args[2]) == "boom"


@patch("bsv.fee_models.live_policy.requests.get")
@patch("bsv.fee_models.live_policy.logger.warning")
def test_invalid_response_triggers_fallback(mock_log, mock_get):
    mock_get.return_value = _mock_response({"policy": {"invalid": True}})

    policy = LivePolicy(cache_ttl_ms=60000, fallback_sat_per_kb=3)

    assert policy.current_rate_sat_per_kb() == 3

    assert mock_log.call_count == 1
    args, _ = mock_log.call_args
    assert args[0] == "Failed to fetch live fee rate, using fallback %d sat/kB: %s"
    assert args[1] == 3
    assert isinstance(args[2], ValueError)
    assert str(args[2]) == "Invalid policy response format"


def test_singleton_returns_same_instance():
    first = LivePolicy.get_instance(cache_ttl_ms=10000)
    second = LivePolicy.get_instance(cache_ttl_ms=20000)

    assert first is second
    assert first.cache_ttl_ms == 10000


def test_custom_instance_uses_provided_ttl():
    policy = LivePolicy(cache_ttl_ms=30000)
    assert policy.cache_ttl_ms == 30000


@patch("bsv.fee_models.live_policy.requests.get")
def test_singleton_cache_shared(mock_get):
    payload = {"policy": {"satPerKb": 25}}
    mock_get.return_value = _mock_response(payload)

    policy1 = LivePolicy.get_instance()
    policy2 = LivePolicy.get_instance()

    assert policy1 is policy2
    assert policy1.current_rate_sat_per_kb() == 25
    assert policy2.current_rate_sat_per_kb() == 25
    mock_get.assert_called_once()
