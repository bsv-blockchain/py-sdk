"""The deprecated Arcade names keep working after the rename to BSV Broadcaster."""

import warnings
from unittest.mock import MagicMock

import pytest

from bsv import broadcasters
from bsv.broadcasters import arcade, bsv_broadcaster
from bsv.http_client import HttpResponse, SyncHttpClient

URL = "https://arcade-v2-us-1.bsvblockchain.tech"


def test_arcade_warns_and_is_a_bsv_broadcaster():
    with pytest.warns(DeprecationWarning, match="Use BsvBroadcaster"):
        instance = arcade.Arcade(URL, "my_api_key")
    assert isinstance(instance, bsv_broadcaster.BsvBroadcaster)
    assert instance.URL == URL
    assert instance.request_headers()["Authorization"] == "Bearer my_api_key"


def test_arcade_config_warns_and_is_accepted_by_bsv_broadcaster():
    with pytest.warns(DeprecationWarning, match="Use BsvBroadcasterConfig"):
        config = arcade.ArcadeConfig(callback_url="https://example.com/cb", callback_token="tok123")
    assert isinstance(config, bsv_broadcaster.BsvBroadcasterConfig)
    headers = bsv_broadcaster.BsvBroadcaster(URL, config).request_headers()
    assert headers["X-CallbackUrl"] == "https://example.com/cb"
    assert headers["X-CallbackToken"] == "tok123"


def test_arcade_warning_points_at_caller():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        arcade.Arcade(URL)
    assert caught[0].filename == __file__


def test_bsv_broadcaster_does_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        bsv_broadcaster.BsvBroadcaster(URL, bsv_broadcaster.BsvBroadcasterConfig())


def test_arcade_behaves_like_bsv_broadcaster():
    txid = "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec"
    sync_client = MagicMock(spec=SyncHttpClient)
    sync_client.get.return_value = HttpResponse(
        ok=True, status_code=200, json_data={"data": {"txid": txid, "txStatus": "MINED"}}
    )
    with pytest.warns(DeprecationWarning):
        legacy = arcade.Arcade(URL, arcade.ArcadeConfig(sync_http_client=sync_client))
    assert legacy.check_transaction_status(txid)["txStatus"] == "MINED"


def test_legacy_names_alias_new_ones():
    assert arcade.ARCADE_MINED_TX_STATUSES is bsv_broadcaster.BSV_BROADCASTER_MINED_TX_STATUSES
    assert arcade.ARCADE_PROGRESSING_TX_STATUSES is bsv_broadcaster.BSV_BROADCASTER_PROGRESSING_TX_STATUSES
    assert arcade.ARCADE_SEEN_TX_STATUSES is bsv_broadcaster.BSV_BROADCASTER_SEEN_TX_STATUSES
    assert arcade.ARCADE_TERMINAL_FAILURE_TX_STATUSES is bsv_broadcaster.BSV_BROADCASTER_TERMINAL_FAILURE_TX_STATUSES
    assert arcade.arcade_post_data_indicates_failure is bsv_broadcaster.bsv_broadcaster_post_data_indicates_failure


def test_package_exports_both_names():
    assert broadcasters.BsvBroadcaster is bsv_broadcaster.BsvBroadcaster
    assert broadcasters.BsvBroadcasterConfig is bsv_broadcaster.BsvBroadcasterConfig
    assert broadcasters.Arcade is arcade.Arcade
    assert broadcasters.ArcadeConfig is arcade.ArcadeConfig
