"""Tests for ARC broadcaster format selection (json / raw / beef)."""

import unittest
from unittest.mock import AsyncMock, MagicMock

import pytest

from bsv.broadcaster import BroadcastFailure, BroadcastResponse
from bsv.broadcasters.arc import ARC, ARCConfig
from bsv.http_client import HttpClient, HttpResponse, SyncHttpClient


def _make_tx(has_source_txs: bool = True):
    """Create a mock Transaction with controllable source_transaction presence."""
    tx = MagicMock()
    ef_bytes = b"\xef" * 32
    mock_ef = MagicMock()
    mock_ef.hex.return_value = ef_bytes.hex()
    tx.to_ef.return_value = mock_ef
    tx.hex.return_value = "aa" * 32
    tx.serialize.return_value = b"\xaa" * 32
    tx.to_beef.return_value = b"\xbe\xef" * 16

    inp = MagicMock()
    inp.source_transaction = MagicMock() if has_source_txs else None
    tx.inputs = [inp]
    return tx


def _ok_response():
    return HttpResponse(
        ok=True,
        status_code=200,
        json_data={
            "data": {
                "txid": "abcd1234" * 8,
                "txStatus": "SEEN_ON_NETWORK",
            }
        },
    )


# ---------------------------------------------------------------------------
# ARCConfig.format
# ---------------------------------------------------------------------------


class TestARCConfigFormat(unittest.TestCase):
    def test_default_format_is_none(self):
        cfg = ARCConfig()
        assert cfg.format is None

    def test_format_stored(self):
        for fmt in ("json", "raw", "beef"):
            cfg = ARCConfig(format=fmt)
            assert cfg.format == fmt


# ---------------------------------------------------------------------------
# ARC.__init__ format resolution
# ---------------------------------------------------------------------------


class TestARCFormatInit(unittest.TestCase):
    def test_str_config_defaults_to_json(self):
        arc = ARC("https://arc.example.com", "my-api-key")
        assert arc.format == "json"

    def test_no_config_defaults_to_json(self):
        arc = ARC("https://arc.example.com")
        assert arc.format == "json"

    def test_config_none_format_defaults_to_json(self):
        arc = ARC("https://arc.example.com", ARCConfig())
        assert arc.format == "json"

    def test_config_format_propagated(self):
        for fmt in ("json", "raw", "beef"):
            arc = ARC("https://arc.example.com", ARCConfig(format=fmt))
            assert arc.format == fmt


# ---------------------------------------------------------------------------
# async broadcast() – format variations
# ---------------------------------------------------------------------------


class TestBroadcastFormat(unittest.IsolatedAsyncioTestCase):
    async def _broadcast_and_capture(self, fmt, has_source_txs=True):
        mock_http = AsyncMock(HttpClient)
        mock_http.fetch = AsyncMock(return_value=_ok_response())
        cfg = ARCConfig(http_client=mock_http, format=fmt)
        arc = ARC("https://arc.example.com", cfg)
        tx = _make_tx(has_source_txs)
        result = await arc.broadcast(tx)
        call_args = mock_http.fetch.call_args
        url = call_args[0][0]
        options = call_args[0][1]
        return result, url, options, tx

    async def test_json_format_sends_json_body(self):
        result, _, options, _ = await self._broadcast_and_capture("json")
        assert isinstance(result, BroadcastResponse)
        assert options["headers"]["Content-Type"] == "application/json"
        assert "data" in options
        assert "rawTx" in options["data"]
        assert "raw_data" not in options

    async def test_json_format_is_default(self):
        mock_http = AsyncMock(HttpClient)
        mock_http.fetch = AsyncMock(return_value=_ok_response())
        arc = ARC("https://arc.example.com", ARCConfig(http_client=mock_http))
        tx = _make_tx()
        await arc.broadcast(tx)
        options = mock_http.fetch.call_args[0][1]
        assert options["headers"]["Content-Type"] == "application/json"
        assert "data" in options

    async def test_raw_format_sends_binary_ef(self):
        result, _, options, tx = await self._broadcast_and_capture("raw", has_source_txs=True)
        assert isinstance(result, BroadcastResponse)
        assert options["headers"]["Content-Type"] == "application/octet-stream"
        assert options["raw_data"] == tx.to_ef.return_value
        assert "data" not in options
        tx.to_ef.assert_called()

    async def test_raw_format_without_source_txs_falls_back_to_serialize(self):
        result, _, options, tx = await self._broadcast_and_capture("raw", has_source_txs=False)
        assert isinstance(result, BroadcastResponse)
        assert options["headers"]["Content-Type"] == "application/octet-stream"
        assert options["raw_data"] == tx.serialize.return_value
        tx.serialize.assert_called()

    async def test_beef_format_sends_binary_beef(self):
        result, _, options, tx = await self._broadcast_and_capture("beef")
        assert isinstance(result, BroadcastResponse)
        assert options["headers"]["Content-Type"] == "application/beef"
        assert options["raw_data"] == tx.to_beef.return_value
        assert "data" not in options
        tx.to_beef.assert_called()


# ---------------------------------------------------------------------------
# sync_broadcast() – format variations
# ---------------------------------------------------------------------------


class TestSyncBroadcastFormat(unittest.TestCase):
    def _sync_broadcast_and_capture(self, fmt, has_source_txs=True):
        mock_sync = MagicMock(SyncHttpClient)
        mock_sync.fetch = MagicMock(return_value=_ok_response())
        cfg = ARCConfig(sync_http_client=mock_sync, format=fmt)
        arc = ARC("https://arc.example.com", cfg)
        tx = _make_tx(has_source_txs)
        result = arc.sync_broadcast(tx)
        call_args = mock_sync.fetch.call_args
        url = call_args[0][0]
        options = call_args[0][1]
        return result, url, options, tx

    def test_json_format_sends_json_body(self):
        result, _, options, _ = self._sync_broadcast_and_capture("json")
        assert isinstance(result, BroadcastResponse)
        assert options["headers"]["Content-Type"] == "application/json"
        assert "data" in options
        assert "raw_data" not in options

    def test_raw_format_sends_binary_ef(self):
        result, _, options, tx = self._sync_broadcast_and_capture("raw", has_source_txs=True)
        assert isinstance(result, BroadcastResponse)
        assert options["headers"]["Content-Type"] == "application/octet-stream"
        assert options["raw_data"] == tx.to_ef.return_value

    def test_raw_format_without_source_txs_falls_back_to_serialize(self):
        _, _, options, tx = self._sync_broadcast_and_capture("raw", has_source_txs=False)
        assert options["raw_data"] == tx.serialize.return_value

    def test_beef_format_sends_binary_beef(self):
        result, _, options, tx = self._sync_broadcast_and_capture("beef")
        assert isinstance(result, BroadcastResponse)
        assert options["headers"]["Content-Type"] == "application/beef"
        assert options["raw_data"] == tx.to_beef.return_value

    def test_sync_json_default_backward_compat(self):
        mock_sync = MagicMock(SyncHttpClient)
        mock_sync.fetch = MagicMock(return_value=_ok_response())
        arc = ARC("https://arc.example.com", ARCConfig(sync_http_client=mock_sync))
        tx = _make_tx()
        arc.sync_broadcast(tx)
        options = mock_sync.fetch.call_args[0][1]
        assert options["headers"]["Content-Type"] == "application/json"
        assert "rawTx" in options["data"]


# ---------------------------------------------------------------------------
# request_headers() content_type parameter
# ---------------------------------------------------------------------------


class TestRequestHeadersContentType(unittest.TestCase):
    def test_default_content_type(self):
        arc = ARC("https://arc.example.com", ARCConfig(api_key="key"))
        headers = arc.request_headers()
        assert headers["Content-Type"] == "application/json"

    def test_custom_content_type(self):
        arc = ARC("https://arc.example.com", ARCConfig(api_key="key"))
        headers = arc.request_headers(content_type="application/beef")
        assert headers["Content-Type"] == "application/beef"

    def test_api_key_in_headers(self):
        arc = ARC("https://arc.example.com", ARCConfig(api_key="my-key", format="beef"))
        headers = arc.request_headers(content_type="application/beef")
        assert headers["Authorization"] == "Bearer my-key"
        assert headers["Content-Type"] == "application/beef"


# ---------------------------------------------------------------------------
# http_client.py raw_data support (unit-level)
# ---------------------------------------------------------------------------


class TestHttpClientRawData(unittest.TestCase):
    def test_sync_fetch_raw_data_uses_data_kwarg(self):
        """SyncHttpClient.fetch sends raw bytes via data= when raw_data is present."""
        import unittest.mock as um

        from bsv.http_client import SyncHttpClient

        client = SyncHttpClient()
        payload = b"\xbe\xef" * 8
        options = {
            "method": "POST",
            "headers": {"Content-Type": "application/beef"},
            "raw_data": payload,
        }

        with um.patch("bsv.http_client.requests.request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": {"txid": "abc"}}
            mock_req.return_value = mock_resp

            client.fetch("https://example.com/v1/tx", options)

            mock_req.assert_called_once()
            _, kwargs = mock_req.call_args
            assert kwargs["data"] == payload
            assert "json" not in kwargs

    def test_sync_fetch_json_data_unchanged(self):
        """SyncHttpClient.fetch still sends JSON when raw_data is absent."""
        import unittest.mock as um

        from bsv.http_client import SyncHttpClient

        client = SyncHttpClient()
        options = {
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "data": {"rawTx": "aabb"},
        }

        with um.patch("bsv.http_client.requests.request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": {"txid": "abc"}}
            mock_req.return_value = mock_resp

            client.fetch("https://example.com/v1/tx", options)

            _, kwargs = mock_req.call_args
            assert kwargs["json"] == {"rawTx": "aabb"}
            assert "data" not in kwargs or kwargs.get("data") is None


if __name__ == "__main__":
    unittest.main()
