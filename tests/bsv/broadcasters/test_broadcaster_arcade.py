import unittest
from unittest.mock import AsyncMock, MagicMock

import pytest

from bsv.broadcaster import BroadcastFailure, BroadcastResponse
from bsv.broadcasters.arcade import (
    ARCADE_MINED_TX_STATUSES,
    ARCADE_PROGRESSING_TX_STATUSES,
    ARCADE_SEEN_TX_STATUSES,
    ARCADE_TERMINAL_FAILURE_TX_STATUSES,
    Arcade,
    ArcadeConfig,
    arcade_post_data_indicates_failure,
)
from bsv.http_client import HttpClient, HttpResponse, SyncHttpClient
from bsv.transaction import Transaction

TXID = "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec"


class TestArcadeBroadcast(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.URL = "https://arcade-v2-us-1.bsvblockchain.tech"
        self.tx = Transaction(tx_data="Hello Arcade")
        self.tx.hex = MagicMock(return_value="hexFormat")

    def _arcade(self, mock_http_client=None, mock_sync_http_client=None) -> Arcade:
        config = ArcadeConfig(
            http_client=mock_http_client,
            sync_http_client=mock_sync_http_client,
        )
        return Arcade(self.URL, config)

    async def test_broadcast_success_202_received(self):
        """Arcade's 202 submit response: {"txid", "status": 202, "txStatus": "RECEIVED"}."""
        mock_response = HttpResponse(
            ok=True,
            status_code=202,
            json_data={"data": {"txid": TXID, "status": 202, "txStatus": "RECEIVED"}},
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        result = await self._arcade(mock_http_client).broadcast(self.tx)

        self.assertIsInstance(result, BroadcastResponse)
        self.assertEqual(result.txid, TXID)
        self.assertEqual(result.message, "RECEIVED")
        # Endpoint must be root-level /tx (no /v1 prefix)
        called_url = mock_http_client.fetch.call_args[0][0]
        self.assertEqual(called_url, f"{self.URL}/tx")

    async def test_broadcast_duplicate_submit_mined_is_success(self):
        """Idempotent re-submit returns 202 with the existing status."""
        mock_response = HttpResponse(
            ok=True,
            status_code=202,
            json_data={"data": {"txid": TXID, "status": 202, "txStatus": "MINED"}},
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        result = await self._arcade(mock_http_client).broadcast(self.tx)

        self.assertIsInstance(result, BroadcastResponse)
        self.assertEqual(result.message, "MINED")

    async def test_broadcast_duplicate_submit_rejected_is_failure(self):
        """202 with terminal txStatus (re-submit of a rejected tx) must be a failure."""
        mock_response = HttpResponse(
            ok=True,
            status_code=202,
            json_data={"data": {"txid": TXID, "status": 202, "txStatus": "REJECTED"}},
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        result = await self._arcade(mock_http_client).broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "ARCADE_TX_STATUS")
        self.assertIn("REJECTED", result.description)
        self.assertEqual(result.txid, TXID)

    async def test_broadcast_double_spend_is_failure(self):
        """DOUBLE_SPEND_ATTEMPTED is terminal in Arcade (unlike ARC)."""
        mock_response = HttpResponse(
            ok=True,
            status_code=202,
            json_data={"data": {"txid": TXID, "status": 202, "txStatus": "DOUBLE_SPEND_ATTEMPTED"}},
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        result = await self._arcade(mock_http_client).broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertIn("DOUBLE_SPEND_ATTEMPTED", result.description)

    async def test_broadcast_400_terminal_validation_failure(self):
        """Arcade's 400 body is flat {"error", "reason"} and terminal."""
        mock_response = HttpResponse(
            ok=False,
            status_code=400,
            json_data={"data": {"error": "transaction failed validation", "reason": "missing inputs"}},
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        result = await self._arcade(mock_http_client).broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "400")
        self.assertEqual(result.description, "transaction failed validation: missing inputs")
        self.assertTrue(result.more.get("terminal"))

    async def test_broadcast_503_backpressure(self):
        mock_response = HttpResponse(
            ok=False,
            status_code=503,
            json_data={"data": {"error": "service overloaded, retry shortly"}},
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        result = await self._arcade(mock_http_client).broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "503")
        self.assertEqual(result.description, "Failed to connect to Arcade service")

    async def test_broadcast_exception(self):
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(side_effect=Exception("Internal Error"))

        result = await self._arcade(mock_http_client).broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "500")
        self.assertEqual(result.description, "Internal Error")

    async def test_broadcast_sends_raw_hex_when_source_txs_missing(self):
        """Without source transactions, the body falls back to plain raw hex."""
        mock_response = HttpResponse(
            ok=True,
            status_code=202,
            json_data={"data": {"txid": TXID, "status": 202, "txStatus": "RECEIVED"}},
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        input_without_source = MagicMock()
        input_without_source.source_transaction = None
        self.tx.inputs = [input_without_source]

        await self._arcade(mock_http_client).broadcast(self.tx)

        request_options = mock_http_client.fetch.call_args[0][1]
        self.assertEqual(request_options["data"], {"rawTx": "hexFormat"})

    def test_sync_broadcast_success(self):
        mock_response = HttpResponse(
            ok=True,
            status_code=202,
            json_data={"data": {"txid": TXID, "status": 202, "txStatus": "RECEIVED"}},
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.fetch = MagicMock(return_value=mock_response)

        result = self._arcade(mock_sync_http_client=mock_sync_http_client).sync_broadcast(self.tx)

        self.assertIsInstance(result, BroadcastResponse)
        self.assertEqual(result.txid, TXID)
        self.assertEqual(result.message, "RECEIVED")

    def test_sync_broadcast_timeout_error(self):
        mock_response = HttpResponse(ok=False, status_code=408, json_data={"data": {"error": "request timed out"}})
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.fetch = MagicMock(return_value=mock_response)

        result = self._arcade(mock_sync_http_client=mock_sync_http_client).sync_broadcast(self.tx, timeout=5)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "408")
        self.assertEqual(result.description, "Transaction broadcast timed out after 5 seconds")

    def test_sync_broadcast_exception(self):
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.fetch = MagicMock(side_effect=Exception("Internal Error"))

        result = self._arcade(mock_sync_http_client=mock_sync_http_client).sync_broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "500")

    def test_check_transaction_status_mined_with_merkle_path(self):
        mock_response = HttpResponse(
            ok=True,
            status_code=200,
            json_data={
                "data": {
                    "txid": TXID,
                    "txStatus": "MINED",
                    "blockHash": "000000000000000001234567890abcdef",
                    "blockHeight": 800000,
                    "merklePath": "fe8a6a0c000c04fde80b",
                }
            },
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.get = MagicMock(return_value=mock_response)

        arcade = self._arcade(mock_sync_http_client=mock_sync_http_client)
        result = arcade.check_transaction_status(TXID)

        self.assertEqual(result["txid"], TXID)
        self.assertEqual(result["txStatus"], "MINED")
        self.assertEqual(result["blockHeight"], 800000)
        self.assertEqual(result["merklePath"], "fe8a6a0c000c04fde80b")
        # Endpoint must be root-level /tx/{txid} (no /v1 prefix)
        called_url = mock_sync_http_client.get.call_args[0][0]
        self.assertEqual(called_url, f"{self.URL}/tx/{TXID}")

    def test_check_transaction_status_not_found(self):
        mock_response = HttpResponse(
            ok=False,
            status_code=404,
            json_data={"data": {"error": "transaction not found"}},
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.get = MagicMock(return_value=mock_response)

        arcade = self._arcade(mock_sync_http_client=mock_sync_http_client)
        result = arcade.check_transaction_status(TXID)

        self.assertEqual(result["status"], "failure")
        self.assertEqual(result["code"], 404)
        self.assertEqual(result["detail"], "transaction not found")

    def test_api_key_string_config(self):
        arcade = Arcade(self.URL, "my_api_key")
        headers = arcade.request_headers()
        self.assertEqual(headers["Authorization"], "Bearer my_api_key")

    def test_callback_headers(self):
        config = ArcadeConfig(callback_url="https://example.com/cb", callback_token="tok123")
        arcade = Arcade(self.URL, config)
        headers = arcade.request_headers()
        self.assertEqual(headers["X-CallbackUrl"], "https://example.com/cb")
        self.assertEqual(headers["X-CallbackToken"], "tok123")


CATEGORIZE_CASES = [
    # (txStatus, extra_fields, expected_category)
    *[(s, {}, "progressing") for s in sorted(ARCADE_PROGRESSING_TX_STATUSES)],
    *[(s, {}, "rejected") for s in sorted(ARCADE_TERMINAL_FAILURE_TX_STATUSES)],
    *[(s, {}, "mined") for s in sorted(ARCADE_MINED_TX_STATUSES)],
    *[(s, {}, "0confirmation") for s in sorted(ARCADE_SEEN_TX_STATUSES)],
    *[(s, {"competingTxs": ["abc"]}, "warning") for s in sorted(ARCADE_SEEN_TX_STATUSES)],
    ("FUTURE_STATUS", {}, "unknown_txStatus"),
]


@pytest.mark.parametrize(
    ("tx_status", "extra_fields", "expected_category"),
    CATEGORIZE_CASES,
    ids=[f"{s}-{cat}" for s, _, cat in CATEGORIZE_CASES],
)
def test_categorize_transaction_status_mapping(tx_status, extra_fields, expected_category):
    response = {"txStatus": tx_status, **extra_fields}
    result = Arcade.categorize_transaction_status(response)
    assert result["status_category"] == expected_category
    assert result["tx_status"] == tx_status


POST_FAILURE_CASES = [
    *[(s, True) for s in sorted(ARCADE_TERMINAL_FAILURE_TX_STATUSES)],
    *[(s, False) for s in sorted(ARCADE_PROGRESSING_TX_STATUSES)],
    *[(s, False) for s in sorted(ARCADE_SEEN_TX_STATUSES)],
    *[(s, False) for s in sorted(ARCADE_MINED_TX_STATUSES)],
]


@pytest.mark.parametrize(
    ("tx_status", "should_fail"),
    POST_FAILURE_CASES,
    ids=[f"{s}-{'fail' if f else 'ok'}" for s, f in POST_FAILURE_CASES],
)
def test_arcade_post_data_indicates_failure_mapping(tx_status, should_fail):
    data = {"txid": "aabbccdd", "txStatus": tx_status}
    result = arcade_post_data_indicates_failure(data)
    if should_fail:
        assert result is not None
        assert tx_status in result
    else:
        assert result is None


if __name__ == "__main__":
    unittest.main()
