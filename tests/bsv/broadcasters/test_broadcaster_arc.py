import os
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from bsv.broadcaster import BroadcastFailure, BroadcastResponse
from bsv.broadcasters.arc import (
    ARC,
    ARC_PROGRESSING_TX_STATUSES,
    ARC_TERMINAL_FAILURE_TX_STATUSES,
    ARC_WARNING_TX_STATUSES,
    ARCConfig,
    arc_post_data_indicates_failure,
)
from bsv.http_client import HttpClient, HttpResponse, SyncHttpClient
from bsv.transaction import Transaction


# Load environment variables from .env.local
def load_env_file():
    """Load environment variables from .env.local file if it exists."""
    env_file = Path(__file__).parent.parent.parent.parent / ".env.local"
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip()


load_env_file()


class TestARCBroadcast(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.URL = "https://api.taal.com/arc"
        self.api_key = os.getenv("ARC_API_KEY", "test_api_key_fallback")
        self.tx = Transaction(tx_data="Hello sCrypt")

        # Mocking the Transaction methods
        self.tx.hex = MagicMock(return_value="hexFormat")

    async def test_broadcast_success(self):
        mock_response = HttpResponse(
            ok=True,
            status_code=200,
            json_data={
                "data": {
                    "txid": "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec",
                    "txStatus": "success",
                    "extraInfo": "extra",
                }
            },
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        arc_config = ARCConfig(api_key=self.api_key, http_client=mock_http_client)
        arc = ARC(self.URL, arc_config)
        result = await arc.broadcast(self.tx)

        self.assertIsInstance(result, BroadcastResponse)
        self.assertEqual(
            result.txid,
            "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec",
        )
        self.assertEqual(result.message, "success extra")

    async def test_broadcast_rejected_txstatus_returns_failure(self):
        """HTTP 200 with txid but REJECTED must be BroadcastFailure (not success)."""
        mock_response = HttpResponse(
            ok=True,
            status_code=200,
            json_data={
                "data": {
                    "txid": "e64bb274027e58a5b2fff2852cabe5c2f8aebe1b70225bb37c17a9b346a97086",
                    "txStatus": "REJECTED",
                    "extraInfo": "double spend attempted",
                }
            },
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        arc_config = ARCConfig(api_key=self.api_key, http_client=mock_http_client)
        arc = ARC(self.URL, arc_config)
        result = await arc.broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "ARC_TX_STATUS")
        self.assertIn("REJECTED", result.description)
        self.assertEqual(result.txid, "e64bb274027e58a5b2fff2852cabe5c2f8aebe1b70225bb37c17a9b346a97086")

    async def test_broadcast_failure(self):
        mock_response = HttpResponse(
            ok=False,
            status_code=400,
            json_data={"data": {"status": "ERR_BAD_REQUEST", "detail": "Invalid transaction"}},
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        arc_config = ARCConfig(api_key=self.api_key, http_client=mock_http_client)
        arc = ARC(self.URL, arc_config)
        result = await arc.broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "400")
        self.assertEqual(result.description, "Invalid transaction")

    async def test_broadcast_exception(self):
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(side_effect=Exception("Internal Error"))

        arc_config = ARCConfig(api_key=self.api_key, http_client=mock_http_client)
        arc = ARC(self.URL, arc_config)
        result = await arc.broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "500")
        self.assertEqual(result.description, "Internal Error")

    def test_sync_broadcast_rejected_txstatus_returns_failure(self):
        mock_response = HttpResponse(
            ok=True,
            status_code=200,
            json_data={
                "data": {
                    "txid": "e64bb274027e58a5b2fff2852cabe5c2f8aebe1b70225bb37c17a9b346a97086",
                    "txStatus": "REJECTED",
                    "extraInfo": "double spend attempted",
                }
            },
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.fetch = MagicMock(return_value=mock_response)

        arc_config = ARCConfig(api_key=self.api_key, sync_http_client=mock_sync_http_client)
        arc = ARC(self.URL, arc_config)
        result = arc.sync_broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "ARC_TX_STATUS")

    def test_sync_broadcast_success(self):
        mock_response = HttpResponse(
            ok=True,
            status_code=200,
            json_data={
                "data": {
                    "txid": "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec",
                    "txStatus": "success",
                    "extraInfo": "extra",
                }
            },
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.fetch = MagicMock(return_value=mock_response)  # fetch → post

        arc_config = ARCConfig(api_key=self.api_key, sync_http_client=mock_sync_http_client)
        arc = ARC(self.URL, arc_config)
        result = arc.sync_broadcast(self.tx)

        self.assertIsInstance(result, BroadcastResponse)
        self.assertEqual(
            result.txid,
            "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec",
        )
        self.assertEqual(result.message, "success extra")

    def test_sync_broadcast_failure(self):
        mock_response = HttpResponse(
            ok=False,
            status_code=400,
            json_data={"data": {"status": "ERR_BAD_REQUEST", "detail": "Invalid transaction"}},
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.fetch = MagicMock(return_value=mock_response)  # fetch → post

        arc_config = ARCConfig(api_key=self.api_key, sync_http_client=mock_sync_http_client)
        arc = ARC(self.URL, arc_config)
        result = arc.sync_broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "400")
        self.assertEqual(result.description, "Invalid transaction")

    def test_sync_broadcast_timeout_error(self):
        """408 time out error test"""
        mock_response = HttpResponse(
            ok=False, status_code=408, json_data={"data": {"status": "ERR_TIMEOUT", "detail": "Request timed out"}}
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.fetch = MagicMock(return_value=mock_response)

        arc_config = ARCConfig(api_key=self.api_key, sync_http_client=mock_sync_http_client)
        arc = ARC(self.URL, arc_config)
        result = arc.sync_broadcast(self.tx, timeout=5)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.status, "failure")
        self.assertEqual(result.code, "408")
        self.assertEqual(result.description, "Transaction broadcast timed out after 5 seconds")

    def test_sync_broadcast_connection_error(self):
        """503 error test"""
        mock_response = HttpResponse(
            ok=False, status_code=503, json_data={"data": {"status": "ERR_CONNECTION", "detail": "Service unavailable"}}
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.fetch = MagicMock(return_value=mock_response)

        arc_config = ARCConfig(api_key=self.api_key, sync_http_client=mock_sync_http_client)
        arc = ARC(self.URL, arc_config)
        result = arc.sync_broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.status, "failure")
        self.assertEqual(result.code, "503")
        self.assertEqual(result.description, "Failed to connect to ARC service")

    def test_sync_broadcast_exception(self):
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.fetch = MagicMock(side_effect=Exception("Internal Error"))

        arc_config = ARCConfig(api_key=self.api_key, sync_http_client=mock_sync_http_client)
        arc = ARC(self.URL, arc_config)
        result = arc.sync_broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "500")
        self.assertEqual(result.description, "Internal Error")

    def test_check_transaction_status_success(self):
        mock_response = HttpResponse(
            ok=True,
            status_code=200,
            json_data={
                "data": {  # dataキーを追加
                    "txid": "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec",
                    "txStatus": "MINED",
                    "blockHash": "000000000000000001234567890abcdef",
                    "blockHeight": 800000,
                }
            },
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.get = MagicMock(return_value=mock_response)  # fetch → get

        arc_config = ARCConfig(api_key=self.api_key, sync_http_client=mock_sync_http_client)
        arc = ARC(self.URL, arc_config)
        result = arc.check_transaction_status("8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec")

        self.assertEqual(result["txid"], "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec")
        self.assertEqual(result["txStatus"], "MINED")
        self.assertEqual(result["blockHeight"], 800000)

    def test_categorize_transaction_status_mined(self):
        response = {"txStatus": "MINED", "blockHeight": 800000}
        result = ARC.categorize_transaction_status(response)

        self.assertEqual(result["status_category"], "mined")
        self.assertEqual(result["tx_status"], "MINED")

    def test_categorize_transaction_status_progressing(self):
        response = {"txStatus": "QUEUED"}
        result = ARC.categorize_transaction_status(response)

        self.assertEqual(result["status_category"], "progressing")
        self.assertEqual(result["tx_status"], "QUEUED")

    def test_categorize_transaction_status_warning(self):
        response = {"txStatus": "SEEN_ON_NETWORK", "competingTxs": ["some_competing_tx"]}
        result = ARC.categorize_transaction_status(response)

        self.assertEqual(result["status_category"], "warning")
        self.assertEqual(result["tx_status"], "SEEN_ON_NETWORK")

    def test_categorize_transaction_status_0confirmation(self):
        response = {"txStatus": "SEEN_ON_NETWORK"}
        result = ARC.categorize_transaction_status(response)

        self.assertEqual(result["status_category"], "0confirmation")
        self.assertEqual(result["tx_status"], "SEEN_ON_NETWORK")

    def test_categorize_transaction_status_unknown_uses_stable_category(self):
        response = {"txStatus": "FUTURE_STATUS"}
        result = ARC.categorize_transaction_status(response)

        self.assertEqual(result["status_category"], "unknown_txStatus")
        self.assertEqual(result["tx_status"], "FUTURE_STATUS")

    def test_arc_post_data_indicates_failure_rejected(self):
        d = {
            "txid": "e64bb274027e58a5b2fff2852cabe5c2f8aebe1b70225bb37c17a9b346a97086",
            "txStatus": "REJECTED",
            "extraInfo": "double spend attempted",
        }
        self.assertIsNotNone(arc_post_data_indicates_failure(d))

    def test_arc_post_data_indicates_failure_none_when_minimal_ok(self):
        d = {"txid": "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec"}
        self.assertIsNone(arc_post_data_indicates_failure(d))


CATEGORIZE_CASES = [
    # (txStatus, extra_fields, expected_category)
    # --- progressing ---
    *[(s, {}, "progressing") for s in sorted(ARC_PROGRESSING_TX_STATUSES)],
    # --- terminal failure → rejected ---
    *[(s, {}, "rejected") for s in sorted(ARC_TERMINAL_FAILURE_TX_STATUSES)],
    # --- warning (plain) ---
    *[(s, {}, "warning") for s in sorted(ARC_WARNING_TX_STATUSES)],
    # --- SEEN_ON_NETWORK variants ---
    ("SEEN_ON_NETWORK", {}, "0confirmation"),
    ("SEEN_ON_NETWORK", {"competingTxs": ["abc"]}, "warning"),
    # --- mined ---
    ("MINED", {}, "mined"),
]


@pytest.mark.parametrize(
    ("tx_status", "extra_fields", "expected_category"),
    CATEGORIZE_CASES,
    ids=[f"{s}-{cat}" for s, _, cat in CATEGORIZE_CASES],
)
def test_categorize_transaction_status_mapping(tx_status, extra_fields, expected_category):
    response = {"txStatus": tx_status, **extra_fields}
    result = ARC.categorize_transaction_status(response)
    assert result["status_category"] == expected_category
    assert result["tx_status"] == tx_status


POST_FAILURE_CASES = [
    # (txStatus, should_indicate_failure)
    *[(s, True) for s in sorted(ARC_TERMINAL_FAILURE_TX_STATUSES)],
    *[(s, False) for s in sorted(ARC_PROGRESSING_TX_STATUSES)],
    *[(s, False) for s in sorted(ARC_WARNING_TX_STATUSES)],
    ("SEEN_ON_NETWORK", False),
    ("MINED", False),
]


@pytest.mark.parametrize(
    ("tx_status", "should_fail"),
    POST_FAILURE_CASES,
    ids=[f"{s}-{'fail' if f else 'ok'}" for s, f in POST_FAILURE_CASES],
)
def test_arc_post_data_indicates_failure_mapping(tx_status, should_fail):
    data = {"txid": "aabbccdd", "txStatus": tx_status}
    result = arc_post_data_indicates_failure(data)
    if should_fail:
        assert result is not None
        assert tx_status in result
    else:
        assert result is None


if __name__ == "__main__":
    unittest.main()
