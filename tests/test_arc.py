import unittest
from unittest.mock import AsyncMock, MagicMock

from bsv.broadcaster import BroadcastResponse, BroadcastFailure
from bsv.broadcasters.arc import ARC, ARCConfig
from bsv.http_client import HttpClient, HttpResponse, SyncHttpClient
from bsv.transaction import Transaction


class TestARCBroadcast(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.URL = "https://api.taal.com/arc"
        self.api_key = "apikey_85678993923y454i4jhd803wsd02"
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

    async def test_broadcast_failure(self):
        mock_response = HttpResponse(
            ok=False,
            status_code=400,
            json_data={
                "data": {"status": "ERR_BAD_REQUEST", "detail": "Invalid transaction"}
            },
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
        mock_sync_http_client.post = MagicMock(return_value=mock_response)  # fetch → post

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
            json_data={
                "data": {"status": "ERR_BAD_REQUEST", "detail": "Invalid transaction"}
            },
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.post = MagicMock(return_value=mock_response)  # fetch → post

        arc_config = ARCConfig(api_key=self.api_key, sync_http_client=mock_sync_http_client)
        arc = ARC(self.URL, arc_config)
        result = arc.sync_broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "400")
        self.assertEqual(result.description, "Invalid transaction")

    def test_sync_broadcast_timeout_error(self):
        """408 time out error test"""
        mock_response = HttpResponse(
            ok=False,
            status_code=408,
            json_data={"data": {"status": "ERR_TIMEOUT", "detail": "Request timed out"}}
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.post = MagicMock(return_value=mock_response)

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
            ok=False,
            status_code=503,
            json_data={"data": {"status": "ERR_CONNECTION", "detail": "Service unavailable"}}
        )
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.post = MagicMock(return_value=mock_response)

        arc_config = ARCConfig(api_key=self.api_key, sync_http_client=mock_sync_http_client)
        arc = ARC(self.URL, arc_config)
        result = arc.sync_broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.status, "failure")
        self.assertEqual(result.code, "503")
        self.assertEqual(result.description, "Failed to connect to ARC service")

    def test_sync_broadcast_exception(self):
        mock_sync_http_client = MagicMock(SyncHttpClient)
        mock_sync_http_client.post = MagicMock(side_effect=Exception("Internal Error"))

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
                    "blockHeight": 800000
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
        response = {
            "txStatus": "MINED",
            "blockHeight": 800000
        }
        result = ARC.categorize_transaction_status(response)

        self.assertEqual(result["status_category"], "mined")
        self.assertEqual(result["tx_status"], "MINED")

    def test_categorize_transaction_status_progressing(self):
        response = {
            "txStatus": "QUEUED"
        }
        result = ARC.categorize_transaction_status(response)

        self.assertEqual(result["status_category"], "progressing")
        self.assertEqual(result["tx_status"], "QUEUED")

    def test_categorize_transaction_status_warning(self):
        response = {
            "txStatus": "SEEN_ON_NETWORK",
            "competingTxs": ["some_competing_tx"]
        }
        result = ARC.categorize_transaction_status(response)

        self.assertEqual(result["status_category"], "warning")
        self.assertEqual(result["tx_status"], "SEEN_ON_NETWORK")

    def test_categorize_transaction_status_0confirmation(self):
        response = {
            "txStatus": "SEEN_ON_NETWORK"
        }
        result = ARC.categorize_transaction_status(response)

        self.assertEqual(result["status_category"], "0confirmation")
        self.assertEqual(result["tx_status"], "SEEN_ON_NETWORK")


if __name__ == "__main__":
    unittest.main()