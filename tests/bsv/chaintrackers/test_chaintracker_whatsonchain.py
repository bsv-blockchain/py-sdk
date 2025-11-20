import pytest
from unittest.mock import AsyncMock, MagicMock
from bsv.chaintrackers import WhatsOnChainTracker
from bsv.http_client import HttpClient


class TestWhatsOnChainTracker:
    def setup_method(self):
        self.mock_http_client = AsyncMock(HttpClient)
        self.tracker = WhatsOnChainTracker(
            network="main",
            http_client=self.mock_http_client
        )

    @pytest.mark.asyncio
    async def test_is_valid_root_for_height_success(self):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.status_code = 200
        mock_response.json = lambda: {"data": {"merkleroot": "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4"}}
        self.mock_http_client.fetch = AsyncMock(return_value=mock_response)

        # Test with matching merkle root
        result = await self.tracker.is_valid_root_for_height(
            "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4",
            813706

        )
        assert result is True

        # Verify API call
        self.mock_http_client.fetch.assert_called_once_with(
            "https://api.whatsonchain.com/v1/bsv/main/block/813706/header",
            {"method": "GET", "headers": {}}
        )

    @pytest.mark.asyncio
    async def test_is_valid_root_for_height_mismatch(self):
        # Setup mock response with different merkle root
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.status_code = 200
        mock_response.json = lambda: {"data": {"merkleroot": "different_merkle_root"}}
        self.mock_http_client.fetch = AsyncMock(return_value=mock_response)

        # Test with non-matching merkle root
        result = await self.tracker.is_valid_root_for_height(
            "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4",
            813706
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_is_valid_root_for_height_not_found(self):
        # Setup mock 404 response
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_response.json = lambda: {"error": "Block not found"}
        self.mock_http_client.fetch = AsyncMock(return_value=mock_response)

        # Test with non-existent block height
        result = await self.tracker.is_valid_root_for_height(
            "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4",
            999999999
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_is_valid_root_for_height_error(self):
        # Setup mock error response
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 500
        mock_response.json = lambda: {"error": "Internal server error"}
        self.mock_http_client.fetch = AsyncMock(return_value=mock_response)

        # Test server error handling
        with pytest.raises(RuntimeError, match=r"Failed to verify merkleroot.*"):
            await self.tracker.is_valid_root_for_height(
                "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4",
                813706
            )

    def test_query_tx_success(self):
        # Test successful transaction query
        result = self.tracker.query_tx(
            "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4"
        )
        assert isinstance(result, dict)
        assert "known" in result

    def test_query_tx_with_api_key(self):
        # Test with API key
        tracker = WhatsOnChainTracker(
            network="main",
            api_key="test_api_key",  # noqa: S106  # NOSONAR - Mock API key for tests
            http_client=self.mock_http_client
        )
        result = tracker.query_tx(
            "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4",
            api_key="override_key"
        )
        assert isinstance(result, dict)
        assert "known" in result

    def test_query_tx_network_error(self):
        import requests
        # Test network error handling
        def mock_get(*args, **kwargs):
            raise requests.exceptions.RequestException("Connection error")

        import requests
        original_get = requests.get
        requests.get = mock_get
        try:
            result = self.tracker.query_tx(
                "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4",
                timeout=1
            )
            assert isinstance(result, dict)
            assert "known" in result
            assert not result["known"]
            assert "error" in result
            assert "Connection error" in result["error"]
        finally:
            requests.get = original_get

    def test_get_headers_with_api_key(self):
        # Test header generation with API key
        tracker = WhatsOnChainTracker(
            network="main",
            api_key="test_api_key"
        )
        headers = tracker.get_headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == "test_api_key"

    def test_get_headers_without_api_key(self):
        # Test header generation without API key
        tracker = WhatsOnChainTracker(network="main")
        headers = tracker.get_headers()
        assert isinstance(headers, dict)
        assert len(headers) == 0

    def test_network_validation(self):
        # Test valid networks
        WhatsOnChainTracker(network="main")
        WhatsOnChainTracker(network="test")
        WhatsOnChainTracker(network="mainnet")  # Should be converted to "main"
        WhatsOnChainTracker(network="testnet")  # Should be converted to "test"