"""
Tests for HeadersClient ported from Go-SDK headers_client_test.go.

These tests use a mock HTTP client to simulate Block Headers Service responses.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from bsv.headers_client import HeadersClient, MerkleRootInfo, Webhook
from bsv.http_client import HttpResponse


class MockHttpClient:
    """Mock HTTP client for testing."""
    
    def __init__(self):
        self.responses = {}
        self.requests = []
    
    def set_response(self, url_pattern, response):
        """Set a response for a URL pattern."""
        self.responses[url_pattern] = response
    
    async def fetch(self, url: str, options: dict) -> HttpResponse:
        """Mock fetch method."""
        self.requests.append({'url': url, 'options': options})
        
        # Find matching response
        for pattern, response in self.responses.items():
            if pattern in url:
                return response
        
        # Default error response
        return HttpResponse(ok=False, status_code=404, json_data={})


class TestHeadersClientGetMerkleRoots:
    """Test GetMerkleRoots method."""
    
    @pytest.mark.asyncio
    async def test_get_merkle_roots_success(self):
        """Test successful retrieval of merkle roots."""
        mock_hash1 = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        mock_hash2 = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
        
        expected_roots = [
            {"merkleRoot": mock_hash1, "blockHeight": 100},
            {"merkleRoot": mock_hash2, "blockHeight": 101},
        ]
        
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/chain/merkleroot",
            HttpResponse(
                ok=True,
                status_code=200,
                json_data={
                    'data': {
                        'content': expected_roots,
                        'page': {'lastEvaluatedKey': ''}
                    }
                }
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        roots = await client.get_merkle_roots(10)
        
        assert len(roots) == 2
        assert roots[0].merkle_root == mock_hash1
        assert roots[0].block_height == 100
        assert roots[1].merkle_root == mock_hash2
        assert roots[1].block_height == 101
        
        # Verify request
        assert len(mock_client.requests) == 1
        assert "batchSize=10" in mock_client.requests[0]['url']
        assert mock_client.requests[0]['options']['headers']['Authorization'] == "Bearer test-api-key"
    
    @pytest.mark.asyncio
    async def test_get_merkle_roots_with_last_evaluated_key(self):
        """Test merkle roots retrieval with pagination."""
        last_key = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/chain/merkleroot",
            HttpResponse(
                ok=True,
                status_code=200,
                json_data={
                    'data': {
                        'content': [],
                        'page': {'lastEvaluatedKey': ''}
                    }
                }
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        roots = await client.get_merkle_roots(10, last_key)
        
        assert len(roots) == 0
        assert len(mock_client.requests) == 1
        assert f"lastEvaluatedKey={last_key}" in mock_client.requests[0]['url']
    
    @pytest.mark.asyncio
    async def test_get_merkle_roots_error(self):
        """Test error handling for merkle roots retrieval."""
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/chain/merkleroot",
            HttpResponse(
                ok=False,
                status_code=500,
                json_data={}
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        
        with pytest.raises(Exception) as exc_info:
            await client.get_merkle_roots(10)
        
        assert "Failed to get merkle roots" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_get_merkle_roots_empty_response(self):
        """Test handling of empty merkle roots response."""
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/chain/merkleroot",
            HttpResponse(
                ok=True,
                status_code=200,
                json_data={
                    'data': {
                        'content': [],
                        'page': {'lastEvaluatedKey': ''}
                    }
                }
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        roots = await client.get_merkle_roots(10)
        
        assert len(roots) == 0
    
    @pytest.mark.asyncio
    async def test_get_merkle_roots_invalid_json(self):
        """Test handling of invalid JSON response."""
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/chain/merkleroot",
            HttpResponse(
                ok=True,
                status_code=200,
                json_data={'invalid': 'json'}
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        
        # Should handle gracefully - return empty list or raise
        roots = await client.get_merkle_roots(10)
        assert isinstance(roots, list)


class TestHeadersClientWebhooks:
    """Test webhook management methods."""
    
    @pytest.mark.asyncio
    async def test_register_webhook_success(self):
        """Test successful webhook registration."""
        expected_webhook = {
            "url": "https://example.com/webhook",
            "createdAt": "2025-09-19T22:27:00Z",
            "lastEmitStatus": "success",
            "lastEmitTimestamp": "2025-09-19T23:00:00Z",
            "errorsCount": 0,
            "active": True,
        }
        
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/webhook",
            HttpResponse(
                ok=True,
                status_code=200,
                json_data={'data': expected_webhook}
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        webhook = await client.register_webhook("https://example.com/webhook", "webhook-auth-token")
        
        assert webhook.url == expected_webhook["url"]
        assert webhook.active == expected_webhook["active"]
        assert webhook.errors_count == expected_webhook["errorsCount"]
        
        # Verify request
        assert len(mock_client.requests) == 1
        request = mock_client.requests[0]
        assert request['options']['method'] == "POST"
        assert request['options']['data']['url'] == "https://example.com/webhook"
        assert request['options']['data']['requiredAuth']['token'] == "webhook-auth-token"
    
    @pytest.mark.asyncio
    async def test_register_webhook_error(self):
        """Test webhook registration error handling."""
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/webhook",
            HttpResponse(
                ok=False,
                status_code=400,
                json_data={'error': 'Invalid webhook URL'}
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        
        with pytest.raises(Exception) as exc_info:
            await client.register_webhook("invalid-url", "token")
        
        assert "failed to register webhook" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_unregister_webhook_success(self):
        """Test successful webhook unregistration."""
        callback_url = "https://example.com/webhook"
        
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/webhook",
            HttpResponse(
                ok=True,
                status_code=200,
                json_data={}
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        await client.unregister_webhook(callback_url)
        
        assert len(mock_client.requests) == 1
        request = mock_client.requests[0]
        assert request['options']['method'] == "DELETE"
        assert f"url={callback_url}" in request['url']
    
    @pytest.mark.asyncio
    async def test_unregister_webhook_error(self):
        """Test webhook unregistration error handling."""
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/webhook",
            HttpResponse(
                ok=False,
                status_code=404,
                json_data={'error': 'Webhook not found'}
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        
        with pytest.raises(Exception) as exc_info:
            await client.unregister_webhook("https://example.com/webhook")
        
        assert "failed to unregister webhook" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_get_webhook_success(self):
        """Test successful webhook retrieval."""
        expected_webhook = {
            "url": "https://example.com/webhook",
            "createdAt": "2025-09-19T22:27:00Z",
            "lastEmitStatus": "success",
            "lastEmitTimestamp": "2025-09-19T23:00:00Z",
            "errorsCount": 0,
            "active": True,
        }
        
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/webhook",
            HttpResponse(
                ok=True,
                status_code=200,
                json_data={'data': expected_webhook}
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        webhook = await client.get_webhook(expected_webhook["url"])
        
        assert webhook.url == expected_webhook["url"]
        assert webhook.active == expected_webhook["active"]
        assert webhook.errors_count == expected_webhook["errorsCount"]
    
    @pytest.mark.asyncio
    async def test_get_webhook_not_found(self):
        """Test webhook retrieval when not found."""
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/webhook",
            HttpResponse(
                ok=False,
                status_code=404,
                json_data={'error': 'Webhook not found'}
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        
        with pytest.raises(Exception) as exc_info:
            await client.get_webhook("https://example.com/webhook")
        
        assert "failed to get webhook" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_webhook_with_multiple_error_counts(self):
        """Test webhook with various error counts."""
        test_cases = [
            {"errorsCount": 0, "lastEmitStatus": "success", "active": True},
            {"errorsCount": 3, "lastEmitStatus": "failed", "active": True},
            {"errorsCount": 10, "lastEmitStatus": "failed", "active": False},
        ]
        
        for tc in test_cases:
            expected_webhook = {
                "url": "https://example.com/webhook",
                "errorsCount": tc["errorsCount"],
                "lastEmitStatus": tc["lastEmitStatus"],
                "active": tc["active"],
            }
            
            mock_client = MockHttpClient()
            mock_client.set_response(
                "/api/v1/webhook",
                HttpResponse(
                    ok=True,
                    status_code=200,
                    json_data={'data': expected_webhook}
                )
            )
            
            client = HeadersClient("http://test.com", "test-api-key", mock_client)
            webhook = await client.get_webhook(expected_webhook["url"])
            
            assert webhook.errors_count == tc["errorsCount"]
            assert webhook.last_emit_status == tc["lastEmitStatus"]
            assert webhook.active == tc["active"]


class TestHeadersClientChainTracker:
    """Test ChainTracker interface implementation."""
    
    @pytest.mark.asyncio
    async def test_is_valid_root_for_height(self):
        """Test merkle root validation."""
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/chain/merkleroot/verify",
            HttpResponse(
                ok=True,
                status_code=200,
                json_data={'data': {'confirmationState': 'CONFIRMED'}}
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        is_valid = await client.is_valid_root_for_height("test_root", 100)
        
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_current_height(self):
        """Test current height retrieval."""
        mock_client = MockHttpClient()
        mock_client.set_response(
            "/api/v1/chain/tip/longest",
            HttpResponse(
                ok=True,
                status_code=200,
                json_data={
                    'data': {
                        'height': 850000,
                        'state': 'LONGEST_CHAIN',
                        'header': {}
                    }
                }
            )
        )
        
        client = HeadersClient("http://test.com", "test-api-key", mock_client)
        height = await client.current_height()
        
        assert height == 850000
    
    @pytest.mark.asyncio
    async def test_implements_chain_tracker_interface(self):
        """Test that HeadersClient implements ChainTracker interface."""
        from bsv.chaintracker import ChainTracker
        
        client = HeadersClient("http://test.com", "test-api-key")
        assert isinstance(client, ChainTracker)
        
        assert hasattr(client, 'is_valid_root_for_height')
        assert hasattr(client, 'current_height')
        assert callable(client.is_valid_root_for_height)
        assert callable(client.current_height)

