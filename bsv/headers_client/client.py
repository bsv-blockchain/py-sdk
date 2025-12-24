"""
HeadersClient implementation for Block Headers Service.

This client provides methods to interact with a Block Headers Service (BHS)
for verifying merkle roots, retrieving block headers, and managing webhooks.

Ported from Go-SDK's transaction/chaintracker/headers_client/headers_client.go
"""

from typing import Optional, List
from bsv.http_client import HttpClient, default_http_client
from bsv.chaintracker import ChainTracker
from .types import Header, State, MerkleRootInfo, Webhook, WebhookRequest, RequiredAuth


class HeadersClientError(Exception):
    """Base exception for HeadersClient errors."""
    pass


class MerkleRootVerificationError(HeadersClientError):
    """Exception raised when merkle root verification fails."""
    pass


class HeaderRetrievalError(HeadersClientError):
    """Exception raised when header retrieval fails."""
    pass


class WebhookError(HeadersClientError):
    """Exception raised when webhook operations fail."""
    pass


class ChainTipError(HeadersClientError):
    """Exception raised when chain tip retrieval fails."""
    pass


class HeadersClient(ChainTracker):
    """
    Client for interacting with Block Headers Service (BHS).
    
    This client implements the ChainTracker interface and provides additional
    methods for querying blockchain headers and managing webhooks.
    
    Example:
        >>> client = HeadersClient("https://api.example.com", "api-key")
        >>> is_valid = await client.is_valid_root_for_height("merkle_root", 100)
        >>> height = await client.current_height()
    """
    
    def __init__(
        self,
        url: str,
        api_key: str,
        http_client: Optional[HttpClient] = None
    ):
        """
        Initialize HeadersClient.
        
        Args:
            url: Base URL of the Block Headers Service
            api_key: API key for authentication
            http_client: Optional HTTP client (defaults to DefaultHttpClient)
        """
        self.url = url.rstrip('/')
        self.api_key = api_key
        self._http_client = http_client or default_http_client()
    
    def _get_headers(self) -> dict:
        """Get default headers with authorization."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
    
    async def is_valid_root_for_height(self, root: str, height: int) -> bool:
        """
        Verify if a merkle root is valid for a given block height.
        
        This method implements ChainTracker.is_valid_root_for_height().
        
        Args:
            root: Merkle root to verify
            height: Block height to verify against
            
        Returns:
            True if merkle root is confirmed, False otherwise
            
        Raises:
            Exception: If the request fails or response is invalid
        """
        url = f"{self.url}/api/v1/chain/merkleroot/verify"
        payload = [{
            "merkleRoot": root,
            "blockHeight": height
        }]
        
        options = {
            "method": "POST",
            "headers": self._get_headers(),
            "data": payload,
        }
        
        response = await self._http_client.fetch(url, options)
        
        if not response.ok:
            raise MerkleRootVerificationError(f"Failed to verify merkle root: status={response.status_code}")
        
        data = response.json()
        # Handle both wrapped and unwrapped responses
        if 'data' in data:
            confirmation_state = data['data'].get('confirmationState', '')
        else:
            confirmation_state = data.get('confirmationState', '')
        
        return confirmation_state == "CONFIRMED"
    
    async def current_height(self) -> int:
        """
        Get the current blockchain height.
        
        This method implements ChainTracker.current_height().
        
        Returns:
            Current blockchain height
            
        Raises:
            Exception: If unable to retrieve height
        """
        tip = await self.get_chaintip()
        return tip.height
    
    async def block_by_height(self, height: int) -> Header:
        """
        Get block header by height.
        
        Args:
            height: Block height to retrieve
            
        Returns:
            Header object for the block
            
        Raises:
            Exception: If block not found or request fails
        """
        url = f"{self.url}/api/v1/chain/header/byHeight?height={height}"
        options = {
            "method": "GET",
            "headers": self._get_headers(),
        }
        
        response = await self._http_client.fetch(url, options)
        
        if not response.ok:
            raise HeaderRetrievalError(f"Failed to get block by height: status={response.status_code}")
        
        data = response.json()
        headers_data = data.get('data', []) if 'data' in data else data
        
        if not headers_data:
            raise HeaderRetrievalError(f"no block headers found for height {height}")
        
        # Try to find header with LONGEST_CHAIN state
        for header_data in headers_data:
            try:
                block_hash = header_data.get('hash', '')
                if block_hash:
                    state = await self.get_block_state(block_hash)
                    if state.state == "LONGEST_CHAIN":
                        return Header(
                            height=state.height,
                            hash=block_hash,
                            version=header_data.get('version', 0),
                            merkle_root=header_data.get('merkleroot', ''),
                            timestamp=header_data.get('creationTimestamp', 0),
                            bits=header_data.get('difficultyTarget', 0),
                            nonce=header_data.get('nonce', 0),
                            previous_block=header_data.get('prevBlockHash', ''),
                        )
            except Exception:
                continue
        
        # Fallback to first header
        header_data = headers_data[0]
        return Header(
            height=height,
            hash=header_data.get('hash', ''),
            version=header_data.get('version', 0),
            merkle_root=header_data.get('merkleroot', ''),
            timestamp=header_data.get('creationTimestamp', 0),
            bits=header_data.get('difficultyTarget', 0),
            nonce=header_data.get('nonce', 0),
            previous_block=header_data.get('prevBlockHash', ''),
        )
    
    async def get_block_state(self, hash: str) -> State:
        """
        Get block state by hash.
        
        Args:
            hash: Block hash
            
        Returns:
            State object for the block
            
        Raises:
            Exception: If block not found or request fails
        """
        url = f"{self.url}/api/v1/chain/header/state/{hash}"
        options = {
            "method": "GET",
            "headers": self._get_headers(),
        }
        
        response = await self._http_client.fetch(url, options)
        
        if not response.ok:
            raise HeaderRetrievalError(f"Failed to get block state: status={response.status_code}")
        
        data = response.json()
        state_data = data.get('data', {}) if 'data' in data else data
        
        header_data = state_data.get('header', {})
        return State(
            header=Header(
                height=header_data.get('height', 0),
                hash=header_data.get('hash', hash),
                version=header_data.get('version', 0),
                merkle_root=header_data.get('merkleroot', ''),
                timestamp=header_data.get('creationTimestamp', 0),
                bits=header_data.get('difficultyTarget', 0),
                nonce=header_data.get('nonce', 0),
                previous_block=header_data.get('prevBlockHash', ''),
            ),
            state=state_data.get('state', ''),
            height=state_data.get('height', 0),
        )
    
    async def get_chaintip(self) -> State:
        """
        Get the longest chain tip.
        
        Returns:
            State object for the chain tip
            
        Raises:
            Exception: If request fails
        """
        url = f"{self.url}/api/v1/chain/tip/longest"
        options = {
            "method": "GET",
            "headers": self._get_headers(),
        }
        
        response = await self._http_client.fetch(url, options)
        
        if not response.ok:
            raise ChainTipError(f"Failed to get chaintip: status={response.status_code}")
        
        data = response.json()
        state_data = data.get('data', {}) if 'data' in data else data
        
        header_data = state_data.get('header', {})
        return State(
            header=Header(
                height=header_data.get('height', 0),
                hash=header_data.get('hash', ''),
                version=header_data.get('version', 0),
                merkle_root=header_data.get('merkleroot', ''),
                timestamp=header_data.get('creationTimestamp', 0),
                bits=header_data.get('difficultyTarget', 0),
                nonce=header_data.get('nonce', 0),
                previous_block=header_data.get('prevBlockHash', ''),
            ),
            state=state_data.get('state', ''),
            height=state_data.get('height', 0),
        )
    
    async def get_merkle_roots(
        self,
        batch_size: int,
        last_evaluated_key: Optional[str] = None
    ) -> List[MerkleRootInfo]:
        """
        Fetch merkle roots in bulk from the block-headers-service.
        
        Args:
            batch_size: Number of merkle roots to fetch
            last_evaluated_key: Optional pagination key from previous request
            
        Returns:
            List of MerkleRootInfo objects
            
        Raises:
            Exception: If request fails or response is invalid
        """
        url = f"{self.url}/api/v1/chain/merkleroot?batchSize={batch_size}"
        if last_evaluated_key:
            url += f"&lastEvaluatedKey={last_evaluated_key}"
        
        options = {
            "method": "GET",
            "headers": self._get_headers(),
        }
        
        response = await self._http_client.fetch(url, options)
        
        if not response.ok:
            raise HeaderRetrievalError(f"Failed to get merkle roots: status={response.status_code}")
        
        data = response.json()
        response_data = data.get('data', {}) if 'data' in data else data
        
        content = response_data.get('content', [])
        return [
            MerkleRootInfo(
                merkle_root=item.get('merkleRoot', ''),
                block_height=item.get('blockHeight', 0),
            )
            for item in content
        ]
    
    async def register_webhook(self, callback_url: str, auth_token: str) -> Webhook:
        """
        Register a webhook URL with the block headers service.
        
        Args:
            callback_url: URL to receive webhook notifications
            auth_token: Authentication token for the webhook
            
        Returns:
            Webhook object with registration details
            
        Raises:
            Exception: If registration fails
        """
        url = f"{self.url}/api/v1/webhook"
        payload = {
            "url": callback_url,
            "requiredAuth": {
                "type": "Bearer",
                "token": auth_token,
                "header": "Authorization",
            }
        }
        
        options = {
            "method": "POST",
            "headers": self._get_headers(),
            "data": payload,
        }
        
        response = await self._http_client.fetch(url, options)
        
        if not response.ok:
            body_text = str(response.json())
            raise WebhookError(f"failed to register webhook: status={response.status_code}, body={body_text}")
        
        data = response.json()
        webhook_data = data.get('data', {}) if 'data' in data else data
        
        return Webhook(
            url=webhook_data.get('url', callback_url),
            created_at=webhook_data.get('createdAt', ''),
            last_emit_status=webhook_data.get('lastEmitStatus', ''),
            last_emit_timestamp=webhook_data.get('lastEmitTimestamp', ''),
            errors_count=webhook_data.get('errorsCount', 0),
            active=webhook_data.get('active', False),
        )
    
    async def unregister_webhook(self, callback_url: str) -> None:
        """
        Remove a webhook URL from the block headers service.
        
        Args:
            callback_url: URL of webhook to remove
            
        Raises:
            Exception: If unregistration fails
        """
        url = f"{self.url}/api/v1/webhook?url={callback_url}"
        options = {
            "method": "DELETE",
            "headers": self._get_headers(),
        }
        
        response = await self._http_client.fetch(url, options)
        
        if not response.ok:
            body_text = str(response.json())
            raise WebhookError(f"failed to unregister webhook: status={response.status_code}, body={body_text}")
    
    async def get_webhook(self, callback_url: str) -> Webhook:
        """
        Retrieve a webhook by URL from the block headers service.
        
        Args:
            callback_url: URL of webhook to retrieve
            
        Returns:
            Webhook object with webhook details
            
        Raises:
            Exception: If webhook not found or request fails
        """
        url = f"{self.url}/api/v1/webhook?url={callback_url}"
        options = {
            "method": "GET",
            "headers": self._get_headers(),
        }
        
        response = await self._http_client.fetch(url, options)
        
        if not response.ok:
            body_text = str(response.json())
            raise WebhookError(f"failed to get webhook: status={response.status_code}, body={body_text}")
        
        data = response.json()
        webhook_data = data.get('data', {}) if 'data' in data else data
        
        return Webhook(
            url=webhook_data.get('url', callback_url),
            created_at=webhook_data.get('createdAt', ''),
            last_emit_status=webhook_data.get('lastEmitStatus', ''),
            last_emit_timestamp=webhook_data.get('lastEmitTimestamp', ''),
            errors_count=webhook_data.get('errorsCount', 0),
            active=webhook_data.get('active', False),
        )

