"""
BlockHeadersService chaintracker implementation.

Ported from TypeScript SDK.
"""

from typing import Optional
from dataclasses import dataclass

from ..chaintracker import ChainTracker
from ..http_client import HttpClient, default_http_client


@dataclass
class BlockHeadersServiceConfig:
    """Configuration options for the BlockHeadersService ChainTracker."""
    http_client: Optional[HttpClient] = None
    api_key: Optional[str] = None


class BlockHeadersService(ChainTracker):
    """
    Represents a chain tracker based on a BlockHeadersService API.

    Ported from TypeScript SDK.
    """

    def __init__(self, base_url: str, config: Optional[BlockHeadersServiceConfig] = None):
        """
        Constructs an instance of the BlockHeadersService ChainTracker.

        :param base_url: The base URL for the BlockHeadersService API (e.g. https://headers.spv.money)
        :param config: Configuration options for the BlockHeadersService ChainTracker.
        """
        self.base_url = base_url
        self.http_client = config.http_client if config and config.http_client else default_http_client()
        self.api_key = config.api_key if config and config.api_key else ""

    async def is_valid_root_for_height(self, root: str, height: int) -> bool:
        """
        Verifies if a given merkle root is valid for a specific block height.

        :param root: The merkle root to verify.
        :param height: The block height to check against.
        :returns: True if the merkle root is valid for the specified block height, false otherwise.
        """
        request_options = {
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            },
            "data": [
                {
                    "blockHeight": height,
                    "merkleRoot": root
                }
            ]
        }

        try:
            response = await self.http_client.fetch(
                f"{self.base_url}/api/v1/chain/merkleroot/verify",
                request_options
            )

            if response.ok:
                response_data = response.json()
                return response_data.get("confirmationState") == "CONFIRMED"
            else:
                raise Exception(
                    f"Failed to verify merkleroot for height {height} because of an error: {response.json()}"
                )

        except Exception as error:
            raise Exception(
                f"Failed to verify merkleroot for height {height} because of an error: {str(error)}"
            )

    async def current_height(self) -> int:
        """
        Gets the current block height from the BlockHeadersService API.

        :returns: The current block height.
        """
        request_options = {
            "method": "GET",
            "headers": {
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
        }

        try:
            response = await self.http_client.fetch(
                f"{self.base_url}/api/v1/chain/tip/longest",
                request_options
            )

            if response.ok:
                response_data = response.json()
                if response_data and isinstance(response_data.get("data", {}).get("height"), int):
                    return response_data["data"]["height"]
                else:
                    raise Exception(
                        f"Failed to get current height because of an error: {response_data}"
                    )
            else:
                raise Exception(
                    f"Failed to get current height because of an error: {response.json()}"
                )

        except Exception as error:
            raise Exception(
                f"Failed to get current height because of an error: {str(error)}"
            )
