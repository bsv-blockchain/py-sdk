"""
Teranode broadcaster implementation.

Ported from TypeScript SDK.
"""

import aiohttp
from typing import Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from ..transaction import Transaction

from .broadcaster import Broadcaster, BroadcastResponse, BroadcastFailure


class Teranode(Broadcaster):
    """
    Represents a Teranode transaction broadcaster.
    """

    def __init__(self, url: str):
        """
        Constructs an instance of the Teranode broadcaster.

        :param url: The URL endpoint for the Teranode API.
        """
        self.URL = url

    async def broadcast(
        self, transaction: 'Transaction'
    ) -> Union[BroadcastResponse, BroadcastFailure]:
        """
        Broadcasts a transaction via Teranode.

        :param transaction: The transaction to be broadcasted.
        :returns: BroadcastResponse on success, BroadcastFailure on failure.
        """
        raw_tx = transaction.to_ef()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.URL,
                    headers={
                        "Content-Type": "application/octet-stream"
                    },
                    data=raw_tx
                ) as response:
                    if response.ok:
                        txid = transaction.txid()
                        return BroadcastResponse(
                            status="success",
                            txid=txid,
                            message="broadcast successful"
                        )
                    else:
                        error_text = await response.text()
                        return BroadcastFailure(
                            status="error",
                            code=str(response.status),
                            description=error_text or f"HTTP {response.status}"
                        )

        except aiohttp.ClientError as error:
            return BroadcastFailure(
                status="error",
                code="500",
                description=f"Network error: {str(error)}"
            )
        except Exception as error:
            return BroadcastFailure(
                status="error",
                code="500",
                description=str(error) if isinstance(error, Exception) else "Internal Server Error"
            )
