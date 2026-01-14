"""
HeadersClient package for interacting with Block Headers Service (BHS).

This package provides a client for querying blockchain headers, verifying
merkle roots, and managing webhooks with a Block Headers Service.

Ported from Go-SDK's transaction/chaintracker/headers_client package.
"""

from .client import HeadersClient
from .types import (
    Header,
    MerkleRootInfo,
    RequiredAuth,
    State,
    Webhook,
    WebhookRequest,
)

__all__ = [
    "Header",
    "HeadersClient",
    "MerkleRootInfo",
    "RequiredAuth",
    "State",
    "Webhook",
    "WebhookRequest",
]
