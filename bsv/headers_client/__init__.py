"""
HeadersClient package for interacting with Block Headers Service (BHS).

This package provides a client for querying blockchain headers, verifying
merkle roots, and managing webhooks with a Block Headers Service.

Ported from Go-SDK's transaction/chaintracker/headers_client package.
"""

from .client import HeadersClient
from .types import (
    Header,
    State,
    MerkleRootInfo,
    Webhook,
    WebhookRequest,
    RequiredAuth,
)

__all__ = [
    'HeadersClient',
    'Header',
    'State',
    'MerkleRootInfo',
    'Webhook',
    'WebhookRequest',
    'RequiredAuth',
]

