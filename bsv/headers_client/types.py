"""
Type definitions for HeadersClient package.

These types correspond to Go-SDK's headers_client package types.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Header:
    """Block header information."""
    height: int
    hash: str
    version: int
    merkle_root: str
    timestamp: int
    bits: int
    nonce: int
    previous_block: str


@dataclass
class State:  # NOSONAR - Field names match protocol specification
    """Blockchain state information."""
    header: Header
    state: str  # NOSONAR - Field names match protocol specification
    height: int


@dataclass
class MerkleRootInfo:
    """Merkle root information with block height."""
    merkle_root: str
    block_height: int


@dataclass
class RequiredAuth:
    """Authentication information for webhook registration."""
    type: str  # e.g., "Bearer"
    token: str  # The auth token
    header: str  # e.g., "Authorization"


@dataclass
class WebhookRequest:
    """Webhook registration request."""
    url: str
    required_auth: RequiredAuth


@dataclass
class Webhook:
    """Registered webhook information."""
    url: str
    created_at: str
    last_emit_status: str
    last_emit_timestamp: str
    errors_count: int
    active: bool

