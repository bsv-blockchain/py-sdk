"""
SPV (Simplified Payment Verification) module.

This module provides SPV verification functionality including:
- GullibleHeadersClient: Test-only chain tracker (DO NOT USE IN PRODUCTION)
- verify_scripts: Script-only verification function
- verify_block_header: Block header validation function
"""

from .gullible_headers_client import GullibleHeadersClient
from .verify import verify_scripts, verify_block_header

__all__ = [
    'GullibleHeadersClient',
    'verify_scripts',
    'verify_block_header',
]

