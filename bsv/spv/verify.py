"""
SPV verification functions.

This module provides script-only verification functionality, ported from
Go-SDK's spv/verify.go package.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bsv.transaction import Transaction

from .gullible_headers_client import GullibleHeadersClient


async def verify_scripts(tx: "Transaction") -> bool:
    """
    Verify transaction scripts without merkle proof validation.
    
    This function verifies that all input scripts are valid, but skips
    merkle proof verification. It uses GullibleHeadersClient which accepts
    any merkle root as valid (for testing purposes).
    
    This is useful for:
    - Testing script validation logic
    - Verifying scripts in transactions that don't have merkle proofs yet
    - Development and debugging
    
    WARNING: This function does NOT verify merkle proofs. For full SPV
    verification including merkle proofs, use Transaction.verify() with
    a real ChainTracker.
    
    Args:
        tx: Transaction to verify
        
    Returns:
        True if all scripts are valid, False otherwise
        
    Raises:
        ValueError: If transaction is missing required data (source transactions, scripts)
        Exception: If verification fails for other reasons
        
    Example:
        >>> from bsv import Transaction
        >>> from bsv.spv import verify_scripts
        >>> 
        >>> tx = Transaction.from_hex("...")
        >>> is_valid = await verify_scripts(tx)
        >>> print(f"Scripts valid: {is_valid}")
    """
    # Use GullibleHeadersClient which accepts any merkle root
    # This allows script verification without merkle proof validation
    gullible_client = GullibleHeadersClient()
    
    # Call transaction verify with scripts_only=True
    # This skips merkle path verification but still verifies scripts
    return await tx.verify(chaintracker=gullible_client, scripts_only=True)

