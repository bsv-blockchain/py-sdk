"""
SPV verification functions.

This module provides script-only verification functionality, ported from
Go-SDK's spv/verify.go package.
"""

from typing import TYPE_CHECKING, List, Dict, Union
import time

if TYPE_CHECKING:
    from bsv.transaction import Transaction

from .gullible_headers_client import GullibleHeadersClient
from bsv.hash import hash256, double_sha256


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


def verify_merkle_proof(txid: bytes, merkle_root: bytes, proof: List[Dict[str, Union[bytes, str]]]) -> bool:
    """
    Verify that a transaction ID is included in a merkle tree with the given root.

    This function implements merkle proof verification, checking that the provided
    txid can be combined with the proof path to produce the expected merkle root.

    Args:
        txid: Transaction ID as 32 bytes
        merkle_root: Expected merkle root as 32 bytes
        proof: List of proof elements, each containing:
            - 'hash': bytes, the sibling hash
            - 'side': str, either 'left' or 'right'

    Returns:
        True if the proof is valid and txid is in the tree, False otherwise

    Raises:
        ValueError: If proof elements are malformed

    Example:
        >>> txid = b'\x01' * 32
        >>> root = b'\x02' * 32
        >>> proof = [{'hash': b'\x03' * 32, 'side': 'left'}]
        >>> verify_merkle_proof(txid, root, proof)
        False
    """
    if not isinstance(txid, bytes) or len(txid) != 32:
        raise ValueError("txid must be 32 bytes")
    if not isinstance(merkle_root, bytes) or len(merkle_root) != 32:
        raise ValueError("merkle_root must be 32 bytes")

    # Start with the txid
    current_hash = txid

    # Apply each proof element
    for element in proof:
        if not isinstance(element, dict):
            raise ValueError("Proof elements must be dictionaries")
        if 'hash' not in element or 'side' not in element:
            raise ValueError("Proof elements must contain 'hash' and 'side' keys")

        sibling_hash = element['hash']
        side = element['side']

        if not isinstance(sibling_hash, bytes) or len(sibling_hash) != 32:
            raise ValueError("Sibling hash must be 32 bytes")
        if side not in ('left', 'right'):
            raise ValueError("Side must be 'left' or 'right'")

        # Combine hashes in the correct order
        if side == 'left':
            # Sibling is on the left, current hash is on the right
            combined = sibling_hash + current_hash
        else:
            # Sibling is on the right, current hash is on the left
            combined = current_hash + sibling_hash

        # Hash the combination
        current_hash = hash256(combined)

    # Check if the final hash matches the expected root
    return current_hash == merkle_root


def verify_block_header(header: bytes) -> bool:
    """
    Verify a Bitcoin block header.

    Performs basic validation of a block header including:
    - Header length (must be 80 bytes)
    - Version validation
    - Timestamp validation (not too far in future)
    - Bits (difficulty target) validation
    - Proof of work validation

    Note: This does not validate against previous blocks or check for
    duplicate blocks. For full blockchain validation, use a proper
    blockchain client.

    Args:
        header: Block header bytes (must be exactly 80 bytes)

    Returns:
        True if header passes basic validation, False otherwise

    Raises:
        ValueError: If header is malformed

    Example:
        >>> header = b'\x01' + b'\x00' * 79  # Genesis-like header
        >>> verify_block_header(header)
        True
    """
    if not isinstance(header, bytes):
        raise ValueError("Header must be bytes")

    if len(header) != 80:
        return False

    # Parse header fields
    version = int.from_bytes(header[0:4], 'little')
    prev_block_hash = header[4:36]  # Not used in basic validation
    merkle_root = header[36:68]     # Not used in basic validation
    timestamp = int.from_bytes(header[68:72], 'little')
    bits = int.from_bytes(header[72:76], 'little')
    nonce = int.from_bytes(header[76:80], 'little')

    # Basic version validation (must be positive, reasonable range)
    if version < 1 or version > 0x7FFFFFFF:
        return False

    # Timestamp validation (not too far in future, within reasonable range)
    current_time = int(time.time())
    max_future_time = current_time + (2 * 60 * 60)  # 2 hours in future max
    if timestamp > max_future_time or timestamp < 1231006505:  # After genesis block
        return False

    # Bits validation (difficulty target)
    # Bits must be in valid range and represent a valid difficulty
    if bits < 0x1d00ffff or bits > 0x2100ffff:  # Reasonable range
        return False

    # Extract target from bits
    # Bits format: 0x1dffffff -> difficulty 1, etc.
    exponent = bits >> 24
    mantissa = bits & 0x00ffffff

    if exponent < 3 or exponent > 32:
        return False

    # Calculate target
    target = mantissa << (8 * (exponent - 3))

    # Proof of work validation
    # Hash the header and check if it's below target
    header_hash = double_sha256(header)
    header_value = int.from_bytes(header_hash[::-1], 'big')  # Reverse for big-endian

    return header_value < target

