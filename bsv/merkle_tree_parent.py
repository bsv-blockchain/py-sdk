"""
Merkle Tree Parent utilities for computing parent hashes from child nodes.
"""
from .hash import hash256
from .utils import to_hex, to_bytes


def merkle_tree_parent_str(left: str, right: str) -> str:
    """
    Compute the parent hash from two child node hex strings.

    Args:
        left: Left child node as hex string
        right: Right child node as hex string

    Returns:
        Parent hash as hex string
    """
    left_bytes = to_bytes(left, "hex")[::-1]  # Reverse for little-endian
    right_bytes = to_bytes(right, "hex")[::-1]  # Reverse for little-endian
    # Concatenate and use double SHA256 like Go implementation
    parent_bytes = hash256(left_bytes + right_bytes)[::-1]  # Reverse result
    return to_hex(parent_bytes)


def merkle_tree_parent_bytes(left: bytes, right: bytes) -> bytes:
    """
    Compute the parent hash from two child node byte arrays.

    Args:
        left: Left child node as bytes
        right: Right child node as bytes

    Returns:
        Parent hash as bytes
    """
    # Reverse bytes for little-endian interpretation, then concatenate and hash
    left_rev = left[::-1]
    right_rev = right[::-1]
    return hash256(left_rev + right_rev)[::-1]  # Reverse result
