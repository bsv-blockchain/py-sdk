"""
Common serialization utilities for wallet serializer modules.
"""
from typing import Dict, Any
from bsv.wallet.substrates.serializer import Reader, Writer

# Re-exports from substrates serializer
from bsv.wallet.substrates.serializer import (
    _encode_key_related_params as encode_key_related_params,
    _decode_key_related_params as decode_key_related_params,
    encode_privileged_params,
    encode_outpoint,
)

# Re-export certificate base helpers from dedicated module
from .certificate import (
    serialize_certificate_base,
    deserialize_certificate_base,
)


def serialize_encryption_args(
    w: Writer,
    protocol_id: Dict[str, Any],
    key_id: str,
    counterparty: Dict[str, Any],
    privileged: bool = None,
    privileged_reason: str = "",
) -> None:
    """
    Serialize common encryption arguments.
    
    Args:
        w: Writer instance
        protocol_id: Dict with 'securityLevel' and 'protocol' keys
        key_id: Key identifier string
        counterparty: Dict with 'type' key or 'counterparty' bytes
        privileged: Optional boolean flag
        privileged_reason: Optional reason string
    """
    # Protocol ID
    w.write_byte(int(protocol_id.get("securityLevel", 0)))
    w.write_string(protocol_id.get("protocol", ""))
    
    # Key ID
    w.write_string(key_id)
    
    # Counterparty: 0/1/2/11/12 or 33 bytes
    cp_type = counterparty.get("type", 0)
    if cp_type in (0, 1, 2, 11, 12):
        w.write_byte(cp_type)
    else:
        w.write_bytes(counterparty.get("counterparty", b""))
    
    # Privileged flag
    if privileged is not None:
        w.write_byte(1 if privileged else 0)
    else:
        w.write_negative_one_byte()
    
    # Privileged reason
    if privileged_reason:
        w.write_string(privileged_reason)
    else:
        w.write_negative_one()


def deserialize_encryption_args(r: Reader) -> Dict[str, Any]:
    """
    Deserialize common encryption arguments.
    
    Args:
        r: Reader instance
        
    Returns:
        Dict with encryption_args containing protocol_id, key_id, counterparty,
        privileged, and privilegedReason
    """
    out: Dict[str, Any] = {"encryption_args": {}}
    
    # Protocol ID
    sec = r.read_byte()
    proto = r.read_string()
    out["encryption_args"]["protocol_id"] = {"securityLevel": int(sec), "protocol": proto}
    
    # Key ID
    out["encryption_args"]["key_id"] = r.read_string()
    
    # Counterparty
    first = r.read_byte()
    if first in (0, 1, 2, 11, 12):
        out["encryption_args"]["counterparty"] = {"type": int(first)}
    else:
        rest = r.read_bytes(32)
        out["encryption_args"]["counterparty"] = bytes([first]) + rest
    
    # Privileged flag
    b = r.read_byte()
    out["encryption_args"]["privileged"] = None if b == 0xFF else (b == 1)
    
    # Privileged reason
    out["encryption_args"]["privilegedReason"] = r.read_string()
    
    return out


def serialize_seek_permission(w: Writer, seek_permission: bool = None) -> None:
    """
    Serialize optional seek permission flag.
    
    Args:
        w: Writer instance
        seek_permission: Optional boolean flag
    """
    if seek_permission is not None:
        w.write_byte(1 if seek_permission else 0)
    else:
        w.write_negative_one_byte()


def deserialize_seek_permission(r: Reader) -> bool:
    """
    Deserialize optional seek permission flag.
    
    Args:
        r: Reader instance
        
    Returns:
        Boolean or None for the seekPermission value
    """
    b = r.read_byte()
    return None if b == 0xFF else (b == 1)


def serialize_relinquish_certificate_result(_: Dict[str, Any]) -> bytes:
    """Serialize relinquish certificate result (empty)."""
    return b""


def deserialize_relinquish_certificate_result(_: bytes) -> Dict[str, Any]:
    """Deserialize relinquish certificate result (empty)."""
    return {}


__all__ = [
    # Re-exported from substrates
    'encode_key_related_params',
    'decode_key_related_params',
    'encode_privileged_params',
    'encode_outpoint',
    # Re-exported from certificate module
    'serialize_certificate_base',
    'deserialize_certificate_base',
    # New common encryption args functions
    'serialize_encryption_args',
    'deserialize_encryption_args',
    'serialize_seek_permission',
    'deserialize_seek_permission',
    # Relinquish certificate helpers
    'serialize_relinquish_certificate_result',
    'deserialize_relinquish_certificate_result',
]
