"""
BSM (Bitcoin Signed Message) implementation.

This module provides legacy Bitcoin Signed Message format support,
matching the TypeScript SDK implementation.
"""
from typing import Union
from bsv.keys import PrivateKey, PublicKey
from bsv.hash import hash256
from bsv.utils import unsigned_to_varint, serialize_ecdsa_der, deserialize_ecdsa_der
import base64


PREFIX = 'Bitcoin Signed Message:\n'


def magic_hash(message_buf: Union[bytes, list]) -> bytes:
    """
    Generates a SHA256 double-hash of the prefixed message.
    
    Args:
        message_buf: Message buffer as bytes or list of integers
        
    Returns:
        The double-hash of the prefixed message as bytes
    """
    if isinstance(message_buf, list):
        message_buf = bytes(message_buf)
    
    # Build the message: varint(prefix_len) + prefix + varint(msg_len) + message
    prefix_bytes = PREFIX.encode('utf-8')
    buf = unsigned_to_varint(len(prefix_bytes))
    buf += prefix_bytes
    buf += unsigned_to_varint(len(message_buf))
    buf += message_buf
    
    # Double SHA256
    hash_buf = hash256(buf)
    return hash_buf


def sign(
    message: Union[bytes, list],
    private_key: PrivateKey,
    mode: str = 'base64'
) -> Union[bytes, str]:
    """
    Signs a BSM message using the given private key.
    
    Args:
        message: The message to be signed as bytes or list of integers
        private_key: The private key used for signing the message
        mode: The mode of operation. When "base64", the BSM format signature is returned.
              When "raw", a DER signature bytes is returned. Default: "base64".
    
    Returns:
        The signature bytes when in raw mode, or the BSM base64 string when in base64 mode.
    """
    hash_buf = magic_hash(message)
    
    # Sign the hash
    sig_bytes = private_key.sign(hash_buf, hasher=lambda x: x)  # No hashing, already hashed
    
    if mode == 'raw':
        return sig_bytes
    
    # Convert to compact format with recovery factor
    # For base64 mode, we need to compute recovery factor and create compact signature
    from bsv.utils import deserialize_ecdsa_der, stringify_ecdsa_recoverable
    r, s = deserialize_ecdsa_der(sig_bytes)
    
    # Compute recovery factor
    public_key = private_key.public_key()
    recovery_id = _calculate_recovery_factor(r, s, hash_buf, public_key)
    
    # Create recoverable signature: r (32 bytes) + s (32 bytes) + recovery_id (1 byte)
    r_bytes = r.to_bytes(32, 'big')
    s_bytes = s.to_bytes(32, 'big')
    recoverable_sig = r_bytes + s_bytes + bytes([recovery_id])
    
    # Stringify with compression flag
    compressed = private_key.compressed
    return stringify_ecdsa_recoverable(recoverable_sig, compressed)


def verify(
    message: Union[bytes, list],
    sig: Union[bytes, str],
    pub_key: PublicKey
) -> bool:
    """
    Verifies a BSM signed message using the given public key.
    
    Args:
        message: The message to be verified as bytes or list of integers
        sig: The signature (DER bytes or base64 string)
        pub_key: The public key for verification
        
    Returns:
        True if the signature is valid, False otherwise
    """
    hash_buf = magic_hash(message)
    
    # Handle base64 string signature
    if isinstance(sig, str):
        from bsv.utils import unstringify_ecdsa_recoverable, deserialize_ecdsa_recoverable
        serialized_recoverable, _ = unstringify_ecdsa_recoverable(sig)
        r, s, _ = deserialize_ecdsa_recoverable(serialized_recoverable)
        der_sig = serialize_ecdsa_der((r, s))
    else:
        der_sig = sig
    
    # Verify using public key
    return pub_key.verify(der_sig, hash_buf, hasher=lambda x: x)


def _calculate_recovery_factor(r: int, s: int, hash_buf: bytes, public_key: PublicKey) -> int:
    """
    Calculate recovery factor for a signature.
    This is a simplified version - full implementation would try all 4 possibilities.
    """
    # Try recovery factors 0-3
    for recovery_id in range(4):
        try:
            from bsv.utils import serialize_ecdsa_recoverable
            recoverable_sig = serialize_ecdsa_recoverable((r, s, recovery_id))
            recovered_pub = recover_public_key(recoverable_sig, hash_buf)
            if recovered_pub and recovered_pub.serialize() == public_key.serialize():
                return recovery_id
        except Exception:
            continue
    return 0  # Default


def recover_public_key(signature: bytes, message_hash: bytes) -> PublicKey:
    """
    Recover public key from recoverable signature.
    Simplified implementation - would need full ECDSA recovery logic.
    """
    # This is a placeholder - full implementation would use coincurve's recovery
    from coincurve import PublicKey as CcPublicKey
    # Try to recover using coincurve
    recovered = CcPublicKey.from_signature_and_message(signature, message_hash, hasher=None)
    return PublicKey(recovered.format(True))

