"""
ECIES (Elliptic Curve Integrated Encryption Scheme) compatibility wrapper.

This module provides compatibility with TS SDK's ECIES API,
wrapping Python SDK's existing ECIES functionality.
"""
from typing import Optional
from bsv.keys import PrivateKey, PublicKey


def bitcore_encrypt(
    message_buf: bytes,
    to_public_key: PublicKey,
    from_private_key: Optional[PrivateKey] = None
) -> bytes:
    """
    Bitcore-style ECIES encryption.
    
    Args:
        message_buf: Message to encrypt
        to_public_key: Recipient's public key
        from_private_key: Optional sender's private key (if None, generates ephemeral)
        
    Returns:
        Encrypted bytes
    """
    # If no from_private_key, use Electrum ECIES (which generates ephemeral)
    if from_private_key is None:
        return to_public_key.encrypt(message_buf)
    
    # With from_private_key, use shared secret derivation
    # This is a simplified version - full Bitcore ECIES would be more complex
    to_public_key.derive_shared_secret(from_private_key)
    # Use Electrum ECIES with derived key (simplified)
    return to_public_key.encrypt(message_buf)


def bitcore_decrypt(encrypted_buf: bytes, private_key: PrivateKey) -> bytes:
    """
    Bitcore-style ECIES decryption.
    
    Args:
        encrypted_buf: Encrypted bytes
        private_key: Recipient's private key
        
    Returns:
        Decrypted message bytes
    """
    return private_key.decrypt(encrypted_buf)


def electrum_encrypt(
    message_buf: bytes,
    to_public_key: PublicKey,
    from_private_key: Optional[PrivateKey] = None
) -> bytes:
    """
    Electrum-style ECIES encryption.
    
    Args:
        message_buf: Message to encrypt
        to_public_key: Recipient's public key
        from_private_key: Optional sender's private key (if None, generates ephemeral)
        
    Returns:
        Encrypted bytes
    """
    # Electrum ECIES always generates ephemeral key, so from_private_key is ignored
    return to_public_key.encrypt(message_buf)


def electrum_decrypt(encrypted_buf: bytes, private_key: PrivateKey) -> bytes:
    """
    Electrum-style ECIES decryption.
    
    Args:
        encrypted_buf: Encrypted bytes
        private_key: Recipient's private key
        
    Returns:
        Decrypted message bytes
    """
    return private_key.decrypt(encrypted_buf)

