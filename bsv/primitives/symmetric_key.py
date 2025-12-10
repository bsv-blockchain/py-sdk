"""SymmetricKey - AES-GCM symmetric encryption compatible with TS/Go SDKs.

This module implements symmetric key encryption using AES-256-GCM, compatible
with the TypeScript and Go SDK implementations.

Format: IV (32 bytes) | ciphertext | authTag (16 bytes)

Reference implementations:
- ts-sdk/src/primitives/SymmetricKey.ts
- go-sdk/primitives/ec/symmetric.go
"""

from __future__ import annotations

import os
import secrets
from typing import Union

from Cryptodome.Cipher import AES


class SymmetricKey:
    """Symmetric key for AES-GCM encryption, compatible with TS/Go SDKs.
    
    The key is always stored as exactly 32 bytes. If a shorter key is provided,
    it is left-padded with zeros (matching Go SDK behavior).
    
    Encryption format: IV (32 bytes) || ciphertext || authTag (16 bytes)
    
    Example:
        >>> key = SymmetricKey.from_random()
        >>> ciphertext = key.encrypt(b"Hello, World!")
        >>> plaintext = key.decrypt(ciphertext)
        >>> assert plaintext == b"Hello, World!"
    """

    IV_LENGTH = 32
    TAG_LENGTH = 16
    KEY_LENGTH = 32

    def __init__(self, key: Union[bytes, bytearray, list, int]):
        """Initialize SymmetricKey from bytes, list, or integer.
        
        Args:
            key: The symmetric key material. Can be:
                - bytes/bytearray: Used directly (padded to 32 bytes if shorter)
                - list: Converted to bytes
                - int: Converted to 32-byte big-endian representation
        
        Raises:
            ValueError: If the key cannot be converted to bytes.
        """
        if isinstance(key, int):
            # Convert integer to 32-byte big-endian (matches TS BigNumber.toArray('be', 32))
            self._key = key.to_bytes(self.KEY_LENGTH, byteorder='big')
        elif isinstance(key, (bytes, bytearray)):
            key_bytes = bytes(key)
            if len(key_bytes) < self.KEY_LENGTH:
                # Left-pad with zeros (matches Go SDK NewSymmetricKey behavior)
                self._key = bytes(self.KEY_LENGTH - len(key_bytes)) + key_bytes
            elif len(key_bytes) > self.KEY_LENGTH:
                # Truncate to 32 bytes
                self._key = key_bytes[:self.KEY_LENGTH]
            else:
                self._key = key_bytes
        elif isinstance(key, list):
            key_bytes = bytes(key)
            if len(key_bytes) < self.KEY_LENGTH:
                self._key = bytes(self.KEY_LENGTH - len(key_bytes)) + key_bytes
            elif len(key_bytes) > self.KEY_LENGTH:
                self._key = key_bytes[:self.KEY_LENGTH]
            else:
                self._key = key_bytes
        else:
            raise ValueError(f"Invalid key type: {type(key)}. Expected bytes, list, or int.")

    @classmethod
    def from_random(cls) -> SymmetricKey:
        """Generate a random symmetric key.
        
        Returns:
            A new SymmetricKey with 32 random bytes.
        """
        return cls(secrets.token_bytes(cls.KEY_LENGTH))

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> SymmetricKey:
        """Create a SymmetricKey from bytes.
        
        Args:
            key_bytes: The key material (will be padded to 32 bytes if shorter).
            
        Returns:
            A new SymmetricKey.
        """
        return cls(key_bytes)

    @classmethod
    def from_hex(cls, hex_string: str) -> SymmetricKey:
        """Create a SymmetricKey from a hex string.
        
        Args:
            hex_string: The key material as a hex string.
            
        Returns:
            A new SymmetricKey.
        """
        return cls(bytes.fromhex(hex_string))

    def to_bytes(self) -> bytes:
        """Return the key as bytes.
        
        Returns:
            The 32-byte key.
        """
        return self._key

    def to_hex(self) -> str:
        """Return the key as a hex string.
        
        Returns:
            The key as a lowercase hex string.
        """
        return self._key.hex()

    def to_list(self) -> list:
        """Return the key as a list of integers.
        
        Returns:
            The key as a list of byte values.
        """
        return list(self._key)

    def encrypt(self, plaintext: Union[bytes, str, list]) -> bytes:
        """Encrypt data using AES-256-GCM.
        
        The output format is: IV (32 bytes) || ciphertext || authTag (16 bytes)
        
        This matches the TS SDK SymmetricKey.encrypt() and Go SDK SymmetricKey.Encrypt()
        format exactly.
        
        Args:
            plaintext: The data to encrypt. Can be bytes, str (UTF-8), or list of ints.
            
        Returns:
            The encrypted data as bytes.
            
        Raises:
            ValueError: If plaintext cannot be converted to bytes.
        """
        # Normalize plaintext to bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        elif isinstance(plaintext, list):
            plaintext = bytes(plaintext)
        elif not isinstance(plaintext, (bytes, bytearray)):
            raise ValueError(f"Invalid plaintext type: {type(plaintext)}")
        
        # Generate random IV (32 bytes, matching TS/Go SDKs)
        iv = secrets.token_bytes(self.IV_LENGTH)
        
        # Encrypt using AES-256-GCM with 32-byte nonce
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=iv)
        ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
        
        # Combine: IV || ciphertext || authTag
        return iv + ciphertext + auth_tag

    def decrypt(self, ciphertext: Union[bytes, str, list]) -> bytes:
        """Decrypt data using AES-256-GCM.
        
        Expects the input format: IV (32 bytes) || ciphertext || authTag (16 bytes)
        
        This matches the TS SDK SymmetricKey.decrypt() and Go SDK SymmetricKey.Decrypt()
        format exactly.
        
        Args:
            ciphertext: The encrypted data. Can be bytes, hex string, or list of ints.
            
        Returns:
            The decrypted plaintext as bytes.
            
        Raises:
            ValueError: If ciphertext is too short or decryption fails.
        """
        # Normalize ciphertext to bytes
        if isinstance(ciphertext, str):
            # Assume hex encoding for strings
            ciphertext = bytes.fromhex(ciphertext)
        elif isinstance(ciphertext, list):
            ciphertext = bytes(ciphertext)
        elif not isinstance(ciphertext, (bytes, bytearray)):
            raise ValueError(f"Invalid ciphertext type: {type(ciphertext)}")
        
        # Validate minimum length: IV (32) + authTag (16) = 48 bytes minimum
        min_length = self.IV_LENGTH + self.TAG_LENGTH
        if len(ciphertext) < min_length:
            raise ValueError(f"Ciphertext too short: {len(ciphertext)} bytes, minimum is {min_length}")
        
        # Extract components: IV || encrypted || authTag
        iv = ciphertext[:self.IV_LENGTH]
        auth_tag = ciphertext[-self.TAG_LENGTH:]
        encrypted_data = ciphertext[self.IV_LENGTH:-self.TAG_LENGTH]
        
        # Decrypt using AES-256-GCM
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=iv)
        try:
            plaintext = cipher.decrypt_and_verify(encrypted_data, auth_tag)
            return plaintext
        except ValueError as e:
            raise ValueError(f"Decryption failed: {e}") from e

    def __eq__(self, other: object) -> bool:
        """Check equality with another SymmetricKey."""
        if not isinstance(other, SymmetricKey):
            return NotImplemented
        return self._key == other._key

    def __repr__(self) -> str:
        """Return a string representation (key hidden for security)."""
        return f"SymmetricKey(key=<{len(self._key)} bytes>)"
