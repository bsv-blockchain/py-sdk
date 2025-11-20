"""
HMAC-based Deterministic Random Bit Generator (DRBG) implementation.

This module implements HMAC-DRBG matching the TypeScript SDK implementation.
"""
from typing import Union, Optional
from bsv.hash import hmac_sha256


class DRBG:
    """
    HMAC-based deterministic random bit generator (DRBG).
    
    Implements a deterministic random number generator using SHA256HMAC hash function.
    Takes an initial entropy and nonce when instantiated for seeding purpose.
    """

    def __init__(self, entropy: Union[str, bytes], nonce: Union[str, bytes]):
        """
        Initialize DRBG with entropy and nonce.
        
        Args:
            entropy: Initial entropy as hex string or bytes (minimum 32 bytes/256 bits)
            nonce: Initial nonce as hex string or bytes
            
        Raises:
            ValueError: If entropy length is less than 32 bytes
        """
        # Convert to bytes if hex string
        if isinstance(entropy, str):
            entropy_bytes = bytes.fromhex(entropy)
        else:
            entropy_bytes = entropy
        
        if isinstance(nonce, str):
            nonce_bytes = bytes.fromhex(nonce)
        else:
            nonce_bytes = nonce

        if len(entropy_bytes) < 32:
            raise ValueError('Not enough entropy. Minimum is 256 bits')

        seed = entropy_bytes + nonce_bytes

        # Initialize K and V
        self.K = bytearray(32)  # All zeros
        self.V = bytearray([0x01] * 32)  # All 0x01

        self.update(seed)

    def _hmac(self) -> bytes:
        """
        Generates HMAC using the K value of the instance.
        
        Returns:
            HMAC-SHA256 of V using K as key
        """
        return hmac_sha256(bytes(self.K), bytes(self.V))

    def update(self, seed: Optional[bytes] = None):
        """
        Updates the K and V values of the instance based on the seed.
        The seed if not provided uses V as seed.
        
        Args:
            seed: Optional value used to update K and V. Default is None.
        """
        # K = HMAC(K, V || 0x00 || seed) if seed provided
        # K = HMAC(K, V || 0x00) if seed not provided
        if seed is not None:
            kmac_input = bytes(self.V) + b'\x00' + seed
        else:
            kmac_input = bytes(self.V) + b'\x00'
        
        self.K = bytearray(hmac_sha256(bytes(self.K), kmac_input))
        
        # Update V using HMAC(K, V)
        self.V = bytearray(hmac_sha256(bytes(self.K), bytes(self.V)))
        
        if seed is None:
            return

        # Additional update if seed provided
        # Update K using HMAC(K, V || 0x01 || seed)
        kmac_input2 = bytes(self.V) + b'\x01' + seed
        self.K = bytearray(hmac_sha256(bytes(self.K), kmac_input2))
        
        # Update V using HMAC(K, V)
        self.V = bytearray(hmac_sha256(bytes(self.K), bytes(self.V)))

    def generate(self, length: int) -> str:
        """
        Generates deterministic random hexadecimal string of given length.
        In every generation process, it also updates the internal state K and V.
        
        Args:
            length: The length of required random bytes (not hex chars)
            
        Returns:
            The required deterministic random hexadecimal string
        """
        temp = bytearray()
        while len(temp) < length:
            # Update V using HMAC(K, V)
            self.V = bytearray(hmac_sha256(bytes(self.K), bytes(self.V)))
            temp.extend(self.V)

        # Take only the required length
        res = temp[:length]
        
        # Update state
        self.update()
        
        return res.hex()

