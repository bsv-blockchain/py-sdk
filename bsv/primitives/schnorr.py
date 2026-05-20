"""
Schnorr Zero-Knowledge Proof implementation.

This module implements Schnorr Zero-Knowledge Proof protocol matching
the TypeScript SDK implementation.
"""

from typing import Any, Dict, Optional

from bsv.curve import Point, curve, curve_add, curve_multiply
from bsv.hash import sha256
from bsv.keys import PrivateKey, PublicKey


class Schnorr:
    """
    Class representing the Schnorr Zero-Knowledge Proof (ZKP) protocol.

    This class provides methods to generate and verify proofs that demonstrate
    knowledge of a secret without revealing it.
    """

    def __init__(self):
        """Initialize Schnorr instance."""

    def generate_proof(  # NOSONAR - Mathematical notation for Schnorr ZKP protocol
        self, a: PrivateKey, a_pub: PublicKey, b_pub: PublicKey, s: Optional[Point]
    ) -> dict[str, Any]:
        """
        Generates a proof that demonstrates the link between public key A and shared secret S.

        Args:
            a: Private key corresponding to public key A
            a_pub: Public key
            b_pub: Other party's public key
            s: Shared secret point

        Returns:
            Proof dictionary with keys: R (Point), SPrime (Point), z (int)
        """
        # Internal PEP8-compliant variable names
        shared_secret = s

        # Generate random private key r
        r_key = PrivateKey()
        r_int = r_key.int()

        # Compute R = r * G
        R = curve_multiply(r_int, curve.g)  # NOSONAR - Mathematical notation

        # Compute S' = r * B
        S_prime = curve_multiply(r_int, b_pub.point())  # NOSONAR - Mathematical notation

        # Compute challenge e
        e = self._compute_challenge(a_pub, b_pub, shared_secret, S_prime, R)

        # Compute z = r + e * a (mod n)
        z = (r_int + e * a.int()) % curve.n

        return {"R": R, "SPrime": S_prime, "z": z}

    def verify_proof(  # NOSONAR - Mathematical notation for Schnorr ZKP protocol
        self,
        a: Optional[Point],
        b: Optional[Point],
        s: Optional[Point],
        proof: dict[str, Any],
    ) -> bool:
        """
        Verifies the proof of the link between public key A and shared secret S.

        Args:
            a: Public key point
            b: Other party's public key point
            s: Shared secret point
            proof: Proof dictionary with keys: R, SPrime, z

        Returns:
            True if the proof is valid, False otherwise
        """
        # Internal PEP8-compliant variable names
        a_point = a
        b_point = b
        s_point = s

        if a_point is None or b_point is None or s_point is None:
            return False

        r = proof.get("R")  # NOSONAR - Mathematical notation
        s_prime = proof.get("SPrime")  # NOSONAR - Mathematical notation
        z = proof.get("z")

        if r is None or s_prime is None or z is None:
            return False

        # Compute challenge e
        e = self._compute_challenge_from_points(a_point, b_point, s_point, s_prime, r)

        # Check zG = R + eA
        zG = curve_multiply(z, curve.g)  # NOSONAR - Mathematical notation
        eA = curve_multiply(e, a_point)  # NOSONAR - Mathematical notation
        R_plus_eA = curve_add(r, eA)  # NOSONAR - Mathematical notation

        if zG != R_plus_eA:
            return False

        # Check zB = S' + eS
        zB = curve_multiply(z, b_point)  # NOSONAR - Mathematical notation
        eS = curve_multiply(e, s_point)  # NOSONAR - Mathematical notation
        S_prime_plus_eS = curve_add(s_prime, eS)  # NOSONAR - Mathematical notation

        if zB != S_prime_plus_eS:
            return False

        return True

    def _compute_challenge(  # NOSONAR - Mathematical notation for Schnorr ZKP protocol
        self,
        a_pub: PublicKey,
        b_pub: PublicKey,
        s_point: Optional[Point],
        s_prime: Optional[Point],
        r_point: Optional[Point],
    ) -> int:
        """Compute challenge e from public keys and points."""
        a_encoded = a_pub.point()
        b_encoded = b_pub.point()
        s_encoded = s_point
        s_prime_encoded = s_prime
        r_encoded = r_point
        return self._compute_challenge_from_points(a_encoded, b_encoded, s_encoded, s_prime_encoded, r_encoded)

    def _compute_challenge_from_points(  # NOSONAR - Mathematical notation for Schnorr ZKP protocol
        self,
        a: Optional[Point],
        b: Optional[Point],
        s: Optional[Point],
        s_prime: Optional[Point],
        r: Optional[Point],
    ) -> int:
        """Compute challenge e from points."""
        if a is None or b is None or s is None or s_prime is None or r is None:
            return 0

        # Encode points as compressed public keys
        a_encoded = self._encode_point(a)
        b_encoded = self._encode_point(b)
        s_encoded = self._encode_point(s)
        s_prime_encoded = self._encode_point(s_prime)
        r_encoded = self._encode_point(r)

        # Concatenate all encoded points
        message = a_encoded + b_encoded + s_encoded + s_prime_encoded + r_encoded

        # Hash and reduce modulo curve order
        hash_bytes = sha256(message)
        hash_int = int.from_bytes(hash_bytes, "big")
        e = hash_int % curve.n

        return e

    def _encode_point(self, point: Optional[Point]) -> bytes:
        """Encode a point as a compressed public key (33 bytes)."""
        if point is None:
            return b"\x00" * 33

        x, y = point
        # Compressed format: 0x02 or 0x03 prefix + 32-byte x coordinate
        prefix = 0x02 if (y % 2 == 0) else 0x03
        x_bytes = x.to_bytes(32, "big")
        return bytes([prefix]) + x_bytes
