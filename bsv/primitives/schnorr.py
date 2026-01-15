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
        self, a: PrivateKey, A: PublicKey, B: PublicKey, S: Optional[Point]
    ) -> dict[str, Any]:
        """
        Generates a proof that demonstrates the link between public key A and shared secret S.

        Args:
            a: Private key corresponding to public key A
            A: Public key
            B: Other party's public key
            S: Shared secret point

        Returns:
            Proof dictionary with keys: R (Point), SPrime (Point), z (int)
        """
        # Internal PEP8-compliant variable names
        a_pub = A
        b_pub = B
        shared_secret = S

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
        self, A: Optional[Point], B: Optional[Point], S: Optional[Point], proof: dict[str, Any]
    ) -> bool:
        """
        Verifies the proof of the link between public key A and shared secret S.

        Args:
            A: Public key point
            B: Other party's public key point
            S: Shared secret point
            proof: Proof dictionary with keys: R, SPrime, z

        Returns:
            True if the proof is valid, False otherwise
        """
        # Internal PEP8-compliant variable names
        a_point = A
        b_point = B
        s_point = S

        if a_point is None or b_point is None or s_point is None:
            return False

        R = proof.get("R")  # NOSONAR - Mathematical notation
        S_prime = proof.get("SPrime")  # NOSONAR - Mathematical notation
        z = proof.get("z")

        if R is None or S_prime is None or z is None:
            return False

        # Compute challenge e
        e = self._compute_challenge_from_points(a_point, b_point, s_point, S_prime, R)

        # Check zG = R + eA
        zG = curve_multiply(z, curve.g)  # NOSONAR - Mathematical notation
        eA = curve_multiply(e, a_point)  # NOSONAR - Mathematical notation
        R_plus_eA = curve_add(R, eA)  # NOSONAR - Mathematical notation

        if zG != R_plus_eA:
            return False

        # Check zB = S' + eS
        zB = curve_multiply(z, b_point)  # NOSONAR - Mathematical notation
        eS = curve_multiply(e, s_point)  # NOSONAR - Mathematical notation
        S_prime_plus_eS = curve_add(S_prime, eS)  # NOSONAR - Mathematical notation

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
        self, A: Optional[Point], B: Optional[Point], S: Optional[Point], S_prime: Optional[Point], R: Optional[Point]
    ) -> int:
        """Compute challenge e from points."""
        if A is None or B is None or S is None or S_prime is None or R is None:
            return 0

        # Encode points as compressed public keys
        A_encoded = self._encode_point(A)
        B_encoded = self._encode_point(B)
        S_encoded = self._encode_point(S)
        S_prime_encoded = self._encode_point(S_prime)
        R_encoded = self._encode_point(R)

        # Concatenate all encoded points
        message = A_encoded + B_encoded + S_encoded + S_prime_encoded + R_encoded

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
