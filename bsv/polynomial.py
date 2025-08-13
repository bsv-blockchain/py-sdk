import secrets
from typing import List, Optional, Union

from .base58 import b58_encode, b58_decode
from .curve import curve


# Define PointInFiniteField class for points in finite field
class PointInFiniteField:
    """
    A class representing a point in a finite field.

    Used for implementing Shamir's Secret Sharing scheme.
    """

    def __init__(self, x: Union[int, bytes], y: Union[int, bytes]):
        """
        Initialize a point in a finite field.

        Args:
            x: The x-coordinate (can be int or bytes)
            y: The y-coordinate (can be int or bytes)
        """
        # Convert inputs to integers if they are bytes
        if isinstance(x, bytes):
            x = int.from_bytes(x, 'big')
        if isinstance(y, bytes):
            y = int.from_bytes(y, 'big')

        # Take modulo of coordinates with prime field size
        self.x = x % curve.p
        self.y = y % curve.p

    def __str__(self) -> str:
        """
        String representation of the point using base58 encoding.

        Returns:
            String in format x.y where x and y are base58 encoded
        """
        # Convert integers to bytes and then base58 encode
        x_bytes = self.x.to_bytes((self.x.bit_length() + 7) // 8, 'big')
        y_bytes = self.y.to_bytes((self.y.bit_length() + 7) // 8, 'big')

        return f"{b58_encode(x_bytes)}.{b58_encode(y_bytes)}"

    @staticmethod
    def from_string(s: str) -> 'PointInFiniteField':
        """
        Create a point from its string representation.

        Args:
            s: String in format x.y where x and y are base58 encoded

        Returns:
            A PointInFiniteField object

        Raises:
            ValueError: If the string is not in the correct format
        """
        parts = s.split('.')
        if len(parts) < 2:
            raise ValueError(f"Invalid point format: {s}")

        x, y = parts[0], parts[1]

        # Decode base58 strings to bytes, then to integers
        x_int = int.from_bytes(b58_decode(x), 'big')
        y_int = int.from_bytes(b58_decode(y), 'big')

        return PointInFiniteField(x_int, y_int)


class Polynomial:
    """
    A class representing a polynomial for Shamir's Secret Sharing.

    This is used to split a private key into shares such that a certain
    threshold of shares is required to reconstruct the key.
    """

    def __init__(self, points: List[PointInFiniteField], threshold: Optional[int] = None):
        """
        Initialize a polynomial with the given points.

        Args:
            points: List of points defining the polynomial
            threshold: Number of points required to reconstruct the polynomial.
                      If None, uses the length of points.
        """
        self.points = points
        # Default threshold is the number of points if not specified
        self.threshold = threshold if threshold is not None else len(points)

    @staticmethod
    def from_private_key(private_key_int: int, threshold: int) -> 'Polynomial':
        """
        Create a polynomial from a private key.

        The private key becomes the y-intercept (at x=0) of the polynomial.
        Additional random points are generated to define the polynomial.

        Args:
            private_key_int: The private key (integer))
            threshold: Number of shares required to reconstruct the key

        Returns:
            A Polynomial object
        """

        # Create first point at x=0, y=private_key
        points = [PointInFiniteField(0, private_key_int)]

        # Generate additional random coefficients (as points)
        for i in range(1, threshold):
            # Generate cryptographically secure random values for x and y
            # The random function from secrets should be more secure than random
            random_x_bytes = secrets.token_bytes(32)
            random_y_bytes = secrets.token_bytes(32)

            # Convert to integers and take modulo p
            random_x = int.from_bytes(random_x_bytes, 'big') % curve.p
            random_y = int.from_bytes(random_y_bytes, 'big') % curve.p

            points.append(PointInFiniteField(random_x, random_y))

        return Polynomial(points)

    def value_at(self, x: Union[int, bytes]) -> int:
        """
        Evaluate the polynomial at the given x coordinate using Lagrange interpolation.

        Args:
            x: The x coordinate at which to evaluate the polynomial

        Returns:
            The y coordinate (as integer) corresponding to the given x
        """
        # Convert x to integer if it's bytes
        if isinstance(x, bytes):
            x = int.from_bytes(x, 'big')

        # Ensure x is within the field
        x = x % curve.p

        # Initialize result
        y = 0

        # Lagrange interpolation
        for i in range(self.threshold):
            term = self.points[i].y
            for j in range(self.threshold):
                if i != j:
                    xi = self.points[i].x
                    xj = self.points[j].x

                    # Calculate numerator: (x - xj) mod p
                    numerator = (x - xj) % curve.p

                    # Calculate denominator: (xi - xj) mod p
                    denominator = (xi - xj) % curve.p

                    # Calculate modular inverse of denominator
                    # pow(base, exponent, modulus) computes (base^exponent) % modulus
                    # When exponent is -1, it computes the modular multiplicative inverse
                    denominator_inverse = pow(denominator, -1, curve.p)

                    # Calculate the fraction: numerator * denominator_inverse mod p
                    fraction = (numerator * denominator_inverse) % curve.p

                    # Multiply the current term by the fraction
                    term = (term * fraction) % curve.p

            # Add this term to the result
            y = (y + term) % curve.p

        return y


class KeyShares:
    """
    A class representing key shares for Shamir's Secret Sharing.

    This is used to store the shares of a split private key along with
    metadata like threshold and integrity hash.
    """

    def __init__(self, points: List[PointInFiniteField], threshold: int, integrity: str):
        """
        Initialize key shares.

        Args:
            points: List of points representing the shares
            threshold: Number of shares required to reconstruct the key
            integrity: Integrity check hash derived from the public key
        """
        self.points = points
        self.threshold = threshold
        self.integrity = integrity

    @staticmethod
    def from_backup_format(shares: List[str]) -> 'KeyShares':
        """
        Create KeyShares from backup format strings.

        Args:
            shares: List of share strings in format "x.y.t.i"

        Returns:
            A KeyShares object

        Raises:
            ValueError: If shares have invalid format or inconsistent threshold/integrity
        """
        threshold = 0
        integrity = ''
        points = []

        for idx, share in enumerate(shares):
            # Split the share string into parts
            share_parts = share.split('.')
            if len(share_parts) != 4:
                raise ValueError(
                    f'Invalid share format in share {idx}. '
                    f'Expected format: "x.y.t.i" - received {share}'
                )

            # Parse the parts
            x, y, t, i = share_parts

            if not t:
                raise ValueError(f'Threshold not found in share {idx}')
            if not i:
                raise ValueError(f'Integrity not found in share {idx}')

            # Parse threshold as integer
            t_int = int(t)

            # Check consistency across shares
            if idx > 0 and threshold != t_int:
                raise ValueError(f'Threshold mismatch in share {idx}')
            if idx > 0 and integrity != i:
                raise ValueError(f'Integrity mismatch in share {idx}')

            threshold = t_int
            integrity = i

            # Create point from x and y components
            point = PointInFiniteField.from_string(f"{x}.{y}")
            points.append(point)

        return KeyShares(points, threshold, integrity)

    def to_backup_format(self) -> List[str]:
        """
        Convert shares to backup format strings.

        Returns:
            List of share strings in format "x.y.t.i"
        """
        return [
            f"{point}.{self.threshold}.{self.integrity}"
            for point in map(str, self.points)
        ]