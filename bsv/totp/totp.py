"""
TOTP (Time-based One-Time Password) implementation.

This module provides TOTP generation and validation following RFC 6238,
matching the TypeScript SDK implementation.
"""
import time
from typing import Optional, Literal, Union
from bsv.hash import hmac_sha1, hmac_sha256, hmac_sha512


TOTPAlgorithm = Literal['SHA-1', 'SHA-256', 'SHA-512']


class TOTPOptions:
    """Options for TOTP generation."""
    def __init__(
        self,
        digits: int = 6,
        algorithm: TOTPAlgorithm = 'SHA-1',
        period: int = 30,
        timestamp: Optional[int] = None
    ):
        self.digits = digits
        self.algorithm = algorithm
        self.period = period
        self.timestamp = timestamp if timestamp is not None else int(time.time() * 1000)


class TOTPValidateOptions(TOTPOptions):
    """Options for TOTP validation."""
    def __init__(
        self,
        digits: int = 6,
        algorithm: TOTPAlgorithm = 'SHA-1',
        period: int = 30,
        timestamp: Optional[int] = None,
        skew: int = 1
    ):
        super().__init__(digits, algorithm, period, timestamp)
        self.skew = skew


class TOTP:
    """
    Time-based One-Time Password (TOTP) generator and validator.
    
    This class implements TOTP according to RFC 6238, matching the
    TypeScript SDK implementation exactly.
    """
    
    @staticmethod
    def generate(secret: bytes, options: Optional[Union[dict, TOTPOptions]] = None) -> str:
        """
        Generates a Time-based One-Time Password (TOTP).
        
        Args:
            secret: The secret key for TOTP as bytes
            options: Optional parameters for TOTP. Can be a dict or TOTPOptions instance.
                    Supported keys: digits (default 6), algorithm (default 'SHA-1'),
                    period (default 30), timestamp (default current time)
        
        Returns:
            The generated TOTP as a string
        """
        _options = TOTP._with_default_options(options)
        
        counter = TOTP._get_counter(_options.timestamp, _options.period)
        otp = TOTP._generate_hotp(secret, counter, _options)
        return otp
    
    @staticmethod
    def validate(
        secret: bytes,
        passcode: str,
        options: Optional[Union[dict, TOTPValidateOptions]] = None
    ) -> bool:
        """
        Validates a Time-based One-Time Password (TOTP).
        
        Args:
            secret: The secret key for TOTP as bytes
            passcode: The passcode to validate
            options: Optional parameters for TOTP validation. Can be a dict or TOTPValidateOptions.
                    Supported keys: digits, algorithm, period, timestamp, skew (default 1)
        
        Returns:
            True if the passcode is valid, False otherwise
        """
        _options = TOTP._with_default_validate_options(options)
        passcode = passcode.strip()
        
        if len(passcode) != _options.digits:
            return False
        
        counter = TOTP._get_counter(_options.timestamp, _options.period)
        
        counters = [counter]
        for i in range(1, _options.skew + 1):
            counters.append(counter + i)
            counters.append(counter - i)
        
        for c in counters:
            if passcode == TOTP._generate_hotp(secret, c, _options):
                return True
        
        return False
    
    @staticmethod
    def _get_counter(timestamp: int, period: int) -> int:
        """Calculate the counter value from timestamp and period."""
        epoch_seconds = timestamp // 1000
        counter = epoch_seconds // period
        return counter
    
    @staticmethod
    def _with_default_options(options: Optional[Union[dict, TOTPOptions]]) -> TOTPOptions:
        """Apply default options."""
        if options is None:
            return TOTPOptions()
        
        if isinstance(options, dict):
            return TOTPOptions(
                digits=options.get('digits', 6),
                algorithm=options.get('algorithm', 'SHA-1'),
                period=options.get('period', 30),
                timestamp=options.get('timestamp')
            )
        
        return options
    
    @staticmethod
    def _with_default_validate_options(
        options: Optional[Union[dict, TOTPValidateOptions]]
    ) -> TOTPValidateOptions:
        """Apply default validation options."""
        if options is None:
            return TOTPValidateOptions()
        
        if isinstance(options, dict):
            return TOTPValidateOptions(
                digits=options.get('digits', 6),
                algorithm=options.get('algorithm', 'SHA-1'),
                period=options.get('period', 30),
                timestamp=options.get('timestamp'),
                skew=options.get('skew', 1)
            )
        
        if isinstance(options, TOTPOptions):
            return TOTPValidateOptions(
                digits=options.digits,
                algorithm=options.algorithm,
                period=options.period,
                timestamp=options.timestamp,
                skew=1
            )
        
        return options
    
    @staticmethod
    def _generate_hotp(secret: bytes, counter: int, options: TOTPOptions) -> str:
        """
        Generate HOTP (HMAC-based One-Time Password) from counter.
        
        This implements RFC 4226 section 5.4.
        """
        # Convert counter to 8-byte big-endian array
        # Handle negative counters by converting to unsigned representation
        if counter < 0:
            # Convert negative to unsigned 64-bit representation
            counter = (1 << 64) + counter
        time_pad = counter.to_bytes(8, byteorder='big')
        
        # Calculate HMAC
        hmac_result = TOTP._calc_hmac(secret, time_pad, options.algorithm)
        
        # RFC 4226 https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
        # offset is the last 4 bits of the last byte in the hmac
        offset = hmac_result[-1] & 0x0f
        
        # Starting from offset, get 4 bytes
        four_bytes_range = hmac_result[offset:offset + 4]
        
        # Convert to 32-bit integer (big-endian)
        masked = int.from_bytes(four_bytes_range, byteorder='big') & 0x7fffffff
        
        # Get last 'digits' digits
        otp_str = str(masked)
        if len(otp_str) < options.digits:
            # Pad with leading zeros if needed
            otp_str = otp_str.zfill(options.digits)
        
        return otp_str[-options.digits:]
    
    @staticmethod
    def _calc_hmac(secret: bytes, time_pad: bytes, algorithm: TOTPAlgorithm) -> bytes:
        """Calculate HMAC based on algorithm."""
        if algorithm == 'SHA-1':
            return hmac_sha1(secret, time_pad)
        elif algorithm == 'SHA-256':
            return hmac_sha256(secret, time_pad)
        elif algorithm == 'SHA-512':
            return hmac_sha512(secret, time_pad)
        else:
            raise ValueError('unsupported HMAC algorithm')

