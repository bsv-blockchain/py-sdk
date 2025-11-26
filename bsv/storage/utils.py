import hashlib
from typing import Optional
from bsv.base58 import to_base58check, from_base58check

UHRP_PREFIX = b"\xce\x00"  # 2-byte prefix for UHRP URLs (same as TS/GO SDK)
UHRP_PREFIX_STR = "uhrp://"

class StorageUtils:
    """
    Utility functions for UHRP URL validation, normalization, hash extraction, and URL generation.
    Compatible with TS/GO SDK UHRP conventions.
    """
    @staticmethod
    def normalize_url(uhrp_url: str) -> str:
        """
        Normalize a UHRP URL by removing known prefixes.
        :param uhrp_url: UHRP URL string
        :return: Normalized URL string (no prefix)
        """
        url = uhrp_url.lower()
        if url.startswith("web+uhrp://"):
            return uhrp_url[11:]
        if url.startswith("uhrp://"):
            return uhrp_url[7:]
        return uhrp_url

    @staticmethod
    def is_valid_url(uhrp_url: str) -> bool:
        """
        Check if a UHRP URL is valid (correct prefix, decodable, correct hash length).
        :param uhrp_url: UHRP URL string
        :return: True if valid, False otherwise
        """
        try:
            StorageUtils.get_hash_from_url(uhrp_url)
            return True
        except Exception:
            return False

    @staticmethod
    def get_hash_from_url(uhrp_url: str) -> bytes:
        """
        Extract the SHA256 hash from a UHRP URL (Base58Check decode and prefix check).
        :param uhrp_url: UHRP URL string
        :return: SHA256 hash as bytes
        :raises ValueError: If prefix or hash length is invalid
        """
        url = StorageUtils.normalize_url(uhrp_url)
        prefix, data = from_base58check(url, prefix_len=2)
        if prefix != UHRP_PREFIX:
            raise ValueError("Bad prefix for UHRP URL")
        if len(data) != 32:
            raise ValueError("Invalid hash length in UHRP URL")
        return data

    @staticmethod
    def get_url_for_file(file_data: bytes) -> str:
        """
        Generate a UHRP URL from file data (SHA256 hash, Base58Check encode, add prefix).
        :param file_data: File content as bytes
        :return: UHRP URL string
        """
        h = hashlib.sha256(file_data).digest()
        url = to_base58check(h, UHRP_PREFIX)
        return f"uhrp://{url}"
