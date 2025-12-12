"""
Error definitions for the script interpreter.

This module provides error codes and error handling for script execution.
"""

from .error import Error, ErrorCode, is_error_code

__all__ = ["Error", "ErrorCode", "is_error_code"]
