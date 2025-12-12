"""
GullibleHeadersClient - Test-only chain tracker implementation.

WARNING: DO NOT USE IN PRODUCTION!

This client accepts any merkle root as valid without verification.
It is intended ONLY for testing script validation without requiring
actual blockchain verification.

Security Risk: Using this client in production would completely bypass
merkle root validation, making your application vulnerable to attacks.
"""

from bsv.chaintracker import ChainTracker


class GullibleHeadersClient(ChainTracker):
    """
    A test-only chain tracker that accepts any merkle root as valid.
    
    This implementation is ported from Go-SDK's spv/scripts_only.go.
    It is used internally by verify_scripts() to allow script-only
    verification without merkle proof validation.
    
    WARNING: This class should NEVER be used in production code.
    It completely bypasses merkle root verification, which is a critical
    security feature. Use only for testing purposes.
    
    Example:
        >>> client = GullibleHeadersClient()
        >>> # Always returns True - DO NOT USE IN PRODUCTION
        >>> await client.is_valid_root_for_height("any_root", 100)
        True
        >>> # Returns dummy height
        >>> await client.current_height()
        800000
    """
    
    async def is_valid_root_for_height(self, root: str, height: int) -> bool:
        """
        Always returns True without verifying the merkle root.
        
        DO NOT USE IN A REAL PROJECT due to security risks of accepting
        any merkle root as valid without verification.
        
        Args:
            root: Merkle root (ignored - always accepted)
            height: Block height (ignored)
            
        Returns:
            Always True (for testing purposes only)
        """
        # DO NOT USE IN A REAL PROJECT due to security risks of accepting
        # any merkle root as valid without verification
        return True
    
    async def current_height(self) -> int:
        """
        Returns a dummy height for testing.
        
        Returns:
            Always returns 800000 (dummy height for testing)
        """
        return 800000  # Return a dummy height for testing

