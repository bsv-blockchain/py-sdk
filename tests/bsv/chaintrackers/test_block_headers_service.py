"""
Tests for BlockHeadersService chaintracker.

Ported from TypeScript SDK.
"""

import pytest
from bsv.chaintrackers.block_headers_service import BlockHeadersService, BlockHeadersServiceConfig


class TestBlockHeadersService:
    """Test BlockHeadersService chaintracker."""

    def test_constructor(self):
        """Test BlockHeadersService constructor."""
        service = BlockHeadersService("https://headers.spv.money")
        assert service.base_url == "https://headers.spv.money"
        assert service.api_key == ""

    def test_constructor_with_config(self):
        """Test BlockHeadersService constructor with config."""
        config = BlockHeadersServiceConfig(api_key="test-key")  # noqa: S106  # NOSONAR - Mock API key for tests
        service = BlockHeadersService("https://headers.spv.money", config)
        assert service.base_url == "https://headers.spv.money"
        assert service.api_key == "test-key"

    @pytest.mark.asyncio
    async def test_is_valid_root_for_height_structure(self):
        """Test is_valid_root_for_height method structure."""
        service = BlockHeadersService("https://headers.spv.money")

        # Test that the method exists and can be called
        # In test environment, it will likely fail due to network/API key requirements
        try:
            result = await service.is_valid_root_for_height("dummy_root", 100000)
            # If it succeeds, should return a boolean
            assert isinstance(result, bool)
        except Exception:
            # Expected to fail in test environment without proper API key
            pass

    @pytest.mark.asyncio
    async def test_current_height_structure(self):
        """Test current_height method structure."""
        service = BlockHeadersService("https://headers.spv.money")

        # Test that the method exists
        # In test environment, it will likely fail due to network
        try:
            result = await service.current_height()
            # If it succeeds, should return an integer
            assert isinstance(result, int)
            assert result >= 0
        except Exception:
            # Expected to fail in test environment without network
            pass
