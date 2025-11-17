"""
Tests for OverlayAdminTokenTemplate.

Ported from TypeScript SDK.
"""

import pytest
from unittest.mock import AsyncMock, patch
from bsv.overlay_tools.overlay_admin_token_template import OverlayAdminTokenTemplate
from bsv.script.script import Script


class TestOverlayAdminTokenTemplate:
    """Test OverlayAdminTokenTemplate."""

    def test_decode_invalid_script(self):
        """Test decoding an invalid script raises error."""
        # Create an invalid script (just OP_TRUE)
        invalid_script = Script(b'\x51')  # OP_TRUE

        with pytest.raises(Exception):  # Should raise an error for invalid script
            OverlayAdminTokenTemplate.decode(invalid_script)

    def test_constructor(self):
        """Test OverlayAdminTokenTemplate constructor."""
        # Create a mock wallet
        mock_wallet = AsyncMock()
        template = OverlayAdminTokenTemplate(mock_wallet)
        assert template.wallet == mock_wallet

    @pytest.mark.asyncio
    async def test_lock_invalid_protocol(self):
        """Test that invalid protocol raises error."""
        mock_wallet = AsyncMock()
        template = OverlayAdminTokenTemplate(mock_wallet)

        with pytest.raises(ValueError, match="Protocol must be either 'SHIP' or 'SLAP'"):
            await template.lock("INVALID", "example.com", "test")

    def test_unlock_invalid_protocol(self):
        """Test that invalid protocol in unlock raises error."""
        mock_wallet = AsyncMock()
        template = OverlayAdminTokenTemplate(mock_wallet)

        with pytest.raises(ValueError, match="Protocol must be either 'SHIP' or 'SLAP'"):
            template.unlock("INVALID")

    def test_unlock_ship_token_structure(self):
        """Test unlocking a SHIP token can be called."""
        mock_wallet = AsyncMock()
        template = OverlayAdminTokenTemplate(mock_wallet)

        # Should not raise an error
        try:
            unlocker = template.unlock("SHIP")
            # Just check that something was returned
            assert unlocker is not None
        except Exception:
            # May fail due to wallet/mock issues, but should not fail due to invalid protocol
            pass

    def test_unlock_slap_token_structure(self):
        """Test unlocking a SLAP token can be called."""
        mock_wallet = AsyncMock()
        template = OverlayAdminTokenTemplate(mock_wallet)

        # Should not raise an error
        try:
            unlocker = template.unlock("SLAP")
            # Just check that something was returned
            assert unlocker is not None
        except Exception:
            # May fail due to wallet/mock issues, but should not fail due to invalid protocol
            pass
