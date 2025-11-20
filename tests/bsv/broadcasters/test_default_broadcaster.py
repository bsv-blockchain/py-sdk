"""
Tests for default_broadcaster function.

Ported from TypeScript SDK.
"""

import pytest
from bsv.broadcasters.default_broadcaster import default_broadcaster
from bsv.broadcasters.arc import ARC
from bsv.constants import Network


class TestDefaultBroadcaster:
    """Test default_broadcaster function."""

    def test_default_broadcaster_mainnet(self):
        """Test default_broadcaster creates ARC broadcaster for mainnet."""
        broadcaster = default_broadcaster()

        # Should create an ARC broadcaster
        assert isinstance(broadcaster, ARC)
        assert broadcaster.URL == "https://arc.gorillapool.io"

    def test_default_broadcaster_testnet(self):
        """Test default_broadcaster creates ARC broadcaster for testnet."""
        broadcaster = default_broadcaster(is_testnet=True)

        # Should create an ARC broadcaster with testnet URL
        assert isinstance(broadcaster, ARC)
        assert broadcaster.URL == "https://testnet.arc.gorillapool.io"

    def test_default_broadcaster_with_config(self):
        """Test default_broadcaster with custom config."""
        from bsv.broadcasters.arc import ARCConfig

        config = ARCConfig(api_key="test-key")  # noqa: S106  # NOSONAR - Mock API key for tests
        broadcaster = default_broadcaster(is_testnet=False, config=config)

        # Should create an ARC broadcaster with config
        assert isinstance(broadcaster, ARC)
        assert broadcaster.URL == "https://arc.gorillapool.io"
        assert broadcaster.api_key == "test-key"

    def test_default_broadcaster_testnet_with_config(self):
        """Test default_broadcaster for testnet with custom config."""
        from bsv.broadcasters.arc import ARCConfig

        config = ARCConfig(api_key="test-key")  # noqa: S106  # NOSONAR - Mock API key for tests
        broadcaster = default_broadcaster(is_testnet=True, config=config)

        # Should create an ARC broadcaster with testnet URL and config
        assert isinstance(broadcaster, ARC)
        assert broadcaster.URL == "https://testnet.arc.gorillapool.io"
        assert broadcaster.api_key == "test-key"
