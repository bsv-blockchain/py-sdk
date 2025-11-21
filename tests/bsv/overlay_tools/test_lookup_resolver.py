"""
Tests for LookupResolver.

Ported from TypeScript SDK.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from bsv.overlay_tools.lookup_resolver import (
    LookupResolver,
    LookupResolverConfig,
    LookupQuestion,
    LookupAnswer,
    LookupOutput,
    HTTPSOverlayLookupFacilitator,
    CacheOptions
)


class TestLookupResolver:
    """Test LookupResolver."""

    def test_lookup_question_creation(self):
        """Test LookupQuestion can be created."""
        question = LookupQuestion(service="ls_test", query={"key": "value"})
        assert question.service == "ls_test"
        assert question.query == {"key": "value"}

    def test_lookup_answer_creation(self):
        """Test LookupAnswer can be created."""
        answer = LookupAnswer()
        assert answer.type == "output-list"
        assert answer.outputs == []

    def test_lookup_output_creation(self):
        """Test LookupOutput can be created."""
        output = LookupOutput(beef=b"test", output_index=0)
        assert output.beef == b"test"
        assert output.output_index == 0
        assert output.context is None

    def test_lookup_resolver_config_creation(self):
        """Test LookupResolverConfig can be created."""
        config = LookupResolverConfig(network_preset="mainnet")
        assert config.network_preset == "mainnet"
        assert config.facilitator is None

    def test_cache_options_creation(self):
        """Test CacheOptions can be created."""
        cache = CacheOptions(hosts_ttl_ms=10000)
        assert cache.hosts_ttl_ms == 10000
        assert cache.hosts_max_entries is None

    def test_https_overlay_lookup_facilitator_creation(self):
        """Test HTTPSOverlayLookupFacilitator can be created."""
        facilitator = HTTPSOverlayLookupFacilitator()
        assert not facilitator.allow_http

        facilitator_http = HTTPSOverlayLookupFacilitator(allow_http=True)
        assert facilitator_http.allow_http

    @pytest.mark.asyncio
    async def test_https_facilitator_lookup_invalid_url(self):
        """Test HTTPS facilitator rejects non-HTTPS URLs."""
        from bsv.overlay_tools.lookup_resolver import HTTPProtocolError
        facilitator = HTTPSOverlayLookupFacilitator(allow_http=False)
        question = LookupQuestion(service="test", query={})

        with pytest.raises(HTTPProtocolError, match="HTTPS facilitator can only use URLs"):
            # Using HTTP intentionally to test security feature that rejects insecure URLs
            await facilitator.lookup("http://example.com", question)  # noqa: S113  # NOSONAR

    def test_lookup_resolver_creation(self):
        """Test LookupResolver can be created."""
        resolver = LookupResolver()
        assert resolver.network_preset == "mainnet"
        assert resolver.facilitator is not None
        assert len(resolver.slap_trackers) > 0

    def test_lookup_resolver_creation_with_config(self):
        """Test LookupResolver can be created with config."""
        config = LookupResolverConfig(network_preset="testnet")
        resolver = LookupResolver(config)
        assert resolver.network_preset == "testnet"

    @pytest.mark.asyncio
    async def test_lookup_resolver_query_no_hosts(self):
        """Test query fails when no competent hosts found."""
        resolver = LookupResolver()

        # Mock _get_competent_hosts to return empty list
        resolver._get_competent_hosts = AsyncMock(return_value=[])

        question = LookupQuestion(service="ls_test", query={})

        with pytest.raises(Exception, match="No competent mainnet hosts found"):
            await resolver.query(question)

    @pytest.mark.asyncio
    async def test_lookup_resolver_prepare_hosts_empty(self):
        """Test _prepare_hosts_for_query with empty host list."""
        resolver = LookupResolver()
        hosts = resolver._prepare_hosts_for_query([], "test context")
        assert hosts == []

    @pytest.mark.asyncio
    async def test_lookup_resolver_prepare_hosts_backoff(self):
        """Test _prepare_hosts_for_query when all hosts are in backoff."""
        resolver = LookupResolver()

        # Mock host reputation to put all hosts in backoff
        resolver.host_reputation.rank_hosts = MagicMock(return_value=[
            MagicMock(host="https://example.com", backoff_until=float('inf'))
        ])

        with pytest.raises(Exception, match="All test context hosts are backing off"):
            resolver._prepare_hosts_for_query(["https://example.com"], "test context")

    def test_lookup_resolver_local_network_preset(self):
        """Test LookupResolver uses local preset correctly."""
        config = LookupResolverConfig(network_preset="local")
        resolver = LookupResolver(config)
        assert resolver.network_preset == "local"

        # Should allow HTTP
        assert isinstance(resolver.facilitator, HTTPSOverlayLookupFacilitator)
        assert resolver.facilitator.allow_http

    def test_lookup_resolver_host_overrides(self):
        """Test host overrides work correctly."""
        overrides = {"ls_test": ["https://override.example.com"]}
        config = LookupResolverConfig(host_overrides=overrides)
        resolver = LookupResolver(config)
        assert resolver.host_overrides == overrides

    def test_lookup_resolver_additional_hosts(self):
        """Test additional hosts work correctly."""
        additional = {"ls_test": ["https://additional.example.com"]}
        config = LookupResolverConfig(additional_hosts=additional)
        resolver = LookupResolver(config)
        assert resolver.additional_hosts == additional
