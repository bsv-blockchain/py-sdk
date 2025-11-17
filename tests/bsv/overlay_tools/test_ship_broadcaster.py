"""
Tests for SHIPBroadcaster.

Ported from TypeScript SDK.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from bsv.overlay_tools.ship_broadcaster import (
    TopicBroadcaster,
    SHIPBroadcaster,
    SHIPCast,
    SHIPBroadcasterConfig,
    TaggedBEEF,
    AdmittanceInstructions,
    HTTPSOverlayBroadcastFacilitator
)
from bsv.transaction import Transaction
from bsv.broadcasters.broadcaster import BroadcastResponse, BroadcastFailure


class TestSHIPBroadcaster:
    """Test SHIPBroadcaster."""

    def test_tagged_beef_creation(self):
        """Test TaggedBEEF can be created."""
        beef = b"test_beef"
        topics = ["tm_test"]
        tagged = TaggedBEEF(beef=beef, topics=topics)
        assert tagged.beef == beef
        assert tagged.topics == topics
        assert tagged.off_chain_values is None

    def test_admittance_instructions_creation(self):
        """Test AdmittanceInstructions can be created."""
        instructions = AdmittanceInstructions(
            outputs_to_admit=[0, 1],
            coins_to_retain=[1000],
            coins_removed=[500]
        )
        assert instructions.outputs_to_admit == [0, 1]
        assert instructions.coins_to_retain == [1000]
        assert instructions.coins_removed == [500]

    def test_ship_broadcaster_config_creation(self):
        """Test SHIPBroadcasterConfig can be created."""
        config = SHIPBroadcasterConfig(network_preset="mainnet")
        assert config.network_preset == "mainnet"
        assert config.facilitator is None

    def test_https_overlay_broadcast_facilitator_creation(self):
        """Test HTTPSOverlayBroadcastFacilitator can be created."""
        facilitator = HTTPSOverlayBroadcastFacilitator()
        assert not facilitator.allow_http

        facilitator_http = HTTPSOverlayBroadcastFacilitator(allow_http=True)
        assert facilitator_http.allow_http

    def test_topic_broadcaster_creation_valid_topics(self):
        """Test TopicBroadcaster can be created with valid topics."""
        broadcaster = TopicBroadcaster(["tm_test_topic"])
        assert broadcaster.topics == ["tm_test_topic"]
        assert broadcaster.network_preset == "mainnet"

    def test_topic_broadcaster_creation_invalid_topics_empty(self):
        """Test TopicBroadcaster rejects empty topics."""
        with pytest.raises(ValueError, match="At least one topic is required"):
            TopicBroadcaster([])

    def test_topic_broadcaster_creation_invalid_topics_no_prefix(self):
        """Test TopicBroadcaster rejects topics without tm_ prefix."""
        with pytest.raises(ValueError, match='Every topic must start with "tm_"'):
            TopicBroadcaster(["invalid_topic"])

    def test_topic_broadcaster_creation_with_config(self):
        """Test TopicBroadcaster can be created with config."""
        config = SHIPBroadcasterConfig(network_preset="testnet")
        broadcaster = TopicBroadcaster(["tm_test"], config)
        assert broadcaster.network_preset == "testnet"

    def test_ship_broadcaster_aliases(self):
        """Test SHIPBroadcaster and SHIPCast are aliases."""
        assert SHIPBroadcaster is TopicBroadcaster
        assert SHIPCast is TopicBroadcaster

    @pytest.mark.asyncio
    async def test_topic_broadcaster_broadcast_invalid_beef(self):
        """Test broadcast fails with invalid BEEF."""
        broadcaster = TopicBroadcaster(["tm_test"])

        # Create a transaction that can't be converted to BEEF
        tx = MagicMock(spec=Transaction)
        tx.to_beef.side_effect = Exception("Invalid BEEF")

        result = await broadcaster.broadcast(tx)

        assert isinstance(result, BroadcastFailure)
        assert result.code == "ERR_INVALID_BEEF"
        assert "BEEF format" in result.description

    @pytest.mark.asyncio
    async def test_topic_broadcaster_broadcast_no_hosts(self):
        """Test broadcast fails when no hosts are interested."""
        broadcaster = TopicBroadcaster(["tm_test"])

        # Mock resolver to return empty results
        broadcaster.resolver = MagicMock()
        broadcaster.resolver.query = AsyncMock(return_value=MagicMock(type="output-list", outputs=[]))

        # Create a valid transaction mock
        tx = MagicMock(spec=Transaction)
        tx.to_beef.return_value = b"mock_beef"
        tx.txid.return_value = "mock_txid"

        result = await broadcaster.broadcast(tx)

        assert isinstance(result, BroadcastFailure)
        assert result.code == "ERR_NO_HOSTS_INTERESTED"

    def test_topic_broadcaster_local_network_preset(self):
        """Test TopicBroadcaster uses local preset correctly."""
        config = SHIPBroadcasterConfig(network_preset="local")
        broadcaster = TopicBroadcaster(["tm_test"], config)
        assert broadcaster.network_preset == "local"

        # Should allow HTTP
        assert isinstance(broadcaster.facilitator, HTTPSOverlayBroadcastFacilitator)
        assert broadcaster.facilitator.allow_http

    def test_has_meaningful_instructions(self):
        """Test _has_meaningful_instructions method."""
        broadcaster = TopicBroadcaster(["tm_test"])

        # Test with meaningful instructions
        instructions = AdmittanceInstructions(
            outputs_to_admit=[0],
            coins_to_retain=[],
            coins_removed=[]
        )
        assert broadcaster._has_meaningful_instructions(instructions)

        # Test with no meaningful instructions
        empty_instructions = AdmittanceInstructions(
            outputs_to_admit=[],
            coins_to_retain=[],
            coins_removed=[]
        )
        assert not broadcaster._has_meaningful_instructions(empty_instructions)

    def test_check_acknowledgment_requirements_no_requirements(self):
        """Test acknowledgment requirements with no requirements."""
        broadcaster = TopicBroadcaster(["tm_test"])

        # No requirements set
        broadcaster.require_acknowledgment_from_any_host_for_topics = None
        broadcaster.require_acknowledgment_from_all_hosts_for_topics = None
        broadcaster.require_acknowledgment_from_specific_hosts_for_topics = {}

        # Should pass with any acknowledgments
        result = broadcaster._check_acknowledgment_requirements({})
        assert result

    def test_check_acknowledgment_requirements_any_host(self):
        """Test acknowledgment requirements for any host."""
        broadcaster = TopicBroadcaster(["tm_test"])
        broadcaster.require_acknowledgment_from_any_host_for_topics = ["tm_test"]
        broadcaster.require_acknowledgment_from_all_hosts_for_topics = None
        broadcaster.require_acknowledgment_from_specific_hosts_for_topics = {}

        # Should pass if any host acknowledges the topic
        host_acknowledgments = {"host1": {"tm_test"}}
        result = broadcaster._check_acknowledgment_requirements(host_acknowledgments)
        assert result

        # Should fail if no host acknowledges the topic
        host_acknowledgments = {"host1": {"tm_other"}}
        result = broadcaster._check_acknowledgment_requirements(host_acknowledgments)
        assert not result

    def test_check_acknowledgment_requirements_specific_hosts(self):
        """Test acknowledgment requirements for specific hosts."""
        broadcaster = TopicBroadcaster(["tm_test"])
        broadcaster.require_acknowledgment_from_any_host_for_topics = None
        broadcaster.require_acknowledgment_from_all_hosts_for_topics = None
        broadcaster.require_acknowledgment_from_specific_hosts_for_topics = {
            "host1": ["tm_test"]
        }

        # Should pass if specific host acknowledges required topic
        host_acknowledgments = {"host1": {"tm_test"}}
        result = broadcaster._check_acknowledgment_requirements(host_acknowledgments)
        assert result

        # Should fail if specific host doesn't acknowledge required topic
        host_acknowledgments = {"host1": {"tm_other"}}
        result = broadcaster._check_acknowledgment_requirements(host_acknowledgments)
        assert not result

        # Should fail if specific host is missing
        host_acknowledgments = {"host2": {"tm_test"}}
        result = broadcaster._check_acknowledgment_requirements(host_acknowledgments)
        assert not result
