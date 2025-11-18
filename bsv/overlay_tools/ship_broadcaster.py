"""
SHIPBroadcaster implementation - Advanced overlay broadcasting.

Ported from TypeScript SDK.
"""

import asyncio
from typing import Dict, List, Optional, Any, Protocol
from dataclasses import dataclass

from bsv.transaction import Transaction
from bsv.broadcasters.broadcaster import BroadcastResponse, BroadcastFailure
from .lookup_resolver import LookupResolver, LookupResolverConfig, LookupQuestion
from .overlay_admin_token_template import OverlayAdminTokenTemplate


@dataclass
class TaggedBEEF:
    """Tagged BEEF structure."""
    beef: bytes
    topics: List[str]
    off_chain_values: Optional[bytes] = None


@dataclass
class AdmittanceInstructions:
    """Instructs about which outputs to admit and retain."""
    outputs_to_admit: List[int]
    coins_to_retain: List[int]
    coins_removed: Optional[List[int]] = None


# Type alias for STEAK (Submitted Transaction Execution AcKnowledgment)
STEAK = Dict[str, AdmittanceInstructions]


@dataclass
class SHIPBroadcasterConfig:
    """Configuration options for the SHIP broadcaster."""
    network_preset: Optional[str] = None  # 'mainnet', 'testnet', or 'local'
    facilitator: Optional['OverlayBroadcastFacilitator'] = None
    resolver: Optional[LookupResolver] = None
    require_acknowledgment_from_all_hosts_for_topics: Optional[List[str]] = None
    require_acknowledgment_from_any_host_for_topics: Optional[List[str]] = None
    require_acknowledgment_from_specific_hosts_for_topics: Optional[Dict[str, List[str]]] = None


class OverlayBroadcastFacilitator(Protocol):
    """Facilitates transaction broadcasts that return STEAK."""

    async def send(self, url: str, tagged_beef: TaggedBEEF) -> STEAK:
        """Send tagged BEEF to a URL and return STEAK."""
        ...


class HTTPSOverlayBroadcastFacilitator:
    """Facilitates broadcasts using HTTPS."""

    def __init__(self, allow_http: bool = False):
        import aiohttp
        self.allow_http = allow_http

    async def send(self, url: str, tagged_beef: TaggedBEEF) -> STEAK:
        """Send tagged BEEF to overlay host."""
        import aiohttp

        if not url.startswith('https:') and not self.allow_http:
            raise ValueError('HTTPS facilitator can only use URLs that start with "https:"')

        headers = {
            'Content-Type': 'application/octet-stream',
            'X-Topics': ','.join(tagged_beef.topics)
        }

        body = tagged_beef.beef
        if tagged_beef.off_chain_values:
            headers['x-includes-off-chain-values'] = 'true'
            # Combine BEEF and off-chain values
            from bsv.utils import Writer
            writer = Writer()
            writer.write_varint(len(tagged_beef.beef))
            writer.write(tagged_beef.beef)
            writer.write(tagged_beef.off_chain_values)
            body = writer.to_bytes()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{url}/submit",
                    headers=headers,
                    data=body
                ) as response:
                    if response.ok:
                        return await response.json()
                    else:
                        error_text = await response.text()
                        raise Exception(f"Broadcast failed: {error_text}")

        except Exception as e:
            raise Exception(f"Broadcast failed: {str(e)}")


class TopicBroadcaster:
    """
    Broadcasts transactions to one or more overlay topics via SHIP.

    Also known as SHIPBroadcaster or SHIPCast.
    """

    MAX_SHIP_QUERY_TIMEOUT = 5000

    def __init__(self, topics: List[str], config: Optional[SHIPBroadcasterConfig] = None):
        if not topics:
            raise ValueError('At least one topic is required for broadcast.')

        if any(not topic.startswith('tm_') for topic in topics):
            raise ValueError('Every topic must start with "tm_".')

        self.topics = topics
        config = config or SHIPBroadcasterConfig()

        self.network_preset = config.network_preset or 'mainnet'
        self.facilitator = config.facilitator or HTTPSOverlayBroadcastFacilitator(
            allow_http=self.network_preset == 'local'
        )
        self.resolver = config.resolver or LookupResolver(
            LookupResolverConfig(network_preset=self.network_preset)
        )

        self.require_acknowledgment_from_all_hosts_for_topics = \
            config.require_acknowledgment_from_all_hosts_for_topics
        self.require_acknowledgment_from_any_host_for_topics = \
            config.require_acknowledgment_from_any_host_for_topics or self.topics
        self.require_acknowledgment_from_specific_hosts_for_topics = \
            config.require_acknowledgment_from_specific_hosts_for_topics or {}

    async def broadcast(self, tx: Transaction) -> BroadcastResponse | BroadcastFailure:
        """Broadcast a transaction to Overlay Services via SHIP."""
        # Convert transaction to BEEF
        try:
            beef = tx.to_beef()
        except Exception as e:
            return BroadcastFailure(
                status="error",
                code="ERR_INVALID_BEEF",
                description=f"Transactions sent via SHIP must be serializable to BEEF format: {str(e)}"
            )

        # Check for off-chain values metadata
        off_chain_values = None
        if hasattr(tx, 'metadata') and tx.metadata:
            off_chain_values = tx.metadata.get('OffChainValues')
            if off_chain_values and not isinstance(off_chain_values, bytes):
                off_chain_values = bytes(off_chain_values)

        # Find interested hosts
        interested_hosts = await self._find_interested_hosts()
        if not interested_hosts:
            return BroadcastFailure(
                status="error",
                code="ERR_NO_HOSTS_INTERESTED",
                description=f"No {self.network_preset} hosts are interested in receiving this transaction."
            )

        # Send to all interested hosts
        host_promises = []
        for host, topics in interested_hosts.items():
            tagged_beef = TaggedBEEF(
                beef=beef,
                topics=list(topics),
                off_chain_values=off_chain_values
            )
            host_promises.append(self._send_to_host_with_tracking(host, tagged_beef))

        # Wait for all responses
        results = await asyncio.gather(*host_promises, return_exceptions=True)

        # Process results
        successful_hosts = []
        host_acknowledgments: Dict[str, set] = {}

        for i, result in enumerate(results):
            host = list(interested_hosts.keys())[i]

            if isinstance(result, Exception):
                continue

            steak = result
            if not steak or not isinstance(steak, dict):
                continue

            acknowledged_topics = set()
            for topic, instructions in steak.items():
                if self._has_meaningful_instructions(instructions):
                    acknowledged_topics.add(topic)

            if acknowledged_topics:
                successful_hosts.append(host)
                host_acknowledgments[host] = acknowledged_topics

        if not successful_hosts:
            return BroadcastFailure(
                status="error",
                code="ERR_ALL_HOSTS_REJECTED",
                description=f"All {self.network_preset} topical hosts have rejected the transaction."
            )

        # Validate acknowledgment requirements
        if not self._check_acknowledgment_requirements(host_acknowledgments):
            return BroadcastFailure(
                status="error",
                code="ERR_REQUIRE_ACK_FAILED",
                description="Acknowledgment requirements not met."
            )

        return BroadcastResponse(
            status="success",
            txid=tx.txid(),
            message=f"Sent to {len(successful_hosts)} Overlay Services {len(successful_hosts) == 1 and 'host' or 'hosts'}."
        )

    def _has_meaningful_instructions(self, instructions: AdmittanceInstructions) -> bool:
        """Check if instructions contain meaningful admittance/retain data."""
        return bool(
            (instructions.outputs_to_admit and len(instructions.outputs_to_admit) > 0) or
            (instructions.coins_to_retain and len(instructions.coins_to_retain) > 0) or
            (instructions.coins_removed and len(instructions.coins_removed) > 0)
        )

    async def _find_interested_hosts(self) -> Dict[str, set]:
        """Find hosts interested in the transaction's topics."""
        if self.network_preset == 'local':
            # Local preset uses localhost
            result_set = set(self.topics)
            return {'http://localhost:8080': result_set}

        # Query for SHIP hosts interested in our topics
        results: Dict[str, set] = {}

        try:
            answer = await self.resolver.query(
                LookupQuestion(service='ls_ship', query={'topics': self.topics}),
                self.MAX_SHIP_QUERY_TIMEOUT
            )

            if answer.type != 'output-list':
                raise Exception('SHIP answer is not an output list.')

            for output in answer.outputs:
                try:
                    # Parse overlay admin token
                    decoded = OverlayAdminTokenTemplate.decode(output.beef)
                    if (decoded['protocol'] == 'SHIP' and
                        decoded['topicOrService'] in self.topics):
                        domain = decoded['domain']
                        if domain not in results:
                            results[domain] = set()
                        results[domain].add(decoded['topicOrService'])
                except Exception:
                    continue

        except Exception as e:
            # If lookup fails, no hosts are interested
            return {}

        return results

    async def _send_to_host_with_tracking(self, host: str, tagged_beef: TaggedBEEF) -> STEAK:
        """Send tagged BEEF to a host with error tracking."""
        try:
            return await self.facilitator.send(host, tagged_beef)
        except Exception as e:
            # In a full implementation, we'd track host failures
            raise e

    def _check_acknowledgment_requirements(self, host_acknowledgments: Dict[str, set]) -> bool:
        """Check if acknowledgment requirements are met."""

        # Check require_acknowledgment_from_all_hosts_for_topics
        if self.require_acknowledgment_from_all_hosts_for_topics:
            required_topics = self.require_acknowledgment_from_all_hosts_for_topics
            for host, acknowledged in host_acknowledgments.items():
                for topic in required_topics:
                    if topic not in acknowledged:
                        return False

        # Check require_acknowledgment_from_any_host_for_topics
        if self.require_acknowledgment_from_any_host_for_topics:
            required_topics = self.require_acknowledgment_from_any_host_for_topics
            for topic in required_topics:
                topic_acknowledged = any(topic in acknowledged
                                       for acknowledged in host_acknowledgments.values())
                if not topic_acknowledged:
                    return False

        # Check require_acknowledgment_from_specific_hosts_for_topics
        for host, requirements in self.require_acknowledgment_from_specific_hosts_for_topics.items():
            if host not in host_acknowledgments:
                return False

            acknowledged = host_acknowledgments[host]
            required_topics = requirements if isinstance(requirements, list) else self.topics

            for topic in required_topics:
                if topic not in acknowledged:
                    return False

        return True


# Alias for backward compatibility
SHIPBroadcaster = TopicBroadcaster
SHIPCast = TopicBroadcaster
