"""
SHIPBroadcaster implementation - Advanced overlay broadcasting.

Ported from TypeScript SDK.
"""

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, Union

from bsv.broadcasters.broadcaster import BroadcastFailure, BroadcastResponse
from bsv.transaction import Transaction

from .lookup_resolver import LookupQuestion, LookupResolver, LookupResolverConfig
from .overlay_admin_token_template import OverlayAdminTokenTemplate


class BroadcastError(Exception):
    """Base exception for SHIP broadcast operations."""


class HTTPProtocolError(BroadcastError):
    """Exception raised when HTTP protocol requirement is violated."""


@dataclass
class TaggedBEEF:
    """Tagged BEEF structure."""

    beef: bytes
    topics: list[str]
    off_chain_values: Optional[bytes] = None


@dataclass
class AdmittanceInstructions:
    """Instructs about which outputs to admit and retain."""

    outputs_to_admit: list[int]
    coins_to_retain: list[int]
    coins_removed: Optional[list[int]] = None


# Type alias for STEAK (Submitted Transaction Execution AcKnowledgment)
STEAK = dict[str, AdmittanceInstructions]


@dataclass
class SHIPBroadcasterConfig:
    """Configuration options for the SHIP broadcaster."""

    network_preset: Optional[str] = None  # 'mainnet', 'testnet', or 'local'
    facilitator: Optional["OverlayBroadcastFacilitator"] = None
    resolver: Optional[LookupResolver] = None
    require_acknowledgment_from_all_hosts_for_topics: Optional[list[str]] = None
    require_acknowledgment_from_any_host_for_topics: Optional[list[str]] = None
    require_acknowledgment_from_specific_hosts_for_topics: Optional[dict[str, list[str]]] = None


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

        if not url.startswith("https:") and not self.allow_http:
            raise ValueError('HTTPS facilitator requires URLs starting with "https:" (allow_http=False)')

        headers = {"Content-Type": "application/octet-stream", "X-Topics": ",".join(tagged_beef.topics)}

        body = tagged_beef.beef
        if tagged_beef.off_chain_values:
            headers["x-includes-off-chain-values"] = "true"
            # Combine BEEF and off-chain values
            from bsv.utils import Writer

            writer = Writer()
            writer.write_varint(len(tagged_beef.beef))
            writer.write(tagged_beef.beef)
            writer.write(tagged_beef.off_chain_values)
            body = writer.to_bytes()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{url}/submit", headers=headers, data=body) as response:
                    if response.ok:
                        return await response.json()
                    else:
                        error_text = await response.text()
                        raise BroadcastError(f"Broadcast failed: {error_text}")

        except BroadcastError:
            raise
        except Exception as e:
            raise BroadcastError(f"Broadcast failed: {e!s}")


class TopicBroadcaster:
    """
    Broadcasts transactions to one or more overlay topics via SHIP.

    Also known as SHIPBroadcaster or SHIPCast.
    """

    MAX_SHIP_QUERY_TIMEOUT = 5000

    def __init__(self, topics: list[str], config: Optional[SHIPBroadcasterConfig] = None):
        if not topics:
            raise ValueError("At least one topic is required for broadcast.")

        if any(not topic.startswith("tm_") for topic in topics):
            raise ValueError('Every topic must start with "tm_".')

        self.topics = topics
        config = config or SHIPBroadcasterConfig()

        self.network_preset = config.network_preset or "mainnet"
        self.facilitator = config.facilitator or HTTPSOverlayBroadcastFacilitator(
            allow_http=self.network_preset == "local"
        )
        self.resolver = config.resolver or LookupResolver(LookupResolverConfig(network_preset=self.network_preset))

        # Initialize failure tracking
        self._failed_hosts: set[str] = set()

        self.require_acknowledgment_from_all_hosts_for_topics = config.require_acknowledgment_from_all_hosts_for_topics
        self.require_acknowledgment_from_any_host_for_topics = (
            config.require_acknowledgment_from_any_host_for_topics or self.topics
        )
        self.require_acknowledgment_from_specific_hosts_for_topics = (
            config.require_acknowledgment_from_specific_hosts_for_topics or {}
        )

    def _extract_beef_from_transaction(self, tx: Transaction) -> tuple[Optional[bytes], Optional[BroadcastFailure]]:
        """Extract BEEF from transaction, returning (beef, error)."""
        try:
            beef = tx.to_beef()
            return beef, None
        except Exception as e:
            return None, BroadcastFailure(
                status="error",
                code="ERR_INVALID_BEEF",
                description=f"Transactions sent via SHIP must be serializable to BEEF format: {e!s}",
            )

    def _extract_off_chain_values(self, tx: Transaction) -> Optional[bytes]:
        """Extract and normalize off-chain values from transaction metadata."""
        if hasattr(tx, "metadata") and tx.metadata:
            off_chain_values = tx.metadata.get("OffChainValues")
            if off_chain_values and not isinstance(off_chain_values, bytes):
                return bytes(off_chain_values)
            return off_chain_values
        return None

    async def _send_to_all_hosts(self, interested_hosts: dict, beef: bytes, off_chain_values: Optional[bytes]) -> list:
        """Send tagged BEEF to all interested hosts and gather results."""
        host_promises = []
        for host, topics in interested_hosts.items():
            tagged_beef = TaggedBEEF(beef=beef, topics=list(topics), off_chain_values=off_chain_values)
            host_promises.append(self._send_to_host_with_tracking(host, tagged_beef))

        return await asyncio.gather(*host_promises, return_exceptions=True)

    def _process_host_results(self, results: list, interested_hosts: dict) -> tuple[list, dict[str, set]]:
        """Process results from all hosts and extract acknowledgments."""
        successful_hosts = []
        host_acknowledgments: dict[str, set] = {}

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

        return successful_hosts, host_acknowledgments

    async def broadcast(self, tx: Transaction) -> Union[BroadcastResponse, BroadcastFailure]:
        """Broadcast a transaction to Overlay Services via SHIP."""
        # Convert transaction to BEEF
        beef, error = self._extract_beef_from_transaction(tx)
        if error:
            return error

        # Extract off-chain values
        off_chain_values = self._extract_off_chain_values(tx)

        # Find interested hosts
        interested_hosts = await self._find_interested_hosts()
        if not interested_hosts:
            return BroadcastFailure(
                status="error",
                code="ERR_NO_HOSTS_INTERESTED",
                description=f"No {self.network_preset} hosts are interested in receiving this transaction.",
            )

        # Send to all interested hosts and collect results
        results = await self._send_to_all_hosts(interested_hosts, beef, off_chain_values)

        # Process results and extract acknowledgments
        successful_hosts, host_acknowledgments = self._process_host_results(results, interested_hosts)

        if not successful_hosts:
            return BroadcastFailure(
                status="error",
                code="ERR_ALL_HOSTS_REJECTED",
                description=f"All {self.network_preset} topical hosts have rejected the transaction.",
            )

        # Validate acknowledgment requirements
        if not self._check_acknowledgment_requirements(host_acknowledgments):
            return BroadcastFailure(
                status="error", code="ERR_REQUIRE_ACK_FAILED", description="Acknowledgment requirements not met."
            )

        return BroadcastResponse(
            status="success",
            txid=tx.txid(),
            message=f"Sent to {len(successful_hosts)} Overlay Services {'host' if len(successful_hosts) == 1 else 'hosts'}.",
        )

    def _has_meaningful_instructions(self, instructions: AdmittanceInstructions) -> bool:
        """Check if instructions contain meaningful admittance/retain data."""
        return bool(
            (instructions.outputs_to_admit and len(instructions.outputs_to_admit) > 0)
            or (instructions.coins_to_retain and len(instructions.coins_to_retain) > 0)
            or (instructions.coins_removed and len(instructions.coins_removed) > 0)
        )

    async def _find_interested_hosts(self) -> dict[str, set]:
        """Find hosts interested in the transaction's topics."""
        if self.network_preset == "local":
            # Local preset uses localhost
            result_set = set(self.topics)
            return {"http://localhost:8080": result_set}

        # Query for SHIP hosts interested in our topics
        results: dict[str, set] = {}

        try:
            answer = await self.resolver.query(
                LookupQuestion(service="ls_ship", query={"topics": self.topics}), self.MAX_SHIP_QUERY_TIMEOUT
            )

            if answer.type != "output-list":
                raise BroadcastError("SHIP answer is not an output list.")

            for output in answer.outputs:
                try:
                    # Parse overlay admin token
                    decoded = OverlayAdminTokenTemplate.decode(output.beef)
                    if decoded["protocol"] == "SHIP" and decoded["topicOrService"] in self.topics:
                        domain = decoded["domain"]
                        if domain not in results:
                            results[domain] = set()
                        results[domain].add(decoded["topicOrService"])
                except Exception:
                    continue

        except Exception:
            # If lookup fails, no hosts are interested
            return {}

        return results

    async def _send_to_host_with_tracking(self, host: str, tagged_beef: TaggedBEEF) -> STEAK:
        """Send tagged BEEF to a host with error tracking."""
        try:
            return await self.facilitator.send(host, tagged_beef)
        except Exception:
            # Basic host failure tracking: record the failing host on this instance.
            self._failed_hosts.add(host)
            # Re-raise the original exception so callers see exactly the same error
            # from facilitator.send as before; tracking must not swallow or wrap it.
            raise

    def _check_all_hosts_acknowledgment(self, host_acknowledgments: dict[str, set]) -> bool:
        """Check if all hosts acknowledged required topics."""
        if not self.require_acknowledgment_from_all_hosts_for_topics:
            return True

        required_topics = self.require_acknowledgment_from_all_hosts_for_topics
        for acknowledged in host_acknowledgments.values():
            for topic in required_topics:
                if topic not in acknowledged:
                    return False
        return True

    def _check_any_host_acknowledgment(self, host_acknowledgments: dict[str, set]) -> bool:
        """Check if at least one host acknowledged required topics."""
        if not self.require_acknowledgment_from_any_host_for_topics:
            return True

        required_topics = self.require_acknowledgment_from_any_host_for_topics
        for topic in required_topics:
            topic_acknowledged = any(topic in acknowledged for acknowledged in host_acknowledgments.values())
            if not topic_acknowledged:
                return False
        return True

    def _check_specific_hosts_acknowledgment(self, host_acknowledgments: dict[str, set]) -> bool:
        """Check if specific hosts acknowledged required topics."""
        for host, requirements in self.require_acknowledgment_from_specific_hosts_for_topics.items():
            if host not in host_acknowledgments:
                return False

            acknowledged = host_acknowledgments[host]
            required_topics = requirements if isinstance(requirements, list) else self.topics

            for topic in required_topics:
                if topic not in acknowledged:
                    return False
        return True

    def _check_acknowledgment_requirements(self, host_acknowledgments: dict[str, set]) -> bool:
        """Check if acknowledgment requirements are met."""
        return (
            self._check_all_hosts_acknowledgment(host_acknowledgments)
            and self._check_any_host_acknowledgment(host_acknowledgments)
            and self._check_specific_hosts_acknowledgment(host_acknowledgments)
        )


# Alias for backward compatibility
SHIPBroadcaster = TopicBroadcaster
SHIPCast = TopicBroadcaster
