from __future__ import annotations

from typing import Any, Dict, List

from bsv.broadcasters import default_broadcaster


class BroadcasterConfig:
    def __init__(self, network_preset: str = "mainnet") -> None:
        self.networkPreset = network_preset  # NOSONAR - camelCase matches external API format


class TopicBroadcaster:
    """Overlay-compatible topic broadcaster.

    In TS/Go, the broadcast destination is the topic name (e.g., tm_basketmap). In Python, it delegates to the existing Broadcaster.
    """

    def __init__(self, topics: List[str], config: BroadcasterConfig) -> None:
        self._topics = topics
        self._config = config
        self._broadcaster = default_broadcaster()

    async def broadcast(self, tx) -> Any:  # returns BroadcastResponse | BroadcastFailure
        # Delegate to the existing Broadcaster (network switching depends on Broadcaster settings)
        return await self._broadcaster.broadcast(tx)

    def sync_broadcast(self, tx):
        if hasattr(self._broadcaster, "sync_broadcast"):
            return self._broadcaster.sync_broadcast(tx)  # type: ignore[attr-defined]
        # If only asynchronous implementation exists, this is equivalent to a No-Op
        return {"status": "noop"}


