"""Poll GorillaPool ARC GET /v1/tx/{txid} until mined or terminal failure (live tests)."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import aiohttp

from bsv.broadcasters.arc import ARC_TERMINAL_FAILURE_TX_STATUSES


def _normalize_arc_get_json(payload: dict[str, Any]) -> dict[str, Any]:
    """GorillaPool returns a flat object; some gateways wrap under `data`."""
    data = payload.get("data")
    if isinstance(data, dict) and "txStatus" in data:
        return data
    if "txStatus" in payload:
        return payload
    if isinstance(data, dict):
        return data
    return payload


async def fetch_arc_tx_json(
    session: aiohttp.ClientSession,
    arc_base_url: str,
    txid: str,
) -> tuple[int, dict[str, Any] | None]:
    """GET ARC tx status. Returns (http_status, parsed_json_or_none)."""
    url = f"{arc_base_url.rstrip('/')}/v1/tx/{txid}"
    async with session.get(url) as resp:
        text = await resp.text()
        if resp.status != 200:
            return resp.status, None
        try:
            return resp.status, json.loads(text)
        except json.JSONDecodeError:
            return resp.status, None


async def wait_until_arc_tx_mined(
    arc_base_url: str,
    txid: str,
    *,
    timeout_sec: float = 300.0,
    poll_interval: float = 2.0,
) -> None:
    """Poll until txStatus is MINED, or raise if terminal failure / timeout.

    Uses the same ARC base URL as the session broadcaster (mainnet vs testnet).
    """
    deadline = time.monotonic() + timeout_sec
    backoff_429 = 1.0
    async with aiohttp.ClientSession() as session:
        while time.monotonic() < deadline:
            status, payload = await fetch_arc_tx_json(session, arc_base_url, txid)
            if status == 429:
                await asyncio.sleep(min(max(backoff_429, 0.5), 45.0))
                backoff_429 = min(backoff_429 * 1.5, 45.0)
                continue
            backoff_429 = 1.0

            if status != 200 or payload is None:
                await asyncio.sleep(poll_interval)
                continue

            data = _normalize_arc_get_json(payload)
            tx_status = data.get("txStatus")
            extra = (data.get("extraInfo") or "").strip()

            if tx_status == "MINED":
                return

            if tx_status in ARC_TERMINAL_FAILURE_TX_STATUSES:
                msg = f"{tx_status}"
                if extra:
                    msg = f"{msg}: {extra}"
                raise RuntimeError(f"ARC tx {txid} failed: {msg}")

            await asyncio.sleep(poll_interval)

    raise RuntimeError(
        f"ARC tx {txid} not MINED within {timeout_sec}s (last ARC base {arc_base_url})"
    )


async def wait_until_arc_tx_seen_on_network(
    arc_base_url: str,
    txid: str,
    *,
    timeout_sec: float = 120.0,
    poll_interval: float = 1.5,
) -> str:
    """Poll GET /v1/tx/{txid} until txStatus is SEEN_ON_NETWORK or MINED.

    Use when POST /v1/tx returns success with an earlier status (e.g. ANNOUNCED_TO_NETWORK)
    despite X-WaitForStatus, so tests still observe propagation before continuing.
    """
    deadline = time.monotonic() + timeout_sec
    backoff_429 = 1.0
    async with aiohttp.ClientSession() as session:
        while time.monotonic() < deadline:
            status, payload = await fetch_arc_tx_json(session, arc_base_url, txid)
            if status == 429:
                await asyncio.sleep(min(max(backoff_429, 0.5), 45.0))
                backoff_429 = min(backoff_429 * 1.5, 45.0)
                continue
            backoff_429 = 1.0

            if status != 200 or payload is None:
                await asyncio.sleep(poll_interval)
                continue

            data = _normalize_arc_get_json(payload)
            tx_status = data.get("txStatus")
            extra = (data.get("extraInfo") or "").strip()

            if tx_status == "MINED":
                return "MINED"
            if tx_status == "SEEN_ON_NETWORK":
                return "SEEN_ON_NETWORK"

            if tx_status in ARC_TERMINAL_FAILURE_TX_STATUSES:
                msg = f"{tx_status}"
                if extra:
                    msg = f"{msg}: {extra}"
                raise RuntimeError(f"ARC tx {txid} failed: {msg}")

            await asyncio.sleep(poll_interval)

    raise RuntimeError(
        f"ARC tx {txid} not SEEN_ON_NETWORK or MINED within {timeout_sec}s (base {arc_base_url})"
    )


async def wait_until_live_tx_confirmed(
    arc_base_url: str,
    woc_api_base: str,
    txid: str,
    *,
    timeout_sec: float = 300.0,
    poll_interval: float = 2.0,
    min_woc_confirmations: int = 1,
) -> None:
    """Wait until ARC reports MINED or WoC reports sufficient confirmations.

    WoC fallback covers indexer lag on ARC GET and txs submitted primarily via WoC.
    """
    deadline = time.monotonic() + timeout_sec
    backoff_429 = 1.0
    woc_url = f"{woc_api_base.rstrip('/')}/tx/{txid}"

    async with aiohttp.ClientSession() as session:
        while time.monotonic() < deadline:
            status, payload = await fetch_arc_tx_json(session, arc_base_url, txid)
            if status == 429:
                await asyncio.sleep(min(max(backoff_429, 0.5), 45.0))
                backoff_429 = min(backoff_429 * 1.5, 45.0)
                continue
            backoff_429 = 1.0

            if status == 200 and payload:
                data = _normalize_arc_get_json(payload)
                tx_status = data.get("txStatus")
                extra = (data.get("extraInfo") or "").strip()
                if tx_status == "MINED":
                    return
                if tx_status in ARC_TERMINAL_FAILURE_TX_STATUSES:
                    msg = f"{tx_status}"
                    if extra:
                        msg = f"{msg}: {extra}"
                    raise RuntimeError(f"ARC tx {txid} failed: {msg}")

            try:
                async with session.get(woc_url) as wresp:
                    if wresp.status == 429:
                        await asyncio.sleep(poll_interval)
                        continue
                    if wresp.status == 200:
                        wj = await wresp.json()
                        conf = wj.get("confirmations")
                        if isinstance(conf, int) and conf >= min_woc_confirmations:
                            return
            except (aiohttp.ClientError, json.JSONDecodeError, TypeError):
                pass

            await asyncio.sleep(poll_interval)

    raise RuntimeError(
        f"Tx {txid} not confirmed (ARC MINED or WoC confirmations>={min_woc_confirmations}) "
        f"within {timeout_sec}s"
    )
