"""Poll GorillaPool ARC GET /v1/tx/{txid} until mined or terminal failure (live tests)."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import aiohttp

from bsv.broadcasters.arc import ARC_PROGRESSING_TX_STATUSES, ARC_TERMINAL_FAILURE_TX_STATUSES


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


def _woc_flatten_http_body_text(text: str) -> str:
    """WhatsOnChain errors may be JSON with nested ``data`` / ``error`` strings."""
    t = (text or "").strip()
    if not t:
        return ""
    try:
        j = json.loads(t)
        if isinstance(j, dict):
            parts: list[str] = []
            for k in ("error", "message", "data", "result"):
                v = j.get(k)
                if isinstance(v, str) and v.strip():
                    parts.append(v.strip())
            return " ".join(parts) if parts else json.dumps(j)
    except json.JSONDecodeError:
        pass
    return t


def _woc_text_means_already_in_mempool(desc: str) -> bool:
    """True when WoC /tx/raw response indicates the tx is already known (mempool / duplicate)."""
    d = desc.lower()
    if not d:
        return False
    return (
        "already in the mempool" in d
        or "already in mempool" in d
        or "txn-already-in-mempool" in d
        or "txn-mempool-conflict" in d
        or "mempool-conflict" in d
        or "transaction already in" in d
        or "already known" in d
        or "rejecting duplicate" in d
        or "duplicate" in d
        or "258:" in d
    )


def _woc_json_has_txid(payload: Any, txid: str) -> bool:
    if not isinstance(payload, dict):
        return False
    want = txid.lower()
    for obj in (payload, payload.get("data")):
        if not isinstance(obj, dict):
            continue
        got = obj.get("txid") or obj.get("hash")
        if isinstance(got, str) and got.lower() == want:
            return True
    return False


async def woc_post_raw_tx_mempool_probe(
    session: aiohttp.ClientSession,
    woc_api_base: str,
    raw_tx_hex: str,
) -> bool:
    """POST the same raw tx to WoC ``/tx/raw``.

    Returns True if WoC accepts it (200) **or** rejects because the tx is already in mempool
    (``txn-mempool-conflict`` / 258 / duplicate). That matches manual rebroadcast on the website
    when GET ``/tx/{txid}`` still returns 404 for 0-conf.
    """
    url = f"{woc_api_base.rstrip('/')}/tx/raw"
    try:
        async with session.post(
            url,
            json={"txhex": raw_tx_hex.strip()},
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
            },
        ) as resp:
            text = await resp.text()
    except aiohttp.ClientError:
        return False

    if resp.status == 200:
        return True
    flat = _woc_flatten_http_body_text(text)
    return _woc_text_means_already_in_mempool(flat)


async def woc_tx_observable_via_get(
    session: aiohttp.ClientSession,
    woc_api_base: str,
    txid: str,
) -> tuple[str | None, bool]:
    """Indexer / hex GET when WoC has indexed the tx (optional; often 404 for 0-conf)."""
    base = woc_api_base.rstrip("/")
    hex_url = f"{base}/tx/{txid}/hex"
    async with session.get(hex_url) as resp:
        if resp.status == 429:
            return None, False
        if resp.status == 200:
            text = (await resp.text()).strip()
            if len(text) >= 40 and all(c in "0123456789abcdefABCDEF" for c in text):
                return "WOC_TX_HEX", True

    json_url = f"{base}/tx/{txid}"
    async with session.get(json_url) as resp:
        if resp.status == 429:
            return None, False
        if resp.status != 200:
            return None, False
        try:
            j = await resp.json()
        except (json.JSONDecodeError, aiohttp.ClientError):
            return None, False
        if _woc_json_has_txid(j, txid):
            return "WOC_TX_JSON", True
    return None, False


async def wait_until_arc_tx_seen_on_network(
    arc_base_url: str,
    txid: str,
    *,
    timeout_sec: float = 120.0,
    poll_interval: float = 1.5,
    woc_api_base: str | None = None,
    raw_tx_hex: str | None = None,
) -> str:
    """Poll ARC until visible, with optional WoC mempool / indexer checks.

    ARC GET succeeds on ``MINED``, ``SEEN_ON_NETWORK``, or any :data:`~bsv.broadcasters.arc.ARC_PROGRESSING_TX_STATUSES`
    value (e.g. ``REQUESTED_BY_NETWORK``) — some gateways rarely report ``SEEN_ON_NETWORK`` on GET.

    **WoC POST fallback** (when ``raw_tx_hex`` is set): POST ``/tx/raw`` with the same hex ARC
    already broadcast. If WoC responds with duplicate / ``txn-mempool-conflict`` (258), the tx is
    in that node's mempool even when GET ``/tx/{txid}`` returns 404 for unconfirmed txs.

    **WoC GET fallback** (when ``woc_api_base`` is set): ``/tx/{txid}/hex`` or JSON ``/tx/{txid}``
    when the indexer has caught up.

    No block confirmations are required—only relay / mempool visibility.
    """
    woc_root = (woc_api_base or "").strip() or None
    raw_hex = (raw_tx_hex or "").strip() or None
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

            tx_status: str | None = None
            extra = ""
            if status == 200 and payload is not None:
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

            # WoC before accepting ARC "progressing": seeds WoC mempool so follow-up spends work.
            if woc_root:
                if raw_hex and await woc_post_raw_tx_mempool_probe(session, woc_root, raw_hex):
                    return "WOC_MEMPOOL_POST"
                woc_reason, woc_ok = await woc_tx_observable_via_get(session, woc_root, txid)
                if woc_ok and woc_reason:
                    return woc_reason

            if status == 200 and payload is not None and tx_status in ARC_PROGRESSING_TX_STATUSES:
                return tx_status

            await asyncio.sleep(poll_interval)

    raise RuntimeError(
        f"Tx {txid} not visible (ARC SEEN_ON_NETWORK/MINED/progressing"
        f"{', or WoC mempool/indexer' if woc_root else ''}) within {timeout_sec}s "
        f"(ARC base {arc_base_url})"
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
