"""Poll GorillaPool ARC GET /v1/tx/{txid} until mined or terminal failure (live tests)."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import aiohttp

from bsv.broadcasters.arc import ARC_PROGRESSING_TX_STATUSES, ARC_TERMINAL_FAILURE_TX_STATUSES

# ARC GET ``ANNOUNCED_TO_NETWORK`` means the tx was relayed; WoC may lag — retry probes with backoff.
_WOC_AFTER_ANNOUNCED_INITIAL_DELAY = 0.35
_WOC_AFTER_ANNOUNCED_BACKOFF_MULT = 1.65
_WOC_AFTER_ANNOUNCED_DELAY_CAP = 12.0
_WOC_AFTER_ANNOUNCED_BURST_CAP_SEC = 28.0


def _body_preview(text: str, limit: int = 6000) -> str:
    """Truncated response-body preview for live reports."""
    if not text:
        return ""
    return text[:limit] + ("…" if len(text) > limit else "")


async def _sleep_on_429(backoff: float) -> float:
    """Sleep for the current 429 backoff and return the next backoff value."""
    await asyncio.sleep(min(max(backoff, 0.5), 45.0))
    return min(backoff * 1.5, 45.0)


def _extract_arc_status(status: int, payload: dict[str, Any] | None) -> tuple[str | None, str]:
    """Return ``(txStatus, extraInfo)`` from an ARC GET response (``(None, \"\")`` if unusable)."""
    if status != 200 or not payload:
        return None, ""
    data = _normalize_arc_get_json(payload)
    return data.get("txStatus"), (data.get("extraInfo") or "").strip()


def _raise_if_arc_terminal(txid: str, tx_status: str | None, extra: str) -> None:
    if tx_status in ARC_TERMINAL_FAILURE_TX_STATUSES:
        msg = f"{tx_status}: {extra}" if extra else f"{tx_status}"
        raise RuntimeError(f"ARC tx {txid} failed: {msg}")


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

    raise RuntimeError(f"ARC tx {txid} not MINED within {timeout_sec}s (last ARC base {arc_base_url})")


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


async def woc_visibility_http_snapshot(
    session: aiohttp.ClientSession,
    woc_api_base: str,
    txid: str,
) -> tuple[str | None, bool, dict[str, Any]]:
    """Indexer / hex GET when WoC has indexed the tx (optional; often 404 for 0-conf).

    Returns ``(method_or_none, visible, http_detail)`` where ``http_detail`` records URLs,
    HTTP status codes, and body previews for the WoC GET probes (for live reports).
    """
    base = woc_api_base.rstrip("/")
    detail: dict[str, Any] = {}
    hex_url = f"{base}/tx/{txid}/hex"
    async with session.get(hex_url) as resp:
        detail["woc_hex_url"] = hex_url
        detail["woc_hex_http_status"] = resp.status
        text = (await resp.text()).strip()
        detail["woc_hex_body_preview"] = _body_preview(text)
        if resp.status == 429:
            return None, False, detail
        if resp.status == 200:
            if len(text) >= 40 and all(c in "0123456789abcdefABCDEF" for c in text):
                return "WOC_TX_HEX", True, detail

    json_url = f"{base}/tx/{txid}"
    async with session.get(json_url) as resp:
        detail["woc_json_url"] = json_url
        detail["woc_json_http_status"] = resp.status
        text = await resp.text()
        detail["woc_json_body_preview"] = _body_preview(text)
        if resp.status == 429:
            return None, False, detail
        if resp.status != 200:
            return None, False, detail
        try:
            j = json.loads(text)
        except (TypeError, ValueError):
            return None, False, detail
        if _woc_json_has_txid(j, txid):
            return "WOC_TX_JSON", True, detail
    return None, False, detail


async def woc_tx_observable_via_get(
    session: aiohttp.ClientSession,
    woc_api_base: str,
    txid: str,
) -> tuple[str | None, bool]:
    """Indexer / hex GET when WoC has indexed the tx (optional; often 404 for 0-conf)."""
    method, visible, _ = await woc_visibility_http_snapshot(session, woc_api_base, txid)
    return method, visible


async def _woc_probes_with_backoff_when_announced(
    session: aiohttp.ClientSession,
    *,
    woc_root: str | None,
    raw_hex: str | None,
    woc_indexer_root: str | None,
    txid: str,
    deadline: float,
) -> str | None:
    """While ARC reports ``ANNOUNCED_TO_NETWORK``, retry WoC mempool POST and indexer GET with backoff."""
    can_mempool = bool(woc_root and raw_hex)
    can_indexer = bool(woc_indexer_root)
    if not can_mempool and not can_indexer:
        return None
    burst_end = min(deadline, time.monotonic() + _WOC_AFTER_ANNOUNCED_BURST_CAP_SEC)
    delay = _WOC_AFTER_ANNOUNCED_INITIAL_DELAY
    while time.monotonic() < burst_end:
        if can_mempool and await woc_post_raw_tx_mempool_probe(session, woc_root, raw_hex):
            return "WOC_MEMPOOL_POST"
        if woc_indexer_root:
            woc_reason, woc_ok = await woc_tx_observable_via_get(session, woc_indexer_root, txid)
            if woc_ok and woc_reason:
                return woc_reason
        remaining = burst_end - time.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(delay, remaining))
        delay = min(delay * _WOC_AFTER_ANNOUNCED_BACKOFF_MULT, _WOC_AFTER_ANNOUNCED_DELAY_CAP)
    return None


async def _woc_probe_round(
    session: aiohttp.ClientSession,
    *,
    tx_status: str | None,
    woc_root: str | None,
    raw_hex: str | None,
    woc_indexer_root: str | None,
    txid: str,
    deadline: float,
) -> str | None:
    """One round of WoC fallbacks; returns a visibility token or ``None``."""
    if tx_status == "ANNOUNCED_TO_NETWORK":
        return await _woc_probes_with_backoff_when_announced(
            session,
            woc_root=woc_root,
            raw_hex=raw_hex,
            woc_indexer_root=woc_indexer_root,
            txid=txid,
            deadline=deadline,
        )
    # POST /tx/raw: duplicate / mempool-conflict means the tx is already known (strict or relaxed).
    if woc_root and raw_hex and await woc_post_raw_tx_mempool_probe(session, woc_root, raw_hex):
        return "WOC_MEMPOOL_POST"
    # WoC GET indexer (relaxed only): hex/json when indexed.
    if woc_indexer_root:
        woc_reason, woc_ok = await woc_tx_observable_via_get(session, woc_indexer_root, txid)
        if woc_ok and woc_reason:
            return woc_reason
    return None


def _seen_timeout_message(
    txid: str,
    arc_base_url: str,
    timeout_sec: float,
    *,
    require_arc_seen_on_network: bool,
    woc_root: str | None,
    raw_hex: str | None,
) -> str:
    if require_arc_seen_on_network:
        woc_note = ", or WoC /tx/raw already-in-mempool" if (woc_root and raw_hex) else ""
        return (
            f"Tx {txid} did not reach ARC SEEN_ON_NETWORK or MINED{woc_note} "
            f"within {timeout_sec}s (ARC base {arc_base_url})"
        )
    woc_note = ", or WoC mempool/indexer" if woc_root else ""
    return (
        f"Tx {txid} not visible (ARC SEEN_ON_NETWORK/MINED/progressing{woc_note}) "
        f"within {timeout_sec}s (ARC base {arc_base_url})"
    )


async def wait_until_arc_tx_seen_on_network(
    arc_base_url: str,
    txid: str,
    *,
    timeout_sec: float = 120.0,
    poll_interval: float = 1.5,
    woc_api_base: str | None = None,
    raw_tx_hex: str | None = None,
    require_arc_seen_on_network: bool = False,
) -> str:
    """Poll ARC until visible, with optional WoC mempool / indexer checks.

    ARC GET succeeds on ``MINED``, ``SEEN_ON_NETWORK``, or any :data:`~bsv.broadcasters.arc.ARC_PROGRESSING_TX_STATUSES`
    value (e.g. ``REQUESTED_BY_NETWORK``) — some gateways rarely report ``SEEN_ON_NETWORK`` on GET.

    When ARC GET reports ``ANNOUNCED_TO_NETWORK`` (already relayed), WhatsOnChain probes run on a
    **backoff/retry** burst before the next ARC poll so mempool/indexer can catch up.

    **WoC POST fallback** (when ``raw_tx_hex`` is set): POST ``/tx/raw`` with the same hex ARC
    already broadcast. If WoC responds with duplicate / ``txn-mempool-conflict`` (258), the tx is
    in that node's mempool even when GET ``/tx/{txid}`` returns 404 for unconfirmed txs.

    **WoC GET fallback** (when ``woc_api_base`` is set): ``/tx/{txid}/hex`` or JSON ``/tx/{txid}``
    when the indexer has caught up.

    When ``require_arc_seen_on_network`` is True (fan-out UTXO pool), success requires **ARC**
    ``SEEN_ON_NETWORK`` or ``MINED``, **or** WhatsOnChain POST ``/tx/raw`` reporting the tx is already
    in mempool (duplicate / conflict — same as a manual rebroadcast). WoC indexer GET fallbacks and
    ARC "progressing" early-exit stay disabled in that mode.

    No block confirmations are required—only relay / mempool visibility (unless strict mode above).
    """
    woc_root = (woc_api_base or "").strip() or None
    raw_hex = (raw_tx_hex or "").strip() or None
    woc_indexer_ok = woc_root if not require_arc_seen_on_network else None
    deadline = time.monotonic() + timeout_sec
    backoff_429 = 1.0
    async with aiohttp.ClientSession() as session:
        while time.monotonic() < deadline:
            status, payload = await fetch_arc_tx_json(session, arc_base_url, txid)
            if status == 429:
                backoff_429 = await _sleep_on_429(backoff_429)
                continue
            backoff_429 = 1.0

            tx_status, extra = _extract_arc_status(status, payload)
            if tx_status in ("MINED", "SEEN_ON_NETWORK"):
                return tx_status
            _raise_if_arc_terminal(txid, tx_status, extra)

            woc_hit = await _woc_probe_round(
                session,
                tx_status=tx_status,
                woc_root=woc_root,
                raw_hex=raw_hex,
                woc_indexer_root=woc_indexer_ok,
                txid=txid,
                deadline=deadline,
            )
            if woc_hit:
                return woc_hit

            if not require_arc_seen_on_network and tx_status in ARC_PROGRESSING_TX_STATUSES:
                return tx_status

            await asyncio.sleep(poll_interval)

    raise RuntimeError(
        _seen_timeout_message(
            txid,
            arc_base_url,
            timeout_sec,
            require_arc_seen_on_network=require_arc_seen_on_network,
            woc_root=woc_root,
            raw_hex=raw_hex,
        )
    )


async def _woc_has_confirmations(
    session: aiohttp.ClientSession,
    woc_url: str,
    min_confirmations: int,
) -> bool:
    """True when the WoC JSON endpoint reports enough confirmations (False on any error)."""
    try:
        async with session.get(woc_url) as wresp:
            if wresp.status != 200:
                return False
            wj = await wresp.json()
            conf = wj.get("confirmations")
            return isinstance(conf, int) and conf >= min_confirmations
    except (aiohttp.ClientError, json.JSONDecodeError, TypeError):
        return False


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
                backoff_429 = await _sleep_on_429(backoff_429)
                continue
            backoff_429 = 1.0

            tx_status, extra = _extract_arc_status(status, payload)
            if tx_status == "MINED":
                return
            _raise_if_arc_terminal(txid, tx_status, extra)

            if await _woc_has_confirmations(session, woc_url, min_woc_confirmations):
                return

            await asyncio.sleep(poll_interval)

    raise RuntimeError(
        f"Tx {txid} not confirmed (ARC MINED or WoC confirmations>={min_woc_confirmations}) within {timeout_sec}s"
    )


async def check_woc_visibility(
    woc_api_base: str,
    txid: str,
    *,
    initial_delay: float = 3.0,
) -> tuple[bool, str, float, dict[str, Any]]:
    """Quick WoC GET probe after successful broadcast.

    Returns ``(is_visible, method_or_reason, elapsed_seconds, http_detail)``.
    ``http_detail`` holds WoC URLs, HTTP status codes, and response body previews for reports.
    Does **not** raise on failure — returns ``(False, reason, elapsed, detail)``.
    """
    import time as _time

    start = _time.monotonic()
    await asyncio.sleep(initial_delay)
    try:
        async with aiohttp.ClientSession() as session:
            method, visible, detail = await woc_visibility_http_snapshot(session, woc_api_base, txid)
            elapsed = _time.monotonic() - start
            if visible and method:
                return True, method, elapsed, detail
            return False, "GET returned 404", elapsed, detail
    except Exception as exc:
        elapsed = _time.monotonic() - start
        return False, f"error: {exc}", elapsed, {"probe_exception": repr(exc)}
