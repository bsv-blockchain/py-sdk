#!/usr/bin/env python3
"""Parse a live pytest log and verify broadcast txids exist on WhatsOnChain (and optionally ARC).

Usage::

    pytest tests/bsv/live/test_live_testnet.py -s -v 2>&1 | tee tests/bsv/live/.artifacts/last_run.log
    python tests/bsv/live/verify_broadcast_log.py tests/bsv/live/.artifacts/last_run.log

Or use ``run_live_with_verification.sh`` to tee and verify in one step.

Exit code 0 if every parsed transaction passes the enabled checks; non-zero otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Literal
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# Match conftest defaults (avoid importing pytest conftest as a script side effect).
WOC_API_TESTNET = "https://api.whatsonchain.com/v1/bsv/test"
WOC_API_MAINNET = "https://api.whatsonchain.com/v1/bsv/main"

# TAAL + GorillaPool defaults (same as tests.bsv.live.conftest).
ARC_API_TESTNET_TAAL = "https://arc-test.taal.com"
ARC_API_MAINNET_TAAL = "https://arc.taal.com"
ARC_API_TESTNET_GP = "https://testnet.arc.gorillapool.io"
ARC_API_MAINNET_GP = "https://arc.gorillapool.io"

Network = Literal["testnet", "mainnet"]

_EXPLORER_TESTNET_TX = re.compile(r"https://test\.whatsonchain\.com/tx/([a-fA-F0-9]{64})\b")
_EXPLORER_MAINNET_TX = re.compile(r"https://(?<!test\.)whatsonchain\.com/tx/([a-fA-F0-9]{64})\b")
_SUCCESS_TXID = re.compile(r"status=success txid=([a-fA-F0-9]{64})\b")
_RAWTX_LINE = re.compile(r"\[rawTx hex (\w+)\]\s*([0-9a-fA-F]+)")


def live_arc_base_url(network_label: str) -> str:
    """Resolve ARC base URL (no ``/v1``); mirrors :func:`tests.bsv.live.conftest.live_arc_base_url`."""
    nl = (network_label or "testnet").strip().lower()
    override = os.environ.get("LIVE_ARC_BASE_URL", "").strip()
    if override:
        return override.rstrip("/")
    if nl == "mainnet":
        u = os.environ.get("LIVE_ARC_BASE_URL_MAINNET", "").strip()
        if u:
            return u.rstrip("/")
    else:
        u = os.environ.get("LIVE_ARC_BASE_URL_TESTNET", "").strip()
        if u:
            return u.rstrip("/")
    backend = os.environ.get("LIVE_ARC_BACKEND", "taal").strip().lower()
    if backend in ("gorillapool", "gorilla", "gp"):
        return ARC_API_MAINNET_GP if nl == "mainnet" else ARC_API_TESTNET_GP
    return ARC_API_MAINNET_TAAL if nl == "mainnet" else ARC_API_TESTNET_TAAL


def parse_broadcast_log(
    text: str,
    *,
    default_network: Network = "testnet",
) -> dict[str, Network]:
    """Return txid (lowercase hex) -> network from explorer URLs and success lines (non-mock)."""
    by_tx: dict[str, Network] = {}
    for line in text.splitlines():
        for m in _EXPLORER_TESTNET_TX.finditer(line):
            by_tx[m.group(1).lower()] = "testnet"
        for m in _EXPLORER_MAINNET_TX.finditer(line):
            by_tx[m.group(1).lower()] = "mainnet"
    for line in text.splitlines():
        if "MockBroadcaster" in line:
            continue
        m = _SUCCESS_TXID.search(line)
        if m:
            tid = m.group(1).lower()
            by_tx.setdefault(tid, default_network)
    return by_tx


def _http_get_json(url: str, *, timeout: float) -> tuple[int, dict | None]:
    req = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if resp.status != 200:
                return resp.status, None
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, None
    except HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, json.loads(body) if body.strip().startswith("{") else None
        except Exception:
            return e.code, None
    except OSError:
        return -1, None


def _http_get_status(url: str, *, timeout: float) -> int:
    req = Request(url, headers={"Accept": "application/json, text/plain, */*"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status
    except HTTPError as e:
        return e.code
    except OSError:
        return -1


def verify_woc_tx(woc_base: str, txid: str, *, timeout: float) -> bool:
    """True if WoC returns JSON for ``/tx/{txid}`` with matching txid field."""
    url = f"{woc_base.rstrip('/')}/tx/{txid}"
    status, payload = _http_get_json(url, timeout=timeout)
    if status != 200 or not isinstance(payload, dict):
        return False
    inner = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    if not isinstance(inner, dict):
        inner = payload
    got = inner.get("txid") or payload.get("txid")
    return isinstance(got, str) and got.lower() == txid.lower()


def verify_woc_tx_hex(woc_base: str, txid: str, *, timeout: float) -> bool:
    """Fallback: raw hex endpoint (some deployments index hex before JSON)."""
    url = f"{woc_base.rstrip('/')}/tx/{txid}/hex"
    st = _http_get_status(url, timeout=timeout)
    return st == 200


def verify_arc_tx(arc_base: str, txid: str, *, timeout: float) -> bool:
    """True if ARC GET /v1/tx/{txid} is 200 and txStatus is not terminal failure."""
    from bsv.broadcasters.arc import ARC_TERMINAL_FAILURE_TX_STATUSES

    url = f"{arc_base.rstrip('/')}/v1/tx/{txid}"
    status, payload = _http_get_json(url, timeout=timeout)
    if status != 200 or not isinstance(payload, dict):
        return False
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    ts = data.get("txStatus") if isinstance(data, dict) else None
    if not ts:
        return True
    return ts not in ARC_TERMINAL_FAILURE_TX_STATUSES


def _env_implies_arc() -> bool:
    keys = (
        "LIVE_ARC_BASE_URL",
        "LIVE_ARC_BASE_URL_TESTNET",
        "LIVE_ARC_BASE_URL_MAINNET",
    )
    return any(os.environ.get(k, "").strip() for k in keys)


def _warn_rawtx_consistency(text: str, known: dict[str, Network]) -> list[str]:
    """If ``bsv`` is importable, warn when raw hex txid does not match parsed ids."""
    warnings: list[str] = []
    try:
        from bsv.transaction import Transaction
    except ImportError:
        return warnings
    for m in _RAWTX_LINE.finditer(text):
        hx = m.group(2).strip()
        if len(hx) < 120:
            continue
        try:
            tx = Transaction.from_hex(hx)
            tid = tx.txid().lower()
        except Exception as e:
            warnings.append(f"rawTx decode failed ({m.group(1)}): {e}")
            continue
        if tid not in known:
            warnings.append(f"rawTx ({m.group(1)}) txid {tid} not among parsed explorer/success txids")
    return warnings


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "log_file",
        nargs="?",
        default=None,
        help="Pytest log (default: tests/bsv/live/.artifacts/last_run.log next to this file)",
    )
    p.add_argument(
        "--default-network",
        choices=("testnet", "mainnet"),
        default="testnet",
        help="Network for success lines with no explorer URL (default: testnet)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP timeout per request (seconds)",
    )
    p.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retries per tx per service (transient failures)",
    )
    arc_group = p.add_mutually_exclusive_group()
    arc_group.add_argument(
        "--arc",
        action="store_true",
        help="Always run ARC GET verification",
    )
    arc_group.add_argument(
        "--no-arc",
        action="store_true",
        help="Skip ARC GET verification",
    )
    p.add_argument(
        "--rawtx-warn",
        action="store_true",
        help="Warn when decoded [rawTx hex] txids are missing from parsed set",
    )
    return p


def _resolve_log_path(candidate: str, base_dirs: tuple[str, ...]) -> str | None:
    """Resolve ``candidate`` and require it to stay under one of ``base_dirs``.

    Prevents CLI-provided paths from escaping the working / test directories
    (e.g. via ``..`` or symlinks). Returns the resolved path or ``None``.
    """
    resolved = os.path.realpath(candidate)
    for base in base_dirs:
        rebuilt = _rebuild_from_listing(os.path.realpath(base), resolved)
        if rebuilt is not None:
            return rebuilt
    return None


def _rebuild_from_listing(base: str, resolved: str) -> str | None:
    """Rebuild ``resolved`` under ``base`` component-by-component from directory listings.

    Every segment of the returned path is taken from the directory listing
    itself rather than from the input string, so the result can only name an
    entry that actually exists under ``base``.
    """
    if resolved == base:
        return base
    if not resolved.startswith(base + os.sep):
        return None
    current = Path(base)
    for part in Path(resolved[len(base) + 1 :]).parts:
        try:
            matches = [entry for entry in current.iterdir() if entry.name == part]
        except OSError:
            return None
        if not matches:
            return None
        current = matches[0]
    return str(current)


def _check_with_retries(check, retries: int) -> bool:
    ok = False
    for attempt in range(max(1, retries + 1)):
        ok = check()
        if ok:
            break
        time.sleep(0.3 * (attempt + 1))
    return ok


def _verify_one_tx(
    txid: str,
    net: Network,
    *,
    use_arc: bool,
    timeout: float,
    retries: int,
) -> tuple[bool, bool | None]:
    woc_bases = {"testnet": WOC_API_TESTNET, "mainnet": WOC_API_MAINNET}
    woc_base = woc_bases[net]
    woc_ok = _check_with_retries(
        lambda: verify_woc_tx(woc_base, txid, timeout=timeout) or verify_woc_tx_hex(woc_base, txid, timeout=timeout),
        retries,
    )
    arc_ok: bool | None = None
    if use_arc:
        arc_base = live_arc_base_url(net)
        arc_ok = _check_with_retries(lambda: verify_arc_tx(arc_base, txid, timeout=timeout), retries)
    return woc_ok, arc_ok


def _print_results_table(rows: list[tuple[str, str, bool, bool | None]], use_arc: bool) -> None:
    hdr = f"{'txid':<66} {'net':<8} {'WoC':<5}"
    if use_arc:
        hdr += f" {'ARC':<5}"
    print(hdr)
    print("-" * len(hdr))
    for txid, net, woc_ok, arc_ok in rows:
        line = f"{txid} {net:<8} {'ok' if woc_ok else 'FAIL':<5}"
        if use_arc:
            line += f" {'ok' if arc_ok else 'FAIL':<5}"
        print(line)


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    here = os.path.dirname(os.path.abspath(__file__))
    candidate = args.log_file or os.path.join(here, ".artifacts", "last_run.log")
    path = _resolve_log_path(candidate, (str(Path.cwd()), here))
    if path is None or not Path(path).is_file():
        print(
            f"error: log file not found (or outside the working/test directories): {candidate}",
            file=sys.stderr,
        )
        return 2

    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()

    known = parse_broadcast_log(text, default_network=args.default_network)
    if not known:
        print("No broadcast txids found in log (explorer URLs or non-mock status=success lines).")
        return 0

    use_arc = args.arc or (not args.no_arc and _env_implies_arc())

    if args.rawtx_warn:
        for w in _warn_rawtx_consistency(text, known):
            print(f"warning: {w}", file=sys.stderr)

    rows: list[tuple[str, str, bool, bool | None]] = []
    failed = False
    for txid, net in sorted(known.items(), key=lambda x: (x[1], x[0])):
        woc_ok, arc_ok = _verify_one_tx(txid, net, use_arc=use_arc, timeout=args.timeout, retries=args.retries)
        if not woc_ok or (use_arc and arc_ok is False):
            failed = True
        rows.append((txid, net, woc_ok, arc_ok))

    _print_results_table(rows, use_arc)

    if failed:
        print("\nVerification failed for one or more transactions.", file=sys.stderr)
        return 1
    print("\nAll listed transactions verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
