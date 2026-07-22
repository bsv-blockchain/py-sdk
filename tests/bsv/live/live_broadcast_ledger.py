"""Session-wide ledger for live ARC/WoC broadcasts; Markdown report for post-run review."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROWS: list[dict[str, Any]] = []


def reset() -> None:
    _ROWS.clear()


def append_row(row: dict[str, Any]) -> None:
    _ROWS.append(row)


def row_count() -> int:
    return len(_ROWS)


def _md_escape_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _short_cell(s: str, max_len: int = 140) -> str:
    t = " ".join(s.split())
    if len(t) > max_len:
        return t[: max_len - 1] + "…"
    return t


def _json_pretty(obj: Any, limit: int = 120_000) -> str:
    try:
        s = json.dumps(obj, indent=2, default=str, ensure_ascii=False)
    except TypeError:
        s = str(obj)
    if len(s) > limit:
        return s[:limit] + "\n… (truncated)"
    return s


def _row_heading(r: dict[str, Any]) -> str:
    idx = r.get("broadcast_index", "")
    kind = r.get("kind", "")
    txid = r.get("txid") or "unknown"
    return f"### Broadcast {idx} — {kind} — `{txid}`"


def _summary_table_lines(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| # | kind | txid | result | failure / poll | message / ARC POST | ARC visibility | WoC probe | ins | outs | pool outs |",
        "|---|------|------|--------|----------------|-------------------|----------------|-----------|-----|------|-----------|",
    ]
    for r in rows:
        pool = r.get("pool_outputs")
        pool_cell = "—" if pool is None else str(pool)
        fail_note = r.get("failure_or_poll_note")
        if fail_note is None or fail_note == "—":
            fn = "—"
        else:
            fn = _short_cell(str(fail_note), 140)
        lines.append(
            "| "
            + " | ".join(
                [
                    _md_escape_cell(str(r.get("broadcast_index", ""))),
                    _md_escape_cell(str(r.get("kind", ""))),
                    _md_escape_cell(str(r.get("txid") or "—")),
                    _md_escape_cell(str(r.get("result_status", ""))),
                    _md_escape_cell(fn),
                    _md_escape_cell(str(r.get("message_summary") or "—")),
                    _md_escape_cell(str(r.get("arc_visibility") or "—")),
                    _md_escape_cell(str(r.get("woc_probe") or "—")),
                    _md_escape_cell(str(r.get("inputs", ""))),
                    _md_escape_cell(str(r.get("outputs", ""))),
                    _md_escape_cell(pool_cell),
                ]
            )
            + " |"
        )
    return lines


def _diagnostics_lines(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "",
        "## ARC & WoC diagnostics",
        "",
        "Structured data per broadcast: ARC POST JSON (or HTTP error body), client transport errors, optional visibility-poll error, and WoC GET probe (URLs, HTTP status, response previews).",
        "",
    ]
    for r in rows:
        diag = r.get("diagnostics") or {}
        lines.append(_row_heading(r))
        lines.append("")
        lines.append("```json")
        lines.append(_json_pretty(diag) if diag else "{}")
        lines.append("```")
        lines.append("")
    return lines


def _raw_hex_lines(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Raw transaction hex",
        "",
        "Serialized transaction hex from `Transaction.hex()` (same order as the table). Copy a block for offline decode / inspection.",
        "",
    ]
    for r in rows:
        hx = (r.get("raw_tx_hex") or "").strip()
        lines.append(_row_heading(r))
        lines.append("")
        if hx:
            lines.append("```")
            lines.append(hx)
            lines.append("```")
        else:
            lines.append("*(no hex captured)*")
        lines.append("")
    return lines


def write_markdown_report(path: str | None = None) -> str | None:
    """Write ``live_broadcast_report.md`` from collected rows. Returns path written, or None if empty."""
    if not _ROWS:
        return None
    default = Path(__file__).resolve().parent / ".artifacts" / "live_broadcast_report.md"
    out = Path(path or os.environ.get("LIVE_BROADCAST_REPORT_MD", str(default)))
    out.parent.mkdir(parents=True, exist_ok=True)

    net = str(_ROWS[0].get("network_label") or "unknown")
    lines: list[str] = [
        "# Live broadcast report",
        "",
        f"- Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"- Network: **{net}**",
        f"- Broadcasts recorded: **{len(_ROWS)}**",
        "",
        "Summary columns: **failure / poll** is a short note (broadcast error, client transport, or visibility-poll error). Full ARC JSON and WoC HTTP previews follow in **ARC & WoC diagnostics**.",
        "",
    ]
    lines.extend(_summary_table_lines(_ROWS))
    lines.extend(_diagnostics_lines(_ROWS))
    lines.extend(_raw_hex_lines(_ROWS))
    out.write_text("\n".join(lines), encoding="utf-8")
    return str(out)
