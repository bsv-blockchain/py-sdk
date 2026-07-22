#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
from typing import Optional

from bsv.http_client import default_sync_http_client


def fetch_woc_tx_and_header(txid: str, network: str = "main", _: Optional[str] = None, height: Optional[int] = None):
    base = f"https://api.whatsonchain.com/v1/bsv/{network}"
    client = default_sync_http_client()

    tx_hex = _fetch_tx_raw(client, base, txid)
    height, header = _fetch_block_header(client, base, txid, height)

    return tx_hex, height, header


def _fetch_tx_raw(client, base: str, txid: str) -> str:
    """Fetch raw transaction hex from WOC."""
    tx_resp = client.get(f"{base}/tx/{txid}/raw")
    if not tx_resp.ok:
        raise SystemExit(f"Failed to fetch tx raw from WOC: {tx_resp.status_code}")
    tx_data = tx_resp.json()
    return tx_data.get("data") if isinstance(tx_data, dict) else None


def _fetch_block_header(client, base: str, txid: str, height: Optional[int]) -> tuple[Optional[int], dict]:
    """Fetch block header and height from WOC."""
    if height is not None:
        return height, _fetch_header_by_height(client, base, height)

    # Get height from tx info
    height = _get_tx_height(client, base, txid)
    if height is None:
        return None, {}

    header = _fetch_header_by_height(client, base, height)
    return height, header


def _get_tx_height(client, base: str, txid: str) -> Optional[int]:
    """Get transaction block height from WOC."""
    info_resp = client.get(f"{base}/tx/hash/{txid}")
    if not info_resp.ok or not isinstance(info_resp.json(), dict):
        return None

    height_data = info_resp.json().get("data", {}).get("blockheight")
    return int(height_data) if height_data else None


def _fetch_header_by_height(client, base: str, height: int) -> dict:
    """Fetch block header by height from WOC."""
    hdr_resp = client.get(f"{base}/block/{height}/header")
    if hdr_resp.ok and isinstance(hdr_resp.json(), dict):
        return hdr_resp.json().get("data", {})
    return {}


def _validate_output_path(out: str) -> str:
    """Resolve the CLI-provided output path and ensure it stays under the current working directory."""
    base_dir = os.path.realpath(Path.cwd())
    resolved = os.path.realpath(out)
    if os.path.commonpath([base_dir, resolved]) != base_dir:
        raise SystemExit(f"Refusing to write outside the working directory: {out}")
    return resolved


def main():
    ap = argparse.ArgumentParser(description="Generate WOC-based vector for Transaction.verify E2E")
    ap.add_argument("txid", help="Transaction ID (hex)")
    ap.add_argument("--network", default=os.getenv("WOC_NETWORK", "main"))
    ap.add_argument("--height", type=int, default=None)
    ap.add_argument("--out", required=True, help="Output JSON path")
    args = ap.parse_args()

    out_path = _validate_output_path(args.out)

    tx_hex, height, header = fetch_woc_tx_and_header(args.txid, args.network, None, args.height)
    if not tx_hex or not height or not isinstance(header, dict):
        raise SystemExit("Missing tx_hex or block header from WOC")

    vector = {
        "tx_hex": tx_hex,
        "block_height": height,
        "header_root": header.get("merkleroot", ""),
        # Users may optionally add merkle_path_binary_hex if they have a proof
    }
    with open(out_path, "w") as f:
        json.dump(vector, f, indent=2)
    print(f"Wrote vector to {out_path}")


if __name__ == "__main__":
    main()
