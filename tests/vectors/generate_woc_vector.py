#!/usr/bin/env python3
import os
import json
import argparse
from typing import Optional

from bsv.http_client import default_sync_http_client


def fetch_woc_tx_and_header(txid: str, network: str = "main", _: Optional[str] = None, height: Optional[int] = None):  # NOSONAR - Complexity (19), requires refactoring
    base = f"https://api.whatsonchain.com/v1/bsv/{network}"
    client = default_sync_http_client()
    # tx raw
    tx_resp = client.get(f"{base}/tx/{txid}/raw")
    if not tx_resp.ok:
        raise SystemExit(f"Failed to fetch tx raw from WOC: {tx_resp.status_code}")
    tx_hex = tx_resp.json().get("data") if isinstance(tx_resp.json(), dict) else None
    # header
    hdr = None
    if height is not None:
        hdr_resp = client.get(f"{base}/block/{height}/header")
        if hdr_resp.ok and isinstance(hdr_resp.json(), dict):
            hdr = hdr_resp.json().get("data", {})
    else:
        # attempt to query tx data to get block hash/height
        info_resp = client.get(f"{base}/tx/hash/{txid}")
        if info_resp.ok and isinstance(info_resp.json(), dict):
            h = info_resp.json().get("data", {}).get("blockheight")
            if h:
                height = int(h)
                hdr_resp = client.get(f"{base}/block/{height}/header")
                if hdr_resp.ok and isinstance(hdr_resp.json(), dict):
                    hdr = hdr_resp.json().get("data", {})
    return tx_hex, height, (hdr or {})


def main():
    ap = argparse.ArgumentParser(description="Generate WOC-based vector for Transaction.verify E2E")
    ap.add_argument("txid", help="Transaction ID (hex)")
    ap.add_argument("--network", default=os.getenv("WOC_NETWORK", "main"))
    ap.add_argument("--height", type=int, default=None)
    ap.add_argument("--out", required=True, help="Output JSON path")
    args = ap.parse_args()

    tx_hex, height, header = fetch_woc_tx_and_header(args.txid, args.network, None, args.height)
    if not tx_hex or not height or not isinstance(header, dict):
        raise SystemExit("Missing tx_hex or block header from WOC")

    vector = {
        "tx_hex": tx_hex,
        "block_height": height,
        "header_root": header.get("merkleroot", ""),
        # Users may optionally add merkle_path_binary_hex if they have a proof
    }
    with open(args.out, "w") as f:
        json.dump(vector, f, indent=2)
    print(f"Wrote vector to {args.out}")


if __name__ == "__main__":
    main()


