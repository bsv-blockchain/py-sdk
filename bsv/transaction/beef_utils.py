from __future__ import annotations

from typing import Optional, List

from bsv.utils import to_hex, to_bytes
from bsv.hash import hash256
from bsv.merkle_path import MerklePath
from .beef import Beef


def find_bump(beef: Beef, txid: str) -> Optional[MerklePath]:
    for bump in getattr(beef, "bumps", []) or []:
        try:
            for leaf in bump.path[0]:
                if leaf.get("hash_str") == txid:
                    return bump
        except Exception:
            pass
    return None


def to_log_string(beef: Beef) -> str:
    lines: List[str] = []
    lines.append(f"BEEF with {len(beef.bumps)} BUMPs and {len(beef.txs)} Transactions")
    for i, bump in enumerate(beef.bumps):
        lines.append(f"  BUMP {i}")
        lines.append(f"    block: {bump.block_height}")
        txids = []
        try:
            for leaf in bump.path[0]:
                if leaf.get("txid"):
                    txids.append(leaf.get("hash_str", ""))
        except Exception:
            pass
        lines.append(f"    txids: [")
        for t in txids:
            lines.append(f"      '{t}',")
        lines.append(f"    ]")
    for i, btx in enumerate(beef.txs.values()):
        lines.append(f"  TX {i}")
        lines.append(f"    txid: {btx.txid}")
        if btx.data_format == 2:
            lines.append("    txidOnly")
        else:
            if btx.bump_index is not None:
                lines.append(f"    bumpIndex: {btx.bump_index}")
            lines.append(f"    rawTx length={len(btx.tx_bytes) if btx.tx_bytes else 0}")
            if btx.tx_obj is not None and getattr(btx.tx_obj, 'inputs', None):
                lines.append("    inputs: [")
                for txin in btx.tx_obj.inputs:
                    sid = getattr(txin, "source_txid", "")
                    lines.append(f"      '{sid}',")
                lines.append("    ]")
    return "\n".join(lines)


def add_computed_leaves(beef: Beef) -> None:
    """
    Add computable leaves to each MerklePath by using row-0 leaves as base.
    """
    def _hash(m: str) -> str:
        return to_hex(hash256(to_bytes(m, "hex")[::-1])[::-1])

    for bump in getattr(beef, "bumps", []) or []:
        try:
            for row in range(1, len(bump.path)):
                # iterate over level-1 lower row leaves
                for leafL in bump.path[row - 1]:
                    if isinstance(leafL, dict) and isinstance(leafL.get("offset"), int):
                        if (leafL["offset"] & 1) == 0 and "hash_str" in leafL:
                            # even offset -> right sibling is offset+1
                            offset_on_row = leafL["offset"] >> 1
                            # skip if already exists
                            exists = any(l.get("offset") == offset_on_row for l in bump.path[row])
                            if exists:
                                continue
                            # locate right sibling
                            leafR = next((l for l in bump.path[row - 1] if l.get("offset") == leafL["offset"] + 1), None)
                            if leafR and "hash_str" in leafR:
                                # String concatenation puts the right leaf on the left of the left leaf hash
                                bump.path[row].append({
                                    "offset": offset_on_row,
                                    "hash_str": _hash(leafR["hash_str"] + leafL["hash_str"])
                                })
        except Exception:
            # best-effort only
            pass


def trim_known_txids(beef: Beef, known_txids: List[str]) -> None:
    known = set(known_txids)
    to_delete = [txid for txid, btx in beef.txs.items() if btx.data_format == 2 and txid in known]
    for txid in to_delete:
        beef.txs.pop(txid, None)


