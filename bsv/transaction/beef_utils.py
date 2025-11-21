from __future__ import annotations

from typing import Optional, List

from bsv.utils import to_hex, to_bytes
from bsv.hash import hash256
from bsv.merkle_path import MerklePath
from .beef import Beef, BeefTx


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
    lines = [f"BEEF with {len(beef.bumps)} BUMPs and {len(beef.txs)} Transactions"]
    _append_bumps_log(lines, beef.bumps)
    _append_txs_log(lines, beef.txs)
    return "\n".join(lines)

def _append_bumps_log(lines: List[str], bumps):
    """Append BUMP information to log lines."""
    for i, bump in enumerate(bumps):
        lines.append(f"  BUMP {i}")
        lines.append(f"    block: {bump.block_height}")
        txids = _extract_txids_from_bump(bump)
        lines.append("    txids: [")
        for t in txids:
            lines.append(f"      '{t}',")
        lines.append("    ]")

def _extract_txids_from_bump(bump) -> List[str]:
    """Extract TXIDs from bump path."""
    txids = []
    try:
        for leaf in bump.path[0]:
            if leaf.get("txid"):
                txids.append(leaf.get("hash_str", ""))
    except Exception:
        pass
    return txids

def _append_txs_log(lines: List[str], txs):
    """Append transaction information to log lines."""
    for i, btx in enumerate(txs.values()):
        lines.append(f"  TX {i}")
        lines.append(f"    txid: {btx.txid}")
        if btx.data_format == 2:
            lines.append("    txidOnly")
        else:
            _append_tx_details(lines, btx)

def _append_tx_details(lines: List[str], btx):
    """Append detailed transaction information."""
    if btx.bump_index is not None:
        lines.append(f"    bumpIndex: {btx.bump_index}")
    lines.append(f"    rawTx length={len(btx.tx_bytes) if btx.tx_bytes else 0}")
    if btx.tx_obj is not None and getattr(btx.tx_obj, 'inputs', None):
        lines.append("    inputs: [")
        for txin in btx.tx_obj.inputs:
            sid = getattr(txin, "source_txid", "")
            lines.append(f"      '{sid}',")
        lines.append("    ]")


def add_computed_leaves(beef: Beef) -> None:
    """
    Add computable leaves to each MerklePath by using row-0 leaves as base.
    """
    def _hash(m: str) -> str:
        return to_hex(hash256(to_bytes(m, "hex")[::-1])[::-1])

    for bump in getattr(beef, "bumps", []) or []:
        try:
            for row in range(1, len(bump.path)):
                _process_merkle_row(bump, row, _hash)
        except Exception:
            # best-effort only
            pass

def _process_merkle_row(bump, row: int, hash_fn):  # NOSONAR - leafL/leafR are standard binary tree notation
    """Process a single row of merkle path, computing parent leaves."""
    for leafL in bump.path[row - 1]:  # NOSONAR - Binary tree notation (Left leaf)
        if not _should_compute_parent_leaf(leafL, bump.path[row]):
            continue
        
        leafR = _find_sibling_leaf(bump.path[row - 1], leafL["offset"])  # NOSONAR - Binary tree notation (Right leaf)
        if leafR:
            parent_leaf = _compute_parent_leaf(leafL, leafR, hash_fn)
            bump.path[row].append(parent_leaf)

def _should_compute_parent_leaf(leaf, parent_row: List) -> bool:
    """Check if a leaf can be used to compute a parent leaf."""
    if not isinstance(leaf, dict) or not isinstance(leaf.get("offset"), int):
        return False
    
    # Only even offsets can be left children
    if (leaf["offset"] & 1) != 0 or "hash_str" not in leaf:
        return False
    
    # Skip if parent already exists
    offset_on_row = leaf["offset"] >> 1
    exists = any(l.get("offset") == offset_on_row for l in parent_row)
    return not exists

def _find_sibling_leaf(row: List, left_offset: int):  # NOSONAR - leafR is binary tree notation
    """Find the right sibling leaf for a given left leaf offset."""
    right_offset = left_offset + 1
    leafR = next((l for l in row if l.get("offset") == right_offset), None)  # NOSONAR - Binary tree notation
    if leafR and "hash_str" in leafR:
        return leafR
    return None

def _compute_parent_leaf(leafL, leafR, hash_fn) -> dict:  # NOSONAR - Binary tree notation (Left/Right leaves)
    """Compute parent leaf from two sibling leaves."""
    offset_on_row = leafL["offset"] >> 1
    # String concatenation puts the right leaf on the left of the left leaf hash
    return {
        "offset": offset_on_row,
        "hash_str": hash_fn(leafR["hash_str"] + leafL["hash_str"])
    }


def trim_known_txids(beef: Beef, known_txids: List[str]) -> None:  # NOSONAR - Complexity (23), requires refactoring
    known = set(known_txids)
    to_delete = [txid for txid, btx in beef.txs.items() if btx.data_format == 2 and txid in known]
    for txid in to_delete:
        beef.txs.pop(txid, None)


def _attach_input_transaction(beef: Beef, txin) -> None:
    """Attach source transaction to input if available in BEEF."""
    if getattr(txin, "source_transaction", None) is None:
        parent = beef.txs.get(getattr(txin, "source_txid", None))
        if parent and parent.tx_obj:
            txin.source_transaction = parent.tx_obj

def _attach_merkle_path_recursive(beef: Beef, tx) -> None:
    """Recursively attach merkle paths to transaction and its parents."""
    mp = find_bump(beef, tx.txid())
    if mp is not None:
        tx.merkle_path = mp
        return
    
    for txin in getattr(tx, "inputs", []) or []:
        _attach_input_transaction(beef, txin)
        if getattr(txin, "source_transaction", None) is not None:
            source_tx = txin.source_transaction
            p = find_bump(beef, source_tx.txid())
            if p is not None:
                source_tx.merkle_path = p
            else:
                _attach_merkle_path_recursive(beef, source_tx)

def find_atomic_transaction(beef: Beef, txid: str):
    """
    Build the proof tree rooted at a specific Transaction.
    - If the transaction is directly proven by a bump, attach it.
    - Otherwise, recursively link parents and attach their bumps when available.
    Returns the Transaction or None.
    """
    btx = beef.txs.get(txid)
    if btx is None or btx.tx_obj is None:
        return None

    _attach_merkle_path_recursive(beef, btx.tx_obj)
    return btx.tx_obj


def txid_only_clone(beef: Beef) -> Beef:
    """
    Create a clone Beef with all transactions represented as txid-only.
    """
    c = Beef(version=beef.version)
    # shallow copy bumps
    c.bumps = list(getattr(beef, "bumps", []) or [])
    for txid, tx in beef.txs.items():
        entry = BeefTx(txid=txid, tx_bytes=b"", tx_obj=None, data_format=2, bump_index=None)
        c.txs[txid] = entry
    return c


