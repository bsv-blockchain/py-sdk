from __future__ import annotations

from typing import Dict, Optional, Set, Tuple

from bsv.merkle_path import MerklePath
from bsv.transaction import Transaction
from bsv.utils import Reader

from .beef import BEEF_V2, Beef, BeefTx


def remove_existing_txid(beef: Beef, txid: str) -> None:
    beef.txs.pop(txid, None)


def _find_identical_bump(beef: Beef, bump: MerklePath) -> int | None:
    """Check if identical bump instance already exists."""
    for i, existing in enumerate(getattr(beef, "bumps", []) or []):
        if existing is bump:
            return i
    return None


def _find_combinable_bump(beef: Beef, bump: MerklePath) -> int | None:
    """Find bump with same height and root that can be combined."""
    for i, existing in enumerate(beef.bumps):
        if getattr(existing, "block_height", None) == getattr(bump, "block_height", None):
            try:
                if existing.compute_root() == bump.compute_root():
                    existing.combine(bump)
                    return i
            except Exception:
                pass
    return None


def _attach_bump_to_transactions(beef: Beef, bump: MerklePath, bump_index: int) -> None:
    """Record bump_index on every unproven transaction (TxIDOnly included) that bump proves."""
    for btx in beef.txs.values():
        if btx.bump_index is None:
            _mark_proven(btx, bump, bump_index)


def _mark_proven(btx: BeefTx, bump: MerklePath, bump_index: int) -> bool:
    """Set btx.bump_index and flag its leaf as a txid when bump holds btx.txid at level 0 (TS)."""
    for leaf in bump.path[0]:
        if leaf.get("hash_str") == btx.txid:
            btx.bump_index = bump_index
            leaf["txid"] = True
            if btx.tx_obj is not None:
                btx.tx_obj.merkle_path = bump
            return True
    return False


def merge_bump(beef: Beef, bump: MerklePath) -> int:
    """
    Merge a MerklePath that is assumed to be fully valid into the beef and return its index.
    Tries to combine proofs that share the same block height and root, then records the index
    on the transactions the merged bump proves (TS Beef.mergeBump).
    """
    idx = _find_identical_bump(beef, bump)
    if idx is None:
        idx = _find_combinable_bump(beef, bump)
    if idx is None:
        beef.bumps.append(bump)
        idx = len(beef.bumps) - 1
    _attach_bump_to_transactions(beef, beef.bumps[idx], idx)
    return idx


def _try_validate_bump_index(beef: Beef, btx: BeefTx) -> None:
    if btx.bump_index is not None:
        return
    for i, bump in enumerate(beef.bumps):
        if _mark_proven(btx, bump, i):
            return


def merge_raw_tx(beef: Beef, raw_tx: bytes, bump_index: int | None = None) -> BeefTx:
    """
    Merge a serialized transaction (raw bytes).
    If bump_index is provided, it must be a valid index in beef.bumps.
    """
    reader = Reader(raw_tx)
    tx = Transaction.from_reader(reader)
    txid = tx.txid()

    remove_existing_txid(beef, txid)

    data_format = 0
    if bump_index is not None:
        if bump_index < 0 or bump_index >= len(beef.bumps):
            raise ValueError("invalid bump index")
        tx.merkle_path = beef.bumps[bump_index]
        data_format = 1

    btx = BeefTx(txid=txid, tx_bytes=tx.serialize(), tx_obj=tx, data_format=data_format, bump_index=bump_index)
    beef.txs[txid] = btx
    _try_validate_bump_index(beef, btx)
    return btx


def merge_transaction(beef: Beef, tx: Transaction) -> BeefTx:
    """
    Merge a Transaction object (and any referenced merklePath / sourceTransaction, recursively).
    """
    txid = tx.txid()
    remove_existing_txid(beef, txid)

    bump_index: int | None = None
    if getattr(tx, "merkle_path", None) is not None:
        bump_index = merge_bump(beef, tx.merkle_path)

    data_format = 0
    if bump_index is not None:
        data_format = 1

    new_tx = BeefTx(txid=txid, tx_bytes=tx.serialize(), tx_obj=tx, data_format=data_format, bump_index=bump_index)
    beef.txs[txid] = new_tx
    _try_validate_bump_index(beef, new_tx)

    if bump_index is None:
        # ensure parents are incorporated
        for txin in getattr(tx, "inputs", []) or []:
            if getattr(txin, "source_transaction", None) is not None:
                merge_transaction(beef, txin.source_transaction)

    return new_tx


def merge_txid_only(beef: Beef, txid: str) -> BeefTx:
    btx = beef.txs.get(txid)
    if btx is None:
        btx = BeefTx(txid=txid, tx_bytes=b"", tx_obj=None, data_format=2, bump_index=None)
        beef.txs[txid] = btx
        _try_validate_bump_index(beef, btx)
    return btx


def make_txid_only(beef: Beef, txid: str) -> BeefTx | None:
    """
    Replace an existing BeefTx for txid with txid-only form.
    """
    btx = beef.txs.get(txid)
    if btx is None:
        return None
    if btx.data_format == 2:
        return btx
    beef.txs[txid] = BeefTx(txid=txid, tx_bytes=b"", tx_obj=None, data_format=2, bump_index=btx.bump_index)
    return beef.txs[txid]


def merge_beef_tx(beef: Beef, other_btx: BeefTx) -> BeefTx:
    """
    Merge a BeefTx-like entry: supports txid-only or full transaction.
    As in TS, an existing entry is replaced only when it is TxIDOnly.
    """
    existing = beef.txs.get(other_btx.txid)
    if existing is not None and not (existing.data_format == 2 and existing.tx_obj is None):
        return existing
    if other_btx.data_format == 2 and other_btx.tx_obj is None and not other_btx.tx_bytes:
        return existing or merge_txid_only(beef, other_btx.txid)
    if other_btx.tx_obj is not None:
        return merge_transaction(beef, other_btx.tx_obj)
    if other_btx.tx_bytes:
        return merge_raw_tx(beef, other_btx.tx_bytes)
    raise ValueError("invalid BeefTx: missing data")


def merge_beef(beef: Beef, other: Beef) -> None:
    """
    Merge all bumps and transactions from another Beef instance.
    """
    for bump in getattr(other, "bumps", []) or []:
        merge_bump(beef, bump)
    for btx in getattr(other, "txs", {}).values():
        merge_beef_tx(beef, btx)
