from __future__ import annotations

from typing import Optional, Dict, Set, Tuple

from bsv.utils import Reader
from bsv.transaction import Transaction
from bsv.merkle_path import MerklePath
from .beef import Beef, BeefTx, BEEF_V2


def remove_existing_txid(beef: Beef, txid: str) -> None:
    beef.txs.pop(txid, None)


def _leaf_exists_in_bump(bump: MerklePath, txid: str) -> bool:  # NOSONAR - Complexity (23), requires refactoring
    try:
        for leaf in bump.path[0]:
            if leaf.get("hash_str") == txid:
                return True
    except Exception:
        pass
    return False


def merge_bump(beef: Beef, bump: MerklePath) -> int:
    """
    Merge a MerklePath that is assumed to be fully valid into the beef and return its index.
    Tries to combine proofs that share the same block height and root.
    """
    # identical instance
    for i, existing in enumerate(getattr(beef, "bumps", []) or []):
        if existing is bump:
            return i

    # same root at same height → combine
    for i, existing in enumerate(beef.bumps):
        if getattr(existing, "block_height", None) == getattr(bump, "block_height", None):
            try:
                if existing.compute_root() == bump.compute_root():
                    existing.combine(bump)
                    return i
            except Exception:
                # cannot compute/compare root; skip to append
                pass

    # append new bump
    beef.bumps.append(bump)
    new_index = len(beef.bumps) - 1

    # attach bumps to any existing transactions if proven by this bump
    for btx in beef.txs.values():
        if btx.tx_obj is not None and btx.bump_index is None:
            try:
                if _leaf_exists_in_bump(bump, btx.txid):
                    btx.bump_index = new_index
                    btx.tx_obj.merkle_path = bump
            except Exception:
                pass

    return new_index


def _try_validate_bump_index(beef: Beef, btx: BeefTx) -> None:
    if btx.bump_index is not None:
        return
    for i, bump in enumerate(beef.bumps):
        if _leaf_exists_in_bump(bump, btx.txid):
            btx.bump_index = i
            try:
                # mark the leaf if present
                for leaf in bump.path[0]:
                    if leaf.get("hash_str") == btx.txid:
                        leaf["txid"] = True
                        break
            except Exception:
                pass
            return


def merge_raw_tx(beef: Beef, raw_tx: bytes, bump_index: Optional[int] = None) -> BeefTx:
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

    bump_index: Optional[int] = None
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
    return btx


def make_txid_only(beef: Beef, txid: str) -> Optional[BeefTx]:
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
    """
    if other_btx.data_format == 2 and other_btx.tx_obj is None and not other_btx.tx_bytes:
        return merge_txid_only(beef, other_btx.txid)
    if other_btx.tx_obj is not None:
        return merge_transaction(beef, other_btx.tx_obj)
    if other_btx.tx_bytes:
        return merge_raw_tx(beef, other_btx.tx_bytes, other_btx.bump_index)
    raise ValueError("invalid BeefTx: missing data")


def merge_beef(beef: Beef, other: Beef) -> None:
    """
    Merge all bumps and transactions from another Beef instance.
    """
    for bump in getattr(other, "bumps", []) or []:
        merge_bump(beef, bump)
    for btx in getattr(other, "txs", {}).values():
        merge_beef_tx(beef, btx)


