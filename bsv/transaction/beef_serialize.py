from __future__ import annotations

from typing import Callable, Dict, Optional, Set

from bsv.merkle_path import MerklePath
from bsv.transaction import Transaction
from bsv.utils import Writer, to_bytes

from .beef import ATOMIC_BEEF, BEEF_V1, BEEF_V2, Beef, BeefTx


def to_bytes_le_u32(v: int) -> bytes:
    return int(v).to_bytes(4, "little", signed=False)


def _ensure_parents_written(writer: Writer, beef: Beef, tx: Transaction, written: set[str]) -> None:
    """Recursively write parent transactions before the current one."""
    for txin in getattr(tx, "inputs", []) or []:
        parent_id = getattr(txin, "source_txid", None)
        if parent_id:
            parent = beef.txs.get(parent_id)
            if parent:
                _append_tx(writer, beef, parent, written)


def _append_tx(writer: Writer, beef: Beef, btx: BeefTx, written: set[str]) -> None:
    """
    Append one BeefTx to writer, ensuring parents are written first.

    V2 (BRC-96) entries are [format][bump index?][raw tx | txid]; V1 (BRC-62) entries are
    [raw tx][has bump][bump index?] and cannot express TxIDOnly.
    """
    if btx.txid in written:
        return

    if btx.data_format == 2:
        if beef.version == BEEF_V1:
            raise ValueError(f"BEEF V1 cannot hold TxIDOnly transactions: {btx.txid}")
        writer.write_uint8(2)
        writer.write(to_bytes(btx.txid, "hex")[::-1])
        written.add(btx.txid)
        return

    if btx.tx_obj is not None:
        _ensure_parents_written(writer, beef, btx.tx_obj, written)
        raw = btx.tx_obj.serialize()
    else:
        raw = btx.tx_bytes
    if not raw:
        raise ValueError(f"missing transaction data: {btx.txid}")

    proof = Writer()
    proof.write_uint8(0 if btx.bump_index is None else 1)
    if btx.bump_index is not None:
        proof.write_var_int_num(btx.bump_index)
    writer.write(raw + proof.to_bytes() if beef.version == BEEF_V1 else proof.to_bytes() + raw)
    written.add(btx.txid)


def to_binary(beef: Beef) -> bytes:
    """
    Serialize to BEEF bytes in the layout of beef.version (BEEF_V1 / BEEF_V2).
    """
    if beef.version not in (BEEF_V1, BEEF_V2):
        raise ValueError(f"unsupported BEEF version: {beef.version}")

    writer = Writer()
    writer.write(to_bytes_le_u32(beef.version))

    # bumps
    writer.write_var_int_num(len(beef.bumps))
    for bump in beef.bumps:
        # MerklePath.to_binary returns bytes
        writer.write(bump.to_binary())

    # transactions
    writer.write_var_int_num(len(beef.txs))
    written: set[str] = set()
    for btx in beef.txs.values():
        _append_tx(writer, beef, btx, written)

    return writer.to_bytes()


def to_binary_atomic(beef: Beef, txid: str) -> bytes:
    """
    Serialize this Beef as AtomicBEEF:
    [ATOMIC_BEEF(4 LE)] + [txid(32 BE bytes reversed)] + [BEEF bytes]
    """
    body = to_binary(beef)
    return to_bytes_le_u32(ATOMIC_BEEF) + to_bytes(txid, "hex")[::-1] + body


def to_hex(beef: Beef) -> str:
    return to_binary(beef).hex()
