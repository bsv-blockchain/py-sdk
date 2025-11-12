from __future__ import annotations

from typing import Dict, Set, Optional, Callable

from bsv.utils import Writer, to_bytes
from bsv.transaction import Transaction
from bsv.merkle_path import MerklePath
from .beef import Beef, BeefTx, BEEF_V1, BEEF_V2, ATOMIC_BEEF


def to_bytes_le_u32(v: int) -> bytes:
    return int(v).to_bytes(4, "little", signed=False)


def _append_tx(writer: Writer, beef: Beef, btx: BeefTx, written: Set[str]) -> None:
    """
    Append one BeefTx to writer, ensuring parents are written first.
    """
    txid = btx.txid
    if txid in written:
        return

    if btx.data_format == 2:
        # TXID_ONLY
        writer.write_uint8(2)
        writer.write(to_bytes(txid, "hex")[::-1])
        written.add(txid)
        return

    tx: Optional[Transaction] = btx.tx_obj
    if tx is None and btx.tx_bytes:
        # best effort: parents unknown, just write as raw
        writer.write_uint8(1 if btx.bump_index is not None else 0)
        if btx.bump_index is not None:
            writer.write_var_int_num(btx.bump_index)
        writer.write(btx.tx_bytes)
        written.add(txid)
        return

    # ensure parents first
    if tx is not None:
        for txin in getattr(tx, "inputs", []) or []:
            parent_id = getattr(txin, "source_txid", None)
            if parent_id:
                parent = beef.txs.get(parent_id)
                if parent:
                    _append_tx(writer, beef, parent, written)

    writer.write_uint8(1 if btx.bump_index is not None else 0)
    if btx.bump_index is not None:
        writer.write_var_int_num(btx.bump_index)
    if tx is not None:
        writer.write(tx.serialize())
    else:
        writer.write(btx.tx_bytes)
    written.add(txid)


def to_binary(beef: Beef) -> bytes:
    """
    Serialize BEEF v2 to bytes (BRC-96).
    Note: Always writes current beef.version as little-endian u32 header.
    """
    writer = Writer()
    writer.write(to_bytes_le_u32(beef.version))

    # bumps
    writer.write_var_int_num(len(beef.bumps))
    for bump in beef.bumps:
        # MerklePath.to_binary returns bytes
        writer.write(bump.to_binary())

    # transactions
    writer.write_var_int_num(len(beef.txs))
    written: Set[str] = set()
    for btx in list(beef.txs.values()):
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


