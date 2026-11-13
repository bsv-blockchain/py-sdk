from __future__ import annotations

from typing import Callable, Dict, Optional, Set

from bsv.merkle_path import MerklePath
from bsv.transaction import Transaction
from bsv.utils import Writer, to_bytes

from .beef import ATOMIC_BEEF, BEEF_V1, BEEF_V2, Beef, BeefTx
from .beef_validate import sort_txs


def to_bytes_le_u32(v: int) -> bytes:
    return int(v).to_bytes(4, "little", signed=False)


def _append_tx(writer: Writer, beef: Beef, btx: BeefTx) -> None:
    """
    Append one BeefTx to writer.

    V2 (BRC-96) entries are [format][bump index?][raw tx | txid]; V1 (BRC-62) entries are
    [raw tx][has bump][bump index?] and cannot express TxIDOnly.
    """
    if btx.data_format == 2:
        if beef.version == BEEF_V1:
            raise ValueError(f"BEEF V1 cannot hold TxIDOnly transactions: {btx.txid}")
        writer.write_uint8(2)
        writer.write(to_bytes(btx.txid, "hex")[::-1])
        return

    raw = btx.tx_obj.serialize() if btx.tx_obj is not None else btx.tx_bytes
    if not raw:
        raise ValueError(f"missing transaction data: {btx.txid}")

    proof = Writer()
    proof.write_uint8(0 if btx.bump_index is None else 1)
    if btx.bump_index is not None:
        proof.write_var_int_num(btx.bump_index)
    writer.write(raw + proof.to_bytes() if beef.version == BEEF_V1 else proof.to_bytes() + raw)


def _serialize(beef: Beef) -> bytes:
    """Write beef in its current transaction order."""
    if beef.version not in (BEEF_V1, BEEF_V2):
        raise ValueError(f"unsupported BEEF version: {beef.version}")

    writer = Writer()
    writer.write(to_bytes_le_u32(beef.version))
    writer.write_var_int_num(len(beef.bumps))
    for bump in beef.bumps:
        writer.write(bump.to_binary())
    writer.write_var_int_num(len(beef.txs))
    for btx in beef.txs.values():
        _append_tx(writer, beef, btx)
    return writer.to_bytes()


def to_binary(beef: Beef) -> bytes:
    """
    Serialize to BEEF bytes in the layout of beef.version (BEEF_V1 / BEEF_V2), after sorting
    the transactions like TS Beef.toBinary (parents before children).
    """
    sort_txs(beef)
    return _serialize(beef)


def to_binary_atomic(beef: Beef, txid: str) -> bytes:
    """
    Serialize this Beef as AtomicBEEF:
    [ATOMIC_BEEF(4 LE)] + [txid(32 BE bytes reversed)] + [BEEF bytes]

    As in TS, txid must be in the Beef, and transactions sorted after it are left out.
    """
    sort_txs(beef)
    if txid not in beef.txs:
        raise ValueError(f"{txid} does not exist in this Beef")
    body = beef
    txids = list(beef.txs)
    if txids[-1] != txid:
        body = beef.clone()
        body.txs = {t: beef.txs[t] for t in txids[: txids.index(txid) + 1]}
    return to_bytes_le_u32(ATOMIC_BEEF) + to_bytes(txid, "hex")[::-1] + _serialize(body)


def to_hex(beef: Beef) -> str:
    return to_binary(beef).hex()
