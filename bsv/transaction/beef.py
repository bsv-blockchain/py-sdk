"""
BEEF / AtomicBEEF parsing utilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple

from bsv.hash import hash256
from bsv.transaction import Transaction  # existing parser

# ---------------------------------------------------------------------------
# 
# ---------------------------------------------------------------------------
# BRC-64 / BRC-96 / BRC-95
BEEF_V1 = 4022206465
BEEF_V2 = 4022206466
ATOMIC_BEEF = 0x01010101

BUFFER_EXHAUSTED_MSG = "buffer exhausted"


@dataclass
class BeefTx:
    """Transaction wrapper held inside a BEEF set."""

    txid: str
    tx_bytes: bytes = b""
    tx_obj: Optional[Transaction] = None
    data_format: int = 0  # 0 RawTx, 1 RawTxAndBumpIndex, 2 TxIDOnly
    bump_index: Optional[int] = None


@dataclass
class Beef:
    """Container for BUMP paths and transactions."""

    version: int
    txs: Dict[str, BeefTx] = field(default_factory=dict)
    bumps: List[object] = field(default_factory=list)

    # --- helpers ---
    def find_transaction(self, txid: str) -> Optional[BeefTx]:
        return self.txs.get(txid)

    def find_transaction_for_signing(self, txid: str) -> Optional[BeefTx]:
        """Return a transaction suitable for signing with inputs linked when possible.

        Current implementation returns the BeefTx if present; linking of inputs is
        a no-op because our minimal BeefTx does not yet hold parsed inputs. This
        will be extended alongside a full Transaction model integration.
        """
        btx = self.txs.get(txid)
        if not btx or not btx.tx_obj:
            return btx
        # Recursively link input source transactions when present in this Beef
        def _link_inputs(tx: Transaction):
            for txin in getattr(tx, "inputs", []) or []:
                src_id = getattr(txin, "source_txid", None)
                if not src_id:
                    continue
                parent = self.txs.get(src_id)
                if parent and parent.tx_obj:
                    txin.source_transaction = parent.tx_obj
                    _link_inputs(parent.tx_obj)
        _link_inputs(btx.tx_obj)
        return btx


# ---------------------------------------------------------------------------
# VarInt helpers (Bitcoin style – little-endian compact)                    
# ---------------------------------------------------------------------------


def _read_varint(buf: memoryview, offset: int) -> Tuple[int, int]:
    """Return (value, new_offset). Raises ValueError on overflow."""
    if offset >= len(buf):
        raise ValueError(BUFFER_EXHAUSTED_MSG)
    first = buf[offset]
    offset += 1
    if first < 0xFD:
        return first, offset
    if first == 0xFD:
        if offset + 2 > len(buf):
            raise ValueError(BUFFER_EXHAUSTED_MSG)
        val = int.from_bytes(buf[offset:offset+2], "little")
        offset += 2
        return val, offset
    if first == 0xFE:
        if offset + 4 > len(buf):
            raise ValueError(BUFFER_EXHAUSTED_MSG)
        val = int.from_bytes(buf[offset:offset+4], "little")
        offset += 4
        return val, offset
    # 0xFF
    if offset + 8 > len(buf):
        raise ValueError(BUFFER_EXHAUSTED_MSG)
    val = int.from_bytes(buf[offset:offset+8], "little")
    offset += 8
    return val, offset


# ---------------------------------------------------------------------------
# Factory helpers – minimal but robust enough for tests and KVStore flows
# ---------------------------------------------------------------------------

def new_beef_from_bytes(data: bytes) -> Beef:
    """Parse BEEF bytes."""
    mv = memoryview(data)
    if len(mv) < 4:
        raise ValueError("beef bytes too short")
    version = int.from_bytes(mv[:4], "little")
    if version == ATOMIC_BEEF:
        beef, _ = new_beef_from_atomic_bytes(data)
        return beef
    if version == BEEF_V2:
        return _parse_beef_v2(mv, version)
    if version == BEEF_V1:
        return _parse_beef_v1(data, version)
    raise ValueError("unsupported BEEF version")


def _parse_beef_v2(mv: memoryview, version: int) -> Beef:
    from bsv.utils import Reader
    from bsv.merkle_path import MerklePath
    reader = Reader(bytes(mv[4:]))
    bump_cnt = reader.read_var_int_num()
    bumps: List[Optional[MerklePath]] = []
    for _ in range(bump_cnt):
        bumps.append(MerklePath.from_reader(reader))
    tx_cnt = reader.read_var_int_num()
    beef = Beef(version=version)
    beef.bumps = bumps
    _parse_beef_v2_txs(reader, tx_cnt, beef, bumps)
    _link_inputs_and_bumps(beef)
    _fill_txidonly_placeholders(beef)
    try:
        normalize_bumps(beef)
    except Exception:
        pass
    return beef

def _parse_beef_v2_txs(reader, tx_cnt, beef, bumps):
    from bsv.transaction import Transaction
    for _ in range(tx_cnt):
        data_format = reader.read_uint8()
        if data_format not in (0, 1, 2):
            raise ValueError("unsupported tx data format")
        bump_index: Optional[int] = None
        if data_format == 1:
            bump_index = reader.read_var_int_num()
        if data_format == 2:
            txid_bytes = reader.read(32)
            txid = txid_bytes[::-1].hex()
            existing = beef.txs.get(txid)
            if existing is None or existing.tx_obj is None:
                beef.txs[txid] = BeefTx(txid=txid, tx_bytes=b"", tx_obj=None, data_format=2)
            continue
        tx = Transaction.from_reader(reader)
        txid = tx.txid()
        if bump_index is not None:
            if bump_index < 0 or bump_index >= len(bumps):
                raise ValueError("invalid bump index")
            tx.merkle_path = bumps[bump_index]
        btx = BeefTx(txid=txid, tx_bytes=tx.serialize(), tx_obj=tx, data_format=data_format, bump_index=bump_index)
        existing = beef.txs.get(txid)
        if existing is not None and existing.tx_obj is None:
            if btx.bump_index is None:
                btx.bump_index = existing.bump_index
        beef.txs[txid] = btx

def _link_inputs_and_bumps(beef: Beef):
    changed = True
    while changed:
        changed = False
        for btx in beef.txs.values():
            if btx.tx_obj is None:
                continue
            if _link_inputs_for_tx(btx, beef):
                changed = True
            _normalize_bump_for_tx(btx)

def _link_inputs_for_tx(btx, beef):
    updated = False
    for txin in btx.tx_obj.inputs:
        sid = getattr(txin, "source_txid", None)
        if sid and txin.source_transaction is None:
            parent = beef.txs.get(sid)
            if parent and parent.tx_obj:
                txin.source_transaction = parent.tx_obj
                updated = True
    return updated

def _normalize_bump_for_tx(btx):
    if btx.bump_index is not None and btx.tx_obj and btx.tx_obj.merkle_path:
        try:
            _ = btx.tx_obj.merkle_path.compute_root()
        except Exception:
            btx.tx_obj.merkle_path = None

def _fill_txidonly_placeholders(beef: Beef):
    for txid, entry in list(beef.txs.items()):
        if entry.tx_obj is None:
            for child in beef.txs.values():
                if child.tx_obj is None:
                    continue
                for txin in child.tx_obj.inputs:
                    if getattr(txin, "source_txid", None) == txid and txin.source_transaction is not None:
                        entry.tx_obj = txin.source_transaction
                        entry.tx_bytes = entry.tx_obj.serialize()
                        break
                if entry.tx_obj is not None:
                    break

def _parse_beef_v1(data: bytes, version: int) -> Beef:
    from bsv.transaction import Transaction as _Tx
    try:
        tx = _Tx.from_beef(data)
        raw = tx.serialize()
        txid = tx.txid()
        beef = Beef(version=version)
        beef.txs[txid] = BeefTx(txid=txid, tx_bytes=raw)
        return beef
    except Exception as e:
        raise ValueError(f"failed to parse BEEF v1: {e}")


def new_beef_from_atomic_bytes(data: bytes) -> tuple[Beef, Optional[str]]:
    if len(data) < 36:
        raise ValueError("atomic beef too short")
    if int.from_bytes(data[:4], "little") != ATOMIC_BEEF:
        raise ValueError("not atomic beef")
    subject = data[4:36][::-1].hex()  # txid big-endian to hex string
    inner = data[36:]
    beef = new_beef_from_bytes(inner)
    return beef, subject


def parse_beef(data: bytes) -> Beef:
    if len(data) < 4:
        raise ValueError("invalid beef bytes")
    version = int.from_bytes(data[:4], "little")
    if version == ATOMIC_BEEF:
        beef, _ = new_beef_from_atomic_bytes(data)
        return beef
    return new_beef_from_bytes(data)


def parse_beef_ex(data: bytes) -> tuple[Beef, Optional[str], Optional[Transaction]]:
    """Extended parser returning (beef, subject_txid_for_atomic, last_tx_for_v1 or subject)."""
    if len(data) < 4:
        raise ValueError("invalid beef bytes")
    version = int.from_bytes(data[:4], "little")
    if version == ATOMIC_BEEF:
        beef, subject = new_beef_from_atomic_bytes(data)
        # Recursively locate the subject tx in the inner BEEF (Go/TS parity)
        last_tx = None
        if subject:
            btx = beef.find_transaction(subject)
            last_tx = getattr(btx, "tx_obj", None) if btx else None
            # If not found, try recursively in nested AtomicBEEF
            if last_tx is None:
                # Try to find the subject in the inner BEEF's raw bytes if available
                # (Assume the inner BEEF is at data[36:])
                try:
                    _, _, nested_last_tx = parse_beef_ex(data[36:])
                    if nested_last_tx is not None:
                        last_tx = nested_last_tx
                except Exception:
                    pass
        return beef, subject, last_tx
    if version == BEEF_V1:
        # Use legacy Transaction.from_beef to get last tx
        from bsv.transaction import Transaction as _Tx
        tx = _Tx.from_beef(data)
        beef = new_beef_from_bytes(data)
        return beef, None, tx
    return new_beef_from_bytes(data), None, None


def normalize_bumps(beef: Beef) -> None:
    """Deduplicate and merge BUMPs by (block_height, root), remap indices on transactions.

    Uses MerklePath.combine/trim to merge proofs sharing the same block root, akin to Go's
    MergeBump. Invalid or non-mergeable bumps are left as-is.
    """
    if not getattr(beef, "bumps", None):
        return
    root_map: Dict[tuple, int] = {}
    index_map: Dict[int, int] = {}
    new_bumps: List[object] = []
    for old_index, bump in enumerate(beef.bumps):
        try:
            height = getattr(bump, "block_height", getattr(bump, "BlockHeight", None))
            root = bump.compute_root() if hasattr(bump, "compute_root") else None
            key = (height, root)
        except Exception:
            key = (old_index, None)
        if key in root_map:
            # Merge this bump into the canonical bump instance
            idx = root_map[key]
            try:
                # Combine proofs and trim
                new_bumps[idx].combine(bump)
                new_bumps[idx].trim()
            except Exception:
                pass
            index_map[old_index] = idx
        else:
            new_index = len(new_bumps)
            root_map[key] = new_index
            index_map[old_index] = new_index
            new_bumps.append(bump)
    beef.bumps = new_bumps
    # Remap tx bump indices
    for btx in beef.txs.values():
        if btx.bump_index is not None and btx.bump_index in index_map:
            btx.bump_index = index_map[btx.bump_index]
