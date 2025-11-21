"""
BEEF / AtomicBEEF parsing utilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple, TYPE_CHECKING

from bsv.hash import hash256
from bsv.transaction import Transaction  # existing parser

if TYPE_CHECKING:
    from bsv.merkle_path import MerklePath

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

    # --- builder: merge/edit APIs ---
    def remove_existing_txid(self, txid: str) -> None:
        from .beef_builder import remove_existing_txid as _rm
        _rm(self, txid)

    def merge_bump(self, bump: "MerklePath") -> int:
        from .beef_builder import merge_bump as _merge_bump
        return _merge_bump(self, bump)

    def merge_raw_tx(self, raw_tx: bytes, bump_index: Optional[int] = None) -> BeefTx:
        from .beef_builder import merge_raw_tx as _merge_raw_tx
        return _merge_raw_tx(self, raw_tx, bump_index)

    def merge_transaction(self, tx: Transaction) -> BeefTx:
        from .beef_builder import merge_transaction as _merge_transaction
        return _merge_transaction(self, tx)

    def merge_txid_only(self, txid: str) -> BeefTx:
        from .beef_builder import merge_txid_only as _merge_txid_only
        return _merge_txid_only(self, txid)

    def make_txid_only(self, txid: str) -> Optional[BeefTx]:
        from .beef_builder import make_txid_only as _make_txid_only
        return _make_txid_only(self, txid)

    def merge_beef_tx(self, btx: BeefTx) -> BeefTx:
        from .beef_builder import merge_beef_tx as _merge_beef_tx
        return _merge_beef_tx(self, btx)

    def merge_beef(self, other: "Beef") -> None:
        from .beef_builder import merge_beef as _merge_beef
        _merge_beef(self, other)

    # --- validation APIs ---
    def is_valid(self, allow_txid_only: bool = False) -> bool:
        from .beef_validate import is_valid as _is_valid
        return _is_valid(self, allow_txid_only=allow_txid_only)

    def verify_valid(self, allow_txid_only: bool = False) -> tuple[bool, Dict[int, str]]:
        from .beef_validate import verify_valid as _verify_valid
        return _verify_valid(self, allow_txid_only=allow_txid_only)

    def get_valid_txids(self) -> List[str]:
        from .beef_validate import get_valid_txids as _get_valid_txids
        return _get_valid_txids(self)

    # --- serialization APIs ---
    def to_binary(self) -> bytes:
        from .beef_serialize import to_binary as _to_binary
        return _to_binary(self)

    def to_hex(self) -> str:
        from .beef_serialize import to_hex as _to_hex
        return _to_hex(self)

    def to_binary_atomic(self, txid: str) -> bytes:
        from .beef_serialize import to_binary_atomic as _to_binary_atomic
        return _to_binary_atomic(self, txid)

    # --- utilities ---
    def find_bump(self, txid: str) -> Optional["MerklePath"]:
        from .beef_utils import find_bump as _find_bump
        return _find_bump(self, txid)

    def find_atomic_transaction(self, txid: str) -> Optional[Transaction]:
        from .beef_utils import find_atomic_transaction as _find_atomic
        return _find_atomic(self, txid)

    def to_log_string(self) -> str:
        from .beef_utils import to_log_string as _to_log_string
        return _to_log_string(self)

    def add_computed_leaves(self) -> None:
        from .beef_utils import add_computed_leaves as _add_computed_leaves
        _add_computed_leaves(self)

    def trim_known_txids(self, known_txids: List[str]) -> None:
        from .beef_utils import trim_known_txids as _trim_known_txids
        _trim_known_txids(self, known_txids)

    def txid_only(self) -> "Beef":
        from .beef_utils import txid_only_clone as _txid_only_clone
        return _txid_only_clone(self)

    async def verify(self, chaintracker, allow_txid_only: bool = False) -> bool:
        """
        Confirm validity by verifying computed merkle roots using ChainTracker.
        """
        from .beef_validate import verify_valid as _verify_valid
        ok, roots = _verify_valid(self, allow_txid_only=allow_txid_only)
        if not ok:
            return False
        # roots: Dict[height, root_hex]
        for height, root in roots.items():
            valid = await chaintracker.is_valid_root_for_height(root, height)
            if not valid:
                return False
        return True

    def merge_beef_bytes(self, data: bytes) -> None:
        """
        Merge BEEF serialized bytes into this Beef.
        """
        from .beef_builder import merge_beef as _merge_beef
        other = new_beef_from_bytes(data)
        _merge_beef(self, other)

    def clone(self) -> "Beef":
        """
        Return a shallow clone of this Beef.
        - BUMPs list is shallow-copied
        - Transactions mapping is shallow-copied (entries reference same BeefTx)
        """
        c = Beef(version=self.version)
        c.bumps = list(getattr(self, "bumps", []) or [])
        c.txs = {txid: entry for txid, entry in getattr(self, "txs", {}).items()}
        return c


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
        _parse_single_beef_tx(reader, beef, bumps)

def _parse_single_beef_tx(reader, beef, bumps):
    """Parse a single transaction from BEEF v2 format."""
    from bsv.transaction import Transaction
    
    data_format = reader.read_uint8()
    if data_format not in (0, 1, 2):
        raise ValueError("unsupported tx data format")
    
    bump_index = _read_bump_index(reader, data_format)
    
    # Handle txid-only format
    if data_format == 2:
        _handle_txid_only_format(reader, beef)
        return
    
    # Parse full transaction
    tx = Transaction.from_reader(reader)
    txid = tx.txid()
    
    if bump_index is not None:
        _attach_merkle_path(tx, bump_index, bumps)
    
    btx = BeefTx(txid=txid, tx_bytes=tx.serialize(), tx_obj=tx, 
                 data_format=data_format, bump_index=bump_index)
    _update_beef_with_tx(beef, txid, btx)

def _read_bump_index(reader, data_format):
    """Read bump index if present in format."""
    if data_format == 1:
        return reader.read_var_int_num()
    return None

def _handle_txid_only_format(reader, beef):
    """Handle txid-only transaction format."""
    txid_bytes = reader.read(32)
    txid = txid_bytes[::-1].hex()
    existing = beef.txs.get(txid)
    if existing is None or existing.tx_obj is None:
        beef.txs[txid] = BeefTx(txid=txid, tx_bytes=b"", tx_obj=None, data_format=2)

def _attach_merkle_path(tx, bump_index, bumps):
    """Attach merkle path from bumps to transaction."""
    if bump_index < 0 or bump_index >= len(bumps):
        raise ValueError("invalid bump index")
    tx.merkle_path = bumps[bump_index]

def _update_beef_with_tx(beef, txid, btx):
    """Update BEEF structure with parsed transaction."""
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

def _normalize_bump_for_tx(btx):  # NOSONAR - Complexity (24), requires refactoring
    if btx.bump_index is not None and btx.tx_obj and btx.tx_obj.merkle_path:
        try:
            _ = btx.tx_obj.merkle_path.compute_root()
        except Exception:
            btx.tx_obj.merkle_path = None

def _find_transaction_in_child_inputs(beef: Beef, target_txid: str):
    """Search for a transaction in child transaction inputs."""
    for child in beef.txs.values():
        if child.tx_obj is None:
            continue
        for txin in child.tx_obj.inputs:
            if getattr(txin, "source_txid", None) == target_txid and txin.source_transaction is not None:
                return txin.source_transaction
    return None

def _fill_txidonly_placeholders(beef: Beef):
    """Fill txid-only placeholders with actual transactions from child inputs."""
    for txid, entry in list(beef.txs.items()):
        if entry.tx_obj is None:
            tx = _find_transaction_in_child_inputs(beef, txid)
            if tx is not None:
                entry.tx_obj = tx
                entry.tx_bytes = tx.serialize()

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


def parse_beef(data: bytes) -> Beef:  # NOSONAR - Complexity (19), requires refactoring
    if len(data) < 4:
        raise ValueError("invalid beef bytes")
    version = int.from_bytes(data[:4], "little")
    if version == ATOMIC_BEEF:
        beef, _ = new_beef_from_atomic_bytes(data)
        return beef
    return new_beef_from_bytes(data)


def _find_subject_transaction(beef: Beef, subject: str, data: bytes) -> Optional[Transaction]:
    """Find the subject transaction in the BEEF, checking nested BEEFs if needed."""
    btx = beef.find_transaction(subject)
    last_tx = getattr(btx, "tx_obj", None) if btx else None
    
    # If not found, try recursively in nested AtomicBEEF
    if last_tx is None:
        try:
            _, _, nested_last_tx = parse_beef_ex(data[36:])
            if nested_last_tx is not None:
                last_tx = nested_last_tx
        except Exception:
            pass
    
    return last_tx

def _parse_atomic_beef(data: bytes) -> tuple[Beef, Optional[str], Optional[Transaction]]:
    """Parse an Atomic BEEF and find the subject transaction."""
    beef, subject = new_beef_from_atomic_bytes(data)
    last_tx = None
    if subject:
        last_tx = _find_subject_transaction(beef, subject, data)
    return beef, subject, last_tx

def _parse_v1_beef(data: bytes) -> tuple[Beef, Optional[str], Optional[Transaction]]:
    """Parse a V1 BEEF format."""
    from bsv.transaction import Transaction as _Tx
    tx = _Tx.from_beef(data)
    beef = new_beef_from_bytes(data)
    return beef, None, tx

def parse_beef_ex(data: bytes) -> tuple[Beef, Optional[str], Optional[Transaction]]:
    """Extended parser returning (beef, subject_txid_for_atomic, last_tx_for_v1 or subject)."""
    if len(data) < 4:
        raise ValueError("invalid beef bytes")
    
    version = int.from_bytes(data[:4], "little")
    
    if version == ATOMIC_BEEF:
        return _parse_atomic_beef(data)
    if version == BEEF_V1:
        return _parse_v1_beef(data)
    return new_beef_from_bytes(data), None, None


def normalize_bumps(beef: Beef) -> None:
    """Deduplicate and merge BUMPs by (block_height, root), remap indices on transactions.

    Uses MerklePath.combine/trim to merge proofs sharing the same block root, akin to Go's
    MergeBump. Invalid or non-mergeable bumps are left as-is.
    """
    if not getattr(beef, "bumps", None):
        return
    
    _, index_map, new_bumps = _deduplicate_bumps(beef.bumps)
    beef.bumps = new_bumps
    _remap_transaction_indices(beef, index_map)

def _deduplicate_bumps(bumps: List) -> tuple[Dict[tuple, int], Dict[int, int], List]:
    """Deduplicate bumps by merging those with same (height, root)."""
    root_map: Dict[tuple, int] = {}
    index_map: Dict[int, int] = {}
    new_bumps: List[object] = []
    
    for old_index, bump in enumerate(bumps):
        key = _compute_bump_key(bump, old_index)
        
        if key in root_map:
            idx = _merge_bump(new_bumps, bump, root_map[key])
            index_map[old_index] = idx
        else:
            new_index = _add_new_bump(new_bumps, bump, key, root_map)
            index_map[old_index] = new_index
    
    return root_map, index_map, new_bumps

def _compute_bump_key(bump, fallback_index: int) -> tuple:
    """Compute deduplication key for a bump (height, root)."""
    try:
        height = getattr(bump, "block_height", getattr(bump, "BlockHeight", None))
        root = bump.compute_root() if hasattr(bump, "compute_root") else None
        return (height, root)
    except Exception:
        return (fallback_index, None)

def _merge_bump(new_bumps: List, bump, target_idx: int) -> int:
    """Merge a bump into an existing bump at target_idx."""
    try:
        new_bumps[target_idx].combine(bump)
        new_bumps[target_idx].trim()
    except Exception:
        pass  # Best-effort merge
    return target_idx

def _add_new_bump(new_bumps: List, bump, key: tuple, root_map: Dict[tuple, int]) -> int:
    """Add a new bump to the collection."""
    new_index = len(new_bumps)
    root_map[key] = new_index
    new_bumps.append(bump)
    return new_index

def _remap_transaction_indices(beef: Beef, index_map: Dict[int, int]):
    """Remap transaction bump indices to use new deduplicated indices."""
    for btx in beef.txs.values():
        if btx.bump_index is not None and btx.bump_index in index_map:
            btx.bump_index = index_map[btx.bump_index]
