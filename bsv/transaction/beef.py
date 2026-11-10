"""
BEEF / AtomicBEEF parsing utilities.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

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


@dataclass
class BeefTx:
    """Transaction wrapper held inside a BEEF set."""

    txid: str
    tx_bytes: bytes = b""
    tx_obj: Transaction | None = None
    data_format: int = 0  # 0 RawTx, 1 RawTxAndBumpIndex, 2 TxIDOnly
    bump_index: int | None = None


@dataclass
class Beef:
    """Container for BUMP paths and transactions.

    atomic_txid is the subject txid when the Beef was parsed from Atomic BEEF (BRC-95).
    """

    version: int = BEEF_V2
    txs: dict[str, BeefTx] = field(default_factory=dict)
    bumps: list[object] = field(default_factory=list)
    atomic_txid: str | None = None

    @classmethod
    def from_binary(cls, data: bytes) -> Beef:
        """Parse BEEF V1, V2 or Atomic BEEF bytes."""
        return new_beef_from_bytes(data)

    @classmethod
    def from_string(cls, s: str, enc: str = "hex") -> Beef:
        """Parse BEEF from a hex or base64 string."""
        if enc == "hex":
            return cls.from_binary(bytes.fromhex(s))
        if enc == "base64":
            return cls.from_binary(base64.b64decode(s))
        raise ValueError(f"unsupported encoding: {enc}")

    # --- helpers ---
    def find_transaction(self, txid: str) -> BeefTx | None:
        return self.txs.get(txid)

    def find_transaction_for_signing(self, txid: str) -> BeefTx | None:
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

    def merge_bump(self, bump) -> int:
        from .beef_builder import merge_bump as _merge_bump

        return _merge_bump(self, bump)

    def merge_raw_tx(self, raw_tx: bytes, bump_index: int | None = None) -> BeefTx:
        from .beef_builder import merge_raw_tx as _merge_raw_tx

        return _merge_raw_tx(self, raw_tx, bump_index)

    def merge_transaction(self, tx: Transaction) -> BeefTx:
        from .beef_builder import merge_transaction as _merge_transaction

        return _merge_transaction(self, tx)

    def merge_txid_only(self, txid: str) -> BeefTx:
        from .beef_builder import merge_txid_only as _merge_txid_only

        return _merge_txid_only(self, txid)

    def make_txid_only(self, txid: str) -> BeefTx | None:
        from .beef_builder import make_txid_only as _make_txid_only

        return _make_txid_only(self, txid)

    def merge_beef_tx(self, btx: BeefTx) -> BeefTx:
        from .beef_builder import merge_beef_tx as _merge_beef_tx

        return _merge_beef_tx(self, btx)

    def merge_beef(self, other: Beef | bytes) -> None:
        """Merge another Beef, or its serialized bytes."""
        from .beef_builder import merge_beef as _merge_beef

        if not isinstance(other, Beef):
            other = new_beef_from_bytes(bytes(other))
        _merge_beef(self, other)

    # --- validation APIs ---
    def is_valid(self, allow_txid_only: bool = False) -> bool:
        from .beef_validate import is_valid as _is_valid

        return _is_valid(self, allow_txid_only=allow_txid_only)

    def verify_valid(self, allow_txid_only: bool = False) -> tuple[bool, dict[int, str]]:
        from .beef_validate import verify_valid as _verify_valid

        return _verify_valid(self, allow_txid_only=allow_txid_only)

    def get_valid_txids(self) -> list[str]:
        from .beef_validate import get_valid_txids as _get_valid_txids

        return _get_valid_txids(self)

    def sort_txs(self):
        """Reorder txs by dependency like TS Beef.sortTxs and return the ValidationResult."""
        from .beef_validate import sort_txs as _sort_txs

        return _sort_txs(self)

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
    def find_bump(self, txid: str) -> MerklePath | None:
        from .beef_utils import find_bump as _find_bump

        return _find_bump(self, txid)

    def find_atomic_transaction(self, txid: str) -> Transaction | None:
        from .beef_utils import find_atomic_transaction as _find_atomic

        return _find_atomic(self, txid)

    def to_log_string(self) -> str:
        from .beef_utils import to_log_string as _to_log_string

        return _to_log_string(self)

    def add_computed_leaves(self) -> None:
        from .beef_utils import add_computed_leaves as _add_computed_leaves

        _add_computed_leaves(self)

    def trim_known_txids(self, known_txids: list[str]) -> None:
        from .beef_utils import trim_known_txids as _trim_known_txids

        _trim_known_txids(self, known_txids)

    def txid_only(self) -> Beef:
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

    def clone(self) -> Beef:
        """
        Return a shallow clone of this Beef.
        - BUMPs list is shallow-copied
        - Transactions mapping is shallow-copied (entries reference same BeefTx)
        """
        c = Beef(version=self.version)
        c.bumps = list(getattr(self, "bumps", []) or [])
        c.txs = dict(getattr(self, "txs", {}).items())
        return c


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def new_beef_from_bytes(data: bytes) -> Beef:
    """Parse BEEF V1, V2 or Atomic BEEF bytes. Atomic BEEF sets atomic_txid; nesting it is rejected."""
    from bsv.utils import Reader

    data = bytes(data)
    if len(data) < 4:
        raise ValueError("beef bytes too short")
    reader = Reader(data)
    version = reader.read_uint32_le()
    atomic_txid = None
    if version == ATOMIC_BEEF:
        if len(data) < 40:
            raise ValueError("atomic beef too short")
        atomic_txid = reader.read(32)[::-1].hex()
        version = reader.read_uint32_le()
    if version not in (BEEF_V1, BEEF_V2):
        raise ValueError(f"unsupported BEEF version: {version}")
    beef = _parse_beef_body(reader, version)
    beef.atomic_txid = atomic_txid
    return beef


def _parse_beef_body(reader, version: int) -> Beef:
    from bsv.merkle_path import MerklePath

    bump_cnt = reader.read_var_int_num()
    bumps: list[MerklePath | None] = []
    for _ in range(bump_cnt):
        # add_computed_leaves() adds leaves that are not legal offsets (TS reads BUMPs the same way).
        bumps.append(MerklePath.from_reader(reader, legal_offsets_only=False))
    tx_cnt = reader.read_var_int_num()
    beef = Beef(version=version)
    beef.bumps = bumps
    for _ in range(tx_cnt):
        _parse_single_beef_tx(reader, beef, bumps, version)
    _link_inputs_and_bumps(beef)
    _fill_txidonly_placeholders(beef)
    try:
        normalize_bumps(beef)
    except Exception:
        pass
    return beef


def _parse_single_beef_tx(reader, beef, bumps, version):
    """Parse one transaction entry.

    V2 (BRC-96): [format][bump index if format 1][raw tx, or txid if format 2]
    V1 (BRC-62): [raw tx][has bump][bump index if has bump]
    """
    from bsv.transaction import Transaction

    if version == BEEF_V1:
        tx = Transaction.from_reader(reader)
        data_format = reader.read_uint8()
        if data_format not in (0, 1):
            raise ValueError("unsupported tx data format")
        bump_index = _read_bump_index(reader, data_format)
    else:
        data_format = reader.read_uint8()
        if data_format not in (0, 1, 2):
            raise ValueError("unsupported tx data format")
        bump_index = _read_bump_index(reader, data_format)
        if data_format == 2:
            _handle_txid_only_format(reader, beef)
            return
        tx = Transaction.from_reader(reader)
    txid = tx.txid()

    if bump_index is not None:
        _attach_merkle_path(tx, bump_index, bumps)

    btx = BeefTx(txid=txid, tx_bytes=tx.serialize(), tx_obj=tx, data_format=data_format, bump_index=bump_index)
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
    for txid, entry in beef.txs.items():
        if entry.tx_obj is None:
            tx = _find_transaction_in_child_inputs(beef, txid)
            if tx is not None:
                entry.tx_obj = tx
                entry.tx_bytes = tx.serialize()


def new_beef_from_atomic_bytes(data: bytes) -> tuple[Beef, str | None]:
    if len(data) < 36:
        raise ValueError("atomic beef too short")
    if int.from_bytes(data[:4], "little") != ATOMIC_BEEF:
        raise ValueError("not atomic beef")
    beef = new_beef_from_bytes(data)
    return beef, beef.atomic_txid


def parse_beef(data: bytes) -> Beef:
    if len(data) < 4:
        raise ValueError("invalid beef bytes")
    return new_beef_from_bytes(data)


def parse_beef_ex(data: bytes) -> tuple[Beef, str | None, Transaction | None]:
    """Extended parser returning (beef, subject_txid_for_atomic, subject tx or last V1 tx).

    Atomic BEEF must contain its subject transaction (TS Transaction.fromAtomicBEEF).
    """
    beef = parse_beef(data)
    if beef.atomic_txid is not None:
        btx = beef.find_transaction(beef.atomic_txid)
        if btx is None or btx.tx_obj is None:
            raise ValueError(f"atomic BEEF does not contain its subject transaction {beef.atomic_txid}")
        return beef, beef.atomic_txid, btx.tx_obj
    if beef.version == BEEF_V1:
        last = next(reversed(beef.txs.values()), None)
        return beef, None, last.tx_obj if last else None
    return beef, None, None


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


def _deduplicate_bumps(bumps: list) -> tuple[dict[tuple, int], dict[int, int], list]:
    """Deduplicate bumps by merging those with same (height, root)."""
    root_map: dict[tuple, int] = {}
    index_map: dict[int, int] = {}
    new_bumps: list[object] = []

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


def _merge_bump(new_bumps: list, bump, target_idx: int) -> int:
    """Merge a bump into an existing bump at target_idx."""
    try:
        new_bumps[target_idx].combine(bump)
        new_bumps[target_idx].trim()
    except Exception:
        pass  # Best-effort merge
    return target_idx


def _add_new_bump(new_bumps: list, bump, key: tuple, root_map: dict[tuple, int]) -> int:
    """Add a new bump to the collection."""
    new_index = len(new_bumps)
    root_map[key] = new_index
    new_bumps.append(bump)
    return new_index


def _remap_transaction_indices(beef: Beef, index_map: dict[int, int]):
    """Remap transaction bump indices to use new deduplicated indices."""
    for btx in beef.txs.values():
        if btx.bump_index is not None and btx.bump_index in index_map:
            btx.bump_index = index_map[btx.bump_index]
