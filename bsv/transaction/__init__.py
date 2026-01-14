# Make bsv.transaction a package and expose pushdrop helpers
# ---------------------------------------------------------------------------
# Legacy transaction module compatibility (lazy load to avoid circular import)
# ---------------------------------------------------------------------------
import importlib.util as _il_util
import pathlib as _pl
import sys as _sys

from .pushdrop import (
    build_lock_before_pushdrop,
    build_pushdrop_locking_script,
    create_minimally_encoded_script_chunk,
    decode_lock_before_pushdrop,
    parse_identity_reveal,
    parse_pushdrop_locking_script,
)

_legacy_path = _pl.Path(__file__).resolve().parent.parent / "transaction.py"

_spec = _il_util.spec_from_file_location("bsv._legacy_transaction", str(_legacy_path))
_legacy_mod = _il_util.module_from_spec(_spec)  # type: ignore[arg-type]
if _spec and _spec.loader:  # pragma: no cover
    _spec.loader.exec_module(_legacy_mod)  # type: ignore[assignment]
_sys.modules.setdefault("bsv._legacy_transaction", _legacy_mod)

Transaction = _legacy_mod.Transaction  # type: ignore[attr-defined]
TransactionInput = _legacy_mod.TransactionInput  # type: ignore[attr-defined]
TransactionOutput = _legacy_mod.TransactionOutput  # type: ignore[attr-defined]
InsufficientFunds = _legacy_mod.InsufficientFunds  # type: ignore[attr-defined]

__all__ = [
    "InsufficientFunds",
    "Transaction",
    "TransactionInput",
    "TransactionOutput",
    "build_lock_before_pushdrop",
    "build_pushdrop_locking_script",
    "create_minimally_encoded_script_chunk",
    "decode_lock_before_pushdrop",
    "parse_identity_reveal",
    "parse_pushdrop_locking_script",
]

from .beef import Beef, new_beef_from_atomic_bytes, new_beef_from_bytes, parse_beef, parse_beef_ex

__all__.extend(["Beef", "new_beef_from_atomic_bytes", "new_beef_from_bytes", "parse_beef", "parse_beef_ex"])
