# Make bsv.transaction a package and expose pushdrop helpers
from .pushdrop import (
    build_pushdrop_locking_script,
    parse_pushdrop_locking_script,
    parse_identity_reveal,
    build_lock_before_pushdrop,
    decode_lock_before_pushdrop,
    create_minimally_encoded_script_chunk,
)

# ---------------------------------------------------------------------------
# Legacy transaction module compatibility (lazy load to avoid circular import)
# ---------------------------------------------------------------------------

import importlib.util as _il_util
import pathlib as _pl
import sys as _sys

_legacy_path = _pl.Path(__file__).resolve().parent.parent / "transaction.py"

_spec = _il_util.spec_from_file_location("bsv._legacy_transaction", str(_legacy_path))
_legacy_mod = _il_util.module_from_spec(_spec)  # type: ignore[arg-type]
if _spec and _spec.loader:  # pragma: no cover
    _spec.loader.exec_module(_legacy_mod)  # type: ignore[assignment]
_sys.modules.setdefault("bsv._legacy_transaction", _legacy_mod)

Transaction = _legacy_mod.Transaction  # type: ignore[attr-defined]
TransactionInput = _legacy_mod.TransactionInput  # type: ignore[attr-defined]
TransactionOutput = _legacy_mod.TransactionOutput  # type: ignore[attr-defined]

__all__ = [
    "build_pushdrop_locking_script",
    "parse_pushdrop_locking_script",
    "parse_identity_reveal",
    "build_lock_before_pushdrop",
    "decode_lock_before_pushdrop",
    "create_minimally_encoded_script_chunk",
    "Transaction",
    "TransactionInput",
    "TransactionOutput",
]

from .beef import Beef, new_beef_from_bytes, new_beef_from_atomic_bytes, parse_beef, parse_beef_ex
__all__.extend(["Beef", "new_beef_from_bytes", "new_beef_from_atomic_bytes", "parse_beef", "parse_beef_ex"])


