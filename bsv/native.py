"""Centralised _bsv_native availability check.

Import helpers from here instead of writing bare ``try: import _bsv_native``
blocks in every module.  A single :func:`warnings.warn` fires on the first
import when the C extension is absent; callers just read the flag.
"""

from __future__ import annotations

import warnings

try:
    import _bsv_native

    # Guard against namespace-package imports: the _bsv_native/ source
    # directory can be importable without a compiled extension present.
    _bsv_native.seckey_verify  # noqa: B018

    NATIVE_AVAILABLE = True
    NATIVE_MODULE = _bsv_native
except (ImportError, AttributeError):
    NATIVE_AVAILABLE = False
    NATIVE_MODULE = None  # type: ignore[assignment]
    warnings.warn(
        "_bsv_native C extension not available — "
        "falling back to pure Python (significantly slower). "
        "Set BSV_NO_NATIVE=1 to silence this warning, "
        "or install from a pre-built wheel for native acceleration.",
        RuntimeWarning,
        stacklevel=2,
    )


def native_status() -> dict[str, object]:
    """Return diagnostic information about native acceleration.

    >>> from bsv.native import native_status
    >>> status = native_status()
    >>> status["available"]  # True when the C extension is loaded
    """
    info: dict[str, object] = {"available": NATIVE_AVAILABLE}
    if NATIVE_AVAILABLE and NATIVE_MODULE is not None:
        info["backend"] = getattr(NATIVE_MODULE, "BACKEND", "unknown")
        info["version"] = getattr(NATIVE_MODULE, "__version__", "unknown")
    return info
