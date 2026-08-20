"""Skip the whole native test package when the C extension is not built.

These modules exercise `_bsv_native` directly — several import it at module
scope or run it in a subprocess — so on a pure-Python install they fail at
collection rather than skipping. One `collect_ignore_glob` here covers every
file in the directory.
"""

from bsv.native import NATIVE_AVAILABLE

collect_ignore_glob = [] if NATIVE_AVAILABLE else ["test_*.py"]
