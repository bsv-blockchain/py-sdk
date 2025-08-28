from __future__ import annotations

from typing import List

from bsv.transaction.beef import BEEF_V2
from bsv.utils import Writer


def build_beef_v2_from_raw_hexes(tx_hex_list: List[str]) -> bytes:
    """Build a minimal BEEF v2 bundle from a list of raw transaction hex strings.

    - No bumps are included (bump_cnt = 0)
    - Each transaction is encoded as data_format = 0 (RawTx)
    This is sufficient for consumers that need to extract locking scripts for
    outputs by vout index, or to rehydrate Transaction objects for simple flows.
    """
    if not tx_hex_list:
        return b""
    w = Writer()
    w.write_uint32_le(int(BEEF_V2))
    w.write_var_int_num(0)  # bump count
    w.write_var_int_num(len(tx_hex_list))  # transaction count
    for h in tx_hex_list:
        if not isinstance(h, str):
            continue
        if len(h) % 2 != 0:
            continue
        try:
            w.write_uint8(0)  # data_format = 0 (RawTx)
            w.write(bytes.fromhex(h))
        except Exception:
            continue
    return w.to_bytes()


