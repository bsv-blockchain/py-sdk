from __future__ import annotations

from typing import List

from bsv.transaction.beef import BEEF_V2
from bsv.utils import Writer


def build_beef_v2_from_raw_hexes(tx_hex_list: list[str]) -> bytes:
    """Build a minimal BEEF v2 bundle from a list of raw transaction hex strings.

    - No bumps are included (bump_cnt = 0)
    - Each transaction is encoded as data_format = 0 (RawTx)
    This is sufficient for consumers that need to extract locking scripts for
    outputs by vout index, or to rehydrate Transaction objects for simple flows.
    """
    if not tx_hex_list:
        return b""
    raw_txs = []
    for h in tx_hex_list:
        try:
            raw_txs.append(bytes.fromhex(h))
        except (TypeError, ValueError):
            continue  # skip entries that are not hex, before the count is written
    w = Writer()
    w.write_uint32_le(int(BEEF_V2))
    w.write_var_int_num(0)  # bump count
    w.write_var_int_num(len(raw_txs))  # transaction count
    for raw in raw_txs:
        w.write_uint8(0)  # data_format: 0 indicates RawTx
        w.write(raw)
    return w.to_bytes()
