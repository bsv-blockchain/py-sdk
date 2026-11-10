"""
Malformed input to the C extension must raise, not crash or leave an
exception set behind a return value (SystemError).

Each case here crashed, read out of bounds, or hit undefined behaviour
before the bounds and type checks in bsv_native.c were tightened.
"""

import pytest

_bsv_native = pytest.importorskip("_bsv_native")

import bsv.merkle_path as merkle_path_mod
from bsv.merkle_path import MerklePath
from bsv.transaction import Transaction

_INT64_MAX = (2**63 - 1).to_bytes(8, "little")

# A script length close to INT64_MAX overflowed `pos + script_len` in
# tx_from_bytes, passed the bounds check and dereferenced a NULL script.
_HUGE_INPUT_SCRIPT = b"\x01\x00\x00\x00" + b"\x01" + b"\x00" * 36 + b"\xff" + _INT64_MAX + b"\x00" * 24
_HUGE_OUTPUT_SCRIPT = b"\x01\x00\x00\x00" + b"\x00" + b"\x01" + b"\x00" * 8 + b"\xff" + _INT64_MAX + b"\x00" * 24


@pytest.mark.parametrize("raw", [_HUGE_INPUT_SCRIPT, _HUGE_OUTPUT_SCRIPT], ids=["input", "output"])
def test_tx_from_bytes_rejects_overflowing_script_length(raw):
    with pytest.raises(ValueError):
        _bsv_native.tx_from_bytes(raw)
    assert Transaction.from_hex(raw.hex()) is None


_SPEND_ARGS = (1, "00" * 32, 0, 0, 0, 0xFFFFFFFF, 0, [], [])


@pytest.mark.parametrize(
    "unlock",
    [[(0x4C, bytearray(200))], [[0x51, None]], [(0x51,)]],
    ids=["bytearray-data", "list-chunk", "short-tuple"],
)
def test_spend_validate_rejects_malformed_chunks(unlock):
    with pytest.raises(TypeError):
        _bsv_native.spend_validate(unlock, [(0x51, None)], *_SPEND_ARGS)


@pytest.mark.parametrize("op, exc", [(300, ValueError), (-1, ValueError), ("x", TypeError)])
def test_serialize_script_chunks_rejects_bad_opcode(op, exc):
    with pytest.raises(exc):
        _bsv_native.serialize_script_chunks([(op, None)])


def test_merkle_compute_root_above_64_levels(monkeypatch):
    # (index >> height) with height >= 64 is undefined in C; hardware masks the
    # shift, so index 1 came back at height 64 and the leaf was not found.
    txid = "aa" * 32
    path = [[{"offset": 1, "hash_str": txid, "txid": True}, {"offset": 0, "hash_str": "bb" * 32}]]
    path += [[{"offset": 1, "hash_str": "cc" * 32}] for _ in range(69)]

    monkeypatch.setattr(merkle_path_mod, "_USE_NATIVE", False)
    expected = MerklePath(0, path).compute_root(txid)

    assert _bsv_native.merkle_compute_root(txid, path) == expected


def test_merkle_compute_root_rejects_non_int_offset():
    txid = "aa" * 32
    path = [
        [{"offset": 1, "hash_str": txid, "txid": True}, {"offset": 0, "hash_str": "bb" * 32}],
        [{"offset": "x", "hash_str": "cc" * 32}],
    ]
    with pytest.raises(TypeError):
        _bsv_native.merkle_compute_root(txid, path)
