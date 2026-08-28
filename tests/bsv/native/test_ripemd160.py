"""Conformance and differential tests for the native RIPEMD-160 paths."""

import hashlib

import pytest
from Cryptodome.Hash import RIPEMD160
from hypothesis import given, settings
from hypothesis import strategies as st

from bsv.native import NATIVE_AVAILABLE
from bsv.native import NATIVE_MODULE as _bsv_native

if not NATIVE_AVAILABLE:
    pytest.skip("native extension not available", allow_module_level=True)

OP_RIPEMD160 = 0xA6
OP_HASH160 = 0xA9
OP_EQUAL = 0x87


def _cryptodome_ripemd160(data: bytes) -> bytes:
    return RIPEMD160.new(data=data).digest()


def _cryptodome_hash160(data: bytes) -> bytes:
    return _cryptodome_ripemd160(hashlib.sha256(data).digest())


def _push_chunk(data: bytes) -> tuple[int, bytes | None]:
    size = len(data)
    if size == 0:
        return 0x00, None
    if size <= 75:
        return size, data
    if size <= 0xFF:
        return 0x4C, data  # OP_PUSHDATA1
    if size <= 0xFFFF:
        return 0x4D, data  # OP_PUSHDATA2
    return 0x4E, data  # OP_PUSHDATA4


def _native_hash_matches(opcode: int, data: bytes, expected: bytes) -> bool:
    return _bsv_native.spend_validate(
        [_push_chunk(data)],
        [(opcode, None), (len(expected), expected), (OP_EQUAL, None)],
        2,
        "00" * 32,
        0,
        0,
        0,
        0xFFFFFFFF,
        1000,
        [],
        [],
    )


# RIPEMD-160 designers' official vectors:
# https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
@pytest.mark.parametrize(
    ("data", "expected_hex"),
    [
        pytest.param(b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31", id="empty"),
        pytest.param(b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", id="a"),
        pytest.param(b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", id="abc"),
        pytest.param(
            b"message digest",
            "5d0689ef49d2fae572b881b123a85ffa21595f36",
            id="message-digest",
        ),
        pytest.param(
            b"abcdefghijklmnopqrstuvwxyz",
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
            id="alphabet",
        ),
        pytest.param(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
            id="two-block-padding",
        ),
        pytest.param(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "b0e20b6e3116640286ed3a87a5713079b21f5189",
            id="alphanumeric",
        ),
        pytest.param(
            b"1234567890" * 8,
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
            id="multi-block",
        ),
        pytest.param(
            b"a" * 1_000_000,
            "52783243c1697bdbe16d37f97f68f08325dc1528",
            id="million-a",
        ),
    ],
)
def test_ripemd160_official_vectors(data: bytes, expected_hex: str) -> None:
    assert _native_hash_matches(OP_RIPEMD160, data, bytes.fromhex(expected_hex)) is True


@pytest.mark.parametrize(
    "length",
    [
        0,
        1,
        54,
        55,
        56,
        57,
        63,
        64,
        65,
        119,
        120,
        121,
        127,
        128,
        129,
        255,
        256,
        257,
        511,
        512,
        513,
        1023,
        1024,
        1025,
        4095,
        4096,
        4097,
    ],
)
@pytest.mark.parametrize(
    ("opcode", "reference"),
    [(OP_RIPEMD160, _cryptodome_ripemd160), (OP_HASH160, _cryptodome_hash160)],
    ids=["ripemd160", "hash160"],
)
def test_native_hash_padding_boundaries(opcode, reference, length: int) -> None:
    data = bytes((index * 17 + 3) % 256 for index in range(length))
    assert _native_hash_matches(opcode, data, reference(data)) is True


@pytest.mark.parametrize(
    ("opcode", "reference"),
    [(OP_RIPEMD160, _cryptodome_ripemd160), (OP_HASH160, _cryptodome_hash160)],
    ids=["ripemd160", "hash160"],
)
@settings(max_examples=100, deadline=None, derandomize=True)
@given(data=st.binary(min_size=0, max_size=4096))
def test_native_hash_random_differential(opcode, reference, data: bytes) -> None:
    assert _native_hash_matches(opcode, data, reference(data)) is True


def test_hash160_compressed_generator_public_key() -> None:
    public_key = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    expected = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    assert _native_hash_matches(OP_HASH160, public_key, expected) is True
