"""BRC-56 HMAC key encoding vectors (leading zero bytes).

Vectors from bsv-blockchain/BRCs#362 (BRC-56/BRC-100 HMAC encoding). The
derived symmetric key is the shared point's X coordinate; createHmac and
verifyHmac key HMAC-SHA256 with its minimal-length unsigned big-endian encoding
(leading zero bytes dropped), the established ts-sdk convention
(`key.toArray()`). Tags keyed with the 32-byte padded encoding are rejected.
"""

import pytest

from bsv.keys import PrivateKey
from bsv.wallet import ProtoWallet

ROOT_KEY = "f0efba88c117ca2614554bb676d743f413822a31e3c8d70cfcc5fff119d20a07"
ROOT_PUBLIC_KEY = "035818cd7cc614fea816c8b39eebe6e43cafc635451ec5a873f8757b418aaae91a"
COUNTERPARTY = "03458d551018414b8fe1adbcef2d0afc17e1074bfab3fdde3e1b0750bdde58a9a7"
PROTOCOL_ID = [2, "hmac key vectors"]
DATA = bytes.fromhex("4252432d353620484d41432074657374")

# (counterparty, key_id, leading_zero_bytes, hmac_key, tag_32_byte_key, tag_minimal_key)
VECTORS = [
    (
        "self",
        "k0",
        0,
        "b1273850ff41cee365a4d590e3c323822129f66c5a9b2eacb8b9e790e000e396",
        "99455edf49ea2156f6109466fb344c3027d4c14485581a50bf5ff0850328a269",
        None,
    ),
    (
        "self",
        "k95",
        1,
        "000c82ac78dc853158f24883ccfda332be6ba34f821765357cc4ef2a190a28fd",
        "054a0fc6a3b0e21b31dc627fb1d645f2eea4127dff71eac95b1f71b7cb13c787",
        "3a968ebaa25eaa4b1cfad138f96105bb1eb738defc066d01e37b32595900d48b",
    ),
    (
        "self",
        "k91538",
        2,
        "00009dc11102cc72eca3c6e4e232460eac581e9b2cee1bb35c395b635d3f6393",
        "ff43127cb1ddfbd19776d01ce34b8c3e83916b51fa55ac045a355b731e6999f5",
        "5a8b84fb2a7d9ce7b12feb8319f14dc6169e0be005a1a8e58d9b9b2d1ac29d47",
    ),
    (
        COUNTERPARTY,
        "k0",
        0,
        "1896e0210afac8dbb4ca3bd4ea25c8377d0352ab83e62fe6ffabeca78c1a6113",
        "986af579272261acf3e890bb1650124b0dfbc0b1edacda202f8ed0c3b876c072",
        None,
    ),
    (
        COUNTERPARTY,
        "k497",
        1,
        "001829e1dd58fc2c45b6edcbb277eecdecbab1c884b42fd779e131fea5881b45",
        "aa39467c48a116ffb00fd7b56ff158bd9af37d1298df2f031c0125458c30f574",
        "3a5ea2bf5bcc9bc1461041737384bf258b0a3e5a475fb281a19c2972cdb1cff6",
    ),
    (
        COUNTERPARTY,
        "k29510",
        2,
        "0000a52a35523175d6c181e90f463a27cdbf70f4ecf055e912d6fc24ac7d0e3c",
        "2677674035f1aaac3219b3405cf8569ec07922a3ceffbd4f7c8a7948b2d3c553",
        "ecca769bb17b1775ce8ae4326fe721ba0f7ba272300741bf4a5b068cf0cebd60",
    ),
]

IDS = [f"{'self' if v[0] == 'self' else 'counterparty'}-{v[1]}-{v[2]}lz" for v in VECTORS]


@pytest.fixture(scope="module")
def wallet():
    return ProtoWallet(PrivateKey(bytes.fromhex(ROOT_KEY)), permission_callback=lambda action: True)


def _args(counterparty, key_id, **extra):
    return {"protocolID": PROTOCOL_ID, "keyID": key_id, "counterparty": counterparty, "data": DATA, **extra}


def _expected_tag(tag_32, tag_minimal):
    # Without leading zero bytes both encodings are identical
    return tag_minimal or tag_32


def test_uses_brc_root_key(wallet):
    assert wallet.public_key.hex() == ROOT_PUBLIC_KEY


@pytest.mark.parametrize("counterparty,key_id,_lz,hmac_key,_tag_32,_tag_min", VECTORS, ids=IDS)
def test_derives_vector_hmac_key(wallet, counterparty, key_id, _lz, hmac_key, _tag_32, _tag_min):
    cp = wallet._normalize_counterparty(counterparty)
    protocol = wallet._normalize_protocol(PROTOCOL_ID)
    key = wallet.key_deriver.derive_symmetric_key(protocol, key_id, cp)
    assert key.hex() == hmac_key


@pytest.mark.parametrize("counterparty,key_id,_lz,_hmac_key,tag_32,tag_min", VECTORS, ids=IDS)
def test_create_hmac_uses_minimal_length_key(wallet, counterparty, key_id, _lz, _hmac_key, tag_32, tag_min):
    result = wallet.create_hmac(_args(counterparty, key_id), "test")
    assert "error" not in result
    assert result["hmac"].hex() == _expected_tag(tag_32, tag_min)


@pytest.mark.parametrize("counterparty,key_id,_lz,_hmac_key,tag_32,tag_min", VECTORS, ids=IDS)
def test_verify_hmac_accepts_minimal_length_key_tag(wallet, counterparty, key_id, _lz, _hmac_key, tag_32, tag_min):
    tag = bytes.fromhex(_expected_tag(tag_32, tag_min))
    result = wallet.verify_hmac(_args(counterparty, key_id, hmac=tag), "test")
    assert result.get("valid") is True


@pytest.mark.parametrize(
    "counterparty,key_id,_lz,_hmac_key,tag_32,tag_min",
    [v for v in VECTORS if v[5] is not None],
    ids=[i for i, v in zip(IDS, VECTORS, strict=True) if v[5] is not None],
)
def test_verify_hmac_refuses_32_byte_key_tag(wallet, counterparty, key_id, _lz, _hmac_key, tag_32, tag_min):
    result = wallet.verify_hmac(_args(counterparty, key_id, hmac=bytes.fromhex(tag_32)), "test")
    assert result.get("valid") is False
