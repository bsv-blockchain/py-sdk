"""High-S signatures must be judged the same by both VM paths.

Chronicle relaxes the low-S requirement for transaction version > 1, so a
high-S signature is valid there. The native VM folds the signature to its
low-S equivalent before verifying; the pure-Python VM went through
`PublicKey.verify`, which rejects the high-S form outright, so the two paths
disagreed on transactions the network accepts.
"""

import pytest

from bsv.constants import NUMBER_BYTE_LENGTH, SIGHASH
from bsv.curve import curve
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.spend import _USE_NATIVE_VM, Spend
from bsv.script.type import P2PKH
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.transaction_preimage import tx_preimage
from bsv.utils import deserialize_ecdsa_der, encode_pushdata

SOURCE_TXID = "22" * 32
SOURCE_SATOSHIS = 10_000
SIGHASH_FLAG = SIGHASH.ALL_FORKID


@pytest.fixture
def priv_key():
    return PrivateKey()


def _outputs():
    return [TransactionOutput(locking_script=Script.from_asm("OP_TRUE"), satoshis=9_000)]


def _der(r: int, s: int) -> bytes:
    """Serialize without the low-S normalization `serialize_ecdsa_der` applies."""
    parts = []
    for v in (r, s):
        b = v.to_bytes(NUMBER_BYTE_LENGTH, "big").lstrip(b"\x00")
        if b[0] & 0x80:
            b = b"\x00" + b
        parts.append(bytes([0x02, len(b)]) + b)
    body = b"".join(parts)
    return bytes([0x30, len(body)]) + body


def _high_s_unlocking(priv_key, locking: Script, tx_version: int) -> Script:
    inp = TransactionInput(
        source_txid=SOURCE_TXID,
        source_output_index=0,
        unlocking_script=Script(),
        sequence=0xFFFFFFFF,
        sighash=SIGHASH_FLAG,
    )
    inp.locking_script = locking
    inp.satoshis = SOURCE_SATOSHIS
    preimage = tx_preimage(0, [inp], _outputs(), tx_version, 0)

    r, s = deserialize_ecdsa_der(priv_key.sign(preimage))
    if s <= curve.n // 2:
        s = curve.n - s  # force the high-S form
    sig = _der(r, s) + SIGHASH_FLAG.to_bytes(1, "little")
    return Script(encode_pushdata(sig) + encode_pushdata(priv_key.public_key().serialize()))


def _results(priv_key, tx_version: int) -> list:
    locking = P2PKH().lock(priv_key.address())
    unlocking = _high_s_unlocking(priv_key, locking, tx_version)
    out = []
    for use_native in (False, True):
        if use_native and not _USE_NATIVE_VM:
            continue
        spend = Spend(
            {
                "sourceTXID": SOURCE_TXID,
                "sourceOutputIndex": 0,
                "sourceSatoshis": SOURCE_SATOSHIS,
                "lockingScript": locking,
                "transactionVersion": tx_version,
                "otherInputs": [],
                "outputs": _outputs(),
                "inputIndex": 0,
                "unlockingScript": unlocking,
                "inputSequence": 0xFFFFFFFF,
                "lockTime": 0,
            }
        )
        try:
            out.append(spend._validate_native() if use_native else spend._validate_python())
        except RuntimeError as e:
            out.append(str(e))
    return out


def test_relaxed_version_accepts_high_s_on_both_paths(priv_key):
    # Version 2 relaxes low-S, and a high-S signature is mathematically valid,
    # so both VMs must accept it. The pure-Python VM used to reject.
    assert _results(priv_key, tx_version=2) == [True] * (2 if _USE_NATIVE_VM else 1)


def test_strict_version_rejects_high_s_on_both_paths(priv_key):
    results = _results(priv_key, tx_version=1)
    assert all(isinstance(r, str) for r in results), results


def test_strict_rejection_names_the_low_s_rule(priv_key):
    # The low-S error used to be raised inside a `suppress(Exception)` block
    # that swallowed it, leaving the misleading "signature format is invalid".
    for message in _results(priv_key, tx_version=1):
        assert "low S value" in message, message
