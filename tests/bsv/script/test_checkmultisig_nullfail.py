"""A failed OP_CHECKMULTISIG requires its signatures to be the empty vector.

The node applies NULLFAIL to `OP_CHECKMULTISIG` exactly as it does to
`OP_CHECKSIG` — `if (!fSuccess && VerifyNullFail(flags) && !ikey2 &&
!vchSig.empty())` in the cleanup loop, guarded by `EnforceNonMalleability`,
which Chronicle relaxes for transaction version > 1. py-sdk enforced it for
`OP_CHECKSIG` only.
"""

import pytest

from bsv.constants import SIGHASH, OpCode
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.spend import _USE_NATIVE_VM, Spend
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.transaction_preimage import tx_preimage
from bsv.utils import encode_pushdata

SOURCE_TXID = "33" * 32
SOURCE_SATOSHIS = 10_000
SIGHASH_FLAG = SIGHASH.ALL_FORKID


@pytest.fixture
def priv_key():
    return PrivateKey()


def _outputs():
    return [TransactionOutput(locking_script=Script.from_asm("OP_TRUE"), satoshis=9_000)]


def _locking_1_of_1_that_fails() -> Script:
    """1-of-1 multisig against an unrelated key, so the check always fails.

    OP_NOT turns the FALSE into TRUE, so the script would otherwise succeed and
    only NULLFAIL decides the outcome.
    """
    other_pub = PrivateKey().public_key().serialize()
    return Script(OpCode.OP_1 + encode_pushdata(other_pub) + OpCode.OP_1 + OpCode.OP_CHECKMULTISIG + OpCode.OP_NOT)


def _unlocking(priv_key, locking: Script, tx_version: int, empty_sig: bool) -> Script:
    # OP_0 is the dummy element CHECKMULTISIG consumes.
    if empty_sig:
        return Script(OpCode.OP_0 + OpCode.OP_0)
    inp = TransactionInput(
        source_txid=SOURCE_TXID,
        source_output_index=0,
        unlocking_script=Script(),
        sequence=0xFFFFFFFF,
        sighash=SIGHASH_FLAG,
    )
    inp.locking_script = locking
    inp.satoshis = SOURCE_SATOSHIS
    sig = priv_key.sign(tx_preimage(0, [inp], _outputs(), tx_version, 0))
    return Script(OpCode.OP_0 + encode_pushdata(sig + SIGHASH_FLAG.to_bytes(1, "little")))


def _spend(locking: Script, unlocking: Script, tx_version: int) -> Spend:
    return Spend(
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


def _results(priv_key, tx_version: int, empty_sig: bool) -> list:
    locking = _locking_1_of_1_that_fails()
    unlocking = _unlocking(priv_key, locking, tx_version, empty_sig)
    out = []
    for use_native in (False, True):
        if use_native and not _USE_NATIVE_VM:
            continue
        spend = _spend(locking, unlocking, tx_version)
        try:
            out.append(spend._validate_native() if use_native else spend._validate_python())
        except RuntimeError as e:
            out.append(str(e))
    return out


def test_strict_version_rejects_a_nonempty_failed_signature(priv_key):
    for result in _results(priv_key, tx_version=1, empty_sig=False):
        assert isinstance(result, str), result
        assert "empty vector" in result, result


def test_strict_version_accepts_an_empty_failed_signature(priv_key):
    # The same script with the empty vector is how a failed slot is spelled.
    assert _results(priv_key, tx_version=1, empty_sig=True) == [True] * (2 if _USE_NATIVE_VM else 1)


def test_relaxed_version_allows_a_nonempty_failed_signature(priv_key):
    # Chronicle relaxes NULLFAIL for version > 1, as it does for OP_CHECKSIG.
    assert _results(priv_key, tx_version=2, empty_sig=False) == [True] * (2 if _USE_NATIVE_VM else 1)
