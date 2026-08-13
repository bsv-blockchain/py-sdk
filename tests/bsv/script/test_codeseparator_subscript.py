"""OP_CODESEPARATOR defines where the signed subscript starts.

The subscript runs from *past* the last OP_CODESEPARATOR, excluding the
separator byte itself, as in the TS SDK (`Spend.ts`) and Go SDK
(`interpreter/thread.go`). Including it changes the sighash preimage, so a
signature made by another SDK would not verify here and vice versa.
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

SOURCE_TXID = "11" * 32
SOURCE_SATOSHIS = 10_000
TX_VERSION = 2
SIGHASH_FLAG = SIGHASH.ALL_FORKID


@pytest.fixture
def priv_key():
    return PrivateKey()


def _outputs():
    return [TransactionOutput(locking_script=Script.from_asm("OP_TRUE"), satoshis=9_000)]


def _preimage_over(subscript: Script) -> bytes:
    """Preimage a signature commits to when the scriptCode is `subscript`."""
    inp = TransactionInput(
        source_txid=SOURCE_TXID,
        source_output_index=0,
        unlocking_script=Script(),
        sequence=0xFFFFFFFF,
        sighash=SIGHASH_FLAG,
    )
    inp.locking_script = subscript
    inp.satoshis = SOURCE_SATOSHIS
    return tx_preimage(0, [inp], _outputs(), TX_VERSION, 0)


def _spend(locking: Script, unlocking: Script) -> Spend:
    return Spend(
        {
            "sourceTXID": SOURCE_TXID,
            "sourceOutputIndex": 0,
            "sourceSatoshis": SOURCE_SATOSHIS,
            "lockingScript": locking,
            "transactionVersion": TX_VERSION,
            "otherInputs": [],
            "outputs": _outputs(),
            "inputIndex": 0,
            "unlockingScript": unlocking,
            "inputSequence": 0xFFFFFFFF,
            "lockTime": 0,
        }
    )


def _sign_over(priv_key, subscript: Script) -> Script:
    sig = priv_key.sign(_preimage_over(subscript))
    return Script(encode_pushdata(sig + SIGHASH_FLAG.to_bytes(1, "little")))


def _validates_on_both_paths(locking: Script, unlocking: Script) -> list:
    results = []
    for use_native in (False, True):
        if use_native and not _USE_NATIVE_VM:
            continue
        spend = _spend(locking, unlocking)
        try:
            results.append(spend._validate_native() if use_native else spend._validate_python())
        except RuntimeError:
            results.append(False)
    return results


def _locking_with_separator(priv_key, trailing_separators: int = 1) -> Script:
    pubkey_push = encode_pushdata(priv_key.public_key().serialize())
    return Script(pubkey_push + OpCode.OP_CODESEPARATOR * trailing_separators + OpCode.OP_CHECKSIG)


def test_signature_over_subscript_excluding_separator_is_accepted(priv_key):
    # Everything past the separator is just OP_CHECKSIG.
    locking = _locking_with_separator(priv_key)
    unlocking = _sign_over(priv_key, Script(OpCode.OP_CHECKSIG))
    assert all(_validates_on_both_paths(locking, unlocking))


def test_signature_over_subscript_including_separator_is_rejected(priv_key):
    # Regression: the subscript started *at* the separator, so this — a
    # signature over `OP_CODESEPARATOR OP_CHECKSIG` — was what py-sdk accepted,
    # and the signature the reference SDKs produce was rejected.
    locking = _locking_with_separator(priv_key)
    unlocking = _sign_over(priv_key, Script(OpCode.OP_CODESEPARATOR + OpCode.OP_CHECKSIG))
    assert not any(_validates_on_both_paths(locking, unlocking))


def test_only_the_last_separator_counts(priv_key):
    # Two separators in a row: the subscript still starts after the last one.
    locking = _locking_with_separator(priv_key, trailing_separators=2)
    unlocking = _sign_over(priv_key, Script(OpCode.OP_CHECKSIG))
    assert all(_validates_on_both_paths(locking, unlocking))


def test_separator_in_first_position_is_also_excluded(priv_key):
    # No special case for index 0: the node advances past the opcode before
    # recording the position, so a leading separator is excluded like any other.
    pubkey_push = encode_pushdata(priv_key.public_key().serialize())
    locking = Script(OpCode.OP_CODESEPARATOR + pubkey_push + OpCode.OP_CHECKSIG)
    unlocking = _sign_over(priv_key, Script(pubkey_push + OpCode.OP_CHECKSIG))
    assert all(_validates_on_both_paths(locking, unlocking))


def test_without_separator_the_whole_script_is_signed(priv_key):
    # No separator: the subscript is the entire locking script, unchanged
    # behaviour that the off-by-one fix must not disturb.
    pubkey_push = encode_pushdata(priv_key.public_key().serialize())
    locking = Script(pubkey_push + OpCode.OP_CHECKSIG)
    unlocking = _sign_over(priv_key, locking)
    assert all(_validates_on_both_paths(locking, unlocking))
