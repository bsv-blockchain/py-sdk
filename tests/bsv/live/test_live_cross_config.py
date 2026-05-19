"""Cross-configuration Chronicle tests.

Tests that configuration transitions work correctly:
- Funding tx version != spending tx version
- Different sighash flags on setup vs spend
- Mixed sighash flags across inputs in a single tx
- Mixed source tx versions across inputs
- Malleability enforcement depends on spending tx version, not source
- Chronicle opcodes work with all version/sighash combos
"""

import pytest

from bsv.constants import SIGHASH, OpCode
from bsv.hash import hash160
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.type import P2PK, P2PKH, BareMultisig, to_unlock_script_template
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.utils import encode_pushdata

from .conftest import (
    build_cross_config_tx,
    build_funding_tx,
    build_signed_tx,
    custom_unlock,
    p2pkh_lock_with_prefix,
    validate_all_inputs,
    validate_spend,
)

# ---------------------------------------------------------------------------
# Parametrize helpers
# ---------------------------------------------------------------------------

VERSION_TRANSITIONS = [
    pytest.param(1, 2, id="v1_to_v2"),
    pytest.param(2, 1, id="v2_to_v1"),
]

SIGHASH_CROSS_PAIRS = [
    pytest.param(SIGHASH.ALL_FORKID, SIGHASH.ALL_FORKID_CHRONICLE, 2, id="BIP143_setup_OTDA_spend"),
    pytest.param(SIGHASH.ALL_FORKID_CHRONICLE, SIGHASH.ALL_FORKID, 1, id="OTDA_setup_BIP143_spend"),
    pytest.param(SIGHASH.ALL_FORKID, SIGHASH.ALL_FORKID_CHRONICLE, 1, id="BIP143_setup_OTDA_spend_v1"),
    pytest.param(SIGHASH.ALL_FORKID_CHRONICLE, SIGHASH.ALL_FORKID, 2, id="OTDA_setup_BIP143_spend_v2"),
]

# "Unnatural" opcode pairings: Chronicle opcodes with non-default version/sighash combos
CROSS_OPCODE_CONFIGS = [
    pytest.param(SIGHASH.ALL_FORKID, 2, id="BIP143_v2"),
    pytest.param(SIGHASH.ALL_FORKID_CHRONICLE, 1, id="OTDA_v1"),
]


# ---------------------------------------------------------------------------
# 1. Version transitions: funding version != spending version
# ---------------------------------------------------------------------------


class TestVersionTransitions:
    """P2PKH, P2PK, and Multisig with funding_version != spending_version."""

    @pytest.mark.parametrize("funding_ver,spending_ver", VERSION_TRANSITIONS)
    def test_p2pkh_bip143(self, priv_key, funding_ver, spending_ver):
        """P2PKH with BIP143 sighash across version transition."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        build_cross_config_tx(
            [(lock, unlock, SIGHASH.ALL_FORKID)],
            spending_version=spending_ver,
            funding_version=funding_ver,
        )

    @pytest.mark.parametrize("funding_ver,spending_ver", VERSION_TRANSITIONS)
    def test_p2pkh_otda(self, priv_key, funding_ver, spending_ver):
        """P2PKH with OTDA sighash across version transition."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        build_cross_config_tx(
            [(lock, unlock, SIGHASH.ALL_FORKID_CHRONICLE)],
            spending_version=spending_ver,
            funding_version=funding_ver,
        )

    @pytest.mark.parametrize("funding_ver,spending_ver", VERSION_TRANSITIONS)
    def test_p2pk(self, priv_key, funding_ver, spending_ver):
        """P2PK across version transition."""
        p2pk = P2PK()
        lock = p2pk.lock(priv_key.public_key().serialize())
        unlock = p2pk.unlock(priv_key)
        build_cross_config_tx(
            [(lock, unlock, SIGHASH.ALL_FORKID)],
            spending_version=spending_ver,
            funding_version=funding_ver,
        )

    @pytest.mark.parametrize("funding_ver,spending_ver", VERSION_TRANSITIONS)
    def test_multisig_2of3(self, priv_key, priv_key2, priv_key3, funding_ver, spending_ver):
        """2-of-3 multisig across version transition."""
        multisig = BareMultisig()
        pubkeys = [
            priv_key.public_key().serialize(),
            priv_key2.public_key().serialize(),
            priv_key3.public_key().serialize(),
        ]
        lock = multisig.lock(pubkeys, threshold=2)
        unlock = multisig.unlock([priv_key, priv_key2])
        build_cross_config_tx(
            [(lock, unlock, SIGHASH.ALL_FORKID)],
            spending_version=spending_ver,
            funding_version=funding_ver,
        )


# ---------------------------------------------------------------------------
# 2. Sighash transitions: setup sighash != spend sighash
# ---------------------------------------------------------------------------


class TestSighashTransitions:
    """Outputs are sighash-agnostic: spend sighash can differ from setup sighash.

    The setup tx's sighash only matters for the setup tx's own inputs.
    The locking script (P2PKH) does not encode any sighash, so any sighash
    can be used to spend it.
    """

    @pytest.mark.parametrize("setup_sh,spend_sh,tx_version", SIGHASH_CROSS_PAIRS)
    def test_p2pkh_sighash_transition(self, priv_key, setup_sh, spend_sh, tx_version):
        """Create output with one sighash, spend with a different one."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())

        # Step 1: Build funding tx signed with setup_sh (simulates the "setup" sighash)
        funding_tx = build_funding_tx(lock, satoshis=10_000, version=tx_version)

        # Step 2: Spend that output with a different sighash
        inp = TransactionInput(
            source_transaction=funding_tx,
            source_output_index=0,
            unlocking_script_template=p2pkh.unlock(priv_key),
            sequence=0xFFFFFFFF,
            sighash=SIGHASH(spend_sh),
        )
        tx = Transaction(
            [inp],
            [TransactionOutput(locking_script=lock, satoshis=9_500)],
            version=tx_version,
        )
        tx.sign(bypass=False)
        validate_all_inputs(tx)


# ---------------------------------------------------------------------------
# 3. Mixed-input sighash: different sighash per input in one tx
# ---------------------------------------------------------------------------


class TestMixedInputSighash:
    """Single tx with inputs using different sighash flags.

    Tests that per-input preimage routing works correctly.
    """

    def test_bip143_and_otda_inputs_v2(self, priv_key):
        """One BIP143 input + one OTDA input in a v2 tx."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        build_cross_config_tx(
            [
                (lock, unlock, SIGHASH.ALL_FORKID),
                (lock, unlock, SIGHASH.ALL_FORKID_CHRONICLE),
            ],
            spending_version=2,
        )

    def test_bip143_and_otda_inputs_v1(self, priv_key):
        """One BIP143 input + one OTDA input in a v1 tx."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        build_cross_config_tx(
            [
                (lock, unlock, SIGHASH.ALL_FORKID),
                (lock, unlock, SIGHASH.ALL_FORKID_CHRONICLE),
            ],
            spending_version=1,
        )

    def test_none_forkid_and_all_chronicle(self, priv_key):
        """NONE_FORKID + ALL_FORKID_CHRONICLE in a v2 tx."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        build_cross_config_tx(
            [
                (lock, unlock, SIGHASH.NONE_FORKID),
                (lock, unlock, SIGHASH.ALL_FORKID_CHRONICLE),
            ],
            spending_version=2,
        )

    def test_single_forkid_and_single_chronicle(self, priv_key):
        """SINGLE_FORKID + SINGLE_FORKID_CHRONICLE in a v2 tx (needs >= 2 outputs)."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)

        # Need at least 2 outputs for SIGHASH_SINGLE with 2 inputs
        inputs = []
        for sh in [SIGHASH.SINGLE_FORKID, SIGHASH.SINGLE_FORKID_CHRONICLE]:
            funding_tx = build_funding_tx(lock, satoshis=10_000)
            inputs.append(
                TransactionInput(
                    source_transaction=funding_tx,
                    source_output_index=0,
                    unlocking_script_template=unlock,
                    sequence=0xFFFFFFFF,
                    sighash=SIGHASH(sh),
                )
            )
        tx = Transaction(
            inputs,
            [
                TransactionOutput(locking_script=lock, satoshis=9_500),
                TransactionOutput(locking_script=lock, satoshis=9_500),
            ],
            version=2,
        )
        tx.sign(bypass=False)
        validate_all_inputs(tx)

    def test_anyonecanpay_mix(self, priv_key):
        """ANYONECANPAY variants: BIP143 + OTDA in a v2 tx."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        build_cross_config_tx(
            [
                (lock, unlock, SIGHASH.ALL_ANYONECANPAY_FORKID),
                (lock, unlock, SIGHASH.ALL_ANYONECANPAY_FORKID_CHRONICLE),
            ],
            spending_version=2,
        )

    def test_three_inputs_all_different(self, priv_key):
        """Three inputs: ALL_FORKID, ALL_FORKID_CHRONICLE, NONE_FORKID_CHRONICLE."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        build_cross_config_tx(
            [
                (lock, unlock, SIGHASH.ALL_FORKID),
                (lock, unlock, SIGHASH.ALL_FORKID_CHRONICLE),
                (lock, unlock, SIGHASH.NONE_FORKID_CHRONICLE),
            ],
            spending_version=2,
        )


# ---------------------------------------------------------------------------
# 4. Mixed source versions: inputs from different-versioned source txs
# ---------------------------------------------------------------------------


class TestMixedInputSources:
    """Single tx spending inputs from different-versioned source txs."""

    @staticmethod
    def _build_mixed_source_tx(priv_key, source_configs, spending_version) -> None:
        """Build a tx with inputs from different-versioned funding txs.

        Args:
            source_configs: List of (funding_version, sighash) per input.
            spending_version: Version of the spending transaction.
        """
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)

        inputs = []
        for funding_ver, sh in source_configs:
            funding_tx = build_funding_tx(lock, satoshis=10_000, version=funding_ver)
            inputs.append(
                TransactionInput(
                    source_transaction=funding_tx,
                    source_output_index=0,
                    unlocking_script_template=unlock,
                    sequence=0xFFFFFFFF,
                    sighash=SIGHASH(sh),
                )
            )

        total = 10_000 * len(source_configs) - 500
        tx = Transaction(
            inputs,
            [TransactionOutput(locking_script=lock, satoshis=total)],
            version=spending_version,
        )
        tx.sign(bypass=False)
        validate_all_inputs(tx)

    def test_v1_and_v2_source_inputs_v2_spend(self, priv_key):
        """Input from v1 source + input from v2 source, v2 spending tx."""
        self._build_mixed_source_tx(
            priv_key,
            [
                (1, SIGHASH.ALL_FORKID),
                (2, SIGHASH.ALL_FORKID_CHRONICLE),
            ],
            spending_version=2,
        )

    def test_v2_and_v1_source_inputs_v1_spend(self, priv_key):
        """Input from v2 source + input from v1 source, v1 spending tx."""
        self._build_mixed_source_tx(
            priv_key,
            [
                (2, SIGHASH.ALL_FORKID),
                (1, SIGHASH.ALL_FORKID),
            ],
            spending_version=1,
        )

    def test_mixed_sources_mixed_sighash_v2(self, priv_key):
        """v1 source with BIP143 + v2 source with OTDA, v2 spending tx."""
        self._build_mixed_source_tx(
            priv_key,
            [
                (1, SIGHASH.ALL_FORKID),
                (2, SIGHASH.ALL_FORKID_CHRONICLE),
            ],
            spending_version=2,
        )


# ---------------------------------------------------------------------------
# 5. Version x malleability: is_relaxed() depends on spending tx, not source
# ---------------------------------------------------------------------------


class TestVersionMalleabilityInteractions:
    """Proves is_relaxed() depends solely on spending tx version, not source.

    v1 source -> v2 spend: relaxed (passes)
    v2 source -> v1 spend: strict (fails)
    """

    # --- Dirty stack ---

    def _make_dirty_stack_lock(self, priv_key):
        """P2PKH that pushes extra TRUE after CHECKSIG -> 2 items on stack."""
        pkh = hash160(priv_key.public_key().serialize())
        return Script(
            OpCode.OP_DUP
            + OpCode.OP_HASH160
            + encode_pushdata(pkh)
            + OpCode.OP_EQUALVERIFY
            + OpCode.OP_CHECKSIG
            + OpCode.OP_TRUE
        )

    def test_v1_source_v2_spend_dirty_stack_passes(self, priv_key):
        """v2 spending tx relaxes clean stack even when source is v1."""
        lock = self._make_dirty_stack_lock(priv_key)
        unlock = P2PKH().unlock(priv_key)
        funding_tx = build_funding_tx(lock, satoshis=10_000, version=1)
        inp = TransactionInput(
            source_transaction=funding_tx,
            source_output_index=0,
            unlocking_script_template=unlock,
            sequence=0xFFFFFFFF,
            sighash=SIGHASH(SIGHASH.ALL_FORKID),
        )
        tx = Transaction(
            [inp],
            [TransactionOutput(locking_script=Script.from_asm("OP_TRUE"), satoshis=9_000)],
            version=2,
        )
        tx.sign(bypass=False)
        assert validate_spend(tx, 0)

    def test_v2_source_v1_spend_dirty_stack_fails(self, priv_key):
        """v1 spending tx enforces clean stack even when source is v2."""
        lock = self._make_dirty_stack_lock(priv_key)
        unlock = P2PKH().unlock(priv_key)
        funding_tx = build_funding_tx(lock, satoshis=10_000, version=2)
        inp = TransactionInput(
            source_transaction=funding_tx,
            source_output_index=0,
            unlocking_script_template=unlock,
            sequence=0xFFFFFFFF,
            sighash=SIGHASH(SIGHASH.ALL_FORKID),
        )
        tx = Transaction(
            [inp],
            [TransactionOutput(locking_script=Script.from_asm("OP_TRUE"), satoshis=9_000)],
            version=1,
        )
        tx.sign(bypass=False)
        with pytest.raises(RuntimeError, match="clean stack rule"):
            validate_spend(tx, 0)

    # --- Non-minimal push ---

    def _make_nonminimal_unlock(self, priv_key):
        """Unlocking template with PUSHDATA1 for a 1-byte value (non-minimal)."""

        def sign(tx, input_index):
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash
            signature = priv_key.sign(tx.preimage(input_index))
            public_key = priv_key.public_key().serialize()
            sig_script = encode_pushdata(signature + sighash.to_bytes(1, "little")) + encode_pushdata(public_key)
            # Non-minimal push: PUSHDATA1 0x01 0x05 instead of OP_5 (0x55)
            nonminimal_5 = OpCode.OP_PUSHDATA1 + b"\x01" + b"\x05"
            return Script(sig_script + nonminimal_5)

        return to_unlock_script_template(sign, lambda: 120)

    def test_v1_source_v2_spend_nonminimal_push_passes(self, priv_key):
        """v2 spending tx allows non-minimal push even when source is v1."""
        lock = p2pkh_lock_with_prefix("OP_5 OP_NUMEQUALVERIFY", priv_key)
        unlock = self._make_nonminimal_unlock(priv_key)
        funding_tx = build_funding_tx(lock, satoshis=10_000, version=1)
        inp = TransactionInput(
            source_transaction=funding_tx,
            source_output_index=0,
            unlocking_script_template=unlock,
            sequence=0xFFFFFFFF,
            sighash=SIGHASH(SIGHASH.ALL_FORKID),
        )
        tx = Transaction(
            [inp],
            [TransactionOutput(locking_script=Script.from_asm("OP_TRUE"), satoshis=9_000)],
            version=2,
        )
        tx.sign(bypass=False)
        assert validate_spend(tx, 0)

    def test_v2_source_v1_spend_nonminimal_push_fails(self, priv_key):
        """v1 spending tx rejects non-minimal push even when source is v2."""
        lock = p2pkh_lock_with_prefix("OP_5 OP_NUMEQUALVERIFY", priv_key)
        unlock = self._make_nonminimal_unlock(priv_key)
        funding_tx = build_funding_tx(lock, satoshis=10_000, version=2)
        inp = TransactionInput(
            source_transaction=funding_tx,
            source_output_index=0,
            unlocking_script_template=unlock,
            sequence=0xFFFFFFFF,
            sighash=SIGHASH(SIGHASH.ALL_FORKID),
        )
        tx = Transaction(
            [inp],
            [TransactionOutput(locking_script=Script.from_asm("OP_TRUE"), satoshis=9_000)],
            version=1,
        )
        tx.sign(bypass=False)
        with pytest.raises(RuntimeError, match="not minimally-encoded"):
            validate_spend(tx, 0)

    # --- Non-push opcodes in unlocking script ---

    def _make_nop_unlock(self, priv_key):
        """Unlocking template that includes OP_NOP (non-push opcode)."""

        def sign(tx, input_index):
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash
            signature = priv_key.sign(tx.preimage(input_index))
            public_key = priv_key.public_key().serialize()
            return Script(
                OpCode.OP_NOP + encode_pushdata(signature + sighash.to_bytes(1, "little")) + encode_pushdata(public_key)
            )

        return to_unlock_script_template(sign, lambda: 110)

    def test_v1_source_v2_spend_nop_in_unlock_passes(self, priv_key):
        """v2 spending tx allows non-push unlocking even when source is v1."""
        lock = P2PKH().lock(priv_key.address())
        unlock = self._make_nop_unlock(priv_key)
        funding_tx = build_funding_tx(lock, satoshis=10_000, version=1)
        inp = TransactionInput(
            source_transaction=funding_tx,
            source_output_index=0,
            unlocking_script_template=unlock,
            sequence=0xFFFFFFFF,
            sighash=SIGHASH(SIGHASH.ALL_FORKID),
        )
        tx = Transaction(
            [inp],
            [TransactionOutput(locking_script=Script.from_asm("OP_TRUE"), satoshis=9_000)],
            version=2,
        )
        tx.sign(bypass=False)
        assert validate_spend(tx, 0)

    def test_v2_source_v1_spend_nop_in_unlock_fails(self, priv_key):
        """v1 spending tx rejects non-push unlocking even when source is v2."""
        lock = P2PKH().lock(priv_key.address())
        unlock = self._make_nop_unlock(priv_key)
        funding_tx = build_funding_tx(lock, satoshis=10_000, version=2)
        inp = TransactionInput(
            source_transaction=funding_tx,
            source_output_index=0,
            unlocking_script_template=unlock,
            sequence=0xFFFFFFFF,
            sighash=SIGHASH(SIGHASH.ALL_FORKID),
        )
        tx = Transaction(
            [inp],
            [TransactionOutput(locking_script=Script.from_asm("OP_TRUE"), satoshis=9_000)],
            version=1,
        )
        tx.sign(bypass=False)
        with pytest.raises(RuntimeError, match="can only contain push operations"):
            validate_spend(tx, 0)


# ---------------------------------------------------------------------------
# 6. Version x opcode: Chronicle opcodes with "unnatural" pairings
# ---------------------------------------------------------------------------


class TestVersionOpcodeInteractions:
    """Chronicle opcodes work with any version/sighash combo (network-wide activation)."""

    @pytest.mark.parametrize("sighash,tx_version", CROSS_OPCODE_CONFIGS)
    def test_op_2mul(self, priv_key, sighash, tx_version):
        """OP_2MUL with BIP143+v2 and OTDA+v1."""
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_4 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_2")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)

    @pytest.mark.parametrize("sighash,tx_version", CROSS_OPCODE_CONFIGS)
    def test_op_2div(self, priv_key, sighash, tx_version):
        """OP_2DIV with BIP143+v2 and OTDA+v1."""
        lock = p2pkh_lock_with_prefix("OP_2DIV OP_5 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_10")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)

    @pytest.mark.parametrize("sighash,tx_version", CROSS_OPCODE_CONFIGS)
    def test_op_ver(self, priv_key, sighash, tx_version):
        """OP_VER with BIP143+v2 and OTDA+v1."""
        ver_le_hex = tx_version.to_bytes(4, "little").hex()
        lock = p2pkh_lock_with_prefix(f"OP_VER {ver_le_hex} OP_EQUALVERIFY", priv_key)
        unlock = custom_unlock(priv_key)
        build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)

    @pytest.mark.parametrize("sighash,tx_version", CROSS_OPCODE_CONFIGS)
    def test_op_substr(self, priv_key, sighash, tx_version):
        """OP_SUBSTR with BIP143+v2 and OTDA+v1."""
        lock = p2pkh_lock_with_prefix("OP_SUBSTR 6263 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_1 OP_2").serialize())
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)

    @pytest.mark.parametrize("sighash,tx_version", CROSS_OPCODE_CONFIGS)
    def test_op_left(self, priv_key, sighash, tx_version):
        """OP_LEFT with BIP143+v2 and OTDA+v1."""
        lock = p2pkh_lock_with_prefix("OP_LEFT 6162 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_2").serialize())
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)

    @pytest.mark.parametrize("sighash,tx_version", CROSS_OPCODE_CONFIGS)
    def test_op_right(self, priv_key, sighash, tx_version):
        """OP_RIGHT with BIP143+v2 and OTDA+v1."""
        lock = p2pkh_lock_with_prefix("OP_RIGHT 6465 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_2").serialize())
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)

    @pytest.mark.parametrize("sighash,tx_version", CROSS_OPCODE_CONFIGS)
    def test_op_lshiftnum(self, priv_key, sighash, tx_version):
        """OP_LSHIFTNUM with BIP143+v2 and OTDA+v1."""
        lock = p2pkh_lock_with_prefix("OP_LSHIFTNUM OP_8 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_1 OP_3")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)

    @pytest.mark.parametrize("sighash,tx_version", CROSS_OPCODE_CONFIGS)
    def test_op_rshiftnum(self, priv_key, sighash, tx_version):
        """OP_RSHIFTNUM with BIP143+v2 and OTDA+v1."""
        lock = p2pkh_lock_with_prefix("OP_RSHIFTNUM OP_2 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_8 OP_2")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)

    @pytest.mark.parametrize("sighash,tx_version", CROSS_OPCODE_CONFIGS)
    def test_op_verif(self, priv_key, sighash, tx_version):
        """OP_VERIF with BIP143+v2 and OTDA+v1."""
        lock = p2pkh_lock_with_prefix("OP_VERIF", priv_key)
        lock = Script(lock.serialize() + Script.from_asm("OP_ELSE OP_FALSE OP_ENDIF").serialize())
        ver_bytes = tx_version.to_bytes(4, "little")
        data = Script(encode_pushdata(ver_bytes))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
