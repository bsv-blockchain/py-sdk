"""Sighash matrix: all 12 sighash flag combinations x 2 tx versions x multiple script types.

Each test builds a real Transaction, signs it with real keys, validates every
input through Spend.validate(), and mock-broadcasts.
"""

import pytest

from bsv.constants import SIGHASH
from bsv.keys import PrivateKey
from bsv.script.type import P2PKH, P2PK, BareMultisig

from .conftest import build_signed_tx, MockBroadcaster

# ---------------------------------------------------------------------------
# Sighash flag sets
# ---------------------------------------------------------------------------

FORKID_SIGHASHES = [
    SIGHASH.ALL_FORKID,
    SIGHASH.NONE_FORKID,
    SIGHASH.SINGLE_FORKID,
    SIGHASH.ALL_ANYONECANPAY_FORKID,
    SIGHASH.NONE_ANYONECANPAY_FORKID,
    SIGHASH.SINGLE_ANYONECANPAY_FORKID,
]

CHRONICLE_SIGHASHES = [
    SIGHASH.ALL_FORKID_CHRONICLE,
    SIGHASH.NONE_FORKID_CHRONICLE,
    SIGHASH.SINGLE_FORKID_CHRONICLE,
    SIGHASH.ALL_ANYONECANPAY_FORKID_CHRONICLE,
    SIGHASH.NONE_ANYONECANPAY_FORKID_CHRONICLE,
    SIGHASH.SINGLE_ANYONECANPAY_FORKID_CHRONICLE,
]

ALL_SIGHASHES = FORKID_SIGHASHES + CHRONICLE_SIGHASHES
TX_VERSIONS = [1, 2]


def _sighash_id(sh):
    return sh.name


def _version_id(v):
    return f"v{v}"


# ---------------------------------------------------------------------------
# P2PKH tests
# ---------------------------------------------------------------------------


class TestP2PKHSighashMatrix:
    """P2PKH across all sighash flags and tx versions."""

    @pytest.mark.parametrize("sighash", ALL_SIGHASHES, ids=_sighash_id)
    @pytest.mark.parametrize("tx_version", TX_VERSIONS, ids=_version_id)
    def test_single_input(self, priv_key, sighash, tx_version):
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert len(tx.inputs) == 1
        assert tx.txid()

    @pytest.mark.parametrize("sighash", ALL_SIGHASHES, ids=_sighash_id)
    @pytest.mark.parametrize("tx_version", TX_VERSIONS, ids=_version_id)
    def test_multi_input(self, priv_key, sighash, tx_version):
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        # For SIGHASH_SINGLE, need num_outputs >= num_inputs
        tx = build_signed_tx(
            lock,
            unlock,
            sighash=sighash,
            tx_version=tx_version,
            num_inputs=3,
            num_outputs=3,
        )
        assert len(tx.inputs) == 3
        assert len(tx.outputs) == 3


# ---------------------------------------------------------------------------
# P2PK tests
# ---------------------------------------------------------------------------


class TestP2PKSighashMatrix:
    """P2PK across all sighash flags and tx versions."""

    @pytest.mark.parametrize("sighash", ALL_SIGHASHES, ids=_sighash_id)
    @pytest.mark.parametrize("tx_version", TX_VERSIONS, ids=_version_id)
    def test_single_input(self, priv_key, sighash, tx_version):
        p2pk = P2PK()
        lock = p2pk.lock(priv_key.public_key().serialize())
        unlock = p2pk.unlock(priv_key)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert len(tx.inputs) == 1
        assert tx.txid()


# ---------------------------------------------------------------------------
# BareMultisig tests
# ---------------------------------------------------------------------------


class TestMultisigSighashMatrix:
    """2-of-3 BareMultisig across all sighash flags and tx versions."""

    @pytest.mark.parametrize("sighash", ALL_SIGHASHES, ids=_sighash_id)
    @pytest.mark.parametrize("tx_version", TX_VERSIONS, ids=_version_id)
    def test_2of3(self, priv_key, priv_key2, priv_key3, sighash, tx_version):
        multisig = BareMultisig()
        pubkeys = [
            priv_key.public_key().serialize(),
            priv_key2.public_key().serialize(),
            priv_key3.public_key().serialize(),
        ]
        lock = multisig.lock(pubkeys, threshold=2)
        unlock = multisig.unlock([priv_key, priv_key2])
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert len(tx.inputs) == 1
        assert tx.txid()


# ---------------------------------------------------------------------------
# Mock broadcast integration
# ---------------------------------------------------------------------------


class TestMockBroadcast:
    """Verify mock broadcast captures transactions after validation."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash", [SIGHASH.ALL_FORKID, SIGHASH.ALL_FORKID_CHRONICLE])
    @pytest.mark.parametrize("tx_version", TX_VERSIONS, ids=_version_id)
    async def test_broadcast_after_validation(self, priv_key, mock_broadcaster, sighash, tx_version):
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        result = await tx.broadcast(broadcaster=mock_broadcaster)
        assert result.status == "success"
        assert result.txid == tx.txid()
        assert len(mock_broadcaster.transactions) == 1


# ---------------------------------------------------------------------------
# Preimage routing verification
# ---------------------------------------------------------------------------


class TestPreimageRouting:
    """Verify FORKID-only uses BIP143 and FORKID+CHRONICLE uses OTDA."""

    def test_forkid_only_uses_bip143(self, priv_key):
        """FORKID without CHRONICLE should produce BIP143 preimage (164 bytes for P2PKH)."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        tx = build_signed_tx(lock, unlock, sighash=SIGHASH.ALL_FORKID, tx_version=1)
        # BIP143 preimage has fixed structure: 4+32+32+32+4+var+8+4+32+4+4 bytes
        preimage = tx.preimage(0)
        # BIP143 preimage starts with version (4 bytes LE)
        assert preimage[:4] == (1).to_bytes(4, "little")
        # Byte 4-36 is hashPrevouts (32 bytes, non-zero for ALL)
        assert preimage[4:36] != b"\x00" * 32

    def test_forkid_chronicle_uses_otda(self, priv_key):
        """FORKID+CHRONICLE should produce OTDA preimage (variable length)."""
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        tx = build_signed_tx(lock, unlock, sighash=SIGHASH.ALL_FORKID_CHRONICLE, tx_version=2)
        preimage = tx.preimage(0)
        # OTDA preimage starts with version (4 bytes LE) = 2
        assert preimage[:4] == (2).to_bytes(4, "little")
        # OTDA does NOT have hashPrevouts at bytes 4-36; instead it has
        # varint(num_inputs) followed by serialized inputs
        # So byte 4 should be 0x01 (varint for 1 input), not a 32-byte hash
        assert preimage[4:5] == b"\x01"
