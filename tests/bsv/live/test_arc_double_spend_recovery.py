"""Unit tests for :func:`~tests.bsv.live.conftest._recover_arc_double_spend_if_visible_on_woc`."""

from unittest.mock import MagicMock

import pytest

from bsv.broadcasters.arc import ARC, ARCConfig
from bsv.broadcasters.broadcaster import Broadcaster, BroadcastFailure, BroadcastResponse
from tests.bsv.live.conftest import _recover_arc_double_spend_if_visible_on_woc


def _tx_mock(txid_hex: str) -> MagicMock:
    tx = MagicMock()
    tx.txid.return_value = txid_hex
    tx.hex.return_value = (
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01"
    )
    return tx


def _arc_bc() -> ARC:
    return ARC("https://arc-test.taal.com", ARCConfig())


class _NonArc(Broadcaster):
    async def broadcast(self, transaction):
        raise NotImplementedError


@pytest.mark.asyncio
async def test_passthrough_success_response():
    bc = _arc_bc()
    tx = _tx_mock("aa" * 32)
    ok = BroadcastResponse(status="success", txid=tx.txid(), message="SEEN_ON_NETWORK")
    out = await _recover_arc_double_spend_if_visible_on_woc("https://api.whatsonchain.com/v1/bsv/test", bc, tx, ok)
    assert out is ok


@pytest.mark.asyncio
async def test_no_recovery_non_arc_broadcaster():
    bc = _NonArc()
    tx = _tx_mock("aa" * 32)
    fail = BroadcastFailure(
        status="failure",
        code="ARC_TX_STATUS",
        description="DOUBLE_SPEND_ATTEMPTED",
        txid=tx.txid(),
    )
    out = await _recover_arc_double_spend_if_visible_on_woc("https://api.whatsonchain.com/v1/bsv/test", bc, tx, fail)
    assert out is fail


@pytest.mark.asyncio
async def test_no_recovery_txid_mismatch():
    bc = _arc_bc()
    tx = _tx_mock("aa" * 32)
    fail = BroadcastFailure(
        status="failure",
        code="ARC_TX_STATUS",
        description="DOUBLE_SPEND_ATTEMPTED",
        txid="bb" * 32,
    )
    out = await _recover_arc_double_spend_if_visible_on_woc("https://api.whatsonchain.com/v1/bsv/test", bc, tx, fail)
    assert out is fail


@pytest.mark.asyncio
async def test_recovery_when_woc_mempool_post_true(monkeypatch):
    bc = _arc_bc()
    tid = "cc" * 32
    tx = _tx_mock(tid)
    fail = BroadcastFailure(
        status="failure",
        code="ARC_TX_STATUS",
        description="DOUBLE_SPEND_ATTEMPTED",
        txid=tid,
    )

    async def _probe_true(*_a, **_k):  # NOSONAR - must be async to match patched coroutine signature
        return True

    monkeypatch.setattr(
        "tests.bsv.live.arc_verify.woc_post_raw_tx_mempool_probe",
        _probe_true,
    )

    out = await _recover_arc_double_spend_if_visible_on_woc("https://api.whatsonchain.com/v1/bsv/test", bc, tx, fail)
    assert isinstance(out, BroadcastResponse)
    assert out.status == "success"
    assert out.txid == tid
    assert "WOC_VISIBLE_AFTER_ARC_DOUBLE_SPEND" in out.message


@pytest.mark.asyncio
async def test_recovery_when_woc_get_observable(monkeypatch):
    bc = _arc_bc()
    tid = "dd" * 32
    tx = _tx_mock(tid)
    fail = BroadcastFailure(
        status="failure",
        code="ARC_TX_STATUS",
        description="DOUBLE_SPEND_ATTEMPTED",
        txid=tid,
    )

    async def _probe_false(*_a, **_k):  # NOSONAR - must be async to match patched coroutine signature
        return False

    async def _get_ok(*_a, **_k):  # NOSONAR - must be async to match patched coroutine signature
        return "WOC_TX_HEX", True

    monkeypatch.setattr(
        "tests.bsv.live.arc_verify.woc_post_raw_tx_mempool_probe",
        _probe_false,
    )
    monkeypatch.setattr(
        "tests.bsv.live.arc_verify.woc_tx_observable_via_get",
        _get_ok,
    )

    out = await _recover_arc_double_spend_if_visible_on_woc("https://api.whatsonchain.com/v1/bsv/test", bc, tx, fail)
    assert isinstance(out, BroadcastResponse)
    assert out.status == "success"
    assert "WOC_TX_HEX" in out.message
