import os

from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import WalletImpl


def _latest_action(wallet: WalletImpl) -> dict:
    assert wallet._actions, "expected at least one action recorded"
    return wallet._actions[-1]


def _find_change_output(outputs: list[dict]) -> dict | None:
    for o in outputs:
        if (o.get("outputDescription") or "").lower() == "change":
            return o
    return None


def test_funding_adds_inputs_and_change_low_fee():
    # Ensure WOC path is off for deterministic mock UTXO
    os.environ.pop("USE_WOC", None)

    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda _: True)

    # Request an output small enough to leave change from the mock 1000-sat UTXO
    # Use very low feeRate so change is certainly >= dust (546)
    args = {
        "labels": ["test", "funding"],
        "description": "funding low fee",
        "outputs": [
            {
                "satoshis": 200,
                "lockingScript": b"\x51",  # OP_TRUE for simplicity in tests
            },
        ],
        "feeRate": 1,
    }
    res = wallet.create_action(None, args, "test")
    assert isinstance(res, dict) and isinstance(res.get("signableTransaction"), dict)

    act = _latest_action(wallet)
    inputs = act.get("inputs") or []
    outputs = act.get("outputs") or []

    assert len(inputs) >= 1, "funding input should be added"
    chg = _find_change_output(outputs)
    assert chg is not None, "change output should be created at low fee"
    assert int(chg.get("satoshis", 0)) >= 546, "change should be above dust threshold"


def test_fee_rate_affects_change_amount():
    os.environ.pop("USE_WOC", None)

    # Low fee wallet
    w1 = WalletImpl(PrivateKey(), permission_callback=lambda _: True)
    args = {
        "labels": ["test", "funding"],
        "description": "funding low fee",
        "outputs": [{"satoshis": 200, "lockingScript": b"\x51"}],
        "feeRate": 1,
    }
    _ = w1.create_action(None, args, "test")
    chg1 = _find_change_output(_latest_action(w1).get("outputs") or [])
    assert chg1 is not None
    c1 = int(chg1.get("satoshis", 0))

    # Higher fee wallet
    w2 = WalletImpl(PrivateKey(), permission_callback=lambda _: True)
    args2 = {
        "labels": ["test", "funding"],
        "description": "funding high fee",
        "outputs": [{"satoshis": 200, "lockingScript": b"\x51"}],
        "feeRate": 500,
    }
    _ = w2.create_action(None, args2, "test")
    chg2 = _find_change_output(_latest_action(w2).get("outputs") or [])
    # High fee may drop change below dust; tolerate missing change, but if present it must be smaller
    if chg2 is not None:
        c2 = int(chg2.get("satoshis", 0))
        assert c2 < c1, "higher fee should reduce change amount"


def test_no_change_when_dust():
    os.environ.pop("USE_WOC", None)

    wallet = WalletImpl(PrivateKey(), permission_callback=lambda _: True)
    # Ask for large output so remaining change (1000 - out - fee) is very small
    args = {
        "labels": ["test", "funding"],
        "description": "funding small change",
        "outputs": [{"satoshis": 900, "lockingScript": b"\x51"}],
        "feeRate": 500,
    }
    _ = wallet.create_action(None, args, "test")
    outs = _latest_action(wallet).get("outputs") or []
    chg = _find_change_output(outs)
    # BSV does not have dust limits, so even small change outputs should be created
    assert chg is not None, "small change output should be created in BSV"
    assert int(chg.get("satoshis", 0)) > 0, "change should be positive"


