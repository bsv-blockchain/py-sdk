import time
import uuid

from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import WalletImpl
from bsv.keystore.interfaces import KVStoreConfig
from bsv.keystore.local_kv_store import LocalKVStore


def test_list_outputs_retention_filter_excludes_expired():
    context = f"kvctx_{uuid.uuid4()}"
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    cfg = KVStoreConfig(wallet=wallet, context=context, originator="org", encrypt=False)
    # Inject retention period (seconds)
    setattr(cfg, "retention_period", 1)
    kv = LocalKVStore(cfg)

    # Create one output with retentionSeconds set via kv.set()
    kv.set(None, "rk", "rv", {"use_woc": False})

    # Without filter, output should be present
    res = wallet.list_outputs(None, {"basket": context, "use_woc": False}, "org")
    outs = res.get("outputs") or []
    assert len(outs) >= 1

    # With excludeExpired and future nowEpoch, output should be filtered out
    future = int(time.time()) + 60
    res2 = wallet.list_outputs(None, {"basket": context, "excludeExpired": True, "nowEpoch": future, "use_woc": False}, "org")
    outs2 = res2.get("outputs") or []
    assert len(outs2) == 0


def test_list_outputs_retention_filter_keeps_unbounded():
    context = f"kvctx_{uuid.uuid4()}"
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    cfg = KVStoreConfig(wallet=wallet, context=context, originator="org", encrypt=False)
    # No retention period => unbounded
    kv = LocalKVStore(cfg)

    kv.set(None, "uk", "uv", {"use_woc": False})
    future = int(time.time()) + 60
    res = wallet.list_outputs(None, {"basket": context, "excludeExpired": True, "nowEpoch": future, "use_woc": False}, "org")
    outs = res.get("outputs") or []
    assert len(outs) >= 1


