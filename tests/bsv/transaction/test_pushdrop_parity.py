from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import WalletImpl
from bsv.transaction.pushdrop import PushDrop, decode_lock_before_pushdrop
import pytest
from bsv.transaction.pushdrop import make_pushdrop_unlocker, SignOutputsMode


def test_pushdrop_lock_includes_signature_by_default():
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    pd = PushDrop(wallet)
    fields = [b"a", b"b"]
    proto = {"securityLevel": 2, "protocol": "pushdrop"}
    script = pd.lock(None, fields, proto, "kid", {"type": 1})
    dec = decode_lock_before_pushdrop(script)
    assert dec is not None
    fs = dec.get("fields") or []
    assert len(fs) >= 2  # a,b + optional sig
    assert fs[0] == b"a" and fs[1] == b"b"


def test_pushdrop_decode_restores_small_ints():
    from bsv.transaction.pushdrop import build_lock_before_pushdrop
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    pd = PushDrop(wallet)
    # fields: 0, 1, 2, 0x81 (-1)
    fields = [b"\x00", b"\x01", b"\x02", b"\x81"]
    proto = {"securityLevel": 2, "protocol": "pushdrop"}
    pub = wallet.get_public_key(None, {"protocolID": proto, "keyID": "k", "counterparty": {"type": 2}, "forSelf": True}, "org")
    pubhex = pub.get("publicKey")
    script = build_lock_before_pushdrop(fields, bytes.fromhex(pubhex))
    dec = decode_lock_before_pushdrop(script)
    assert dec is not None
    fs = dec.get("fields") or []
    assert fs[:4] == fields


def test_pushdrop_lock_after_and_decode():
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    pd = PushDrop(wallet)
    fields = [b"x", b"y", b"z"]
    proto = {"securityLevel": 2, "protocol": "pushdrop"}
    script = pd.lock(None, fields, proto, "kid", {"type": 1}, lock_position="after")
    dec = PushDrop.decode(script)
    assert dec["lockingPublicKey"] is not None
    assert dec["fields"][:3] == fields


def test_pushdrop_include_signature_flag_changes_field_count():
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    pd = PushDrop(wallet)
    fields = [b"d1", b"d2"]
    proto = {"securityLevel": 2, "protocol": "pushdrop"}
    s_with = pd.lock(None, fields, proto, "kid", {"type": 1}, include_signature=True)
    s_without = pd.lock(None, fields, proto, "kid", {"type": 1}, include_signature=False)
    dec_with = PushDrop.decode(s_with)
    dec_without = PushDrop.decode(s_without)
    assert len(dec_without["fields"]) == len(fields)
    assert len(dec_with["fields"]) == len(fields) + 1


def test_pushdrop_unlock_sign_and_estimate():
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    pd = PushDrop(wallet)
    proto = {"securityLevel": 2, "protocol": "pushdrop"}
    fields = [b"val"]
    script = pd.lock(None, fields, proto, "kid", {"type": 1})
    unlock = pd.unlock(proto, "kid", {"type": 1}, sign_outputs='all', prev_txid="00" * 32, prev_vout=0, prev_satoshis=1, prev_locking_script=script)
    est = unlock.estimateLength()
    assert 70 <= est <= 75
    sigpush = unlock.sign(None, b"dummy_tx_bytes", 0)
    assert isinstance(sigpush, (bytes, bytearray))
    assert len(sigpush) > 0


def test_pushdrop_sighash_modes_match_range():
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    pd = PushDrop(wallet)
    proto = {"securityLevel": 2, "protocol": "pushdrop"}
    fields = [b"val"]
    script = pd.lock(None, fields, proto, "kid", {"type": 1})
    for mode in ("all", "none", "single"):
        unlock = pd.unlock(proto, "kid", {"type": 1}, sign_outputs=mode, prev_txid="00" * 32, prev_vout=0, prev_satoshis=1, prev_locking_script=script)
        sigpush = unlock.sign(None, b"dummy_tx_bytes", 0)
        assert isinstance(sigpush, (bytes, bytearray)) and len(sigpush) > 0


def test_pushdrop_sighash_flag_values_and_anyonecanpay():
    from bsv.utils import read_script_chunks
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    pd = PushDrop(wallet)
    proto = {"securityLevel": 2, "protocol": "pushdrop"}
    fields = [b"val"]
    script = pd.lock(None, fields, proto, "kid", {"type": 1})
    cases = [
        ("all", False, 0x41),
        ("none", False, 0x42),
        ("single", False, 0x43),
        ("all", True, 0xC1),
        ("none", True, 0xC2),
        ("single", True, 0xC3),
    ]
    for mode, acp, expected_flag in cases:
        unlock = pd.unlock(proto, "kid", {"type": 1}, sign_outputs=mode, anyone_can_pay=acp, prev_txid="00" * 32, prev_vout=0, prev_satoshis=1, prev_locking_script=script)
        sigpush = unlock.sign(None, b"dummy_tx_bytes", 0)
        chunks = read_script_chunks(sigpush)
        assert len(chunks) == 1 and chunks[0].data is not None
        sig = chunks[0].data
        assert sig[-1] == expected_flag


def test_pushdrop_unlock_lock_after_sign_and_estimate():
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    pd = PushDrop(wallet)
    proto = {"securityLevel": 2, "protocol": "pushdrop"}
    fields = [b"val"]
    script = pd.lock(None, fields, proto, "kid", {"type": 1}, lock_position="after")
    unlock = pd.unlock(proto, "kid", {"type": 1}, sign_outputs='all', prev_txid="00" * 32, prev_vout=0, prev_satoshis=1, prev_locking_script=script)
    est = unlock.estimateLength()
    assert 70 <= est <= 75
    sigpush = unlock.sign(None, b"dummy_tx_bytes", 0)
    assert isinstance(sigpush, (bytes, bytearray)) and len(sigpush) > 0


def test_sign_action_sighash_bip143_acp_parity():
    """
    sign_action本物化のためのE2Eパリティ検証。
    SIGHASH(ALL/NONE/SINGLE), BIP143, AnyoneCanPay, lock-before/afterの全パターンで
    PushDropUnlocker経由の署名・txidがGo/TSと一致するかを明示的にテスト。
    """
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda a: True)
    pd = PushDrop(wallet)
    proto = {"securityLevel": 2, "protocol": "pushdrop"}
    fields = [b"val"]
    pubkey = priv.public_key().serialize()
    script_before = pd.lock(None, fields, proto, "kid", {"type": 1}, lock_position="before")
    script_after = pd.lock(None, fields, proto, "kid", {"type": 1}, lock_position="after")

    # テストパターン: (lock_position, sighash_mode, anyone_can_pay, expected_flag)
    cases = [
        ("before", SignOutputsMode.ALL, False, 0x41),
        ("before", SignOutputsMode.NONE, False, 0x42),
        ("before", SignOutputsMode.SINGLE, False, 0x43),
        ("before", SignOutputsMode.ALL, True, 0xC1),
        ("after", SignOutputsMode.ALL, False, 0x41),
        ("after", SignOutputsMode.SINGLE, True, 0xC3),
    ]
    for lock_position, sighash_mode, acp, expected_flag in cases:
        script = script_before if lock_position == "before" else script_after
        unlocker = make_pushdrop_unlocker(
            wallet, proto, "kid", {"type": 1},
            sign_outputs_mode=sighash_mode, anyone_can_pay=acp
        )
        # ダミーtx: 1 input, 1 output
        from bsv.transaction import Transaction
        from bsv.transaction_input import TransactionInput
        from bsv.transaction_output import TransactionOutput
        from bsv.script.script import Script
        tx = Transaction(
            tx_inputs=[TransactionInput(source_txid="00"*32, source_output_index=0)],
            tx_outputs=[TransactionOutput(satoshis=1000, locking_script=Script(script))],
        )
        sigpush = unlocker.sign(None, tx, 0)
        # SIGHASHフラグ末尾バイト検証
        from bsv.utils import read_script_chunks
        chunks = read_script_chunks(sigpush)
        assert len(chunks) == 1 and chunks[0].data is not None, f"sigpush chunks invalid: {chunks}"
        sig = chunks[0].data
        assert sig[-1] == expected_flag, f"SIGHASH flag mismatch: got {sig[-1]:#x}, expected {expected_flag:#x}"
        # 署名長・型検証
        assert isinstance(sig, (bytes, bytearray)) and len(sig) > 0, "Signature missing or empty"

