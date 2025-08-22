from typing import List, Union, Tuple, Optional, Dict
import types
from enum import Enum

from bsv.constants import OpCode
from bsv.utils import encode_pushdata, read_script_chunks


def build_pushdrop_locking_script(items: List[Union[str, bytes]]) -> bytes:
    """
    Build a PushDrop locking script:
    <data1> OP_DROP <data2> OP_DROP ... OP_TRUE
    Items may be str (utf-8 encoded) or bytes.
    """
    parts: List[bytes] = []
    for it in items:
        data = it.encode("utf-8") if isinstance(it, str) else bytes(it)
        parts.append(encode_pushdata(data))
        parts.append(OpCode.OP_DROP)
    parts.append(OpCode.OP_TRUE)
    return b"".join(parts)


def parse_pushdrop_locking_script(script: bytes) -> List[bytes]:
    """
    Parse a PushDrop locking script built as: <data> OP_DROP ... OP_TRUE
    Returns the sequence of pushed data items.
    """
    items: List[bytes] = []
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if op == 0x51:  # OP_TRUE / OP_1
            break
        if op <= 75:
            ln = op
            if i + ln > n:
                break
            items.append(script[i:i+ln])
            i += ln
        elif op == 0x4c:  # OP_PUSHDATA1
            if i >= n:
                break
            ln = script[i]
            i += 1
            if i + ln > n:
                break
            items.append(script[i:i+ln])
            i += ln
        elif op == 0x4d:  # OP_PUSHDATA2
            if i + 1 >= n:
                break
            ln = int.from_bytes(script[i:i+2], 'little')
            i += 2
            if i + ln > n:
                break
            items.append(script[i:i+ln])
            i += ln
        elif op == 0x4e:  # OP_PUSHDATA4
            if i + 3 >= n:
                break
            ln = int.from_bytes(script[i:i+4], 'little')
            i += 4
            if i + ln > n:
                break
            items.append(script[i:i+ln])
            i += ln
        else:
            # Expect OP_DROP between pushes; ignore it
            continue
    return items


def parse_identity_reveal(items: List[bytes]) -> List[Tuple[str, str]]:
    """
    Given data items from parse_pushdrop_locking_script, interpret as identity.reveal payload:
    [b'identity.reveal', b'field1', b'value1', ...] -> [(field1, value1), ...]
    """
    out: List[Tuple[str, str]] = []
    if not items:
        return out
    try:
        if items[0].decode('utf-8') != 'identity.reveal':
            return out
    except Exception:
        return out
    i = 1
    while i + 1 < len(items):
        try:
            k = items[i].decode('utf-8')
            v = items[i + 1].decode('utf-8')
            out.append((k, v))
        except Exception:
            break
        i += 2
    return out


# --- TS/Go-compatible lock-before PushDrop helpers ---

def create_minimally_encoded_script_chunk(data: bytes) -> bytes:
    """Return minimal encoding for data (OP_0/OP_1NEGATE/OP_1..OP_16 when applicable)."""
    if len(data) == 0:
        return b"\x00"
    if len(data) == 1:
        b0 = data[0]
        if b0 == 0x00:
            return b"\x00"  # OP_0
        if b0 == 0x81:
            return b"\x4f"  # OP_1NEGATE
        if 0x01 <= b0 <= 0x10:
            return bytes([0x50 + b0])  # OP_1..OP_16
    return encode_pushdata(data)


def build_lock_before_pushdrop(
    fields: List[bytes],
    public_key: bytes,
    *,
    include_signature: bool = False,
    signature: Optional[bytes] = None,
    lock_position: str = "before"
) -> bytes:
    """
    Create a lock-before (or lock-after) PushDrop script:
    <pubkey> OP_CHECKSIG <fields...> OP_DROP/OP_2DROP...  (lock_position="before")
    <fields...> OP_DROP/OP_2DROP... <pubkey> OP_CHECKSIG  (lock_position="after")
    """
    chunks: List[bytes] = []
    lock_chunks: List[bytes] = []
    pushdrop_chunks: List[bytes] = []
    # Lock part (use minimally encoded chunk for pubkey)
    lock_chunks.append(create_minimally_encoded_script_chunk(public_key))
    lock_chunks.append(OpCode.OP_CHECKSIG)
    # Fields/PushDrop part
    data_fields = list(fields)
    if include_signature and signature is not None:
        data_fields.append(signature)
    for field in data_fields:
        pushdrop_chunks.append(create_minimally_encoded_script_chunk(field))
    not_yet_dropped = len(data_fields)
    while not_yet_dropped > 1:
        pushdrop_chunks.append(OpCode.OP_2DROP)
        not_yet_dropped -= 2
    if not_yet_dropped != 0:
        pushdrop_chunks.append(OpCode.OP_DROP)
    # lock_position
    if lock_position == "before":
        chunks = lock_chunks + pushdrop_chunks
    else:
        chunks = pushdrop_chunks + lock_chunks
    return b"".join(chunks)


def decode_lock_before_pushdrop(
    script: bytes,
    *,
    lock_position: str = "before"
) -> Optional[Dict[str, object]]:
    """
    Decode a lock-before (or lock-after) PushDrop script.
    Returns dict with pubkey and fields (list of bytes).
    """
    chunks = read_script_chunks(script)
    print("[decode] chunks:", [(c.op, c.data.hex() if c.data else None) for c in chunks])
    if len(chunks) < 2:
        print("[decode] not enough chunks")
        return None
    # lock_position
    if lock_position == "before":
        first = chunks[0]
        second = chunks[1]
        print(f"[decode] first.op={first.op}, first.data={first.data.hex() if first.data else None}, second.op={second.op}")
        print(f"[decode] second.op={second.op} ({type(second.op)}), OpCode.OP_CHECKSIG={OpCode.OP_CHECKSIG} ({type(OpCode.OP_CHECKSIG)})")
        sop = second.op
        opcs = OpCode.OP_CHECKSIG
        if isinstance(sop, bytes):
            sop = int.from_bytes(sop, 'little')
        if isinstance(opcs, bytes):
            opcs = int.from_bytes(opcs, 'little')
        if sop != opcs or first.data is None or len(first.data) not in (33, 65):
            print("[decode] header mismatch")
            return None
        pubkey = first.data
        fields: List[bytes] = []
        for i in range(2, len(chunks)):
            c = chunks[i]
            cop = c.op
            if isinstance(cop, bytes):
                cop = int.from_bytes(cop, 'little')
            drop = OpCode.OP_DROP
            twodrop = OpCode.OP_2DROP
            if isinstance(drop, bytes):
                drop = int.from_bytes(drop, 'little')
            if isinstance(twodrop, bytes):
                twodrop = int.from_bytes(twodrop, 'little')
            if cop == drop or cop == twodrop:
                break
            if c.data is None or (isinstance(c.data, (bytes, bytearray)) and len(c.data) == 0):
                if cop == 0x00:
                    fields.append(b"\x00")
                    continue
                if cop == 0x4f:
                    fields.append(b"\x81")
                    continue
                if 0x51 <= cop <= 0x60:
                    fields.append(bytes([cop - 0x50]))
                    continue
            fields.append(c.data or b"")
        return {"pubkey": pubkey, "fields": fields}
    else:  # lock-after
        # Find OP_CHECKSIG and pubkey at the end
        last_op = chunks[-1].op
        if isinstance(last_op, bytes):
            last_op = int.from_bytes(last_op, 'little')
        opcs = OpCode.OP_CHECKSIG
        if isinstance(opcs, bytes):
            opcs = int.from_bytes(opcs, 'little')
        if last_op != opcs:
            print("[decode] lock-after: no OP_CHECKSIG at end")
            return None
        pubkey_chunk = chunks[-2]
        print(f"[decode] lock-after: pubkey_chunk.op={pubkey_chunk.op}, pubkey_chunk.data={pubkey_chunk.data.hex() if pubkey_chunk.data else None}")
        if pubkey_chunk.data is None or len(pubkey_chunk.data) not in (33, 65):
            print("[decode] lock-after: pubkey length mismatch")
            return None
        pubkey = pubkey_chunk.data
        fields: List[bytes] = []
        drop = OpCode.OP_DROP
        twodrop = OpCode.OP_2DROP
        if isinstance(drop, bytes):
            drop = int.from_bytes(drop, 'little')
        if isinstance(twodrop, bytes):
            twodrop = int.from_bytes(twodrop, 'little')
        for i in range(0, len(chunks) - 2):
            c = chunks[i]
            cop = c.op
            if isinstance(cop, bytes):
                cop = int.from_bytes(cop, 'little')
            if cop == drop or cop == twodrop:
                break
            if c.data is None or (isinstance(c.data, (bytes, bytearray)) and len(c.data) == 0):
                if cop == 0x00:
                    fields.append(b"\x00")
                    continue
                if cop == 0x4f:
                    fields.append(b"\x81")
                    continue
                if 0x51 <= cop <= 0x60:
                    fields.append(bytes([cop - 0x50]))
                    continue
            fields.append(c.data or b"")
        return {"pubkey": pubkey, "fields": fields}


# ---------------------------------------------------------------------------
# PushDrop class (TS/Go-like) – lock/unlock/decode
# ---------------------------------------------------------------------------

class PushDrop:
    def __init__(self, wallet, originator: Optional[str] = None):
        self.wallet = wallet
        self.originator = originator

    @staticmethod
    def decode(script: bytes) -> Dict[str, object]:
        res = decode_lock_before_pushdrop(script) or decode_lock_before_pushdrop(script, lock_position="after") or {}
        # TS parity: key name lockingPublicKey
        if res:
            return {"lockingPublicKey": res.get("pubkey"), "fields": res.get("fields", [])}
        return {"lockingPublicKey": None, "fields": []}

    def lock(
        self,
        ctx,
        fields: List[bytes],
        protocol_id,
        key_id: str,
        counterparty,
        *,
        for_self: bool = False,
        include_signature: bool = True,
        lock_position: str = "before",
    ) -> bytes:
        # get public key
        args = {
            "protocolID": protocol_id,
            "keyID": key_id,
            "counterparty": counterparty,
            "forSelf": for_self,
        }
        pub = self.wallet.get_public_key(ctx, args, self.originator) or {}
        pubhex = pub.get("publicKey") or ""
        sig_bytes: Optional[bytes] = None
        if include_signature:
            data_to_sign = b"".join(fields)
            sargs = {
                "encryption_args": {
                    "protocol_id": protocol_id if isinstance(protocol_id, dict) else {"securityLevel": 0, "protocol": str(protocol_id)},
                    "key_id": key_id,
                    "counterparty": counterparty,
                },
                "data": data_to_sign,
            }
            try:
                cres = self.wallet.create_signature(ctx, sargs, self.originator) or {}
                sig = cres.get("signature")
                if isinstance(sig, (bytes, bytearray)):
                    sig_bytes = bytes(sig)
                else:
                    # ensure an extra field exists when requested
                    sig_bytes = b"\x00"
            except Exception:
                sig_bytes = b"\x00"
        if isinstance(pubhex, str) and len(pubhex) >= 66:
            try:
                return build_lock_before_pushdrop(fields, bytes.fromhex(pubhex), include_signature=include_signature, signature=sig_bytes, lock_position=lock_position)
            except Exception:
                return b"\x51"
        return b"\x51"

    def unlock(
        self,
        protocol_id,
        key_id: str,
        counterparty,
        *,
        sign_outputs: str = 'all',
        anyone_can_pay: bool = False,
        prev_txid: Optional[str] = None,
        prev_vout: Optional[int] = None,
        prev_satoshis: Optional[int] = None,
        prev_locking_script: Optional[bytes] = None,
    ):
        # Map sign_outputs string to mode
        mode = SignOutputsMode.ALL
        so = (sign_outputs or 'all').lower()
        if so == 'none':
            mode = SignOutputsMode.NONE
        elif so == 'single':
            mode = SignOutputsMode.SINGLE
        unlocker = PushDropUnlocker(
            self.wallet,
            protocol_id,
            key_id,
            counterparty,
            sign_outputs_mode=mode,
            anyone_can_pay=anyone_can_pay,
            prev_txid=prev_txid,
            prev_vout=prev_vout,
            prev_satoshis=prev_satoshis,
            prev_locking_script=prev_locking_script,
        )
        return types.SimpleNamespace(
            sign=lambda ctx, tx, input_index: unlocker.sign(ctx, tx, input_index),
            estimateLength=lambda: unlocker.estimate_length(),
        )


# ---------------------------------------------------------------------------
# Unlocker helper (stub) – will sign PushDrop outputs for spending
# ---------------------------------------------------------------------------

class SignOutputsMode(Enum):
    ALL = 1
    NONE = 2
    SINGLE = 3


class PushDropUnlocker:
    """Generate unlocking script for a PushDrop output (lock-before pattern).

    The locking script is:
        <pubkey> OP_CHECKSIG  <data...> ...
    Unlocking script therefore pushes a valid ECDSA signature for that pubkey.
    """

    def __init__(self, wallet, protocol_id, key_id, counterparty, sign_outputs_mode=SignOutputsMode.ALL, anyone_can_pay: bool = False,
                 prev_txid: str | None = None, prev_vout: int | None = None,
                 prev_satoshis: int | None = None, prev_locking_script: bytes | None = None):
        self.wallet = wallet
        self.protocol_id = protocol_id
        self.key_id = key_id
        self.counterparty = counterparty
        self.sign_outputs_mode = sign_outputs_mode
        self.anyone_can_pay = anyone_can_pay
        # Optional precise BIP143 context (TS/Go equivalent unlock params)
        self.prev_txid = prev_txid
        self.prev_vout = prev_vout
        self.prev_satoshis = prev_satoshis
        self.prev_locking_script = prev_locking_script

    def estimate_length(self) -> int:  # noqa: D401
        """Approximate unlocking script length for a single DER signature.

        Estimates: 1-byte length prefix + 最大73バイトのDER署名＋1バイトのSIGHASHフラグ。
        """
        return 1 + 73 + 1

    def estimate_length_bounds(self) -> tuple[int, int]:  # noqa: D401
        """Return (min_estimate, max_estimate) for unlocking script length.

        DER署名の長さは低S値などにより70〜73バイトの範囲で変動する。PUSHDATA長1＋DER長＋SIGHASH 1の範囲。
        """
        min_len = 1 + 70 + 1
        max_len = 1 + 73 + 1
        return (min_len, max_len)

    def sign(self, ctx, tx, input_index: int) -> bytes:  # noqa: D401
        """Create a signature for the given input using SIGHASH flags and return as pushdata.

        Flags: base (ALL/NONE/SINGLE) derived from sign_outputs_mode, always includes FORKID,
        and optionally ANYONECANPAY when anyone_can_pay is True.
        """
        # Compute sighash flag
        # Map sign_outputs_mode to base SIGHASH (TS/Go enum semantics)
        base = 0x01  # ALL
        mode = self.sign_outputs_mode
        if isinstance(mode, SignOutputsMode):
            if mode is SignOutputsMode.ALL:
                base = 0x01
            elif mode is SignOutputsMode.NONE:
                base = 0x02
            elif mode is SignOutputsMode.SINGLE:
                base = 0x03
        else:
            # Back-compat for int/str usage
            if mode in (2, 'none', 'NONE'):
                base = 0x02
            elif mode in (3, 'single', 'SINGLE'):
                base = 0x03
        sighash_flag = base | 0x40  # include FORKID
        if self.anyone_can_pay:
            sighash_flag |= 0x80

        # Prefer BIP143 preimage on Transaction objects with explicit flags
        hash_to_sign: bytes
        used_preimage = False
        try:
            from bsv.transaction import Transaction as _Tx
            from bsv.transaction_preimage import tx_preimage as _tx_preimage
            if isinstance(tx, _Tx):
                # If caller provided precise prevout context, compute BIP143 preimage using it.
                if (
                    self.prev_txid is not None
                    and self.prev_vout is not None
                    and self.prev_satoshis is not None
                    and self.prev_locking_script is not None
                ):
                    from bsv.transaction_input import TransactionInput
                    from bsv.script.script import Script
                    # Build a synthetic input list with correct sighash and prevout context
                    synthetic = TransactionInput(
                        source_txid=self.prev_txid,
                        source_output_index=int(self.prev_vout),
                    )
                    synthetic.satoshis = int(self.prev_satoshis)
                    synthetic.locking_script = Script(self.prev_locking_script)
                    synthetic.sighash = sighash_flag
                    hash_to_sign = _tx_preimage(0, [synthetic], tx.outputs, tx.version, tx.locktime)
                    used_preimage = True
                else:
                    # Fallback to using tx.inputs context if present
                    for i, _in in enumerate(getattr(tx, "inputs", []) or []):
                        if not hasattr(_in, "sighash"):
                            setattr(_in, "sighash", 0x41)
                        if i == int(input_index):
                            setattr(_in, "sighash", sighash_flag)
                    hash_to_sign = _tx_preimage(input_index, tx.inputs, tx.outputs, tx.version, tx.locktime)
                    used_preimage = True
            else:
                raise TypeError
        except Exception:
            # Fallbacks: tx may expose .preimage(), otherwise treat as bytes
            if hasattr(tx, "preimage") and callable(getattr(tx, "preimage")):
                try:
                    hash_to_sign = tx.preimage(input_index)
                    used_preimage = True
                except Exception:
                    raw = tx.serialize() if hasattr(tx, "serialize") else (tx if isinstance(tx, (bytes, bytearray)) else b"")
                    hash_to_sign = raw
            else:
                raw = tx if isinstance(tx, (bytes, bytearray)) else getattr(tx, "bytes", b"")
                hash_to_sign = raw

        create_args = {
            "encryption_args": {
                "protocol_id": self.protocol_id,
                "key_id": self.key_id,
                "counterparty": self.counterparty,
            },
            ("hash_to_sign" if used_preimage else "data"): hash_to_sign,
        }
        res = self.wallet.create_signature(ctx, create_args, "") if hasattr(self.wallet, "create_signature") else {}
        sig = res.get("signature", b"")
        # Always append sighash flag byte even if signature is empty (test/mocks)
        sig = bytes(sig) + bytes([sighash_flag])
        return encode_pushdata(sig)


def make_pushdrop_unlocker(wallet, protocol_id, key_id, counterparty, sign_outputs_mode: SignOutputsMode = SignOutputsMode.ALL, anyone_can_pay: bool = False,
                           prev_txid: str | None = None, prev_vout: int | None = None,
                           prev_satoshis: int | None = None, prev_locking_script: bytes | None = None) -> PushDropUnlocker:
    """Convenience factory mirroring Go/TS helper to construct an unlocker.

    Returns a `PushDropUnlocker` ready to `sign(ctx, tx_bytes, input_index)`.
    """
    return PushDropUnlocker(
        wallet,
        protocol_id,
        key_id,
        counterparty,
        sign_outputs_mode,
        anyone_can_pay,
        prev_txid,
        prev_vout,
        prev_satoshis,
        prev_locking_script,
    )

