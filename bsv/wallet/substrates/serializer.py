import struct
from typing import List, Optional, Union
import os
from ..key_deriver import CounterpartyType

class Writer:
    def __init__(self):
        self.buf = bytearray()

    def write_byte(self, b: int):
        self.buf.append(b & 0xFF)

    def write_bytes(self, b: bytes):
        self.buf.extend(b)

    def write_bytes_reverse(self, b: bytes):
        self.buf.extend(b[::-1])

    def write_varint(self, n: int):
        if n < 0:
            n = (1 << 64) - 1  # negative one (0xFFFFFFFFFFFFFFFF)
        if n < 0xfd:
            self.write_byte(n)
        elif n <= 0xffff:
            self.write_byte(0xfd)
            self.buf.extend(struct.pack('<H', n))
        elif n <= 0xffffffff:
            self.write_byte(0xfe)
            self.buf.extend(struct.pack('<I', n))
        else:
            self.write_byte(0xff)
            self.buf.extend(struct.pack('<Q', n))

    def write_string(self, s: str):
        b = s.encode('utf-8')
        self.write_varint(len(b))
        self.write_bytes(b)

    def write_negative_one(self):
        self.write_varint((1 << 64) - 1)

    def write_negative_one_byte(self):
        self.write_byte(0xFF)

    # Optional helpers (Go compatible conventions)
    def write_optional_uint32(self, n: Optional[int]):
        if n is None:
            self.write_negative_one()
        else:
            self.write_varint(int(n) & 0xFFFFFFFF)

    def write_optional_bytes(self, b: Optional[bytes]):
        if b is None:
            self.write_negative_one()
        else:
            self.write_varint(len(b))
            self.write_bytes(b)

    def write_string_slice(self, slice: Optional[List[str]]):
        if slice is None:
            self.write_negative_one()
            return
        self.write_varint(len(slice))
        for s in slice:
            self.write_string(s)

    def write_int_bytes(self, b: bytes):
        self.write_varint(len(b))
        self.write_bytes(b)

    def write_int_bytes_optional(self, b: Optional[bytes]):
        if not b:
            self.write_negative_one()
        else:
            self.write_int_bytes(b)

    # --------------------
    # Helper for optional bool (Go style 0xFF = nil)
    # --------------------
    def write_optional_bool(self, b: Optional[bool]):
        if b is None:
            self.write_negative_one_byte()
        else:
            self.write_byte(1 if b else 0)

    def to_bytes(self) -> bytes:
        return bytes(self.buf)

class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def is_complete(self) -> bool:
        return self.pos >= len(self.data)

    def read_byte(self) -> int:
        if self.is_complete():
            raise EOFError('read past end of data')
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise EOFError('read past end of data')
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def read_bytes_reverse(self, n: int) -> bytes:
        return self.read_bytes(n)[::-1]

    def read_varint(self) -> int:
        first = self.read_byte()
        if first < 0xfd:
            return first
        elif first == 0xfd:
            return struct.unpack('<H', self.read_bytes(2))[0]
        elif first == 0xfe:
            return struct.unpack('<I', self.read_bytes(4))[0]
        elif first == 0xff:
            return struct.unpack('<Q', self.read_bytes(8))[0]
        else:
            raise ValueError('Invalid varint prefix')

    def read_string(self) -> str:
        length = self.read_varint()
        if length == (1 << 64) - 1 or length == 0:
            return ''
        b = self.read_bytes(length)
        return b.decode('utf-8')

    def read_int_bytes(self) -> Optional[bytes]:
        length = self.read_varint()
        if length == (1 << 64) - 1 or length == 0:
            return None
        return self.read_bytes(length)

    # Optional helpers
    def read_optional_uint32(self) -> Optional[int]:
        val = self.read_varint()
        if val == (1 << 64) - 1:
            return None
        return int(val & 0xFFFFFFFF)

    def read_optional_bytes(self) -> Optional[bytes]:
        length = self.read_varint()
        if length == (1 << 64) - 1 or length == 0:
            return None
        return self.read_bytes(length)

    def read_string_slice(self) -> Optional[List[str]]:
        count = self.read_varint()
        if count == (1 << 64) - 1:
            return None
        return [self.read_string() for _ in range(int(count))]

    def read_optional_bool(self) -> Optional[bool]:
        b = self.read_byte()
        if b == 0xFF:
            return None
        return bool(b)

# ==========================================================
# KeyRelatedParams encode / decode (ProtocolID, KeyID, Counterparty, Privileged)
# ==========================================================

def _encode_key_related_params(w: Writer, params: dict):
    # ProtocolID
    proto: dict = params.get('protocol_id', {})
    w.write_byte(proto.get('securityLevel', 0))
    w.write_string(proto.get('protocol', ''))
    # KeyID
    w.write_string(params.get('key_id', ''))
    # Determine counterparty type
    cp_val = params.get('counterparty')
    cp_bytes_param = params.get('counterparty_bytes')
    if cp_bytes_param or cp_val:
        cp_type = CounterpartyType.OTHER
    else:
        cp_type = params.get('counterparty_type', CounterpartyType.UNINITIALIZED)

    w.write_byte(cp_type)
    if cp_type not in (CounterpartyType.UNINITIALIZED, CounterpartyType.ANYONE, CounterpartyType.SELF):
        # Determine bytes
        cp_pub = cp_bytes_param
        if cp_pub is None:
            if isinstance(cp_val, str):
                cp_pub = bytes.fromhex(cp_val)
            elif isinstance(cp_val, bytes):
                cp_pub = cp_val
            else:
                cp_pub = b''
        w.write_bytes(cp_pub)
    # Privileged bool + Reason
    w.write_optional_bool(params.get('privileged'))
    w.write_string(params.get('privileged_reason', ''))
    # forSelf optional bool
    w.write_optional_bool(params.get('forSelf'))

def _decode_key_related_params(r: Reader) -> dict:
    sec_level = r.read_byte()
    protocol  = r.read_string()
    key_id    = r.read_string()
    cp_type   = r.read_byte()
    cp_pub    = b''
    if cp_type not in (CounterpartyType.UNINITIALIZED, CounterpartyType.ANYONE, CounterpartyType.SELF):
        cp_pub = r.read_bytes(33)
    privileged = r.read_optional_bool()
    priv_reason = r.read_string()
    for_self = r.read_optional_bool()
    return {
        'protocol_id': {'securityLevel': sec_level, 'protocol': protocol},
        'key_id': key_id,
        'counterparty_type': cp_type,
        'counterparty_bytes': cp_pub,
        'counterparty': cp_pub.hex() if cp_pub else None,
        'privileged': privileged,
        'privileged_reason': priv_reason,
        'forSelf': for_self,
    }

# ==========================================================
# Encrypt / Decrypt Serialize / Deserialize
# ==========================================================

def serialize_encrypt_args(args: dict) -> bytes:
    w = Writer()
    enc_args = args.get('encryption_args', args)
    if enc_args is None:
        enc_args = {}
    if os.getenv("BSV_DEBUG", "0") == "1":
        print(f"[DEBUG serialize_encrypt_args] enc_args keys={list(enc_args.keys())}")
    _encode_key_related_params(w, enc_args)
    plaintext: bytes = args.get('plaintext', b'')
    w.write_int_bytes(plaintext)
    w.write_optional_bool(args.get('encryption_args', {}).get('seekPermission'))
    return w.to_bytes()

def deserialize_encrypt_args(data: bytes) -> dict:
    r = Reader(data)
    enc_args = _decode_key_related_params(r)
    plaintext = r.read_int_bytes() or b''
    seek_perm = r.read_optional_bool()
    enc_args['seekPermission'] = seek_perm
    return {'encryption_args': enc_args, 'plaintext': plaintext}

def serialize_encrypt_result(result: dict) -> bytes:
    return result.get('ciphertext', b'')

def deserialize_encrypt_result(data: bytes) -> dict:
    return {'ciphertext': data}


def serialize_decrypt_args(args: dict) -> bytes:
    w = Writer()
    enc_args = args.get('encryption_args', args)
    if os.getenv("BSV_DEBUG", "0") == "1":
        print(f"[DEBUG serialize_decrypt_args] enc_args keys={list(enc_args.keys())}")
    _encode_key_related_params(w, enc_args)
    ciphertext: bytes = args.get('ciphertext', b'')
    w.write_int_bytes(ciphertext)
    w.write_optional_bool(args.get('encryption_args', {}).get('seekPermission'))
    return w.to_bytes()

def deserialize_decrypt_args(data: bytes) -> dict:
    r = Reader(data)
    enc_args = _decode_key_related_params(r)
    ciphertext = r.read_int_bytes() or b''
    seek_perm = r.read_optional_bool()
    enc_args['seekPermission'] = seek_perm
    return {'encryption_args': enc_args, 'ciphertext': ciphertext}

def serialize_decrypt_result(result: dict) -> bytes:
    return result.get('plaintext', b'')

def deserialize_decrypt_result(data: bytes) -> dict:
    return {'plaintext': data}

# ==========================================================
# Additional helpers for Actions / Certificates / Discovery serialization
# ==========================================================


def encode_outpoint(outpoint: Union[str, bytes, dict]) -> bytes:
    """Encode an outpoint into <32-byte txid LE><varint index> bytes.

    Supported inputs:
    1. str  -> "txid.index"  (hex txid big-endian)
    2. bytes -> already encoded 36+ bytes (simply returned)
    3. dict  -> {"txid": str|bytes, "index": int}
    """
    if isinstance(outpoint, bytes):
        return outpoint  # assume already encoded correctly
    if isinstance(outpoint, str):
        if "." in outpoint:
            txid_hex, idx_str = outpoint.split(".")
            idx = int(idx_str)
        else:
            txid_hex, idx = outpoint, 0
        txid_be = bytes.fromhex(txid_hex) if txid_hex else b"\x00" * 32
    elif isinstance(outpoint, dict):
        txid_val = outpoint.get("txid", b"")
        idx = int(outpoint.get("index", 0))
        if isinstance(txid_val, bytes):
            txid_be = txid_val
        else:
            txid_be = bytes.fromhex(txid_val) if txid_val else b"\x00" * 32
    else:
        # Fallback empty
        txid_be, idx = b"\x00" * 32, 0
    w = Writer()
    w.write_bytes_reverse(txid_be)
    w.write_varint(idx)
    return w.to_bytes()


def encode_privileged_params(privileged: Optional[bool], reason: str) -> bytes:
    """Encode privileged flag and reason into bytes per wire conventions."""
    w = Writer()
    w.write_optional_bool(privileged)
    if reason:
        w.write_string(reason)
    else:
        w.write_negative_one()
    return w.to_bytes()


def decode_outpoint(r: Reader) -> str:
    """Decode outpoint from reader and return "txid.index" string."""
    txid_le = r.read_bytes(32)
    txid_be = txid_le[::-1]
    idx = r.read_varint()
    return f"{txid_be.hex()}.{idx}"


# ==========================================================
# Actions Serializers (Args only – Results TBD)
# ==========================================================

def serialize_create_action_args(args: dict) -> bytes:
    """Ported from Go SerializeCreateActionArgs / TS implementation."""
    w = Writer()
    # Description & inputBEEF
    w.write_string(args.get("description", ""))
    input_beef = args.get("inputBEEF")
    if input_beef:
        w.write_int_bytes(input_beef)
    else:
        w.write_negative_one()
    # Inputs
    inputs = args.get("inputs")
    if not inputs:
        w.write_negative_one()
    else:
        w.write_varint(len(inputs))
        for inp in inputs:
            # Outpoint
            w.write_bytes(encode_outpoint(inp.get("outpoint", "")))
            # Unlocking script
            unlocking = inp.get("unlockingScript")
            if unlocking:
                w.write_int_bytes(unlocking)
            else:
                w.write_negative_one()
                w.write_varint(inp.get("unlockingScriptLength", 0))
            # Input description & sequence
            w.write_string(inp.get("inputDescription", ""))
            seq = inp.get("sequenceNumber")
            if seq is not None:
                w.write_varint(seq)
            else:
                w.write_negative_one()
    # Outputs
    outputs = args.get("outputs")
    if not outputs:
        w.write_negative_one()
    else:
        w.write_varint(len(outputs))
        for out in outputs:
            locking = out.get("lockingScript")
            if locking:
                w.write_int_bytes(locking)
            else:
                w.write_negative_one()
            w.write_varint(out.get("satoshis", 0))
            w.write_string(out.get("outputDescription", ""))
            basket = out.get("basket")
            if basket is not None:
                w.write_string(basket)
            else:
                w.write_negative_one()
            custom = out.get("customInstructions")
            if custom is not None:
                w.write_string(custom)
            else:
                w.write_negative_one()
            tags = out.get("tags")
            if tags:
                w.write_varint(len(tags))
                for tag in tags:
                    w.write_string(tag)
            else:
                w.write_negative_one()
    # LockTime, Version, Labels
    for key in ("lockTime", "version"):
        val = args.get(key)
        if val is not None:
            w.write_varint(val)
        else:
            w.write_negative_one()
    labels = args.get("labels")
    if labels:
        w.write_varint(len(labels))
        for label in labels:
            w.write_string(label)
    else:
        w.write_negative_one()
    # Options (not yet implemented)
    w.write_byte(0)  # flag not present
    return w.to_bytes()


def deserialize_create_action_args(data: bytes) -> dict:
    """Decode create action args. NOTE: This is an initial minimal implementation; complex nested structures will need further work."""
    r = Reader(data)
    description = r.read_string()
    input_beef = r.read_int_bytes()
    # Inputs
    num_inputs = r.read_varint()
    inputs = []
    if num_inputs != (1 << 64) - 1:
        for _ in range(num_inputs):
            outpoint = decode_outpoint(r)
            unlocking = r.read_int_bytes()
            if unlocking is None:
                # When optional, we consumed negative one earlier and len
                unlocking_len = r.read_varint()
            input_description = r.read_string()
            seq = r.read_varint()
            if seq == (1 << 64) - 1:
                seq = None
            inputs.append({
                "outpoint": outpoint,
                "unlockingScript": unlocking,
                "inputDescription": input_description,
                "sequenceNumber": seq,
            })
    # Outputs decoding and rest is deferred for now.
    # For now skip parsing remainder and return minimal dict with raw data.
    return {"description": description, "inputBEEF": input_beef, "raw_rest": r.data[r.pos:]}  # pragma: no cover


# TODO: Implement additional serializers below. For now they are placeholders.


def serialize_sign_action_args(args: dict) -> bytes:
    raise NotImplementedError("serialize_sign_action_args not yet ported")

def deserialize_sign_action_args(data: bytes) -> dict:
    raise NotImplementedError("deserialize_sign_action_args not yet ported")

def serialize_abort_action_args(args: dict) -> bytes:
    raise NotImplementedError("serialize_abort_action_args not yet ported")

def deserialize_abort_action_args(data: bytes) -> dict:
    raise NotImplementedError("deserialize_abort_action_args not yet ported")

def serialize_list_actions_args(args: dict) -> bytes:
    raise NotImplementedError("serialize_list_actions_args not yet ported")

def deserialize_list_actions_args(data: bytes) -> dict:
    raise NotImplementedError("deserialize_list_actions_args not yet ported")

def serialize_internalize_action_args(args: dict) -> bytes:
    raise NotImplementedError("serialize_internalize_action_args not yet ported")

def deserialize_internalize_action_args(data: bytes) -> dict:
    raise NotImplementedError("deserialize_internalize_action_args not yet ported")


# ==========================================================
# Certificates Serializers (placeholders)
# ==========================================================

def serialize_acquire_certificate_args(args: dict) -> bytes:
    raise NotImplementedError("serialize_acquire_certificate_args not yet ported")

def deserialize_acquire_certificate_args(data: bytes) -> dict:
    raise NotImplementedError("deserialize_acquire_certificate_args not yet ported")

def serialize_list_certificates_args(args: dict) -> bytes:
    raise NotImplementedError("serialize_list_certificates_args not yet ported")

def deserialize_list_certificates_args(data: bytes) -> dict:
    raise NotImplementedError("deserialize_list_certificates_args not yet ported")

def serialize_prove_certificate_args(args: dict) -> bytes:
    raise NotImplementedError("serialize_prove_certificate_args not yet ported")

def deserialize_prove_certificate_args(data: bytes) -> dict:
    raise NotImplementedError("deserialize_prove_certificate_args not yet ported")

def serialize_relinquish_certificate_args(args: dict) -> bytes:
    raise NotImplementedError("serialize_relinquish_certificate_args not yet ported")

def deserialize_relinquish_certificate_args(data: bytes) -> dict:
    raise NotImplementedError("deserialize_relinquish_certificate_args not yet ported")


# ==========================================================
# Discovery Serializers (placeholders)
# ==========================================================

def serialize_discover_by_identity_key_args(args: dict) -> bytes:
    raise NotImplementedError("serialize_discover_by_identity_key_args not yet ported")

def deserialize_discover_by_identity_key_args(data: bytes) -> dict:
    raise NotImplementedError("deserialize_discover_by_identity_key_args not yet ported")

def serialize_discover_by_attributes_args(args: dict) -> bytes:
    raise NotImplementedError("serialize_discover_by_attributes_args not yet ported")

def deserialize_discover_by_attributes_args(data: bytes) -> dict:
    raise NotImplementedError("deserialize_discover_by_attributes_args not yet ported")
