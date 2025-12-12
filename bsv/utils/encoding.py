import base64
import json
from typing import Any, List, Union

class BytesList(bytes):
    def to_json(self) -> str:
        # JSON array of numbers
        return json.dumps([b for b in self])
    @staticmethod
    def from_json(data: str) -> 'BytesList':
        arr = json.loads(data)
        return BytesList(bytes(arr))

class BytesHex(bytes):
    def to_json(self) -> str:
        return json.dumps(self.hex())
    @staticmethod
    def from_json(data: str) -> 'BytesHex':
        s = json.loads(data)
        return BytesHex(bytes.fromhex(s))

class Bytes32Base64(bytes):
    def __new__(cls, b: bytes):
        if len(b) != 32:
            raise ValueError(f"Bytes32Base64: expected 32 bytes, got {len(b)}")
        return super().__new__(cls, b)
    def to_json(self) -> str:
        return json.dumps(base64.b64encode(self).decode('ascii'))
    @staticmethod
    def from_json(data: str) -> 'Bytes32Base64':
        s = json.loads(data)
        b = base64.b64decode(s)
        return Bytes32Base64(b)

class Bytes33Hex(bytes):
    def __new__(cls, b: bytes):
        if len(b) != 33:
            raise ValueError(f"Bytes33Hex: expected 33 bytes, got {len(b)}")
        return super().__new__(cls, b)
    def to_json(self) -> str:
        return json.dumps(self.hex())
    @staticmethod
    def from_json(data: str) -> 'Bytes33Hex':
        s = json.loads(data)
        return Bytes33Hex(bytes.fromhex(s))

class StringBase64(str):
    def to_array(self) -> bytes:
        return base64.b64decode(self)
    @staticmethod
    def from_array(arr: bytes) -> 'StringBase64':
        return StringBase64(base64.b64encode(arr).decode('ascii'))

class Signature:
    def __init__(self, sig_bytes: bytes):
        self.sig_bytes = sig_bytes
    def to_json(self) -> str:
        # serialize as array of numbers
        return json.dumps([b for b in self.sig_bytes])
    @staticmethod
    def from_json(data: str) -> 'Signature':
        arr = json.loads(data)
        return Signature(bytes(arr))
