"""
writer.py - Writer class (binary writing utilities).
"""
import struct
from io import BytesIO

class Writer(BytesIO):
    def __init__(self):
        super().__init__()

    def write(self, buf: bytes) -> 'Writer':
        super().write(buf)
        return self

    def write_reverse(self, buf: bytes) -> 'Writer':
        super().write(buf[::-1])
        return self

    def write_uint8(self, n: int) -> 'Writer':
        self.write(struct.pack('B', n))
        return self

    def write_int8(self, n: int) -> 'Writer':
        self.write(struct.pack('b', n))
        return self

    def write_uint16_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>H', n))
        return self

    def write_int16_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>h', n))
        return self

    def write_uint16_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<H', n))
        return self

    def write_int16_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<h', n))
        return self

    def write_uint32_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>I', n))
        return self

    def write_int32_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>i', n))
        return self

    def write_uint32_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<I', n))
        return self

    def write_int32_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<i', n))
        return self

    def write_uint64_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>Q', n))
        return self

    def write_uint64_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<Q', n))
        return self

    def write_int64_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<q', n))
        return self

    def write_int64_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>q', n))
        return self

    def write_bytes(self, buf: bytes) -> 'Writer':
        self.write(buf)
        return self

    def write_var_int_num(self, n: int) -> 'Writer':
        self.write(self.var_int_num(n))
        return self

    def to_bytes(self) -> bytes:
        return self.getvalue()

    @staticmethod
    def var_int_num(n: int) -> bytes:
        from .binary import unsigned_to_varint
        return unsigned_to_varint(n)