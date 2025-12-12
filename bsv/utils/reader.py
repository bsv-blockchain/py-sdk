"""
reader.py - Reader class (binary reading utilities).
"""
from io import BytesIO
from typing import Optional, Literal

class Reader(BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)

    def eof(self) -> bool:
        return self.tell() >= len(self.getvalue())

    def read(self, length: int = None) -> bytes:
        result = super().read(length)
        return result if result else None

    def read_reverse(self, length: int = None) -> bytes:
        data = self.read(length)
        return data[::-1] if data else None

    def read_uint8(self) -> Optional[int]:
        data = self.read(1)
        return data[0] if data else None

    def read_int8(self) -> Optional[int]:
        data = self.read(1)
        return int.from_bytes(data, byteorder='big', signed=True) if data else None

    def read_uint16_be(self) -> Optional[int]:
        data = self.read(2)
        return int.from_bytes(data, byteorder='big') if data else None

    def read_int16_be(self) -> Optional[int]:
        data = self.read(2)
        return int.from_bytes(data, byteorder='big', signed=True) if data else None

    def read_uint16_le(self) -> Optional[int]:
        data = self.read(2)
        return int.from_bytes(data, byteorder='little') if data else None

    def read_int16_le(self) -> Optional[int]:
        data = self.read(2)
        return int.from_bytes(data, byteorder='little', signed=True) if data else None

    def read_uint32_be(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='big') if data else None

    def read_int32_be(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='big', signed=True) if data else None

    def read_uint32_le(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='little') if data else None

    def read_int32_le(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='little', signed=True) if data else None

    def read_uint64_be(self) -> Optional[int]:
        data = self.read(8)
        return int.from_bytes(data, byteorder='big') if data else None

    def read_uint64_le(self) -> Optional[int]:
        data = self.read(8)
        return int.from_bytes(data, byteorder='little') if data else None

    def read_int64_le(self) -> Optional[int]:
        data = self.read(8)
        return int.from_bytes(data, byteorder='little', signed=True) if data else None

    def read_int64_be(self) -> Optional[int]:
        data = self.read(8)
        return int.from_bytes(data, byteorder='big', signed=True) if data else None

    def read_var_int_num(self) -> Optional[int]:
        first_byte = self.read_uint8()
        if first_byte is None:
            return None
        if first_byte < 253:
            return first_byte
        elif first_byte == 253:
            return self.read_uint16_le()
        elif first_byte == 254:
            return self.read_uint32_le()
        elif first_byte == 255:
            data = self.read(8)
            return int.from_bytes(data, byteorder='little') if data else None
        else:
            raise ValueError("Invalid varint encoding")

    def read_var_int(self) -> Optional[bytes]:
        first_byte = self.read(1)
        if not first_byte:
            return None
        if first_byte[0] == 0xfd:
            return first_byte + (self.read(2) or b'')
        elif first_byte[0] == 0xfe:
            return first_byte + (self.read(4) or b'')
        elif first_byte[0] == 0xff:
            return first_byte + (self.read(8) or b'')
        else:
            return first_byte

    def read_bytes(self, byte_length: Optional[int] = None) -> bytes:
        result = self.read(byte_length)
        return result if result else b''

    def read_int(
            self, byte_length: int, byteorder: Literal["big", "little"] = "little"
    ) -> Optional[int]:
        octets = self.read_bytes(byte_length)
        if not octets:
            return None
        return int.from_bytes(octets, byteorder=byteorder)