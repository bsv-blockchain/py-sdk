"""
Reader and Writer utilities from main utils.py
"""

from io import BytesIO
from typing import Optional


def unsigned_to_varint(num: int) -> bytes:
    """
    convert an unsigned int to varint.
    """
    if num < 0 or num > 0xffffffffffffffff:
        raise OverflowError(f"can't convert {num} to varint")
    if num <= 0xfc:
        return num.to_bytes(1, 'little')
    elif num <= 0xffff:
        return b'\xfd' + num.to_bytes(2, 'little')
    elif num <= 0xffffffff:
        return b'\xfe' + num.to_bytes(4, 'little')
    else:
        return b'\xff' + num.to_bytes(8, 'little')


class Writer(BytesIO):
    """
    A writer for binary data
    """

    def write_bytes(self, data: bytes) -> None:
        self.write(data)

    def write_uint8(self, num: int) -> None:
        self.write(num.to_bytes(1, 'little'))

    def write_int8(self, num: int) -> None:
        self.write(num.to_bytes(1, 'little', signed=True))

    def write_uint16_le(self, num: int) -> None:
        self.write(num.to_bytes(2, 'little'))

    def write_int16_le(self, num: int) -> None:
        self.write(num.to_bytes(2, 'little', signed=True))

    def write_uint32_le(self, num: int) -> None:
        self.write(num.to_bytes(4, 'little'))

    def write_int32_le(self, num: int) -> None:
        self.write(num.to_bytes(4, 'little', signed=True))

    def write_uint64_le(self, num: int) -> None:
        self.write(num.to_bytes(8, 'little'))

    def write_int64_le(self, num: int) -> None:
        self.write(num.to_bytes(8, 'little', signed=True))

    def write_uint16_be(self, num: int) -> None:
        self.write(num.to_bytes(2, 'big'))

    def write_int16_be(self, num: int) -> None:
        self.write(num.to_bytes(2, 'big', signed=True))

    def write_uint32_be(self, num: int) -> None:
        self.write(num.to_bytes(4, 'big'))

    def write_int32_be(self, num: int) -> None:
        self.write(num.to_bytes(4, 'big', signed=True))

    def write_uint64_be(self, num: int) -> None:
        self.write(num.to_bytes(8, 'big'))

    def write_int64_be(self, num: int) -> None:
        self.write(num.to_bytes(8, 'big', signed=True))

    def write_var_int_num(self, n: int) -> None:
        self.write(unsigned_to_varint(n))

    @staticmethod
    def var_int_num(n: int) -> bytes:
        return unsigned_to_varint(n)


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

    def read_uint32_be(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='big') if data else None

    def read_int32_be(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='big', signed=True) if data else None

    def read_uint64_be(self) -> Optional[int]:
        data = self.read(8)
        return int.from_bytes(data, byteorder='big') if data else None

    def read_int64_be(self) -> Optional[int]:
        data = self.read(8)
        return int.from_bytes(data, byteorder='big', signed=True) if data else None

    def read_uint16_le(self) -> Optional[int]:
        data = self.read(2)
        return int.from_bytes(data, byteorder='little') if data else None

    def read_int16_le(self) -> Optional[int]:
        data = self.read(2)
        return int.from_bytes(data, byteorder='little', signed=True) if data else None

    def read_uint32_le(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='little') if data else None

    def read_int32_le(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='little', signed=True) if data else None

    def read_uint64_le(self) -> Optional[int]:
        data = self.read(8)
        return int.from_bytes(data, byteorder='little') if data else None

    def read_int64_le(self) -> Optional[int]:
        data = self.read(8)
        return int.from_bytes(data, byteorder='little', signed=True) if data else None

    def read_var_int_num(self) -> Optional[int]:
        """read varint"""
        first_byte = self.read_uint8()
        if first_byte is None:
            return None
        
        if first_byte <= 0xfc:
            return first_byte
        elif first_byte == 0xfd:
            return self.read_uint16_le()
        elif first_byte == 0xfe:
            return self.read_uint32_le()
        elif first_byte == 0xff:
            return self.read_uint64_le()
        else:
            return None
