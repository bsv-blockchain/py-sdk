from contextlib import suppress
from typing import Optional, Union

from .script.script import Script
from .utils import Reader


class TransactionOutput:

    def __init__(
            self,
            locking_script: Script,
            satoshis: int = None,
            change: bool = False,
    ):
        self.satoshis = satoshis
        self.locking_script = locking_script
        self.change = change

    def serialize(self) -> bytes:
        return b"".join(
            [
                self.satoshis.to_bytes(8, "little"),
                self.locking_script.byte_length_varint(),
                self.locking_script.serialize(),
            ]
        )

    def __str__(self) -> str:  # pragma: no cover
        return (
            f"<TxOutput value={self.satoshis} locking_script={self.locking_script.hex()}>"
        )

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def from_hex(cls, stream: Union[str, bytes, Reader]) -> Optional["TransactionOutput"]:
        """Parse a transaction output from hex string, bytes, or Reader.

        Returns None if data is invalid or incomplete.
        """
        try:
            stream = (
                stream
                if isinstance(stream, Reader)
                else Reader(
                    stream if isinstance(stream, bytes) else bytes.fromhex(stream)
                )
            )
        except ValueError:
            return None

        try:
            satoshis = stream.read_int(8)
            if satoshis is None:
                return None
            script_length = stream.read_var_int_num()
            if script_length is None:
                return None
            locking_script_bytes = stream.read_bytes(script_length)
            # Be lenient: create output even with partial script data
            return TransactionOutput(locking_script=Script(locking_script_bytes), satoshis=satoshis)
        except ValueError:
            return None
