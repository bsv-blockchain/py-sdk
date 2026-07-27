import re
from contextlib import suppress
from io import BytesIO
from typing import Optional, Union

from .constants import (
    SIGHASH,
    TRANSACTION_SEQUENCE,
)
from .script.script import Script
from .script.unlocking_template import UnlockingScriptTemplate
from .utils import Reader

_TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def txid_to_bytes_le(txid: str) -> bytes:
    if not isinstance(txid, str) or not _TXID_RE.match(txid):
        raise ValueError(
            f"source_txid must be exactly 64 hex characters, got {txid!r}"
        )
    return bytes.fromhex(txid)[::-1]


class TransactionInput:
    def __init__(
        self,
        source_transaction=None,
        source_txid: Optional[str] = None,
        source_output_index: int = 0,
        unlocking_script: Optional[Script] = None,
        unlocking_script_template: UnlockingScriptTemplate = None,
        sequence: int = TRANSACTION_SEQUENCE,
        sighash: SIGHASH = SIGHASH.ALL_FORKID,
    ):
        utxo = None
        if source_transaction:
            utxo = source_transaction.outputs[source_output_index]

        self.source_txid = source_txid
        if source_transaction and not source_txid:
            self.source_txid = source_transaction.txid()

        self.source_output_index: int = source_output_index
        self.satoshis: int = utxo.satoshis if utxo else None
        self.locking_script: Script = utxo.locking_script if utxo else None
        self.source_transaction = source_transaction
        self.unlocking_script: Script = unlocking_script
        self.unlocking_script_template = unlocking_script_template
        self.sequence: int = sequence
        self.sighash: SIGHASH = sighash

    def serialize(self) -> bytes:
        stream = BytesIO()
        stream.write(txid_to_bytes_le(self.source_txid))
        stream.write(self.source_output_index.to_bytes(4, "little"))
        stream.write(self.unlocking_script.byte_length_varint() if self.unlocking_script else b"\x00")
        stream.write(self.unlocking_script.serialize() if self.unlocking_script else b"")
        stream.write(self.sequence.to_bytes(4, "little"))
        return stream.getvalue()

    def __str__(self) -> str:  # pragma: no cover
        return (
            f"<TransactionInput outpoint={self.source_txid}:{self.source_output_index} "
            f"value={self.satoshis} locking_script={self.locking_script}>"
        )

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def from_hex(cls, stream: str | bytes | Reader) -> Optional["TransactionInput"]:
        """Parse a transaction input from hex string, bytes, or Reader.

        Returns None if data is invalid or incomplete.
        """
        try:
            if isinstance(stream, Reader):
                reader = stream
            else:
                data = stream if isinstance(stream, bytes) else bytes.fromhex(stream)
                reader = Reader(data)
            stream = reader
        except ValueError:
            return None

        try:
            txid = stream.read_bytes(32)
            if len(txid) != 32:
                return None
            txid = txid[::-1]  # Reverse for display

            vout = stream.read_int(4)
            if vout is None:
                return None

            script_length = stream.read_var_int_num()
            if script_length is None:
                return None

            unlocking_script_bytes = stream.read_bytes(script_length)
            if len(unlocking_script_bytes) < script_length:
                return None

            sequence = stream.read_int(4)
            if sequence is None:
                return None

            return TransactionInput(
                source_txid=txid.hex(),
                source_output_index=vout,
                unlocking_script=Script(unlocking_script_bytes),
                sequence=sequence,
            )
        except ValueError:
            return None
