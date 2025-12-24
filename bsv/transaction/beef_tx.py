"""
BeefTx implementation for representing transactions in BEEF format.

Translated from ts-sdk/src/transaction/BeefTx.ts
"""
from typing import Optional, List, Union
from bsv.transaction import Transaction
from bsv.utils import Writer, Reader
from bsv.hash import hash256


class TX_DATA_FORMAT:  # NOSONAR - Matches TS SDK naming
    """Transaction data format constants."""
    RAWTX = 0
    RAWTX_AND_BUMP_INDEX = 1


class BeefTx:
    """
    A single bitcoin transaction associated with a BEEF validity proof set.
    
    Supports transactions as raw bytes, parsed Transaction objects, or just txids.
    """

    def __init__(
        self,
        tx: Union[Transaction, bytes, str],
        bump_index: Optional[int] = None
    ):
        """
        Initialize BeefTx.
        
        Args:
            tx: Transaction as Transaction object, raw bytes, or txid string
            bump_index: Optional bump index if transaction has proof
        """
        self._bump_index: Optional[int] = None
        self._tx: Optional[Transaction] = None
        self._raw_tx: Optional[bytes] = None
        self._txid: Optional[str] = None
        self.input_txids: List[str] = []
        self.is_valid: Optional[bool] = None

        if isinstance(tx, str):
            self._txid = tx
        elif isinstance(tx, bytes):
            self._raw_tx = tx
        elif isinstance(tx, Transaction):
            self._tx = tx
        else:
            raise TypeError(f"Unsupported tx type: {type(tx)}")

        self.bump_index = bump_index
        self._update_input_txids()

    @property
    def bump_index(self) -> Optional[int]:
        """Get bump index."""
        return self._bump_index

    @bump_index.setter
    def bump_index(self, value: Optional[int]) -> None:
        """Set bump index and update input txids."""
        self._bump_index = value
        self._update_input_txids()

    @property
    def has_proof(self) -> bool:
        """Check if transaction has proof."""
        return self._bump_index is not None

    @property
    def is_txid_only(self) -> bool:
        """Check if this is txid-only representation."""
        return (
            self._txid is not None and
            self._txid != '' and
            self._raw_tx is None and
            self._tx is None
        )

    @property
    def txid(self) -> str:
        """Get transaction ID."""
        if self._txid and self._txid != '':
            return self._txid
        if self._tx:
            self._txid = self._tx.txid()
            return self._txid
        if self._raw_tx:
            self._txid = hash256(self._raw_tx).hex()
            return self._txid
        raise ValueError('Cannot determine txid')

    @property
    def tx(self) -> Optional[Transaction]:
        """Get parsed Transaction object."""
        if self._tx:
            return self._tx
        if self._raw_tx:
            from bsv.utils import Reader
            self._tx = Transaction.from_reader(Reader(self._raw_tx))
            return self._tx
        return None

    @property
    def raw_tx(self) -> Optional[bytes]:
        """Get raw transaction bytes."""
        if self._raw_tx:
            return self._raw_tx
        if self._tx:
            self._raw_tx = self._tx.serialize()
            return self._raw_tx
        return None

    @staticmethod
    def from_tx(tx: Transaction, bump_index: Optional[int] = None) -> 'BeefTx':
        """Create BeefTx from Transaction object."""
        return BeefTx(tx, bump_index)

    @staticmethod
    def from_raw_tx(raw_tx: bytes, bump_index: Optional[int] = None) -> 'BeefTx':
        """Create BeefTx from raw transaction bytes."""
        return BeefTx(raw_tx, bump_index)

    @staticmethod
    def from_txid(txid: str, bump_index: Optional[int] = None) -> 'BeefTx':
        """Create BeefTx from txid string."""
        return BeefTx(txid, bump_index)

    def _update_input_txids(self) -> None:
        """Update list of input transaction IDs."""
        if self.has_proof or self.tx is None:
            self.input_txids = []
        else:
            input_txids_set = set()
            for tx_input in self.tx.inputs:
                if hasattr(tx_input, 'source_txid') and tx_input.source_txid:
                    input_txids_set.add(tx_input.source_txid)
            self.input_txids = list(input_txids_set)

    def to_writer(self, writer: Writer, version: int) -> None:
        """
        Write BeefTx to writer.
        
        Args:
            writer: Writer to write to
            version: BEEF version
        """
        def write_txid() -> None:
            if self._txid is None:
                raise ValueError('Transaction ID (_txid) is undefined')
            txid_bytes = bytes.fromhex(self._txid)
            writer.write(txid_bytes[::-1])  # Reverse byte order

        def write_tx() -> None:
            if self._raw_tx:
                writer.write(self._raw_tx)
            elif self._tx:
                writer.write(self._tx.serialize())
            else:
                raise ValueError('a valid serialized Transaction is expected')

        def write_bump_index() -> None:
            if self.bump_index is None:
                writer.write_uint8(TX_DATA_FORMAT.RAWTX)
            else:
                writer.write_uint8(TX_DATA_FORMAT.RAWTX_AND_BUMP_INDEX)
                writer.write_var_int_num(self.bump_index)

        if self.is_txid_only:
            write_txid()
        else:
            write_bump_index()
            write_tx()

