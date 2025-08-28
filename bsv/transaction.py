import math
from contextlib import suppress
from typing import List, Optional, Union, Dict, Any

from .broadcaster import Broadcaster, BroadcastResponse
from .broadcasters import default_broadcaster
from .chaintracker import ChainTracker
from .chaintrackers import default_chain_tracker
from .fee_models import SatoshisPerKilobyte
from .constants import (
    TRANSACTION_VERSION,
    TRANSACTION_LOCKTIME,
    TRANSACTION_FEE_RATE,
)
from .hash import hash256
from .merkle_path import MerklePath
from .script.type import P2PKH
from .transaction_input import TransactionInput
from .transaction_output import TransactionOutput
from .transaction_preimage import tx_preimage
from .utils import unsigned_to_varint, Reader, Writer, reverse_hex_byte_order

# Lazy import to avoid circular dependency
def Spend(params):
    from .script.spend import Spend as SpendClass
    return SpendClass(params)


class InsufficientFunds(ValueError):
    pass


class Transaction:

    def __init__(
            self,
            tx_inputs: Optional[List[TransactionInput]] = None,
            tx_outputs: Optional[List[TransactionOutput]] = None,
            version: int = TRANSACTION_VERSION,
            locktime: int = TRANSACTION_LOCKTIME,
            merkle_path: Optional[MerklePath] = None,
            **kwargs,
    ):
        self.inputs: List[TransactionInput] = tx_inputs or []
        self.outputs: List[TransactionOutput] = tx_outputs or []
        self.version: int = version
        self.locktime: int = locktime
        self.merkle_path = merkle_path

        self.kwargs: Dict[str, Any] = dict(**kwargs) or {}

    def serialize(self) -> bytes:
        raw = self.version.to_bytes(4, "little")
        raw += unsigned_to_varint(len(self.inputs))
        for tx_input in self.inputs:
            raw += tx_input.serialize()
        raw += unsigned_to_varint(len(self.outputs))
        for tx_output in self.outputs:
            raw += tx_output.serialize()
        raw += self.locktime.to_bytes(4, "little")
        return raw

    def add_input(
            self, tx_input: TransactionInput
    ) -> "Transaction":  # pragma: no cover
        if isinstance(tx_input, TransactionInput):
            self.inputs.append(tx_input)
        else:
            raise TypeError("unsupported transaction input type")
        return self

    def add_inputs(self, tx_inputs: List[TransactionInput]) -> "Transaction":
        for tx_input in tx_inputs:
            self.add_input(tx_input)
        return self

    def add_output(self, tx_output: TransactionOutput) -> "Transaction":  # pragma: no cover
        self.outputs.append(tx_output)
        return self

    def add_outputs(self, tx_outputs: List[TransactionOutput]) -> "Transaction":
        for tx_output in tx_outputs:
            self.add_output(tx_output)
        return self

    def hex(self) -> str:  # pragma: no cover
        return self.serialize().hex()

    raw = hex

    def hash(self) -> bytes:
        return hash256(self.serialize())

    def txid(self) -> str:
        return self.hash()[::-1].hex()

    def preimage(self, index: int) -> bytes:
        """
        :returns: digest of the input specified by index
        """
        assert (
                0 <= index < len(self.inputs)
        ), f"index out of range [0, {len(self.inputs)})"
        return tx_preimage(index, self.inputs, self.outputs, self.version, self.locktime)

    def sign(self, bypass: bool = True) -> "Transaction":  # pragma: no cover
        """
        :bypass: if True then ONLY sign inputs which unlocking script is None, otherwise sign all the inputs
        sign all inputs according to their script type
        """
        for out in self.outputs:
            if out.satoshis is None:
                if out.change:
                    raise ValueError('There are still change outputs with uncomputed amounts. Use the fee() method to compute the change amounts and transaction fees prior to signing.')
                else:
                    raise ValueError('One or more transaction outputs is missing an amount. Ensure all output amounts are provided before signing.')

        for i in range(len(self.inputs)):
            tx_input = self.inputs[i]
            if tx_input.unlocking_script is None or not bypass:
                tx_input.unlocking_script = tx_input.unlocking_script_template.sign(
                    self, i
                )
        return self

    def total_value_in(self) -> int:
        return sum([tx_input.satoshis for tx_input in self.inputs])

    def total_value_out(self) -> int:
        return sum([tx_output.satoshis for tx_output in self.outputs])

    def get_fee(self) -> int:
        """
        :returns: actual fee paid of this transaction under the current state
        """
        return self.total_value_in() - self.total_value_out()

    def byte_length(self) -> int:
        """
        :returns: actual byte length of this transaction under the current state
        """
        return len(self.serialize())

    size = byte_length

    def estimated_byte_length(self) -> int:
        """
        :returns: estimated byte length of this transaction after signing
        if transaction has already signed, it will return the same value as function byte_length
        """
        estimated_length = (
                4
                + len(unsigned_to_varint(len(self.inputs)))
                + len(unsigned_to_varint(len(self.outputs)))
                + 4
        )
        for tx_input in self.inputs:
            if tx_input.unlocking_script is not None:
                # unlocking script already set
                estimated_length += len(tx_input.serialize())
            else:
                estimated_length += (
                        41
                        + tx_input.unlocking_script_template.estimated_unlocking_byte_length()
                )
        for tx_output in self.outputs:
            estimated_length += (
                    8
                    + len(tx_output.locking_script.byte_length_varint())
                    + tx_output.locking_script.byte_length()
            )
        return estimated_length

    estimated_size = estimated_byte_length

    def fee(self, model_or_fee=None, change_distribution='equal'):
        """
        Computes the fee for the transaction and adjusts the change outputs accordingly.
        
        :param model_or_fee: Fee model or fee amount. Defaults to `SatoshisPerKilobyte` with value 10 if not provided.
        :param change_distribution: Method of change distribution ('equal' or 'random'). Defaults to 'equal'.
        """
        
        if model_or_fee is None:
            model_or_fee = SatoshisPerKilobyte(int(TRANSACTION_FEE_RATE))

        if isinstance(model_or_fee, int):
            fee = model_or_fee
        else:
            fee = model_or_fee.compute_fee(self)

        change = 0
        for tx_in in self.inputs:
            if not tx_in.source_transaction:
                raise ValueError('Source transactions are required for all inputs during fee computation')
            change += tx_in.source_transaction.outputs[tx_in.source_output_index].satoshis
        
        change -= fee
        
        change_count = 0
        for out in self.outputs:
            if not out.change:
                change -= out.satoshis
            else:
                change_count += 1
        
        if change <= change_count:
            # Not enough change to distribute among the change outputs.
            # Remove all change outputs and leave the extra for the miners.
            self.outputs = [out for out in self.outputs if not out.change]
            return
        
        # Distribute change among change outputs
        if change_distribution == 'random':
            # TODO: Implement random distribution
            raise NotImplementedError('Random change distribution is not yet implemented')
        elif change_distribution == 'equal':
            per_output = change // change_count
            for out in self.outputs:
                if out.change:
                    out.satoshis = per_output

    async def broadcast(
            self,
            broadcaster: Broadcaster = default_broadcaster(),
            check_fee: bool = True
    ) -> BroadcastResponse:  # pragma: no cover
        return await broadcaster.broadcast(self)

    @classmethod
    def from_hex(cls, stream: Union[str, bytes, Reader]) -> Optional["Transaction"]:
        with suppress(Exception):
            if isinstance(stream, str):
                return cls.from_reader(Reader(bytes.fromhex(stream)))
            elif isinstance(stream, bytes):
                return cls.from_reader(Reader(stream))
            return cls.from_reader(stream)
        return None

    @classmethod
    def from_beef(cls, stream: Union[str, bytes, Reader]) -> "Transaction":
        stream = (
            stream
            if isinstance(stream, Reader)
            else Reader(
                stream if isinstance(stream, bytes) else bytes.fromhex(stream)
            )
        )
        version = stream.read_uint32_le()
        if version != 4022206465:
            raise ValueError(
                f"Invalid BEEF version. Expected 4022206465, received {version}."
            )

        number_of_bumps = stream.read_var_int_num()
        bumps = []
        for _ in range(number_of_bumps):
            bumps.append(MerklePath.from_reader(stream))

        number_of_transactions = stream.read_var_int_num()
        transactions = {}
        last_txid = None
        for i in range(number_of_transactions):
            tx = cls.from_reader(stream)
            obj = {"tx": tx}
            txid = tx.txid()
            if i + 1 == number_of_transactions:
                last_txid = txid
            has_bump = bool(stream.read_uint8())
            if has_bump:
                obj["pathIndex"] = stream.read_var_int_num()
            transactions[txid] = obj

        def add_path_or_inputs(item):
            if "pathIndex" in item:
                path = bumps[item["pathIndex"]]
                if not isinstance(path, MerklePath):
                    raise ValueError("Invalid merkle path index found in BEEF!")
                item["tx"].merkle_path = path
            else:
                for tx_input in item["tx"].inputs:
                    source_obj = transactions[tx_input.source_txid]
                    if not isinstance(source_obj, dict):
                        raise ValueError(
                            f"Reference to unknown TXID in BUMP: {tx_input.source_txid}"
                        )
                    tx_input.source_transaction = source_obj["tx"]
                    add_path_or_inputs(source_obj)

        add_path_or_inputs(transactions[last_txid])
        return transactions[last_txid]["tx"]

    def to_ef(self) -> bytes:
        writer = Writer()
        writer.write_uint32_le(self.version)
        writer.write(bytes.fromhex('0000000000ef'))
        writer.write_var_int_num(len(self.inputs))

        for i in self.inputs:
            if i.source_transaction is None:
                raise ValueError('All inputs must have source transactions when serializing to EF format')
            if i.source_txid and i.source_txid != '00' * 32:
                writer.write(bytes.fromhex(reverse_hex_byte_order(i.source_txid)))
            else:
                writer.write(i.source_transaction.hash())
            writer.write_uint32_le(i.source_output_index)
            script_bin = i.unlocking_script.serialize()
            writer.write_var_int_num(len(script_bin))
            writer.write(script_bin)
            writer.write_uint32_le(i.sequence)
            writer.write_uint64_le(i.source_transaction.outputs[i.source_output_index].satoshis)
            locking_script_bin = i.source_transaction.outputs[i.source_output_index].locking_script.serialize()
            writer.write_var_int_num(len(locking_script_bin))
            writer.write(locking_script_bin)

        writer.write_var_int_num(len(self.outputs))
        for o in self.outputs:
            writer.write_uint64_le(o.satoshis)
            script_bin = o.locking_script.serialize()
            writer.write_var_int_num(len(script_bin))
            writer.write(script_bin)

        writer.write_uint32_le(self.locktime)
        return writer.to_bytes()

    def to_beef(self) -> bytes:
        writer = Writer()
        writer.write_uint32_le(4022206465)
        bumps = []
        txs = []

        def add_paths_and_inputs(tx):
            obj = {'tx': tx}
            has_proof = isinstance(tx.merkle_path, MerklePath)
            if has_proof:
                added = False
                for i, bump in enumerate(bumps):
                    if bump == tx.merkle_path:
                        obj['path_index'] = i
                        added = True
                        break
                    if bump.block_height == tx.merkle_path.block_height:
                        root_a = bump.compute_root()
                        root_b = tx.merkle_path.compute_root()
                        if root_a == root_b:
                            bump.combine(tx.merkle_path)
                            obj['path_index'] = i
                            added = True
                            break
                if not added:
                    obj['path_index'] = len(bumps)
                    bumps.append(tx.merkle_path)
            txs.insert(0, obj)
            if not has_proof:
                for tx_input in tx.inputs:
                    if not isinstance(tx_input.source_transaction, Transaction):
                        raise ValueError('A required source transaction is missing!')
                    add_paths_and_inputs(tx_input.source_transaction)

        add_paths_and_inputs(self)

        writer.write_var_int_num(len(bumps))
        for b in bumps:
            writer.write(b.to_binary())
        writer.write_var_int_num(len(txs))
        for t in txs:
            writer.write(t['tx'].serialize())
            if 'path_index' in t:
                writer.write_uint8(1)
                writer.write_var_int_num(t['path_index'])
            else:
                writer.write_uint8(0)
        return writer.to_bytes()

    @classmethod
    def from_reader(cls, reader: Reader) -> 'Transaction':
        t = cls()
        t.version = reader.read_uint32_le()
        assert t.version is not None
        inputs_count = reader.read_var_int_num()
        assert inputs_count is not None
        for _ in range(inputs_count):
            _input = TransactionInput.from_hex(reader)
            assert _input is not None
            t.inputs.append(_input)
        outputs_count = reader.read_var_int_num()
        assert outputs_count is not None
        for _ in range(outputs_count):
            _output = TransactionOutput.from_hex(reader)
            assert _output is not None
            t.outputs.append(_output)
        t.locktime = reader.read_uint32_le()
        assert t.locktime is not None
        return t

    async def verify(self, chaintracker: Optional[ChainTracker] = default_chain_tracker(), scripts_only=False) -> bool:
        if self.merkle_path and not scripts_only:
            proof_valid = await self.merkle_path.verify(self.txid(), chaintracker)
            if proof_valid:
                return True

        input_total = 0
        for i, tx_input in enumerate(self.inputs):
            if not tx_input.source_transaction:
                raise ValueError(
                    f"Verification failed because the input at index {i} of transaction {self.txid()} "
                    f"is missing an associated source transaction. "
                    f"This source transaction is required for transaction verification because there is no "
                    f"merkle proof for the transaction spending a UTXO it contains.")
            if not tx_input.unlocking_script:
                raise ValueError(
                    f"Verification failed because the input at index {i} of transaction {self.txid()} "
                    f"is missing an associated unlocking script. "
                    f"This script is required for transaction verification because there is no "
                    f"merkle proof for the transaction spending the UTXO.")

            source_output = tx_input.source_transaction.outputs[tx_input.source_output_index]
            input_total += source_output.satoshis

            input_verified = await tx_input.source_transaction.verify(chaintracker)
            if not input_verified:
                return False

            other_inputs = self.inputs[:i] + self.inputs[i + 1:]
            spend = Spend({
                'sourceTXID': tx_input.source_transaction.txid(),
                'sourceOutputIndex': tx_input.source_output_index,
                'sourceSatoshis': source_output.satoshis,
                'lockingScript': source_output.locking_script,
                'transactionVersion': self.version,
                'otherInputs': other_inputs,
                'inputIndex': i,
                'unlockingScript': tx_input.unlocking_script,
                'outputs': self.outputs,
                'inputSequence': tx_input.sequence,
                'lockTime': self.locktime,
            })
            spend_valid = spend.validate()
            if not spend_valid:
                return False

        output_total = 0
        for out in self.outputs:
            if not out.satoshis:
                raise ValueError("Every output must have a defined amount during transaction verification.")
            output_total += out.satoshis

        return output_total <= input_total

    @classmethod
    def parse_script_offsets(cls, octets: Union[bytes, str]) -> Dict[str, List[Dict[str, int]]]:
        """
        Since the validation of blockchain data is atomically transaction data validation,
        any application seeking to validate data in output scripts must store the entire transaction as well.
        Since the transaction data includes the output script data, saving a second copy of potentially
        large scripts can bloat application storage requirements.

        This function efficiently parses binary transaction data to determine the offsets and lengths of each script.
        This supports the efficient retrieval of script data from transaction data.

        @param octets: binary transaction data or hex string
        @returns: {
            inputs: { vin: number, offset: number, length: number }[]
            outputs: { vout: number, offset: number, length: number }[]
        }
        """
        if isinstance(octets, str):
            octets = bytes.fromhex(octets)

        br = Reader(octets)
        inputs: List[Dict[str, int]] = []
        outputs: List[Dict[str, int]] = []

        br.read(4)  # skip version
        inputs_length = br.read_var_int_num()
        for i in range(inputs_length):
            br.read(36)  # skip txid and vout
            script_length = br.read_var_int_num()
            inputs.append({'vin': i, 'offset': br.tell(), 'length': script_length})
            br.read(script_length + 4)  # script and sequence

        outputs_length = br.read_var_int_num()
        for i in range(outputs_length):
            br.read(8)
            script_length = br.read_var_int_num()
            outputs.append({'vout': i, 'offset': br.tell(), 'length': script_length})
            br.read(script_length)  # skip script

        return {'inputs': inputs, 'outputs': outputs}
