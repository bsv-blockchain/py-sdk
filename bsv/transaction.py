import math
from contextlib import suppress
from typing import List, Optional, Union, Dict, Any

from .broadcaster import Broadcaster, BroadcastResponse
from .broadcasters import default_broadcaster
from .chaintracker import ChainTracker
from .chaintrackers import default_chain_tracker
from .fee_models import LivePolicy
from .constants import (
    SIGHASH,
    TRANSACTION_VERSION,
    TRANSACTION_LOCKTIME,
    TRANSACTION_FEE_RATE,
)
from .hash import hash256
from .merkle_path import MerklePath
from .script.script import Script
from .script.type import P2PKH
from .transaction_input import TransactionInput
from .transaction_output import TransactionOutput
from .transaction_preimage import tx_preimage
from .utils import unsigned_to_varint, Reader, Writer, reverse_hex_byte_order

# Lazy import to avoid circular dependency
def Spend(params):  # NOSONAR - Matches TS SDK naming (class Spend)
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

    def calc_input_signature_hash(self, input_index: int, hash_type: int, script_code: Script, prev_satoshis: int = 0) -> bytes:
        """
        Calculate the signature hash for a specific input using the appropriate algorithm.

        :param input_index: Index of the input to calculate the signature hash for
        :param hash_type: 32-bit unsigned integer specifying the hash type (including ForkID bit)
        :param script_code: The script code to use for hashing
        :param prev_satoshis: The satoshis value of the previous output (for BIP143)
        :returns: The signature hash digest (32 bytes)
        """
        # Ensure hash_type is treated as uint32
        hash_type = hash_type & 0xFFFFFFFF

        # Choose algorithm based on ForkID bit
        if hash_type & int(SIGHASH.FORKID):
            # Use BIP143/ForkID algorithm
            preimage = self._calc_input_preimage_bip143(input_index, hash_type, script_code, prev_satoshis)
            return hash256(preimage)
        else:
            # Use legacy algorithm
            preimage = self._calc_input_preimage_legacy(input_index, hash_type)
            return hash256(preimage)

    def _calc_input_preimage_bip143(self, input_index: int, hash_type: int, script_code: Script, prev_satoshis: int) -> bytes:
        """
        Calculate BIP143/ForkID preimage for signature hashing.
        Uses tx_input.locking_script as the script_code.
        """
        """
        Calculate BIP143/ForkID preimage for signature hashing.
        """
        from io import BytesIO
        from .utils import unsigned_to_varint

        # Get the input
        tx_input = self.inputs[input_index]

        # Calculate hashPrevouts (32-byte hash)
        if hash_type & int(SIGHASH.ANYONECANPAY):
            hash_prevouts = b"\x00" * 32
        else:
            prevouts_data = b""
            for inp in self.inputs:
                prevouts_data += bytes.fromhex(inp.source_txid)[::-1]
                prevouts_data += inp.source_output_index.to_bytes(4, "little")
            hash_prevouts = hash256(prevouts_data)

        # Calculate hashSequence (32-byte hash)
        if hash_type & int(SIGHASH.ANYONECANPAY) or (hash_type & 0x1F) == int(SIGHASH.SINGLE) or (hash_type & 0x1F) == int(SIGHASH.NONE):
            hash_sequence = b"\x00" * 32
        else:
            sequence_data = b""
            for inp in self.inputs:
                sequence_data += inp.sequence.to_bytes(4, "little")
            hash_sequence = hash256(sequence_data)

        # Calculate hashOutputs (32-byte hash)
        if (hash_type & 0x1F) == int(SIGHASH.SINGLE) and input_index < len(self.outputs):
            hash_outputs = hash256(self.outputs[input_index].serialize())
        elif (hash_type & 0x1F) == int(SIGHASH.NONE):
            hash_outputs = b"\x00" * 32
        else:
            outputs_data = b""
            for out in self.outputs:
                outputs_data += out.serialize()
            hash_outputs = hash256(outputs_data)

        # Build the preimage
        stream = BytesIO()
        # 1. nVersion (4-byte little endian)
        stream.write(self.version.to_bytes(4, "little"))
        # 2. hashPrevouts (32 bytes)
        stream.write(hash_prevouts)
        # 3. hashSequence (32 bytes)
        stream.write(hash_sequence)
        # 4. outpoint (32-byte hash + 4-byte little endian)
        stream.write(bytes.fromhex(tx_input.source_txid)[::-1])
        stream.write(tx_input.source_output_index.to_bytes(4, "little"))
        # 5. scriptCode (varint length + bytes)
        script_bytes = tx_input.locking_script.serialize()
        stream.write(unsigned_to_varint(len(script_bytes)))
        stream.write(script_bytes)
        # 6. value of output (8-byte little endian)
        prev_sats = prev_satoshis if prev_satoshis != 0 else (tx_input.satoshis or 0)
        stream.write(prev_sats.to_bytes(8, "little"))
        # 7. nSequence of input (4-byte little endian)
        stream.write(tx_input.sequence.to_bytes(4, "little"))
        # 8. hashOutputs (32 bytes)
        stream.write(hash_outputs)
        # 9. nLocktime (4-byte little endian)
        stream.write(self.locktime.to_bytes(4, "little"))
        # 10. sighash type (4-byte little endian) - full uint32
        stream.write(hash_type.to_bytes(4, "little"))

        return stream.getvalue()

    def _calc_input_preimage_legacy(self, input_index: int, hash_type: int) -> bytes:
        """
        Calculate legacy preimage for signature hashing.
        Implements the original Bitcoin signature hashing algorithm with SIGHASH_SINGLE bug.
        """
        from io import BytesIO

        # Handle SIGHASH_SINGLE out-of-range bug
        if (hash_type & 0x1F) == int(SIGHASH.SINGLE) and input_index >= len(self.outputs):
            # Return the special "1" hash as uint256 little endian
            return b"\x01" + (b"\x00" * 31)

        # Create a copy of the transaction for modification
        tx_copy = Transaction(
            tx_inputs=[inp.__class__(
                source_transaction=inp.source_transaction,
                source_txid=inp.source_txid,
                source_output_index=inp.source_output_index,
                unlocking_script=Script.from_bytes(b""),  # Clear unlocking scripts
                sequence=inp.sequence
            ) for inp in self.inputs],
            version=self.version,
            locktime=self.locktime
        )
        tx_copy.outputs = self.outputs.copy()

        # Set the script for the input we're signing
        tx_copy.inputs[input_index].unlocking_script = self.inputs[input_index].locking_script

        # Apply SIGHASH_NONE
        if hash_type & int(SIGHASH.NONE):
            tx_copy.outputs.clear()
            # Clear sequences for other inputs
            for i, inp in enumerate(tx_copy.inputs):
                if i != input_index:
                    inp.sequence = 0

        # Apply SIGHASH_SINGLE
        elif hash_type & int(SIGHASH.SINGLE):
            tx_copy.outputs = tx_copy.outputs[:input_index + 1]
            # Null out outputs before the input index
            for i in range(input_index):
                tx_copy.outputs[i].satoshis = 0xFFFFFFFFFFFFFFFF  # -1 as underflow
                tx_copy.outputs[i].locking_script = Script.from_bytes(b"")
            # Clear sequences for other inputs
            for i, inp in enumerate(tx_copy.inputs):
                if i != input_index:
                    inp.sequence = 0

        # Apply ANYONECANPAY
        if hash_type & int(SIGHASH.ANYONECANPAY):
            # Only keep the input we're signing
            tx_copy.inputs = [tx_copy.inputs[input_index]]

        # Serialize and append hash type
        stream = BytesIO()
        stream.write(tx_copy.serialize())
        stream.write(hash_type.to_bytes(4, "little"))

        return stream.getvalue()

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
        Computes the transaction fee and adjusts the change outputs accordingly.
        This method can be called synchronously or from async contexts.

        :param model_or_fee: A fee model or a fee amount. If not provided, it defaults to an instance
            of `LivePolicy` that fetches the latest mining fees.
        :param change_distribution: Method of distributing change ('equal' or 'random'). Defaults to 'equal'.
        """
        if model_or_fee is None:
            # Retrieve the default fee model
            model_or_fee = LivePolicy.get_instance(
                fallback_sat_per_kb=int(TRANSACTION_FEE_RATE)
            )

        # If the fee is provided as a fixed value (synchronous)
        if isinstance(model_or_fee, int):
            self._apply_fee_amount(model_or_fee, change_distribution)
            return model_or_fee

        # Compute the fee using the fee model
        fee_estimate = model_or_fee.compute_fee(self)
        
        # Apply the fee directly
        self._apply_fee_amount(fee_estimate, change_distribution)
        return fee_estimate

    def _apply_fee_amount(self, fee: int, change_distribution: str):
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
        return None

    async def broadcast(
            self,
            broadcaster: Broadcaster = default_broadcaster(),
            check_fee: bool = True
    ) -> BroadcastResponse:  # pragma: no cover
        return await broadcaster.broadcast(self)

    @classmethod
    def from_hex(cls, stream: Union[str, bytes, Reader]) -> Optional["Transaction"]:
        """Parse a transaction from hex string, bytes, or Reader.
        
        Returns None only for invalid hex format, raises exception for parse errors.
        """
        try:
            if isinstance(stream, str):
                return cls.from_reader(Reader(bytes.fromhex(stream)))
            elif isinstance(stream, bytes):
                return cls.from_reader(Reader(stream))
            return cls.from_reader(stream)
        except ValueError:
            # Invalid hex string
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
        """Parse a transaction from a Reader.
        
        Raises ValueError if data is invalid or incomplete.
        """
        t = cls()
        t.version = reader.read_uint32_le()
        if t.version is None:
            raise ValueError("Incomplete data: cannot read transaction version")
        
        inputs_count = reader.read_var_int_num()
        if inputs_count is None:
            raise ValueError("Incomplete data: cannot read inputs count")
        
        for i in range(inputs_count):
            _input = TransactionInput.from_hex(reader)
            if _input is None:
                raise ValueError(f"Failed to parse input {i}")
            t.inputs.append(_input)
        
        outputs_count = reader.read_var_int_num()
        if outputs_count is None:
            raise ValueError("Incomplete data: cannot read outputs count")
        
        for i in range(outputs_count):
            _output = TransactionOutput.from_hex(reader)
            if _output is None:
                raise ValueError(f"Failed to parse output {i}")
            t.outputs.append(_output)
        
        t.locktime = reader.read_uint32_le()
        if t.locktime is None:
            raise ValueError("Incomplete data: cannot read locktime")
        
        return t

    async def verify(self, chaintracker: Optional[ChainTracker] = default_chain_tracker(), scripts_only=False) -> bool:
        if self.merkle_path and not scripts_only:
            proof_valid = await self.merkle_path.verify(self.txid(), chaintracker)
            if proof_valid:
                return True

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

            input_verified = await tx_input.source_transaction.verify(chaintracker, scripts_only=scripts_only)
            if not input_verified:
                return False

            # Use Engine-based script interpreter (matches Go SDK implementation)
            from bsv.script.interpreter import Engine, with_tx, with_after_genesis, with_fork_id
            
            engine = Engine()
            err = engine.execute(
                with_tx(self, i, source_output),
                with_after_genesis(),
                with_fork_id()
            )
            
            if err is not None:
                # Script verification failed
                return False

        # All inputs verified successfully
        # Note: Fee validation would be done separately if needed
        return True

    def signature_hash(self, index: int) -> bytes:
        """
        Calculate the signature hash for the input at the specified index.
        This is the hash that gets signed for transaction signing.
        """
        preimage = self.preimage(index)
        return hash256(preimage)

    def to_json(self) -> str:
        """
        Convert the transaction to a JSON string representation.
        """
        import json

        tx_dict = {
            "txid": self.txid(),
            "version": self.version,
            "lockTime": self.locktime,
            "hex": self.hex(),
            "inputs": [
                {
                    "txid": inp.source_txid if hasattr(inp, 'source_txid') and inp.source_txid else "",
                    "vout": inp.source_output_index if hasattr(inp, 'source_output_index') else 0,
                    "sequence": inp.sequence,
                    "unlockingScript": inp.unlocking_script.hex() if inp.unlocking_script else "",
                    "satoshis": inp.satoshis if hasattr(inp, 'satoshis') else 0,
                }
                for inp in self.inputs
            ],
            "outputs": [
                {
                    "satoshis": out.satoshis,
                    "lockingScript": out.locking_script.hex(),
                }
                for out in self.outputs
            ]
        }

        return json.dumps(tx_dict, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "Transaction":
        """
        Create a Transaction from a JSON string representation.
        """
        import json

        tx_dict = json.loads(json_str)

        # If hex is provided, use it directly
        if "hex" in tx_dict:
            return cls.from_hex(tx_dict["hex"])

        # Otherwise, construct from components
        # Create inputs
        inputs = []
        for inp_dict in tx_dict.get("inputs", []):
            inp = TransactionInput(
                source_txid=inp_dict.get("txid", ""),
                source_output_index=inp_dict.get("vout", 0),
                sequence=inp_dict.get("sequence", 0xFFFFFFFF),
            )
            if "satoshis" in inp_dict:
                inp.satoshis = inp_dict["satoshis"]
            if "unlockingScript" in inp_dict and inp_dict["unlockingScript"]:
                from .script.script import Script
                inp.unlocking_script = Script(bytes.fromhex(inp_dict["unlockingScript"]))
            inputs.append(inp)

        # Create outputs
        outputs = []
        for out_dict in tx_dict.get("vout", tx_dict.get("outputs", [])):
            from .script.script import Script
            out = TransactionOutput(
                satoshis=out_dict["satoshis"],
                locking_script=Script(bytes.fromhex(out_dict.get("lockingScript", out_dict.get("scriptPubKey", ""))))
            )
            outputs.append(out)

        return cls(
            tx_inputs=inputs,
            tx_outputs=outputs,
            version=tx_dict.get("version", 1),
            locktime=tx_dict.get("lockTime", tx_dict.get("locktime", 0)),
        )

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
