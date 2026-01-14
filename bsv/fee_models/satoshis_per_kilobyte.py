import asyncio
import math
from abc import ABC

from ..fee_model import FeeModel


class SatoshisPerKilobyte(FeeModel):
    """
    Represents the "satoshis per kilobyte" transaction fee model.
    """

    def __init__(self, value: int):
        """
        Constructs an instance of the sat/kb fee model.

        :param value: The number of satoshis per kilobyte to charge as a fee.
        """
        self.value = value

    def compute_fee(self, tx) -> int:
        """
        Computes the fee for a given transaction.

        :param tx: The transaction for which a fee is to be computed.
        :returns: The fee in satoshis for the transaction.
        """

        def get_varint_size(i: int) -> int:
            if i > 2**32:
                return 9
            elif i > 2**16:
                return 5
            elif i > 253:
                return 3
            else:
                return 1

        # Compute the (potentially estimated) size of the transaction
        size = 4  # version
        size += get_varint_size(len(tx.inputs))  # number of inputs

        for tx_input in tx.inputs:
            size += 40  # txid, output index, sequence number
            if tx_input.unlocking_script:
                script_length = len(tx_input.unlocking_script.serialize())
            elif tx_input.unlocking_script_template:
                script_length = tx_input.unlocking_script_template.estimated_unlocking_byte_length()
            else:
                raise ValueError(
                    "All inputs must have an unlocking script or an unlocking script template for sat/kb fee computation."
                )
            size += get_varint_size(script_length)  # unlocking script length
            size += script_length  # unlocking script

        size += get_varint_size(len(tx.outputs))  # number of outputs

        for tx_output in tx.outputs:
            size += 8  # satoshis
            length = len(tx_output.locking_script.serialize())
            size += get_varint_size(length)  # script length
            size += length  # script

        size += 4  # lock time

        # We'll use math.ceil to ensure the miners get the extra satoshi.
        fee = math.ceil((size / 1000) * self.value)
        return fee
