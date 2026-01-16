from abc import ABCMeta, abstractmethod
from typing import List, Optional, Union

from ..constants import PUBLIC_KEY_BYTE_LENGTH_LIST, PUBLIC_KEY_HASH_BYTE_LENGTH, SIGHASH, OpCode
from ..hash import hash256
from ..keys import PrivateKey
from ..utils import address_to_public_key_hash, encode_int, encode_pushdata
from .script import Script
from .unlocking_template import UnlockingScriptTemplate


def to_unlock_script_template(sign, estimated_unlocking_byte_length):
    class_attrs = {"sign": sign, "estimated_unlocking_byte_length": estimated_unlocking_byte_length}

    dynamic_class = type("UnlockScriptTemplateImpl", (UnlockingScriptTemplate,), class_attrs)

    return dynamic_class


class ScriptTemplate(metaclass=ABCMeta):
    @abstractmethod
    def lock(self, **kwargs) -> Script:
        """
        :returns: locking script
        """
        raise NotImplementedError("ScriptTemplate.locking")

    @abstractmethod
    def unlock(self, **kwargs) -> UnlockingScriptTemplate:
        """
        :returns: sign (function), estimated_unlocking_byte_length (function)
        """
        raise NotImplementedError("ScriptTemplate.unlocking")


class Unknown(ScriptTemplate):  # pragma: no cover
    def __str__(self) -> str:
        return "<ScriptTemplate:Unknown>"

    def __repr__(self) -> str:
        return self.__str__()

    def lock(self, **kwargs) -> Script:
        raise ValueError("don't know how to lock for script of unknown type")

    def unlock(self, **kwargs):
        raise ValueError("don't know how to unlock for script of unknown type")


class P2PKH(ScriptTemplate):
    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:P2PKH>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def lock(self, addr: Union[str, bytes]) -> Script:
        """
        from address (str) or public key hash160 (bytes)
        """
        if isinstance(addr, str):
            pkh: bytes = address_to_public_key_hash(addr)
        elif isinstance(addr, bytes):
            pkh: bytes = addr
        else:
            raise TypeError("unsupported type to parse P2PKH locking script")

        assert len(pkh) == PUBLIC_KEY_HASH_BYTE_LENGTH, "invalid byte length of public key hash"

        return Script(
            OpCode.OP_DUP + OpCode.OP_HASH160 + encode_pushdata(pkh) + OpCode.OP_EQUALVERIFY + OpCode.OP_CHECKSIG
        )

    def unlock(self, private_key: PrivateKey):
        def sign(tx, input_index) -> Script:
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash

            signature = private_key.sign(tx.preimage(input_index))

            public_key: bytes = private_key.public_key().serialize()
            return Script(encode_pushdata(signature + sighash.to_bytes(1, "little")) + encode_pushdata(public_key))

        def estimated_unlocking_byte_length() -> int:
            return 107 if private_key.compressed else 139

        return to_unlock_script_template(sign, estimated_unlocking_byte_length)


class OpReturn(ScriptTemplate):
    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:OP_RETURN>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def lock(self, pushdatas: list[Union[str, bytes]]) -> Script:
        script: bytes = OpCode.OP_FALSE + OpCode.OP_RETURN
        for pushdata in pushdatas:
            if isinstance(pushdata, str):
                pushdata_bytes: bytes = pushdata.encode("utf-8")
            elif isinstance(pushdata, bytes):
                pushdata_bytes: bytes = pushdata
            else:
                raise TypeError("unsupported type to parse OP_RETURN locking script")
            script += encode_pushdata(pushdata_bytes, minimal_push=False)
        return Script(script)

    def unlock(self, **kwargs):  # pragma: no cover
        raise ValueError("OP_RETURN cannot be unlocked")


class P2PK(ScriptTemplate):
    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:P2PK>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def lock(self, public_key: Union[str, bytes]) -> Script:
        """
        from public key in format str or bytes
        """
        if isinstance(public_key, str):
            pk: bytes = bytes.fromhex(public_key)
        elif isinstance(public_key, bytes):
            pk: bytes = public_key
        else:
            raise TypeError("unsupported type to parse P2PK locking script")

        assert len(pk) in PUBLIC_KEY_BYTE_LENGTH_LIST, "invalid byte length of public key"

        return Script(encode_pushdata(pk) + OpCode.OP_CHECKSIG)

    def unlock(self, private_key: PrivateKey):
        def sign(tx, input_index) -> Script:
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash

            signature = private_key.sign(tx.preimage(input_index))
            return Script(encode_pushdata(signature + sighash.to_bytes(1, "little")))

        def estimated_unlocking_byte_length() -> int:
            return 73

        return to_unlock_script_template(sign, estimated_unlocking_byte_length)


class BareMultisig(ScriptTemplate):
    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:BareMultisig>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def lock(self, participants: list[Union[str, bytes]], threshold: int) -> Script:
        assert 1 <= threshold <= len(participants), "bad threshold or number of participants"

        participants_parsed = []
        for participant in participants:
            assert type(participant).__name__ in [
                "str",
                "bytes",
            ], "unsupported public key type"
            if isinstance(participant, str):
                participant = bytes.fromhex(participant)
            assert len(participant) in PUBLIC_KEY_BYTE_LENGTH_LIST, "invalid byte length of public key"
            participants_parsed.append(participant)
        script: bytes = encode_int(threshold)
        for participant in participants_parsed:
            script += encode_pushdata(participant)
        return Script(script + encode_int(len(participants)) + OpCode.OP_CHECKMULTISIG)

    def unlock(self, private_keys: list[PrivateKey]):
        def sign(tx, input_index) -> Script:
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash

            script: bytes = OpCode.OP_0  # Append 0 to satisfy SCRIPT_VERIFY_NULLDUMMY
            for private_key in private_keys:
                signature = private_key.sign(tx.preimage(input_index))
                script += encode_pushdata(signature + sighash.to_bytes(1, "little"))
            return Script(script)

        def estimated_unlocking_byte_length() -> int:
            return 1 + 73 * len(private_keys) + 1

        return to_unlock_script_template(sign, estimated_unlocking_byte_length)


class RPuzzle(ScriptTemplate):
    def __init__(self, puzzle_type: str = "raw"):
        """
        Constructs an R Puzzle template instance for a given puzzle type.

        :param puzzle_type: Denotes the type of puzzle to create ('raw', 'SHA1', 'SHA256', 'HASH256', 'RIPEMD160', 'HASH160')
        """
        assert puzzle_type in ["raw", "SHA1", "SHA256", "HASH256", "RIPEMD160", "HASH160"]
        self.type = puzzle_type

    def lock(self, value: bytes) -> Script:
        """
        Creates an R puzzle locking script for a given R value or R value hash.

        :param value: A byte array representing the R value or its hash.
        :returns: An R puzzle locking script.
        """
        chunks = [
            OpCode.OP_OVER,
            OpCode.OP_3,
            OpCode.OP_SPLIT,
            OpCode.OP_NIP,
            OpCode.OP_1,
            OpCode.OP_SPLIT,
            OpCode.OP_SWAP,
            OpCode.OP_SPLIT,
            OpCode.OP_DROP,
        ]
        if self.type != "raw":
            chunks.append(getattr(OpCode, f"OP_{self.type}"))
        chunks.append(encode_pushdata(value))
        chunks.append(OpCode.OP_EQUALVERIFY)
        chunks.append(OpCode.OP_CHECKSIG)
        return Script(b"".join(chunks))

    def unlock(
        self,
        k: int,
        private_key: Optional[PrivateKey] = PrivateKey(),
        sign_outputs: str = "all",
        anyone_can_pay: bool = False,
    ):
        """
        Creates a function that generates an R puzzle unlocking script along with its signature and length estimation.

        :param k: The K-value used to unlock the R-puzzle.
        :param private_key: The private key used for signing the transaction.
        :param sign_outputs: The signature scope for outputs ('all', 'none', 'single').
        :param anyone_can_pay: Flag indicating if the signature allows for other inputs to be added later.
        :returns: An object containing the `sign` and `estimate_length` functions.
        """

        def sign(tx, input_index) -> Script:
            sighash = SIGHASH.FORKID
            if sign_outputs == "all":
                sighash |= SIGHASH.ALL
            elif sign_outputs == "none":
                sighash |= SIGHASH.NONE
            elif sign_outputs == "single":
                sighash |= SIGHASH.SINGLE
            if anyone_can_pay:
                sighash |= SIGHASH.ANYONECANPAY

            tx.inputs[input_index].sighash = sighash

            preimage = tx.preimage(input_index)

            sig = private_key.sign(preimage, hasher=hash256, k=k) + sighash.to_bytes(1, "little")
            pubkey_for_script = private_key.public_key().serialize()

            return Script(encode_pushdata(sig) + encode_pushdata(pubkey_for_script))

        def estimated_unlocking_byte_length() -> int:
            # public key (1+33) + signature (1+73)
            # Note: We add 1 to each element's length because of the associated OP_PUSH
            return 108

        return to_unlock_script_template(sign, estimated_unlocking_byte_length)
