from contextlib import suppress
from typing import Literal

from .script import ScriptChunk, Script
from ..constants import OpCode, OPCODE_VALUE_NAME_DICT, SIGHASH
from ..curve import curve
from ..hash import sha1, sha256, ripemd160, hash256, hash160
from ..keys import PublicKey
from ..transaction_input import TransactionInput
from ..transaction_preimage import tx_preimage
from ..utils import unsigned_to_bytes, deserialize_ecdsa_der

MAX_SCRIPT_ELEMENT_SIZE = 1024 * 1024 * 1024
MAX_MULTISIG_KEY_COUNT = pow(2, 31) - 1
REQUIRE_MINIMAL_PUSH = True
REQUIRE_PUSH_ONLY_UNLOCKING_SCRIPTS = True
REQUIRE_LOW_S_SIGNATURES = True
REQUIRE_CLEAN_STACK = True


class Spend:
    def __init__(self, params):
        """
        Constructs a Spend object with necessary transaction details.

        :param str params['sourceTXID']: The transaction ID of the source UTXO.
        :param int params['sourceOutputIndex']: The index of the output in the source transaction.
        :param BigNumber params['sourceSatoshis']: The amount of satoshis in the source UTXO.
        :param LockingScript params['lockingScript']: The locking script associated with the UTXO.
        :param int params['transactionVersion']: The version of the current transaction.
        :param list params['otherInputs']: An array of other inputs in the transaction.
        :param list params['outputs']: The outputs of the current transaction.
        :param int params['inputIndex']: The index of this input in the current transaction.
        :param UnlockingScript params['unlockingScript']: The unlocking script for this spend.
        :param int params['inputSequence']: The sequence number of this input.
        :param int params['lockTime']: The lock time of the transaction.

        Example:
        spend = Spend({
            'sourceTXID': "abcd1234",  # sourceTXID
            'sourceOutputIndex': 0,  # sourceOutputIndex
            'sourceSatoshis': BigNumber(1000),  # sourceSatoshis
            'lockingScript': LockingScript.from_asm("OP_DUP OP_HASH160 abcd1234... OP_EQUALVERIFY OP_CHECKSIG"),
            'transactionVersion': 1,  # transactionVersion
            'otherInputs': [{'sourceTXID': "abcd1234", 'sourceOutputIndex': 1, 'sequence': 0xffffffff}],  # otherInputs
            'outputs': [{'satoshis': BigNumber(500), 'lockingScript': LockingScript.from_asm("OP_DUP...")}],  # outputs
            'inputIndex': 0,  # inputIndex
            'unlockingScript': UnlockingScript.from_asm("3045... 02ab..."),
            'inputSequence': 0xffffffff,  # inputSequence
            'lockTime': 0  # lockTime
        })
        """
        self.source_txid = params['sourceTXID']
        self.source_output_index = params['sourceOutputIndex']
        self.source_satoshis = params['sourceSatoshis']
        self.locking_script: Script = params['lockingScript']
        self.transaction_version = params['transactionVersion']
        self.other_inputs = params['otherInputs']
        self.outputs = params['outputs']
        self.input_index = params['inputIndex']
        self.unlocking_script: Script = params['unlockingScript']
        self.input_sequence = params['inputSequence']
        self.lock_time = params['lockTime']

        self.context: Literal["UnlockingScript", "LockingScript"] = 'UnlockingScript'
        self.program_counter = 0
        self.last_code_separator = None
        self.stack = []
        self.alt_stack = []
        self.if_stack = []

    def step(self) -> None:
        # If the context is UnlockingScript, and we have reached the end,
        # set the context to LockingScript and zero the program counter
        if self.context == 'UnlockingScript' and self.program_counter >= len(self.unlocking_script.chunks):
            self.context = 'LockingScript'
            self.program_counter = 0

        if self.context == 'UnlockingScript':
            operation = self.unlocking_script.chunks[self.program_counter]
        else:
            operation = self.locking_script.chunks[self.program_counter]

        is_script_executing = not (b'' in self.if_stack)

        # Read instruction
        current_opcode = operation.op
        if current_opcode not in OPCODE_VALUE_NAME_DICT.keys() \
                and not (b'\x01' <= current_opcode < OpCode.OP_PUSHDATA1):
            self.script_evaluation_error(f'An opcode is missing in this chunk of the {self.context}!')
        if operation.data is not None and len(operation.data) > MAX_SCRIPT_ELEMENT_SIZE:
            _m = f"It's not currently possible to push data larger than {MAX_SCRIPT_ELEMENT_SIZE} bytes."
            self.script_evaluation_error(_m)
        if is_script_executing and self.is_op_disabled(current_opcode):
            self.script_evaluation_error('This opcode is currently disabled.')

        if is_script_executing and OpCode.OP_0 <= current_opcode <= OpCode.OP_PUSHDATA4:
            if REQUIRE_MINIMAL_PUSH and not self.is_chunk_minimal(operation):
                self.script_evaluation_error('This data is not minimally-encoded.')
            if operation.data is None:
                self.stack.append(b'')
            else:
                self.stack.append(operation.data)
        elif is_script_executing or (OpCode.OP_IF <= current_opcode <= OpCode.OP_ENDIF):
            if current_opcode in [
                OpCode.OP_1NEGATE,
                OpCode.OP_1,
                OpCode.OP_2,
                OpCode.OP_3,
                OpCode.OP_4,
                OpCode.OP_5,
                OpCode.OP_6,
                OpCode.OP_7,
                OpCode.OP_8,
                OpCode.OP_9,
                OpCode.OP_10,
                OpCode.OP_11,
                OpCode.OP_12,
                OpCode.OP_13,
                OpCode.OP_14,
                OpCode.OP_15,
                OpCode.OP_16,
            ]:
                n = int.from_bytes(current_opcode, 'big') - (int.from_bytes(OpCode.OP_1, 'big') - 1)
                self.stack.append(self.minimally_encode(n))

            elif current_opcode in [
                OpCode.OP_NOP,
                OpCode.OP_NOP1,
                OpCode.OP_NOP2,
                OpCode.OP_NOP3,
                OpCode.OP_NOP4,
                OpCode.OP_NOP5,
                OpCode.OP_NOP6,
                OpCode.OP_NOP7,
                OpCode.OP_NOP8,
                OpCode.OP_NOP9,
                OpCode.OP_NOP10,
                OpCode.OP_NOP11,
                OpCode.OP_NOP12,
                OpCode.OP_NOP13,
                OpCode.OP_NOP14,
                OpCode.OP_NOP15,
                OpCode.OP_NOP16,
                OpCode.OP_NOP17,
                OpCode.OP_NOP18,
                OpCode.OP_NOP19,
                OpCode.OP_NOP20,
                OpCode.OP_NOP21,
                OpCode.OP_NOP22,
                OpCode.OP_NOP23,
                OpCode.OP_NOP24,
                OpCode.OP_NOP25,
                OpCode.OP_NOP26,
                OpCode.OP_NOP27,
                OpCode.OP_NOP28,
                OpCode.OP_NOP29,
                OpCode.OP_NOP30,
                OpCode.OP_NOP31,
                OpCode.OP_NOP32,
                OpCode.OP_NOP33,
                OpCode.OP_NOP34,
                OpCode.OP_NOP35,
                OpCode.OP_NOP36,
                OpCode.OP_NOP37,
                OpCode.OP_NOP38,
                OpCode.OP_NOP39,
                OpCode.OP_NOP40,
                OpCode.OP_NOP41,
                OpCode.OP_NOP42,
                OpCode.OP_NOP43,
                OpCode.OP_NOP44,
                OpCode.OP_NOP45,
                OpCode.OP_NOP46,
                OpCode.OP_NOP47,
                OpCode.OP_NOP48,
                OpCode.OP_NOP49,
                OpCode.OP_NOP50,
                OpCode.OP_NOP51,
                OpCode.OP_NOP52,
                OpCode.OP_NOP53,
                OpCode.OP_NOP54,
                OpCode.OP_NOP55,
                OpCode.OP_NOP56,
                OpCode.OP_NOP57,
                OpCode.OP_NOP58,
                OpCode.OP_NOP59,
                OpCode.OP_NOP60,
                OpCode.OP_NOP61,
                OpCode.OP_NOP62,
                OpCode.OP_NOP63,
                OpCode.OP_NOP64,
                OpCode.OP_NOP65,
                OpCode.OP_NOP66,
                OpCode.OP_NOP67,
                OpCode.OP_NOP68,
                OpCode.OP_NOP69,
                OpCode.OP_NOP70,
                OpCode.OP_NOP71,
                OpCode.OP_NOP72,
                OpCode.OP_NOP73,
                OpCode.OP_NOP77,
            ]:
                pass

            elif current_opcode in [OpCode.OP_IF, OpCode.OP_NOTIF]:
                f = False
                if is_script_executing:
                    if len(self.stack) < 1:
                        _m = 'OP_IF and OP_NOTIF require at least one item on the stack when they are used!'
                        self.script_evaluation_error(_m)
                    octets = self.stacktop(-1)
                    f = self.cast_to_bool(octets)
                    if current_opcode == OpCode.OP_NOTIF:
                        f = not f
                    self.stack.pop()
                self.if_stack.append(self.encode_bool(f))

            elif current_opcode == OpCode.OP_ELSE:
                if len(self.if_stack) == 0:
                    self.script_evaluation_error('OP_ELSE requires a preceeding OP_IF.')
                f = not self.cast_to_bool(self.if_stack[-1])
                self.if_stack[-1] = self.encode_bool(f)

            elif current_opcode == OpCode.OP_ENDIF:
                if len(self.if_stack) == 0:
                    self.script_evaluation_error('OP_ENDIF requires a preceeding OP_IF.')
                self.if_stack.pop()

            elif current_opcode == OpCode.OP_VERIFY:
                if len(self.stack) < 1:
                    self.script_evaluation_error('OP_VERIFY requires at least one item to be on the stack.')
                f = self.cast_to_bool(self.stacktop(-1))
                if f:
                    self.stack.pop()
                else:
                    self.script_evaluation_error('OP_VERIFY requires the top stack value to be truthy.')

            elif current_opcode == OpCode.OP_RETURN:
                if self.context == 'UnlockingScript':
                    self.program_counter = len(self.unlocking_script.chunks)
                else:
                    self.program_counter = len(self.locking_script.chunks)
                self.if_stack = []

            elif current_opcode == OpCode.OP_TOALTSTACK:
                if len(self.stack) < 1:
                    self.script_evaluation_error('OP_TOALTSTACK requires at oeast one item to be on the stack.')
                self.alt_stack.append(self.stack.pop())

            elif current_opcode == OpCode.OP_FROMALTSTACK:
                if len(self.alt_stack) < 1:
                    self.script_evaluation_error('OP_FROMALTSTACK requires at least one item to be on the stack.')
                self.stack.append(self.alt_stack.pop())

            elif current_opcode == OpCode.OP_2DROP:
                if len(self.stack) < 2:
                    self.script_evaluation_error('OP_2DROP requires at least two items to be on the stack.')
                self.stack.pop()
                self.stack.pop()

            elif current_opcode == OpCode.OP_2DUP:
                if len(self.stack) < 2:
                    self.script_evaluation_error('OP_2DUP requires at least two items to be on the stack.')
                x1 = self.stacktop(-2)
                x2 = self.stacktop(-1)
                self.stack.append(x1)
                self.stack.append(x2)

            elif current_opcode == OpCode.OP_3DUP:
                if len(self.stack) < 3:
                    self.script_evaluation_error('OP_3DUP requires at least three items to be on the stack.')
                x1 = self.stacktop(-3)
                x2 = self.stacktop(-2)
                x3 = self.stacktop(-1)
                self.stack.append(x1)
                self.stack.append(x2)
                self.stack.append(x3)

            elif current_opcode == OpCode.OP_2OVER:
                if len(self.stack) < 4:
                    self.script_evaluation_error('OP_2OVER requires at least four items to be on the stack.')
                x1 = self.stacktop(-4)
                x2 = self.stacktop(-3)
                self.stack.append(x1)
                self.stack.append(x2)

            elif current_opcode == OpCode.OP_2ROT:
                if len(self.stack) < 6:
                    self.script_evaluation_error('OP_2ROT requires at least six items to be on the stack.')
                x1 = self.stack.pop(-6)
                x2 = self.stack.pop(-5)
                self.stack.append(x1)
                self.stack.append(x2)

            elif current_opcode == OpCode.OP_2SWAP:
                if len(self.stack) < 4:
                    self.script_evaluation_error('OP_2SWAP requires at least four items to be on the stack.')
                x1 = self.stack.pop(-4)
                x2 = self.stack.pop(-3)
                self.stack.append(x1)
                self.stack.append(x2)

            elif current_opcode == OpCode.OP_IFDUP:
                if len(self.stack) < 1:
                    self.script_evaluation_error('OP_IFDUP requires at least one item to be on the stack.')
                octets = self.stacktop(-1)
                f = self.cast_to_bool(octets)
                if f:
                    self.stack.append(octets)

            elif current_opcode == OpCode.OP_DEPTH:
                self.stack.append(self.minimally_encode(len(self.stack)))

            elif current_opcode == OpCode.OP_DROP:
                if len(self.stack) < 1:
                    self.script_evaluation_error('OP_DROP requires at least one item to be on the stack.')
                self.stack.pop()

            elif current_opcode == OpCode.OP_DUP:
                if len(self.stack) < 1:
                    self.script_evaluation_error('OP_DUP requires at least one item to be on the stack.')
                self.stack.append(self.stacktop(-1))

            elif current_opcode == OpCode.OP_NIP:
                if len(self.stack) < 2:
                    self.script_evaluation_error('OP_NIP requires at least two items to be on the stack.')
                self.stack.pop(-2)

            elif current_opcode == OpCode.OP_OVER:
                if len(self.stack) < 2:
                    self.script_evaluation_error('OP_OVER requires at least two items to be on the stack.')
                self.stack.append(self.stacktop(-2))

            elif current_opcode in [OpCode.OP_PICK, OpCode.OP_ROLL]:
                _codename = OPCODE_VALUE_NAME_DICT[current_opcode]
                if len(self.stack) < 2:
                    self.script_evaluation_error(f'{_codename} requires at least two items to be on the stack.')
                n = self.bin2num(self.stacktop(-1))
                self.stack.pop()
                if n < 0 or n >= len(self.stack):
                    _m = (f'{_codename} requires the top stack element to be 0 or '
                          'a positive number less than the current size of the stack.')
                    self.script_evaluation_error(_m)
                octets = self.stacktop(-n - 1)
                if current_opcode == OpCode.OP_ROLL:
                    octets = self.stack.pop(len(self.stack) - n - 1)
                self.stack.append(octets)

            elif current_opcode == OpCode.OP_ROT:
                if len(self.stack) < 3:
                    self.script_evaluation_error('OP_ROT requires at least three items to be on the stack.')
                x1 = self.stacktop(-3)
                x2 = self.stacktop(-2)
                x3 = self.stacktop(-1)
                self.stack[-3] = x2
                self.stack[-2] = x3
                self.stack[-1] = x1

            elif current_opcode == OpCode.OP_SWAP:
                if len(self.stack) < 2:
                    self.script_evaluation_error('OP_SWAP requires at least two items to be on the stack.')
                x1 = self.stacktop(-2)
                x2 = self.stacktop(-1)
                self.stack[-2] = x2
                self.stack[-1] = x1

            elif current_opcode == OpCode.OP_TUCK:
                if len(self.stack) < 2:
                    self.script_evaluation_error('OP_TUCK requires at least two items to be on the stack.')
                x1 = self.stack.pop(-2)
                x2 = self.stack.pop(-1)
                self.stack.append(x2)
                self.stack.append(x1)
                self.stack.append(x2)

            elif current_opcode == OpCode.OP_SIZE:
                if len(self.stack) < 1:
                    self.script_evaluation_error('OP_SIZE requires at least one item to be on the stack.')
                n = len(self.stacktop(-1))
                self.stack.append(self.minimally_encode(n))

            elif current_opcode in [OpCode.OP_AND, OpCode.OP_OR, OpCode.OP_XOR]:
                _codename = OPCODE_VALUE_NAME_DICT[current_opcode]
                if len(self.stack) < 2:
                    self.script_evaluation_error(f'{_codename} requires at least one item to be on the stack.')
                x1 = self.stack.pop(-2)
                x2 = self.stack.pop(-1)
                if len(x1) != len(x2):
                    self.script_evaluation_error(f'{_codename} requires the top two stack items to be the same size.')
                if current_opcode == OpCode.OP_AND:
                    sig = bytes([a & b for a, b in zip(x1, x2)])
                elif current_opcode == OpCode.OP_OR:
                    sig = bytes([a | b for a, b in zip(x1, x2)])
                else:
                    sig = bytes([a ^ b for a, b in zip(x1, x2)])
                self.stack.append(sig)

            elif current_opcode == OpCode.OP_INVERT:
                if len(self.stack) < 1:
                    self.script_evaluation_error('OP_INVERT requires at least one item to be on the stack.')
                x = self.stack.pop()
                x = bytes([~b for b in x])
                self.stack.append(x)

            elif current_opcode in [OpCode.OP_LSHIFT, OpCode.OP_RSHIFT]:
                _codename = OPCODE_VALUE_NAME_DICT[current_opcode]
                if len(self.stack) < 2:
                    self.script_evaluation_error(f'{_codename} requires at least two items to be on the stack.')
                n = self.bin2num(self.stacktop(-1))
                if n < 0:
                    self.script_evaluation_error(f'{_codename} requires the top stack item to be non-negative.')
                x = self.stack.pop(-2)
                if current_opcode == OpCode.OP_LSHIFT:
                    x = x[n:] + b'\x00' * n
                else:
                    x = b'\x00' * n + x[:-n]
                self.stack.append(x)

            elif current_opcode in [OpCode.OP_EQUAL, OpCode.OP_EQUALVERIFY]:
                _codename = OPCODE_VALUE_NAME_DICT[current_opcode]
                if len(self.stack) < 2:
                    self.script_evaluation_error(f'{_codename} requires at least two items to be on the stack.')
                x1 = self.stack.pop(-2)
                x2 = self.stack.pop(-1)
                f = x1 == x2
                self.stack.append(self.encode_bool(f))
                if current_opcode == OpCode.OP_EQUALVERIFY:
                    if f:
                        self.stack.pop()
                    else:
                        self.script_evaluation_error('OP_EQUALVERIFY requires the top two stack items to be equal.')

            elif current_opcode in [
                OpCode.OP_1ADD,
                OpCode.OP_1SUB,
                OpCode.OP_NEGATE,
                OpCode.OP_ABS,
                OpCode.OP_NOT,
                OpCode.OP_0NOTEQUAL,
            ]:
                _codename = OPCODE_VALUE_NAME_DICT[current_opcode]
                if len(self.stack) < 1:
                    self.script_evaluation_error(f'{_codename} requires at least one items to be on the stack.')
                x = self.bin2num(self.stack.pop())
                if current_opcode == OpCode.OP_1ADD:
                    x += 1
                elif current_opcode == OpCode.OP_1SUB:
                    x -= 1
                elif current_opcode == OpCode.OP_NEGATE:
                    x = -x
                elif current_opcode == OpCode.OP_ABS:
                    x = abs(x)
                elif current_opcode == OpCode.OP_NOT:
                    x = 1 if x == 0 else 0
                else:
                    x = 1 if x != 0 else 0
                self.stack.append(self.minimally_encode(x))

            elif current_opcode in [
                OpCode.OP_ADD,
                OpCode.OP_SUB,
                OpCode.OP_MUL,
                OpCode.OP_MOD,
                OpCode.OP_DIV,
                OpCode.OP_BOOLAND,
                OpCode.OP_BOOLOR,
                OpCode.OP_NUMEQUAL,
                OpCode.OP_NUMEQUALVERIFY,
                OpCode.OP_NUMNOTEQUAL,
                OpCode.OP_LESSTHAN,
                OpCode.OP_GREATERTHAN,
                OpCode.OP_LESSTHANOREQUAL,
                OpCode.OP_GREATERTHANOREQUAL,
                OpCode.OP_MIN,
                OpCode.OP_MAX,
            ]:
                _codename = OPCODE_VALUE_NAME_DICT[current_opcode]
                if len(self.stack) < 2:
                    self.script_evaluation_error(f'{_codename} requires at least two items to be on the stack.')
                x1 = self.bin2num(self.stack.pop(-2))
                x2 = self.bin2num(self.stack.pop())
                if current_opcode == OpCode.OP_ADD:
                    x = x1 + x2
                elif current_opcode == OpCode.OP_SUB:
                    x = x1 - x2
                elif current_opcode == OpCode.OP_MUL:
                    x = x1 * x2
                elif current_opcode == OpCode.OP_DIV:
                    if x2 == 0:
                        self.script_evaluation_error('OP_DIV cannot divide by zero!')
                    x = x1 // x2
                elif current_opcode == OpCode.OP_MOD:
                    if x2 == 0:
                        self.script_evaluation_error('OP_MOD cannot divide by zero!')
                    x = x1 % x2
                elif current_opcode == OpCode.OP_BOOLAND:
                    x = 1 if x1 != 0 and x2 != 0 else 0
                elif current_opcode == OpCode.OP_BOOLOR:
                    x = 1 if x1 != 0 or x2 != 0 else 0
                elif current_opcode == OpCode.OP_NUMEQUAL:
                    x = 1 if x1 == x2 else 0
                elif current_opcode == OpCode.OP_NUMEQUALVERIFY:
                    x = 1 if x1 == x2 else 0
                elif current_opcode == OpCode.OP_NUMNOTEQUAL:
                    x = 1 if x1 != x2 else 0
                elif current_opcode == OpCode.OP_LESSTHAN:
                    x = 1 if x1 < x2 else 0
                elif current_opcode == OpCode.OP_GREATERTHAN:
                    x = 1 if x1 > x2 else 0
                elif current_opcode == OpCode.OP_LESSTHANOREQUAL:
                    x = 1 if x1 <= x2 else 0
                elif current_opcode == OpCode.OP_GREATERTHANOREQUAL:
                    x = 1 if x1 >= x2 else 0
                elif current_opcode == OpCode.OP_MIN:
                    x = min(x1, x2)
                else:
                    x = max(x1, x2)
                self.stack.append(self.minimally_encode(x))

                if current_opcode == OpCode.OP_NUMEQUALVERIFY:
                    if self.cast_to_bool(self.stacktop(-1)):
                        self.stack.pop()
                    else:
                        self.script_evaluation_error('OP_NUMEQUALVERIFY requires the top stack item to be truthy.')

            elif current_opcode == OpCode.OP_WITHIN:
                if len(self.stack) < 3:
                    self.script_evaluation_error('OP_WITHIN requires at least three items to be on the stack.')
                x1 = self.bin2num(self.stack.pop(-3))
                x2 = self.bin2num(self.stack.pop(-2))
                x3 = self.bin2num(self.stack.pop())
                f = x2 <= x1 < x3
                self.stack.append(self.encode_bool(f))

            elif current_opcode in [
                OpCode.OP_RIPEMD160,
                OpCode.OP_SHA1,
                OpCode.OP_SHA256,
                OpCode.OP_HASH160,
                OpCode.OP_HASH256,
            ]:
                _codename = OPCODE_VALUE_NAME_DICT[current_opcode]
                if len(self.stack) < 1:
                    self.script_evaluation_error(f'{_codename} requires at least one item to be on the stack.')
                sig = self.stack.pop()
                if current_opcode == OpCode.OP_RIPEMD160:
                    sig = ripemd160(sig)
                elif current_opcode == OpCode.OP_SHA1:
                    sig = sha1(sig)
                elif current_opcode == OpCode.OP_SHA256:
                    sig = sha256(sig)
                elif current_opcode == OpCode.OP_HASH160:
                    sig = hash160(sig)
                else:
                    sig = hash256(sig)
                self.stack.append(sig)

            elif current_opcode == OpCode.OP_CODESEPARATOR:
                self.last_code_separator = self.program_counter

            elif current_opcode in [OpCode.OP_CHECKSIG, OpCode.OP_CHECKSIGVERIFY]:
                _codename = OPCODE_VALUE_NAME_DICT[current_opcode]
                if len(self.stack) < 2:
                    self.script_evaluation_error(f'{_codename} requires at least two items to be on the stack.')
                sig = self.stack.pop(-2)
                pub_key = self.stack.pop()
                if not self.check_signature_encoding(sig) or not self.check_public_key_encoding(pub_key):
                    _m = f'{_codename} requires correct encoding for the public key and signature.'
                    self.script_evaluation_error(_m)

                # Subset of script starting at the most recent code separator
                if self.context == 'UnlockingScript':
                    sub_script = Script.from_chunks(self.unlocking_script.chunks[self.last_code_separator:])
                else:
                    sub_script = Script.from_chunks(self.locking_script.chunks[self.last_code_separator:])

                # Drop the signature, since there's no way for a signature to sign itself
                sub_script = Script.find_and_delete(sub_script, Script.write_bin(sig))

                # TODO
                f = self.verify_signature(sig, pub_key, sub_script)

                if not f and len(sig) > 0:
                    self.script_evaluation_error(f'{_codename} failed to verify the signature, '
                                                 'and requires an empty signature when verification fails.')
                self.stack.append(self.encode_bool(f))

                if current_opcode == OpCode.OP_CHECKSIGVERIFY:
                    if f:
                        self.stack.pop()
                    else:
                        self.script_evaluation_error('OP_CHECKSIGVERIFY requires that a valid signature is provided.')

            elif current_opcode in [OpCode.OP_CHECKMULTISIG, OpCode.OP_CHECKMULTISIGVERIFY]:
                _codename = OPCODE_VALUE_NAME_DICT[current_opcode]
                i = 1
                if len(self.stack) < i:
                    self.script_evaluation_error(f'{_codename} requires at least 1 item to be on the stack.')

                keys_count = self.bin2num(self.stacktop(-i))
                if keys_count < 0 or keys_count > MAX_MULTISIG_KEY_COUNT:
                    _m = f'${_codename} requires a key count between 0 and {MAX_MULTISIG_KEY_COUNT}.'
                    self.script_evaluation_error(_m)
                i += 1
                i_key = i
                i += keys_count

                # ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
                # With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
                i_key2 = keys_count + 2
                
                if len(self.stack) < i:
                    _m = f'{_codename} requires the number of stack items not to be less than the number of keys used.'
                    self.script_evaluation_error(_m)

                sigs_count = self.bin2num(self.stacktop(-i))
                if sigs_count < 0 or sigs_count > keys_count:
                    _m = f'{_codename} requires the number of signatures to be no greater than the number of keys.'
                    self.script_evaluation_error(_m)
                i += 1
                i_sig = i
                i += sigs_count
                if len(self.stack) < i:
                    _m = (f'{_codename} requires the number of stack items '
                          'not to be less than the number of signatures provided.')
                    self.script_evaluation_error(_m)

                # Subset of script starting at the most recent code separator
                if self.context == 'UnlockingScript':
                    sub_script = Script.from_chunks(self.unlocking_script.chunks[self.last_code_separator:])
                else:
                    sub_script = Script.from_chunks(self.locking_script.chunks[self.last_code_separator:])

                # Drop the signatures, since there's no way for a signature to sign itself
                for j in range(sigs_count):
                    sub_script = Script.find_and_delete(sub_script, Script.write_bin(self.stacktop(-i_sig - j)))

                f = True
                while f and sigs_count > 0:
                    buf_sig = self.stacktop(-i_sig)
                    buf_pub_key = self.stacktop(-i_key)

                    if not self.check_signature_encoding(buf_sig) or not self.check_public_key_encoding(buf_pub_key):
                        _m = f'{_codename} requires correct encoding for the public key and signature.'
                        self.script_evaluation_error(_m)

                    # TODO
                    f_verify = self.verify_signature(buf_sig, buf_pub_key, sub_script)

                    if f_verify:
                        i_sig += 1
                        sigs_count -= 1
                    i_key += 1
                    sigs_count -= 1

                    # If there are more signatures left than keys left, then too many signatures have failed
                    if sigs_count > keys_count:
                        f = False

                # Clean up stack of actual arguments
                while i > 1:
                    if not f and not i_key2 and ():
                        _m = (f'{_codename} failed to verify a signature, '
                              'and requires an empty signature when verification fails.')
                        self.script_evaluation_error(_m)

                    if i_key2 > 0:
                        i_key2 -= 1

                    self.stack.pop()
                    i -= 1

                # A bug causes CHECKMULTISIG to consume one extra argument whose contents were not checked in any way.
                #
                # Unfortunately this is a potential source of mutability,
                # so optionally verify it is exactly equal to zero prior
                # to removing it from the stack.
                if len(self.stack) < 1:
                    self.script_evaluation_error(f'{_codename} requires an extra item to be on the stack.')
                if len(self.stacktop(-1)) > 0:
                    self.script_evaluation_error(f'{_codename} requires the extra stack item to be empty.')
                self.stack.pop()

                self.stack.append(self.encode_bool(f))

                if current_opcode == OpCode.OP_CHECKMULTISIGVERIFY:
                    if f:
                        self.stack.pop()
                    else:
                        _m = 'OP_CHECKMULTISIGVERIFY requires a sufficient number of valid signatures are provided.'
                        self.script_evaluation_error(_m)

            elif current_opcode == OpCode.OP_CAT:
                if len(self.stack) < 2:
                    self.script_evaluation_error('OP_CAT requires at least two items to be on the stack.')
                x1 = self.stack.pop(-2)
                x2 = self.stack.pop()
                if len(x1) + len(x2) > MAX_SCRIPT_ELEMENT_SIZE:
                    self.script_evaluation_error("It's not currently possible to push data "
                                                 f"larger than {MAX_SCRIPT_ELEMENT_SIZE} bytes.")
                self.stack.append(x1 + x2)

            elif current_opcode == OpCode.OP_SPLIT:
                if len(self.stack) < 2:
                    self.script_evaluation_error('OP_SPLIT requires at least two items to be on the stack.')
                x1 = self.stack.pop(-2)
                #  Make sure the split point is appropriate.
                n = self.bin2num(self.stack.pop())
                if n < 0 or n > len(x1):
                    self.script_evaluation_error("OP_SPLIT requires the first stack item to be a non-negative number "
                                                 "less than or equal to the size of the second-from-top stack item.")
                self.stack.append(x1[:n])
                self.stack.append(x1[n:])

            elif current_opcode == OpCode.OP_NUM2BIN:
                if len(self.stack) < 2:
                    self.script_evaluation_error('OP_NUM2BIN requires at least two items to be on the stack.')
                size = self.bin2num(self.stack.pop())
                if size > MAX_SCRIPT_ELEMENT_SIZE:
                    self.script_evaluation_error("It's not currently possible to push data "
                                                 f"larger than {MAX_SCRIPT_ELEMENT_SIZE} bytes.")
                n = self.bin2num(self.stack.pop())
                x = bytearray(self.minimally_encode(n))

                # Try to see if we can fit that number in the number of byte requested.
                if len(x) > size:
                    _m = ('OP_NUM2BIN requires that the size expressed in the top stack item '
                          'is large enough to hold the value expressed in the second-from-top stack item.')
                    self.script_evaluation_error(_m)

                msb = b'\x00'
                if len(x) > 0:
                    msb = x[-1] & 0x80
                    x[-1] &= 0x7f
                octets = x + b'\x00' * (size - len(x))
                octets[-1] |= msb

                self.stack.append(octets)

            elif current_opcode == OpCode.OP_BIN2NUM:
                if len(self.stack) < 1:
                    self.script_evaluation_error('OP_BIN2NUM requires at least one item to be on the stack.')
                x = self.stack.pop()
                self.stack.append(self.minimally_encode(self.bin2num(x)))

            else:
                self.script_evaluation_error('Invalid opcode!')

        # Finally, increment the program counter
        self.program_counter += 1

    def validate(self) -> bool:
        """
        Validates the spend action by interpreting the locking and unlocking scripts.
        Returns true if the scripts are valid and the spend is legitimate, otherwise false.
        """
        if REQUIRE_PUSH_ONLY_UNLOCKING_SCRIPTS and not self.unlocking_script.is_push_only():
            self.script_evaluation_error('Unlocking scripts can only contain push operations, and no other opcodes.')

        while True:
            self.step()
            if self.context == 'LockingScript' and self.program_counter >= len(self.locking_script.chunks):
                break

        if len(self.if_stack) > 0:
            self.script_evaluation_error('Every OP_IF must be terminated prior to the end of the script.')

        if REQUIRE_CLEAN_STACK:
            if len(self.stack) != 1:
                self.script_evaluation_error(
                    'The clean stack rule requires exactly one item to be on the stack after script execution.')

        if not self.cast_to_bool(self.stacktop(-1)):
            self.script_evaluation_error('The top stack element must be truthy after script evaluation.')

        return True

    def stacktop(self, i: int) -> bytes:
        return self.stack[len(self.stack) + i]

    def script_evaluation_error(self, message: str) -> None:
        raise RuntimeError(f"Script evaluation error: {message}\n\n"
                        f"Source TXID: {self.source_txid}\n"
                        f"Source output index: {self.source_output_index}\n"
                        f"Context: {self.context}\n"
                        f"Program counter: {self.program_counter}\n"
                        f"Stack size: {len(self.stack)}\n"
                        f"Alt stack size: {len(self.alt_stack)}")

    @staticmethod
    def cast_to_bool(val: bytes) -> bool:
        for i in range(len(val)):
            if val[i] != 0:
                # can be negative zero
                if i == len(val) - 1 and val[i] == 0x80:
                    return False
                return True
        return False

    @classmethod
    def is_op_disabled(cls, opcode: bytes) -> bool:
        return (opcode == OpCode.OP_2MUL
                or opcode == OpCode.OP_2DIV
                or opcode == OpCode.OP_VERIF
                or opcode == OpCode.OP_VERNOTIF
                or opcode == OpCode.OP_VER)

    @classmethod
    def is_chunk_minimal(cls, chunk: ScriptChunk) -> bool:
        data = chunk.data
        op = chunk.op
        if data is None:
            return True
        if len(data) == 0:
            return op == OpCode.OP_0
        if len(data) == 1 and 1 <= data[0] <= 16:
            return op == OpCode.OP_1 + (int.from_bytes(data, 'big') - 1).to_bytes(1, 'big')
        if len(data) == 1 and data[0] == 0x81:
            return op == OpCode.OP_1NEGATE
        if len(data) <= 75:
            return op == len(data).to_bytes(1, 'big')
        if len(data) <= 255:
            return op == OpCode.OP_PUSHDATA1
        if len(data) <= 65535:
            return op == OpCode.OP_PUSHDATA2
        return op == OpCode.OP_PUSHDATA4

    @classmethod
    def minimally_encode(cls, num: int) -> bytes:
        if num == 0:
            return b''
        negative: bool = num < 0
        octets: bytearray = bytearray(unsigned_to_bytes(-num if negative else num, 'little'))
        if octets[-1] & 0x80:
            octets += b'\x00'
        if negative:
            octets[-1] |= 0x80
        return octets

    @classmethod
    def bin2num(cls, octets: bytes) -> int:
        if len(octets) == 0:
            return 0
        negative = octets[-1] & 0x80
        octets = bytearray(octets)
        octets[-1] &= 0x7f
        n = int.from_bytes(octets, 'little')
        return -n if negative else n

    def check_signature_encoding(self, octets: bytes) -> bool:
        # Empty signature. Not strictly DER encoded, but allowed to provide a
        # compact way to provide an invalid signature for use with CHECK(MULTI)SIG
        if octets == b'':
            return True
        sig, sighash = octets[:-1], octets[-1]

        if not SIGHASH.validate(sighash):
            self.script_evaluation_error('Invalid SIGHASH flag')

        with suppress(Exception):
            _, s = deserialize_ecdsa_der(sig)
            if REQUIRE_LOW_S_SIGNATURES and s > curve.n // 2:
                self.script_evaluation_error('The signature must have a low S value.')
            return True
        self.script_evaluation_error('The signature format is invalid.')

    @classmethod
    def check_public_key_encoding(cls, octets: bytes) -> bool:
        with suppress(Exception):
            PublicKey(octets)
            return True
        return False

    def verify_signature(self, sig: bytes, pub_key: bytes, sub_script: Script) -> bool:
        if sig == b'':
            return False

        current_input = TransactionInput(
            source_txid=self.source_txid,
            source_output_index=self.source_output_index,
            unlocking_script=self.unlocking_script,
            sequence=self.input_sequence,
            sighash=SIGHASH(sig[-1]),
        )
        current_input.locking_script = sub_script
        current_input.satoshis = self.source_satoshis

        inputs = self.other_inputs[:]
        inputs.insert(self.input_index, current_input)

        preimage = tx_preimage(self.input_index, inputs, self.outputs, self.transaction_version, self.lock_time)
        return PublicKey(pub_key).verify(sig[:-1], preimage)

    @classmethod
    def encode_bool(cls, f: bool) -> bytes:
        return b'\x01' if f else b''
