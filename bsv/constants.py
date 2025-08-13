import os
from enum import Enum
from typing import Dict, List

NUMBER_BYTE_LENGTH: int = 32

TRANSACTION_SEQUENCE: int = int(os.getenv('BSV_PY_SDK_TRANSACTION_SEQUENCE') or 0xffffffff)
TRANSACTION_VERSION: int = int(os.getenv('BSV_PY_SDK_TRANSACTION_VERSION') or 1)
TRANSACTION_LOCKTIME: int = int(os.getenv('BSV_PY_SDK_TRANSACTION_LOCKTIME') or 0)
TRANSACTION_FEE_RATE: int = int(os.getenv('BSV_PY_SDK_TRANSACTION_FEE_RATE') or 5)  # satoshi per kilobyte
BIP32_DERIVATION_PATH = os.getenv('BSV_PY_SDK_BIP32_DERIVATION_PATH') or "m/"
BIP39_ENTROPY_BIT_LENGTH: int = int(os.getenv('BSV_PY_SDK_BIP39_ENTROPY_BIT_LENGTH') or 128)
BIP44_DERIVATION_PATH = os.getenv('BSV_PY_SDK_BIP44_DERIVATION_PATH') or "m/44'/236'/0'"

HTTP_REQUEST_TIMEOUT: int = int(os.getenv('BSV_PY_SDK_HTTP_REQUEST_TIMEOUT') or 30)
THREAD_POOL_MAX_EXECUTORS: int = int(os.getenv('BSV_PY_SDK_THREAD_POOL_MAX_EXECUTORS') or 10)


class Network(str, Enum):
    MAINNET = 'mainnet'
    TESTNET = 'testnet'


class SIGHASH(int, Enum):
    ALL: int = 0x01
    NONE: int = 0x02
    SINGLE: int = 0x03
    ANYONECANPAY: int = 0x80

    FORKID: int = 0x40

    ALL_FORKID = ALL | FORKID
    NONE_FORKID = NONE | FORKID
    SINGLE_FORKID = SINGLE | FORKID
    ALL_ANYONECANPAY_FORKID = ALL_FORKID | ANYONECANPAY
    NONE_ANYONECANPAY_FORKID = NONE_FORKID | ANYONECANPAY
    SINGLE_ANYONECANPAY_FORKID = SINGLE_FORKID | ANYONECANPAY

    @classmethod
    def validate(cls, sighash: int) -> bool:
        return sighash in [
            cls.ALL_FORKID,
            cls.NONE_FORKID,
            cls.SINGLE_FORKID,
            cls.ALL_ANYONECANPAY_FORKID,
            cls.NONE_ANYONECANPAY_FORKID,
            cls.SINGLE_ANYONECANPAY_FORKID,
        ]

#
# ARC
#
#
taal_mainnet_apikey = os.getenv('TAAL_MAINNET_APIKEY', '')
taal_testnet_apikey = os.getenv('TAAL_TESTNET_APIKEY', '')

#
# P2PKH address
#
ADDRESS_MAINNET_PREFIX: bytes = b'\x00'
ADDRESS_TESTNET_PREFIX: bytes = b'\x6f'
NETWORK_ADDRESS_PREFIX_DICT: Dict[Network, bytes] = {
    Network.MAINNET: ADDRESS_MAINNET_PREFIX,
    Network.TESTNET: ADDRESS_TESTNET_PREFIX,
}
ADDRESS_PREFIX_NETWORK_DICT: Dict[bytes, Network] = {
    ADDRESS_MAINNET_PREFIX: Network.MAINNET,
    ADDRESS_TESTNET_PREFIX: Network.TESTNET,
}

#
# WIF
#
WIF_MAINNET_PREFIX: bytes = b'\x80'
WIF_TESTNET_PREFIX: bytes = b'\xef'
NETWORK_WIF_PREFIX_DICT: Dict[Network, bytes] = {
    Network.MAINNET: WIF_MAINNET_PREFIX,
    Network.TESTNET: WIF_TESTNET_PREFIX,
}
WIF_PREFIX_NETWORK_DICT: Dict[bytes, Network] = {
    WIF_MAINNET_PREFIX: Network.MAINNET,
    WIF_TESTNET_PREFIX: Network.TESTNET,
}

#
# public key
#
PUBLIC_KEY_COMPRESSED_EVEN_Y_PREFIX: bytes = b'\x02'
PUBLIC_KEY_COMPRESSED_ODD_Y_PREFIX: bytes = b'\x03'
PUBLIC_KEY_COMPRESSED_PREFIX_LIST: List[bytes] = [
    PUBLIC_KEY_COMPRESSED_EVEN_Y_PREFIX,
    PUBLIC_KEY_COMPRESSED_ODD_Y_PREFIX
]
PUBLIC_KEY_COMPRESSED_BYTE_LENGTH: int = 33
PUBLIC_KEY_UNCOMPRESSED_BYTE_LENGTH: int = 65
PUBLIC_KEY_BYTE_LENGTH_LIST: List[int] = [PUBLIC_KEY_COMPRESSED_BYTE_LENGTH, PUBLIC_KEY_UNCOMPRESSED_BYTE_LENGTH]
PUBLIC_KEY_HASH_BYTE_LENGTH: int = 20

#
# extended private key
#
XPRV_MAINNET_PREFIX: bytes = b'\x04\x88\xAD\xE4'
XPRV_TESTNET_PREFX: bytes = b'\x04\x35\x83\x94'
XPRV_PREFIX_LIST: List[bytes] = [XPRV_MAINNET_PREFIX, XPRV_TESTNET_PREFX]
NETWORK_XPRV_PREFIX_DICT: Dict[Network, bytes] = {
    Network.MAINNET: XPRV_MAINNET_PREFIX,
    Network.TESTNET: XPRV_TESTNET_PREFX,
}
XPRV_PREFIX_NETWORK_DICT: Dict[bytes, Network] = {
    XPRV_MAINNET_PREFIX: Network.MAINNET,
    XPRV_TESTNET_PREFX: Network.TESTNET,
}

#
# extended public key
#
XPUB_MAINNET_PREFIX: bytes = b'\x04\x88\xB2\x1E'
XPUB_TESTNET_PREFIX: bytes = b'\x04\x35\x87\xCF'
XPUB_PREFIX_LIST: List[bytes] = [XPUB_MAINNET_PREFIX, XPUB_TESTNET_PREFIX]
NETWORK_XPUB_PREFIX_DICT: Dict[Network, bytes] = {
    Network.MAINNET: XPUB_MAINNET_PREFIX,
    Network.TESTNET: XPUB_TESTNET_PREFIX,
}
XPUB_PREFIX_NETWORK_DICT: Dict[bytes, Network] = {
    XPUB_MAINNET_PREFIX: Network.MAINNET,
    XPUB_TESTNET_PREFIX: Network.TESTNET,
}

#
# extended key
#
XKEY_BYTE_LENGTH: int = 78
XKEY_PREFIX_LIST: List[bytes] = XPRV_PREFIX_LIST + XPUB_PREFIX_LIST
#
# BIP32
#
BIP32_SEED_BYTE_LENGTH: int = 64
#
# BIP39
#
BIP39_ENTROPY_BIT_LENGTH_LIST: List[int] = [128, 160, 192, 224, 256]


class OpCode(bytes, Enum):
    """
    https://wiki.bitcoinsv.io/index.php/Opcodes_used_in_Bitcoin_Script
    """
    OP_0 = b'\x00'
    OP_FALSE = b'\x00'
    OP_PUSHDATA1 = b'\x4c'
    OP_PUSHDATA2 = b'\x4d'
    OP_PUSHDATA4 = b'\x4e'
    OP_1NEGATE = b'\x4f'
    OP_TRUE = b'\x51'
    OP_1 = b'\x51'
    OP_2 = b'\x52'
    OP_3 = b'\x53'
    OP_4 = b'\x54'
    OP_5 = b'\x55'
    OP_6 = b'\x56'
    OP_7 = b'\x57'
    OP_8 = b'\x58'
    OP_9 = b'\x59'
    OP_10 = b'\x5a'
    OP_11 = b'\x5b'
    OP_12 = b'\x5c'
    OP_13 = b'\x5d'
    OP_14 = b'\x5e'
    OP_15 = b'\x5f'
    OP_16 = b'\x60'
    # flow control
    OP_NOP = b'\x61'
    OP_VER = b'\x62'
    OP_IF = b'\x63'
    OP_NOTIF = b'\x64'
    OP_VERIF = b'\x65'
    OP_VERNOTIF = b'\x66'
    OP_ELSE = b'\x67'
    OP_ENDIF = b'\x68'
    OP_VERIFY = b'\x69'
    OP_RETURN = b'\x6a'
    # stack
    OP_TOALTSTACK = b'\x6b'
    OP_FROMALTSTACK = b'\x6c'
    OP_2DROP = b'\x6d'
    OP_2DUP = b'\x6e'
    OP_3DUP = b'\x6f'
    OP_2OVER = b'\x70'
    OP_2ROT = b'\x71'
    OP_2SWAP = b'\x72'
    OP_IFDUP = b'\x73'
    OP_DEPTH = b'\x74'
    OP_DROP = b'\x75'
    OP_DUP = b'\x76'
    OP_NIP = b'\x77'
    OP_OVER = b'\x78'
    OP_PICK = b'\x79'
    OP_ROLL = b'\x7a'
    OP_ROT = b'\x7b'
    OP_SWAP = b'\x7c'
    OP_TUCK = b'\x7d'
    # data manipulation
    OP_CAT = b'\x7e'
    OP_SPLIT = b'\x7f'
    OP_NUM2BIN = b'\x80'
    OP_BIN2NUM = b'\x81'
    OP_SIZE = b'\x82'
    # bitwise logic
    OP_INVERT = b'\x83'
    OP_AND = b'\x84'
    OP_OR = b'\x85'
    OP_XOR = b'\x86'
    OP_EQUAL = b'\x87'
    OP_EQUALVERIFY = b'\x88'
    # arithmetic
    OP_1ADD = b'\x8b'
    OP_1SUB = b'\x8c'
    OP_2MUL = b'\x8d'
    OP_2DIV = b'\x8e'
    OP_NEGATE = b'\x8f'
    OP_ABS = b'\x90'
    OP_NOT = b'\x91'
    OP_0NOTEQUAL = b'\x92'
    OP_ADD = b'\x93'
    OP_SUB = b'\x94'
    OP_MUL = b'\x95'
    OP_DIV = b'\x96'
    OP_MOD = b'\x97'
    OP_LSHIFT = b'\x98'
    OP_RSHIFT = b'\x99'
    OP_BOOLAND = b'\x9a'
    OP_BOOLOR = b'\x9b'
    OP_NUMEQUAL = b'\x9c'
    OP_NUMEQUALVERIFY = b'\x9d'
    OP_NUMNOTEQUAL = b'\x9e'
    OP_LESSTHAN = b'\x9f'
    OP_GREATERTHAN = b'\xa0'
    OP_LESSTHANOREQUAL = b'\xa1'
    OP_GREATERTHANOREQUAL = b'\xa2'
    OP_MIN = b'\xa3'
    OP_MAX = b'\xa4'
    OP_WITHIN = b'\xa5'
    # cryptography
    OP_RIPEMD160 = b'\xa6'
    OP_SHA1 = b'\xa7'
    OP_SHA256 = b'\xa8'
    OP_HASH160 = b'\xa9'
    OP_HASH256 = b'\xaa'
    OP_CODESEPARATOR = b'\xab'
    OP_CHECKSIG = b'\xac'
    OP_CHECKSIGVERIFY = b'\xad'
    OP_CHECKMULTISIG = b'\xae'
    OP_CHECKMULTISIGVERIFY = b'\xaf'
    # reserved words
    OP_RESERVED = b'\x50'
    OP_RESERVED1 = b'\x89'
    OP_RESERVED2 = b'\x8a'
    OP_NOP1 = b'\xb0'
    OP_NOP2 = b'\xb1'
    OP_NOP3 = b'\xb2'
    OP_NOP4 = b'\xb3'
    OP_NOP5 = b'\xb4'
    OP_NOP6 = b'\xb5'
    OP_NOP7 = b'\xb6'
    OP_NOP8 = b'\xb7'
    OP_NOP9 = b'\xb8'
    OP_NOP10 = b'\xb9'
    OP_NOP11 = b'\xba'
    OP_NOP12 = b'\xbb'
    OP_NOP13 = b'\xbc'
    OP_NOP14 = b'\xbd'
    OP_NOP15 = b'\xbe'
    OP_NOP16 = b'\xbf'
    OP_NOP17 = b'\xc0'
    OP_NOP18 = b'\xc1'
    OP_NOP19 = b'\xc2'
    OP_NOP20 = b'\xc3'
    OP_NOP21 = b'\xc4'
    OP_NOP22 = b'\xc5'
    OP_NOP23 = b'\xc6'
    OP_NOP24 = b'\xc7'
    OP_NOP25 = b'\xc8'
    OP_NOP26 = b'\xc9'
    OP_NOP27 = b'\xca'
    OP_NOP28 = b'\xcb'
    OP_NOP29 = b'\xcc'
    OP_NOP30 = b'\xcd'
    OP_NOP31 = b'\xce'
    OP_NOP32 = b'\xcf'
    OP_NOP33 = b'\xd0'
    OP_NOP34 = b'\xd1'
    OP_NOP35 = b'\xd2'
    OP_NOP36 = b'\xd3'
    OP_NOP37 = b'\xd4'
    OP_NOP38 = b'\xd5'
    OP_NOP39 = b'\xd6'
    OP_NOP40 = b'\xd7'
    OP_NOP41 = b'\xd8'
    OP_NOP42 = b'\xd9'
    OP_NOP43 = b'\xda'
    OP_NOP44 = b'\xdb'
    OP_NOP45 = b'\xdc'
    OP_NOP46 = b'\xdd'
    OP_NOP47 = b'\xde'
    OP_NOP48 = b'\xdf'
    OP_NOP49 = b'\xe0'
    OP_NOP50 = b'\xe1'
    OP_NOP51 = b'\xe2'
    OP_NOP52 = b'\xe3'
    OP_NOP53 = b'\xe4'
    OP_NOP54 = b'\xe5'
    OP_NOP55 = b'\xe6'
    OP_NOP56 = b'\xe7'
    OP_NOP57 = b'\xe8'
    OP_NOP58 = b'\xe9'
    OP_NOP59 = b'\xea'
    OP_NOP60 = b'\xeb'
    OP_NOP61 = b'\xec'
    OP_NOP62 = b'\xed'
    OP_NOP63 = b'\xee'
    OP_NOP64 = b'\xef'
    OP_NOP65 = b'\xf0'
    OP_NOP66 = b'\xf1'
    OP_NOP67 = b'\xf2'
    OP_NOP68 = b'\xf3'
    OP_NOP69 = b'\xf4'
    OP_NOP70 = b'\xf5'
    OP_NOP71 = b'\xf6'
    OP_NOP72 = b'\xf7'
    OP_NOP73 = b'\xf8'
    OP_NOP77 = b'\xfc'
    # template matching params
    OP_SMALLDATA = b'\xf9'
    OP_SMALLINTEGER = b'\xfa'
    OP_PUBKEYS = b'\xfb'
    OP_PUBKEYHASH = b'\xfd'
    OP_PUBKEY = b'\xfe'
    # invalid opcode
    OP_INVALIDOPCODE = b'\xff'


OPCODE_VALUE_NAME_DICT: Dict[bytes, str] = {item.value: item.name for item in OpCode}
OPCODE_VALUE_NAME_DICT[b'\x00'] = 'OP_0'
