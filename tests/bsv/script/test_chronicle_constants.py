from bsv.constants import OPCODE_VALUE_NAME_DICT, TRANSACTION_VERSION_CHRONICLE, OpCode
from bsv.script.script import Script


def test_op_substr_constant():
    assert OpCode.OP_SUBSTR == b"\xb3"


def test_op_left_constant():
    assert OpCode.OP_LEFT == b"\xb4"


def test_op_right_constant():
    assert OpCode.OP_RIGHT == b"\xb5"


def test_op_lshiftnum_constant():
    assert OpCode.OP_LSHIFTNUM == b"\xb6"


def test_op_rshiftnum_constant():
    assert OpCode.OP_RSHIFTNUM == b"\xb7"


def test_nop_aliases_backward_compat():
    assert OpCode.OP_NOP4 == b"\xb3"
    assert OpCode.OP_NOP5 == b"\xb4"
    assert OpCode.OP_NOP6 == b"\xb5"
    assert OpCode.OP_NOP7 == b"\xb6"
    assert OpCode.OP_NOP8 == b"\xb7"


def test_opcode_value_name_dict():
    assert OPCODE_VALUE_NAME_DICT[b"\xb3"] == "OP_SUBSTR"
    assert OPCODE_VALUE_NAME_DICT[b"\xb4"] == "OP_LEFT"
    assert OPCODE_VALUE_NAME_DICT[b"\xb5"] == "OP_RIGHT"
    assert OPCODE_VALUE_NAME_DICT[b"\xb6"] == "OP_LSHIFTNUM"
    assert OPCODE_VALUE_NAME_DICT[b"\xb7"] == "OP_RSHIFTNUM"


def test_asm_round_trip_new_opcodes():
    for name in ["OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_LSHIFTNUM", "OP_RSHIFTNUM"]:
        script = Script.from_asm(name)
        assert script.to_asm() == name


def test_asm_nop_aliases_parse():
    """OP_NOP4-8 should parse to the same script as the new Chronicle names."""
    assert Script.from_asm("OP_NOP4").serialize() == Script.from_asm("OP_SUBSTR").serialize()
    assert Script.from_asm("OP_NOP5").serialize() == Script.from_asm("OP_LEFT").serialize()
    assert Script.from_asm("OP_NOP6").serialize() == Script.from_asm("OP_RIGHT").serialize()
    assert Script.from_asm("OP_NOP7").serialize() == Script.from_asm("OP_LSHIFTNUM").serialize()
    assert Script.from_asm("OP_NOP8").serialize() == Script.from_asm("OP_RSHIFTNUM").serialize()


def test_transaction_version_chronicle_constant():
    assert TRANSACTION_VERSION_CHRONICLE == 2
