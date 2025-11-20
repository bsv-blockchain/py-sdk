"""
Tests for script interpreter engine.

Ported from go-sdk/script/interpreter/engine_test.go
"""

import pytest
from bsv.script.script import Script
from bsv.script.interpreter import Engine, with_scripts, with_after_genesis, with_fork_id
from bsv.script.interpreter.errs import ErrorCode, is_error_code


class TestEngine:
    """Test script interpreter engine."""

    def test_engine_creation(self):
        """Test that engine can be created and has expected default state."""
        engine = Engine()
        assert engine is not None, "Engine should be created successfully"
        
        # Verify engine can be created multiple times independently
        engine2 = Engine()
        assert engine2 is not None, "Multiple engines should be creatable"
        assert engine is not engine2, "Each Engine() call should create a new instance"

    def test_engine_execute_with_simple_scripts(self):
        """Test executing simple scripts with basic opcodes (OP_1 OP_EQUAL)."""
        engine = Engine()
        
        # Simple script: push 1, then check equality
        # Unlocking: OP_1 (pushes 1 onto stack)
        # Locking: OP_1 OP_EQUAL (pushes 1, then checks top two stack items are equal)
        locking_script = Script.from_asm("51 OP_EQUAL")  # OP_1 (0x51) OP_EQUAL
        unlocking_script = Script.from_asm("51")  # OP_1 (0x51)
        
        # This should succeed: stack will have [1, 1] then OP_EQUAL checks they match
        err = engine.execute(
            with_scripts(locking_script, unlocking_script),
        )
        
        # Engine should execute successfully (no error)
        assert err is None, f"Simple script execution should succeed, got error: {err}"
        
        # Test with another simple script for thoroughness
        engine2 = Engine()
        locking_script2 = Script.from_asm("52 OP_EQUAL")  # OP_2 OP_EQUAL
        unlocking_script2 = Script.from_asm("52")  # OP_2
        err2 = engine2.execute(with_scripts(locking_script2, unlocking_script2))
        assert err2 is None, f"OP_2 script execution should also succeed, got error: {err2}"

    def test_engine_execute_with_missing_scripts(self):
        """Test that engine returns ERR_INVALID_PARAMS when scripts are missing."""
        engine = Engine()
        
        # Missing scripts should return error
        from bsv.script.interpreter.options import ExecutionOptions
        _ = ExecutionOptions()
        
        # Empty options (no scripts) should be caught by validation
        err = engine.execute(lambda o: None)  # Empty options
        assert err is not None, "Engine should return error for missing scripts"
        assert is_error_code(err, ErrorCode.ERR_INVALID_PARAMS), \
            f"Expected ERR_INVALID_PARAMS for missing scripts, got {err.code}"

    def test_engine_with_after_genesis(self):
        """Test engine with after genesis flag."""
        engine = Engine()
        
        locking_script = Script.from_asm("51 OP_EQUAL")  # OP_1 OP_EQUAL
        unlocking_script = Script.from_asm("51")  # OP_1
        
        err = engine.execute(
            with_scripts(locking_script, unlocking_script),
            with_after_genesis(),
        )
        
        # Engine should execute successfully with after_genesis flag
        assert err is None

    def test_engine_with_fork_id(self):
        """Test engine with fork ID flag."""
        engine = Engine()

        locking_script = Script.from_asm("51 OP_EQUAL")  # OP_1 OP_EQUAL
        unlocking_script = Script.from_asm("51")  # OP_1

        err = engine.execute(
            with_scripts(locking_script, unlocking_script),
            with_fork_id(),
        )

        # Engine should execute successfully with fork_id flag
        assert err is None

    @pytest.mark.parametrize("nop_opcode", [
        "OP_NOP", "OP_NOP1", "OP_NOP2", "OP_NOP3", "OP_NOP4", "OP_NOP5",
        "OP_NOP6", "OP_NOP7", "OP_NOP8", "OP_NOP9", "OP_NOP10"
    ])
    def test_nop_opcodes_execution(self, nop_opcode):
        """Test that all NOP opcodes execute without errors."""
        engine = Engine()

        # Test script: push 1, execute NOP opcode, check equality
        locking_script = Script.from_asm(f"51 {nop_opcode} OP_EQUAL")  # OP_1 NOP_OP OP_EQUAL
        unlocking_script = Script.from_asm("51")  # OP_1

        err = engine.execute(
            with_scripts(locking_script, unlocking_script),
        )

        # NOP opcodes should not cause errors
        assert err is None

    def test_nop_opcodes_in_unlocking_script(self):
        """Test that NOP opcodes in unlocking script don't interfere with execution."""
        engine = Engine()

        # Test script with multiple NOP opcodes in unlocking script
        # NOPs should do nothing and allow the OP_1 to proceed normally
        locking_script = Script.from_asm("51 OP_EQUAL")  # OP_1 OP_EQUAL
        unlocking_script = Script.from_asm("OP_NOP1 OP_NOP5 OP_NOP10 51")  # NOPs then OP_1

        err = engine.execute(
            with_scripts(locking_script, unlocking_script),
        )

        # NOP opcodes should be no-ops and not cause errors
        assert err is None, f"NOP opcodes should not cause errors, got: {err}"
        
        # Test with NOPs in different positions
        engine2 = Engine()
        locking_script2 = Script.from_asm("51 OP_NOP2 OP_EQUAL")  # OP_1 NOP OP_EQUAL
        unlocking_script2 = Script.from_asm("51 OP_NOP3")  # OP_1 NOP
        err2 = engine2.execute(with_scripts(locking_script2, unlocking_script2))
        assert err2 is None, f"NOPs in locking script should also work, got: {err2}"

