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
        """Test that engine can be created."""
        engine = Engine()
        assert engine is not None

    def test_engine_execute_with_simple_scripts(self):
        """Test executing simple scripts."""
        engine = Engine()
        
        # Simple script: push 1, then check equality
        # Use hex format for data pushes
        locking_script = Script.from_asm("51 OP_EQUAL")  # OP_1 (0x51) OP_EQUAL
        unlocking_script = Script.from_asm("51")  # OP_1 (0x51)
        
        # This should work (basic structure test)
        # Note: Full opcode execution not yet implemented
        err = engine.execute(
            with_scripts(locking_script, unlocking_script),
        )
        
        # Engine should execute successfully (no error)
        assert err is None

    def test_engine_execute_with_missing_scripts(self):
        """Test that engine returns error for missing scripts."""
        engine = Engine()
        
        # Missing scripts should return error
        from bsv.script.interpreter.options import ExecutionOptions
        opts = ExecutionOptions()
        
        # This should be caught by validation
        err = engine.execute(lambda o: None)  # Empty options
        assert err is not None
        assert is_error_code(err, ErrorCode.ERR_INVALID_PARAMS)

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
        """Test NOP opcodes in unlocking script."""
        engine = Engine()

        # Test script with NOP opcodes in unlocking script
        locking_script = Script.from_asm("51 OP_EQUAL")  # OP_1 OP_EQUAL
        unlocking_script = Script.from_asm("OP_NOP1 OP_NOP5 OP_NOP10 51")  # NOPs then OP_1

        err = engine.execute(
            with_scripts(locking_script, unlocking_script),
        )

        # NOP opcodes in unlocking script should not cause errors
        assert err is None

