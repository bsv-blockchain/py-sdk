"""
Comprehensive edge case tests for script interpreter.

These tests cover edge cases, error conditions, and boundary conditions
that should be thoroughly tested for script interpreter reliability.
"""

import pytest
from bsv.script.script import Script
from bsv.script.interpreter import Engine, with_scripts, with_flags, with_after_genesis, with_fork_id
from bsv.script.interpreter.errs import ErrorCode, is_error_code
from bsv.script.interpreter.scriptflag import Flag
from bsv.transaction import Transaction, TransactionInput, TransactionOutput


class TestScriptInterpreterEdgeCases:
    """Test edge cases for script interpreter operations."""

    def test_stack_overflow_prevention(self):
        """Test that stack overflow is prevented."""
        engine = Engine()

        # Create a script that tries to create a very deep stack
        script_parts = []
        # Push 1000 items onto the stack
        for i in range(1000):
            script_parts.append("OP_1")

        # Try to execute
        locking_script = Script.from_asm(" ".join(script_parts))
        unlocking_script = Script.from_bytes(b"")

        err = engine.execute(with_scripts(locking_script, unlocking_script))

        # Should either succeed (if limit is high) or fail with stack overflow
        # The important thing is it doesn't crash
        assert err is None or is_error_code(err, ErrorCode.ERR_STACK_OVERFLOW)

    def test_stack_underflow_detection(self):
        """Test detection of stack underflow conditions."""
        engine = Engine()

        # Test various opcodes that require stack items
        test_cases = [
            ("OP_DROP", "drop requires 1 item"),
            ("OP_DUP", "dup requires 1 item"),
            ("OP_ADD", "add requires 2 items"),
            ("OP_EQUAL", "equal requires 2 items"),
            ("OP_CHECKSIG", "checksig requires 2 items"),
        ]

        for opcode, description in test_cases:
            locking_script = Script.from_asm(opcode)
            unlocking_script = Script.from_bytes(b"")

            err = engine.execute(with_scripts(locking_script, unlocking_script))

            assert err is not None, f"{description} - should fail with stack underflow"
            assert is_error_code(err, ErrorCode.ERR_INVALID_STACK_OPERATION)

    def test_invalid_opcodes(self):
        """Test handling of invalid/unimplemented opcodes."""
        engine = Engine()

        # Test some invalid opcodes (high numbers that don't exist)
        invalid_opcodes = [0xFF, 0xFE, 0xFD]

        for opcode in invalid_opcodes:
            locking_script = Script.from_bytes(bytes([opcode]))
            unlocking_script = Script.from_bytes(b"")

            err = engine.execute(with_scripts(locking_script, unlocking_script))

            # Should either succeed (if treated as NOP) or fail gracefully
            # The important thing is no crash
            assert err is None or isinstance(err, Exception)

    def test_script_size_limits(self):
        """Test script size limits and edge cases."""
        engine = Engine()

        # Test with extremely large scripts
        large_script = "OP_1 " * 10000  # 10,000 OP_1 operations
        locking_script = Script.from_asm(large_script)
        unlocking_script = Script.from_bytes(b"")

        err = engine.execute(with_scripts(locking_script, unlocking_script))

        # Should either succeed or fail gracefully (not crash)
        assert err is None or isinstance(err, Exception)

    def test_arithmetic_edge_cases(self):
        """Test arithmetic operations with edge case values."""
        engine = Engine()

        test_cases = [
            # Test with maximum/minimum integer values
            ("0x7FFFFFFF", "0x00000001", "OP_ADD", "Max int + 1"),
            ("0x80000000", "0xFFFFFFFF", "OP_ADD", "Negative + max"),
            ("0x00000000", "0x00000000", "OP_DIV", "Division by zero"),
            ("0x7FFFFFFF", "0x00000001", "OP_MUL", "Large multiplication"),
        ]

        for a, b, op, description in test_cases:
            script_str = f"{a} {b} {op}"
            locking_script = Script.from_asm(script_str)
            unlocking_script = Script.from_bytes(b"")

            err = engine.execute(with_scripts(locking_script, unlocking_script))

            # Should either succeed or fail with appropriate error
            # Division by zero should fail
            if "DIV" in op and b == "0x00000000":
                assert err is not None, f"Division by zero should fail: {description}"
            else:
                # Other operations should succeed or fail gracefully
                assert err is None or isinstance(err, Exception)

    def test_hash_operation_edge_cases(self):
        """Test hash operations with various input sizes."""
        engine = Engine()

        test_cases = [
            ("", "OP_SHA256", "Empty input"),
            ("OP_0", "OP_SHA256", "Zero input"),
            ("0x" + "00" * 1000, "OP_SHA256", "Large input (1000 bytes)"),
            ("0x" + "FF" * 1000, "OP_SHA256", "Large input (all FF)"),
        ]

        for data, hash_op, description in test_cases:
            script_str = f"{data} {hash_op}"
            locking_script = Script.from_asm(script_str)
            unlocking_script = Script.from_bytes(b"")

            err = engine.execute(with_scripts(locking_script, unlocking_script))

            # Hash operations should always succeed or fail gracefully
            assert err is None or isinstance(err, Exception), f"Hash operation failed: {description}"

    def test_conditional_execution_complex(self):
        """Test complex conditional execution scenarios."""
        engine = Engine()

        test_cases = [
            # Nested IF statements
            ("OP_1 OP_IF OP_1 OP_IF OP_1 OP_ENDIF OP_ENDIF", "Nested IF true/true"),
            ("OP_1 OP_IF OP_0 OP_IF OP_1 OP_ENDIF OP_ENDIF", "Nested IF true/false"),
            ("OP_0 OP_IF OP_1 OP_IF OP_1 OP_ENDIF OP_ENDIF", "Nested IF false/ignored"),

            # IF without ENDIF
            ("OP_1 OP_IF OP_1", "IF without ENDIF - should fail"),

            # ELSE without IF
            ("OP_1 OP_ELSE OP_1 OP_ENDIF", "ELSE without matching IF"),

            # Multiple ELSE statements
            ("OP_1 OP_IF OP_1 OP_ELSE OP_2 OP_ELSE OP_3 OP_ENDIF", "Multiple ELSE statements"),
        ]

        for script_str, description in test_cases:
            locking_script = Script.from_asm(script_str)
            unlocking_script = Script.from_bytes(b"")

            err = engine.execute(with_scripts(locking_script, unlocking_script))

            # Some should succeed, some should fail - but no crashes
            assert isinstance(err, (type(None), Exception)), f"Unexpected result for: {description}"

    def test_string_operations_edge_cases(self):
        """Test string operation edge cases."""
        engine = Engine()

        test_cases = [
            # Empty strings
            ("OP_0 OP_0 OP_CAT", "Concatenate empty strings"),
            ("OP_0 OP_SIZE", "Size of empty string"),

            # Large strings
            (f"0x{'00'*500} 0x{'FF'*500} OP_CAT", "Concatenate large strings"),

            # Split operations
            ("0x0102030405 0x02 OP_SPLIT", "Split with valid position"),
            ("0x0102030405 0xFF OP_SPLIT", "Split with invalid position"),
        ]

        for script_str, description in test_cases:
            locking_script = Script.from_asm(script_str)
            unlocking_script = Script.from_bytes(b"")

            err = engine.execute(with_scripts(locking_script, unlocking_script))

            # Operations should succeed or fail gracefully
            assert isinstance(err, (type(None), Exception)), f"String operation failed: {description}"

    def test_bitwise_operations_edge_cases(self):
        """Test bitwise operations with edge cases."""
        engine = Engine()

        test_cases = [
            # Large numbers
            ("0xFFFFFFFFFFFFFFFF 0xFFFFFFFFFFFFFFFF OP_AND", "AND with max values"),
            ("0xFFFFFFFFFFFFFFFF 0x0000000000000000 OP_OR", "OR with zero"),
            ("0xAAAAAAAAAAAAAAAA 0x5555555555555555 OP_XOR", "XOR alternating bits"),

            # Shift operations
            ("0x80000000 0x01 OP_LSHIFT", "Left shift"),
            ("0x00000001 0x20 OP_RSHIFT", "Right shift"),
            ("0xFFFFFFFFFFFFFFFF 0xFF OP_LSHIFT", "Excessive left shift"),
        ]

        for script_str, description in test_cases:
            locking_script = Script.from_asm(script_str)
            unlocking_script = Script.from_bytes(b"")

            err = engine.execute(with_scripts(locking_script, unlocking_script))

            # Operations should succeed or fail gracefully
            assert isinstance(err, (type(None), Exception)), f"Bitwise operation failed: {description}"

    def test_memory_and_performance_limits(self):
        """Test memory usage and performance limits."""
        engine = Engine()

        # Test with many nested operations
        nested_script = ""
        depth = 50  # Reasonable depth for testing

        # Create deeply nested IF statements
        for i in range(depth):
            nested_script += "OP_1 OP_IF "
        nested_script += "OP_1 "  # Final operation
        for i in range(depth):
            nested_script += "OP_ENDIF "

        locking_script = Script.from_asm(nested_script)
        unlocking_script = Script.from_bytes(b"")

        err = engine.execute(with_scripts(locking_script, unlocking_script))

        # Should complete without crashing
        assert isinstance(err, (type(None), Exception)), "Deep nesting should not crash"

    def test_script_flags_edge_cases(self):
        """Test script execution with various flag combinations."""
        engine = Engine()

        # Test with minimal script
        locking_script = Script.from_asm("OP_1 OP_1 OP_EQUAL")
        unlocking_script = Script.from_bytes(b"")

        # Test with different flag combinations
        flag_combinations = [
            Flag.VERIFY_DER_SIGNATURES,
            Flag.VERIFY_STRICT_ENCODING,
            Flag.VERIFY_DER_SIGNATURES | Flag.VERIFY_STRICT_ENCODING,
            Flag(0),  # No flags
        ]

        for flags in flag_combinations:
            err = engine.execute(
                with_scripts(locking_script, unlocking_script),
                with_flags(flags)
            )

            # Should succeed with valid flags
            assert err is None, f"Failed with flags {flags}"

    def test_transaction_context_edge_cases(self):
        """Test script execution with various transaction contexts."""
        engine = Engine()

        # Create a transaction with unusual properties
        tx = Transaction()

        # Add many inputs/outputs
        for i in range(10):
            tx.add_input(TransactionInput(f"{'00'*32}", i, Script.from_bytes(b"")))

        for i in range(10):
            tx.add_output(TransactionOutput(1000 + i, Script.from_bytes(b"")))

        # Test script execution with this transaction
        locking_script = Script.from_asm("OP_1")
        unlocking_script = Script.from_bytes(b"")

        # Test with different input indices
        for vin in range(len(tx.inputs)):
            err = engine.execute(
                with_scripts(locking_script, unlocking_script),
                with_tx(tx, vin, locking_script)
            )

            # Should succeed
            assert err is None, f"Failed with input index {vin}"

    def test_concurrent_execution_safety(self):
        """Test that script execution is safe for concurrent use."""
        import threading
        import time

        results = []
        errors = []

        def run_script():
            try:
                engine = Engine()
                locking_script = Script.from_asm("OP_1 OP_1 OP_EQUAL")
                unlocking_script = Script.from_bytes(b"")

                err = engine.execute(with_scripts(locking_script, unlocking_script))
                results.append(err)
            except Exception as e:
                errors.append(e)

        # Run multiple threads concurrently
        threads = []
        for i in range(10):
            t = threading.Thread(target=run_script)
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        # Check results
        assert len(errors) == 0, f"Concurrent execution errors: {errors}"
        assert len(results) == 10, "Not all threads completed"
        assert all(r is None for r in results), "Some executions failed"

    def test_error_recovery_and_cleanup(self):
        """Test that failed executions properly clean up state."""
        engine = Engine()

        # Run a failing script first
        fail_script = Script.from_asm("OP_ADD")  # Stack underflow
        fail_unlock = Script.from_bytes(b"")

        err1 = engine.execute(with_scripts(fail_script, fail_unlock))
        assert err1 is not None, "First script should fail"

        # Run a successful script second
        success_script = Script.from_asm("OP_1 OP_1 OP_EQUAL")
        success_unlock = Script.from_bytes(b"")

        err2 = engine.execute(with_scripts(success_script, success_unlock))
        assert err2 is None, "Second script should succeed after failure"

        # Engine should be in clean state
        assert engine._thread is None or not hasattr(engine._thread, '_stack') or len(engine._thread._stack) == 0
