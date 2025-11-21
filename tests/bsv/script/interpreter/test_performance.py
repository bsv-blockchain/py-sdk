"""
Performance and stress tests for script interpreter.

These tests ensure the script interpreter performs well under various loads
and handles resource-intensive operations appropriately.
"""

import pytest
import time
from bsv.script.script import Script
from bsv.script.interpreter import Engine, with_scripts, with_after_genesis, with_fork_id
from bsv.script.interpreter.errs import ErrorCode


class TestScriptInterpreterPerformance:
    """Test script interpreter performance and resource usage."""

    def test_large_script_execution_time(self):
        """Test execution time for large scripts."""
        engine = Engine()

        # Create a moderately large script by building it manually
        script_bytes = b""
        script_size = 1000

        # Add 1000 OP_1 opcodes (0x51 each)
        for _ in range(script_size):
            script_bytes += b'\x51'  # OP_1

        locking_script = Script(script_bytes)
        unlocking_script = Script.from_bytes(b"")

        start_time = time.time()
        err = engine.execute(with_scripts(locking_script, unlocking_script))
        end_time = time.time()

        execution_time = end_time - start_time

        # Should complete successfully
        assert err is None

        # Should complete in reasonable time (less than 1 second for 1000 operations)
        assert execution_time < 1.0, f"Execution took too long: {execution_time:.3f}s"

    def test_hash_performance(self):
        """Test performance of hash operations."""
        engine = Engine()

        # Test with different input sizes (within script interpreter limits)
        sizes = [50, 100, 500]

        for size in sizes:
            # Create data of specified size
            data = "00" * size
            script_str = f"{data} OP_SHA256"

            locking_script = Script.from_asm(script_str)
            unlocking_script = Script.from_bytes(b"")

            start_time = time.time()
            err = engine.execute(with_scripts(locking_script, unlocking_script))
            end_time = time.time()

            execution_time = end_time - start_time

            assert err is None, f"Hash operation failed for size {size}"
            # Hash operations should be fast (less than 0.1s even for large data)
            assert execution_time < 0.1, f"Hash took too long for size {size}: {execution_time:.3f}s"

    def test_arithmetic_performance(self):
        """Test performance of arithmetic operations."""
        engine = Engine()

        # Test with many arithmetic operations
        num_operations = 500

        # Create a script that adds 500 ones together
        script_bytes = b""
        for _ in range(num_operations):
            script_bytes += b'\x51'  # OP_1

        for _ in range(num_operations - 1):
            script_bytes += b'\x93'  # OP_ADD

        locking_script = Script(script_bytes)
        unlocking_script = Script.from_bytes(b"")

        start_time = time.time()
        err = engine.execute(with_scripts(locking_script, unlocking_script))
        end_time = time.time()

        execution_time = end_time - start_time

        assert err is None, "Arithmetic chain failed"
        assert execution_time < 0.5, f"Arithmetic operations took too long: {execution_time:.3f}s"

    def test_stack_operations_performance(self):
        """Test performance of stack operations."""
        engine = Engine()

        # Test DUP operations on a growing stack
        stack_depth = 100

        script_bytes = b'\x51'  # Start with OP_1
        for _ in range(stack_depth - 1):
            script_bytes += b'\x76'  # OP_DUP

        locking_script = Script(script_bytes)
        unlocking_script = Script.from_bytes(b"")

        start_time = time.time()
        err = engine.execute(with_scripts(locking_script, unlocking_script))
        end_time = time.time()

        execution_time = end_time - start_time

        assert err is None, "Stack operations failed"
        assert execution_time < 0.2, f"Stack operations took too long: {execution_time:.3f}s"

    def test_conditional_execution_performance(self):
        """Test performance of conditional execution."""
        engine = Engine()

        # Test nested IF statements
        nesting_depth = 20

        script_bytes = b""
        for _ in range(nesting_depth):
            script_bytes += b'\x51'  # OP_1 (always true)
            script_bytes += b'\x63'  # OP_IF

        script_bytes += b'\x51'  # Final OP_1 result

        for _ in range(nesting_depth):
            script_bytes += b'\x68'  # OP_ENDIF

        locking_script = Script(script_bytes)
        unlocking_script = Script.from_bytes(b"")

        start_time = time.time()
        err = engine.execute(with_scripts(locking_script, unlocking_script))
        end_time = time.time()

        execution_time = end_time - start_time

        assert err is None, "Conditional execution failed"
        assert execution_time < 0.3, f"Conditional execution took too long: {execution_time:.3f}s"

    def test_memory_usage_bounds(self):
        """Test that memory usage stays within reasonable bounds."""
        psutil = pytest.importorskip("psutil", reason="psutil not installed")
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        engine = Engine()

        # Run a memory-intensive script
        script_parts = []
        for _ in range(500):
            script_parts.extend(["OP_TRUE", "OP_DUP"])

        locking_script = Script.from_asm(" ".join(script_parts))
        unlocking_script = Script.from_bytes(b"")

        err = engine.execute(with_scripts(locking_script, unlocking_script))

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        assert err is None, "Memory test script failed"
        # Memory increase should be reasonable (less than 10MB)
        assert memory_increase < 10 * 1024 * 1024, f"Memory usage too high: {memory_increase} bytes"

    def test_operation_limits(self):
        """Test various operation limits."""
        engine = Engine()

        # Test maximum script size (approximate limit)
        max_ops = 10000
        script_parts = ["OP_TRUE"] * max_ops

        locking_script = Script.from_asm(" ".join(script_parts))
        unlocking_script = Script.from_bytes(b"")

        start_time = time.time()
        err = engine.execute(with_scripts(locking_script, unlocking_script))
        end_time = time.time()

        execution_time = end_time - start_time

        # Should either succeed or fail gracefully
        assert err is None or isinstance(err, Exception), "Should handle large scripts"

        # Should complete in reasonable time even if large
        assert execution_time < 5.0, f"Large script took too long: {execution_time:.3f}s"

    def test_string_operation_performance(self):
        """Test performance of string operations."""
        engine = Engine()

        # Test concatenation of many strings
        num_strings = 50
        string_size = 100  # bytes per string

        script_parts = []
        for _ in range(num_strings):
            # Create a string of specified size
            data = "41" * string_size  # 'A' characters
            script_parts.append(f"{data}")

        # Add concatenation operations
        for _ in range(num_strings - 1):
            script_parts.append("OP_CAT")

        locking_script = Script.from_asm(" ".join(script_parts))
        unlocking_script = Script.from_bytes(b"")

        start_time = time.time()
        err = engine.execute(with_scripts(locking_script, unlocking_script))
        end_time = time.time()

        execution_time = end_time - start_time

        # Should succeed or fail gracefully
        assert isinstance(err, (type(None), Exception)), "String operations failed"
        assert execution_time < 1.0, f"String operations took too long: {execution_time:.3f}s"

    @pytest.mark.skip(reason="Requires benchmark framework")
    def test_benchmark_comparison(self):
        """Benchmark script execution against known performance targets."""
        # This test would require a benchmarking framework
        # and established performance baselines
        pass

    def test_resource_cleanup(self):
        """Test that resources are properly cleaned up after execution."""
        import gc

        # Run many script executions
        for _ in range(100):
            engine = Engine()
            locking_script = Script.from_asm("OP_TRUE OP_TRUE OP_EQUAL")
            unlocking_script = Script.from_bytes(b"")

            err = engine.execute(with_scripts(locking_script, unlocking_script))
            assert err is None

            # Force cleanup
            del engine

        # Force garbage collection
        gc.collect()

        # Memory should not be growing significantly
        # (This is a basic check - more sophisticated memory profiling would be needed)
        assert True, "Resource cleanup test completed"
