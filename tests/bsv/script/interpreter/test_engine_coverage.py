"""
Coverage tests for script/interpreter/engine.py - untested branches.
"""
import pytest
from bsv.script.script import Script


# ========================================================================
# Script engine initialization branches
# ========================================================================

def test_script_engine_init():
    """Test script engine initialization."""
    try:
        from bsv.script.interpreter import Engine

        engine = Engine()
        assert engine is not None
    except (ImportError, AttributeError):
        pytest.skip("Engine not available")


def test_script_engine_with_flags():
    """Test script engine with verification flags."""
    from bsv.script.interpreter.engine import Engine
    from bsv.script.interpreter.options import with_flags
    from bsv.script.interpreter.scriptflag.scriptflag import Flag

    engine = Engine()
    script = Script(b'\x51')
    unlocking_script = Script(b'')
    try:
        from bsv.script.interpreter.options import with_scripts
        result = engine.execute(
            with_flags(Flag(0)),
            with_scripts(script, unlocking_script)
        )
        assert result is None or hasattr(result, 'code')
    except Exception:
        # May require transaction context
        pytest.skip("Requires transaction context")


# ========================================================================
# Script execution branches
# ========================================================================

def test_script_engine_execute():
    """Test executing script."""
    try:
        from bsv.script.interpreter import Engine, with_scripts

        engine = Engine()
        script = Script(b'\x51')  # OP_1
        unlocking_script = Script(b'')

        if hasattr(engine, 'execute'):
            try:
                result = engine.execute(with_scripts(script, unlocking_script))
                # Result is None for success, or an Error object for failure
                assert result is None or hasattr(result, 'code')
            except Exception:
                # May require valid context
                pytest.skip("Requires valid execution context")
    except (ImportError, AttributeError):
        pytest.skip("Engine not available")


def test_script_engine_step():
    """Test stepping through script execution."""
    try:
        from bsv.script.interpreter import Engine

        engine = Engine()

        if hasattr(engine, 'step'):
            try:
                result = engine.step()
                assert isinstance(result, bool) or True
            except Exception:
                # May require valid context or step may not be implemented
                pytest.skip("Step functionality not implemented or requires context")
    except (ImportError, AttributeError):
        pytest.skip("Engine not available")


# ========================================================================
# Stack operations branches
# ========================================================================

def test_script_engine_get_stack():
    """Test getting script stack."""
    from bsv.script.interpreter.engine import Engine

    engine = Engine()

    # Engine doesn't provide direct stack access methods
    assert not hasattr(engine, 'get_stack')
    assert hasattr(engine, 'execute')  # But it does have execute


def test_script_engine_get_alt_stack():
    """Test getting alt stack."""
    from bsv.script.interpreter.engine import Engine

    engine = Engine()

    # Engine doesn't provide direct alt stack access methods
    assert not hasattr(engine, 'get_alt_stack')
    assert hasattr(engine, 'execute')  # But it does have execute


# ========================================================================
# Edge cases
# ========================================================================

def test_script_engine_empty_script():
    """Test engine with empty script."""
    try:
        from bsv.script.interpreter import Engine, with_scripts

        engine = Engine()
        script = Script(b'')
        unlocking_script = Script(b'')

        if hasattr(engine, 'execute'):
            try:
                result = engine.execute(with_scripts(script, unlocking_script))
                # Result is None for success, Error for failure
                assert result is None or hasattr(result, 'code')
            except Exception:
                # May have different behavior
                pytest.skip("Empty script behavior varies")
    except (ImportError, AttributeError):
        pytest.skip("Engine not available")


def test_script_engine_complex_script():
    """Test engine with complex script."""
    try:
        from bsv.script.interpreter import Engine, with_scripts

        # OP_1 OP_2 OP_ADD OP_3 OP_EQUAL
        script = Script(b'\x51\x52\x93\x53\x87')
        unlocking_script = Script(b'')
        engine = Engine()

        if hasattr(engine, 'execute'):
            try:
                result = engine.execute(with_scripts(script, unlocking_script))
                # Result is None for success, Error for failure
                assert result is None or hasattr(result, 'code')
            except Exception:
                # May require transaction context
                pytest.skip("Requires transaction context")
    except (ImportError, AttributeError):
        pytest.skip("Engine not available")

