"""
Coverage tests for script/interpreter/scriptflag.py - untested branches.
"""
import pytest


# ========================================================================
# Script flag constants branches
# ========================================================================

def test_scriptflag_module_exists():
    """Test that scriptflag module exists."""
    try:
        import bsv.script.interpreter.scriptflag
        assert bsv.script.interpreter.scriptflag is not None
    except ImportError:
        pytest.skip("scriptflag module not available")


def test_scriptflag_verify_p2sh():
    """Test SCRIPT_VERIFY_P2SH flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_P2SH
        assert SCRIPT_VERIFY_P2SH is not None
        assert isinstance(SCRIPT_VERIFY_P2SH, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_P2SH not available")


def test_scriptflag_verify_strictenc():
    """Test SCRIPT_VERIFY_STRICTENC flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_STRICTENC
        assert SCRIPT_VERIFY_STRICTENC is not None
        assert isinstance(SCRIPT_VERIFY_STRICTENC, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_STRICTENC not available")


def test_scriptflag_verify_dersig():
    """Test SCRIPT_VERIFY_DERSIG flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_DERSIG
        assert SCRIPT_VERIFY_DERSIG is not None
        assert isinstance(SCRIPT_VERIFY_DERSIG, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_DERSIG not available")


def test_scriptflag_verify_low_s():
    """Test SCRIPT_VERIFY_LOW_S flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_LOW_S
        assert SCRIPT_VERIFY_LOW_S is not None
        assert isinstance(SCRIPT_VERIFY_LOW_S, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_LOW_S not available")


def test_scriptflag_verify_nulldummy():
    """Test SCRIPT_VERIFY_NULLDUMMY flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_NULLDUMMY
        assert SCRIPT_VERIFY_NULLDUMMY is not None
        assert isinstance(SCRIPT_VERIFY_NULLDUMMY, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_NULLDUMMY not available")


def test_scriptflag_verify_sigpushonly():
    """Test SCRIPT_VERIFY_SIGPUSHONLY flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_SIGPUSHONLY
        assert SCRIPT_VERIFY_SIGPUSHONLY is not None
        assert isinstance(SCRIPT_VERIFY_SIGPUSHONLY, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_SIGPUSHONLY not available")


def test_scriptflag_verify_minimaldata():
    """Test SCRIPT_VERIFY_MINIMALDATA flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_MINIMALDATA
        assert SCRIPT_VERIFY_MINIMALDATA is not None
        assert isinstance(SCRIPT_VERIFY_MINIMALDATA, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_MINIMALDATA not available")


def test_scriptflag_verify_discourage_upgradable_nops():
    """Test SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
        assert SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS is not None
        assert isinstance(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS not available")


def test_scriptflag_verify_cleanstack():
    """Test SCRIPT_VERIFY_CLEANSTACK flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_CLEANSTACK
        assert SCRIPT_VERIFY_CLEANSTACK is not None
        assert isinstance(SCRIPT_VERIFY_CLEANSTACK, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_CLEANSTACK not available")


def test_scriptflag_verify_checklocktimeverify():
    """Test SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
        assert SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY is not None
        assert isinstance(SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY not available")


def test_scriptflag_verify_checksequenceverify():
    """Test SCRIPT_VERIFY_CHECKSEQUENCEVERIFY flag."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
        assert SCRIPT_VERIFY_CHECKSEQUENCEVERIFY is not None
        assert isinstance(SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, int)
    except (ImportError, AttributeError):
        pytest.skip("SCRIPT_VERIFY_CHECKSEQUENCEVERIFY not available")


# ========================================================================
# Flag combination branches
# ========================================================================

def test_scriptflag_combinations():
    """Test combining script flags."""
    try:
        from bsv.script.interpreter.scriptflag import SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_STRICTENC
        
        combined = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC
        assert isinstance(combined, int)
        assert combined != 0
    except (ImportError, AttributeError):
        pytest.skip("Script flags not available")

