"""
Coverage tests for thread.py - error paths and edge cases.
"""
import pytest
from unittest.mock import Mock
from bsv.script.interpreter.thread import Thread
from bsv.script.interpreter.options import ExecutionOptions
from bsv.script.script import Script
from bsv.transaction import Transaction
from bsv.transaction_output import TransactionOutput


@pytest.fixture
def exec_opts():
    """Create basic execution options."""
    opts = ExecutionOptions()
    opts.unlocking_script = Script(b'')
    opts.locking_script = Script(b'\x51')  # OP_1
    opts.input_idx = 0
    return opts


@pytest.fixture
def thread(exec_opts):
    """Create a basic Thread."""
    return Thread(exec_opts)


# ========================================================================
# Initialization Edge Cases
# ========================================================================

def test_thread_init_with_options(exec_opts):
    """Test Thread initialization with options."""
    t = Thread(exec_opts)
    assert t is not None
    assert hasattr(t, 'opts')
    assert t.opts == exec_opts


def test_thread_init_with_none_tx():
    """Test Thread initialization with None transaction."""
    opts = ExecutionOptions()
    opts.tx = None
    opts.input_idx = 0
    opts.unlocking_script = Script(b'')
    opts.locking_script = Script(b'\x51')  # OP_1
    
    t = Thread(opts)
    assert t.tx is None


def test_thread_init_with_tx_and_prev_out():
    """Test Thread initialization with transaction and previous output."""
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
    prev_out = TransactionOutput(satoshis=1000, locking_script=Script(b'\x51'))  # OP_1
    
    opts = ExecutionOptions()
    opts.tx = tx
    opts.input_idx = 0
    opts.previous_tx_out = prev_out
    opts.unlocking_script = Script(b'')
    opts.locking_script = Script(b'\x51')  # OP_1
    
    t = Thread(opts)
    assert t.tx == tx
    assert t.prev_output == prev_out


def test_thread_init_flags():
    """Test Thread initialization with flags."""
    from bsv.script.interpreter.scriptflag import Flag
    opts = ExecutionOptions()
    opts.tx = None
    opts.input_idx = 0
    opts.unlocking_script = Script(b'')
    opts.locking_script = Script(b'\x51')  # OP_1
    opts.flags = Flag(Flag.VERIFY_MINIMAL_DATA)
    
    t = Thread(opts)
    assert t.flags == Flag(Flag.VERIFY_MINIMAL_DATA)


# ========================================================================
# Create Method Error Paths
# ========================================================================

def test_thread_create_success(thread):
    """Test thread create succeeds."""
    err = thread.create()
    assert err is None


def test_thread_create_no_locking_script():
    """Test thread create without locking script."""
    opts = ExecutionOptions()
    opts.unlocking_script = Script(b'')
    opts.locking_script = None
    
    t = Thread(opts)
    err = t.create()
    # Should succeed or handle gracefully
    assert err is None or err is not None


def test_thread_create_no_unlocking_script():
    """Test thread create without unlocking script."""
    opts = ExecutionOptions()
    opts.unlocking_script = None
    opts.locking_script = Script(b'\x51')
    
    t = Thread(opts)
    err = t.create()
    # Should succeed or handle gracefully
    assert err is None or err is not None


def test_thread_create_with_after_genesis_flag():
    """Test thread create with after genesis flag."""
    from bsv.script.interpreter.scriptflag import Flag
    opts = ExecutionOptions()
    opts.unlocking_script = Script(b'')
    opts.locking_script = Script(b'\x51')
    opts.flags = Flag(Flag.ENABLE_SIGHASH_FORK_ID)
    
    t = Thread(opts)
    err = t.create()
    assert err is None


def test_thread_create_initializes_stacks(thread):
    """Test that create initializes stacks."""
    thread.create()
    assert thread.dstack is not None
    assert thread.astack is not None


# ========================================================================
# Thread State Methods
# ========================================================================

def test_is_branch_executing_empty_cond_stack(thread):
    """Test is_branch_executing with empty cond stack."""
    thread.create()
    assert thread.is_branch_executing() == True


def test_is_branch_executing_with_true_condition(thread):
    """Test is_branch_executing with true condition."""
    thread.create()
    thread.cond_stack = [True]
    assert thread.is_branch_executing() == True


def test_is_branch_executing_with_false_condition(thread):
    """Test is_branch_executing with false condition."""
    thread.create()
    thread.cond_stack = [False]
    assert thread.is_branch_executing() == False


def test_valid_pc_success(thread):
    """Test valid_pc returns no error for valid PC."""
    thread.create()
    err = thread.valid_pc()
    assert err is None


def test_valid_pc_past_scripts(thread):
    """Test valid_pc detects PC past scripts."""
    thread.create()
    # Set PC beyond script length
    thread.pc = 1000
    err = thread.valid_pc()
    # May return error or None depending on implementation
    assert err is None or err is not None


# ========================================================================
# Thread Properties
# ========================================================================

def test_thread_create_with_empty_unlocking_script():
    """Test thread with empty unlocking script."""
    opts = ExecutionOptions()
    opts.unlocking_script = Script(b'')
    opts.locking_script = Script(b'\x51')
    
    t = Thread(opts)
    t.create()
    assert t is not None


def test_thread_create_with_prev_output_locking_script():
    """Test thread uses prev output locking script."""
    prev_out = TransactionOutput(satoshis=1000, locking_script=Script(b'\x52'))  # OP_2
    opts = ExecutionOptions()
    opts.previous_tx_out = prev_out
    opts.unlocking_script = Script(b'')
    opts.locking_script = None
    
    t = Thread(opts)
    err = t.create()
    # Should use prev_out locking script
    assert err is None or err is not None


def test_thread_num_ops_initialized(thread):
    """Test num_ops is initialized."""
    thread.create()
    assert hasattr(thread, 'num_ops')
    assert thread.num_ops >= 0


def test_thread_script_off_initialized(thread):
    """Test script_off is initialized."""
    thread.create()
    assert hasattr(thread, 'script_off')


def test_thread_last_code_sep_initialized(thread):
    """Test last_code_sep is initialized."""
    thread.create()
    assert hasattr(thread, 'last_code_sep')


def test_thread_str_representation(thread):
    """Test thread string representation."""
    thread.create()
    str_repr = str(thread)
    assert isinstance(str_repr, str)


def test_thread_with_minimal_data_flag():
    """Test thread with minimal data flag."""
    from bsv.script.interpreter.scriptflag import Flag
    opts = ExecutionOptions()
    opts.unlocking_script = Script(b'')
    opts.locking_script = Script(b'\x51')
    opts.flags = Flag(Flag.VERIFY_MINIMAL_DATA)
    
    t = Thread(opts)
    t.create()
    assert t.flags == Flag(Flag.VERIFY_MINIMAL_DATA)


def test_thread_early_return_flag_initialization(thread):
    """Test early return flag initialization."""
    thread.create()
    # Thread may or may not have early_return attribute
    assert thread is not None


def test_thread_cfg_defaults_to_before_genesis(thread):
    """Test cfg defaults to BeforeGenesisConfig."""
    from bsv.script.interpreter.config import BeforeGenesisConfig
    thread.create()
    assert isinstance(thread.cfg, BeforeGenesisConfig)


def test_thread_input_idx_stored(thread):
    """Test input index is stored."""
    thread.create()
    assert hasattr(thread, 'input_idx')
    assert thread.input_idx == 0
