"""
Execution options for script interpreter.

Ported from go-sdk/script/interpreter/options.go
"""

from typing import Callable, Optional, Protocol

from bsv.script.script import Script
from bsv.transaction import Transaction, TransactionOutput
from .scriptflag import Flag


class Debugger(Protocol):
    """Debugger interface for script execution."""

    def before_step(self) -> None:
        """Called before each step."""
        ...

    def after_step(self) -> None:
        """Called after each step."""
        ...


class State(Protocol):
    """State interface for script execution."""

    def data_stack(self) -> list:
        """Get data stack."""
        ...

    def alt_stack(self) -> list:
        """Get alt stack."""
        ...


class ExecutionOptions:
    """Execution options for script interpreter."""

    def __init__(self):
        self.locking_script: Optional[Script] = None
        self.unlocking_script: Optional[Script] = None
        self.previous_tx_out: Optional[TransactionOutput] = None
        self.tx: Optional[Transaction] = None
        self.input_idx: int = 0
        self.flags: Flag = Flag(0)
        self.debugger: Optional[Debugger] = None
        self.state: Optional[State] = None


ExecutionOptionFunc = Callable[[ExecutionOptions], None]


def with_tx(tx: Transaction, input_idx: int, prev_output: TransactionOutput) -> ExecutionOptionFunc:
    """Configure execution to run against a transaction."""
    def option(opts: ExecutionOptions) -> None:
        opts.tx = tx
        opts.previous_tx_out = prev_output
        opts.input_idx = input_idx
    return option


def with_scripts(locking_script: Script, unlocking_script: Script) -> ExecutionOptionFunc:
    """Configure execution to run against scripts."""
    def option(opts: ExecutionOptions) -> None:
        opts.locking_script = locking_script
        opts.unlocking_script = unlocking_script
    return option


def with_after_genesis() -> ExecutionOptionFunc:
    """Configure execution to operate in after-genesis context."""
    def option(opts: ExecutionOptions) -> None:
        from .scriptflag import Flag
        opts.flags = opts.flags.add_flag(Flag.UTXO_AFTER_GENESIS)
    return option


def with_fork_id() -> ExecutionOptionFunc:
    """Configure execution to allow fork ID."""
    def option(opts: ExecutionOptions) -> None:
        from .scriptflag import Flag
        opts.flags = opts.flags.add_flag(Flag.ENABLE_SIGHASH_FORK_ID)
    return option


def with_p2sh() -> ExecutionOptionFunc:
    """Configure execution to allow P2SH output."""
    def option(opts: ExecutionOptions) -> None:
        from .scriptflag import Flag
        opts.flags = opts.flags.add_flag(Flag.BIP16)
    return option


def with_flags(flags: Flag) -> ExecutionOptionFunc:
    """Configure execution with provided flags."""
    def option(opts: ExecutionOptions) -> None:
        opts.flags = opts.flags.add_flag(flags)
    return option


def with_debugger(debugger: Debugger) -> ExecutionOptionFunc:
    """Enable execution debugging with provided debugger."""
    def option(opts: ExecutionOptions) -> None:
        opts.debugger = debugger
    return option


def with_state(state: State) -> ExecutionOptionFunc:
    """Inject provided state into execution thread."""
    def option(opts: ExecutionOptions) -> None:
        opts.state = state
    return option

