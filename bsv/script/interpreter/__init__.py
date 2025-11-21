"""
Bitcoin Script Interpreter Package

This package implements a Bitcoin transaction script interpreter engine,
providing comprehensive script validation capabilities.

Usage:
    from bsv.script.interpreter import Engine
    
    engine = Engine()
    err = engine.execute(
        Engine.with_tx(tx, input_idx, prev_output),
        Engine.with_after_genesis(),
        Engine.with_fork_id(),
    )
"""

from .engine import Engine
from .options import (
    ExecutionOptionFunc,
    with_tx,
    with_scripts,
    with_after_genesis,
    with_fork_id,
    with_p2sh,
    with_flags,
    with_debugger,
    with_state,
)

__all__ = [
    "Engine",
    "ExecutionOptionFunc",
    "with_tx",
    "with_scripts",
    "with_after_genesis",
    "with_fork_id",
    "with_p2sh",
    "with_flags",
    "with_debugger",
    "with_state",
]

