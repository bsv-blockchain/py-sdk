"""
Script interpreter engine.

Ported from go-sdk/script/interpreter/engine.go
"""

from typing import Optional

from .errs import Error, ErrorCode
from .options import ExecutionOptionFunc, ExecutionOptions
from .thread import Thread


class Engine:
    """Engine is the virtual machine that executes scripts."""

    def __init__(self):
        """Create a new script engine."""
        pass

    def execute(self, *options: ExecutionOptionFunc) -> Optional[Error]:
        """
        Execute will execute all scripts in the script engine and return either None
        for successful validation or an Error if one occurred.
        
        Usage:
            engine = Engine()
            err = engine.execute(
                with_tx(tx, input_idx, prev_output),
                with_after_genesis(),
                with_fork_id(),
            )
        """
        opts = ExecutionOptions()
        for option in options:
            option(opts)
        
        # Validate options
        err = self._validate_options(opts)
        if err:
            return err
        
        # Create thread
        thread = Thread(opts)
        err = thread.create()
        if err:
            return err
        
        # Execute
        err = thread.execute()
        if err:
            thread.after_error(err)
            return err
        
        return None

    def _validate_options(self, opts: ExecutionOptions) -> Optional[Error]:
        """Validate execution options."""
        err = self._validate_input_index(opts)
        if err:
            return err
        
        err = self._validate_scripts(opts)
        if err:
            return err
        
        return self._validate_script_consistency(opts)

    def _validate_input_index(self, opts: ExecutionOptions) -> Optional[Error]:
        """Validate the input index."""
        if opts.input_idx < 0:
            return Error(ErrorCode.ERR_INVALID_INDEX, f"input index {opts.input_idx} is negative")
        
        if opts.tx is not None and opts.input_idx >= len(opts.tx.inputs):
            return Error(
                ErrorCode.ERR_INVALID_INDEX,
                f"input index {opts.input_idx} >= {len(opts.tx.inputs)}",
            )
        return None

    def _validate_scripts(self, opts: ExecutionOptions) -> Optional[Error]:
        """Validate that required scripts are provided."""
        output_has_locking_script = (
            opts.previous_tx_out is not None
            and opts.previous_tx_out.locking_script is not None
        )
        tx_has_unlocking_script = (
            opts.tx is not None
            and opts.tx.inputs
            and len(opts.tx.inputs) > opts.input_idx
            and opts.tx.inputs[opts.input_idx].unlocking_script is not None
        )
        
        if opts.locking_script is None and not output_has_locking_script:
            return Error(ErrorCode.ERR_INVALID_PARAMS, "no locking script provided")
        
        if opts.unlocking_script is None and not tx_has_unlocking_script:
            return Error(ErrorCode.ERR_INVALID_PARAMS, "no unlocking script provided")
        
        return None

    def _validate_script_consistency(self, opts: ExecutionOptions) -> Optional[Error]:
        """Validate that provided scripts are consistent with transaction scripts."""
        output_has_locking_script = (
            opts.previous_tx_out is not None
            and opts.previous_tx_out.locking_script is not None
        )
        
        if opts.locking_script is not None and output_has_locking_script:
            if opts.locking_script.hex() != opts.previous_tx_out.locking_script.hex():
                return Error(
                    ErrorCode.ERR_INVALID_PARAMS,
                    "locking script does not match previous output locking script",
                )
        
        tx_has_unlocking_script = (
            opts.tx is not None
            and opts.tx.inputs
            and len(opts.tx.inputs) > opts.input_idx
            and opts.tx.inputs[opts.input_idx].unlocking_script is not None
        )
        
        if opts.unlocking_script is not None and tx_has_unlocking_script:
            if opts.unlocking_script.hex() != opts.tx.inputs[opts.input_idx].unlocking_script.hex():
                return Error(
                    ErrorCode.ERR_INVALID_PARAMS,
                    "unlocking script does not match transaction input unlocking script",
                )

        return None
