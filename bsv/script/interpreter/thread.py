"""
Thread for script execution.

Ported from go-sdk/script/interpreter/thread.go
"""

from typing import List, Optional

from bsv.constants import OpCode

from .config import BeforeGenesisConfig, AfterGenesisConfig, Config
from .errs import Error, ErrorCode, is_error_code
from .op_parser import DefaultOpcodeParser, ParsedOpcode, ParsedScript
from .operations import OPCODE_DISPATCH
from .options import ExecutionOptions
from .scriptflag import Flag
from .stack import Stack


class Thread:
    """Thread represents a script execution thread."""

    def __init__(self, opts: ExecutionOptions):
        """Initialize a new thread."""
        self.opts = opts
        self.dstack: Optional[Stack] = None
        self.astack: Optional[Stack] = None
        self.cfg: Config = BeforeGenesisConfig()
        self.scripts: List[ParsedScript] = []
        self.cond_stack: List[int] = []
        self.script_idx: int = 0
        self.script_off: int = 0
        self.last_code_sep: int = 0
        self.tx = opts.tx
        self.input_idx = opts.input_idx
        self.prev_output = opts.previous_tx_out
        self.num_ops: int = 0
        self.flags: Flag = opts.flags
        self.after_genesis: bool = False
        self.early_return_after_genesis: bool = False
        self.script_parser = DefaultOpcodeParser(error_on_check_sig=(opts.tx is None or opts.previous_tx_out is None))
        self.error_on_check_sig = self.script_parser.error_on_check_sig

    def create(self) -> Optional[Error]:
        """Create and initialize the thread."""
        # Determine configuration
        if self.flags.has_flag(Flag.UTXO_AFTER_GENESIS):
            self.cfg = AfterGenesisConfig()
            self.after_genesis = True
        
        # Initialize stacks
        verify_minimal = self.flags.has_flag(Flag.VERIFY_MINIMAL_DATA)
        self.dstack = Stack(self.cfg, verify_minimal)
        self.astack = Stack(self.cfg, verify_minimal)
        
        # Get scripts
        if self.opts.locking_script is not None:
            locking_script = self.opts.locking_script
        elif self.prev_output is not None:
            locking_script = self.prev_output.locking_script
        else:
            return Error(ErrorCode.ERR_INVALID_PARAMS, "no locking script available")
        
        if self.opts.unlocking_script is not None:
            unlocking_script = self.opts.unlocking_script
        elif self.tx is not None and self.tx.inputs and len(self.tx.inputs) > self.input_idx:
            unlocking_script = self.tx.inputs[self.input_idx].unlocking_script
        else:
            return Error(ErrorCode.ERR_INVALID_PARAMS, "no unlocking script available")
        
        # Parse scripts
        try:
            parsed_unlocking = self.script_parser.parse(unlocking_script)
            parsed_locking = self.script_parser.parse(locking_script)
        except Exception as e:
            return Error(ErrorCode.ERR_INVALID_PARAMS, f"failed to parse scripts: {e}")
        
        self.scripts = [parsed_unlocking, parsed_locking]
        
        # Skip unlocking script if empty
        if len(parsed_unlocking) == 0:
            self.script_idx = 1
        
        return None

    def is_branch_executing(self) -> bool:
        """Check if current branch is executing."""
        return len(self.cond_stack) == 0 or self.cond_stack[-1] == 1

    def should_exec(self, _: ParsedOpcode = None) -> bool:
        """Check if opcode should be executed."""
        return self.is_branch_executing()

    def valid_pc(self) -> Optional[Error]:
        """Validate program counter."""
        if self.script_idx >= len(self.scripts):
            return Error(
                ErrorCode.ERR_INVALID_PROGRAM_COUNTER,
                f"past input scripts {self.script_idx}:{self.script_off} {len(self.scripts)}:xxxx",
            )
        if self.script_off >= len(self.scripts[self.script_idx]):
            return Error(
                ErrorCode.ERR_INVALID_PROGRAM_COUNTER,
                f"past input scripts {self.script_idx}:{self.script_off} {self.script_idx}:{len(self.scripts[self.script_idx]):04d}",
            )
        return None

    def execute_opcode(self, pop: ParsedOpcode) -> Optional[Error]:
        """Execute a single opcode."""
        # Check element size
        if pop.data and len(pop.data) > self.cfg.max_script_element_size():
            return Error(
                ErrorCode.ERR_ELEMENT_TOO_BIG,
                f"element size {len(pop.data)} exceeds max {self.cfg.max_script_element_size()}",
            )
        
        _exec = self.should_exec(pop)  # NOSONAR - renamed to avoid shadowing builtin
        
        # Check disabled opcodes
        if pop.is_disabled() and (not self.after_genesis or _exec):
            return Error(ErrorCode.ERR_DISABLED_OPCODE, f"attempt to execute disabled opcode {pop.name()}")
        
        # Count operations
        if pop.opcode > OpCode.OP_16:
            self.num_ops += 1
            if self.num_ops > self.cfg.max_ops():
                return Error(ErrorCode.ERR_TOO_MANY_OPERATIONS, f"exceeded max operation limit of {self.cfg.max_ops()}")
        
        # Skip if not executing branch and not conditional
        if not self.is_branch_executing() and not pop.is_conditional():
            return None
        
        # Check minimal data encoding
        if self.dstack.verify_minimal_data and self.is_branch_executing() and pop.opcode <= OpCode.OP_PUSHDATA4 and _exec:
            err_msg = pop.enforce_minimum_data_push()
            if err_msg:
                return Error(ErrorCode.ERR_MINIMAL_DATA, err_msg)
        
        # Skip if early return and not conditional
        if not _exec and not pop.is_conditional():
            return None
        
        # Execute opcode
        handler = OPCODE_DISPATCH.get(pop.opcode)
        if handler:
            return handler(pop, self)
        
        # Unknown opcode
        return Error(ErrorCode.ERR_DISABLED_OPCODE, f"unknown opcode {pop.name()}")

    def step(self) -> tuple[bool, Optional[Error]]:
        """Execute one step."""
        err = self.valid_pc()
        if err:
            return True, err
        
        pop = self.scripts[self.script_idx][self.script_off]
        err = self.execute_opcode(pop)
        
        if err:
            return self._handle_execution_error(err)
        
        self.script_off += 1
        
        err = self._check_stack_overflow()
        if err:
            return False, err
        
        return self._check_script_completion()
    
    def _handle_execution_error(self, err: Error) -> tuple[bool, Optional[Error]]:
        """Handle opcode execution error."""
        if is_error_code(err, ErrorCode.ERR_EARLY_RETURN):
            self.shift_script()
            return self.script_idx >= len(self.scripts), None
        return True, err
    
    def _check_stack_overflow(self) -> Optional[Error]:
        """Check if combined stack size exceeds maximum."""
        combined_size = self.dstack.depth() + self.astack.depth()
        if combined_size > self.cfg.max_stack_size():
            return Error(
                ErrorCode.ERR_STACK_OVERFLOW,
                f"combined stack size {combined_size} > max allowed {self.cfg.max_stack_size()}",
            )
        return None
    
    def _check_script_completion(self) -> tuple[bool, Optional[Error]]:
        """Check if current script is complete and prepare for next."""
        if self.script_off < len(self.scripts[self.script_idx]):
            return False, None
        
        if len(self.cond_stack) != 0:
            return False, Error(ErrorCode.ERR_UNBALANCED_CONDITIONAL, "end of script reached in conditional execution")
        
        self.shift_script()
        return self.script_idx >= len(self.scripts), None

    def sub_script(self) -> "ParsedScript":
        """Get the script starting from the most recent OP_CODESEPARATOR."""
        # TODO: Implement proper OP_CODESEPARATOR handling
        # For now, return the current script
        return self.scripts[self.script_idx]

    def shift_script(self) -> None:
        """Move to next script."""
        self.script_idx += 1
        self.script_off = 0

    def check_error_condition(self, final_script: bool = True) -> Optional[Error]:
        """Check final error condition."""
        if self.dstack.depth() < 1:
            return Error(ErrorCode.ERR_EMPTY_STACK, "stack empty at end of script execution")
        
        if final_script and self.flags.has_flag(Flag.VERIFY_CLEAN_STACK) and self.dstack.depth() != 1:
            return Error(ErrorCode.ERR_CLEAN_STACK, f"stack contains {self.dstack.depth() - 1} unexpected items")
        
        val = self.dstack.pop_bool()
        if not val:
            return Error(ErrorCode.ERR_EVAL_FALSE, "false stack entry at end of script execution")
        
        return None

    def execute(self) -> Optional[Error]:
        """Execute the scripts."""
        while True:
            done, err = self.step()
            if err:
                return err
            if done:
                break
        
        return self.check_error_condition(True)

    def after_error(self, err: Error) -> None:
        """Handle error after execution."""
        # Placeholder for error handling
        pass

