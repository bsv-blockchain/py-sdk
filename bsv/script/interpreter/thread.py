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
        self.else_stack: List[bool] = []
        self.saved_first_stack: List[bytes] = []
        self.script_idx: int = 0
        self.script_off: int = 0
        self.last_code_sep: int = 0
        self.tx = opts.tx
        self.input_idx = opts.input_idx
        self.prev_output = opts.previous_tx_out
        self.num_ops: int = 0
        self.flags: Flag = opts.flags
        self.bip16: bool = False
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

        # In go-sdk, enabling forkid also enables strict encoding.
        if self.flags.has_flag(Flag.ENABLE_SIGHASH_FORK_ID):
            self.flags = self.flags.add_flag(Flag.VERIFY_STRICT_ENCODING)
        
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

        us_bytes = unlocking_script.serialize()
        ls_bytes = locking_script.serialize()

        # When both scripts are empty, the stack would end empty -> eval-false.
        if len(us_bytes) == 0 and len(ls_bytes) == 0:
            return Error(ErrorCode.ERR_EVAL_FALSE, "false stack entry at end of script execution")

        # VERIFY_CLEAN_STACK is only valid with BIP16 in go-sdk.
        if self.flags.has_flag(Flag.VERIFY_CLEAN_STACK) and not self.flags.has_flag(Flag.BIP16):
            return Error(ErrorCode.ERR_INVALID_FLAGS, "invalid scriptflag combination")

        # Script size limits (before genesis).
        if len(us_bytes) > self.cfg.max_script_size():
            return Error(
                ErrorCode.ERR_SCRIPT_TOO_BIG,
                f"unlocking script size {len(us_bytes)} is larger than the max allowed size {self.cfg.max_script_size()}",
            )
        if len(ls_bytes) > self.cfg.max_script_size():
            return Error(
                ErrorCode.ERR_SCRIPT_TOO_BIG,
                f"locking script size {len(ls_bytes)} is larger than the max allowed size {self.cfg.max_script_size()}",
            )
        
        # Parse scripts (malformed pushes are script errors, not invalid params).
        try:
            parsed_unlocking = self.script_parser.parse(unlocking_script)
            parsed_locking = self.script_parser.parse(locking_script)
        except Error as e:
            return e
        except Exception as e:
            return Error(ErrorCode.ERR_INVALID_PARAMS, f"failed to parse scripts: {e}")
        
        self.scripts = [parsed_unlocking, parsed_locking]

        # Detect P2SH locking script when enabled (BIP16).
        # P2SH pattern: OP_HASH160 OP_DATA_20 <20-byte> OP_EQUAL
        ls = locking_script.serialize()
        is_p2sh = len(ls) == 23 and ls[0:1] == OpCode.OP_HASH160 and ls[1:2] == b"\x14" and ls[-1:] == OpCode.OP_EQUAL
        if self.flags.has_flag(Flag.BIP16) and is_p2sh:
            # When evaluating P2SH, the unlocking script must only contain pushes.
            if not unlocking_script.is_push_only():
                return Error(ErrorCode.ERR_NOT_PUSH_ONLY, "pay to script hash is not push only")
            self.bip16 = True

        # Signature script must be push-only when requested.
        if self.flags.has_flag(Flag.VERIFY_SIG_PUSH_ONLY):
            for pop in parsed_unlocking:
                if pop.opcode > OpCode.OP_16:
                    return Error(ErrorCode.ERR_NOT_PUSH_ONLY, "signature script is not push only")
        
        # Skip unlocking script if empty
        if len(parsed_unlocking) == 0:
            self.script_idx = 1

        # Provide prevout data to the tx input for signature hashing (BIP143-style preimage)
        if self.tx is not None and self.prev_output is not None and len(self.tx.inputs) > self.input_idx:
            self.tx.inputs[self.input_idx].locking_script = self.prev_output.locking_script
            self.tx.inputs[self.input_idx].satoshis = self.prev_output.satoshis
        
        return None

    def is_branch_executing(self) -> bool:
        """Check if current branch is executing."""
        # Matches go-sdk: the top value encodes whether we're executing, with a special skip state.
        return len(self.cond_stack) == 0 or self.cond_stack[-1] == 1

    def should_exec(self, _: ParsedOpcode = None) -> bool:
        """Check if opcode should be executed."""
        # Mirror go-sdk/thread.shouldExec:
        # - Before genesis: always execute (conditional skip state is handled separately).
        # - After genesis: execution is disabled if *any* conditional on the stack is false.
        # - After genesis + OP_RETURN early return: only OP_RETURN itself is considered "executing";
        #   conditionals still run to maintain balancing, but other ops are skipped.
        if not self.after_genesis:
            return True

        cf = True
        for v in self.cond_stack:
            if v == 0:  # opCondFalse
                cf = False
                break

        if _ is None:
            return cf and (not self.early_return_after_genesis)

        return cf and (not self.early_return_after_genesis or _.opcode == OpCode.OP_RETURN)

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

    def _check_element_size(self, pop: ParsedOpcode) -> Optional[Error]:
        """Check if element size exceeds maximum."""
        if pop.data and len(pop.data) > self.cfg.max_script_element_size():
            return Error(
                ErrorCode.ERR_ELEMENT_TOO_BIG,
                f"element size {len(pop.data)} exceeds max {self.cfg.max_script_element_size()}",
            )
        return None

    def _check_disabled_opcode(self, pop: ParsedOpcode, _exec: bool) -> Optional[Error]:
        """Check if opcode is disabled."""
        if pop.is_disabled() and (not self.after_genesis or _exec):
            return Error(ErrorCode.ERR_DISABLED_OPCODE, f"attempt to execute disabled opcode {pop.name()}")
        return None

    def _check_operation_count(self, pop: ParsedOpcode) -> Optional[Error]:
        """Check and update operation count."""
        if pop.opcode > OpCode.OP_16:
            self.num_ops += 1
            if self.num_ops > self.cfg.max_ops():
                return Error(ErrorCode.ERR_TOO_MANY_OPERATIONS, f"exceeded max operation limit of {self.cfg.max_ops()}")
        return None

    def _check_minimal_data(self, pop: ParsedOpcode, _exec: bool) -> Optional[Error]:
        """Check minimal data encoding."""
        if self.dstack.verify_minimal_data and self.is_branch_executing() and pop.opcode <= OpCode.OP_PUSHDATA4 and _exec:
            err_msg = pop.enforce_minimum_data_push()
            if err_msg:
                return Error(ErrorCode.ERR_MINIMAL_DATA, err_msg)
        return None

    def execute_opcode(self, pop: ParsedOpcode) -> Optional[Error]:
        """Execute a single opcode."""
        # Check element size
        err = self._check_element_size(pop)
        if err:
            return err
        
        _exec = self.should_exec(pop)  # NOSONAR - renamed to avoid shadowing builtin
        
        # Check disabled opcodes
        err = self._check_disabled_opcode(pop, _exec)
        if err:
            return err

        # Always-illegal opcodes are fail on program counter before genesis.
        if pop.always_illegal() and not self.after_genesis:
            return Error(ErrorCode.ERR_RESERVED_OPCODE, f"attempt to execute reserved opcode {pop.name()}")
        
        # Count operations
        err = self._check_operation_count(pop)
        if err:
            return err
        
        # Skip if not executing branch and not conditional
        if not self.is_branch_executing() and not pop.is_conditional():
            return None
        
        # Check minimal data encoding
        err = self._check_minimal_data(pop, _exec)
        if err:
            return err
        
        # Skip if early return and not conditional
        if not _exec and not pop.is_conditional():
            return None
        
        # Execute opcode
        handler = OPCODE_DISPATCH.get(pop.opcode)
        if handler:
            return handler(pop, self)
        
        # Unknown opcode
        return Error(ErrorCode.ERR_RESERVED_OPCODE, f"attempt to execute invalid opcode {pop.name()}")

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
        # In go-sdk, OP_RETURN after genesis can return ERR_OK to signal a successful early termination.
        if is_error_code(err, ErrorCode.ERR_OK):
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

        # Alt stack doesn't persist between scripts (go-sdk behavior).
        if self.astack is not None:
            try:
                self.astack.drop_n(self.astack.depth())
            except Exception:
                pass
        
        self.shift_script()

        # P2SH (BIP16) evaluation (go-sdk behavior before genesis only):
        # - after finishing scriptSig (idx becomes 1): save stack
        # - after finishing scriptPubKey (idx becomes 2): verify success, then execute redeemScript from saved stack
        if self.bip16 and not self.after_genesis and self.script_idx <= 2:
            if self.script_idx == 1:
                self.saved_first_stack = list(self.dstack.stk)
            elif self.script_idx == 2:
                err = self.check_error_condition(False)
                if err:
                    return False, err
                if len(self.saved_first_stack) < 1:
                    return False, Error(ErrorCode.ERR_EVAL_FALSE, "false stack entry at end of script execution")

                redeem_script_bytes = self.saved_first_stack[-1]
                try:
                    from bsv.script.script import Script
                    parsed_redeem = self.script_parser.parse(Script.from_bytes(redeem_script_bytes))
                except Error as e:
                    return False, e
                except Exception as e:
                    return False, Error(ErrorCode.ERR_INVALID_PARAMS, f"failed to parse redeem script: {e}")

                self.scripts.append(parsed_redeem)
                # Restore stack from first script, excluding redeem script itself.
                self.dstack.stk = list(self.saved_first_stack[:-1])

        return self.script_idx >= len(self.scripts), None

    def sub_script(self) -> "ParsedScript":
        """Get the script starting from the most recent OP_CODESEPARATOR."""
        skip = 0
        # Match go-sdk behavior: if last_code_sep > 0, skip separator itself (idx + 1)
        if self.last_code_sep > 0:
            skip = self.last_code_sep + 1
        return self.scripts[self.script_idx][skip:]

    def shift_script(self) -> None:
        """Move to next script."""
        self.script_idx += 1
        self.script_off = 0
        self.last_code_sep = 0
        self.num_ops = 0
        self.early_return_after_genesis = False
        # Mirror go-sdk: there are zero-length scripts in the wild; skip over them.
        while self.script_idx < len(self.scripts) and self.script_off >= len(self.scripts[self.script_idx]):
            self.script_idx += 1

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

