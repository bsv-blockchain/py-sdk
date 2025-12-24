"""
Configuration for script interpreter limits.

Ported from go-sdk/script/interpreter/config.go
"""

import sys
from typing import Protocol


class Config(Protocol):
    """Configuration interface for script limits."""

    def after_genesis(self) -> bool:
        """Return whether this is after genesis."""
        ...

    def max_ops(self) -> int:
        """Return maximum number of operations."""
        ...

    def max_stack_size(self) -> int:
        """Return maximum stack size."""
        ...

    def max_script_size(self) -> int:
        """Return maximum script size."""
        ...

    def max_script_element_size(self) -> int:
        """Return maximum script element size."""
        ...

    def max_script_number_length(self) -> int:
        """Return maximum script number length."""
        ...

    def max_pub_keys_per_multisig(self) -> int:
        """Return maximum public keys per multisig."""
        ...


# Limits applied to transactions before genesis
MAX_OPS_BEFORE_GENESIS = 500
MAX_STACK_SIZE_BEFORE_GENESIS = 1000
MAX_SCRIPT_SIZE_BEFORE_GENESIS = 10000
MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS = 520
MAX_SCRIPT_NUMBER_LENGTH_BEFORE_GENESIS = 4
MAX_PUB_KEYS_PER_MULTISIG_BEFORE_GENESIS = 20


class BeforeGenesisConfig:
    """Configuration for before genesis limits."""

    def after_genesis(self) -> bool:
        return False

    def max_stack_size(self) -> int:
        return MAX_STACK_SIZE_BEFORE_GENESIS

    def max_script_size(self) -> int:
        return MAX_SCRIPT_SIZE_BEFORE_GENESIS

    def max_script_element_size(self) -> int:
        return MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS

    def max_script_number_length(self) -> int:
        return MAX_SCRIPT_NUMBER_LENGTH_BEFORE_GENESIS

    def max_ops(self) -> int:
        return MAX_OPS_BEFORE_GENESIS

    def max_pub_keys_per_multisig(self) -> int:
        return MAX_PUB_KEYS_PER_MULTISIG_BEFORE_GENESIS


class AfterGenesisConfig:
    """Configuration for after genesis limits."""

    def after_genesis(self) -> bool:
        return True

    def max_stack_size(self) -> int:
        return sys.maxsize

    def max_script_size(self) -> int:
        return sys.maxsize

    def max_script_element_size(self) -> int:
        return sys.maxsize

    def max_script_number_length(self) -> int:
        return 750 * 1000  # 750 KB

    def max_ops(self) -> int:
        return sys.maxsize

    def max_pub_keys_per_multisig(self) -> int:
        return sys.maxsize

