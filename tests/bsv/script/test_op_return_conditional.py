"""OP_RETURN behaves differently at the top level and inside a conditional.

At the top level the node ends evaluation successfully and nothing after it
affects validity — "even in presence of unbalanced IFs, invalid opcodes etc".
Inside a conditional it instead sets `nonTopLevelReturnAfterGenesis`, which
stops execution but keeps the script being scanned so the conditional grammar
is still checked (`interpreter.cpp`).
"""

import pytest

from bsv.script.spend import _USE_NATIVE_VM

from .conftest import make_spend


def _accepted(locking_asm: str, unlocking_asm: str = "") -> bool:
    """True when both VM paths accept; asserts they agree."""
    results = [make_spend(locking_asm, unlocking_asm, tx_version=2)._validate_python()]
    if _USE_NATIVE_VM:
        results.append(make_spend(locking_asm, unlocking_asm, tx_version=2)._validate_native())
    assert len(set(results)) == 1, results
    return results[0]


def _rejected_with(locking_asm: str, unlocking_asm: str, match: str) -> None:
    python_spend = make_spend(locking_asm, unlocking_asm, tx_version=2)
    with pytest.raises(RuntimeError, match=match):
        python_spend._validate_python()
    if _USE_NATIVE_VM:
        native_spend = make_spend(locking_asm, unlocking_asm, tx_version=2)
        with pytest.raises(RuntimeError, match=match):
            native_spend._validate_native()


def test_top_level_return_ends_evaluation():
    # The trailing OP_IF is never reached, so it cannot unbalance anything.
    assert _accepted("OP_1 OP_RETURN OP_IF", "OP_1")


def test_top_level_return_ignores_invalid_trailing_opcodes():
    assert _accepted("OP_1 OP_RETURN OP_ELSE OP_ENDIF OP_ENDIF", "OP_1")


def test_return_inside_a_conditional_still_checks_the_grammar():
    # Regression: OP_RETURN cleared the conditional stack and jumped to the end,
    # so the unbalanced OP_IF was never reported.
    _rejected_with("OP_IF OP_1 OP_RETURN OP_IF", "OP_1", "Every OP_IF must be terminated")


def test_return_inside_a_conditional_stops_execution():
    # The OP_1 after the conditional closes must not run, leaving the stack
    # empty and the script failing on the final truthiness check.
    _rejected_with("OP_IF OP_RETURN OP_ENDIF OP_1", "OP_1", "must be truthy")


def test_value_pushed_before_the_return_survives():
    assert _accepted("OP_1 OP_IF OP_RETURN OP_ENDIF", "OP_1")


def test_return_in_a_skipped_branch_is_inert():
    # The branch is not taken, so nothing is flagged and the OP_1 still runs.
    assert _accepted("OP_IF OP_RETURN OP_ENDIF OP_1", "OP_0")
