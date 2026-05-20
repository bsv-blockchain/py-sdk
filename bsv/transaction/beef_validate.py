from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from bsv.merkle_path import MerklePath

from .beef import Beef, BeefTx


class ValidationResult:
    def __init__(self) -> None:
        self.valid: list[str] = []
        self.not_valid: list[str] = []
        self.txid_only: list[str] = []
        self.with_missing_inputs: list[str] = []
        self.missing_inputs: list[str] = []

    def __str__(self) -> str:
        return f"{{valid: {self.valid}, not_valid: {self.not_valid}, txid_only: {self.txid_only}, with_missing_inputs: {self.with_missing_inputs}, missing_inputs: {self.missing_inputs}}}"


def _txids_in_bumps(beef: Beef) -> set[str]:
    s: set[str] = set()
    for bump in getattr(beef, "bumps", []) or []:
        try:
            for leaf in bump.path[0]:
                h = leaf.get("hash_str")
                if h:
                    s.add(h)
        except Exception:
            pass
    return s


def validate_transactions(beef: Beef) -> ValidationResult:
    """
    Classify transactions by validity against available bumps and inputs.
    This mirrors the logic of GO's ValidateTransactions at a high level.
    """
    result = ValidationResult()
    txids_in_bumps = _txids_in_bumps(beef)

    context = _ValidationContext(txids_in_bumps)
    _classify_transactions(beef, context)
    _validate_dependencies(context)
    _collect_results(result, context)
    return result


class _ValidationContext:
    """Context for transaction validation."""

    def __init__(self, txids_in_bumps: set[str]):
        self.txids_in_bumps = txids_in_bumps
        self.valid_txids: set[str] = set()
        self.missing_inputs: set[str] = set()
        self.has_proof: list[BeefTx] = []
        self.txid_only: list[BeefTx] = []
        self.needs_validation: list[BeefTx] = []
        self.with_missing: list[BeefTx] = []


def _classify_transactions(beef: Beef, ctx: _ValidationContext):
    """Classify transactions by format and initial validity."""
    for txid, btx in getattr(beef, "txs", {}).items():
        if btx.data_format == 2:
            _handle_txid_only(btx, txid, ctx)
        elif btx.data_format == 1:
            _handle_format_1(btx, txid, beef, ctx)
        else:
            _handle_format_0(btx, txid, beef, ctx)


def _handle_txid_only(btx: BeefTx, txid: str, ctx: _ValidationContext):
    """Handle txid-only format."""
    ctx.txid_only.append(btx)
    if txid in ctx.txids_in_bumps:
        ctx.valid_txids.add(txid)


def _handle_format_1(btx: BeefTx, txid: str, beef: Beef, ctx: _ValidationContext):
    """Handle format 1 (with bump index)."""
    ok = False
    if btx.bump_index is not None and 0 <= btx.bump_index < len(beef.bumps):
        bump = beef.bumps[btx.bump_index]
        ok = any(leaf.get("hash_str") == txid for leaf in bump.path[0])

    if ok:
        ctx.valid_txids.add(txid)
        ctx.has_proof.append(btx)
    else:
        ctx.needs_validation.append(btx)


def _handle_format_0(btx: BeefTx, txid: str, beef: Beef, ctx: _ValidationContext):
    """Handle format 0 (full transaction)."""
    if txid in ctx.txids_in_bumps:
        ctx.valid_txids.add(txid)
        ctx.has_proof.append(btx)
    elif btx.tx_obj is not None:
        if _check_missing_inputs(btx, beef, ctx):
            ctx.with_missing.append(btx)
        else:
            ctx.needs_validation.append(btx)


def _check_missing_inputs(btx: BeefTx, beef: Beef, ctx: _ValidationContext) -> bool:
    """Check for missing inputs and update context."""
    inputs = getattr(btx.tx_obj, "inputs", []) or []
    has_missing = False
    for txin in inputs:
        src = getattr(txin, "source_txid", None)
        if src and src not in beef.txs:
            ctx.missing_inputs.add(src)
            has_missing = True
    return has_missing


def _validate_dependencies(ctx: _ValidationContext):
    """Iteratively validate transaction dependencies."""
    while ctx.needs_validation:
        still: list[BeefTx] = []
        progress = False

        for btx in ctx.needs_validation:
            if _can_validate_transaction(btx, ctx):
                ctx.valid_txids.add(btx.txid)
                ctx.has_proof.append(btx)
                progress = True
            else:
                still.append(btx)

        if not progress:
            _mark_unvalidatable(still, ctx)
            break

        ctx.needs_validation = still


def _can_validate_transaction(btx: BeefTx, ctx: _ValidationContext) -> bool:
    """Check if transaction can be validated."""
    if btx.tx_obj is None:
        return False

    for txin in btx.tx_obj.inputs:
        src = getattr(txin, "source_txid", None)
        if src and src not in ctx.valid_txids:
            return False

    # Require at least one valid input to anchor to proven chain
    return any(getattr(txin, "source_txid", None) in ctx.valid_txids for txin in btx.tx_obj.inputs)


def _mark_unvalidatable(still: list[BeefTx], ctx: _ValidationContext):
    """Mark remaining transactions as not valid."""
    # These are added to result.not_valid in _collect_results


def _collect_results(result: ValidationResult, ctx: _ValidationContext):
    """Collect validation results."""
    for btx in ctx.with_missing:
        if btx.tx_obj is not None:
            result.with_missing_inputs.append(btx.tx_obj.txid())

    for btx in ctx.needs_validation:
        if btx.tx_obj is not None:
            result.not_valid.append(btx.tx_obj.txid())

    result.txid_only = [b.txid for b in ctx.txid_only]
    result.valid = list(ctx.valid_txids)
    result.missing_inputs = list(ctx.missing_inputs)


def verify_valid(beef: Beef, allow_txid_only: bool = False) -> tuple[bool, dict[int, str]]:
    """
    Validate structure and confirm that computed roots are consistent per block height.
    Returns (valid, roots_map).
    """
    vr = validate_transactions(beef)
    if not _is_basic_validation_passed(vr, allow_txid_only):
        return False, {}

    roots = _validate_bump_roots(beef)
    if roots is None:
        return False, {}

    if not _validate_btx_references(beef):
        return False, {}

    return True, roots


def _is_basic_validation_passed(vr, allow_txid_only: bool) -> bool:
    """Check if basic transaction validation passed."""
    return not (vr.missing_inputs or vr.not_valid or (vr.txid_only and not allow_txid_only) or vr.with_missing_inputs)


def _validate_bump_roots(beef: Beef) -> dict[int, str] | None:
    """Validate that all bumps have internally consistent roots."""
    roots: dict[int, str] = {}

    for bump in getattr(beef, "bumps", []) or []:
        if not _validate_single_bump_roots(bump, roots):
            return None

    return roots


def _validate_single_bump_roots(bump, roots: dict[int, str]) -> bool:
    """Validate roots for a single bump."""
    try:
        for leaf in bump.path[0]:
            if leaf.get("txid") and leaf.get("hash_str"):
                if not _confirm_computed_root(bump, leaf["hash_str"], roots):
                    return False
    except Exception:
        return False
    return True


def _confirm_computed_root(mp: MerklePath, txid: str, roots: dict[int, str]) -> bool:
    """Confirm that computed root matches existing roots for the block height."""
    try:
        try:
            root = mp.compute_root(txid)  # type: ignore[arg-type]
        except TypeError:
            root = mp.compute_root()  # type: ignore[call-arg]
    except Exception:
        return False

    existing = roots.get(mp.block_height)
    if existing is None:
        roots[mp.block_height] = root
        return True
    return existing == root


def _validate_btx_references(beef: Beef) -> bool:
    """Validate that beefTx references are correct."""
    for txid, btx in getattr(beef, "txs", {}).items():
        if btx.data_format == 1:
            if not _validate_single_btx_reference(beef, txid, btx):
                return False
    return True


def _validate_single_btx_reference(beef: Beef, txid: str, btx) -> bool:
    """Validate a single beefTx reference."""
    if btx.bump_index is None or btx.bump_index < 0 or btx.bump_index >= len(beef.bumps):
        return False

    bump = beef.bumps[btx.bump_index]
    found = any(leaf.get("hash_str") == txid for leaf in bump.path[0])
    return found


def is_valid(beef: Beef, allow_txid_only: bool = False) -> bool:
    ok, _ = verify_valid(beef, allow_txid_only=allow_txid_only)
    return ok


def get_valid_txids(beef: Beef) -> list[str]:
    return validate_transactions(beef).valid
