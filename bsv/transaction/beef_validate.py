from __future__ import annotations

from bsv.merkle_path import MerklePath

from .beef import Beef


class ValidationResult:
    def __init__(self) -> None:
        self.valid: list[str] = []
        self.not_valid: list[str] = []
        self.txid_only: list[str] = []
        self.with_missing_inputs: list[str] = []
        self.missing_inputs: list[str] = []

    def __str__(self) -> str:
        return f"{{valid: {self.valid}, not_valid: {self.not_valid}, txid_only: {self.txid_only}, with_missing_inputs: {self.with_missing_inputs}, missing_inputs: {self.missing_inputs}}}"


def validate_transactions(beef: Beef) -> ValidationResult:
    """
    Classify transactions the way TS Beef.sortTxs does. A transaction is valid when it has a bump
    index (proof claim), is TxIDOnly, or all of its inputs chain back to valid transactions.
    Entries without transaction data are not valid (fail closed).
    """
    result = ValidationResult()
    valid: set[str] = set()
    missing: set[str] = set()
    queue = _classify_entries(beef, result, valid, missing)
    _resolve_input_chains(queue, valid)

    result.not_valid += [txid for txid, _ in queue]
    result.valid = list(valid)
    result.missing_inputs = list(missing)
    return result


def _classify_entries(
    beef: Beef, result: ValidationResult, valid: set[str], missing: set[str]
) -> list[tuple[str, set[str]]]:
    """Sort entries into valid, TxIDOnly, not valid or missing inputs; return the rest with their inputs."""
    queue: list[tuple[str, set[str]]] = []
    for txid, btx in getattr(beef, "txs", {}).items():
        if btx.bump_index is not None:
            valid.add(txid)
        elif btx.data_format == 2 and btx.tx_obj is None:
            valid.add(txid)
            result.txid_only.append(txid)
        elif btx.tx_obj is None:
            result.not_valid.append(txid)
        else:
            inputs = {i.source_txid for i in btx.tx_obj.inputs if getattr(i, "source_txid", None)}
            if inputs - beef.txs.keys():
                missing |= inputs - beef.txs.keys()
                result.with_missing_inputs.append(txid)
            else:
                queue.append((txid, inputs))
    return queue


def _resolve_input_chains(queue: list[tuple[str, set[str]]], valid: set[str]) -> None:
    """Move queued transactions whose inputs are all valid into valid until nothing changes."""
    progress = True
    while queue and progress:
        progress = False
        for item in list(queue):
            txid, inputs = item
            # An unproven tx without inputs has nothing to anchor it to a proof.
            if inputs and inputs <= valid:
                valid.add(txid)
                queue.remove(item)
                progress = True


def verify_valid(beef: Beef, allow_txid_only: bool = False) -> tuple[bool, dict[int, str]]:
    """
    Validate structure and confirm that computed roots are consistent per block height.
    Returns (valid, roots_map); the roots must then be confirmed by a ChainTracker.
    """
    vr = validate_transactions(beef)
    if vr.missing_inputs or vr.not_valid or vr.with_missing_inputs or (vr.txid_only and not allow_txid_only):
        return False, {}

    roots: dict[int, str] = {}
    bumps = getattr(beef, "bumps", []) or []
    if not _confirm_flagged_leaf_roots(bumps, roots) or not _confirm_bump_index_roots(beef, bumps, roots):
        return False, {}
    return True, roots


def _confirm_flagged_leaf_roots(bumps: list[MerklePath], roots: dict[int, str]) -> bool:
    """Compute the root of every level-0 leaf with the txid flag."""
    for bump in bumps:
        for leaf in bump.path[0]:
            if leaf.get("txid") and leaf.get("hash_str") and not _confirm_computed_root(bump, leaf["hash_str"], roots):
                return False
    return True


def _confirm_bump_index_roots(beef: Beef, bumps: list[MerklePath], roots: dict[int, str]) -> bool:
    """
    Every bump index must point at a leaf for its txid (TS verifyBumpIndexLeaves), and that leaf's
    root must go to the ChainTracker even when the leaf has no txid flag.
    """
    for txid, btx in beef.txs.items():
        if btx.bump_index is None:
            continue
        if not 0 <= btx.bump_index < len(bumps):
            return False
        bump = bumps[btx.bump_index]
        if not any(leaf.get("hash_str") == txid for leaf in bump.path[0]):
            return False
        if not _confirm_computed_root(bump, txid, roots):
            return False
    return True


def _confirm_computed_root(mp: MerklePath, txid: str, roots: dict[int, str]) -> bool:
    """Confirm that txid is in mp and its computed root matches other roots for the block height."""
    try:
        root = mp.compute_root(txid)
    except Exception:
        return False
    return roots.setdefault(mp.block_height, root) == root


def is_valid(beef: Beef, allow_txid_only: bool = False) -> bool:
    ok, _ = verify_valid(beef, allow_txid_only=allow_txid_only)
    return ok


def get_valid_txids(beef: Beef) -> list[str]:
    return validate_transactions(beef).valid
