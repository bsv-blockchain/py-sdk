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
        self.order: list[str] = []

    def __str__(self) -> str:
        return f"{{valid: {self.valid}, not_valid: {self.not_valid}, txid_only: {self.txid_only}, with_missing_inputs: {self.with_missing_inputs}, missing_inputs: {self.missing_inputs}}}"


def validate_transactions(beef: Beef) -> ValidationResult:
    """
    Classify transactions the way TS Beef.sortTxs does. A transaction is valid when it has a bump
    index (proof claim), is TxIDOnly, or all of its inputs chain back to valid transactions.
    Entries without transaction data are not valid (fail closed).

    result.order lists the txids in TS sort order: missing inputs, unsortable, TxIDOnly, then the
    rest with every parent before its children.
    """
    result = ValidationResult()
    valid: dict[str, None] = {}  # insertion-ordered set
    missing: set[str] = set()
    queue = _classify_entries(beef, result, valid, missing)
    no_data = list(result.not_valid)
    proven = [txid for txid, btx in beef.txs.items() if btx.bump_index is not None]
    chained, unanchored = _resolve_input_chains(queue, valid)

    result.not_valid += [txid for txid, _ in queue] + unanchored
    result.valid = list(valid)
    result.missing_inputs = list(missing)
    result.order = result.with_missing_inputs + no_data + [t for t, _ in queue] + result.txid_only + proven + chained
    return result


def _classify_entries(
    beef: Beef, result: ValidationResult, valid: dict[str, None], missing: set[str]
) -> list[tuple[str, set[str]]]:
    """Sort entries into valid, TxIDOnly, not valid or missing inputs; return the rest with their inputs."""
    queue: list[tuple[str, set[str]]] = []
    for txid, btx in getattr(beef, "txs", {}).items():
        if btx.bump_index is not None:
            valid[txid] = None
        elif btx.data_format == 2 and btx.tx_obj is None:
            valid[txid] = None
            result.txid_only.append(txid)
        elif btx.tx_obj is None:
            result.not_valid.append(txid)
        else:
            inputs = {i.source_txid for i in btx.tx_obj.inputs if getattr(i, "source_txid", None)}
            if inputs - beef.txs.keys():
                missing.update(inputs - beef.txs.keys())
                result.with_missing_inputs.append(txid)
            else:
                queue.append((txid, inputs))
    return queue


def _resolve_input_chains(queue: list[tuple[str, set[str]]], valid: dict[str, None]) -> tuple[list[str], list[str]]:
    """
    Take each queued transaction out of queue once all its inputs are placed, until nothing changes.
    Returns (placed txids in order, placed txids that are not valid). A placed transaction is valid
    when it has inputs and all of them are valid. TS sorts an unproven tx without inputs as valid;
    it keeps that place in the order, but it is not valid here: nothing anchors it to a proof.
    """
    placed = dict(valid)
    chained: list[str] = []
    unanchored: list[str] = []
    progress = True
    while queue and progress:
        progress = False
        for item in list(queue):
            txid, inputs = item
            if not all(i in placed for i in inputs):
                continue
            queue.remove(item)
            placed[txid] = None
            chained.append(txid)
            progress = True
            if inputs and all(i in valid for i in inputs):
                valid[txid] = None
            else:
                unanchored.append(txid)
    return chained, unanchored


def sort_txs(beef: Beef) -> ValidationResult:
    """Reorder beef.txs into the TS Beef.sortTxs order and return the classification."""
    result = validate_transactions(beef)
    beef.txs = {txid: beef.txs[txid] for txid in result.order}
    return result


def verify_valid(beef: Beef, allow_txid_only: bool = False) -> tuple[bool, dict[int, str]]:
    """
    Validate structure and confirm that computed roots are consistent per block height.
    Returns (valid, roots_map); the roots must then be confirmed by a ChainTracker.
    """
    vr = validate_transactions(beef)
    # Any TxIDOnly entry needs allow_txid_only, even one a bump proves (TS collectTxidOnlyTxids).
    has_txid_only = any(btx.data_format == 2 and btx.tx_obj is None for btx in beef.txs.values())
    if vr.missing_inputs or vr.not_valid or vr.with_missing_inputs or (has_txid_only and not allow_txid_only):
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
