from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from bsv.merkle_path import MerklePath
from .beef import Beef, BeefTx


class ValidationResult:
    def __init__(self) -> None:
        self.valid: List[str] = []
        self.not_valid: List[str] = []
        self.txid_only: List[str] = []
        self.with_missing_inputs: List[str] = []
        self.missing_inputs: List[str] = []

    def __str__(self) -> str:
        return f"{{valid: {self.valid}, not_valid: {self.not_valid}, txid_only: {self.txid_only}, with_missing_inputs: {self.with_missing_inputs}, missing_inputs: {self.missing_inputs}}}"


def _txids_in_bumps(beef: Beef) -> Set[str]:
    s: Set[str] = set()
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

    valid_txids: Set[str] = set()
    missing_inputs: Set[str] = set()
    has_proof: List[BeefTx] = []
    txid_only: List[BeefTx] = []
    needs_validation: List[BeefTx] = []
    with_missing: List[BeefTx] = []

    for txid, btx in getattr(beef, "txs", {}).items():
        if btx.data_format == 2:
            txid_only.append(btx)
            if txid in txids_in_bumps:
                valid_txids.add(txid)
            continue
        if btx.data_format == 1:
            # verify bump index and tx presence in that bump
            ok = False
            if btx.bump_index is not None and 0 <= btx.bump_index < len(beef.bumps):
                bump = beef.bumps[btx.bump_index]
                ok = any(leaf.get("hash_str") == txid for leaf in bump.path[0])
            if ok:
                valid_txids.add(txid)
                has_proof.append(btx)
            else:
                needs_validation.append(btx)
            continue
        # data_format == 0
        if txid in txids_in_bumps:
            valid_txids.add(txid)
            has_proof.append(btx)
        elif btx.tx_obj is not None:
            inputs = getattr(btx.tx_obj, "inputs", []) or []
            has_missing = False
            for txin in inputs:
                src = getattr(txin, "source_txid", None)
                if src and src not in beef.txs:
                    missing_inputs.add(src)
                    has_missing = True
            if has_missing:
                with_missing.append(btx)
            else:
                needs_validation.append(btx)

    # iterative dependency validation
    while needs_validation:
        progress = False
        still: List[BeefTx] = []
        for btx in needs_validation:
            ok = True
            if btx.tx_obj is not None:
                for txin in btx.tx_obj.inputs:
                    src = getattr(txin, "source_txid", None)
                    if src and src not in valid_txids:
                        ok = False
                        break
            if ok and btx.tx_obj is not None:
                # Require at least one input to already be valid to anchor to a proven chain.
                # Transactions with zero inputs must have a bump to be considered valid.
                if any(getattr(txin, "source_txid", None) in valid_txids for txin in btx.tx_obj.inputs):
                    valid_txids.add(btx.txid)
                    has_proof.append(btx)
                    progress = True
                else:
                    still.append(btx)
            else:
                still.append(btx)
        if not progress:
            # remaining cannot be validated
            for btx in still:
                if btx.tx_obj is not None:
                    result.not_valid.append(btx.tx_obj.txid())
            break
        needs_validation = still

    # collect outputs
    for btx in with_missing:
        if btx.tx_obj is not None:
            result.with_missing_inputs.append(btx.tx_obj.txid())
    result.txid_only = [b.txid for b in txid_only]
    result.valid = list(valid_txids)
    result.missing_inputs = list(missing_inputs)
    return result


def verify_valid(beef: Beef, allow_txid_only: bool = False) -> Tuple[bool, Dict[int, str]]:
    """
    Validate structure and confirm that computed roots are consistent per block height.
    Returns (valid, roots_map).
    """
    vr = validate_transactions(beef)
    if vr.missing_inputs or vr.not_valid or (vr.txid_only and not allow_txid_only) or vr.with_missing_inputs:
        return False, {}

    roots: Dict[int, str] = {}

    def confirm_computed_root(mp: MerklePath, txid: str) -> bool:
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

    # all bumps must have internally consistent roots across txid leaves
    for bump in getattr(beef, "bumps", []) or []:
        try:
            for leaf in bump.path[0]:
                if leaf.get("txid") and leaf.get("hash_str"):
                    if not confirm_computed_root(bump, leaf["hash_str"]):
                        return False, {}
        except Exception:
            return False, {}

    # beefTx with bump_index must be present in specified bump
    for txid, btx in getattr(beef, "txs", {}).items():
        if btx.data_format == 1:
            if btx.bump_index is None or btx.bump_index < 0 or btx.bump_index >= len(beef.bumps):
                return False, {}
            bump = beef.bumps[btx.bump_index]
            found = any(leaf.get("hash_str") == txid for leaf in bump.path[0])
            if not found:
                return False, {}

    return True, roots


def is_valid(beef: Beef, allow_txid_only: bool = False) -> bool:
    ok, _ = verify_valid(beef, allow_txid_only=allow_txid_only)
    return ok


def get_valid_txids(beef: Beef) -> List[str]:
    return validate_transactions(beef).valid


