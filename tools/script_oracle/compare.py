"""Compare py-sdk's script VMs with GoBDK, the bitcoin-sv node interpreter that
Teranode validates transactions with.

    python tools/script_oracle/compare.py

builds the GoBDK oracle from this directory (Go is required) and checks the
fixed cases. Each case is a transaction spending one output. Its script is
checked by the Python VM, the C VM (when the extension is built) and GoBDK
under consensus and policy rules at a post-Chronicle height.

    python tools/script_oracle/compare.py --fuzz 20000 --seed 1 2 3

runs seeded random scripts instead of the fixed cases.

A difference fails the run (exit status 1) when it is a consensus difference
(py-sdk accepts a spend the node rejects in a block, or rejects one the node
accepts under both rule sets) or when the Python and C VMs disagree.
Policy-only differences are listed but do not fail: py-sdk does not model the
mempool's policy limits. Known differences are listed with their reason.
"""

import argparse
import json
import random
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from bsv.constants import SIGHASH, OpCode
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.spend import _USE_NATIVE_VM, Spend
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.transaction_preimage import tx_preimage
from bsv.utils import encode_pushdata

BLOCK_HEIGHT = 950_000  # after Chronicle (943,816 on mainnet)
UTXO_HEIGHT = BLOCK_HEIGHT - 1

KEY = PrivateKey(1001)
OTHER_KEY = PrivateKey(1002)
PUBKEY = KEY.public_key().serialize()


@dataclass
class Case:
    name: str
    tx: Transaction
    verdicts: dict = field(default_factory=dict)  # backend -> (ok, error)
    known: str = ""  # why a difference here is expected for now


def _push(data: bytes) -> bytes:
    return encode_pushdata(data)


P2PK = _push(PUBKEY) + OpCode.OP_CHECKSIG


def _spending_tx(locking: bytes, version: int) -> Transaction:
    source = Transaction([], [TransactionOutput(locking_script=Script(locking), satoshis=10_000)])
    spend = TransactionInput(source_transaction=source, source_output_index=0, unlocking_script=Script())
    return Transaction(
        [spend],
        [TransactionOutput(locking_script=Script(OpCode.OP_FALSE + OpCode.OP_RETURN), satoshis=9_000)],
        version=version,
    )


def _sign(tx: Transaction, key: PrivateKey, script_code: bytes, sighash: int = SIGHASH.ALL_FORKID) -> bytes:
    """A signature for input 0 that commits to `script_code` as its scriptCode."""
    spent = tx.inputs[0]
    inp = TransactionInput(
        source_txid=spent.source_txid,
        source_output_index=spent.source_output_index,
        unlocking_script=Script(),
        sequence=spent.sequence,
        sighash=SIGHASH(sighash),
    )
    inp.locking_script = Script(script_code)
    inp.satoshis = spent.satoshis
    return key.sign(tx_preimage(0, [inp], tx.outputs, tx.version, tx.locktime)) + bytes([sighash])


def case(name: str, locking: bytes, unlocking, version: int = 2, known: str = "") -> Case:
    """`unlocking(tx)` returns the unlocking script bytes for the spending tx."""
    tx = _spending_tx(locking, version)
    tx.inputs[0].unlocking_script = Script(unlocking(tx))
    return Case(name, tx, known=known)


def signed_p2pk(
    name: str, head: bytes, tail: bytes, script_code=None, version: int = 2, sighash: int = SIGHASH.ALL_FORKID
):
    locking = head + P2PK + tail
    code = locking if script_code is None else script_code
    return case(name, locking, lambda tx: _push(_sign(tx, KEY, code, sighash)), version)


def cases() -> list[Case]:
    out = []
    # The scriptCode is the locking script's bytes (#247): a correct signature
    # passes and one over a minimally re-encoded script fails.
    for label, head, tail, rewritten_head, rewritten_tail in [
        ("op-return-tail", b"", bytes.fromhex("6a0500000000000000"), b"", bytes.fromhex("080500000000000000")),
        ("push-01-05", bytes.fromhex("010575"), b"", bytes.fromhex("5575"), b""),
        ("pushdata1-short", bytes.fromhex("4c03aabbcc75"), b"", bytes.fromhex("03aabbcc75"), b""),
    ]:
        for version in (1, 2):
            out.append(signed_p2pk(f"{label} v{version} sig-over-script", head, tail, version=version))
            out.append(
                signed_p2pk(
                    f"{label} v{version} sig-over-rewritten",
                    head,
                    tail,
                    script_code=rewritten_head + P2PK + rewritten_tail,
                    version=version,
                )
            )

    out.append(signed_p2pk("p2pk", b"", b""))
    out.append(_codeseparator())

    # Numeric operands. The unlocking script is empty; the locking script must
    # leave a single true value.
    for name, asm_hex, version in [
        # OP_RSHIFTNUM fails above INT_MAX, whatever the value.
        ("rshiftnum by 2^31-1", "51" + "04ffffff7f" + "b7" + "0087", 2),
        ("rshiftnum by 2^31", "51" + "050000008000" + "b7" + "0087", 2),
        # Counts are script numbers: `01 00` is a non-minimal zero.
        ("pick count 0100", "51" + "0100" + "79" + "75", 1),
        ("roll count 0100", "51" + "0100" + "7a", 1),
        ("lshift count 0100", "02ff00" + "0100" + "98" + "02ff00" + "87", 1),
        ("rshift count 0100", "02ff00" + "0100" + "99" + "02ff00" + "87", 1),
        # The value of OP_NUM2BIN is normalised, not read as a script number.
        ("num2bin value 0100", "020100" + "52" + "80" + "020100" + "87", 1),
    ]:
        out.append(case(name, bytes.fromhex(asm_hex), lambda tx: b"", version))

    # Sighash types: Chronicle routes FORKID|CHRONICLE and no-FORKID to OTDA.
    for sighash in (0x61, 0x01, 0x02, 0x03):  # ALL|FORKID|CHRONICLE, then no FORKID
        out.append(signed_p2pk(f"p2pk sighash 0x{sighash:02x}", b"", b"", sighash=sighash))

    # Removing a signature without FORKID from the scriptCode (FindAndDelete).
    legacy = bytes.fromhex("300602010102010101")
    multisig = (
        OpCode.OP_2 + _push(OTHER_KEY.public_key().serialize()) + _push(PUBKEY) + OpCode.OP_2 + OpCode.OP_CHECKMULTISIG
    )
    for label, push, sig in [
        ("09<sig>", bytes.fromhex("09") + legacy, legacy),
        ("4c09<sig>", bytes.fromhex("4c09") + legacy, legacy),
        ("0105", bytes.fromhex("0105"), b"\x05"),
        ("55", bytes.fromhex("55"), b"\x05"),
    ]:
        locking = push + OpCode.OP_DROP + multisig + OpCode.OP_NOT
        out.append(
            case(
                f"find-and-delete {label}",
                locking,
                lambda tx, locking=locking, sig=sig: OpCode.OP_0 + _push(sig) + _push(_sign(tx, KEY, locking)),
            )
        )
    tail_locking = multisig + OpCode.OP_NOT + OpCode.OP_RETURN + _push(legacy)
    for label, code in [("full", tail_locking), ("cleaned", multisig + OpCode.OP_NOT + OpCode.OP_RETURN)]:
        out.append(
            case(
                f"find-and-delete after OP_RETURN, sig over {label}",
                tail_locking,
                lambda tx, code=code: OpCode.OP_0 + _push(legacy) + _push(_sign(tx, KEY, code)),
                known="the node removes a signature push after a top-level OP_RETURN; py-sdk keeps that tail as one chunk",
            )
        )
    return out


def _codeseparator() -> Case:
    locking = _push(PUBKEY) + OpCode.OP_CODESEPARATOR + OpCode.OP_CHECKSIG
    return case("codeseparator", locking, lambda tx: _push(_sign(tx, KEY, OpCode.OP_CHECKSIG)))


def run_py(c: Case) -> None:
    inp = c.tx.inputs[0]
    params = {
        "sourceTXID": inp.source_txid,
        "sourceOutputIndex": inp.source_output_index,
        "sourceSatoshis": inp.satoshis,
        "lockingScript": inp.locking_script,
        "transactionVersion": c.tx.version,
        "otherInputs": [],
        "outputs": c.tx.outputs,
        "inputIndex": 0,
        "unlockingScript": inp.unlocking_script,
        "inputSequence": inp.sequence,
        "lockTime": c.tx.locktime,
    }
    for backend in ["python", "native"] if _USE_NATIVE_VM else ["python"]:
        spend = Spend(params)
        try:
            ok = spend._validate_native() if backend == "native" else spend._validate_python()
            c.verdicts[backend] = (bool(ok), "")
        except Exception as e:  # a script error is a rejection
            c.verdicts[backend] = (False, str(e).splitlines()[0])


def run_oracle(all_cases: list[Case]) -> None:
    requests = "".join(
        json.dumps(
            {"id": str(i), "ef": c.tx.to_ef().hex(), "utxo_heights": [UTXO_HEIGHT], "block_height": BLOCK_HEIGHT}
        )
        + "\n"
        for i, c in enumerate(all_cases)
    )
    with tempfile.TemporaryDirectory() as tmp:
        oracle = str(Path(tmp) / "script_oracle")
        subprocess.run(["go", "build", "-C", str(Path(__file__).parent), "-o", oracle, "."], check=True)
        lines = subprocess.run([oracle], input=requests, capture_output=True, text=True, check=True).stdout.splitlines()
    for line in lines:
        r = json.loads(line)
        if r.get("error"):
            raise RuntimeError(f"oracle could not check case {r.get('id')}: {r['error']}")
        c = all_cases[int(r["id"])]
        for mode in ("consensus", "policy"):
            c.verdicts[f"node-{mode}"] = (r[mode]["ok"], r[mode].get("err", ""))


# Opcodes the fuzzer draws from: everything that is not a push of data,
# including disabled/invalid ones, flow control and OP_RETURN. Most draws come
# from COMMON_OPS (numbers, flow control, stack, splice, bitwise, arithmetic,
# hashes) so that scripts get past their first few opcodes.
FUZZ_OPS = list(range(0x4F, 0x100))
COMMON_OPS = [
    0x4F,  # OP_1NEGATE
    *range(0x51, 0x61),  # OP_1..OP_16
    *range(0x63, 0x6A),  # OP_IF..OP_RETURN
    *range(0x6B, 0x83),  # stack, splice, OP_INVERT
    *range(0x87, 0x89),  # OP_EQUAL, OP_EQUALVERIFY
    *range(0x8B, 0xAC),  # arithmetic, hashes
]


def _random_push(rng: random.Random) -> bytes:
    n = rng.choice([0, 1, 1, 1, 2, 3, 4, 5, 8, 9, 20, 33, 76])
    data = bytes([rng.choice([0, 1, 5, 16, 17, 0x7F, 0x80, 0x81, 0xFF])]) if n == 1 else rng.randbytes(n)
    style = rng.random()
    if style < 0.7 or n == 0:
        return encode_pushdata(data)  # minimal
    if style < 0.85 and n <= 75:
        return bytes([n]) + data
    if style < 0.95 and n <= 255:
        return OpCode.OP_PUSHDATA1 + bytes([n]) + data
    return OpCode.OP_PUSHDATA2 + n.to_bytes(2, "little") + data


def _random_script(rng: random.Random, length: int, push_only: bool) -> bytes:
    return b"".join(
        (
            _random_push(rng)
            if push_only or rng.random() < 0.45
            else bytes([rng.choice(COMMON_OPS if rng.random() < 0.8 else FUZZ_OPS)])
        )
        for _ in range(length)
    )


def fuzz_cases(count: int, seed: int) -> list[Case]:
    rng = random.Random(seed)
    out = []
    for i in range(count):
        version = rng.choice([1, 2])
        locking = _random_script(rng, rng.randint(1, 12), push_only=False)
        unlocking = _random_script(rng, rng.randint(0, 6), push_only=version == 1 or rng.random() < 0.7)
        out.append(case(f"fuzz {seed}:{i} v{version}", locking, lambda tx, u=unlocking: u, version))
    return out


FAILING = ("split", "consensus")


def kind(c: Case, backends: list[str]) -> str | None:
    """How py-sdk differs from the node for this case, or None if it agrees."""
    verdicts = {c.verdicts[b][0] for b in backends}
    policy, consensus = c.verdicts["node-policy"][0], c.verdicts["node-consensus"][0]
    if len(verdicts) > 1:
        found = "split"  # the Python and C VMs disagree
    elif verdicts == {policy}:
        return None
    elif verdicts == {True} and consensus:
        found = "policy"  # only the node's policy rejects it
    else:
        found = "consensus"
    return "known" if c.known and found in FAILING else found


def report_table(all_cases: list[Case], backends: list[str]) -> dict:
    header = ["case", *backends, "node-policy", "node-consensus"]
    print("\t".join(header))
    counts: dict[str, int] = {}
    for c in all_cases:
        k = kind(c, backends)
        if k:
            counts[k] = counts.get(k, 0) + 1
        cells = ["ok" if c.verdicts[h][0] else "REJECT" for h in header[1:]]
        print("\t".join([f"{k or '':10s}{c.name}", *cells]))
        if k:
            _print_details(c, header[1:])
    return counts


def _print_details(c: Case, columns: list[str]) -> None:
    if c.known:
        print(f"\t\tknown: {c.known}")
    for h in columns:
        if c.verdicts[h][1]:
            print(f"\t\t{h}: {c.verdicts[h][1][:160]}")


def report_groups(all_cases: list[Case], backends: list[str]) -> dict:
    """Differences grouped by kind, verdicts and errors, with one example each."""
    groups: dict[tuple, list[Case]] = {}
    for c in all_cases:
        k = kind(c, backends)
        if not k:
            continue
        py = "/".join("ok" if c.verdicts[b][0] else "REJECT" for b in backends)
        py_err = next((c.verdicts[b][1] for b in backends if c.verdicts[b][1]), "")
        node_err = c.verdicts["node-consensus"][1] or c.verdicts["node-policy"][1]
        groups.setdefault((k, py, _shorten(py_err), _shorten(node_err)), []).append(c)
    counts: dict[str, int] = {}
    for key, members in sorted(groups.items(), key=lambda kv: (kv[0][0] not in FAILING, -len(kv[1]))):
        counts[key[0]] = counts.get(key[0], 0) + len(members)
        ex = members[0]
        inp = ex.tx.inputs[0]
        print(f"{len(members):5d}  {key[0]}: py[{'/'.join(backends)}]={key[1]}")
        print(f"       py: {key[2]}\n       node: {key[3]}")
        print(f"       e.g. {ex.name} unlock={inp.unlocking_script.hex()} lock={inp.locking_script.hex()}")
    return counts


def _shorten(err: str) -> str:
    return err.split(" (", maxsplit=1)[0][:110]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--fuzz", type=int, metavar="N", help="run N random scripts per seed instead of the fixed cases"
    )
    parser.add_argument("--seed", type=int, nargs="+", default=[1])
    args = parser.parse_args(argv[1:])

    all_cases = [c for s in args.seed for c in fuzz_cases(args.fuzz, s)] if args.fuzz else cases()
    for c in all_cases:
        run_py(c)
    run_oracle(all_cases)

    backends = ["python", "native"] if _USE_NATIVE_VM else ["python"]
    counts = (report_groups if args.fuzz else report_table)(all_cases, backends)
    summary = ", ".join(f"{n} {k}" for k, n in sorted(counts.items())) or "no differences"
    print(f"\n{len(all_cases)} cases on {'/'.join(backends)}: {summary}")
    return 1 if any(k in FAILING for k in counts) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
