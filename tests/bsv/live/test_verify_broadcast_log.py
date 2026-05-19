"""Unit tests for :mod:`verify_broadcast_log` log parsing (no network)."""

import sys
from pathlib import Path

_LIVE_DIR = Path(__file__).resolve().parent
if str(_LIVE_DIR) not in sys.path:
    sys.path.insert(0, str(_LIVE_DIR))

from verify_broadcast_log import parse_broadcast_log

TID_A = "a" * 64
TID_B = "b" * 64
TID_M = "f" * 64


def test_parse_testnet_explorer_url():
    log = f"""
  -> https://test.whatsonchain.com/tx/{TID_A}
"""
    got = parse_broadcast_log(log)
    assert got[TID_A.lower()] == "testnet"


def test_parse_mainnet_explorer_url():
    log = f"""
  -> https://whatsonchain.com/tx/{TID_B}
"""
    got = parse_broadcast_log(log)
    assert got[TID_B.lower()] == "mainnet"


def test_parse_fan_out_line():
    log = f"""
  -> Fan-out: https://test.whatsonchain.com/tx/{TID_A}
"""
    got = parse_broadcast_log(log)
    assert got[TID_A.lower()] == "testnet"


def test_parse_success_txid_non_mock():
    log = f"""
  [ARC tx] status=success txid={TID_A}
"""
    got = parse_broadcast_log(log, default_network="testnet")
    assert got[TID_A.lower()] == "testnet"


def test_parse_skips_mock_broadcaster_success_line():
    log = f"""
  [MockBroadcaster tx] status=success txid={TID_M}
  [ARC tx] status=success txid={TID_A}
  -> https://test.whatsonchain.com/tx/{TID_A}
"""
    got = parse_broadcast_log(log)
    assert TID_M.lower() not in got
    assert got[TID_A.lower()] == "testnet"


def test_explorer_url_overrides_default_network_for_success_line():
    """URL pass assigns network; success-only line uses default."""
    log = f"""
  [ARC tx] status=success txid={TID_B}
  -> https://test.whatsonchain.com/tx/{TID_B}
"""
    got = parse_broadcast_log(log, default_network="mainnet")
    assert got[TID_B.lower()] == "testnet"
