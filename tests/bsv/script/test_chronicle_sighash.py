from bsv.constants import SIGHASH


def test_sighash_chronicle_constant():
    assert SIGHASH.CHRONICLE == 0x20


def test_sighash_all_forkid_chronicle():
    assert SIGHASH.ALL_FORKID_CHRONICLE == 0x61


def test_sighash_validate_accepts_chronicle_variants():
    assert SIGHASH.validate(0x61)  # ALL_FORKID_CHRONICLE
    assert SIGHASH.validate(0x62)  # NONE_FORKID_CHRONICLE
    assert SIGHASH.validate(0x63)  # SINGLE_FORKID_CHRONICLE
    assert SIGHASH.validate(0xE1)  # ALL_ANYONECANPAY_FORKID_CHRONICLE
    assert SIGHASH.validate(0xE2)  # NONE_ANYONECANPAY_FORKID_CHRONICLE
    assert SIGHASH.validate(0xE3)  # SINGLE_ANYONECANPAY_FORKID_CHRONICLE


def test_sighash_validate_still_accepts_forkid():
    assert SIGHASH.validate(0x41)  # ALL_FORKID
    assert SIGHASH.validate(0x42)  # NONE_FORKID
    assert SIGHASH.validate(0x43)  # SINGLE_FORKID


def test_sighash_validate_rejects_invalid():
    assert not SIGHASH.validate(0x00)
    assert not SIGHASH.validate(0x01)  # ALL without FORKID
    assert not SIGHASH.validate(0xFF)
