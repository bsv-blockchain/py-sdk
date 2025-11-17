"""
Script flags for interpreter execution.

Ported from go-sdk/script/interpreter/scriptflag/scriptflag.go
"""

from enum import Flag as EnumFlag


class Flag(int):
    """Flag is a bitmask defining additional operations or tests for script execution."""

    # Bip16 defines whether the bip16 threshold has passed
    BIP16 = 1 << 0

    # StrictMultiSig defines whether to verify the stack item used by CHECKMULTISIG
    STRICT_MULTISIG = 1 << 1

    # DiscourageUpgradableNops defines whether to verify NOP1 through NOP10
    DISCOURAGE_UPGRADABLE_NOPS = 1 << 2

    # VerifyCheckLockTimeVerify defines whether to verify locktime
    VERIFY_CHECK_LOCK_TIME_VERIFY = 1 << 3

    # VerifyCheckSequenceVerify defines whether to allow execution pathways
    VERIFY_CHECK_SEQUENCE_VERIFY = 1 << 4

    # VerifyCleanStack defines that the stack must contain only one element
    VERIFY_CLEAN_STACK = 1 << 5

    # VerifyDERSignatures defines that signatures are required to comply with DER
    VERIFY_DER_SIGNATURES = 1 << 6

    # VerifyLowS defines that signatures S value is <= order / 2
    VERIFY_LOW_S = 1 << 7

    # VerifyMinimalData defines that signatures must use smallest push operator
    VERIFY_MINIMAL_DATA = 1 << 8

    # VerifyNullFail defines that signatures must be empty if CHECKSIG fails
    VERIFY_NULL_FAIL = 1 << 9

    # VerifySigPushOnly defines that signature scripts must contain only pushed data
    VERIFY_SIG_PUSH_ONLY = 1 << 10

    # EnableSighashForkID defined that signature scripts have forkid enabled
    ENABLE_SIGHASH_FORK_ID = 1 << 11

    # VerifyStrictEncoding defines strict encoding requirements
    VERIFY_STRICT_ENCODING = 1 << 12

    # VerifyBip143SigHash defines BIP143 signature hashing
    VERIFY_BIP143_SIGHASH = 1 << 13

    # UTXOAfterGenesis defines that the utxo was created after genesis
    UTXO_AFTER_GENESIS = 1 << 14

    # VerifyMinimalIf defines enforcement of minimal conditional statements
    VERIFY_MINIMAL_IF = 1 << 15

    def has_flag(self, flag: "Flag") -> bool:
        """Check if this flag has the passed flag set."""
        return bool(self & flag)

    def has_any(self, *flags: "Flag") -> bool:
        """Check if any of the passed flags are present."""
        return any(self.has_flag(flag) for flag in flags)

    def add_flag(self, flag: "Flag") -> "Flag":
        """Add the passed flag to this flag."""
        return Flag(self | flag)

    def remove_flag(self, flag: "Flag") -> "Flag":
        """Remove the passed flag from this flag."""
        return Flag(self & ~flag)

