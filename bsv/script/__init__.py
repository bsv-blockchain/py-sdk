from .bip276 import (
    BIP276,
    CURRENT_VERSION,
    NETWORK_MAINNET,
    NETWORK_TESTNET,
    PREFIX_SCRIPT,
    PREFIX_TEMPLATE,
    InvalidBIP276Format,
    InvalidChecksum,
    decode_bip276,
    decode_script,
    decode_template,
    encode_bip276,
    encode_script,
    encode_template,
)
from .script import Script, ScriptChunk
from .type import P2PK, P2PKH, BareMultisig, OpReturn, ScriptTemplate, Unknown, to_unlock_script_template
from .unlocking_template import UnlockingScriptTemplate


# Lazy import for Spend to avoid circular dependency
# (Spend imports TransactionInput, which imports Script from here)
def __getattr__(name):
    if name == "Spend":
        from .spend import Spend

        return Spend
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
