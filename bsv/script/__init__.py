from .script import Script, ScriptChunk
from .type import ScriptTemplate, Unknown, P2PKH, OpReturn, P2PK, BareMultisig, to_unlock_script_template
from .unlocking_template import UnlockingScriptTemplate
from .bip276 import (
    BIP276,
    encode_bip276,
    decode_bip276,
    encode_script,
    encode_template,
    decode_script,
    decode_template,
    InvalidBIP276Format,
    InvalidChecksum,
    PREFIX_SCRIPT,
    PREFIX_TEMPLATE,
    NETWORK_MAINNET,
    NETWORK_TESTNET,
    CURRENT_VERSION,
)

# Lazy import for Spend to avoid circular dependency
# (Spend imports TransactionInput, which imports Script from here)
def __getattr__(name):
    if name == "Spend":
        from .spend import Spend
        return Spend
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
