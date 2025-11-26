"""bsv Python SDK package initializer.

Provides backward-compatible exports while maintaining modular structure.
You can import commonly used classes directly:
    from bsv import Transaction, PrivateKey, PublicKey
    from bsv.auth.peer import Peer
"""

# Phase 1: Safe imports - constants, hash, curve (no dependencies)
from .constants import *
from .hash import *
from .curve import *

# Base58 encoding/decoding functions
from .base58 import base58check_encode, base58check_decode, b58_encode, b58_decode, to_base58check, from_base58check

# Step 2: HTTP client
from .http_client import HttpClient, default_http_client

# Step 3: Keys
from .keys import PrivateKey, PublicKey, verify_signed_text

# Step 4: Data structures
from .merkle_path import MerklePath, MerkleLeaf
from .encrypted_message import *
from .signed_message import *
from .transaction_input import TransactionInput
from .transaction_output import TransactionOutput
from .transaction_preimage import *

# Step 5: Transaction
from .transaction import Transaction, InsufficientFunds

# Phase 3: Wildcard imports (one at a time, testing for circular imports)
# Step 6.1: broadcaster (base classes)
from .broadcaster import *
# Step 6.2: broadcasters (implementations)
from .broadcasters import *
# Step 6.3: chaintracker (base classes)
from .chaintracker import *
# Step 6.4: chaintrackers (implementations)
from .chaintrackers import *
# Step 6.5: fee_model (base classes)
from .fee_model import *
# Step 6.6: fee_models (implementations)
from .fee_models import *
# Step 6.7: script
from .script import *
# Step 6.8: utils
from .utils import *

__version__ = '1.0.12'
