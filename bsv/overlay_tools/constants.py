"""
Constants for overlay tools.

Ported from TypeScript SDK.
"""

# Default SLAP trackers for mainnet
DEFAULT_SLAP_TRACKERS = [
    # BSVA clusters
    "https://overlay-us-1.bsvb.tech",
    "https://overlay-eu-1.bsvb.tech",
    "https://overlay-ap-1.bsvb.tech",

    # Babbage primary overlay service
    "https://users.bapp.dev"
]

# Default testnet SLAP trackers
DEFAULT_TESTNET_SLAP_TRACKERS = [
    # Babbage primary testnet overlay service
    "https://testnet-users.bapp.dev"
]

# Maximum time to wait for tracker responses (in milliseconds)
MAX_TRACKER_WAIT_TIME = 5000

__all__ = [
    "DEFAULT_SLAP_TRACKERS",
    "DEFAULT_TESTNET_SLAP_TRACKERS",
    "MAX_TRACKER_WAIT_TIME"
]
