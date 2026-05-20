from ..chaintracker import ChainTracker
from .whatsonchain import WhatsOnChainTracker


def default_chain_tracker() -> ChainTracker:
    return WhatsOnChainTracker()
