from typing import Optional, Union

from ..constants import Network
from .arc import ARC, ARCConfig
from .broadcaster import Broadcaster


def default_broadcaster(is_testnet: bool = False, config: Optional[ARCConfig] = None) -> Broadcaster:
    """
    Create a default ARC broadcaster for the specified network.

    :param is_testnet: Whether to use testnet (default: False for mainnet)
    :param config: Optional ARC configuration
    :returns: ARC broadcaster instance
    """
    url = "https://testnet.arc.gorillapool.io" if is_testnet else "https://arc.gorillapool.io"
    return ARC(url, config or ARCConfig())


__all__ = ["default_broadcaster"]
