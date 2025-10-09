from typing import Union
from ..http_client import HttpClient
from ..constants import Network
from .broadcaster import Broadcaster
from .whatsonchain import WhatsOnChainBroadcaster


def default_broadcaster(network: Union[Network, str] = Network.MAINNET, http_client: HttpClient = None) -> Broadcaster:
    return WhatsOnChainBroadcaster(network=network, http_client=http_client)


__all__ = ["default_broadcaster"]
