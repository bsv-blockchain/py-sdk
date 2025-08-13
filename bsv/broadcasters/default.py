from typing import Union

from .arc import ARC, ARCConfig
from ..broadcaster import Broadcaster
from ..constants import taal_mainnet_apikey, taal_testnet_apikey


def default_broadcaster(
        is_testnet: bool = False,
        config: Union[ARCConfig, dict] = None
) -> Broadcaster:
    # Use existing broadcaster functions to get the base broadcaster
    if is_testnet:
        base_broadcaster = gorillapool_testnet_broadcaster()
    else:
        base_broadcaster = gorillapool_broadcaster()

    # If no config provided, return the base broadcaster as-is
    if config is None:
        return base_broadcaster

    # Convert dict config to ARCConfig if needed
    if isinstance(config, dict):
        config = ARCConfig(**config)

    # Create new ARC instance with the same URL but custom config
    return ARC(base_broadcaster.URL, config)


def taal_broadcaster() -> Broadcaster:
    # taal now requires an API key to broadcast transactions via ARC. If you would like to use it,
    # please visit https://taal.com/ to register for one.
    arc_config = ARCConfig(api_key=taal_mainnet_apikey)
    return ARC('https://arc.taal.com', arc_config)

def taal_testnet_broadcaster() -> Broadcaster:
    # taal now requires an API key to broadcast transactions via ARC. If you would like to use it,
    # please visit https://taal.com/ to register for one.
    arc_config = ARCConfig(api_key=taal_testnet_apikey)
    return ARC('https://arc-test.taal.com/', arc_config)

def gorillapool_broadcaster() -> Broadcaster:
    return ARC('https://arc.gorillapool.io')

def gorillapool_testnet_broadcaster() -> Broadcaster:
    return ARC('https://testnet.arc.gorillapool.io')

