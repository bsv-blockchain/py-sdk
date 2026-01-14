from typing import List, Union

from ..constants import BIP44_DERIVATION_PATH, Network
from .bip32 import Xprv, Xpub, bip32_derive_xkeys_from_xkey, bip32_derive_xprv_from_mnemonic, step_to_index


def bip44_derive_xprv_from_mnemonic(
    mnemonic: str,
    lang: str = "en",
    passphrase: str = "",
    prefix: str = "mnemonic",
    path: str = BIP44_DERIVATION_PATH,
    network: Network = Network.MAINNET,
) -> Xprv:
    """
    Derives extended private key using BIP44 format- it is a subset of BIP32.
    Inherits from BIP32, only changing the default path value.
    """
    return bip32_derive_xprv_from_mnemonic(
        mnemonic=mnemonic, lang=lang, passphrase=passphrase, prefix=prefix, path=path, network=network
    )


def bip44_derive_xprvs_from_mnemonic(
    mnemonic: str,
    index_start: Union[str, int],
    index_end: Union[str, int],
    lang: str = "en",
    passphrase: str = "",
    prefix: str = "mnemonic",
    path: str = BIP44_DERIVATION_PATH,
    change: Union[str, int] = 0,
    network: Network = Network.MAINNET,
) -> list[Xprv]:
    """
    Derive a range of extended keys from a nmemonic using BIP44 format
    """

    xprv = bip44_derive_xprv_from_mnemonic(mnemonic, lang, passphrase, prefix, path, network)
    return _derive_xkeys_from_xkey(xprv, index_start, index_end, change)


def _derive_xkeys_from_xkey(
    xkey: Union[Xprv, Xpub], index_start: Union[str, int], index_end: Union[str, int], change: Union[str, int] = 0
) -> list[Union[Xprv, Xpub]]:
    """
    this function is internal use only within bip44 module
    """
    change_xkey = xkey.ckd(step_to_index(change))
    return [change_xkey.ckd(i) for i in range(step_to_index(index_start), step_to_index(index_end))]


# [DEPRECATED]
def derive_xkeys_from_xkey(
    xkey: Union[Xprv, Xpub], index_start: Union[str, int], index_end: Union[str, int], change: Union[str, int] = 0
) -> list[Union[Xprv, Xpub]]:
    """
    [DEPRECATED] Use bip32_derive_xkeys_from_xkey instead.
      This function name is kept for backward compatibility.
    """
    return _derive_xkeys_from_xkey(xkey=xkey, index_start=index_start, index_end=index_end, change=change)


# [DEPRECATED]
def derive_xprv_from_mnemonic(
    mnemonic: str,
    lang: str = "en",
    passphrase: str = "",
    prefix: str = "mnemonic",
    path: str = BIP44_DERIVATION_PATH,
    network: Network = Network.MAINNET,
) -> Xprv:
    """
    [DEPRECATED] Use bip44_derive_xprv_from_mnemonic instead.
      This function name is kept for backward compatibility.
    """
    return bip44_derive_xprv_from_mnemonic(
        mnemonic=mnemonic, lang=lang, passphrase=passphrase, prefix=prefix, path=path, network=network
    )


# [DEPRECATED]
def derive_xprvs_from_mnemonic(
    mnemonic: str,
    index_start: Union[str, int],
    index_end: Union[str, int],
    lang: str = "en",
    passphrase: str = "",
    prefix: str = "mnemonic",
    path: str = BIP44_DERIVATION_PATH,
    change: Union[str, int] = 0,
    network: Network = Network.MAINNET,
) -> list[Xprv]:
    """
    [DEPRECATED] Use bip44_derive_xprvs_from_mnemonic instead.
      This function name is kept for backward compatibility.
    """
    return bip44_derive_xprvs_from_mnemonic(
        mnemonic=mnemonic,
        index_start=index_start,
        index_end=index_end,
        lang=lang,
        passphrase=passphrase,
        prefix=prefix,
        path=path,
        change=change,
        network=network,
    )
