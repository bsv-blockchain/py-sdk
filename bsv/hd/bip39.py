import os
from contextlib import suppress
from hashlib import pbkdf2_hmac
from secrets import randbits
from typing import Dict, List, Union

from ..constants import BIP39_ENTROPY_BIT_LENGTH, BIP39_ENTROPY_BIT_LENGTH_LIST
from ..hash import sha256
from ..utils import bits_to_bytes, bytes_to_bits


class WordList:
    """
    BIP39 word list
    """

    LIST_WORDS_COUNT: int = 2048

    path = os.path.join(os.path.dirname(__file__), "wordlist")
    #
    # en
    #   https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    # zh-cn
    #   https://github.com/bitcoin/bips/blob/master/bip-0039/chinese_simplified.txt
    #
    files: dict[str, str] = {
        "en": os.path.join(path, "english.txt"),
        "zh-cn": os.path.join(path, "chinese_simplified.txt"),
    }
    wordlists: dict[str, list[str]] = {}

    @property
    @classmethod
    def wordlist(cls) -> dict[str, list[str]]:
        """Backward compatibility property for wordlist field."""
        return cls.wordlists

    @classmethod
    def load(cls) -> None:
        for lang in WordList.files:
            if not WordList.wordlists.get(lang):
                WordList.wordlists[lang] = WordList.load_wordlist(lang)

    @classmethod
    def load_wordlist(cls, lang: str = "en") -> list[str]:
        assert lang in WordList.files, f"{lang} wordlist not supported"
        with open(WordList.files[lang], encoding="utf-8") as f:
            words: list[str] = f.read().splitlines()
        assert len(words) == WordList.LIST_WORDS_COUNT, "broken wordlist file"
        return words

    @classmethod
    def get_word(cls, index: Union[int, bytes], lang: str = "en") -> str:
        WordList.load()
        assert lang in WordList.wordlists, f"{lang} wordlist not supported"
        if isinstance(index, bytes):
            index = int.from_bytes(index, "big")
        assert 0 <= index < WordList.LIST_WORDS_COUNT, "index out of range"
        return WordList.wordlists[lang][index]

    @classmethod
    def index_word(cls, word: str, lang: str = "en") -> int:
        WordList.load()
        assert lang in WordList.wordlists, f"{lang} wordlist not supported"
        with suppress(Exception):
            return WordList.wordlists[lang].index(word)
        raise ValueError("invalid word")


def mnemonic_from_entropy(entropy: Union[bytes, str, None] = None, lang: str = "en") -> str:
    if entropy:
        assert type(entropy).__name__ in ["bytes", "str"], "unsupported entropy type"
        entropy_bytes = entropy if isinstance(entropy, bytes) else bytes.fromhex(entropy)
    else:
        # random a new entropy
        entropy_bytes = randbits(BIP39_ENTROPY_BIT_LENGTH).to_bytes(BIP39_ENTROPY_BIT_LENGTH // 8, "big")
    entropy_bits: str = bytes_to_bits(entropy_bytes)
    assert len(entropy_bits) in BIP39_ENTROPY_BIT_LENGTH_LIST, "invalid entropy bit length"
    checksum_bits: str = bytes_to_bits(sha256(entropy_bytes))[: len(entropy_bits) // 32]

    bits: str = entropy_bits + checksum_bits
    indexes_bits: list[str] = [bits[i : i + 11] for i in range(0, len(bits), 11)]
    return " ".join([WordList.get_word(bits_to_bytes(index_bits), lang) for index_bits in indexes_bits])


def validate_mnemonic(mnemonic: str, lang: str = "en"):
    indexes: list[int] = [WordList.index_word(word, lang) for word in mnemonic.split(" ")]
    bits: str = "".join([bin(index)[2:].zfill(11) for index in indexes])
    entropy_bit_length: int = len(bits) * 32 // 33
    assert entropy_bit_length in BIP39_ENTROPY_BIT_LENGTH_LIST, "invalid mnemonic, bad entropy bit length"
    entropy_bits: str = bits[:entropy_bit_length]
    checksum_bits: str = bytes_to_bits(sha256(bits_to_bytes(entropy_bits)))[: entropy_bit_length // 32]
    assert bits.endswith(checksum_bits) and len(bits) == entropy_bit_length + len(
        checksum_bits
    ), "invalid mnemonic, checksum mismatch"


def seed_from_mnemonic(mnemonic: str, lang: str = "en", passphrase: str = "", prefix: str = "mnemonic") -> bytes:
    validate_mnemonic(mnemonic, lang)
    hash_name = "sha512"
    password = mnemonic.encode()
    salt = (prefix + passphrase).encode()
    iterations = 2048
    dklen = 64
    return pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
