import pytest

from bsv.base58 import base58check_encode, base58check_decode, b58_encode, b58_decode
from bsv.base58 import to_base58check, from_base58check

BITCOIN_ADDRESS = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
PUBLIC_KEY_HASH = bytes.fromhex('62e907b15cbf27d5425399ebf6f0fb50ebb88f18')
MAIN_ADDRESS_PREFIX = b'\x00'


def test_base58():
    assert b58_encode(b'\x00') == '1'
    assert b58_encode(b'\x00\x00') == '11'
    assert b58_encode(b'hello world') == 'StV1DL6CwTryKyV'

    assert b58_decode('1') == b'\x00'
    assert b58_decode('111') == b'\x00\x00\x00'
    assert b58_decode('StV1DL6CwTryKyV') == b'hello world'


def test_base58check_encode():
    assert base58check_encode(b'hello world') == '3vQB7B6MrGQZaxCuFg4oh'
    assert base58check_encode(MAIN_ADDRESS_PREFIX + PUBLIC_KEY_HASH) == BITCOIN_ADDRESS


def test_base58check_decode():
    assert base58check_decode('3vQB7B6MrGQZaxCuFg4oh') == b'hello world'
    assert base58check_decode(BITCOIN_ADDRESS) == MAIN_ADDRESS_PREFIX + PUBLIC_KEY_HASH
    with pytest.raises(ValueError, match=r'invalid base58 encoded'):
        base58check_decode('l')
    with pytest.raises(ValueError, match=r'unmatched base58 checksum'):
        base58check_decode('L')


def test_to_base58check():
    payloads = [
        bytes.fromhex('f5f2d624cfb5c3f66d06123d0829d1c9cebf770e'),
        bytes.fromhex('27b5891b01da2db74cde1689a97a2acbe23d5fb1'),
        bytes.fromhex('1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD'),
        bytes.fromhex('3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6'),
        bytes.fromhex('086eaa677895f92d4a6c5ef740c168932b5e3f44')
    ]
    encoded = [
        '1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK',
        '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3',
        '5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn',
        '5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K',
        '1mayif3H2JDC62S4N3rLNtBNRAiUUP99k',
    ]
    prefixes = [
        b'\x00',
        b'\x00',
        b'\x80',
        b'\x80',
        b'\x00',
    ]
    for i in range(len(payloads)):
        assert to_base58check(payloads[i], prefixes[i]) == encoded[i]
        assert from_base58check(encoded[i]) == (prefixes[i], payloads[i])
