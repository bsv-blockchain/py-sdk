import hashlib

import ecdsa
import pytest

from bsv.constants import Network
from bsv.curve import Point
from bsv.hash import sha256
from bsv.keys import PrivateKey, PublicKey, verify_signed_text
from bsv.utils import text_digest, unstringify_ecdsa_recoverable
from .test_transaction import digest1, digest2, digest3

private_key_hex = 'f97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a4b62'
private_key_bytes = bytes.fromhex(private_key_hex)
private_key_int = int(private_key_hex, 16)
private_key = PrivateKey(private_key_int)

x = 'e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789'
y = '97693d32c540ac253de7a3dc73f7e4ba7b38d2dc1ecc8e07920b496fb107d6b2'
point = Point(int(x, 16), int(y, 16))
public_key = PublicKey(point)

address_compressed_main = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
address_uncompressed_main = '1BVHzn1J8VZWRuVWbPrj2Szx1j7hHdt5zP'
address_compressed_test = 'mqBuyzdHfD87VfgxaYeM9pex3sJn4ihYHY'
address_uncompressed_test = 'mr1FHq6GwWzmD1y8Jxq6rNDGsiiQ9caF7r'


def test_public_key():
    public_key_compressed = f'02{x}'
    public_key_uncompressed = f'04{x}{y}'

    assert public_key.point() == point
    assert public_key.hex() == public_key_compressed
    assert public_key.hex(compressed=True) == public_key_compressed
    assert public_key.hex(compressed=False) == public_key_uncompressed

    assert public_key.address() == address_compressed_main
    assert public_key.address(compressed=True, network=Network.MAINNET) == address_compressed_main
    assert public_key.address(compressed=False, network=Network.MAINNET) == address_uncompressed_main
    assert public_key.address(compressed=True, network=Network.TESTNET) == address_compressed_test
    assert public_key.address(compressed=False, network=Network.TESTNET) == address_uncompressed_test

    assert PublicKey(public_key_compressed) == public_key
    assert PublicKey(public_key_compressed).address() == address_compressed_main

    assert PublicKey(public_key_uncompressed) == public_key
    assert PublicKey(public_key_uncompressed).address() == address_uncompressed_main

    assert PublicKey(bytes.fromhex(public_key_compressed)) == public_key

    with pytest.raises(TypeError, match=r'unsupported public key type'):
        # noinspection PyTypeChecker
        PublicKey(1.23)


def test_private_key():
    assert private_key == PrivateKey.from_hex(private_key_hex)
    assert private_key.public_key() == public_key
    assert private_key.hex() == private_key_hex
    assert private_key.serialize() == private_key_bytes
    assert private_key.int() == private_key_int

    priv_key_wif_compressed_main = 'L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9'
    priv_key_wif_uncompressed_main = '5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U'
    priv_key_wif_compressed_test = 'cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA'
    priv_key_wif_uncompressed_test = '93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me'

    assert private_key.wif() == priv_key_wif_compressed_main
    assert private_key.wif(compressed=True, network=Network.MAINNET) == priv_key_wif_compressed_main
    assert private_key.wif(compressed=False, network=Network.MAINNET) == priv_key_wif_uncompressed_main
    assert private_key.wif(compressed=True, network=Network.TESTNET) == priv_key_wif_compressed_test
    assert private_key.wif(compressed=False, network=Network.TESTNET) == priv_key_wif_uncompressed_test

    assert PrivateKey(private_key_bytes) == private_key
    assert PrivateKey(priv_key_wif_compressed_main) == private_key
    assert PrivateKey(priv_key_wif_uncompressed_main) == private_key
    assert PrivateKey(priv_key_wif_compressed_test) == private_key
    assert PrivateKey(priv_key_wif_uncompressed_test) == private_key

    assert PrivateKey(private_key_bytes).wif() == priv_key_wif_compressed_main
    assert PrivateKey(private_key_bytes).address() == address_compressed_main

    assert PrivateKey(priv_key_wif_compressed_main).wif() == priv_key_wif_compressed_main
    assert PrivateKey(priv_key_wif_compressed_main).address() == address_compressed_main

    assert PrivateKey(priv_key_wif_uncompressed_main).wif() == priv_key_wif_uncompressed_main
    assert PrivateKey(priv_key_wif_uncompressed_main).address() == address_uncompressed_main

    assert PrivateKey(priv_key_wif_compressed_test).wif() == priv_key_wif_compressed_test
    assert PrivateKey(priv_key_wif_compressed_test).address() == address_compressed_test

    assert PrivateKey(priv_key_wif_uncompressed_test).wif() == priv_key_wif_uncompressed_test
    assert PrivateKey(priv_key_wif_uncompressed_test).address() == address_uncompressed_test

    with pytest.raises(TypeError, match=r'unsupported private key type'):
        # noinspection PyTypeChecker
        PrivateKey(1.23)


def test_verify():
    # https://whatsonchain.com/tx/4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb
    der: bytes = bytes.fromhex('304402207e2c6eb8c4b20e251a71c580373a2836e209c50726e5f8b0f4f59f8af00eee1a'
                               '022019ae1690e2eb4455add6ca5b86695d65d3261d914bc1d7abb40b188c7f46c9a5')
    assert private_key.verify(der, digest1)

    # https://whatsonchain.com/tx/c04bbd007ad3987f9b2ea8534175b5e436e43d64471bf32139b5851adf9f477e
    der: bytes = bytes.fromhex('3043022053b1f5a28a011c60614401eeef88e49c676a098ce36d95ded1b42667f40efa37'
                               '021f4de6703f8c74b0ce5dad617c00d1fb99580beb7972bf681e7215911c3648de')
    assert private_key.verify(der, digest2)
    der: bytes = bytes.fromhex('3045022100b9f293781ae1e269591df779dbadb41b9971d325d7b8f83d883fb55f2cb3ff76'
                               '02202fe1e822628d85b0f52966602d0e153be411980d54884fa48a41d6fc32b4e9f5')
    assert private_key.verify(der, digest3)


def test_sign():
    # ecdsa
    message: bytes = b'hello world'
    der: bytes = private_key.sign(message)
    vk = ecdsa.VerifyingKey.from_string(public_key.serialize(), curve=ecdsa.SECP256k1)
    assert vk.verify(signature=der, data=sha256(message), hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der)

    # recoverable ecdsa
    text = 'hello world'
    address, signature = private_key.sign_text(text)
    assert verify_signed_text(text, address, signature)

    message: bytes = text_digest(text)
    serialized_recoverable, _ = unstringify_ecdsa_recoverable(signature)
    assert private_key.verify_recoverable(serialized_recoverable, message)

    address, signature = PrivateKey('5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U').sign_text(text)
    assert verify_signed_text(text, address, signature)


def test_ecdh():
    alice, bob = PrivateKey(), PrivateKey()
    assert alice.derive_shared_secret(bob.public_key()) == bob.derive_shared_secret(alice.public_key())
    ephemeral = PrivateKey()
    assert alice.public_key().derive_shared_secret(ephemeral) == alice.derive_shared_secret(ephemeral.public_key())


def test_encryption():
    plain = 'hello world'
    encrypted = ('QklFMQPkjNG3xxnfRv7oUDjUYPH2VN3VFrcglCcwmeYpJpsjRKnfl/XsS+dOg'
                 'ocRV6JKVHkfUZAKIHDo7vwxjv/BPkV5EA2Dl4RJ6d/jpWwgGdFBYA==')
    assert private_key.decrypt_text(encrypted) == plain
    assert private_key.decrypt_text(public_key.encrypt_text(plain)) == plain


def test_brc42():
    # https://github.com/bitcoin-sv/BRCs/blob/master/key-derivation/0042.md#test-vectors
    private_key_derivation_cases = [{
        'senderPublicKey': '033f9160df035156f1c48e75eae99914fa1a1546bec19781e8eddb900200bff9d1',
        'recipientPrivateKey': '6a1751169c111b4667a6539ee1be6b7cd9f6e9c8fe011a5f2fe31e03a15e0ede',
        'invoiceNumber': 'f3WCaUmnN9U=',
        'privateKey': '761656715bbfa172f8f9f58f5af95d9d0dfd69014cfdcacc9a245a10ff8893ef'
    }, {
        'senderPublicKey': '027775fa43959548497eb510541ac34b01d5ee9ea768de74244a4a25f7b60fae8d',
        'recipientPrivateKey': 'cab2500e206f31bc18a8af9d6f44f0b9a208c32d5cca2b22acfe9d1a213b2f36',
        'invoiceNumber': '2Ska++APzEc=',
        'privateKey': '09f2b48bd75f4da6429ac70b5dce863d5ed2b350b6f2119af5626914bdb7c276'
    }, {
        'senderPublicKey': '0338d2e0d12ba645578b0955026ee7554889ae4c530bd7a3b6f688233d763e169f',
        'recipientPrivateKey': '7a66d0896f2c4c2c9ac55670c71a9bc1bdbdfb4e8786ee5137cea1d0a05b6f20',
        'invoiceNumber': 'cN/yQ7+k7pg=',
        'privateKey': '7114cd9afd1eade02f76703cc976c241246a2f26f5c4b7a3a0150ecc745da9f0'
    }, {
        'senderPublicKey': '02830212a32a47e68b98d477000bde08cb916f4d44ef49d47ccd4918d9aaabe9c8',
        'recipientPrivateKey': '6e8c3da5f2fb0306a88d6bcd427cbfba0b9c7f4c930c43122a973d620ffa3036',
        'invoiceNumber': 'm2/QAsmwaA4=',
        'privateKey': 'f1d6fb05da1225feeddd1cf4100128afe09c3c1aadbffbd5c8bd10d329ef8f40'
    }, {
        'senderPublicKey': '03f20a7e71c4b276753969e8b7e8b67e2dbafc3958d66ecba98dedc60a6615336d',
        'recipientPrivateKey': 'e9d174eff5708a0a41b32624f9b9cc97ef08f8931ed188ee58d5390cad2bf68e',
        'invoiceNumber': 'jgpUIjWFlVQ=',
        'privateKey': 'c5677c533f17c30f79a40744b18085632b262c0c13d87f3848c385f1389f79a6'
    }]
    for case in private_key_derivation_cases:
        sender_public_key = PublicKey(case['senderPublicKey'])
        recipient_private_key = PrivateKey.from_hex(case['recipientPrivateKey'])
        invoice_number = case['invoiceNumber']
        correct_private_key = case['privateKey']
        assert recipient_private_key.derive_child(sender_public_key, invoice_number).hex() == correct_private_key

    public_key_derivation_cases = [{
        'senderPrivateKey': '583755110a8c059de5cd81b8a04e1be884c46083ade3f779c1e022f6f89da94c',
        'recipientPublicKey': '02c0c1e1a1f7d247827d1bcf399f0ef2deef7695c322fd91a01a91378f101b6ffc',
        'invoiceNumber': 'IBioA4D/OaE=',
        'publicKey': '03c1bf5baadee39721ae8c9882b3cf324f0bf3b9eb3fc1b8af8089ca7a7c2e669f'
    }, {
        'senderPrivateKey': '2c378b43d887d72200639890c11d79e8f22728d032a5733ba3d7be623d1bb118',
        'recipientPublicKey': '039a9da906ecb8ced5c87971e9c2e7c921e66ad450fd4fc0a7d569fdb5bede8e0f',
        'invoiceNumber': 'PWYuo9PDKvI=',
        'publicKey': '0398cdf4b56a3b2e106224ff3be5253afd5b72de735d647831be51c713c9077848'
    }, {
        'senderPrivateKey': 'd5a5f70b373ce164998dff7ecd93260d7e80356d3d10abf928fb267f0a6c7be6',
        'recipientPublicKey': '02745623f4e5de046b6ab59ce837efa1a959a8f28286ce9154a4781ec033b85029',
        'invoiceNumber': 'X9pnS+bByrM=',
        'publicKey': '0273eec9380c1a11c5a905e86c2d036e70cbefd8991d9a0cfca671f5e0bbea4a3c'
    }, {
        'senderPrivateKey': '46cd68165fd5d12d2d6519b02feb3f4d9c083109de1bfaa2b5c4836ba717523c',
        'recipientPublicKey': '031e18bb0bbd3162b886007c55214c3c952bb2ae6c33dd06f57d891a60976003b1',
        'invoiceNumber': '+ktmYRHv3uQ=',
        'publicKey': '034c5c6bf2e52e8de8b2eb75883090ed7d1db234270907f1b0d1c2de1ddee5005d'
    }, {
        'senderPrivateKey': '7c98b8abd7967485cfb7437f9c56dd1e48ceb21a4085b8cdeb2a647f62012db4',
        'recipientPublicKey': '03c8885f1e1ab4facd0f3272bb7a48b003d2e608e1619fb38b8be69336ab828f37',
        'invoiceNumber': 'PPfDTTcl1ao=',
        'publicKey': '03304b41cfa726096ffd9d8907fe0835f888869eda9653bca34eb7bcab870d3779'
    }]
    for case in public_key_derivation_cases:
        sender_private_key = PrivateKey.from_hex(case['senderPrivateKey'])
        recipient_public_key = PublicKey(case['recipientPublicKey'])
        invoice_number = case['invoiceNumber']
        correct_public_key = case['publicKey']
        assert recipient_public_key.derive_child(sender_private_key, invoice_number).hex() == correct_public_key
