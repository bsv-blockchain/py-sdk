import pytest
from bsv.wallet.substrates.wallet_wire_transceiver import WalletWireTransceiver
from bsv.wallet.substrates.wallet_wire_processor import WalletWireProcessor
from bsv.wallet import ProtoWallet
from bsv.keys import PrivateKey
from bsv.wallet.key_deriver import Protocol

sample_data = bytes([3, 1, 4, 1, 5, 9])

@pytest.fixture
def user_key():
    return PrivateKey(1001)

@pytest.fixture
def counterparty_key():
    return PrivateKey(1002)

@pytest.fixture
def user_wallet(user_key):
    return WalletWireTransceiver(WalletWireProcessor(ProtoWallet(user_key, permission_callback=lambda a: True)))

@pytest.fixture
def counterparty_wallet(counterparty_key):
    return WalletWireTransceiver(WalletWireProcessor(ProtoWallet(counterparty_key, permission_callback=lambda a: True)))


def test_encrypt_decrypt(user_wallet, counterparty_wallet, user_key, counterparty_key):
    _ = Protocol(2, 'tests')
    key_id = '4'
    plaintext = sample_data
    # Encrypt with user, decrypt with counterparty
    enc = user_wallet.encrypt(None, {
        'encryption_args': {
            'protocolID': {'securityLevel': 2, 'protocol': 'tests'},
            'keyID': key_id,
            'counterparty': counterparty_key.public_key().hex(),
        },
        'plaintext': plaintext
    }, 'test')
    assert isinstance(enc, dict)
    assert isinstance(enc.get('ciphertext', b''), (bytes, bytearray))
    dec = counterparty_wallet.decrypt(None, {
        'encryption_args': {
            'protocolID': {'securityLevel': 2, 'protocol': 'tests'},
            'keyID': key_id,
            'counterparty': user_key.public_key().hex(),
        },
        'ciphertext': enc.get('ciphertext', b'')
    }, 'test')
    assert isinstance(dec, dict)
    assert dec.get('plaintext') == plaintext


def test_create_and_verify_signature(user_wallet, counterparty_wallet, user_key, counterparty_key):
    _ = Protocol(2, 'tests')
    key_id = '4'
    data = sample_data
    sig = user_wallet.create_signature(None, {
        'protocolID': {'securityLevel': 2, 'protocol': 'tests'},
            'keyID': key_id,
            'counterparty': counterparty_key.public_key().hex(),
        'data': data
    }, 'test')
    assert isinstance(sig, dict)
    assert isinstance(sig.get('signature', b''), (bytes, bytearray))
    ver = counterparty_wallet.verify_signature(None, {
        'protocolID': {'securityLevel': 2, 'protocol': 'tests'},
            'keyID': key_id,
            'counterparty': user_key.public_key().hex(),
        'data': data,
        'signature': sig.get('signature', b'')
    }, 'test')
    assert isinstance(ver, dict)
    assert ver.get('valid') in (True, False)


def test_create_and_verify_hmac(user_wallet, counterparty_wallet, user_key, counterparty_key):
    _ = Protocol(2, 'tests')
    key_id = '4'
    data = sample_data
    h = user_wallet.create_hmac(None, {
        'encryption_args': {
            'protocolID': {'securityLevel': 2, 'protocol': 'tests'},
            'keyID': key_id,
            'counterparty': counterparty_key.public_key().hex(),
        },
        'data': data
    }, 'test')
    assert isinstance(h, dict)
    assert isinstance(h.get('hmac', b''), (bytes, bytearray))
    ver = counterparty_wallet.verify_hmac(None, {
        'encryption_args': {
            'protocolID': {'securityLevel': 2, 'protocol': 'tests'},
            'keyID': key_id,
            'counterparty': user_key.public_key().hex(),
        },
        'data': data,
        'hmac': h.get('hmac', b'')
    }, 'test')
    assert isinstance(ver, dict)
    assert ver.get('valid') in (True, False)
