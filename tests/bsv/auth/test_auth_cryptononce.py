import pytest
import base64
from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import WalletImpl
from bsv.auth.utils import create_nonce, verify_nonce

class DummyWallet(WalletImpl):
    def __init__(self, priv=None, fail_hmac=False, hmac_valid=True):
        super().__init__(priv or PrivateKey())
        self.fail_hmac = fail_hmac
        self.hmac_valid = hmac_valid
        self._hmac_map = {}
    def create_hmac(self, args=None, originator=None):
        if self.fail_hmac:
            raise RuntimeError('Failed to create HMAC')
        data = args.get('data')
        if not isinstance(data, bytes):
            data = bytes(data)
        hmac = b'\x11' * 16
        print(f"[DummyWallet] create_hmac: data={data.hex()} hmac={hmac.hex()}")
        self._hmac_map[data] = hmac
        return {'hmac': hmac}
    def verify_hmac(self, args=None, originator=None):
        if not self.hmac_valid:
            return {'valid': False}
        data = args.get('data')
        if not isinstance(data, bytes):
            data = bytes(data)
        hmac = args.get('hmac')
        expected = self._hmac_map.get(data)
        print(f"[DummyWallet] verify_hmac: data={data.hex()} hmac={hmac.hex() if hmac else None} expected={expected.hex() if expected else None}")
        print(f"[DummyWallet] verify_hmac: expected type={type(expected)} hmac type={type(hmac)}")
        print(f"[DummyWallet] verify_hmac: comparison result={expected == hmac}")
        return {'valid': expected == hmac}

def test_create_nonce_error():
    wallet = DummyWallet(fail_hmac=True)
    with pytest.raises(RuntimeError, match='Failed to create HMAC'):
        create_nonce(wallet)

def test_create_nonce_length():
    wallet = DummyWallet()
    nonce = create_nonce(wallet)
    assert len(base64.b64decode(nonce)) == 32

def test_verify_nonce_invalid():
    wallet = DummyWallet(hmac_valid=False)
    nonce = create_nonce(DummyWallet())
    # 末尾改変
    assert not verify_nonce(nonce + 'ABC', wallet)
    assert not verify_nonce(nonce + '=', wallet)
    # Test with extra data appended to base64 nonce
    # Note: extra = base64.b64encode(b'extra').decode()
    n2 = base64.b64encode(base64.b64decode(nonce) + b'extra').decode()
    assert not verify_nonce(n2, wallet)

def test_verify_nonce_hmac_fail():
    wallet = DummyWallet(hmac_valid=False)
    nonce = create_nonce(wallet)
    assert not verify_nonce(nonce, wallet)

def test_verify_nonce_success():
    wallet = DummyWallet()
    nonce1 = create_nonce(wallet)
    nonce2 = create_nonce(wallet)
    assert len(base64.b64decode(nonce1)) == 32
    assert len(base64.b64decode(nonce2)) == 32
    assert verify_nonce(nonce1, wallet)
    assert verify_nonce(nonce2, wallet)

def test_real_wallet_success():
    priv = PrivateKey()
    wallet = WalletImpl(priv)
    nonce = create_nonce(wallet)
    assert verify_nonce(nonce, wallet)

def test_serial_number_use_case():
    # TypeScript版と完全一致：相互nonceを作成・検証し、シリアル番号をHMACで生成・検証
    client_priv = PrivateKey()
    server_priv = PrivateKey()
    client_wallet = WalletImpl(client_priv)
    server_wallet = WalletImpl(server_priv)
    
    # Get identity keys (TypeScript版と同じ方式)
    client_identity_result = client_wallet.get_public_key({'identityKey': True}, '')
    server_identity_result = server_wallet.get_public_key({'identityKey': True}, '')
    client_pub = client_identity_result['publicKey']
    server_pub = server_identity_result['publicKey']
    
    # Client creates a random nonce that the server can verify
    client_nonce = create_nonce(client_wallet, counterparty=server_pub)
    # The server verifies the client created the nonce provided
    assert verify_nonce(client_nonce, server_wallet, counterparty=client_pub)
    
    # Server creates a random nonce that the client can verify
    server_nonce = create_nonce(server_wallet, counterparty=client_pub)
    
    # The server compute a serial number from the client and server nonce
    data = (client_nonce + server_nonce).encode('utf-8')
    hmac_result = server_wallet.create_hmac({
        'encryption_args': {
            'protocol_id': {'securityLevel': 2, 'protocol': 'certificate creation'},
            'key_id': server_nonce + client_nonce,
            'counterparty': client_pub
        },
        'data': data
    }, '')
    serial_number = hmac_result['hmac']
    
    # Client verifies server's nonce
    assert verify_nonce(server_nonce, client_wallet, counterparty=server_pub)
    
    # Client verifies the server included their nonce
    verify_result = client_wallet.verify_hmac({
        'encryption_args': {
            'protocol_id': {'securityLevel': 2, 'protocol': 'certificate creation'},
            'key_id': server_nonce + client_nonce,
            'counterparty': server_pub
        },
        'data': data,
        'hmac': serial_number
    }, '')
    assert verify_result['valid']
