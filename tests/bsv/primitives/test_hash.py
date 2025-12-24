from bsv.hash import sha256, double_sha256, ripemd160_sha256, hmac_sha256, hmac_sha512

MESSAGE = 'hello'.encode('utf-8')
MESSAGE_SHA256 = bytes.fromhex('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
MESSAGE_HASH256 = bytes.fromhex('9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50')
MESSAGE_HASH160 = bytes.fromhex('b6a9c8c230722b7c748331a8b450f05566dc7d0f')


def test_sha256():
    assert sha256(MESSAGE) == MESSAGE_SHA256


def test_double_sha256():
    assert double_sha256(MESSAGE) == MESSAGE_HASH256


def test_ripemd160_sha256():
    assert ripemd160_sha256(MESSAGE) == MESSAGE_HASH160


KEY = 'key'.encode('utf-8')
MESSAGE_HMAC_SHA256 = bytes.fromhex('9307b3b915efb5171ff14d8cb55fbcc798c6c0ef1456d66ded1a6aa723a58b7b')
MESSAGE_HMAC_SHA512 = bytes.fromhex('ff06ab36757777815c008d32c8e14a705b4e7bf310351a06a23b612dc4c7433e\
                                     7757d20525a5593b71020ea2ee162d2311b247e9855862b270122419652c0c92')


def test_hmac_sha256():
    assert hmac_sha256(KEY, MESSAGE) == MESSAGE_HMAC_SHA256


def test_hmac_sha512():
    assert hmac_sha512(KEY, MESSAGE) == MESSAGE_HMAC_SHA512
