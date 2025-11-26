from bsv.keys import PrivateKey, PublicKey


def test_ecdh_shared_secret_symmetry_and_length():
    a = PrivateKey(321)
    b = PrivateKey(654)
    a_pub = a.public_key()
    b_pub = b.public_key()

    # Two ways to derive should match
    secret_ab = a.derive_shared_secret(b_pub)
    secret_ba = PublicKey(a_pub.serialize()).derive_shared_secret(b)

    assert isinstance(secret_ab, bytes)
    assert isinstance(secret_ba, bytes)
    assert len(secret_ab) == len(secret_ba) and len(secret_ab) > 0
    assert secret_ab == secret_ba

    # Secrets should differ for different pairs
    c = PrivateKey(777)
    c_pub = c.public_key()
    secret_ac = a.derive_shared_secret(c_pub)
    assert secret_ac != secret_ab





