import pytest 

from bsv.constants import SIGHASH
from bsv.hash import hash256
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.type import P2PKH, OpReturn
from bsv.transaction import TransactionInput, TransactionOutput, Transaction
from bsv.transaction_preimage import _preimage, tx_preimages
from bsv.utils import encode_pushdata, Reader
from bsv.fee_models import SatoshisPerKilobyte

digest1 = bytes.fromhex(
    "01000000"
    "ae4b0ed7fb33ec9d5c567520f8cf5f688207f28d5c2f2225c5fe62f7f17c0a25"
    "3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044"
    "48dd1f8e77b4a6a75e9b0d0908b25f56b8c98ce37d1fb5ada534d49d0957bcd201000000"
    "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"
    "e803000000000000"
    "ffffffff"
    "048129b26f1d89828c88cdcd472f8f20927822ab7a3d6532cb921c4019f51301"
    "00000000"
    "41000000"
)
digest2 = bytes.fromhex(
    "01000000"
    "ee2851915c957b7187967dabb54f32c00964c689285d3b73e7b2b92e30723c88"
    "752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad"
    "48dd1f8e77b4a6a75e9b0d0908b25f56b8c98ce37d1fb5ada534d49d0957bcd202000000"
    "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ace"
    "803000000000000"
    "ffffffff"
    "d67a44dde8ee744b7d73b50a3b3a887cb3321d6e16025273f760046c35a265fd"
    "00000000"
    "41000000"
)
digest3 = bytes.fromhex(
    "01000000"
    "ee2851915c957b7187967dabb54f32c00964c689285d3b73e7b2b92e30723c88"
    "752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad"
    "e4c1a33b3a7ca18ef1d6030c6ec222902195f186cb864e09bc1db08b3ea5c1fc00000000"
    "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ace"
    "803000000000000"
    "ffffffff"
    "d67a44dde8ee744b7d73b50a3b3a887cb3321d6e16025273f760046c35a265fd"
    "00000000"
    "41000000"
)

BRC62Hex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"
MerkleRootFromBEEF = "bb6f640cc4ee56bf38eb5a1969ac0c16caa2d3d202b22bf3735d10eec0ca6e00"

tx_in = TransactionInput(unlocking_script=Script("ae"))

tx_out = TransactionOutput(locking_script=Script("ae"), satoshis=5)

tx = Transaction(
    tx_inputs=[tx_in],
    tx_outputs=[tx_out],
)
txhex = "000000000100000000000000000000000000000000000000000000000000000000000000000000000001ae0000000001050000000000000001ae00000000"
txbuf = bytes.fromhex(txhex)

tx2idhex = "8c9aa966d35bfeaf031409e0001b90ccdafd8d859799eb945a3c515b8260bcf2"
tx2hex = "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f000000008c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2ffffffffa3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f020000008b48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff02206b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88acf0ca0100000000001976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000"
tx2buf = bytes.fromhex(tx2hex)


def test_new_tx():
    tx = Transaction()

    assert Transaction.from_hex(txbuf).hex() == txhex

    # should set known defaults
    assert tx.version == 1
    assert len(tx.inputs) == 0
    assert len(tx.outputs) == 0
    assert tx.locktime == 0


def test_transaction_from_hex():
    assert Transaction.from_hex(txhex).hex() == txhex
    assert Transaction.from_hex(tx2hex).hex() == tx2hex


def test_transaction_parse_script_offsets():
    tx = Transaction.from_hex(tx2buf)
    assert tx.txid() == tx2idhex
    r = Transaction.parse_script_offsets(tx2buf)
    assert len(r["inputs"]) == 2
    assert len(r["outputs"]) == 2
    for vin in range(2):
        i = r["inputs"][vin]
        script = tx2buf[i["offset"] : i["offset"] + i["length"]]
        assert script == tx.inputs[vin].unlocking_script.serialize()
    for vout in range(2):
        o = r["outputs"][vout]
        script = tx2buf[o["offset"] : o["offset"] + o["length"]]
        assert script == tx.outputs[vout].locking_script.serialize()


def test_transaction_to_hex():
    assert Transaction.from_hex(txhex).hex() == txhex


def test_transaction_serialize():
    assert Transaction.from_hex(txbuf).serialize().hex() == txhex


def test_transaction_hash():
    tx = Transaction.from_hex(tx2buf)
    assert tx.hash()[::-1].hex() == tx2idhex


def test_transaction_id():
    tx = Transaction.from_hex(tx2buf)
    assert tx.txid() == tx2idhex


def test_transaction_add_input():
    tx_in = TransactionInput()
    tx = Transaction()
    assert len(tx.inputs) == 0
    tx.add_input(tx_in)
    assert len(tx.inputs) == 1


def test_transaction_add_output():
    tx_out = TransactionOutput(locking_script=Script("6a"), satoshis=0)
    tx = Transaction()
    assert len(tx.outputs) == 0
    tx.add_output(tx_out)
    assert len(tx.outputs) == 1


def test_transaction_signing_hydrate_scripts():
    private_key = PrivateKey(
        bytes.fromhex(
            "f97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a4b62"
        )
    )
    public_key = private_key.public_key()
    public_key_hash = public_key.address()

    source_tx = Transaction(
        [], [TransactionOutput(P2PKH().lock(public_key_hash), 4000)]
    )
    spend_tx = Transaction(
        [
            TransactionInput(
                source_transaction=source_tx,
                source_output_index=0,
                unlocking_script_template=P2PKH().unlock(private_key),
            )
        ],
        [
            TransactionOutput(
                P2PKH().lock(public_key_hash),
                1000,
            ),
            TransactionOutput(
                P2PKH().lock(public_key_hash),
                change=True,
            ),
        ],
    )

    assert not spend_tx.inputs[0].unlocking_script

    spend_tx.fee()
    spend_tx.sign()
    assert spend_tx.inputs[0].unlocking_script


def test_estimated_byte_length():
    _in = TransactionInput(
        source_txid="00" * 32,
        unlocking_script=None,
        unlocking_script_template=P2PKH().unlock(PrivateKey()),
    )
    _in.satoshis = 2000

    _out = TransactionOutput(P2PKH().lock(PrivateKey().address()), 1000)

    t = Transaction().add_input(_in).add_output(_out)

    _in.private_keys = [PrivateKey()]
    assert t.estimated_byte_length() == 192

    _in.unlocking_script = b""
    assert t.estimated_byte_length() == 85
    assert t.estimated_byte_length() == t.byte_length()


def test_beef_serialization():
    brc62_hex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"
    t = Transaction.from_beef(bytes.fromhex(brc62_hex))
    assert t.inputs[0].source_transaction.merkle_path.block_height == 814435
    beef = t.to_beef()
    assert beef.hex() == brc62_hex


def test_from_reader():
    assert TransactionInput.from_hex("") is None
    tx_in = TransactionInput.from_hex("0011" * 16 + "00112233" + "00" + "00112233")
    assert tx_in.source_txid == "1100" * 16
    assert tx_in.source_output_index == 0x33221100
    assert tx_in.unlocking_script == Script()
    assert tx_in.sequence == 0x33221100

    assert TransactionOutput.from_hex("") is None
    assert Transaction.from_hex("") is None

    t_hex = (
        "01000000"
        + "03"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "01000000"
        + "6b"
        + "483045"
        + "0221008b6f070f73242c7c8c654f493dd441d46dc7b2365c8e9e4c62732da0fb535c58"
        + "02204b96edfb934d08ad0cfaa9bf75887bd8541498fbe19189d45683dcbd0785d0df"
        + "41"
        + "2102e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789"
        + "ffffffff"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "03000000"
        + "6a"
        + "473044"
        + "0220501dae7c51c6e5cb0f12a635ccbc61e283cb2e838d624d7df7f1ba1b0ab2087b"
        + "02207f67f3883735464f6067357c901fc1b8ddf8bf8695b54b2790d6a0106acf2340"
        + "41"
        + "2102e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789"
        + "ffffffff"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "02000000"
        + "8b"
        + "483045"
        + "022100b04829882018f7488508cb8587612fb017584ffc2b4d22e4300b95178be642a3"
        + "02207937cb643eef061b53704144148bec25645fbbaf4eedd5586ad9b018d4f6c9d441"
        + "41"
        + "04"
        + "e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd78997693d32c540ac253de7a3dc73f7e4ba7b38d2dc1ecc8e07920b496fb107d6b2"
        + "ffffffff"
        + "02"
        + "0a1a000000000000"
        + "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"
        + "05ea1c0000000000"
        + "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"
        + "00000000"
    )

    r = Reader(bytes.fromhex(t_hex))
    t = Transaction.from_reader(r)
    assert (
        t.txid() == "e8c6b26f26d90e9cf035762a91479635a75eff2b3b2845663ed72a2397acdfd2"
    )


def test_from_hex():
    assert TransactionInput.from_hex("") is None
    tx_in = TransactionInput.from_hex("0011" * 16 + "00112233" + "00" + "00112233")
    assert tx_in.source_txid == "1100" * 16
    assert tx_in.source_output_index == 0x33221100
    assert tx_in.unlocking_script == Script()
    assert tx_in.sequence == 0x33221100

    assert TransactionOutput.from_hex("") is None
    assert Transaction.from_hex("") is None

    t = Transaction.from_hex(
        "01000000"
        + "03"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "01000000"
        + "6b"
        + "483045"
        + "0221008b6f070f73242c7c8c654f493dd441d46dc7b2365c8e9e4c62732da0fb535c58"
        + "02204b96edfb934d08ad0cfaa9bf75887bd8541498fbe19189d45683dcbd0785d0df"
        + "41"
        + "2102e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789"
        + "ffffffff"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "03000000"
        + "6a"
        + "473044"
        + "0220501dae7c51c6e5cb0f12a635ccbc61e283cb2e838d624d7df7f1ba1b0ab2087b"
        + "02207f67f3883735464f6067357c901fc1b8ddf8bf8695b54b2790d6a0106acf2340"
        + "41"
        + "2102e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789"
        + "ffffffff"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "02000000"
        + "8b"
        + "483045"
        + "022100b04829882018f7488508cb8587612fb017584ffc2b4d22e4300b95178be642a3"
        + "02207937cb643eef061b53704144148bec25645fbbaf4eedd5586ad9b018d4f6c9d441"
        + "41"
        + "04"
        + "e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd78997693d32c540ac253de7a3dc73f7e4ba7b38d2dc1ecc8e07920b496fb107d6b2"
        + "ffffffff"
        + "02"
        + "0a1a000000000000"
        + "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"
        + "05ea1c0000000000"
        + "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"
        + "00000000"
    )
    assert (
        t.txid() == "e8c6b26f26d90e9cf035762a91479635a75eff2b3b2845663ed72a2397acdfd2"
    )


def test_transaction_bytes_io():
    io = Reader(
        bytes.fromhex(
            "0011223344556677889912fd1234fe12345678ff1234567890abcdef00112233"
        )
    )

    assert io.read_bytes(4) == bytes.fromhex("00112233")
    assert io.read_int(1) == int.from_bytes(bytes.fromhex("44"), "little")
    assert io.read_int(2) == int.from_bytes(bytes.fromhex("5566"), "little")
    assert io.read_int(3, "big") == int.from_bytes(bytes.fromhex("778899"), "big")
    assert io.read_var_int_num() == int.from_bytes(bytes.fromhex("12"), "little")
    assert io.read_var_int_num() == int.from_bytes(bytes.fromhex("1234"), "little")
    assert io.read_var_int_num() == int.from_bytes(bytes.fromhex("12345678"), "little")
    assert io.read_var_int_num() == int.from_bytes(
        bytes.fromhex("1234567890abcdef"), "little"
    )

    assert io.read_bytes(0) == b""
    assert io.read_bytes() == bytes.fromhex("00112233")
    assert io.read_bytes() == b""
    assert io.read_bytes(1) == b""

    assert io.read_int(1) is None
    assert io.read_var_int_num() is None


BRC62Hex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"


def test_output():
    assert TransactionOutput(
        locking_script=OpReturn().lock(["123", "456"])
    ).locking_script == Script("006a" + "03313233" + "03343536")


def test_digest():
    address = "1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9"
    # https://whatsonchain.com/tx/4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb
    expected_digest = [digest1]
    t: Transaction = Transaction()
    t_in = TransactionInput(
        source_transaction=Transaction(
            [],
            [
                None,
                TransactionOutput(locking_script=P2PKH().lock(address), satoshis=1000),
            ],
        ),
        source_txid="d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48",
        source_output_index=1,
        unlocking_script_template=P2PKH().unlock(PrivateKey()),
    )
    t.add_input(t_in)
    t.add_output(
        TransactionOutput(
            locking_script=P2PKH().lock("1JDZRGf5fPjGTpqLNwjHFFZnagcZbwDsxw"),
            satoshis=800,
        )
    )
    assert tx_preimages(t.inputs, t.outputs, t.version, t.locktime) == expected_digest

    # https://whatsonchain.com/tx/c04bbd007ad3987f9b2ea8534175b5e436e43d64471bf32139b5851adf9f477e
    expected_digest = [digest2, digest3]
    t: Transaction = Transaction()
    t_in1 = TransactionInput(
        source_transaction=Transaction(
            [],
            [
                None,
                None,
                TransactionOutput(locking_script=P2PKH().lock(address), satoshis=1000),
            ],
        ),
        source_txid="d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48",
        source_output_index=2,
        unlocking_script_template=P2PKH().lock(address),
    )
    t_in2 = TransactionInput(
        source_transaction=Transaction(
            [], [TransactionOutput(locking_script=P2PKH().lock(address), satoshis=1000)]
        ),
        source_txid="fcc1a53e8bb01dbc094e86cb86f195219022c26e0c03d6f18ea17c3a3ba3c1e4",
        source_output_index=0,
        unlocking_script_template=P2PKH().unlock(PrivateKey()),
    )
    t.add_inputs([t_in1, t_in2])
    t.add_output(
        TransactionOutput(
            P2PKH().lock("18CgRLx9hFZqDZv75J5kED7ANnDriwvpi1"), satoshis=1700
        )
    )
    assert t.preimage(0) == expected_digest[0]
    assert t.preimage(1) == expected_digest[1]


def test_transaction():
    address = "1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9"
    t = Transaction()
    t_in = TransactionInput(
        source_transaction=Transaction(
            [],
            [
                None,
                TransactionOutput(locking_script=P2PKH().lock(address), satoshis=1000),
            ],
        ),
        source_txid="d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48",
        source_output_index=1,
        unlocking_script_template=P2PKH().unlock(PrivateKey()),
    )
    t.add_input(t_in)
    t.add_output(
        TransactionOutput(
            P2PKH().lock("1JDZRGf5fPjGTpqLNwjHFFZnagcZbwDsxw"), satoshis=800
        )
    )

    signature = bytes.fromhex(
        "3044"
        "02207e2c6eb8c4b20e251a71c580373a2836e209c50726e5f8b0f4f59f8af00eee1a"
        "022019ae1690e2eb4455add6ca5b86695d65d3261d914bc1d7abb40b188c7f46c9a5"
    )
    sighash = bytes.fromhex("41")
    public_key = bytes.fromhex(
        "02e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789"
    )
    t.inputs[0].unlocking_script = Script(
        encode_pushdata(signature + sighash) + encode_pushdata(public_key)
    )

    assert (
        t.txid() == "4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb"
    )
    assert t.get_fee() == 200
    assert t.byte_length() == 191

    t.inputs[0].sighash = SIGHASH.NONE_ANYONECANPAY_FORKID
    assert t.preimage(0) == _preimage(
        t.inputs[0], t.version, t.locktime, b"\x00" * 32, b"\x00" * 32, b"\x00" * 32
    )
    t.inputs[0].sighash = SIGHASH.SINGLE_ANYONECANPAY_FORKID
    assert t.preimage(0) == _preimage(
        t.inputs[0],
        t.version,
        t.locktime,
        b"\x00" * 32,
        b"\x00" * 32,
        hash256(t.outputs[0].serialize()),
    )

    t.inputs[0].private_keys = [
        PrivateKey("L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9")
    ]

    t.outputs[0].satoshis = 100
    t.add_output(TransactionOutput(P2PKH().lock(address), change=True))

    t.fee(SatoshisPerKilobyte(500))

    # 1-2 transaction 226 bytes --> fee 113 satoshi --> 787 left
    assert len(t.outputs) == 2
    assert t.outputs[1].locking_script == P2PKH().lock(address)
    assert t.outputs[1].satoshis == 787


def test_transaction_bytes_io():
    io = Reader(
        bytes.fromhex(
            "0011223344556677889912fd1234fe12345678ff1234567890abcdef00112233"
        )
    )

    assert io.read_bytes(4) == bytes.fromhex("00112233")
    assert io.read_int(1) == int.from_bytes(bytes.fromhex("44"), "little")
    assert io.read_int(2) == int.from_bytes(bytes.fromhex("5566"), "little")
    assert io.read_int(3, "big") == int.from_bytes(bytes.fromhex("778899"), "big")
    assert io.read_var_int_num() == int.from_bytes(bytes.fromhex("12"), "little")
    assert io.read_var_int_num() == int.from_bytes(bytes.fromhex("1234"), "little")
    assert io.read_var_int_num() == int.from_bytes(bytes.fromhex("12345678"), "little")
    assert io.read_var_int_num() == int.from_bytes(
        bytes.fromhex("1234567890abcdef"), "little"
    )

    assert io.read_bytes(0) == b""
    assert io.read_bytes() == bytes.fromhex("00112233")
    assert io.read_bytes() == b""
    assert io.read_bytes(1) == b""

    assert io.read_int(1) is None
    assert io.read_var_int_num() is None


def test_from_hex():
    assert TransactionInput.from_hex("") is None
    tx_in = TransactionInput.from_hex("0011" * 16 + "00112233" + "00" + "00112233")
    assert tx_in.source_txid == "1100" * 16
    assert tx_in.source_output_index == 0x33221100
    assert tx_in.unlocking_script == Script()
    assert tx_in.sequence == 0x33221100

    assert TransactionOutput.from_hex("") is None
    assert Transaction.from_hex("") is None

    t = Transaction.from_hex(
        "01000000"
        + "03"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "01000000"
        + "6b"
        + "483045"
        + "0221008b6f070f73242c7c8c654f493dd441d46dc7b2365c8e9e4c62732da0fb535c58"
        + "02204b96edfb934d08ad0cfaa9bf75887bd8541498fbe19189d45683dcbd0785d0df"
        + "41"
        + "2102e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789"
        + "ffffffff"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "03000000"
        + "6a"
        + "473044"
        + "0220501dae7c51c6e5cb0f12a635ccbc61e283cb2e838d624d7df7f1ba1b0ab2087b"
        + "02207f67f3883735464f6067357c901fc1b8ddf8bf8695b54b2790d6a0106acf2340"
        + "41"
        + "2102e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789"
        + "ffffffff"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "02000000"
        + "8b"
        + "483045"
        + "022100b04829882018f7488508cb8587612fb017584ffc2b4d22e4300b95178be642a3"
        + "02207937cb643eef061b53704144148bec25645fbbaf4eedd5586ad9b018d4f6c9d441"
        + "41"
        + "04"
        + "e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd78997693d32c540ac253de7a3dc73f7e4ba7b38d2dc1ecc8e07920b496fb107d6b2"
        + "ffffffff"
        + "02"
        + "0a1a000000000000"
        + "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"
        + "05ea1c0000000000"
        + "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"
        + "00000000"
    )
    assert (
        t.txid() == "e8c6b26f26d90e9cf035762a91479635a75eff2b3b2845663ed72a2397acdfd2"
    )


def test_from_reader():
    assert TransactionInput.from_hex("") is None
    tx_in = TransactionInput.from_hex("0011" * 16 + "00112233" + "00" + "00112233")
    assert tx_in.source_txid == "1100" * 16
    assert tx_in.source_output_index == 0x33221100
    assert tx_in.unlocking_script == Script()
    assert tx_in.sequence == 0x33221100

    assert TransactionOutput.from_hex("") is None
    assert Transaction.from_hex("") is None

    t_hex = (
        "01000000"
        + "03"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "01000000"
        + "6b"
        + "483045"
        + "0221008b6f070f73242c7c8c654f493dd441d46dc7b2365c8e9e4c62732da0fb535c58"
        + "02204b96edfb934d08ad0cfaa9bf75887bd8541498fbe19189d45683dcbd0785d0df"
        + "41"
        + "2102e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789"
        + "ffffffff"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "03000000"
        + "6a"
        + "473044"
        + "0220501dae7c51c6e5cb0f12a635ccbc61e283cb2e838d624d7df7f1ba1b0ab2087b"
        + "02207f67f3883735464f6067357c901fc1b8ddf8bf8695b54b2790d6a0106acf2340"
        + "41"
        + "2102e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789"
        + "ffffffff"
        + "7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08"
        + "02000000"
        + "8b"
        + "483045"
        + "022100b04829882018f7488508cb8587612fb017584ffc2b4d22e4300b95178be642a3"
        + "02207937cb643eef061b53704144148bec25645fbbaf4eedd5586ad9b018d4f6c9d441"
        + "41"
        + "04"
        + "e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd78997693d32c540ac253de7a3dc73f7e4ba7b38d2dc1ecc8e07920b496fb107d6b2"
        + "ffffffff"
        + "02"
        + "0a1a000000000000"
        + "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"
        + "05ea1c0000000000"
        + "1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"
        + "00000000"
    )

    r = Reader(bytes.fromhex(t_hex))
    t = Transaction.from_reader(r)
    assert (
        t.txid() == "e8c6b26f26d90e9cf035762a91479635a75eff2b3b2845663ed72a2397acdfd2"
    )


def test_beef_serialization():
    t = Transaction.from_beef(bytes.fromhex(BRC62Hex))
    assert t.inputs[0].source_transaction.merkle_path.block_height == 814435
    beef = t.to_beef()
    assert beef.hex() == BRC62Hex


def test_ef_serialization():
    tx = Transaction.from_beef(bytes.fromhex(BRC62Hex))
    ef = tx.to_ef()
    expected_ef = "010000000000000000ef01ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff3e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac00000000"
    assert ef.hex() == expected_ef

    tx = Transaction.from_hex(
        "0100000001478a4ac0c8e4dae42db983bc720d95ed2099dec4c8c3f2d9eedfbeb74e18cdbb1b0100006b483045022100b05368f9855a28f21d3cb6f3e278752d3c5202f1de927862bbaaf5ef7d67adc50220728d4671cd4c34b1fa28d15d5cd2712b68166ea885522baa35c0b9e399fe9ed74121030d4ad284751daf629af387b1af30e02cf5794139c4e05836b43b1ca376624f7fffffffff01000000000000000070006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a406164386337373536356335363935353261626463636634646362353537376164633936633866613933623332663630373865353664666232326265623766353600000000"
    )

    prev_tx_outs = [None] * 501
    prev_tx_outs[283] = TransactionOutput(
        locking_script=Script("76a9140c77a935b45abdcf3e472606d3bc647c5cc0efee88ac"),
        satoshis=16,
    )
    prev_tx = Transaction([], prev_tx_outs)
    tx.inputs[0].source_transaction = prev_tx

    ef = tx.to_ef()
    expected_ef = "010000000000000000ef01478a4ac0c8e4dae42db983bc720d95ed2099dec4c8c3f2d9eedfbeb74e18cdbb1b0100006b483045022100b05368f9855a28f21d3cb6f3e278752d3c5202f1de927862bbaaf5ef7d67adc50220728d4671cd4c34b1fa28d15d5cd2712b68166ea885522baa35c0b9e399fe9ed74121030d4ad284751daf629af387b1af30e02cf5794139c4e05836b43b1ca376624f7fffffffff10000000000000001976a9140c77a935b45abdcf3e472606d3bc647c5cc0efee88ac01000000000000000070006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a406164386337373536356335363935353261626463636634646362353537376164633936633866613933623332663630373865353664666232326265623766353600000000"
    assert ef.hex() == expected_ef


def test_input_auto_txid():
    prev_tx = Transaction.from_hex('0100000001478a4ac0c8e4dae42db983bc720d95ed2099dec4c8c3f2d9eedfbeb74e18cdbb1b0100006b483045022100b05368f9855a28f21d3cb6f3e278752d3c5202f1de927862bbaaf5ef7d67adc50220728d4671cd4c34b1fa28d15d5cd2712b68166ea885522baa35c0b9e399fe9ed74121030d4ad284751daf629af387b1af30e02cf5794139c4e05836b43b1ca376624f7fffffffff01000000000000000070006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a406164386337373536356335363935353261626463636634646362353537376164633936633866613933623332663630373865353664666232326265623766353600000000')
    
    private_key = PrivateKey("L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9")

    tx_in = TransactionInput(
        source_transaction=prev_tx,
        source_output_index=0,
        unlocking_script_template=P2PKH().unlock(private_key),
    )
    
    assert tx_in.source_txid == 'e6adcaf6b86fb5d690a3bade36011cd02f80dd364f1ecf2bb04902aa1b6bf455'
    
    prev_tx.outputs[0].locking_script = None
    with pytest.raises(Exception):
        tx_in = TransactionInput(
            source_transaction=prev_tx,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(private_key),
        )


def test_transaction_fee_with_default_rate():
    from bsv.constants import TRANSACTION_FEE_RATE

    address = "1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9"
    t = Transaction()
    t_in = TransactionInput(
        source_transaction=Transaction(
            [],
            [
                None,
                TransactionOutput(locking_script=P2PKH().lock(address), satoshis=1000),
            ],
        ),
        source_txid="d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48",
        source_output_index=1,
        unlocking_script_template=P2PKH().unlock(PrivateKey()),
    )
    t.add_input(t_in)
    t.add_output(
        TransactionOutput(
            P2PKH().lock("1JDZRGf5fPjGTpqLNwjHFFZnagcZbwDsxw"), satoshis=100
        )
    )
    t.add_output(TransactionOutput(P2PKH().lock(address), change=True))

    t.fee()

    estimated_size = t.estimated_byte_length()
    expected_fee = int((estimated_size / 1000) * TRANSACTION_FEE_RATE)
    actual_fee = t.get_fee()

    assert abs(actual_fee - expected_fee) <= 1

# TODO: Test tx.verify()
