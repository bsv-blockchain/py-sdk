import unittest


from bsv.keys import PrivateKey
from bsv.polynomial import KeyShares, PointInFiniteField


class TestPrivateKeySharing(unittest.TestCase):
    # 既知のバックアップシェアデータ
    sample_backup = [
        '45s4vLL2hFvqmxrarvbRT2vZoQYGZGocsmaEksZ64o5M.A7nZrGux15nEsQGNZ1mbfnMKugNnS6SYYEQwfhfbDZG8.3.2f804d43',
        '7aPzkiGZgvU4Jira5PN9Qf9o7FEg6uwy1zcxd17NBhh3.CCt7NH1sPFgceb6phTRkfviim2WvmUycJCQd2BxauxP9.3.2f804d43',
        '9GaS2Tw5sXqqbuigdjwGPwPsQuEFqzqUXo5MAQhdK3es.8MLh2wyE3huyq6hiBXjSkJRucgyKh4jVY6ESq5jNtXRE.3.2f804d43',
        'GBmoNRbsMVsLmEK5A6G28fktUNonZkn9mDrJJ58FXgsf.HDBRkzVUCtZ38ApEu36fvZtDoDSQTv3TWmbnxwwR7kto.3.2f804d43',
        '2gHebXBgPd7daZbsj6w9TPDta3vQzqvbkLtJG596rdN1.E7ZaHyyHNDCwR6qxZvKkPPWWXzFCiKQFentJtvSSH5Bi.3.2f804d43'
    ]

    def test_split_private_key_into_shares_correctly(self):
        """Test that a private key can be split into shares correctly."""
        private_key = PrivateKey()  # Generate random private key
        threshold = 2
        total_shares = 5

        # Split the private key
        shares = private_key.to_key_shares(threshold, total_shares)
        backup = shares.to_backup_format()

        # Check the number of shares
        self.assertEqual(len(backup), total_shares)

        # Check that each share is a PointInFiniteField
        for share in shares.points:
            self.assertIsInstance(share, PointInFiniteField)

        # Check the threshold
        self.assertEqual(shares.threshold, threshold)

    def test_recombine_shares_into_private_key_correctly(self):
        """Test that shares can be recombined to recover the original key."""
        for _ in range(3):
            key = PrivateKey()
            all_shares = key.to_key_shares(3, 5)
            backup = all_shares.to_backup_format()

            # Use only the first 3 shares (the threshold)
            some_shares = KeyShares.from_backup_format(backup[:3])
            rebuilt_key = PrivateKey.from_key_shares(some_shares)

            # Check if the recovered key matches the original
            self.assertEqual(rebuilt_key.wif(), key.wif())

    def test_invalid_threshold_or_total_shares_type(self):
        """Test that invalid threshold or totalShares types raise errors."""
        k = PrivateKey()

        # Test with invalid threshold type
        with self.assertRaises(ValueError) as cm:
            k.to_key_shares("invalid", 14)  # type: ignore
        self.assertIn("threshold and totalShares must be numbers", str(cm.exception))

        # Test with invalid totalShares type
        with self.assertRaises(ValueError) as cm:
            k.to_key_shares(4, None)  # type: ignore
        self.assertIn("threshold and totalShares must be numbers", str(cm.exception))

    def test_invalid_threshold_value(self):
        """Test that invalid threshold values raise errors."""
        k = PrivateKey()

        # Test with threshold less than 2
        with self.assertRaises(ValueError) as cm:
            k.to_key_shares(1, 2)
        self.assertIn("threshold must be at least 2", str(cm.exception))

    def test_invalid_total_shares_value(self):
        """Test that invalid totalShares values raise errors."""
        k = PrivateKey()

        # Test with negative totalShares
        with self.assertRaises(ValueError) as cm:
            k.to_key_shares(2, -4)
        self.assertIn("totalShares must be at least 2", str(cm.exception))

    def test_threshold_greater_than_total_shares(self):
        """Test that threshold greater than totalShares raises an error."""
        k = PrivateKey()

        # Test with threshold > totalShares
        with self.assertRaises(ValueError) as cm:
            k.to_key_shares(3, 2)
        self.assertIn("threshold should be less than or equal to totalShares", str(cm.exception))

    def test_duplicate_share_in_recovery_with_sample_data(self):
        """Test that using duplicate shares from sample data during recovery raises an error."""
        # 既知のバックアップデータから重複するシェアを含むリストを作成
        duplicate_shares = [
            self.sample_backup[0],
            self.sample_backup[1],
            self.sample_backup[1]  # 重複するシェア
        ]

        # KeySharesオブジェクトを作成
        recovery = KeyShares.from_backup_format(duplicate_shares)

        # 重複するシェアがあるため、キーの復元時にエラーが発生することを確認
        with self.assertRaises(ValueError) as cm:
            PrivateKey.from_key_shares(recovery)
        self.assertIn("Duplicate share detected, each must be unique", str(cm.exception))

    def test_parse_and_verify_sample_shares(self):
        """Test parsing and verification of sample backup shares."""
        # サンプルバックアップデータからKeySharesオブジェクトを作成
        shares = KeyShares.from_backup_format(self.sample_backup[:3])

        # 基本的な検証
        self.assertEqual(shares.threshold, 3)
        self.assertEqual(shares.integrity, "2f804d43")
        self.assertEqual(len(shares.points), 3)

        # 各ポイントがPointInFiniteFieldインスタンスであることを確認
        for point in shares.points:
            self.assertIsInstance(point, PointInFiniteField)

        # バックアップ形式に戻せることを確認
        backup_format = shares.to_backup_format()
        self.assertEqual(len(backup_format), 3)

        # 元のバックアップと同じフォーマットであることを確認
        for i in range(3):
            parts_original = self.sample_backup[i].split('.')
            parts_new = backup_format[i].split('.')

            # 最後の2つの部分（しきい値と整合性ハッシュ）が同じか確認
            self.assertEqual(parts_original[-2:], parts_new[-2:])

    def test_recombination_with_sample_shares(self):
        """Test recombination of private key using different combinations of sample shares."""
        # サンプルシェアの様々な組み合わせでキーを復元
        combinations = [
            [0, 1, 2],  # 最初の3つのシェア
            [0, 2, 4],  # 異なる3つのシェア
            [1, 3, 4]  # 別の組み合わせ
        ]

        # 各組み合わせでキーを復元
        for combo in combinations:
            selected_shares = [self.sample_backup[i] for i in combo]
            key_shares = KeyShares.from_backup_format(selected_shares)

            # キーを復元（例外が投げられなければテストは成功）
            recovered_key = PrivateKey.from_key_shares(key_shares)

            # 復元されたキーがPrivateKeyインスタンスであることを確認
            self.assertIsInstance(recovered_key, PrivateKey)

            # WIFを生成できることを確認
            wif = recovered_key.wif()
            self.assertIsInstance(wif, str)
            self.assertTrue(len(wif) > 0)

    def test_create_backup_and_recover(self):
        """Test creating backup shares and recovering the key from them."""
        key = PrivateKey()
        backup = key.to_backup_shares(3, 5)

        # Recover using only the first 3 shares
        recovered_key = PrivateKey.from_backup_shares(backup[:3])

        # Verify the recovered key matches the original
        self.assertEqual(recovered_key.wif(), key.wif())

    def test_insufficient_shares_for_recovery(self):
        """Test that attempting to recover with insufficient shares raises an error."""
        key = PrivateKey()
        all_shares = key.to_key_shares(3, 5)
        backup = all_shares.to_backup_format()

        # しきい値未満のシェアでKeySharesオブジェクトを作成
        insufficient_shares = KeyShares.from_backup_format(backup[:2])

        # シェアが不足しているため、キーの復元時にエラーが発生することを確認
        with self.assertRaises(ValueError) as cm:
            PrivateKey.from_key_shares(insufficient_shares)
        self.assertIn("At least 3 shares are required", str(cm.exception))

    def test_share_format_validation(self):
        """Test validation of share format."""
        # 不正なフォーマットのシェア
        invalid_shares = [
            '45s4vLL2hFvqmxrarvbRT2vZoQYGZGocsmaEksZ64o5M.A7nZrGux15nEsQGNZ1mbfnMKugNnS6SYYEQwfhfbDZG8.3',  # 完全ではない
            'invalid-format',  # 完全に無効
            '45s4vLL2hFvqmxrarvbRT2vZoQYGZGocsmaEksZ64o5M'  # ドットがない
        ]

        # 各無効なシェアに対して、エラーが発生することを確認
        for invalid_share in invalid_shares:
            with self.assertRaises(ValueError):
                KeyShares.from_backup_format([invalid_share])


if __name__ == '__main__':
    unittest.main()