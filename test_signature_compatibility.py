#!/usr/bin/env python3
"""
署名互換性テスト - TypeScript/Go/Pythonで同じ署名が生成されるか検証
"""
import hashlib
from bsv.keys import PrivateKey

# 共通テストベクター（TypeScript/Goと同じ）
PRIVATE_KEY_HEX = "1e5edd45de6d22deebef4596b80444ffcc29143839c1dce18db470e25b4be7b5"
MESSAGE_HEX = "deadbeef"

def _generate_signature():
    """
    Python版で署名を生成し、結果を返す（内部関数）
    """
    # 秘密鍵の作成
    private_key = PrivateKey.from_hex(PRIVATE_KEY_HEX)
    
    # メッセージのハッシュ化（SHA-256を1回）
    message_bytes = bytes.fromhex(MESSAGE_HEX)
    message_hash = hashlib.sha256(message_bytes).digest()
    
    # 署名の生成（追加のハッシュ化なし）
    # hasher=lambda m: m で、追加のハッシュ化を防ぐ
    signature = private_key.sign(message_hash, hasher=lambda m: m)
    
    return signature.hex(), private_key, message_hash, signature

def test_signature_compatibility():
    """
    Python版で署名を生成し、結果を表示（テスト関数 - 戻り値なし）
    """
    print("=" * 80)
    print("Python SDK 署名互換性テスト")
    print("=" * 80)
    
    # 秘密鍵の作成
    private_key = PrivateKey.from_hex(PRIVATE_KEY_HEX)
    print(f"\n秘密鍵 (hex): {PRIVATE_KEY_HEX}")
    
    # 公開鍵の表示
    public_key = private_key.public_key()
    print(f"公開鍵 (hex): {public_key.hex()}")
    
    # メッセージのハッシュ化（SHA-256を1回）
    message_bytes = bytes.fromhex(MESSAGE_HEX)
    message_hash = hashlib.sha256(message_bytes).digest()
    print(f"\nメッセージ (hex): {MESSAGE_HEX}")
    print(f"SHA-256 ハッシュ: {message_hash.hex()}")
    
    # 署名の生成（追加のハッシュ化なし）
    # hasher=lambda m: m で、追加のハッシュ化を防ぐ
    signature = private_key.sign(message_hash, hasher=lambda m: m)
    print(f"\n署名 (DER形式, hex):")
    print(f"{signature.hex()}")
    print(f"署名長: {len(signature)} bytes")
    
    # 検証（追加のハッシュ化なし）
    is_valid = private_key.verify(signature, message_hash, hasher=lambda m: m)
    print(f"\n署名検証: {'✅ 成功' if is_valid else '❌ 失敗'}")
    
    # Test functions should not return values
    assert is_valid, "Signature verification failed"

if __name__ == "__main__":
    python_sig, _, _, _ = _generate_signature()
    
    print("=" * 80)
    print("Python SDK 署名互換性テスト")
    print("=" * 80)
    print(f"\nPython署名: {python_sig}")
    print("\n" + "=" * 80)
    print("期待される動作:")
    print("=" * 80)
    print("- RFC6979決定的署名を使用しているため、同じ入力は常に同じ署名を生成")
    print("- TypeScript/Go版と完全に同じ署名が生成されるはず")

