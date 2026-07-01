# py-sdk C拡張計画

## モチベーション

BSV の発展・普及が進むことにより、今後、ユーザー数の増加に伴うトランザクション処理量の増大、
さまざまなユーザーニーズに合わせた複雑なスクリプトの利用、Kusabiトークンなどの検証に用いられる
chain of tx の検証など、SDK 側に求められる処理能力は確実に高まっていく。

py-sdk は Python 言語を利用しており、その利便性や柔軟性には大きな強みがある一方、
処理速度では他の言語に比べて優位とは言えない。
ただし Python では C言語を組み込むことでネイティブ並みの処理性能を得ることができる。
実際、py-sdk には既に coincurve を通じて ECDSA の C ライブラリである libsecp256k1 が導入されている。
しかし、シリアライズ/デシリアライズ、スクリプトチャンクパース、Merkle Path 検証、
preimage 構築、スクリプト VM など、完全に Python で実装されている部分も多く、
将来のボトルネックになりかねない。
また、Python は AI 技術との相性が良く、その方面からの需要増加も見込まれる。

本計画では、py-sdk の性能律速箇所を C拡張化することで処理能力を引き上げる。
加えて、前述の coincurve はメンテナンスの遅れが目立ち、新しい Python バージョンへの対応が
リリースブロッカーとなるリスクがあるため、py-sdk から直接 libsecp256k1 を呼べるようにし、
外部依存を削減することも本計画のもう一つの目標である。

## 概要

bsv-sdk (py-sdk) のパフォーマンスクリティカルな箇所を CPython C拡張モジュール `_bsv_native` として実装する。
libsecp256k1 ソースを同梱ビルドし、coincurve 依存を段階的に廃止する。

既に coincurve (libsecp256k1) / pycryptodomex / hashlib により ECDSA・AES・ハッシュ関数はC実装だが、
それらを**繋ぐPython層**にオーバーヘッドが残っている。

---

## 設計原則

### 1. 前後互換性の維持

- 既存の公開 API (関数シグネチャ、戻り値型、例外型) を変更しない
- `from bsv.keys import PrivateKey, PublicKey` 等の既存コードがそのまま動く
- C拡張はあくまで内部実装の差し替えであり、利用者から見える振る舞いは同一
- 新しいバージョンの py-sdk で作成したデータが古いバージョンでも読めること（シリアライズ形式は不変）

### 2. 純Python実装の保存（フォールバック + 検証用）

- C拡張で置き換える全ての処理について、**既存の純Python実装を削除しない**
- 純Python実装は以下の目的で残す:
  - **フォールバック**: C拡張がビルドできない環境での動作保証
  - **検証**: C実装と純Python実装の出力一致テスト（等価性テスト）の基準
  - **可読性**: アルゴリズムの参照実装としてのドキュメント価値
- 暗号処理のフォールバック階層:
  ```
  _bsv_native (libsecp256k1 統合)    ← 推奨 (最速)
    → coincurve (CFFI)               ← フォールバック (移行期間 + Cビルド不可環境)
      → ImportError                  ← 暗号機能は利用不可、明確なエラーメッセージ
  ```
- 非暗号処理のフォールバック階層:
  ```
  _bsv_native (C実装)               ← 推奨 (最速)
    → 既存の純Python実装             ← フォールバック (常に利用可能)
  ```

### 3. マルチプラットフォーム対応

- できるだけ多くのプラットフォームで pre-built wheel を提供する
- ビルドできない環境でもフォールバックで動作する設計を維持する
- CPython Limited API (`Py_LIMITED_API`) の採用を検討し、Python バージョン間でバイナリ互換を確保する
- CI でのビルド・テストマトリクス:
  ```
  OS:      Linux (manylinux, musllinux), macOS, Windows
  Arch:    x86_64, aarch64 (ARM64)
  Python:  3.10, 3.11, 3.12, 3.13
  Mode:    C拡張あり / coincurve フォールバック / 純Python フォールバック
  ```

### 4. coincurve の段階的廃止

coincurve を即座に削除するのではなく、段階的に移行する:

- **Phase 0 完了時**: `_bsv_native` が推奨、coincurve はフォールバック
- **Phase 1-2 安定後**: coincurve を optional dependency に格下げ (`pip install bsv-sdk[coincurve]`)
- **十分な実績蓄積後**: coincurve フォールバックコードを削除（メジャーバージョンで）

廃止の動機:

- 新しい Python バージョンへの対応が遅れがち（リリースブロッカーになりうる）
- CFFI 経由のオーバーヘッド（CPython C API 直接呼びで排除可能）
- Phase 3 (Script VM) で OP_CHECKSIG が C → Python → CFFI → C の往復を避けられる
- libsecp256k1 の全機能に直接アクセスできる（tweak_add、Schnorr 等）

---

## 現状の依存関係

| 処理                           | 現在の実装                         | 備考       |
| ------------------------------ | ---------------------------------- | ---------- |
| ECDSA署名・検証                | C (coincurve/libsecp256k1)         | 最適化済み |
| SHA256 / RIPEMD160             | C (hashlib / pycryptodomex)        | 最適化済み |
| AES-CBC / AES-GCM              | C (pycryptodomex)                  | 最適化済み |
| Txシリアライズ/デシリアライズ  | **純Python**                       | 候補       |
| スクリプトチャンクパース       | **純Python**                       | 候補       |
| Merkle Path検証 (compute_root) | **純Python** (hex⇔bytes変換が重い) | 候補       |
| 署名ハッシュ(preimage)構築     | **純Python**                       | 候補       |
| スクリプトVM                   | **純Python**                       | 候補       |
| BRC-42鍵導出パイプライン       | Python + C混在                     | 候補       |

---

## 全体像

```
Phase 0 ─── 基盤構築 + libsecp256k1 統合 + coincurve 置換          ✅ 完了
  │
Phase 1 ─── Tx パース / シリアライズ / Script チャンク / MerklePath  ✅ 完了
  │           → BEEF SPV検証フロー全体がC化
  │
Phase 2 ─── Preimage 構築                                           ✅ 完了
  │           → 署名パイプライン全体がC化
  │
Phase 3 ─── スクリプト VM                                           ✅ 3b 完了 + バグ修正
  │           → VM ループ + 全 opcode が C VM で実行可能
  │           3a: コア opcodes + ビット/文字列/Chronicle + VM ループ ✅
  │           3b: 署名検証 (CHECKSIG/CHECKMULTISIG) コールバック方式  ✅
  │           3b+: CHECKMULTISIG ループ変数バグ修正 (Python/C 同時)   ✅
  │           3c: (任意) CHECKSIG パスの C 内完結化                    未着手
  │
Phase 4 ─── BRC-42 鍵導出最適化 + libsecp256k1 活用拡大        ✅ 4.1-4.3 完了
              → 認証・ウォレット操作の最適化
              4.1: pubkey_tweak_add で公開鍵導出簡素化           ✅
              4.2: seckey_tweak_add で秘密鍵導出を定数時間化     ✅
              4.3: _sign_custom_k を libsecp256k1 に置換         ✅
```

---

## Phase 0: 基盤構築 + libsecp256k1 統合 + coincurve 置換

**目的:** `_bsv_native` モジュールの基盤を構築し、coincurve を置き換える。

### 0A: モジュール基盤 + SHA256

| #   | タスク                                          | 成果物                                         |
| --- | ----------------------------------------------- | ---------------------------------------------- |
| 0.1 | `_bsv_native` スケルトン作成                    | `_bsv_native/bsv_native.c` (モジュール初期化)  |
| 0.2 | SHA256 / HMAC-SHA256 埋め込み                   | libsecp256k1 `src/hash_impl.h` ベース (~280行) |
| 0.3 | `hash256()` (double-SHA256) を Python に公開    | `_bsv_native.hash256(data) → bytes`            |
| 0.4 | `pyproject.toml` / `setup.py` にC拡張ビルド定義 | `pip install -e .` でビルド確認                |

#### SHA256 実装戦略

C拡張内部で SHA256 が必要な箇所:

| 用途                    | 関数                                                         | 呼び出し頻度             |
| ----------------------- | ------------------------------------------------------------ | ------------------------ |
| txid 計算               | `hash256(serialize(tx))`                                     | Tx毎                     |
| MerklePath compute_root | `hash256(left \|\| right)` × 木の高さ                        | SPV検証毎（20〜30回/Tx） |
| Preimage ハッシュ       | `hash256(prevouts)`, `hash256(sequence)`, `hash256(outputs)` | 署名毎                   |
| Script VM OP_SHA256     | `sha256(data)`                                               | スクリプト実行時         |

libsecp256k1 は SHA256 を内部に自前実装している (`src/hash_impl.h`, ~160行, Pieter Wuille 作, MIT License)
が、公開 API には出していない（`static` 関数のみ）。
libsecp256k1 を同梱ビルドするため、ソースツリー内の hash_impl.h をそのまま利用できる。

### 0B: libsecp256k1 ソース同梱 + ビルド統合

| #   | タスク                                                 | 成果物                                                                           |
| --- | ------------------------------------------------------ | -------------------------------------------------------------------------------- |
| 0.5 | libsecp256k1 ソースを `_bsv_native/secp256k1/` に配置  | git subtree または vendoring                                                     |
| 0.6 | `setup.py` で libsecp256k1 を静的ビルド + リンク       | `_bsv_native.so` に libsecp256k1 が含まれる                                      |
| 0.7 | secp256k1 モジュール有効化設定                         | `ENABLE_MODULE_RECOVERY=1`, `ENABLE_MODULE_ECDH=1`, `ENABLE_MODULE_SCHNORRSIG=1` |
| 0.8 | `secp256k1_context_create` / `_destroy` / `_randomize` | グローバルコンテキスト管理                                                       |

### 0C: coincurve 置換 — 暗号API実装

py-sdk が使用している libsecp256k1 関数を CPython C API でラップする。

| #    | libsecp256k1 関数                          | Python API                                      | 置換対象 (coincurve)                                |
| ---- | ------------------------------------------ | ----------------------------------------------- | --------------------------------------------------- |
| 0.9  | `secp256k1_ec_pubkey_create`               | `pubkey_from_secret(secret) → bytes`            | `CcPublicKey.from_valid_secret()`                   |
| 0.10 | `secp256k1_ec_pubkey_parse` / `_serialize` | `pubkey_parse(data) → bytes`                    | `CcPublicKey(data)` / `.format()`                   |
| 0.11 | `secp256k1_ecdsa_sign`                     | `ecdsa_sign(msg32, secret) → bytes`             | `CcPrivateKey.sign()`                               |
| 0.12 | `secp256k1_ecdsa_verify`                   | `ecdsa_verify(sig, msg32, pubkey) → bool`       | `CcPublicKey.verify()`                              |
| 0.13 | `secp256k1_ecdsa_sign_recoverable`         | `ecdsa_sign_recoverable(msg32, secret) → bytes` | `CcPrivateKey.sign_recoverable()`                   |
| 0.14 | `secp256k1_ecdsa_recover`                  | `ecdsa_recover(sig65, msg32) → bytes`           | `CcPublicKey.from_signature_and_message()`          |
| 0.15 | `secp256k1_ecdh`                           | `ecdh(secret, pubkey) → bytes`                  | `CcPrivateKey.ecdh()`                               |
| 0.16 | `secp256k1_ec_pubkey_combine`              | `pubkey_combine(pubkeys) → bytes`               | `CcPublicKey.combine()`                             |
| 0.17 | `secp256k1_ec_pubkey_tweak_mul`            | `pubkey_tweak_mul(pubkey, scalar) → bytes`      | `CcPublicKey.multiply()`                            |
| 0.18 | DER encode / decode                        | 内部関数                                        | `coincurve.ecdsa.cdata_to_der()` / `der_to_cdata()` |

### 0D: py-sdk 側の移行

| #    | タスク                                                                    | 対象ファイル                                     |
| ---- | ------------------------------------------------------------------------- | ------------------------------------------------ |
| 0.19 | `bsv/keys.py` を `_bsv_native` に切り替え（coincurve フォールバック付き） | `from coincurve import ...` → `_bsv_native` 優先 |
| 0.20 | `bsv/curve.py` を `_bsv_native` に切り替え                                | `curve_add()`, `curve_multiply()`                |
| 0.21 | `bsv/compat/bsm.py` を `_bsv_native` に切り替え                           | 署名復元                                         |
| 0.22 | `pyproject.toml` で coincurve を optional dependency に変更               | `[project.optional-dependencies]`                |

### 0E: CI + 配布

| #    | タスク               | 成果物                                               |
| ---- | -------------------- | ---------------------------------------------------- |
| 0.23 | CI パイプライン更新  | 3モード（native / coincurve / pure-python）テスト    |
| 0.24 | cibuildwheel 設定    | manylinux, musllinux, macOS, Windows の wheel ビルド |
| 0.25 | `--no-binary` テスト | フォールバック動作確認                               |

### ファイル構成

```
_bsv_native/
  bsv_native.c          ← モジュール初期化 + Python API 定義
  secp256k1_wrap.h / .c ← libsecp256k1 ラッパー (~400行)
  secp256k1/             ← libsecp256k1 ソース (vendored)
    include/
      secp256k1.h
      secp256k1_ecdh.h
      secp256k1_recovery.h
      secp256k1_schnorrsig.h
      secp256k1_extrakeys.h
    src/
      secp256k1.c        ← SHA256 (hash_impl.h) もここに含まれる
      ...
```

### フォールバック戦略

```python
# bsv/keys.py — 暗号処理: 3段階フォールバック
_CRYPTO_BACKEND = None

try:
    from _bsv_native import ecdsa_sign, ecdsa_verify, pubkey_from_secret, ...
    _CRYPTO_BACKEND = "native"
except ImportError:
    try:
        from coincurve import PrivateKey as CcPrivateKey, PublicKey as CcPublicKey
        _CRYPTO_BACKEND = "coincurve"
    except ImportError:
        raise ImportError(
            "bsv-sdk requires either _bsv_native (recommended) or coincurve. "
            "Install with: pip install bsv-sdk  (includes pre-built binaries)"
        )
```

```python
# bsv/transaction.py — 非暗号処理: 2段階フォールバック
try:
    from _bsv_native import tx_from_bytes, tx_to_bytes
    _USE_NATIVE = True
except ImportError:
    _USE_NATIVE = False  # 既存の純Python実装がそのまま動く

@classmethod
def from_reader(cls, reader):
    if _USE_NATIVE:
        return tx_from_bytes(reader.getvalue()[reader.tell():])
    # 既存Python実装（削除しない、フォールバック + 検証基準として保存）
    ...
```

### 完了条件

- [x] `pip install -e .` で `_bsv_native` がビルドされる（libsecp256k1 含む） ✅ 2026-06-30
- [x] coincurve なしで既存テストスイート全体が通る（5466件全パス） ✅ 2026-06-30
- [x] coincurve フォールバック時も既存テスト全件通過 ✅ 2026-06-30
- [ ] CI で manylinux / macOS / Windows の wheel ビルド成功（0E: CI + 配布は未着手）

### 実装メモ (2026-06-30)

- `bsv_native.c`: secp256k1.c をアマルガメーション方式でインクルード（precomputed_ecmult.c, precomputed_ecmult_gen.c を先行インクルード）
- `ecdsa_sign`: 常に low-S 正規化を適用
- `ecdsa_verify`: 正規化なし — libsecp256k1 が high-S を拒否。BSV tx version 依存の malleability 制御は Script VM ポリシー層（`Spend.is_relaxed()`）で行う
- ファイル構成: `bsv_native.c` 1ファイル（~700行）にラッパーを集約、`secp256k1_wrap.h/.c` は不要に
- `pubkey_tweak_add`, `seckey_tweak_add`, `context_randomize` は Phase 4 向けだが Phase 0 で先行実装済み

### 想定期間: 3〜4週間 → 完了（0A〜0D）、0E は Phase 1 と並行で実施

---

## Phase 1: Tx パース / シリアライズ / Script チャンク / MerklePath

**目的:** 最も呼び出し頻度が高い処理をC化し、BEEF SPV検証フロー全体を高速化する。

### 対象ファイル

- `bsv/transaction.py` — `from_reader()` (L586-620), `serialize()` (L56-65), `from_beef()` (L456-501)
- `bsv/transaction_input.py` — `from_hex()` (L61-97), `serialize()`
- `bsv/transaction_output.py` — `from_hex()` (L35-61), `serialize()`
- `bsv/utils/reader.py` — `Reader` クラス全体 (118行)
- `bsv/utils/writer.py` — `Writer` クラス全体 (93行)
- `bsv/utils/script_chunks.py` — `_parse_script_bytes()`, `serialize_chunks()` (173行)
- `bsv/script/script.py` — `_build_chunks()` (L113-131), `_read_push_data()` (L98-111)
- `bsv/merkle_path.py` — `compute_root()` (L201-242), `find_or_compute_leaf()` (L244-271)
- `bsv/merkle_tree_parent.py` — `merkle_tree_parent_str()`, `merkle_tree_parent_bytes()`

### 問題

1入力1出力の最小Txでも `from_reader()` は以下の呼び出しを行う:

```
Reader.read_uint32_le()        # version
Reader.read_var_int_num()      # inputs count
  Reader.read_bytes(32)        # txid
  Reader.read_int(4)           # vout
  Reader.read_var_int_num()    # script length
  Reader.read_bytes(n)         # unlocking script
  Reader.read_int(4)           # sequence
Reader.read_var_int_num()      # outputs count
  Reader.read_int(8)           # satoshis
  Reader.read_var_int_num()    # script length
  Reader.read_bytes(n)         # locking script
Reader.read_uint32_le()        # locktime
```

- 最小でも **15回** のPythonメソッド呼び出し（各メソッドが `BytesIO.read()` → `int.from_bytes()` と2段階）
- 入出力が増えるとリニアに増加（100入力 → 500回超）
- Script の `_build_chunks()` で opcode ごとに Python 関数呼び出しがさらに追加

#### MerklePath `compute_root()` のオーバーヘッド

SPV検証の核心である `compute_root()` は、木の高さ分（典型20〜30回）ハッシュを繰り返すが、
**毎回hex⇔bytes変換が4回走る**:

```python
def hash_fn(m: str) -> str:
    return to_hex(hash256(to_bytes(m, "hex")[::-1])[::-1])  # 4回の変換/回
```

hash256自体はC (hashlib) だが、前後のhex⇔bytes変換がPythonで支配的。

### 呼び出し元（20箇所超）

```
bsv/transaction/beef_builder.py    bsv/transaction/beef.py
bsv/transaction/beef_tx.py         bsv/keystore/local_kv_store.py  × 5
bsv/wallet/wallet_impl.py  × 4    bsv/registry/client.py  × 2
bsv/overlay_tools/...              アプリ層 (Kusabi Token等)
```

### タスク

| #    | タスク                                                                   | C関数                           |
| ---- | ------------------------------------------------------------------------ | ------------------------------- |
| 1.1  | Reader/Writer 相当のCポインタ走査                                        | 内部ユーティリティ              |
| 1.2  | Tx デシリアライズ                                                        | `bsv_tx_from_bytes()`           |
| 1.3  | Tx シリアライズ                                                          | `bsv_tx_to_bytes()`             |
| 1.4  | txid 計算 (serialize + hash256 融合)                                     | `bsv_tx_txid()`                 |
| 1.5  | TransactionInput/Output パース                                           | 1.2 の内部                      |
| 1.6  | Script チャンクパース                                                    | `bsv_parse_script_chunks()`     |
| 1.7  | Script チャンクシリアライズ                                              | `bsv_serialize_script_chunks()` |
| 1.8  | MerklePath compute_root                                                  | `bsv_merkle_compute_root()`     |
| 1.9  | Python側ディスパッチ差し替え（`_USE_NATIVE` 分岐、既存Python実装は保存） | —                               |
| 1.10 | テスト: 等価性 + 境界値 + メモリ安全 + ファズ                            | —                               |
| 1.11 | ベンチマーク                                                             | —                               |

### 提案するC API

```c
PyObject* bsv_tx_from_bytes(const uint8_t* data, size_t len);
PyObject* bsv_tx_to_bytes(PyObject* tx);
PyObject* bsv_tx_txid(PyObject* tx);
PyObject* bsv_parse_script_chunks(const uint8_t* script, size_t len);
PyObject* bsv_serialize_script_chunks(PyObject* chunks);
PyObject* bsv_merkle_compute_root(
    const uint8_t* txid, const uint8_t* path_hashes,
    const uint8_t* flags, int height
);
```

### 期待される効果

| ケース                                     | 改善前 | 改善後 | 高速化 |
| ------------------------------------------ | ------ | ------ | ------ |
| 1-in/1-out Tx デシリアライズ               | ~15μs  | ~0.5μs | 30x    |
| 100-in/2-out Tx デシリアライズ             | ~800μs | ~5μs   | 160x   |
| BEEF解析 (複数Tx)                          | ms単位 | μs単位 | 100x+  |
| serialize + txid                           | ~20μs  | ~1μs   | 20x    |
| Script チャンクパース (P2PKH)              | ~5μs   | ~0.2μs | 25x    |
| Script チャンクパース (FT inscription付き) | ~30μs  | ~1μs   | 30x    |
| MerklePath compute_root (高さ20)           | ~200μs | ~5μs   | 40x    |
| BEEF SPV検証 (5Tx)                         | ~1ms   | ~25μs  | 40x    |

### 完了条件

- [x] 既存テストスイート全体が native モードで通る (5466 passed, 0 failed) ✅ 2026-06-30
- [ ] 等価性テスト: 全C関数が対応するPython実装と同一出力
- [ ] ファズテスト: 10万件のランダム入力でクラッシュなし
- [ ] メモリリークテスト: 10万回反復で 1MB 以内
- [ ] CI で 3モード + manylinux/macOS/Windows テスト (0E と合わせて実施)

### 実装メモ (2026-06-30)

- **C 関数 7 個を追加** (`bsv_native.c` +818 行):
  - `parse_script_chunks`, `serialize_script_chunks` — Script チャンクのパース/シリアライズ
  - `tx_from_bytes`, `tx_to_bytes`, `tx_txid` — Tx パース/シリアライズ/txid 計算
  - `merkle_compute_root` — 単純な Merkle パス計算（直接検索のみ）
  - `merkle_hash_pair` — 2 つの hex ハッシュを hash256 で結合（ハイブリッド方式用）
- **Python ディスパッチ**: `script_chunks.py`, `merkle_path.py`, `transaction.py` に `_USE_NATIVE` 分岐追加
- **merkle_path のハイブリッド設計**: `find_or_compute_leaf` の再帰ロジックは Python 側に残し、ハッシュ計算のみ C に委譲。詳細は「Phase 1 実装課題」セクション参照
- **バリデーション**: `serialize_script_chunks` に direct push 長チェック、PUSHDATA1/2/4 上限チェック、非 push opcode + data チェックを追加
- **フォールバック**: `tx_from_bytes` が ValueError を返した場合、Python パーサーへフォールバック（`transaction.py` の `from_reader()` 内で try/except）

### 想定期間: 3〜4週間 → 完了（コア実装）、等価性/ファズ/メモリテストは 0E と合わせて実施

---

## Phase 2: Preimage 構築

**目的:** 署名ハッシュ構築をC化し、署名パイプライン全体を高速化する。

### BSV の Preimage 形式

BSV には **3 つの preimage 形式**があり、SIGHASH フラグによってルーティングされる:

| # | 形式 | ルーティング条件 | 特徴 |
|---|---|---|---|
| **1** | **BIP-143** (ForkID) | `FORKID` あり、`CHRONICLE` なし | ハッシュコミットメント方式。hashPrevouts / hashSequence / hashOutputs を事前計算し、入力ごとに 10 フィールドを連結。現在の BSV 標準 |
| **2** | **OTDA** (Original Transaction Digest Algorithm) | `FORKID` なし、または `FORKID + CHRONICLE` | 元祖 Bitcoin の方式。tx 全体をコピーして SIGHASH に応じて改変 → シリアライズ。Chronicle アップグレードで復活 |
| **3** | **Legacy OTDA** (SIGHASH_SINGLE バグ) | OTDA の特殊ケース | `SIGHASH_SINGLE` で input_index >= outputs 数のとき、`0x01 + 0x00*31` を返す。Bitcoin 初期からのバグ互換 |

ルーティングロジック (`constants.py` `SIGHASH.use_otda()`):

```
FORKID のみ        → BIP-143    (現在の標準。ほぼ全ての通常トランザクション)
FORKID + CHRONICLE → OTDA       (Chronicle アップグレード後の新形式)
FORKID なし        → OTDA       (レガシー互換)
```

### エントリーポイント

preimage 構築には 2 つの呼び出し経路がある:

| エントリーポイント | 呼び出し元 | 形式 | 特徴 |
|---|---|---|---|
| `tx_preimages()` | `Transaction.sign()` 経由 | BIP-143 のみ | 全入力を一括計算。hashPrevouts 等を**1 回だけ計算して共有** |
| `tx_preimage()` | `Transaction.preimage(i)` | BIP-143 / OTDA | 1 入力ずつ計算。SIGHASH で形式をルーティング |
| `calc_input_signature_hash()` | Script VM `OP_CHECKSIG` | BIP-143 / OTDA (Legacy) | preimage → hash256 まで実行。OTDA パスは tx コピー方式 |

### 対象ファイル

- `bsv/transaction_preimage.py`:
  - `_preimage()` (L10-54) — BIP-143 preimage の 10 フィールド連結
  - `tx_preimages()` (L57-96) — 全入力の BIP-143 preimage 一括計算
  - `_preimage_otda()` (L138-177) — OTDA preimage 構築（Chronicle 用）
  - `tx_preimage()` (L195-237) — ルーティング (BIP-143 / OTDA 振り分け)
- `bsv/transaction.py`:
  - `calc_input_signature_hash()` (L115-134) — Script VM 向け preimage → hash256
  - `_calc_input_preimage_bip143()` (L136-157) — BIP-143 パス（内部用）
  - `_calc_input_preimage_legacy()` (L239-251) — OTDA Legacy パス（tx コピー方式）
  - `_build_bip143_preimage()` (L197-237) — BIP-143 preimage 10 フィールド構築
  - `_apply_sighash_modifications()` (L282-290) — OTDA 用の tx 改変ロジック

### 問題

BIP143 preimage構築は、入力ごとに `bytes.fromhex()` → `[::-1]` → `.to_bytes()` → `b"".join()` の
Python中間オブジェクト生成を繰り返す。OTDA (Chronicle) パスも同様の BytesIO + `.write()` 連打。

### C化の段階的アプローチ

3 形式の C 化難易度と効果が大きく異なるため、段階的に実装する:

```
Phase 2a: BIP-143 preimage (優先)
  ├── tx_preimages() 一括計算 — 最も呼び出し頻度が高い (Transaction.sign())
  ├── tx_preimage() 単体計算 — BIP-143 パスのみ
  └── _build_bip143_preimage() — calc_input_signature_hash() の BIP-143 パス
      → 純粋なバイト連結 + hash256。Python オブジェクト依存が少なく C 化しやすい
      → Phase 1 で tx パースの C 化済みのため、入力値は C 側でも取得可能

Phase 2b: OTDA preimage (Chronicle) — Phase 2a 完了後
  ├── _preimage_otda() — tx 全体のシリアライズ変形版
  └── varint + バイト書き込みの繰り返し (Phase 1 の write_varint と同パターン)
      → BIP-143 より複雑だが、構造的には Phase 1 の tx シリアライズと類似

Phase 2c: OTDA Legacy — Phase 3 (Script VM) と統合
  ├── _calc_input_preimage_legacy() — tx ディープコピー → SIGHASH 改変 → serialize
  └── Python オブジェクト操作が多く、C 化の恩恵が小さい
      → Phase 3 で Script VM を C 化する際に tx コピー操作を C 内で完結させる方が自然
      → OP_CHECKSIG 内で preimage → verify を C 内一気通貫にできる
```

**Phase 2c を Phase 3 に後回しにする理由:**

- OTDA Legacy パスは Transaction オブジェクトのディープコピー (`_create_transaction_copy_for_signing`)
  → unlocking script 差し替え → SIGHASH に応じた inputs/outputs の改変 (`_apply_sighash_modifications`)
  → serialize という流れで、**Python オブジェクト操作が支配的**
- Script VM (Phase 3) で OP_CHECKSIG を C 化する際、tx のメモリ表現が C 側にある前提で
  コピー + 改変を C 内で完結させる方が、Python ↔ C の往復を避けられる
- BIP-143 が現在の BSV 標準であり、OTDA Legacy の呼び出し頻度は相対的に低い

### タスク

| #   | タスク                                                                            | C関数                    | 段階 |
| --- | --------------------------------------------------------------------------------- | ------------------------ | ---- |
| 2.1 | BIP143 preimage 一括構築                                                          | `bsv_tx_preimages()`     | 2a   |
| 2.2 | BIP143 preimage 単体計算 (calc_input_signature_hash 用)                           | `bsv_tx_preimage()`      | 2a   |
| 2.3 | OTDA preimage (Chronicle)                                                         | `bsv_tx_preimage_otda()` | 2b   |
| 2.4 | Phase 1 との結合 (deserialize → preimage → hash256 一体化)                        | —                        | 2a   |
| 2.5 | Python側ディスパッチ差し替え（既存Python実装は保存）                              | —                        | 2a-b |
| 2.6 | テスト: SIGHASH全パターン (ALL, NONE, SINGLE × ANYONECANPAY × FORKID × CHRONICLE) | —                        | 2a-b |
| 2.7 | OTDA Legacy (tx コピー方式)                                                       | Phase 3 で実装           | 3b   |

### SIGHASH フラグの組み合わせ (テストマトリクス)

```
ベースタイプ (下位 5 bit):
  ALL (0x01), NONE (0x02), SINGLE (0x03)

修飾フラグ:
  FORKID (0x40), CHRONICLE (0x20), ANYONECANPAY (0x80)

有効な組み合わせ:
  BIP-143:  ALL|FORKID, NONE|FORKID, SINGLE|FORKID
            + 各 ANYONECANPAY 組み合わせ              → 6 パターン
  OTDA:    ALL|FORKID|CHRONICLE, NONE|FORKID|CHRONICLE, SINGLE|FORKID|CHRONICLE
            + 各 ANYONECANPAY 組み合わせ              → 6 パターン
  Legacy:  ALL, NONE, SINGLE (FORKID なし)
            + 各 ANYONECANPAY 組み合わせ              → 6 パターン
                                              合計: 18 パターン
```

### 期待される効果

| ケース                 | 改善前 | 改善後 | 高速化 |
| ---------------------- | ------ | ------ | ------ |
| 1入力 preimage         | ~30μs  | ~2μs   | 15x    |
| 100入力 preimages 一括 | ~3ms   | ~50μs  | 60x    |

### 相乗効果

Phase 0 で libsecp256k1 を統合済みなので、パイプライン全体が C内で完結する:

```
from_beef(bytes)              ── Phase 1
  → MerklePath.compute_root() ── Phase 1
  → tx_preimages()            ── Phase 2a (BIP-143)
  → hash256(preimage)         ── Phase 0
  → secp256k1_ecdsa_sign()    ── Phase 0 (libsecp256k1 直接)
```

Phase 3 完了後は OP_CHECKSIG パスも C 内で完結:

```
Script VM (OP_CHECKSIG)       ── Phase 3
  → calc_input_signature_hash ── Phase 2a (BIP-143) / Phase 3 (OTDA Legacy)
  → secp256k1_ecdsa_verify    ── Phase 0 (libsecp256k1 直接)
```

### 完了条件

- [x] BIP-143 preimage: C 実装が全 SIGHASH パターンで Python 実装と同一出力 ✅ 2026-06-30
- [x] OTDA preimage: C 実装が SIGHASH_ALL/NONE/SINGLE × ANYONECANPAY で正常動作 ✅ 2026-06-30
- [x] 既存テストスイート全体が native モードで通る (5466 passed, 0 failed) ✅ 2026-06-30
- [ ] 等価性テスト: 18 パターンの SIGHASH 組み合わせで C ⇔ Python 出力一致
- [x] OTDA Legacy: Phase 3b のコールバック方式により Python 側 verify_signature が OTDA ルーティングを透過的に処理 ✅ 2026-07-01

### 実装メモ (2026-06-30)

- **C 関数 2 個を追加** (`bsv_native.c`):
  - `tx_preimages(version, locktime, inputs, outputs)` — BIP-143 preimage を全入力分一括計算。SIGHASH ロジック (ANYONECANPAY, SINGLE, NONE) を C 内で処理
  - `tx_preimage_otda(input_index, version, locktime, inputs, outputs)` — OTDA preimage 構築
- **内部ヘルパー追加**: `hash256_var` (可変長 hash256), `parse_input_tuple`, `write_u32_le`, `write_u64_le`
- **Python ディスパッチ**: `transaction_preimage.py` に `_USE_NATIVE` 分岐、`transaction.py` に `_calc_input_preimage_bip143_native`
- **入力データ形式**: `(txid_hex, vout, locking_script_bytes, satoshis, sequence, sighash)` タプルのリスト。Python 側で TransactionInput から抽出して渡す
- **locking_script が None のケース**: `calc_input_signature_hash` 経由では署名対象以外の入力の locking_script が None になりうる。Python 側で `b""` にフォールバック
- **Phase 1 課題の教訓適用**: hex⇔bytes 変換は Phase 1 で整備済みの `hex_to_bytes_reversed` を再利用。SIGHASH ロジックの中間値は既存テストベクトルで検証済み

### 想定期間: 2〜3週間 → 完了 (2a+2b)、2c は Phase 3b に統合

---

## Phase 3: スクリプト VM

**目的:** スクリプト検証をC化。libsecp256k1 統合済みなので OP_CHECKSIG が C内で完結する。

### 対象ファイル

- `bsv/script/spend.py` — 1004行、`Spend` クラス全体

### tx version による動作の違い

BSV では tx version が Script VM の動作に影響する。Chronicle アップグレード (MainNet block 943,816) 以降、
**opcode の有効/無効は tx version に依存しない** (全 opcode がネットワーク全体で有効) が、
**malleability 制限は tx version > 1 で緩和される** (`is_relaxed()`)。

#### opcode の利用可否: tx version に依存しない

Chronicle 以降、以下の 10 個の opcode が **全ての tx version で復活**している:

| opcode | 機能 | 実装箇所 (spend.py) |
|---|---|---|
| OP_VER | tx version をスタックに push | L126-128 |
| OP_VERIF | スタック値 <= tx version なら true → if_stack push | L130-144 |
| OP_VERNOTIF | OP_VERIF の否定 | L130-144 |
| OP_2MUL | スタック top を 2倍 | L489-499 |
| OP_2DIV | スタック top を 2で整数除算 (ゼロ方向に切り捨て) | L489-499 |
| OP_SUBSTR | data[start:start+length] を取り出す (3引数) | L774-786 |
| OP_LEFT | data[:length] を取り出す | L788-795 |
| OP_RIGHT | data[len-length:] を取り出す | L797-804 |
| OP_LSHIFTNUM | 算術左シフト (符号付き整数) | L501-516 |
| OP_RSHIFTNUM | 算術右シフト (符号保存) | L501-516 |

`is_op_disabled()` は常に `False` を返す (L902-914)。

**C 化の注意**: これらは全て通常の opcode としてディスパッチすればよく、version 分岐は不要。

#### malleability 制限: tx version > 1 で緩和 (`is_relaxed()`)

`is_relaxed()` (L897-899) は `transaction_version > 1` のときに `True` を返し、
以下の 7 つの malleability 制限を緩和する:

| 制限 | version 1 (厳格) | version > 1 (緩和) | 実装箇所 |
|---|---|---|---|
| **Minimal push** | push data は最小エンコーディング必須 | 制限なし | L97 |
| **MINIMALIF** | OP_IF/NOTIF の条件は空 or `0x01` のみ | 任意のバイト列許可 | L227-236 |
| **NULLFAIL** | OP_CHECKSIG 失敗時は空署名必須 | 非空署名でも許可 | L640-644 |
| **NULLDUMMY** | OP_CHECKMULTISIG のダミー要素は空必須 | 非空ダミー許可 | L736-737 |
| **Low-S** | 署名の S 値は curve.n/2 以下必須 | high-S 許可 | L970-971 |
| **Push-only unlocking** | unlocking script は push 命令のみ | 非 push opcode 許可 | L851-852 |
| **Clean stack** | 実行後スタックに要素 1 個のみ | 複数要素許可 | L862-866 |

**C 化の設計方針**: C の VM にも `uint32_t tx_version` を渡し、各チェックポイントで
`if (tx_version <= 1)` で malleability 制限を適用する。`is_relaxed()` に相当する
判定は単純な整数比較なので C 化のコストはゼロ。

#### OP_VER / OP_VERIF / OP_VERNOTIF の特殊性

これらは復活 opcode の中でも特殊で、tx version を**実行時パラメータ**として参照する:

- **OP_VER** (L126-128): `transaction_version.to_bytes(4, "little")` をスタックに push
- **OP_VERIF** (L130-144): スタック top を 4 バイト LE 整数として解釈し、
  `tx_version >= popped_value` なら true。結果を `if_stack` に push
  → version による条件分岐スクリプトを実現する opcode
- **OP_VERNOTIF** (L142-143): OP_VERIF の否定

**C 化の注意**: C の VM に `tx_version` を渡す設計は必須。OP_VERIF/VERNOTIF は
`if_stack` 操作を伴うため、OP_IF/NOTIF と同じ制御フロー管理に統合する。

#### SIGHASH との相互作用

OP_CHECKSIG / OP_CHECKMULTISIG 内で署名検証を行う際:
- 署名の最終バイトが SIGHASH フラグ (L991)
- SIGHASH フラグに基づいて preimage 形式を選択 (BIP-143 / OTDA)
- `check_signature_encoding` (L958-973) で SIGHASH.validate() + Low-S チェック
- Low-S チェックは `is_relaxed()` で version ゲート (L970)

### SDK 間の Chronicle 対応差異 (2026-06-30 調査)

調査対象:
- **py-sdk**: `bsv/script/spend.py` (1004行)
- **ts-stack** (最新版): `packages/sdk/src/script/Spend.ts` (1596行) — `@ts-stack` monorepo、git pull 2026-06-30
- **Go SDK**: `script/interpreter/` — Chronicle 未対応のまま

**結論: py-sdk と ts-stack はどちらも Chronicle 対応済み。Go SDK は未対応。**

#### 1. opcode 有効/無効

| 動作 | py-sdk | ts-stack (最新版) | Go SDK |
|---|---|---|---|
| 復活 opcode | 常に有効 (`is_op_disabled()` = False) | `isAfterChronicle()` で条件付き有効。デフォルト: `isRelaxed()` (version > 1) で有効 | 未対応 (disabled/reserved のまま) |
| OP_VER handler | tx version を 4 バイト LE で push (L126) | 同じ (L735-739) | なし (reserved) |
| OP_VERIF/VERNOTIF | tx version `==` スタック値で完全一致比較 (L130-141) ★修正済み | 同じ (L849-865) | なし |
| OP_2MUL/OP_2DIV | 常に有効 (L489) | `isAfterChronicle()` が true なら有効 (L696) | なし (disabled) |
| OP_SUBSTR/LEFT/RIGHT | 常に有効 (L774-804) | `isAfterChronicle()` が true なら有効 (L677-693) | 未定義 |
| OP_LSHIFTNUM/RSHIFTNUM | 常に有効 (L501) | `isAfterChronicle()` が true なら有効 (L677-693) | 未定義 |

#### 2. OP_VERIF の比較セマンティクス ★修正済み (2026-06-30)

BSV node v1.2.0 ソース (`src/script/interpreter.cpp` L804-812) を確認:

```cpp
if(opcode == OP_VERIF || opcode == OP_VERNOTIF)
{
    if(vch.size() == 4)
    {
        std::vector<uint8_t> val(sizeof(checker.Version()));
        to_le(checker.Version(), val.data());
        fValue = std::ranges::equal(val, vch);  // ← 完全一致
    }
}
```

**`std::ranges::equal` = 完全一致比較**。py-sdk の `>=` 比較は誤りだった。

- **修正前** (py-sdk): `f_value = tx_ver_int >= buf_int` — ≧ 比較
- **修正後** (py-sdk): `f_value = buf == ver_bytes` — 完全一致 (node と ts-stack に一致)
- **ts-stack**: `fValue = compareNumberArrays(buf1, buf2)` — 完全一致 (正しい)

修正コミット: `bsv/script/spend.py` L130-141

#### 3. Chronicle 復活 opcode のバイト値

**3 SDK とも 0xb3-0xb7 で一致** (ts-stack は旧 ts-sdk から修正済み):

| opcode | py-sdk | ts-stack (最新) | Go SDK |
|---|---|---|---|
| OP_SUBSTR | 0xb3 | 0xb3 (= OP_NOP4 alias) | 未定義 (0xb3 は OP_NOP4) |
| OP_LEFT | 0xb4 | 0xb4 (= OP_NOP5 alias) | 未定義 |
| OP_RIGHT | 0xb5 | 0xb5 (= OP_NOP6 alias) | 未定義 |
| OP_LSHIFTNUM | 0xb6 | 0xb6 (= OP_NOP7 alias) | 未定義 |
| OP_RSHIFTNUM | 0xb7 | 0xb7 (= OP_NOP8 alias) | 未定義 |
| OP_SPLIT | 0x7f | 0x7f | — |
| OP_NUM2BIN | 0x80 | 0x80 | — |
| OP_BIN2NUM | 0x81 | 0x81 | — |

ts-stack 最新版は旧 OP_SPLIT(0x7f)/OP_NUM2BIN(0x80)/OP_BIN2NUM(0x81) と
新 OP_SUBSTR(0xb3)/OP_LEFT(0xb4)/OP_RIGHT(0xb5) を**別バイト値として正しく区別**している。

#### 4. malleability 緩和 (`is_relaxed`)

| チェック | py-sdk | ts-stack (最新版) | Go SDK |
|---|---|---|---|
| version ゲート | `is_relaxed()`: `version > 1` | `isRelaxed()`: `isRelaxedOverride \|\| version > 1` | なし |
| Minimal push | `not is_relaxed()` で強制 (L97) | `shouldEnforceMinimalData()`: デフォルト `!isRelaxed()` (L270) | — |
| MINIMALIF | `not is_relaxed()` で強制 (L227) | `hasFlag('MINIMALIF')` でのみ強制 (L872) | — |
| NULLFAIL | `not is_relaxed()` で強制 (L640) | `hasFlag('NULLFAIL')` でのみ強制 (L1234) | — |
| NULLDUMMY | `not is_relaxed()` で強制 (L736) | `shouldEnforceNullDummy()`: デフォルト `!isRelaxed()` (L280) | — |
| Low-S | `not is_relaxed()` で強制 (L970) | `shouldEnforceLowS()`: デフォルト `!isRelaxed()` (L275) | — |
| Clean stack | `not is_relaxed()` で強制 (L862) | `shouldEnforceCleanStack()`: デフォルト `!isRelaxed()` (L290) | — |
| Push-only unlocking | `not is_relaxed()` で強制 (L851) | `shouldEnforceSigPushOnly()`: デフォルト `!isRelaxed()` (L285) | — |

**概ね一致。** 差異は MINIMALIF と NULLFAIL: py-sdk は `is_relaxed()` でゲートするが、
ts-stack はデフォルトではこれらを強制しない (explicit flags 必要)。

#### 5. OTDA / Chronicle SIGHASH

| 機能 | py-sdk | ts-stack (最新版) | Go SDK |
|---|---|---|---|
| SIGHASH_CHRONICLE (0x20) | 定義済み | 定義済み (`TransactionSignature.SIGHASH_CHRONICLE`) | 未定義 |
| OTDA preimage | `_preimage_otda()` 実装済み | `formatOTDA()` 実装済み | 未実装 |
| ルーティング | `SIGHASH.use_otda()` | `formatBytes()`: FORKID のみ→BIP143、それ以外→OTDA | 未実装 |
| SIGHASH_FORKID 強制 | OTDA では不要 | デフォルトではチェックなし (explicit flags 時のみ) | — |
| OTDA SIGHASH_SINGLE bug | Phase 3 で対応予定 | `usesOtdaSingleBug()` 実装済み | — |

#### 6. ts-stack 独自の追加機能

py-sdk にない ts-stack の機能:
- **`verifyFlags`**: explicit flag set で Pre-Genesis/Post-Genesis/Chronicle の動作を個別制御
- **`isRelaxedOverride`**: コンストラクタで `isRelaxed: true` を明示指定可能
- **P2SH 対応**: `validate()` 内で P2SH スクリプト評価
- **OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY**: explicit flags でのみ有効化
- **`usesOtdaSingleBug()`**: OTDA + SIGHASH_SINGLE + inputIndex >= outputs.length のバグ検出
- **OP_CODESEPARATOR + CHECKSIG**: unlocking script の OP_CODESEPARATOR 後、subscript が locking script も含む
- **メモリ制限**: `stackMem` / `altStackMem` によるスタックメモリ制限
- **executedOpCount**: opcode 実行数制限 (Pre-Genesis のみ)

#### Phase 3 C 化への影響

- py-sdk と ts-stack は Chronicle 対応で**概ね一致**。OP_VERIF バグは修正済み
- BSV node v1.2.0 の `EnforceNonMalleability(flags, txnVersion)` = `!(IsChronicle(flags) && version > 1)` で、py-sdk の `not is_relaxed()` と同じセマンティクス
- BSV node の `IsOpcodeDisabled()` は OP_2MUL/OP_2DIV のみ対象、`utxo_era != PostChronicle` でゲート。py-sdk は常に有効としているが、Chronicle 後のみを想定しているため実運用上は問題なし
- ts-stack の `usesOtdaSingleBug()` は py-sdk の Phase 3b (OTDA Legacy) で参考にできる
- NULLFAIL / MINIMALIF のデフォルト動作の差異: py-sdk は `is_relaxed()` でゲート (version 1 で強制)、ts-stack は explicit flags のみ。BSV node は `VerifyNullFail(flags) && EnforceNonMalleability()` で両条件を要求 — py-sdk の方がノードに近い
- C VM は py-sdk の動作を忠実に再現すれば node と整合する

### 問題

- **opcode分岐**: 巨大な if/elif チェーン（数十の分岐）
- **スタック操作**: `list.pop()` / `list.append()` の繰り返し
- **ビット演算**: `OP_AND` / `OP_OR` 等がバイト単位のPythonループ
  ```python
  sig = bytes([a & b for a, b in zip(x1, x2)])  # OP_AND
  ```
- **マルチシグ検証** (L696-738): ネストした while/for ループで署名検証を繰り返し

### 段階的アプローチ

```
Phase 3a: コア opcodes + ビット/文字列/Chronicle + VM ループ  ✅ 完了
  ├── スタック操作 (OP_DUP, OP_DROP, OP_SWAP, OP_ROT 等 ~20個)
  ├── 比較・論理 (OP_EQUAL, OP_VERIFY, OP_IF/ELSE/ENDIF)
  ├── 算術 (OP_ADD, OP_SUB, OP_NUMEQUAL 等 ~25個, PyLong で任意精度)
  ├── ハッシュ (OP_SHA256, OP_HASH160, OP_HASH256 — secp256k1_sha256 直接利用)
  ├── ビット演算 (OP_AND/OR/XOR, OP_INVERT, OP_LSHIFT/RSHIFT)
  ├── 文字列 (OP_CAT, OP_SPLIT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_NUM2BIN, OP_BIN2NUM)
  ├── Chronicle opcodes (OP_VER, OP_VERIF/VERNOTIF, OP_2MUL/2DIV, OP_LSHIFTNUM/RSHIFTNUM)
  ├── NOP 系 (OP_NOP1〜OP_NOP77 + OP_PUBKEYHASH/PUBKEY/INVALIDOPCODE)
  ├── validate() の malleability ゲート (push-only, clean stack, minimal push)
  └── CHECKSIG スタブ (Phase 3b エラー → Python フォールバック)
  実装: ~830行の C コード (bsv_native.c に追加)
  spend.py: _validate_native() + "Phase 3b" フォールバック

Phase 3b: 署名検証 (コールバック方式)                          ✅ 完了
  ├── OP_CHECKSIG / OP_CHECKSIGVERIFY — C で stack 操作、Python コールバックで検証
  ├── OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY — C で stack 操作・ループ
  ├── Python コールバック: encoding check + subscript 構築 + verify_signature
  ├── malleability チェック C 内完結 (NULLFAIL, NULLDUMMY, Low-S)
  └── "Phase 3b" フォールバック除去 — C VM が全 opcode をハンドル
  実装: ~200行の C コード (CHECKSIG/CHECKMULTISIG ハンドラ)
  spend.py: checksig_cb クロージャ + _validate_native() 更新

Phase 3b+: CHECKMULTISIG ループ変数バグ修正                    ✅ 完了 (2026-07-01)
  ├── BSV node v1.2.2 / ts-sdk / py-sdk Engine との比較調査
  ├── spend.py L718: sigs_count -= 1 → keys_count -= 1
  ├── bsv_native.c L3375: loop_sigs -= 1 → keys_count -= 1
  └── 失敗パステスト4件追加 (2of3 正常, 2of3 外部キー, 2of2 両方無効, 1of3 不足)
  詳細: 本ファイル末尾「CHECKMULTISIG ループ変数バグ — 詳細調査報告」参照

Phase 3c: CHECKSIG パスの C 内完結化 (任意・将来)
  ├── encoding チェック (DER parse, Low-S, SIGHASH validate, pubkey parse) を C 化
  ├── subscript 構築 (from_chunks, find_and_delete) を C 化
  ├── preimage を C 内で直接呼び出し (Phase 2 の tx_preimages/tx_preimage_otda 利用)
  ├── secp256k1_ecdsa_verify を C 内で直接呼び出し (Phase 0 の g_ctx 利用)
  └── Python コールバックを廃止 → OP_CHECKSIG が完全に C 内で完結
  期待効果: CHECKSIG あたりの Python ↔ C 境界越え排除 (~5μs → ~0.5μs)
  前提: subscript の Script.from_chunks / find_and_delete ロジックを C で再実装する必要がある
```

### C VM に渡すべきパラメータ

```c
typedef struct {
    /* Scripts */
    const uint8_t *locking_script;   size_t locking_len;
    const uint8_t *unlocking_script; size_t unlocking_len;
    /* Transaction context */
    uint32_t tx_version;              /* is_relaxed = (tx_version > 1) */
    uint32_t lock_time;
    int32_t  input_index;
    uint32_t input_sequence;
    int64_t  source_satoshis;
    /* Source outpoint */
    const char *source_txid;          /* 64-char hex */
    uint32_t source_output_index;
    /* Other inputs (for preimage) */
    PyObject *other_inputs;           /* list of tuples */
    PyObject *outputs;                /* list of bytes */
} SpendParams;
```

### 期待される効果

| ケース              | 改善前 | 改善後 | 高速化 |
| ------------------- | ------ | ------ | ------ |
| P2PKH 検証          | ~50μs  | ~2μs   | 25x    |
| マルチシグ (2-of-3) | ~200μs | ~5μs   | 40x    |
| 複雑なスクリプト    | ms単位 | μs単位 | 100x+  |

### libsecp256k1 統合の恩恵

```
coincurve 維持の場合:
  C (Script VM) → Python → CFFI → C (libsecp256k1) → Python → C
  OP_CHECKSIG 1回あたり ~5μs のオーバーヘッド

libsecp256k1 統合済みの場合:
  C (Script VM) → C (secp256k1_ecdsa_verify)  ← 直接呼び出し
  OP_CHECKSIG 1回あたり ~0.5μs のオーバーヘッド
```

### 想定期間: 4〜6週間 (3段階で分割リリース)

---

## Phase 4: BRC-42 鍵導出最適化 + libsecp256k1 活用拡大

**目的:** Phase 0 で統合した libsecp256k1 の未活用機能を py-sdk に展開する。

### 対象ファイル

- `bsv/wallet/key_deriver.py` — `_branch_scalar()` (L107-140), `derive_*()` メソッド群
- `bsv/keys.py` — `_sign_custom_k()` (L217-268)
- `bsv/curve.py` — `curve_add()`, `curve_multiply()`

### 問題

1回の鍵導出で ECDH(C) → HMAC(C) → Python大整数mod → C の往復が発生。
`_sign_custom_k()` は ECDSA 署名を**純Pythonで実装**しており、最も遅い。

### タスク

| #   | タスク                                                   | 効果                           |
| --- | -------------------------------------------------------- | ------------------------------ |
| 4.1 | `ec_pubkey_tweak_add` で BRC-42 公開鍵導出を簡素化       | 2呼び出し → 1呼び出し          |
| 4.2 | `ec_seckey_tweak_add` で秘密鍵導出を定数時間化           | Python大整数mod排除            |
| 4.3 | `_sign_custom_k` を libsecp256k1 カスタムnonce関数に置換 | 純Python ECDSA 排除、20x高速化 |
| 4.4 | `context_randomize` でサイドチャネル対策                 | セキュリティ改善               |
| 4.5 | Schnorr 署名 API 公開 (将来のプロトコル拡張用)           | API準備                        |

### libsecp256k1 未活用機能の統合

| libsecp256k1 機能     | 現状                                          | 改善                                                 |
| --------------------- | --------------------------------------------- | ---------------------------------------------------- |
| `ec_pubkey_tweak_add` | 未使用 (curve_multiply + combine の2呼び出し) | 1呼び出しに                                          |
| `ec_seckey_tweak_add` | 未使用 (Python大整数mod)                      | 定数時間C演算                                        |
| カスタムnonce ECDSA   | 純Python実装 (`_sign_custom_k`)               | libsecp256k1 `secp256k1_ecdsa_sign` + nonce function |
| Schnorr 署名          | 未使用                                        | 将来のプロトコル拡張に備え API を用意                |
| `context_randomize`   | 未使用                                        | サイドチャネル対策強化                               |

### 期待される効果

| ケース                              | 改善前          | 改善後 | 高速化 |
| ----------------------------------- | --------------- | ------ | ------ |
| derive_private_key (キャッシュミス) | ~200μs          | ~50μs  | 4x     |
| derive_public_key (for_self=False)  | ~400μs          | ~80μs  | 5x     |
| `_sign_custom_k`                    | ~1ms (純Python) | ~50μs  | 20x    |
| バッチ導出 (100鍵)                  | ~40ms           | ~5ms   | 8x     |

### 完了条件

- [x] `seckey_tweak_add` で秘密鍵導出を定数時間化 ✅ 2026-07-01
- [x] `pubkey_tweak_add` で公開鍵導出を 2→1 native call に簡素化 ✅ 2026-07-01
- [x] `ecdsa_sign_with_k` で純 Python ECDSA を排除 ✅ 2026-07-01
- [x] 既存テストスイート全体が native モードで通る (3430 passed) ✅ 2026-07-01
- [ ] `context_randomize` 定期呼び出し (4.4) — 初期化時のみ実行中、定期化は任意
- [ ] Schnorr 署名 API 公開 (4.5) — 将来のプロトコル拡張用、任意

### 実装メモ (2026-07-01)

- **C 関数 1 個追加**: `ecdsa_sign_with_k(msg32, secret32, k32)` — libsecp256k1 の `secp256k1_ecdsa_sign` にカスタム nonce 関数 `nonce_fn_custom_k` を渡す。nonce 関数は渡された `k` を `nonce32` にコピーするだけ
- **Python 側変更**:
  - `keys.py`: `sign(k=...)` で native 優先パスを追加。pure Python `_sign_custom_k` はフォールバックとして保存
  - `key_deriver.py`: `_USE_NATIVE` フラグを追加。`derive_private_key` で `seckey_tweak_add` を使用（Python 大整数 mod 排除、定数時間化）。`derive_public_key(for_self=False)` で `pubkey_tweak_add` を使用（2 native calls → 1、Point 中間変換排除）
- **Phase 0 で先行実装済みの C 関数を活用**: `pubkey_tweak_add`, `seckey_tweak_add`, `context_randomize` は全て Phase 0 で libsecp256k1 ラッパーとして実装済みだったが、Python 側から直接呼ばれていなかった。Phase 4 でこれらを key_deriver.py から直接利用するようにした

### 想定期間: 2〜3週間 → 完了 (4.1-4.3)、4.4/4.5 は任意

---

## タイムライン

```
       ✅ 完了         ✅ 完了         ✅ 完了         ✅ 完了         ✅ 完了
       ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌───────────┐  ┌─────────┐
       │ Phase 0    │  │ Phase 1    │  │ Phase 2  │  │ Phase 3   │  │ Phase 4 │
       │ 基盤構築   │  │ Tx/Script  │  │ Preimage │  │ Script VM │  │ 鍵導出  │
       │ libsecp統合 │  │ MerklePath │  │ BIP143   │  │ 3a+3b+3b+ │  │ 4.1-4.3│
       │ coincurve  │  │            │  │ + OTDA   │  │ +SE統合   │  │         │
       │ 置換       │  │            │  │          │  │           │  │         │
       └──────┬─────┘  └─────┬──────┘  └────┬─────┘  └─────┬─────┘  └────┬────┘
              ▼              ▼              ▼               ▼              ▼
         2026-06-30     2026-06-30     2026-06-30      2026-07-01     2026-07-01
```

| Phase | 期間     | 状態     | 主な成果                                                       |
| ----- | -------- | -------- | -------------------------------------------------------------- |
| **0** | 3〜4週間 | ✅ 完了  | libsecp256k1 統合、coincurve フォールバック化、SHA256 埋め込み |
| **1** | 3〜4週間 | ✅ 完了  | Tx/Script/MerklePath C化、5466テスト全パス                     |
| **2** | 2〜3週間 | ✅ 完了  | BIP-143 + OTDA preimage C化、5466テスト全パス                  |
| **3** | 4〜6週間 | ✅ 3b+ 完了 | 3a+3b: VM+全opcode C化完了, 3b+: CHECKMULTISIG バグ修正完了。残り 3c (任意) |
| **SE** | — | ✅ 完了 | Script Engine 統合: Engine/interpreter 削除 (~9,100行削除)、Spend 一本化 |
| **4** | 2〜3週間 | ✅ 4.1-4.3 完了 | seckey/pubkey_tweak_add 直接利用、ecdsa_sign_with_k で純Python ECDSA 排除 |

**合計: 約 14〜20週間** (3.5〜5ヶ月)
**進捗: Phase 0+1+2+3(3a+3b+3b+) + SE統合 + Phase 4(4.1-4.3) 完了 (2026-07-01)**
**テスト: 3,430 passed, 259 skipped**
**残り: Phase 3c (任意)、Phase 4.4 (context_randomize 定期呼び出し)、4.5 (Schnorr API)**
**未着手横断タスク: CI/wheel (0E)、等価性/ファズ/メモリテスト**

---

## リリース戦略

| バージョン | Phase | 変更点                                         | coincurve の扱い             |
| ---------- | ----- | ---------------------------------------------- | ---------------------------- |
| **v2.2.0** | 0+1   | `_bsv_native` 導入、Tx パース / SPV検証 高速化 | フォールバックとして残留     |
| **v2.3.0** | 2     | 署名パイプライン高速化                         | optional dependency に格下げ |
| **v2.4.0** | 3a+3b+3b+ | スクリプトVM + CHECKMULTISIG修正            | optional (非推奨)            |
| **v2.5.0** | 3c    | Chronicle opcodes C化                          | optional (非推奨)            |
| **v2.6.0** | 4     | 鍵導出最適化、Schnorr API                      | 十分な実績確認後、削除を検討 |

### 配布

- **バイナリ wheel** (cibuildwheel): できるだけ多くのプラットフォームで提供
  - Linux: manylinux (x86_64, aarch64), musllinux (Alpine 対応)
  - macOS: x86_64, arm64 (Apple Silicon)
  - Windows: x86_64
- **ソース配布** (`sdist`): Cコンパイラがあればどの環境でもビルド可能
- **Pure Python フォールバック**: C拡張なしでも非暗号処理は動作。暗号処理は coincurve フォールバックまたは wheel で対応
- **CPython Limited API の検討**: `Py_LIMITED_API` を使えば1つの wheel で複数の Python バージョンに対応可能

---

## テスト戦略

既存テストスイート (`pytest --cov=bsv`) がそのまま通ることが最低条件。
C拡張導入に伴い、以下の7カテゴリのテストを新規追加する。

| カテゴリ           | 内容                                 | 優先度   |
| ------------------ | ------------------------------------ | -------- |
| **等価性**         | C実装 ⇔ Python実装の出力一致         | 必須     |
| **境界値**         | 切り詰め入力、varint境界、空データ   | 必須     |
| **メモリ安全**     | tracemalloc / valgrind でリーク検出  | 必須     |
| **フォールバック** | 3モード全てで既存テスト通過          | 必須     |
| **coincurve互換**  | coincurve フォールバック時に全件通過 | 必須     |
| **ファズ**         | hypothesis による不正入力テスト      | 強く推奨 |
| **ベンチマーク**   | pytest-benchmark で高速化を定量化    | 推奨     |

### 等価性テスト

```python
@pytest.mark.parametrize("hex_data", KNOWN_TX_VECTORS)
def test_tx_from_bytes_equivalence(hex_data):
    raw = bytes.fromhex(hex_data)
    py_result = _py_tx_from_reader(Reader(raw))
    c_result  = _bsv_native.tx_from_bytes(raw)
    assert py_result.txid() == c_result.txid()
    assert py_result.serialize() == c_result.serialize()
```

### 境界値テスト

```python
def test_tx_from_bytes_truncated():
    """途中で切れたバイト列でクラッシュしない"""
    raw = bytes.fromhex(VALID_TX_HEX)
    for i in range(1, len(raw)):
        with pytest.raises((ValueError, BufferError)):
            _bsv_native.tx_from_bytes(raw[:i])

@pytest.mark.parametrize("n", [0, 0xFC, 0xFD, 0xFFFE, 0xFFFF, 0x10000, 0xFFFFFFFF])
def test_varint_boundary(n):
    """varint 1/3/5/9バイト切り替え境界"""
    ...
```

### メモリ安全テスト

```python
def test_no_memory_leak():
    import tracemalloc
    tracemalloc.start()
    raw = bytes.fromhex(VALID_TX_HEX)
    for _ in range(100_000):
        tx = _bsv_native.tx_from_bytes(raw)
        del tx
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert current < 1_000_000
```

### フォールバックテスト

```python
def test_fallback_when_native_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, '_bsv_native', None)
    importlib.reload(bsv.transaction)
    assert bsv.transaction._USE_NATIVE is False
    tx = Transaction.from_hex(VALID_TX_HEX)
    assert tx.txid() == EXPECTED_TXID
```

### ファズテスト

```python
from hypothesis import given, strategies as st

@given(data=st.binary(min_size=0, max_size=10000))
def test_tx_from_bytes_never_crashes(data):
    try:
        _bsv_native.tx_from_bytes(data)
    except (ValueError, BufferError):
        pass  # 例外は OK、クラッシュは NG

@given(data=st.binary(min_size=0, max_size=5000))
def test_script_chunks_roundtrip(data):
    try:
        chunks = _bsv_native.parse_script_chunks(data)
        reserialized = _bsv_native.serialize_script_chunks(chunks)
        chunks2 = _bsv_native.parse_script_chunks(reserialized)
        assert chunks == chunks2
    except ValueError:
        pass
```

### CI マトリクス

3つの動作モードを全て CI でテストし、前後互換性を保証する。

```
                  _bsv_native    coincurve       純Python
                  (推奨)         (フォールバック)  (非暗号のみ)
Python 3.10         ✓              ✓              ✓
Python 3.11         ✓              ✓              ✓
Python 3.12         ✓              ✓              ✓
Python 3.13         ✓              ✓              ✓
```

```
                  Linux          Linux          macOS        macOS       Windows
                  x86_64         aarch64        x86_64       arm64       x86_64
wheel ビルド        ✓              ✓              ✓           ✓            ✓
テスト実行          ✓              ✓              ✓           ✓            ✓
```

---

## coincurve → \_bsv_native 移行マッピング

### py-sdk で使用中の API 対応表

| py-sdk の呼び出し                   | coincurve API                              | \_bsv_native API                                        |
| ----------------------------------- | ------------------------------------------ | ------------------------------------------------------- |
| `PrivateKey.__init__()`             | `CcPrivateKey(secret)`                     | `pubkey_from_secret(secret)`                            |
| `PrivateKey.sign()`                 | `CcPrivateKey.sign(msg, hasher)`           | `ecdsa_sign(msg32, secret)`                             |
| `PrivateKey.sign_recoverable()`     | `CcPrivateKey.sign_recoverable()`          | `ecdsa_sign_recoverable(msg32, secret)`                 |
| `PublicKey.verify()`                | `CcPublicKey.verify(sig, msg)`             | `ecdsa_verify(sig, msg32, pubkey)`                      |
| `PublicKey.combine()`               | `CcPublicKey.combine([other])`             | `pubkey_combine([pk1, pk2])`                            |
| `PublicKey.multiply()`              | `CcPublicKey.multiply(scalar)`             | `pubkey_tweak_mul(pubkey, scalar)`                      |
| `PublicKey.from_point()`            | `CcPublicKey.from_point(x, y)`             | `pubkey_parse(b'\x04' + x + y)`                         |
| `PublicKey.point()`                 | `CcPublicKey.point()`                      | `pubkey_serialize(pubkey, compressed=False)` → x,y 分離 |
| `PrivateKey.derive_shared_secret()` | `CcPublicKey.multiply(secret)`             | `ecdh(secret, pubkey)`                                  |
| `recover_public_key()`              | `CcPublicKey.from_signature_and_message()` | `ecdsa_recover(sig65, msg32)`                           |

### Phase 4 で追加

| \_bsv_native API                       | libsecp256k1 関数               | 用途                 |
| -------------------------------------- | ------------------------------- | -------------------- |
| `pubkey_tweak_add(pubkey, scalar)`     | `secp256k1_ec_pubkey_tweak_add` | BRC-42 公開鍵導出    |
| `seckey_tweak_add(secret, scalar)`     | `secp256k1_ec_seckey_tweak_add` | BRC-42 秘密鍵導出    |
| `schnorr_sign(msg32, secret)`          | `secp256k1_schnorrsig_sign32`   | 将来のプロトコル拡張 |
| `schnorr_verify(sig64, msg32, pubkey)` | `secp256k1_schnorrsig_verify`   | 将来のプロトコル拡張 |
| `context_randomize(seed32)`            | `secp256k1_context_randomize`   | サイドチャネル対策   |

---

## リスクと対策

| リスク                                          | 影響                             | 対策                                                                        |
| ----------------------------------------------- | -------------------------------- | --------------------------------------------------------------------------- |
| libsecp256k1 ビルドのクロスプラットフォーム対応 | 特定 OS/arch でビルド失敗        | cibuildwheel + CI マトリクス。wheel 未提供環境では coincurve フォールバック |
| coincurve 廃止時の移行混乱                      | 既存ユーザーが壊れる             | 段階的格下げ。coincurve フォールバックコードは十分な実績蓄積まで保存        |
| libsecp256k1 のセキュリティ更新追跡             | 脆弱性の見逃し                   | bitcoin-core/secp256k1 の release watch を設定、定期的にバージョン更新      |
| Python バージョン互換                           | CPython API 変更で破損           | Limited API (`Py_LIMITED_API`) の採用を検討                                 |
| 未対応プラットフォーム                          | wheel なし環境でインストール不可 | coincurve フォールバック維持 + sdist からのソースビルド対応                 |
| C実装とPython実装の不整合                       | デグレッション                   | 等価性テストを全CI実行。純Python実装を検証基準として保存                    |

---

## 前提条件

- Python >= 3.10 (py-sdk 既存要件)
- C99 準拠コンパイラ (gcc, clang, MSVC)
- libsecp256k1 ソース同梱 (vendored, MIT License)
- SHA256 / HMAC-SHA256: libsecp256k1 ソースツリー内の実装を利用
- pycryptodomex: AES-CBC / AES-GCM / RIPEMD160 用に残留
- coincurve: Phase 0 以降 optional dependency に格下げ（フォールバック用に保存）
- 純Python実装: C拡張で置き換える全処理の既存コードを削除せず保存
- マルチプラットフォーム wheel: cibuildwheel で主要 OS/arch をカバー

---

## Phase 1 実装課題 (2026-06-30)

Phase 1 の C 実装で遭遇した問題と、今後の Phase に適用すべき教訓。

### 1. hex⇔bytes 変換のセマンティクス差異

**問題**: Python の `hash_fn(a + b)` は 128 文字 hex を 64 バイトに変換してから**全体を reverse** するが、最初の C 実装は 2 つの 32 バイトを**個別に reverse** してから連結した。結果が異なる。

**原因**: Bitcoin の慣例で txid を「表示用 hex ↔ 内部バイト列」変換する際に byte-reverse するが、Python コードは hex 文字列連結後に一括変換するため、reverse の適用範囲が C と異なる。

**対策**: `merkle_hash_pair` を「Python の `hash_fn` と完全に同じセマンティクス」で再実装。**C 関数を書く前に Python の等価コードをステップごとに分解し、各中間値を検証すべき**。

**Phase 2 への教訓**: preimage 構築でも hex⇔bytes + reverse が多用される。Python コードの中間値を print して C と照合するユニットテストを先に書く。

### 2. merkle_compute_root のハイブリッド設計

**問題**: Python の `compute_root` は `find_or_compute_leaf` を呼び、パスに存在しないノードを再帰的に下位レベルから計算する。C で完全再実装するとパスデータ構造（Python list of list of dict）の走査が複雑になり、バグの温床となる。

**対策**: ハイブリッド方式を採用 — Python の `find_or_compute_leaf` でリーフ探索（再帰あり）、C の `merkle_hash_pair` でハッシュ計算のみ委譲。パフォーマンスのボトルネックは hash256 + hex⇔bytes 変換であり、リーフ探索は軽量なので、このトレードオフは妥当。

**Phase 3 への教訓**: Script VM でも Python データ構造（スタック = Python list）の走査が必要。C に渡すデータの粒度を慎重に設計する。全てを C 化するのではなく、計算集約的な部分だけを C に委譲するハイブリッド方式が有効な場合がある。

### 3. sprintf null terminator 問題

**問題**: `sprintf(buf + offset, "%02x", byte)` は各呼び出しで null terminator を書き込み、次の hex ペアの先頭を上書きする。結果として txid が 2 文字に切り詰められた。

**対策**: LUT (Lookup Table) ベースの手動 hex 変換に切り替え（`bytes_to_hex`, `bytes_to_hex_reversed`）。**C での hex 文字列構築に sprintf を使わない**。

**全 Phase 共通**: hex 変換ユーティリティは Phase 0/1 で整備済み。以降の Phase では既存の `bytes_to_hex` / `hex_to_bytes` ファミリを再利用する。

### 4. Python パーサーの寛容さ vs C パーサーの厳格さ

**問題**: Python の tx パーサーは不完全なデータ（locktime が 1 バイト不足等）でも部分的にパースできるが、C は厳密にバッファ境界をチェックして ValueError を返す。keystore テストのモック tx データが 61 バイト（正しくは 62 バイト）だったため失敗。

**対策**: `transaction.py` の `from_reader()` で C パーサーを try/except で囲み、ValueError 時に Python パーサーにフォールバック。

**Phase 2 への教訓**: preimage 構築では入力データは常に有効な tx から来るため、この問題は発生しにくい。ただし、テストでモックデータを使う場合は C の厳格さを考慮する必要がある。

### 5. serialize バリデーションの不足

**問題**: C の `serialize_script_chunks` に当初バリデーションがなく、以下のテストが失敗:
- direct push opcode の data 長が opcode 値と不一致
- OP_PUSHDATA1 の data が 255 バイト超
- 非 push opcode (> 0x4E) に data が付いている

**対策**: Python 版と同等のバリデーションを C 版にも追加。

**全 Phase 共通**: **C 関数を書いたらまず既存テストを全件実行する**。Python 版のバリデーションロジックを漏らさず移植する。テスト駆動で漏れを検出できるが、そもそも Python 版のバリデーション箇所を事前に洗い出しておくべき。

### 6. 未実施の品質タスク

以下は Phase 1 コア実装完了後の残タスクとして、CI/wheel (0E) と合わせて実施予定:

| タスク | 状態 | 備考 |
| --- | --- | --- |
| 等価性テスト (C ⇔ Python 出力一致) | 未着手 | Phase 2 と並行で実施 |
| ファズテスト (hypothesis) | 未着手 | 特に tx_from_bytes, parse_script_chunks |
| メモリリークテスト (tracemalloc) | 未着手 | 10万回ループで検証 |
| ベンチマーク (pytest-benchmark) | 未着手 | Phase 1 の効果測定 |
| CI 3モードテスト | 未着手 | 0E と統合 |

---

## Phase 2 実装課題 (2026-06-30)

Phase 2 は Phase 1 の教訓を活かし、比較的スムーズに完了した。以下は Phase 3 に持ち越す課題と設計判断の記録。

### 1. locking_script が None の入力

**問題**: `calc_input_signature_hash()` (Script VM の OP_CHECKSIG 経由) では、署名対象以外の入力の `locking_script` が `None` のまま呼ばれる。C 側に渡す際に `inp.locking_script.serialize()` で `AttributeError` が発生。

**対策**: Python 側で `inp.locking_script.serialize() if inp.locking_script else b""` にフォールバック。C 側は空バイトを受け取っても正常に処理する。

**Phase 3 への教訓**: Script VM では Transaction オブジェクトの状態が「部分的に構築済み」であるケースが多い（署名中の未完了入力など）。C に渡すデータの事前検証で None チェックを忘れない。Python オブジェクトのフィールドが None になりうるケースを洗い出してから C を書くべき。

### 2. Phase 1 の資産再利用が効果的

**成果**: Phase 1 で整備した `hex_to_bytes_reversed`, `write_varint`, `hash256_64` などの内部ヘルパーが Phase 2 でそのまま再利用できた。新規追加したヘルパーは `hash256_var`（可変長版）, `parse_input_tuple`, `write_u32_le`, `write_u64_le` のみ。

**Phase 3 への教訓**: Phase 2 で追加した `parse_input_tuple` や `write_u32_le`/`write_u64_le` は Phase 3 でも OTDA Legacy パスの tx シリアライズで再利用可能。共通ヘルパーの設計が蓄積効果を生んでいる。

### 3. OTDA Legacy の Phase 3 統合判断

**判断**: OTDA Legacy（tx コピー → SIGHASH 改変 → serialize）は Phase 3 に後回しにした。

**理由**:
- Transaction オブジェクトのディープコピー (`_create_transaction_copy_for_signing`) が Python オブジェクト操作に深く依存
- `_apply_sighash_modifications` が inputs/outputs の list 操作（clear, slice, 個別フィールド書き換え）を行う
- Phase 3 で Script VM を C 化する際、tx のメモリ表現が C 側にある前提でコピー + 改変 + serialize を C 内で一気通貫にする方が、Python ↔ C の往復を最小化できる
- 現時点で OTDA Legacy を呼ぶのは Script VM の OP_CHECKSIG のみであり、Script VM 自体が Python なので C 化の効果が限定的

**Phase 3 での実装方針**: `_calc_input_preimage_legacy` 全体を C 関数化する。tx データの C 構造体への変換は Phase 1 の `tx_from_bytes` の内部表現を流用可能。

### 4. BIP-143 の入力データ形式設計

**設計**: Python → C のデータ受け渡しに `(txid_hex, vout, locking_script_bytes, satoshis, sequence, sighash)` タプルのリストを採用。TransactionInput オブジェクトを直接渡さず、必要なフィールドだけ抽出して渡す。

**利点**:
- C 側が Python オブジェクトの属性アクセスに依存しない（`PyObject_GetAttrString` 不要）
- テスト時に Python オブジェクトなしで C 関数を直接呼び出せる
- 型チェックが明確（タプル要素ごとに型を検証）

**Phase 3 への教訓**: Script VM では Python のスタック（`list[bytes]`）を C に渡す必要がある。タプル方式と同様に、C 側は Python オブジェクトの構造に依存せず、プリミティブ型で受け渡しする設計が望ましい。

### 5. 全 Phase 蓄積状況

| Phase | bsv_native.c 行数 (累計) | C 関数数 (累計) | 内部ヘルパー数 (累計) |
| --- | --- | --- | --- |
| 0 | ~820 | 18 | 0 |
| 1 | ~1640 (+820) | 25 (+7) | 8 (+8) |
| 2 | ~2150 (+510) | 27 (+2) | 12 (+4) |
| 3a | ~2980 (+830) | 28 (+1) | ~30 (+18) |
| 3b | ~3180 (+200) | 28 (+0) | ~30 (+0) |
| 3b+ | ~3180 (+0) | 28 (+0) | ~30 (+0) |
| SE統合 | ~3180 (+0) | 28 (+0) | ~30 (+0) |
| 4 | ~3240 (+60) | 29 (+1) | ~31 (+1) |

Phase 3a で VM の基盤構造体・ヘルパー群を大量追加。Phase 3b は既存のスイッチ文に CHECKSIG/CHECKMULTISIG ハンドラを埋め込む形のため追加行数は少ない。Phase 3b+ はバグ修正 (1行変更 × 2ファイル) + テスト追加のみ。SE統合は Engine 削除のため C コード変更なし。Phase 4 は `ecdsa_sign_with_k` 1関数追加 + カスタム nonce 関数。Python 側は key_deriver.py で `seckey_tweak_add`/`pubkey_tweak_add` を直接呼び出しに変更。

---

## Phase 3 準備調査の課題 (2026-06-30)

Phase 3 着手前に tx version / opcode の動作調査と SDK 間クロスチェックを実施した。以下は発見した課題と対応の記録。

### 1. OP_VERIF 比較セマンティクスのバグ修正

**問題**: py-sdk の OP_VERIF 実装が `tx_version >= popped_value` (≧ 比較) になっていた。

**原因調査**: BSV node v1.2.0 のソース (`src/script/interpreter.cpp` L804-812) を直接確認:
```cpp
fValue = std::ranges::equal(val, vch);  // 完全一致比較
```
ts-stack 最新版 (`packages/sdk/src/script/Spend.ts` L859) も `compareNumberArrays` で完全一致。

**修正**: `bsv/script/spend.py` L141 を `f_value = buf == ver_bytes` に変更。5466 テスト全パス。

**教訓**: SDK 間で同じ opcode の意味が異なるケースは、必ず BSV node のリファレンス実装で正しい動作を確認すべき。ts-stack は node に追従しているが、py-sdk は独自実装の箇所があった。Phase 3 で C 化する際も node の実装を参照コードとして使う。

### 2. SDK 間 Chronicle 対応状況の整理

**調査対象**:
- py-sdk: `bsv/script/spend.py`
- ts-stack (最新版, git pull 2026-06-30): `packages/sdk/src/script/Spend.ts` (1596行)
- Go SDK: `script/interpreter/` — Chronicle 未対応

**主要な発見**:

1. **旧 ts-sdk と ts-stack は別物**: 旧 ts-sdk リポジトリ (`/Users/cdl/development/ts-sdk`) は Chronicle 未対応。正式実装は `ts-stack/packages/sdk` にある。最新版で opcode バイト値・OTDA・`isRelaxed()` 全て対応済み
2. **opcode バイト値は一致**: py-sdk と ts-stack で OP_SUBSTR=0xb3, OP_LEFT=0xb4, OP_RIGHT=0xb5, OP_LSHIFTNUM=0xb6, OP_RSHIFTNUM=0xb7 が一致
3. **Go SDK は Chronicle 完全未対応**: OP_2MUL/2DIV が disabled、OP_VER が reserved、OTDA 未実装

**Phase 3 への影響**: C 化の参照コードとして BSV node v1.2.0 のソースと ts-stack の両方を活用できる。詳細な比較表は「SDK 間の Chronicle 対応差異」セクションに記載済み。

### 3. BSV node の EnforceNonMalleability パターンの確認

**発見**: BSV node v1.2.0 では全ての malleability チェックが同一パターンで実装されている:
```cpp
// !(Chronicle && version > 1) のとき true → チェックを強制
inline constexpr bool EnforceNonMalleability(uint32_t flags, int32_t txnVersion) {
    return !(IsChronicle(flags) && IsMalleableTxnVersion(txnVersion));
}
```

py-sdk の `not is_relaxed()` = `not (version > 1)` と同等。ただし node は `IsChronicle(flags)` フラグが前提条件。py-sdk は Chronicle 後のみを想定しているためフラグチェックは省略している。

**確認済みチェックポイント** (node vs py-sdk 対応):
| node のチェック | node コード位置 | py-sdk 対応 |
|---|---|---|
| requireMinimal push | L431 | L97 (`not is_relaxed()`) ✅ |
| MINIMALIF | L799 | L227 (`not is_relaxed()`) ✅ |
| Low-S | L282 | L970 (`not is_relaxed()`) ✅ |
| NULLFAIL (CHECKSIG) | L1496 | L640 (`not is_relaxed()`) ✅ |
| NULLFAIL (CHECKMULTISIG) | L1640 | — (py-sdk は CHECKMULTISIG 内で個別チェックなし) ⚠️ |
| NULLDUMMY | L1663 | L736 (`not is_relaxed()`) ✅ |
| Clean stack | L2426 | L862 (`not is_relaxed()`) ✅ |
| Push-only unlocking | L2312 | L851 (`not is_relaxed()`) ✅ |

⚠️ **CHECKMULTISIG の NULLFAIL**: node は CHECKMULTISIG 内の各署名ポップ時にも `VerifyNullFail && EnforceNonMalleability` チェックを行う (L1638-1643)。py-sdk はこのチェックがない。Phase 3 の C 化時に追加を検討する。

### 4. ts-stack にあって py-sdk にない機能

Phase 3 または将来のフェーズで検討すべき ts-stack の追加機能:

| 機能 | ts-stack | py-sdk | 優先度 |
|---|---|---|---|
| `verifyFlags` (explicit flag set) | Pre-Genesis/Post-Genesis/Chronicle を個別制御 | なし (Chronicle 後のみ想定) | 低 |
| P2SH 対応 | `validate()` 内で P2SH 評価 | なし | 低 |
| `usesOtdaSingleBug()` | OTDA + SINGLE + inputIndex >= outputs.length 検出 | なし | 将来 |
| OP_CODESEPARATOR + CHECKSIG 境界 | unlocking の CODESEPARATOR 後、subscript が locking も含む | 要確認 | 将来 |
| スタックメモリ制限 | `stackMem` / `altStackMem` で制限 | なし | 将来 |
| opcode 実行数制限 | `executedOpCount` (Pre-Genesis のみ) | なし | 低 |
| OP_CHECKLOCKTIMEVERIFY / CSV | explicit flags でのみ有効化 | なし | 低 |

---

## Phase 3b 完了記録 (2026-07-01)

### 実装内容

OP_CHECKSIG/CHECKSIGVERIFY/CHECKMULTISIG/CHECKMULTISIGVERIFY を C VM に実装。
署名検証は Python コールバック方式を採用し、C VM がスタック操作・フロー制御を担当、
Python 側で encoding チェック・subscript 構築・verify_signature を実行する。

### アーキテクチャ

```
C VM (vm_step)
  ├── スタック操作 (sig/pub_key の pop, 結果の push)
  ├── NULLFAIL / NULLDUMMY チェック
  ├── CHECKSIGVERIFY / CHECKMULTISIGVERIFY 分岐
  └── PyObject_CallFunction(checksig_cb, ...)
         ↓
Python コールバック (checksig_cb クロージャ)
  ├── SIGHASH.validate()
  ├── deserialize_ecdsa_der() + Low-S チェック
  ├── PublicKey() encoding チェック
  ├── Script.from_chunks() + find_and_delete()
  └── verify_signature() → tx_preimage() → PublicKey.verify()
```

### コールバックの返り値プロトコル

| 値 | 意味 | C 側の動作 |
|---|---|---|
| 1 | 検証成功 | push TRUE |
| 0 | 検証失敗 (encoding OK) | push FALSE + NULLFAIL チェック |
| -1 | Invalid SIGHASH | vm_error("Invalid SIGHASH flag") |
| -3 | DER エラー or Low-S 違反 | vm_error("The signature format is invalid.") |
| -4 | 公開鍵 encoding エラー | vm_errorf("%s requires correct encoding...") |

### 設計判断

1. **コールバック方式を採用**: preimage 構築 (BIP-143/OTDA) + ECDSA 検証は Python/C 拡張で
   既に最適化済み (Phase 0-2)。subscript 構築 (Script.from_chunks, find_and_delete) は
   Script クラスの複雑なロジックに依存するため、C に再実装するよりコールバックが安全。

2. **Low-S の suppress(Exception) 動作をそのまま再現**: Python の check_signature_encoding は
   `with suppress(Exception):` 内で Low-S エラーを raise → suppress が catch → 最終的に
   "The signature format is invalid." になる。コールバックはこの動作を再現し -3 を返す。

3. **"Phase 3b" フォールバックを除去**: _validate_native() は常に checksig_cb を渡し、
   全 opcode を C VM が処理する。Python VM へのフォールバックは不要になった。

### 変更ファイル

| ファイル | 変更量 |
|---|---|
| `_bsv_native/bsv_native.c` | +200行 (CHECKSIG/CHECKMULTISIG ハンドラ), -5行 (スタブ削除) |
| `bsv/script/spend.py` | +20行 (checksig_cb), -8行 (Phase 3b フォールバック削除) |
| `docs/c-extension-plan.md` | ロードマップ更新 |

### テスト結果

全 5466 テスト合格、0 失敗。C VM が全 opcode (OP_CHECKSIG 含む) を処理し、
Python VM へのフォールバックなしで全テストベクタを通過。

### 発見した課題 (py-sdk 既存バグ)

Phase 3b の C 化で Python 実装を精密に分析した結果、以下のバグを発見した。
C 実装はテスト互換性のため全て Python の動作を忠実に再現している。

#### 1. CHECKMULTISIG ループ変数バグ (spend.py L718) — ✅ 修正済み (2026-07-01)

```python
# spend.py L714-722 (修正前)
if f_verify:
    i_sig += 1
    sigs_count -= 1    # ✅ 正しい: 検証成功時にsigs_countをデクリメント
i_key += 1
sigs_count -= 1        # ❌ バグ: keys_count -= 1 であるべき
if sigs_count > keys_count:
    f = False
```

**問題**: `sigs_count -= 1` (L718) は Bitcoin Core の `nKeysCount--` に相当すべき箇所。
`sigs_count` を二重にデクリメントしているため、ループが早期終了する。
2-of-3 マルチシグで1つ目のみ検証成功してもループが終了し `f=True` (成功) になる。
また `keys_count` が不変のため `sigs_count > keys_count` は常に False で、失敗パスに到達不能。

**Bitcoin Core 参照** (interpreter.cpp):
```cpp
if (fOk) { isig++; nSigsCount--; }
ikey++;
nKeysCount--;  // ← これが正しい
if (nSigsCount > nKeysCount) fSuccess = false;
```

**影響**: CHECKMULTISIG の検証が常に成功する。ただし BSV 上の標準 P2PKH 取引では
CHECKMULTISIG は使用されにくく、テストスイートで露出していない。

**修正内容** (2026-07-01):
- spend.py L718: `sigs_count -= 1` → `keys_count -= 1`
- bsv_native.c L3375: `loop_sigs -= 1` → `keys_count -= 1`
- テスト追加: CHECKMULTISIG 失敗パステスト4件 (test_scripts.py)
- 詳細調査報告: 本ファイル末尾参照

#### 2. check_signature_encoding の suppress(Exception) (spend.py L997)

```python
with suppress(Exception):
    _, s = deserialize_ecdsa_der(sig)
    if not self.is_relaxed() and REQUIRE_LOW_S_SIGNATURES and s > curve.n // 2:
        self.script_evaluation_error("The signature must have a low S value.")  # ← suppressed!
    return True
self.script_evaluation_error("The signature format is invalid.")  # ← この行が実行される
```

**問題**: Low-S 違反の `script_evaluation_error` は `RuntimeError` を raise するが、
`suppress(Exception)` に catch される。最終的に「format is invalid」エラーになる。
Low-S 固有のエラーメッセージが表面に出ない。

**テストの期待値** (`test_v1_rejects_high_s`): `match="signature format is invalid"` で、
suppress 後のメッセージを正しく期待している（テストは正しい）。

**対応**: C コールバックは -3 を返す (= "format is invalid")。Python の動作に一致。

#### 3. `$` プレフィックスの CHECKMULTISIG エラーメッセージ (spend.py L664)

```python
_m = f"${_codename} requires a key count between 0 and {MAX_MULTISIG_KEY_COUNT}."
# 出力: "$OP_CHECKMULTISIG requires a key count between 0 and 2147483647."
```

**問題**: JavaScript テンプレートリテラル `${...}` から Python f-string への移植時に
`$` が残留。Python f-string では `$` はリテラル文字。

**対応**: C は `vm_errorf(st, "$%s requires...", name)` で再現。

#### 4. CHECKMULTISIG の NULLFAIL 未実装

BSV node (interpreter.cpp L1638-1643) は CHECKMULTISIG の各署名ポップ時にも
`VerifyNullFail && EnforceNonMalleability` チェックを行うが、py-sdk にはこのチェックがない。
C 実装は py-sdk の動作に合わせ、このチェックを省略している。

#### 5. CHECKMULTISIG テストカバレッジの不足 — ✅ 対応済み (2026-07-01)

spend_vector.py の CHECKMULTISIG テストベクタは 0-key/0-sig の構造テストのみで、
実際の署名検証を伴う失敗パスのテストが存在しなかった。バグ #1 が長期間潜伏した原因。

**対応**: test_scripts.py に CHECKMULTISIG 失敗パステスト4件を追加:
- `test_bare_multisig_2of3_valid` — 正常系回帰テスト
- `test_bare_multisig_2of3_wrong_signer` — 外部キー混入 → 失敗
- `test_bare_multisig_2of2_wrong_signers` — 両方外部キー → 失敗
- `test_bare_multisig_1of3_insufficient` — 有効署名不足 → 失敗

#### 6. Spend クラスと Engine の二重実装 — 解決済み (2026-07-01)

py-sdk に2つの独立したスクリプトインタープリタが存在していた:
- `bsv/script/spend.py` の `Spend` クラス (TS-SDK ポート)
- `bsv/script/interpreter/` の `Engine`/`Thread` (Go-SDK ポート) — **削除済み**

**対応完了**:
1. `Transaction.verify()` を `Engine` → `Spend` に切替 (Phase 1)
2. Engine テストベクターの移植評価 → 移植不要と判定 (Phase 2)
3. `bsv/script/interpreter/` と `tests/bsv/script/interpreter/` を完全削除 (Phase 3)
   - ソース約2,700行、テスト約6,440行を削除
詳細は `docs/script-engine-consolidation.md` を参照。

### Phase 3b/3b+ への教訓

1. **`suppress(Exception)` の影響範囲**: Python コードの `suppress` ブロック内で `raise` する
   場合、意図しないエラーメッセージの隠蔽が起こりうる。C 化で全パスを明示的にたどることで
   初めてこの挙動に気づける。

2. **ループ変数の C トレース**: Python のインデント構造だけでは変数の役割を見誤りやすい。
   C に1行ずつ翻訳することで論理バグが浮き彫りになる。

3. **コールバック方式の有効性**: subscript 構築 (Script.from_chunks, find_and_delete) と
   verify_signature を Python に委任することで、Phase 3b を ~200行の C 追加で完了できた。
   完全 C 化 (Phase 3c) は subscript ロジックの再実装が必要で規模が大きい。
   コールバック方式は「まず動かす」段階として適切。

4. **OTDA Legacy の自然解決**: コールバック方式により、Python 側の verify_signature が
   SIGHASH.use_otda() ルーティングを透過的に処理。OTDA Legacy の C 再実装 (Phase 2c) は
   Phase 3c でのみ必要になった。

5. **クロス SDK 比較の価値**: BSV node / ts-sdk / py-sdk Engine の3つとの比較により、
   バグの確定と修正方針の確信度を高められた。TS からの移植コードは特に元 SDK との
   差分チェックが有効。

6. **失敗パステストの必要性**: CHECKMULTISIG のテストが成功パスのみだったことで
   バグが潜伏。暗号検証系は「正しく拒否する」テストが「正しく受理する」テストと
   同等以上に重要。

---

## CHECKMULTISIG ループ変数バグ — 詳細調査報告

**調査日**: 2026-06-30
**発端**: Phase 3b の C 化で spend.py L718 のバグを発見。ユーザー依頼により詳細調査を実施。

### 1. クロスリファレンス比較

4つの実装を比較し、py-sdk `Spend` クラスのみが誤りであることを確認した。

| 実装 | ファイル | 無条件デクリメント変数 | 判定 |
|------|---------|---------------------|------|
| BSV node v1.2.2 | `src/script/interpreter.cpp` L1624 | `nKeysCount--` | ✅ 正しい |
| ts-sdk | `src/script/Spend.ts` L1313 | `nKeysCount--` | ✅ 正しい |
| py-sdk Engine | `bsv/script/interpreter/operations.py` L1691 | `remaining_pubkeys -= 1` | ✅ 正しい |
| **py-sdk Spend** | **`bsv/script/spend.py` L718** | **`sigs_count -= 1`** | **❌ バグ** |
| C 拡張 | `_bsv_native/bsv_native.c` L3375 | `loop_sigs -= 1` | ❌ Python バグ再現 |

### 2. 正しいアルゴリズム（BSV node 参照実装）

```
初期状態: nSigsCount = M, nKeysCount = N (M-of-N multisig)

while (fSuccess && nSigsCount > 0):
    sig = stacktop(-isig)
    key = stacktop(-ikey)
    fOk = CheckSig(sig, key, subscript)

    if fOk:               # 署名が一致した場合のみ
        isig++             # 次の署名へ進む
        nSigsCount--       # 残り署名数をデクリメント

    ikey++                 # 常に次の鍵へ進む
    nKeysCount--           # 常に残り鍵数をデクリメント ← これが正しい

    if nSigsCount > nKeysCount:   # 早期失敗: 残り署名 > 残り鍵
        fSuccess = false
```

**核心**: 各イテレーションで「鍵を1つ消費した」ことを記録する。残り鍵数が
残り署名数を下回った時点で、照合不可能と判断して早期終了する。

### 3. py-sdk Spend クラスのバグ動作

```python
# spend.py L714-722（現行コード）
if f_verify:
    i_sig += 1
    sigs_count -= 1    # (A) 検証成功時: 残り署名をデクリメント
i_key += 1
sigs_count -= 1        # (B) ❌ バグ: sigs_count を二重デクリメント

if sigs_count > keys_count:   # keys_count は不変 → 常に False
    f = False
```

**二つの欠陥**:
1. **(B)** で `sigs_count` を二重にデクリメントしているため、ループが本来の半分の
   イテレーションで終了する
2. `keys_count` が一切デクリメントされないため、`sigs_count > keys_count` の
   早期失敗条件が機能しない

### 4. 影響分析 — トレーステーブル

#### ケース1: 2-of-3 正当な署名（sig0→key0 ✅, sig1→key1 ✅）

**正しい動作** (BSV node):
```
iter 1: sig0+key0 → OK, nSigsCount=1, nKeysCount=2  → 1≤2, 続行
iter 2: sig1+key1 → OK, nSigsCount=0, nKeysCount=1  → ループ終了
結果: fSuccess=true ✅
```

**バグ動作** (py-sdk Spend):
```
iter 1: sig0+key0 → OK, sigs_count=2→1(A)→0(B), keys_count=3(不変)
→ ループ終了 (sigs_count=0)
結果: f=true ✅ (見かけ上正しいが、sig1 は未検証)
```
sig1 が無効でも成功する。**1つの有効な署名だけで 2-of-3 が通る。**

#### ケース2: 2-of-3 不正な署名（sig0→key0 ❌, sig1→key1 ?）

**正しい動作** (BSV node):
```
iter 1: sig0+key0 → FAIL, nSigsCount=2, nKeysCount=2  → 2≤2, 続行
iter 2: sig0+key1 → OK,   nSigsCount=1, nKeysCount=1  → 1≤1, 続行
iter 3: sig1+key2 → OK,   nSigsCount=0, nKeysCount=0  → ループ終了
結果: fSuccess=true ✅
```

**バグ動作** (py-sdk Spend):
```
iter 1: sig0+key0 → FAIL, sigs_count=2→1(B), keys_count=3(不変)
→ 1≤3, 続行
iter 2: sig0+key1 → OK,   sigs_count=1→0(A)→-1(B), keys_count=3(不変)
→ ループ終了 (sigs_count≤0)
結果: f=true ✅ (sigs_count=-1 だがループ条件は > 0)
```
sig1 は完全に未検証。**全ての署名が未検証でもパスしうる。**

#### ケース3: 2-of-2 両方不正（sig0→key0 ❌, sig1→key1 ❌）

**正しい動作** (BSV node):
```
iter 1: sig0+key0 → FAIL, nSigsCount=2, nKeysCount=1 → 2>1
結果: fSuccess=false ❌
```

**バグ動作** (py-sdk Spend):
```
iter 1: sig0+key0 → FAIL, sigs_count=2→1(B), keys_count=2(不変)
→ 1≤2, 続行
iter 2: sig0+key1 → FAIL, sigs_count=1→0(B), keys_count=2(不変)
→ ループ終了 (sigs_count=0)
結果: f=true ✅ ← 署名が一つも合っていないのに成功
```
**最も深刻なケース**: 2-of-2 で両方の署名が無効でも成功する。

### 5. 実際の影響度

**軽減要因**:
- BSV 上で最も一般的なスクリプトは P2PKH (OP_CHECKSIG)。CHECKMULTISIG は比較的少ない
- `Transaction.verify()` は `Spend` に切替済み (2026-07-01)。旧実装は `Engine` (Go-SDK ポート) で正しい実装
  (`operations.py` の `remaining_pubkeys -= 1`)
- `Spend.validate()` は主にユニットテスト/直接呼び出しで使用

**リスク**:
- `Spend` クラスは `BareMultisig` テンプレートの `unlock()` メソッドから利用可能
- マルチシグの署名検証を `Spend.validate()` 経由で行うアプリケーションは、
  無効な署名を受け入れてしまう
- C 拡張 (`_bsv_native`) は `Spend._validate_native()` から呼ばれるため、
  C 化後も同じバグが継続する

### 6. テストカバレッジのギャップ

現在の CHECKMULTISIG テスト:
- `spend_vector.py`: 0-key/0-sig の構造テストのみ（署名検証なし）
- `test_scripts.py::test_bare_multisig`: ロッキングスクリプト構築テスト（検証なし）
- `test_chronicle_malleability.py`: `is_relaxed()` ゲーティングテスト
- **失敗パスのテストが一切ない** — 無効な署名で CHECKMULTISIG が失敗することを
  検証するテストが存在しない

### 7. 修正方針

#### Step 1: py-sdk Spend クラスの修正

```python
# spend.py L718: sigs_count -= 1 → keys_count -= 1
if f_verify:
    i_sig += 1
    sigs_count -= 1
i_key += 1
keys_count -= 1        # ← 修正
if sigs_count > keys_count:
    f = False
```

#### Step 2: C 拡張の修正

```c
// bsv_native.c L3374-3375: loop_sigs -= 1 → keys_count -= 1
if (rv > 0) {
    loop_i_sig += 1;
    loop_sigs -= 1;
}
loop_i_key += 1;
keys_count -= 1;       // ← 修正

if (loop_sigs > keys_count)   // ← loop_sigs (残り署名数) > keys_count (残り鍵数)
    f = 0;
```

#### Step 3: テスト追加

以下の失敗パステストを追加する:
1. 2-of-3 で無効な署名1つ → 失敗すること
2. 2-of-2 で両方無効 → 失敗すること
3. 2-of-3 で有効1つ + 無効1つ → 失敗すること (1-of-3 では不足)
4. 正常系: 2-of-3 で有効2つ → 成功すること（回帰テスト）

### 8. NULLFAIL 未実装について

BSV node の CHECKMULTISIG は cleanup ループ内で NULLFAIL チェックを行う
(`!fSuccess && VerifyNullFail(flags) && !ikey2 && !vchSig.empty()`)。
py-sdk Spend クラスにはこのチェックがない。ただし:
- Chronicle tx_version > 1 では `EnforceNonMalleability` が無効化される
- NULLFAIL は主にマリアビリティ対策であり、セキュリティ上の影響は限定的
- 修正優先度はループ変数バグより低い
