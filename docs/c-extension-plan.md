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
Phase 1 ─── Tx パース / シリアライズ / Script チャンク / MerklePath  ← 次
  │           → BEEF SPV検証フロー全体がC化
  │
Phase 2 ─── Preimage 構築
  │           → 署名パイプライン全体がC化
  │
Phase 3 ─── スクリプト VM
  │           → トランザクション検証全体がC化（OP_CHECKSIG が C内で完結）
  │
Phase 4 ─── BRC-42 鍵導出最適化 + libsecp256k1 活用拡大
              → 認証・ウォレット操作の最適化
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

- [ ] 既存テストスイート全体が 3モード全てで通る
- [ ] 等価性テスト: 全C関数が対応するPython実装と同一出力
- [ ] ファズテスト: 10万件のランダム入力でクラッシュなし
- [ ] メモリリークテスト: 10万回反復で 1MB 以内

### 想定期間: 3〜4週間

---

## Phase 2: Preimage 構築

**目的:** 署名ハッシュ構築をC化し、署名パイプライン全体を高速化する。

### 対象ファイル

- `bsv/transaction_preimage.py` — `tx_preimage()` (L195-236), `tx_preimages()` (L57-96), `_preimage_otda()` (L138-177)
- `bsv/transaction.py` — `calc_input_signature_hash()` (L106-147)

### 問題

BIP143 preimage構築は、入力ごとに `bytes.fromhex()` → `[::-1]` → `.to_bytes()` → `b"".join()` の
Python中間オブジェクト生成を繰り返す。OTDA (Chronicle) パスも同様の BytesIO + `.write()` 連打。

### タスク

| #   | タスク                                                                            | C関数                    |
| --- | --------------------------------------------------------------------------------- | ------------------------ |
| 2.1 | BIP143 preimage 一括構築                                                          | `bsv_tx_preimages()`     |
| 2.2 | OTDA preimage (Chronicle)                                                         | `bsv_tx_preimage_otda()` |
| 2.3 | Phase 1 との結合 (deserialize → preimage → hash256 一体化)                        | —                        |
| 2.4 | Python側ディスパッチ差し替え（既存Python実装は保存）                              | —                        |
| 2.5 | テスト: SIGHASH全パターン (ALL, NONE, SINGLE × ANYONECANPAY × FORKID × CHRONICLE) | —                        |

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
  → tx_preimages()            ── Phase 2
  → hash256(preimage)         ── Phase 0
  → secp256k1_ecdsa_sign()    ── Phase 0 (libsecp256k1 直接)
```

### 想定期間: 2〜3週間

---

## Phase 3: スクリプト VM

**目的:** スクリプト検証をC化。libsecp256k1 統合済みなので OP_CHECKSIG が C内で完結する。

### 対象ファイル

- `bsv/script/spend.py` — 1004行、`Spend` クラス全体

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
Phase 3a: コア opcodes (~30個)
  ├── スタック操作 (OP_DUP, OP_DROP, OP_SWAP, OP_ROT 等)
  ├── 比較・論理 (OP_EQUAL, OP_VERIFY, OP_IF/ELSE/ENDIF)
  ├── 算術 (OP_ADD, OP_SUB, OP_NUMEQUAL 等)
  └── ハッシュ (OP_SHA256, OP_HASH160, OP_HASH256, OP_RIPEMD160)

Phase 3b: 署名検証
  ├── OP_CHECKSIG / OP_CHECKSIGVERIFY
  ├── OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
  └── preimage構築 → secp256k1_ecdsa_verify を C内で直接呼び出し

Phase 3c: ビット演算 + Chronicle opcodes
  ├── OP_AND, OP_OR, OP_XOR, OP_INVERT
  ├── OP_SUBSTR, OP_LEFT, OP_RIGHT
  ├── OP_LSHIFTNUM, OP_RSHIFTNUM
  └── OP_2MUL, OP_2DIV, OP_VER, OP_VERIF, OP_VERNOTIF
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

### 想定期間: 2〜3週間

---

## タイムライン

```
       ✅ 完了         ← 次          Week 3-5       Week 6-11      Week 12-14
       ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌───────────┐  ┌─────────┐
       │ Phase 0    │  │ Phase 1    │  │ Phase 2  │  │ Phase 3   │  │ Phase 4 │
       │ 基盤構築   │  │ Tx/Script  │  │ Preimage │  │ Script VM │  │ 鍵導出  │
       │ libsecp統合 │  │ MerklePath │  │          │  │ (3段階)   │  │ secp活用│
       │ coincurve  │  │ + CI/wheel │  │          │  │           │  │         │
       │ 置換       │  │            │  │          │  │           │  │         │
       └──────┬─────┘  └─────┬──────┘  └────┬─────┘  └─────┬─────┘  └────┬────┘
              ▼              ▼              ▼               ▼              ▼
         ✅ 完了          v2.2.0        v2.3.0        v2.4.0-2.5.0     v2.6.0
```

| Phase | 期間     | 状態     | 主な成果                                                       |
| ----- | -------- | -------- | -------------------------------------------------------------- |
| **0** | 3〜4週間 | ✅ 完了  | libsecp256k1 統合、coincurve フォールバック化、SHA256 埋め込み |
| **1** | 3〜4週間 | ← **次** | BEEF SPV検証 40x高速化 + CI/wheel 構築 (0E含む)                |
| **2** | 2〜3週間 | 未着手   | 署名パイプライン 15〜60x高速化                                 |
| **3** | 4〜6週間 | 未着手   | スクリプト検証 25〜100x高速化 (OP_CHECKSIG C内完結)            |
| **4** | 2〜3週間 | 未着手   | 鍵導出 4〜20x高速化 + セキュリティ改善                         |

**合計: 約 14〜20週間** (3.5〜5ヶ月)
**進捗: Phase 0 完了 (2026-06-30)、残り約 12〜16週間**

---

## リリース戦略

| バージョン | Phase | 変更点                                         | coincurve の扱い             |
| ---------- | ----- | ---------------------------------------------- | ---------------------------- |
| **v2.2.0** | 0+1   | `_bsv_native` 導入、Tx パース / SPV検証 高速化 | フォールバックとして残留     |
| **v2.3.0** | 2     | 署名パイプライン高速化                         | optional dependency に格下げ |
| **v2.4.0** | 3a+3b | スクリプトVM (コア + 署名検証)                 | optional (非推奨)            |
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
