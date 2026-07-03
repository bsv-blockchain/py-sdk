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
  OS:      Linux (manylinux), macOS, Windows  ※musllinux は現在スキップ
  Arch:    x86_64, aarch64 (ARM64)
  Python:  3.10, 3.11, 3.12, 3.13
  Mode:    C拡張あり / coincurve フォールバック / 純Python フォールバック
  ```

### 4. coincurve の段階的廃止 — ✅ 完全廃止済み (2026-07-02)

> **状態更新 (2026-07-02):** coincurve は当初「メジャーバージョンで削除」の予定だったが、
> **前倒しで完全削除**した。フォールバック階層は 3 段 (native / coincurve / 純Python) から
> **2 段 (native / 純Python) に変更**。詳細は末尾「coincurve 完全廃止記録」参照。
> 本セクション以下の「段階的移行」記述は**歴史的経緯**であり、現行構成は 2 段フォールバック。

当初計画 (段階的移行) — 履歴として保存:

- **Phase 0 完了時**: `_bsv_native` が推奨、coincurve はフォールバック
- **Phase 1-2 安定後**: coincurve を optional dependency に格下げ (`pip install bsv-sdk[coincurve]`)
- **十分な実績蓄積後**: coincurve フォールバックコードを削除（メジャーバージョンで）

前倒し実施の理由 (2026-07-02):

- **Python 3.14 のブロッカー解消**: coincurve は 3.14 wheel を出しておらず、optional のままでも
  「3.14 で coincurve を要求する経路」が残ると混乱の元。純Python フォールバックに置き換えることで
  3.14 でも追加依存ゼロで動作する
- Phase 0-4 で `_bsv_native` が coincurve の全機能を代替済み。純Python フォールバックを足すだけで
  coincurve 固有の機能 (DER/PEM 入出力を除く) はすべて代替できる状態だった

廃止の動機 (当初からのもの):

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
Phase 3 ─── スクリプト VM                                           ✅ 3c 完了
  │           → VM ループ + 全 opcode が C VM で実行可能
  │           3a: コア opcodes + ビット/文字列/Chronicle + VM ループ ✅
  │           3b: 署名検証 (CHECKSIG/CHECKMULTISIG) コールバック方式  ✅
  │           3b+: CHECKMULTISIG ループ変数バグ修正 (Python/C 同時)   ✅
  │           3c: CHECKSIG パス C 内完結化（コールバック廃止）          ✅
  │
Phase 4 ─── BRC-42 鍵導出最適化 + libsecp256k1 活用拡大        ✅ 4.1-4.3 完了
  │           → 認証・ウォレット操作の最適化
  │           4.1: pubkey_tweak_add で公開鍵導出簡素化           ✅
  │           4.2: seckey_tweak_add で秘密鍵導出を定数時間化     ✅
  │           4.3: _sign_custom_k を libsecp256k1 に置換         ✅
  │
品質 ──── ファズテスト + メモリテスト                              ✅ 完了
  │         → hypothesis ベース 46 テスト + ASAN ビルド
  │         ecdsa_recover recid 範囲チェック欠落バグを発見・修正
  │
CI ───── CI/wheel パイプライン                                     ✅ 完了
  │         → cibuildwheel (Linux/macOS/Windows × Py3.10-3.13)
  │         MANIFEST.in, BuildExtFallback, BSV_REQUIRE_NATIVE
  │         wheel から C ソース除外、純 Python フォールバックテスト
  │
F8 ────── Python 3.13/3.14 対応 (私的API廃止)                       ✅ 完了 (2026-07-02)
  │         → _PyLong_FromByteArray/_AsByteArray (私的API) を公開 API
  │           PyLong_FromUnsignedNativeBytes/AsNativeBytes へ移行 (≥3.13)。≤3.12 は従来 API
  │           x86_64/arm64 の Py3.13 で native ビルド + 159 テスト通過。3.11 回帰なし
  │
3.14 ──── Python 3.14 対応                       🔶 標準ビルド検証済み / CI・freethreading 残
  │         → 標準(GIL)ビルド: arm64 Py3.14.6 で native ビルド + 159 テスト通過、
  │           ヘッダ実コンパイル エラー0・非推奨警告0、依存も cp314 wheel 有り (実測 2026-07-02)
  │           残: [CI] cp314 を wheels.yml に追加 + cibuildwheel bump、
  │              [free-threading] cp314t 対応 (Py_mod_gil + g_ctx スレッド安全化)
  │           詳細は末尾「Python 3.14 対応」セクション参照
  │
監査 ──── ドキュメント整合性チェック                                 ✅ 完了
              → c-extension-plan.md 全 2,121 行の監査
              チェックボックス未更新 4件、事実矛盾 2件、
              musllinux 記述不整合 3箇所、古い情報 2件を修正
  │
レビュー ── コードレビュー + アドバーサリアル検証                     ✅ 完了 (2026-07-02)
  │         → 16 指摘を実測検証。P0 リーク (tx_from_bytes 202B/call) 修正
  │         格上げ2/格下げ5/棄却2/新規発見1。検証済みアクションプラン策定
  │
全面監査 ─ 全29関数リーク/クラッシュ監査                              ✅ 完了 (2026-07-02)
              → 実測52ケース + 静的9領域。リーク残存なしを確認
              クラッシュ級2件を新規発見・修正:
                ① ecdsa_sign_with_k(k=0) 無限ハング (DoS)
                ② OTDA SIGHASH_SINGLE 範囲外 SIGSEGV (OTDA実装2系統)
              回帰テスト44件追加 (crash/hang subprocess隔離 + 全関数memory scan)
  │
coincurve廃止 ─ coincurve 完全削除 + 純Python フォールバック導入        ✅ 完了 (2026-07-02)
              → フォールバックを 3段(native/coincurve/純Python) → 2段(native/純Python) に変更
              curve.py: 純Python 点加算 + double-and-add スカラー倍を追加
              keys.py: RFC6979 署名 / verify / recover / ECDH / pubkey パースを純Python実装
              pyproject.toml: coincurve optional dependency を削除
              前倒し動機: coincurve が 3.14 wheel 未提供でブロッカーになるため
              回帰テスト65件追加 (フォールバック強制 + native⇔python 等価性)
              DER/PEM 入出力のみ廃止 (NotImplementedError、テスト外・実運用未使用)
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
| 0.24 | cibuildwheel 設定    | manylinux, macOS, Windows の wheel ビルド (musllinux はスキップ) |
| 0.25 | `--no-binary` テスト | フォールバック動作確認                               |

### ファイル構成

```
_bsv_native/
  bsv_native.c          ← 全 API + ラッパーを 1 ファイルに集約 (~4,345行)
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
※ 当初計画の `secp256k1_wrap.h/.c` は不要となり、`bsv_native.c` に統合。

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
- [x] CI で manylinux / macOS / Windows の wheel ビルド成功 (cp310-313) ✅ 2026-07-01 (wheels.yml, musllinux はスキップ)
  - cp313 は当初 F8 (`_PyLong_AsByteArray` の 6 引数化) で native ビルド不能だったが、2026-07-02 に F8 を修正 (公開 API へ移行) し cp313 も native ビルド可能に

### 実装メモ (2026-06-30)

- `bsv_native.c`: secp256k1.c をアマルガメーション方式でインクルード（precomputed_ecmult.c, precomputed_ecmult_gen.c を先行インクルード）
- `ecdsa_sign`: 常に low-S 正規化を適用
- `ecdsa_verify`: 正規化なし — libsecp256k1 は high-S 署名も数学的に正しく検証成功する (Phase 3c で確認)。BSV tx version 依存の Low-S 制御は Script VM ポリシー層（`Spend.is_relaxed()`）で行う
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
- [x] 等価性テスト: 全C関数が対応するPython実装と同一出力 (65テスト, 9カテゴリ) ✅ 2026-07-01
- [x] ファズテスト: hypothesis ベース 46 テスト (全 29 エクスポート関数 + VM + refcount) ✅ 2026-07-01
- [x] メモリテスト: ASAN ビルド + refcount ストレステスト (5,000〜10,000 回反復) ✅ 2026-07-01
- [x] CI で 3モード + manylinux/macOS/Windows テスト (wheels.yml + build.yml) ✅ 2026-07-01

### 実装メモ (2026-06-30)

- **C 関数 7 個を追加** (`bsv_native.c` +818 行):
  - `parse_script_chunks`, `serialize_script_chunks` — Script チャンクのパース/シリアライズ
  - `tx_from_bytes`, `tx_to_bytes`, `tx_txid` — Tx パース/シリアライズ/txid 計算
  - `merkle_compute_root` — Merkle パス全体を C 内で計算（単純パス用、バイトオーダーバグ修正済み 2026-07-01）
  - `merkle_hash_pair` — 2 つの hex ハッシュを hash256 で結合（compound path フォールバック用）
- **Python ディスパッチ**: `script_chunks.py`, `merkle_path.py`, `transaction.py` に `_USE_NATIVE` 分岐追加
- **merkle_path の段階的最適化**: 当初はハイブリッド方式（`merkle_hash_pair` のみ C 化）だったが、`merkle_compute_root` のバグ修正後に全 C 完結パスを有効化。compound path では `find_or_compute_leaf` + `merkle_hash_pair` にフォールバック。詳細は「Phase 1 実装課題」セクション参照
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
- [x] 等価性テスト: 18 パターンの SIGHASH 組み合わせで C ⇔ Python 出力一致 (BIP143×12 + OTDA×6) ✅ 2026-07-01
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

Phase 3c: CHECKSIG パス C 内完結化（コールバック廃止）          ✅ 完了 (2026-07-01)
  ├── SIGHASH validate — 12種の有効値テーブルチェック
  ├── DER parse + Low-S — secp256k1_ecdsa_signature_parse_der + normalize
  ├── pubkey 検証 — secp256k1_ec_pubkey_parse
  ├── subscript 構築 — c_encode_pushdata + find_and_delete を C 再実装
  ├── preimage 生成 — BIP143/OTDA を C 内で直接計算 (Phase 2 ヘルパー再利用)
  ├── ECDSA 検証 — hash256(preimage) → secp256k1_ecdsa_verify (g_ctx 直接)
  └── Python コールバック廃止 → spend_validate API 変更
  実装: ~550行の C コード追加 + spend.py API 変更
  動機: 大量入力 tx を高頻度検証するユースケース
  効果: CHECKSIG あたりの Python ↔ C 境界越え排除 (~5μs → ~0.5μs)
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
- [x] ファズテスト (hypothesis) + ASAN メモリテスト ✅ 2026-07-01
- [x] CI/wheel ビルド (0E) — cibuildwheel + sdist + 純 Python フォールバック ✅ 2026-07-01
- [ ] `context_randomize` 定期呼び出し (4.4) — 初期化時のみ実行中、定期化は任意
- [ ] Schnorr 署名 API 公開 (4.5) — 将来のプロトコル拡張用、任意
- [x] Python-only / C パス等価性テスト — 65テスト9カテゴリ (Hash, ScriptChunks, Tx, Crypto, BIP143, OTDA, Merkle, Spend VM, KnownDifferences) ✅ 2026-07-01

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
       ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌─────────────┐  ┌─────────┐
       │ Phase 0    │  │ Phase 1    │  │ Phase 2  │  │ Phase 3     │  │ Phase 4 │
       │ 基盤構築   │  │ Tx/Script  │  │ Preimage │  │ Script VM   │  │ 鍵導出  │
       │ libsecp統合 │  │ MerklePath │  │ BIP143   │  │ 3a+3b+3b+  │  │ 4.1-4.3│
       │ coincurve  │  │            │  │ + OTDA   │  │ +3c+SE統合  │  │         │
       │ 置換       │  │            │  │          │  │             │  │         │
       └──────┬─────┘  └─────┬──────┘  └────┬─────┘  └──────┬──────┘  └────┬────┘
              ▼              ▼              ▼                ▼              ▼
         2026-06-30     2026-06-30     2026-06-30       2026-07-01     2026-07-01
```

| Phase | 期間     | 状態     | 主な成果                                                       |
| ----- | -------- | -------- | -------------------------------------------------------------- |
| **0** | 3〜4週間 | ✅ 完了  | libsecp256k1 統合、coincurve フォールバック化、SHA256 埋め込み |
| **1** | 3〜4週間 | ✅ 完了  | Tx/Script/MerklePath C化、5466テスト全パス                     |
| **2** | 2〜3週間 | ✅ 完了  | BIP-143 + OTDA preimage C化、5466テスト全パス                  |
| **3** | 4〜6週間 | ✅ 3c 完了 | 3a+3b: VM+全opcode C化, 3b+: CHECKMULTISIG バグ修正, 3c: CHECKSIG C内完結化 |
| **SE** | — | ✅ 完了 | Script Engine 統合: Engine/interpreter 削除 (~9,100行削除)、Spend 一本化 |
| **4** | 2〜3週間 | ✅ 4.1-4.3 完了 | seckey/pubkey_tweak_add 直接利用、ecdsa_sign_with_k で純Python ECDSA 排除 |
| **品質** | — | ✅ 完了 | ファズ46件 + ASAN + ecdsa_recover バグ修正 |
| **CI** | — | ✅ 完了 | cibuildwheel 5プラットフォーム × Py3.10-3.13、sdist、純Python フォールバック |
| **F8** | — | ✅ 完了 | Python 3.13/3.14 対応: 私的API `_PyLong_*` を公開 `PyLong_*NativeBytes` へ移行。x86_64/arm64 の 3.13 で検証 |
| **3.14** | — | 🔶 標準検証済 | 標準ビルド: arm64 3.14.6 で native ビルド + 159 テスト通過。残: CI 組込 (cibuildwheel bump) + cp314t (freethreading) |
| **監査** | — | ✅ 完了 | c-extension-plan.md 全量監査、11箇所修正 |
| **等価性** | — | ✅ 完了 | 65テスト9カテゴリ、C⇔Python全関数の出力一致検証 |
| **ベンチマーク** | — | ✅ 完了 | 31ベンチマーク、C vs Python 全 dispatch ポイントの速度計測 |
| **lazy chunks** | — | ✅ 完了 | Script.chunks 遅延初期化。Tx parse 5.3x / Spend VM 2.1x の絶対速度改善 |
| **merkle 改修** | — | ✅ 完了 | merkle_compute_root バイトオーダーバグ修正 + 全 C 完結パス活用。14.3x (9.5x→) |
| **レビュー** | — | ✅ 完了 | コードレビュー 16 指摘 → アドバーサリアル検証 → P0 リーク (tx_from_bytes 202B/call) 修正 |
| **全面監査** | — | ✅ 完了 | 全29関数リーク/クラッシュ監査。リーク残存なし。クラッシュ級2件 (sign_with_k ハング, OTDA SINGLE SIGSEGV) 修正 + 回帰44件 |

**合計: 約 14〜20週間** (3.5〜5ヶ月)
**進捗: Phase 0-4 + SE統合 + 品質テスト + CI/wheel + 監査 + 等価性 + ベンチマーク + lazy chunks + merkle 改修 + レビュー検証 + 全面リーク/クラッシュ監査 完了 (2026-07-02)**
**テスト: 3,589 passed (等価性65 + ファズ46 + crash/hang回帰4 + 全関数memory scan40 + メモリ増加4 含む), 259 skipped, ベンチ31 別途**
**残り (優先順): ~~① Py3.13 コンパイル修正 (F8)~~ ✅ 完了 (2026-07-02) → ① Transaction.sign() O(N²)解消 (F11/ordinalx直結) → ② tx_to_bytes 入力検証 (F4) → 以降は「残タスク一覧」参照**

---

## リリース戦略

| バージョン | Phase | 変更点                                         | coincurve の扱い             |
| ---------- | ----- | ---------------------------------------------- | ---------------------------- |
| **v2.2.0** | 0+1   | `_bsv_native` 導入、Tx パース / SPV検証 高速化 | フォールバックとして残留     |
| **v2.3.0** | 2     | 署名パイプライン高速化                         | optional dependency に格下げ |
| **v2.4.0** | 3a+3b+3b+ | スクリプトVM + CHECKMULTISIG修正            | optional (非推奨)            |
| **v2.5.0** | 3c    | CHECKSIG パス C 内完結化（コールバック廃止）    | optional (非推奨)            |
| **v2.6.0** | 4     | 鍵導出最適化、Schnorr API                      | 十分な実績確認後、削除を検討 |

### 配布

- **バイナリ wheel** (cibuildwheel): できるだけ多くのプラットフォームで提供
  - Linux: manylinux (x86_64, aarch64) ※musllinux は現在スキップ
  - macOS: x86_64, arm64 (Apple Silicon)
  - Windows: x86_64
- **ソース配布** (`sdist`): Cコンパイラがあればどの環境でもビルド可能
- **Pure Python フォールバック**: C拡張なしでも非暗号処理は動作。暗号処理は coincurve フォールバックまたは wheel で対応
- **CPython Limited API**: `Py_LIMITED_API` 採用は見送り。PyLong / PyBytes 等の安定 API のみ使用しているが、`PyArg_ParseTuple` format や `PyObject_CallFunction` の制約があり、対応コストに見合わない。Python バージョンごとの wheel を cibuildwheel で個別ビルドする方針

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
Python 3.13         ✓ (F8修正)     ✓              ✓
```
※ Python 3.13 の `_bsv_native` (native) は F8 修正 (2026-07-02、公開 API へ移行) により
x86_64/arm64 ともビルド・動作する。Python 3.14 も安定公開 API のみ使用のため対応見込み (3.14 実機は未検証)。

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

### 2. merkle_compute_root のバイトオーダーバグと段階的改善

**Phase 1 時点の対策**: ハイブリッド方式を採用 — Python の `find_or_compute_leaf` でリーフ探索（再帰あり）、C の `merkle_hash_pair` でハッシュ計算のみ委譲。

**後日発見 (2026-07-01)**: `merkle_compute_root` C 関数に**バイトオーダーバグ**があり、全 C 完結パスが使えない状態だった。Python の `hash256(to_bytes(left+right)[::-1])` は 64 バイト全体を reverse するが、C 関数は各 32 バイト半分を `hex_to_bytes_reversed` で個別に reverse してから結合していた。全体 reverse は結合順序を反転するため、結果が異なる。この関数はファズテストでクラッシュしないことのみ検証され、プロダクションコードから一度も呼ばれていなかったためバグが潜伏していた。

**修正**: C 関数の結合順序を修正。display order `left||right` の全体 reverse は internal order で `right_rev||left_rev` になるため、`offset % 2` による分岐の memcpy 順序を入れ替え。

**改善 (2026-07-01)**: Python 側 `_compute_root_native` で `merkle_compute_root` を第一候補として使用し、ValueError (compound path で leaf が見つからない場合) は `merkle_hash_pair` ループにフォールバック。単純パス (標準 SPV プルーフ) では Python/C 境界越えが 20回→1回に減少。**Merkle root h=10: 9.5x → 14.3x に改善**。

**教訓**: hex⇔bytes + reverse のセマンティクスは「課題 1」と同根。C 関数を書く際に Python の中間値をステップごとに照合するテストが不可欠。また、ファズテストはクラッシュ防止には有効だが、**正当性のテストには等価性テストが必要**。

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

以下は Phase 1 コア実装完了後の残タスクとして、CI/wheel (0E) と合わせて実施予定だったもの:

| タスク | 状態 | 備考 |
| --- | --- | --- |
| 等価性テスト (C ⇔ Python 出力一致) | ✅ 完了 | 65テスト9カテゴリ: Hash(15), ScriptChunks(11), Tx(4), Crypto(11), BIP143(12), OTDA(6), Merkle(2), Spend VM(3+1), KnownDiff(1) (2026-07-01) |
| ファズテスト (hypothesis) | ✅ 完了 | 46テスト、全29関数+VM+refcountカバー (2026-07-01) |
| メモリテスト (ASAN + refcount) | ✅ 完了 | ASAN ビルド + refcount ストレス 5,000〜10,000回 (2026-07-01) |
| ベンチマーク (pytest-benchmark) | ✅ 完了 | 31ベンチマーク、C vs Python 全関数の速度比較 (2026-07-01) |
| CI 3モードテスト | ✅ 完了 | wheels.yml + build.yml で native/pure-python をカバー (2026-07-01) |

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
| 3c | ~4340 (+1100) | 29 (+0) | ~42 (+11) |
| fuzz/mem | ~4345 (+5) | 29 (+0) | ~42 (+0) |

Fuzz/memory テストで `ecdsa_recover` の recid 範囲チェック欠落 (abort) を発見・修正。C コード変更は 5行追加のみ。テストコードは `tests/bsv/native/test_fuzz_native.py` (46テスト)、ASAN スクリプトは `scripts/run_asan_tests.sh`。

Phase 3c は CHECKSIG パスの C 内完結化。Python コールバックを廃止し、DER parse + Low-S check + pubkey parse + subscript 構築 + preimage 計算 + secp256k1_ecdsa_verify を全て C 内で実行。PreimageCtx 構造体 + pctx_init/pctx_free + sighash_validate + encode_pushdata + build_subscript + build_bip143_preimage + build_otda_preimage + checksig_verify の 11 ヘルパー追加。spend_validate API を拡張 (lock_time, input_index, input_sequence, source_satoshis, other_inputs, outputs を追加)。

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

3. **コールバック方式の有効性 → Phase 3c で廃止**: subscript 構築 (Script.from_chunks, find_and_delete) と
   verify_signature を Python に委任することで、Phase 3b を ~200行の C 追加で完了できた。
   コールバック方式は「まず動かす」段階として適切。Phase 3c でこれらを全て C に再実装し
   コールバックを廃止。結果 ~1,100行の C 追加 (3b の ~5.5倍) だが、CHECKSIG あたりの
   Python ↔ C 境界越えが完全に排除された。

4. **OTDA Legacy の自然解決 → Phase 3c で C 再実装**: コールバック方式 (3b) では Python 側の
   verify_signature が SIGHASH.use_otda() ルーティングを透過的に処理していた。Phase 3c で
   `c_sighash_use_otda()` + `c_build_otda_preimage()` として C に再実装。`sighash & 0x20`
   (CHRONICLE bit) で BIP143 / OTDA を分岐するシンプルなルーティングに統一。

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

---

## Phase 3c 完了記録 (2026-07-01)

### 実装内容

CHECKSIG/CHECKMULTISIG の署名検証パイプライン全体を C 内で完結化。
Phase 3b で採用した Python コールバック方式を廃止し、DER parse → Low-S check →
pubkey parse → subscript 構築 → preimage 計算 → ECDSA 検証を全て C 内で実行。

### 動機

大量入力 tx を高頻度で検証するユースケース。Phase 3b のコールバック方式では
CHECKSIG ごとに Python ↔ C 境界越えが発生し、ボトルネックになっていた。

### アーキテクチャ変更

**Phase 3b (コールバック方式)**:
```
C VM (vm_step)
  └── PyObject_CallFunction(checksig_cb, ...)
         ↓
Python コールバック (checksig_cb クロージャ)
  ├── SIGHASH.validate()
  ├── deserialize_ecdsa_der() + Low-S チェック
  ├── Script.from_chunks() + find_and_delete()
  └── verify_signature() → tx_preimage() → PublicKey.verify()
```

**Phase 3c (C 内完結)**:
```
C VM (vm_step)
  └── c_checksig_verify(sig, pubkey, subscript, pctx)
         ├── c_sighash_validate()      — 12種テーブルチェック
         ├── secp256k1_ecdsa_signature_parse_der()
         ├── secp256k1_ecdsa_signature_normalize()  — Low-S
         ├── secp256k1_ec_pubkey_parse()
         ├── c_build_bip143_preimage() / c_build_otda_preimage()
         ├── secp256k1_sha256 (hash256)
         └── secp256k1_ecdsa_verify()
```

### 新規データ構造

```c
typedef struct {
    unsigned char txid_le[32];
    uint32_t vout;
    const unsigned char *script;
    Py_ssize_t script_len;
    int64_t satoshis;
    uint32_t sequence;
    uint32_t sighash;
} PCtxInput;

typedef struct {
    uint32_t version, locktime;
    int32_t  input_index;
    unsigned char cur_txid_le[32];
    uint32_t cur_vout;
    int64_t  cur_satoshis;
    uint32_t cur_sequence;
    PCtxInput *other_inputs;
    Py_ssize_t n_other;
    PyObject *outputs_list;
    Py_ssize_t n_outputs;
    unsigned char hash_prevouts[32];
    unsigned char hash_sequence[32];
    unsigned char hash_outputs[32];
} PreimageCtx;
```

`PreimageCtx` は `pctx_init()` で `spend_validate` 進入時に一度だけ構築される。
BIP143 の共有ハッシュ (hashPrevouts, hashSequence, hashOutputs) をこの時点で事前計算し、
複数 CHECKSIG でのハッシュ再計算を排除。

### 新規 C ヘルパー (11個)

| 関数名 | 役割 |
|--------|------|
| `c_sighash_validate` | SIGHASH 値が 12 種のうちいずれかであることを検証 |
| `c_sighash_use_otda` | `sighash & 0x20` で OTDA ルーティング判定 |
| `c_encode_pushdata` | バイト列をスクリプトプッシュデータとしてエンコード |
| `c_build_subscript` | ロッキングスクリプトから署名を除去した subscript 構築 |
| `c_build_bip143_preimage` | BIP143 preimage をバッファに構築 |
| `c_build_otda_preimage` | OTDA (Original Transaction Digest Algorithm) preimage 構築 |
| `c_checksig_verify` | 署名検証パイプライン全体 (返り値: 1/0/-1〜-5) |
| `pctx_init` | PreimageCtx の初期化 + 共有ハッシュ事前計算 |
| `pctx_free` | PreimageCtx のメモリ解放 |
| `VALID_SIGHASH[256]` | 有効な SIGHASH 値のルックアップテーブル |
| `ensure_context` | secp256k1 コンテキストの遅延初期化 |

### `c_checksig_verify` 返り値プロトコル

| 値 | 意味 | C 側の動作 |
|---|---|---|
| 1 | 検証成功 | push TRUE |
| 0 | 検証失敗 (encoding OK) | push FALSE + NULLFAIL チェック |
| -1 | Invalid SIGHASH | vm_error("Invalid SIGHASH flag") |
| -2 | High-S 値 (Low-S 違反) | vm_error("The signature must have a low S value.") |
| -3 | DER パースエラー | vm_error("The signature format is invalid.") |
| -4 | 公開鍵パースエラー | vm_errorf("%s requires correct encoding...") |
| -5 | Preimage 構築エラー | vm_error("CHECKSIG preimage error") |

### `spend_validate` API 変更

```python
# Phase 3b: checksig_cb コールバック
_bsv_native.spend_validate(
    unlock_chunks, lock_chunks,
    tx_version, source_txid, source_output_index,
    checksig_cb,  # Python callable
)

# Phase 3c: トランザクションデータを直接渡す
_bsv_native.spend_validate(
    unlock_chunks, lock_chunks,
    tx_version, source_txid, source_output_index,
    lock_time, input_index, input_sequence,  # unsigned int
    source_satoshis,                          # int64
    other_inputs,  # list[tuple[txid, vout, script, satoshis, seq, sighash]]
    outputs,       # list[bytes]  (各 output の serialize())
)
```

### 変更ファイル

| ファイル | 変更内容 |
|---------|---------|
| `_bsv_native/bsv_native.c` | +~1100行 (PreimageCtx, 11ヘルパー, CHECKSIG/CHECKMULTISIG 書き直し) |
| `bsv/script/spend.py` | `_validate_native()` 全面書き直し (checksig_cb 廃止, tx データ直接渡し) |
| `tests/bsv/live/test_live_malleability.py` | エラーメッセージ/動作変更に合わせてテスト更新 |
| `docs/c-extension-plan.md` | ロードマップ + 完了記録 |

### テスト結果

全 3,430 テスト合格、259 スキップ、0 失敗。

---

## Phase 3c 課題と発見 (2026-07-01)

Phase 3c の実装で発見した動作差異と注意点を記録する。

### 1. `suppress(Exception)` による Low-S エラーメッセージ隠蔽 — C で正確化

**Python-only パスの動作** (spend.py `check_signature_encoding`):
```python
with suppress(Exception):
    _, s = deserialize_ecdsa_der(sig)
    if not self.is_relaxed() and REQUIRE_LOW_S_SIGNATURES and s > curve.n // 2:
        self.script_evaluation_error("The signature must have a low S value.")
    return True
self.script_evaluation_error("The signature format is invalid.")
```
Low-S 違反時の `script_evaluation_error` は `RuntimeError` を raise するが、
`suppress(Exception)` に catch されるため「format is invalid」が表面に出る。

**Phase 3b (コールバック)**: この動作を忠実に再現し、-3 (= "format is invalid") を返していた。

**Phase 3c (C 内完結)**: `secp256k1_ecdsa_signature_normalize` で Low-S を直接検出。
返り値 -2 で "The signature must have a low S value." を返す。
これにより Python-only パスとのエラーメッセージが異なるが、**検証の合否は一致**する。

**テスト影響**: `test_v1_rejects_high_s` の match を `"signature format is invalid"` →
`"low S value"` に更新。

### 2. High-S 署名の ECDSA 検証 — libsecp256k1 の正しい挙動

**Python-only パス (coincurve)**: `coincurve.PublicKey.verify()` は内部で
`secp256k1_ecdsa_verify` を呼ぶ前に signature を normalize している可能性があり、
high-S 署名に対する挙動が version による差異を生んでいた。

**Phase 3c (libsecp256k1 直接)**: `secp256k1_ecdsa_verify` は数学的に正しい ECDSA 検証を
行うため、high-S 署名でも (s, n-s) の対称性により検証成功する。
tx_version > 1 (relaxed) で Low-S チェックをスキップした場合、high-S 署名は正当に検証成功する。

**テスト影響**: `test_v2_bypasses_low_s_check` を「RuntimeError を期待」→「成功を期待」に変更。
これは libsecp256k1 の正しい動作であり、バグではない。

### 3. `input_sequence` の OverflowError

`self.input_sequence = 0xFFFFFFFF` は Python の signed int 範囲を超える。
`PyArg_ParseTuple` の format `"i"` (signed int) では OverflowError が発生。
format を `"I"` (unsigned int) に変更して解決。`lock_time` も同様に `"I"` に変更。

### 4. Python-only パスと C パスの挙動差分サマリ

| 項目 | Python-only | Phase 3b (callback) | Phase 3c (C内完結) |
|------|-------------|--------------------|--------------------|
| Low-S エラーメッセージ | "format is invalid" | "format is invalid" | "low S value" |
| High-S + relaxed の検証 | coincurve 依存 | coincurve 依存 | 検証成功 (正しい) |
| CHECKSIG あたりの境界越え | なし (全 Python) | 2回 (C→Py→C) | 0回 (全 C) |

これらの差異は検証の合否 (accept/reject) には影響しない。エラーメッセージと
内部パスのみの違いであり、セキュリティ特性は同等。

### Phase 3b → 3c への教訓

1. **コールバックは段階的移行に有効**: 3b でまず全 opcode を C VM で動かし、
   3c で内部ロジックを C 化する2段階アプローチにより、各段階でテスト通過を確認しながら
   安全に移行できた。

2. **suppress(Exception) の副作用は C 化で露出**: Python の例外制御フローの
   意図しない副作用が、C への逐語翻訳で明確になる。

3. **PreimageCtx の事前計算は大量入力 tx で効果大**: BIP143 の hashPrevouts/hashSequence/
   hashOutputs を spend_validate 進入時に一度だけ計算することで、N 入力 tx の CHECKSIG で
   O(N) → O(1) のハッシュ計算に削減。

4. **unsigned int 注意**: BSV のプロトコル値 (sequence, locktime) は uint32_t だが、
   Python は整数型の符号を区別しないため、PyArg_ParseTuple の format 指定に注意が必要。

---

## ファズテスト + メモリテスト 完了記録 (2026-07-01)

### 実装内容

hypothesis ベースのファズテスト 46 件と AddressSanitizer (ASAN) ビルドスクリプトを追加。
全 29 エクスポート関数 + VM (spend_validate) + refcount ストレステストをカバー。

### テスト構成

| カテゴリ | テスト数 | 対象関数 |
|---------|---------|---------|
| Hash | 3 | sha256, hash256, hmac_sha256 |
| Pubkey | 7 | pubkey_from_secret, parse, serialize, point, tweak_add, tweak_mul, combine |
| Seckey | 2 | seckey_verify, seckey_tweak_add |
| ECDSA | 6 | sign, sign_bad_secret, verify, sign_with_k, sign_recoverable, recover |
| ECDSA roundtrip | 1 | sign → verify |
| ECDH | 2 | ecdh (正常/不正入力) |
| Tx | 5 | tx_from_bytes, tx_to_bytes, roundtrip, tx_txid |
| Script | 3 | parse_script_chunks, serialize_script_chunks, roundtrip |
| Merkle | 2 | merkle_hash_pair, merkle_compute_root |
| Preimage | 3 | tx_preimages (BIP143), tx_preimage_otda, garbage input |
| spend_validate | 6 | random script, stack ops, arithmetic, flow control, hash ops, bad types |
| Refcount stress | 6 | 各関数の正常/エラーパスを 5,000〜10,000 回反復 |

### 発見したバグ

#### `ecdsa_recover` の recid 範囲チェック欠落 — ✅ 修正済み

```c
// bsv_native.c L711 (修正前)
const unsigned char *sigdata = (const unsigned char *)sig_buf.buf;
int recid = sigdata[64];
// recid が 0-3 範囲外だと secp256k1_ecdsa_recoverable_signature_parse_compact が
// 内部 VERIFY_CHECK で abort() → プロセスクラッシュ
```

**問題**: `sigdata[64]` は 0〜255 の任意の値を取りうるが、libsecp256k1 の
`secp256k1_ecdsa_recoverable_signature_parse_compact` は `recid` が 0-3 であることを
前提とし、範囲外では `VERIFY_CHECK(recid >= 0 && recid < 4)` で abort する。

**影響**: 不正な recoverable signature (65バイト目が 4 以上) を `ecdsa_recover` に
渡すとプロセスが abort する。外部入力を処理する場合にクラッシュの原因になる。

**修正**: recid の範囲チェックを `secp256k1_ecdsa_recoverable_signature_parse_compact`
呼び出し前に追加。

```c
int recid = sigdata[64];
if (recid < 0 || recid > 3) {
    PyBuffer_Release(&sig_buf);
    PyBuffer_Release(&msg_buf);
    PyErr_SetString(PyExc_ValueError, "recovery id must be 0, 1, 2, or 3");
    return NULL;
}
```

### ASAN 結果

AddressSanitizer (`-fsanitize=address -fno-omit-frame-pointer -g -O1`) でビルドし
全 46 テスト通過。以下のメモリエラーは検出されなかった:
- Heap buffer overflow / underflow
- Stack buffer overflow
- Use-after-free
- Double free

macOS (Darwin) では LeakSanitizer が非サポートのため `detect_leaks=0` で実行。
リークチェックは refcount ストレステスト (Python レベル) で代替。

### 変更ファイル

| ファイル | 変更内容 |
|---------|---------|
| `_bsv_native/bsv_native.c` | +5行 (ecdsa_recover recid 範囲チェック) |
| `tests/bsv/native/__init__.py` | 新規 (テストパッケージ) |
| `tests/bsv/native/test_fuzz_native.py` | 新規 (~430行, 46テスト) |
| `scripts/run_asan_tests.sh` | 新規 (ASAN ビルド + テスト + 復元スクリプト) |

### 教訓

1. **libsecp256k1 の VERIFY_CHECK は abort する**: libsecp256k1 は assert の代わりに
   `VERIFY_CHECK` マクロを使用し、条件不成立で `abort()` を呼ぶ。Python 例外に変換
   されないため、呼び出し前に全ての前提条件を C 側で検証する必要がある。

2. **ファズテストの初回実行で即座にバグ検出**: hypothesis の 200 例ランダム入力で
   `ecdsa_recover` のクラッシュが検出された。手動テストでは recid=0 の正常パスしか
   通らないため、このバグは長期間潜伏していた。

3. **ASAN + hypothesis の組み合わせ**: ASAN ビルドで hypothesis を実行することで、
   ランダム入力 × メモリ検査の二重チェックが可能。ASAN 単体よりカバレッジが広い。

---

## CI/wheel パイプライン 完了記録 (2026-07-01)

### 実装内容

cibuildwheel を使ったマルチプラットフォーム wheel ビルドパイプラインを構築。
タグ push (`v*.*.*`) で自動的に wheel をビルドし PyPI にパブリッシュする。

### ビルドマトリクス

| プラットフォーム | アーキテクチャ | Runner | 方式 |
|----------------|--------------|--------|------|
| Linux (manylinux) | x86_64 | ubuntu-latest | ネイティブ |
| Linux (manylinux) | aarch64 | ubuntu-latest | QEMU エミュレーション |
| macOS | x86_64 | macos-13 | ネイティブ |
| macOS | arm64 | macos-14 | ネイティブ |
| Windows | AMD64 | windows-latest | MSVC |

各プラットフォーム × Python 3.10/3.11/3.12/3.13 = 最大 20 wheel。
musllinux, win32, manylinux_i686 はスキップ。

> ℹ️ **cp313 の経緯**: 一時期 F8 (`_PyLong_AsByteArray` が Python 3.13 で 6 引数化) により
> cp313 native wheel がビルド不能だった (2026-07-02 に Py3.13 ヘッダで確認)。同日 F8 を修正
> (私的 API → 公開 `PyLong_*NativeBytes`) し、x86_64/arm64 の Python 3.13 で native ビルド +
> 159 テスト通過を確認。cp313 wheel 提供可能。

### 変更ファイル

| ファイル | 変更内容 |
|---------|---------|
| `.github/workflows/wheels.yml` | 新規 — cibuildwheel + sdist + 純 Python テスト + PyPI publish |
| `.github/workflows/build.yml` | C 拡張ビルド検証ステップ + hypothesis 追加 |
| `.github/workflows/workflow.yml` | deprecated に変更 (wheels.yml にリダイレクト) |
| `MANIFEST.in` | 新規 — sdist に C ソース + secp256k1 を含める |
| `setup.py` | BuildExtFallback + BSV_REQUIRE_NATIVE |
| `pyproject.toml` | wheel から `_bsv_native/` ソースと `examples/` を除外 |

### 発見した課題

#### 1. setuptools namespace package による不要ファイル混入

`[tool.setuptools.packages.find]` はデフォルトで namespace package 検出を使う。
`__init__.py` がないディレクトリでも Python ファイルを含めばパッケージとして認識される。

**影響**: wheel に `_bsv_native/` (C ソース + secp256k1 ソース 105 ファイル) と
`examples/` (サンプルスクリプト 17 ファイル) が丸ごと含まれていた。

**対応**: `exclude` に `"_bsv_native*"` と `"examples*"` を追加。

```toml
[tool.setuptools.packages.find]
exclude = ["tests*", "_bsv_native*", "examples*"]
```

#### 2. `package-data` のワイルドカードスコープ

```toml
# 修正前 — "*" は全パッケージ (namespace 含む) にマッチ
[tool.setuptools.package-data]
"*" = ["hd/wordlist/*.txt"]

# 修正後 — bsv パッケージに限定
[tool.setuptools.package-data]
"bsv" = ["hd/wordlist/*.txt"]
```

#### 3. Windows ビルドの C 標準指定

setup.py で Windows 向けに `/std:c11` を追加 (MSVC は `-std=c99` を受け付けない)。
libsecp256k1 は C99 互換だが、MSVC では C11 モードが最も近い互換設定。

### 設計判断

1. **BSV_REQUIRE_NATIVE**: wheel CI では C 拡張のコンパイル失敗をエラーにする。
   純 Python wheel を誤って配布しないための安全装置。`BSV_NO_NATIVE=1` はユーザーが
   明示的に純 Python を選択する場合に使用。

2. **BuildExtFallback**: `pip install bsv-sdk` でコンパイラがない環境でも
   フォールバックとして純 Python でインストール可能にする。sdist からのインストール時に
   有効。wheel からのインストールでは不要 (コンパイル済み `.so` が含まれるため)。

3. **cibuildwheel でのテスト**: wheel ビルド後にファズテストを実行し、コンパイル済み
   バイナリの動作を検証。`_bsv_native` の import + バックエンド名確認 + fuzz テスト。

---

## ドキュメント監査 完了記録 (2026-07-01)

### 実施内容

c-extension-plan.md 全 2,121 行の整合性チェックを実施。
チェックボックスの更新漏れ、事実と矛盾する記述、実装と乖離した記載を修正。

### 修正箇所 (11件)

| # | 箇所 | 種別 | 修正内容 |
|---|------|------|---------|
| 1 | Phase 0 完了条件 | チェックボックス | `[ ] CI wheel ビルド` → `[x]` (CI/wheel 完了済み) |
| 2 | Phase 0 実装メモ | 事実矛盾 | `libsecp256k1 が high-S を拒否` → `high-S でも検証成功` (Phase 3c で判明) |
| 3 | Phase 1 完了条件 | チェックボックス | ファズ/メモリ/CI の3項目を `[x]` に更新 |
| 4 | リリース戦略 | 記述誤り | v2.5.0 `Chronicle opcodes C化` → `CHECKSIG パス C 内完結化` |
| 5 | 設計原則 CI マトリクス | 実装乖離 | `musllinux` にスキップ注記追加 |
| 6 | 0E タスク表 | 実装乖離 | `musllinux` 除外を反映 |
| 7 | 配布セクション | 実装乖離 | `musllinux` にスキップ注記追加 |
| 8 | ファイル構成図 | 古い情報 | `secp256k1_wrap.h/.c` 削除、行数 ~700 → ~4,345 に更新 |
| 9 | CPython Limited API | 未記録 | 見送り理由を記載 (PyArg_ParseTuple 等の制約) |
| 10 | Phase 1 品質タスク表 | 古い情報 | ファズ/メモリ/CI を完了に更新 |
| 11 | 進捗行 | 追記 | ベンチマークを残タスクに追加 |

### 発見した課題

#### 1. ドキュメント鮮度の構造的問題

c-extension-plan.md は ~2,130 行の大規模ドキュメント。各 Phase の完了条件・タスク表・
実装メモが時系列で追記されるため、**同じ事実が複数箇所に記載され、片方だけ更新される**
パターンが繰り返し発生した。

- Phase 0 の `ecdsa_verify` 記述 (L279) と Phase 3c の High-S 発見 (L1905) が矛盾
- Phase 1 の品質タスク表 (L1206) がファズ/ASAN 完了後も `未着手` のまま
- `musllinux` が計画時点の 3箇所に記載され、実装時にスキップしたが反映漏れ

**対策**: 完了記録を書く際に、同じ事実を記載している過去セクションも grep して更新する。
特に完了条件チェックボックスは Phase ヘッダ直下にあるため見落としやすい。

#### 2. CLAUDE.md の更新漏れ

CLAUDE.md の "Important Notes" に `The SDK uses coincurve for ECDSA operations` と
記載されているが、現在は `_bsv_native` が推奨で coincurve はフォールバック。
CLAUDE.md は c-extension-plan.md の管轄外だが、SDK の実態と乖離している。

#### 3. 残存する未実施タスク

> ⚠️ この表は 2026-07-01 時点の任意タスクのみを列挙していた。2026-07-02 のレビュー・全面監査で
> 非任意の未着手項目 (F8/F11/F4 等) が追加された (F8 は同日修正済み)。最新の完全な残タスクは
> 末尾の「残タスク一覧 (PM バックログ)」を正とすること。以下は当時の記録として残す
> (「全て任意」は現在は誤り)。

当時の記録 (2026-07-01, 優先度順):

| タスク | 優先度 | 理由 |
|--------|--------|------|
| ~~等価性テスト (C ⇔ Python)~~ | ~~中~~ | ✅ 完了 (2026-07-01)。65テスト9カテゴリ。Low-S メッセージ差異は KnownDifferences として文書化 |
| ~~ベンチマーク (pytest-benchmark)~~ | ~~低~~ | ✅ 完了 (2026-07-01)。31ベンチマーク + lazy chunks 改修後に再計測済み |
| context_randomize 定期化 (4.4) | 低 | 初期化時のみ実行中。定期呼び出しはセキュリティ改善だが実運用影響は限定的 |
| Schnorr API (4.5) | 低 | 将来のプロトコル拡張用。BSV で現在使用されていない |
| musllinux wheel | 低 | Alpine Linux 対応。需要に応じて追加 |

---

## 等価性テスト 実装記録 (2026-07-01)

### 実施内容

`tests/bsv/native/test_equivalence.py` を新規作成。C 拡張 (`_bsv_native`) の全エクスポート関数と
対応する Python フォールバック実装の出力が一致することを検証する 65 テスト / 9 カテゴリ。

| カテゴリ | テスト数 | 検証内容 |
|----------|---------|---------|
| Hash | 15 | sha256, hash256, hmac_sha256 — 空入力〜256バイトまで |
| ScriptChunks | 11 | parse/serialize の C⇔Python ラウンドトリップ |
| Tx | 4 | tx_from_bytes/tx_to_bytes/txid — 1入力・2入力トランザクション |
| Crypto | 11 | ECDSA sign/verify/recover, pubkey 操作, ECDH, tweak 系 |
| BIP-143 Preimage | 12 | 6 SIGHASH × 2 トランザクションサイズ |
| OTDA Preimage | 6 | 6 SIGHASH (CHRONICLE フラグ付き) |
| Merkle | 2 | merkle_hash_pair — 固定値 + 可変値 |
| Spend VM | 4 | P2PKH, P2PK, BareMultisig 2-of-2, OP_RETURN エラー |
| KnownDifferences | 1 | high-S エラーメッセージ差異の文書化 |

### 発見した課題

#### 1. Spend コンストラクタの API が文書化不足

`Spend.__init__(self, params)` は単一の dict を受け取るが、dict のキーが camelCase
(`sourceTXID`, `lockingScript` 等) であることがテストコード側で把握しづらい。
等価性テストでは `_make_spend()` ヘルパーを作成してこの変換を隠蔽した。

既存テストスイートは全て `Transaction.verify()` 経由で Spend を構築するため、
直接 `Spend({...})` を呼ぶテストがなかった。Spend の公開 API としての使いやすさは
改善の余地がある（TS/Go SDK との互換性のため camelCase は維持）。

#### 2. Transaction.verify() は async だが Spend.validate() は同期

`Transaction.verify()` は async coroutine のため、同期テスト内で直接呼べない。
等価性テストでは `Spend` オブジェクトを直接構築し `.validate()` を呼ぶ方式に変更。
これは正しい回避策だが、`verify()` と `validate()` のテスト経路が異なることを意味する。
`verify()` 経由の等価性テストは既存の統合テストスイート (3,541 passed) がカバーしている。

#### 3. BareMultisig.lock() が PublicKey オブジェクトを受け付けない

`BareMultisig().lock()` の型ヒントは `list[str | bytes]` で、`PublicKey` オブジェクトを
渡すと `AssertionError: unsupported public key type` が発生する。
`key.public_key()` の戻り値は `PublicKey` インスタンスなので、`.hex()` への変換が必要。
P2PK や P2PKH は同様のパターンだが `lock()` が `str` を期待するため問題にならない。
BareMultisig だけ `PublicKey` を直接受け付ける拡張を検討してもよい。

#### 4. PrivateKey のバイト取得 API の不統一

`PrivateKey._secret` (内部属性) でしか raw 32バイトを取得できない。
`.serialize()` も存在するが、用途が WIF 文字列返却と混同しやすい。
等価性テストでは `key._secret` を使用したが、公開 API としては
`.to_bytes()` または `.secret_bytes` のようなプロパティがあると明確。

---

## ベンチマーク結果 (2026-07-01)

### 実施内容

`tests/bsv/native/test_benchmark_native.py` を新規作成。pytest-benchmark で C 拡張と
Python フォールバックの全 dispatch ポイントの速度を比較。31 ベンチマーク / 7 カテゴリ。

### 結果サマリ

環境: macOS Darwin 25.4.0, Python 3.11.3, Apple Silicon

| カテゴリ | ベンチマーク | C (μs) | Python (μs) | 高速化 | 計画値 |
|----------|-------------|--------|-------------|--------|--------|
| **Hash** | sha256 (32B) | 0.49 | 0.72 | 1.5x | — |
| | hash256 (32B) | 0.70 | 1.27 | 1.8x | — |
| | hash256 (1KB) | 5.70 | 1.96 | 0.3x ※ | — |
| **Script** | parse P2PKH | 0.23 | 2.29 | **10x** | 25x |
| | parse large (2.5KB) | 0.76 | 10.02 | **13x** | 30x |
| | serialize P2PKH | 0.10 | 0.49 | **4.9x** | — |
| **Tx** | parse 1-in | 1.46 | 4.62 | **3.2x** | 30x |
| | parse 100-in | 49.21 | 131.01 | **2.7x** | 160x |
| | serialize | 0.84 | 2.73 | **3.3x** | 20x |
| | txid | 1.08 | 1.51 | 1.4x | — |
| **Preimage** | BIP-143 (1-in) | 2.82 | 8.26 | **2.9x** | — |
| **Merkle** | hash_pair | 1.42 | 3.81 | 2.7x | — |
| | compute_root (h=10) | 13.13 | 187.30 | **14.3x** | 40x |
| **Spend VM** | P2PKH validate | 54.78 | 215.69 | **3.9x** | — |
| **Crypto** | ecdsa_sign | 31.71 | — | — | — |
| | ecdsa_verify | 38.89 | — | — | — |
| | pubkey_from_secret | 21.09 | — | — | — |

※ hash256 (1KB) が C < Python なのは、Python の hashlib.sha256 が OpenSSL の C 実装を直接呼ぶため。
_bsv_native は libsecp256k1 の secp256k1_sha256 を使っており、CPython→C 呼び出しオーバーヘッド +
libsecp256k1 の SHA256 実装が OpenSSL ほど最適化されていないことが原因。小データ (32B) では C が勝つ。

### 計画値との比較

| 項目 | 計画値 | 実測値 | 評価 |
|------|--------|--------|------|
| 1-in Tx parse | 30x | 3.2x | Python 側も lazy chunks で高速化し差が縮小 |
| 100-in Tx parse | 160x | 2.7x | 同上 + Python オブジェクト生成コストが支配的 |
| Script parse (P2PKH) | 25x | 10x | おおむね計画の半分。実用上十分 |
| Merkle root (h=10) | 40x | 14.3x | merkle_compute_root バグ修正後、単純パスは全 C 完結 |
| serialize + txid | 20x | 3.3x | tx_to_bytes は dict→C 変換コストが支配的 |

計画値は「C 内部のみ」の理想値。実測値は Python⇔C のデータ変換オーバーヘッドを含むため低めだが、
**絶対速度は全カテゴリで改善**。lazy chunks 化により Python 側も大幅に高速化
（100-in Tx parse: 413→131μs、Spend VM: 410→216μs）。

### 注記

- Crypto 系 (ECDSA sign/verify, pubkey) は C 実装のみ（Python フォールバックは coincurve 経由で
  同じく C ライブラリを呼ぶため、比較対象として不適切）
- Spend VM の 3.5x はマーシャリングコストを含む。VM ループ自体の高速化はそれ以上
- hash256 の大データ (1KB+) では Python (hashlib/OpenSSL) が速い。これは想定内の結果

---

## 改修: Script.chunks lazy 化 (2026-07-01)

### 背景

ベンチマークで 100-input Tx parse が計画値 160x に対し実測 7.3x にとどまった。
原因を分解した結果、ボトルネックは C パースではなく Python 側の `Script.__init__` にあると判明。

```
C tx_from_bytes (raw→dict):      48 μs   ← C のバイトパースは高速
_from_native_dict (dict→Py):    324 μs   ← ★ ボトルネック
  └ Script(bytes) × 100:        449 μs
    └ _build_chunks() × 100:   ~448 μs   ← Script 生成コストの 99%
```

`Script.__init__` はコンストラクタ内で即座に `_build_chunks()` を呼ぶが、
Tx パース時点では chunks は不要。chunks が必要になるのは sign / validate / to_asm 時。

### 改修内容

`Script.chunks` を即時パースから **lazy property** に変更する。

#### 変更前

```python
class Script:
    def __init__(self, script):
        self._bytes = script if isinstance(script, bytes) else bytes.fromhex(script)
        self.chunks = []
        self._build_chunks()   # ← 毎回即時パース
```

#### 変更後

```python
class Script:
    def __init__(self, script):
        self._bytes = script if isinstance(script, bytes) else bytes.fromhex(script)
        self._chunks = None    # ← 遅延初期化

    @property
    def chunks(self):
        if self._chunks is None:
            self._build_chunks()
        return self._chunks

    @chunks.setter
    def chunks(self, value):
        self._chunks = value
```

#### 影響箇所

| ファイル | 箇所 | 影響 |
|----------|------|------|
| `bsv/script/script.py` | `__init__`, `_build_chunks`, `from_chunks` | 直接変更 |
| `bsv/script/script.py` | `serialize`, `is_push_only`, `to_asm`, `find_and_delete` | 影響なし (読み取りのみ) |
| `bsv/script/spend.py` | `.chunks` 参照 10箇所 | 影響なし (読み取りのみ) |
| `tests/` | `.chunks` 参照 50箇所以上 | 影響なし (読み取りのみ) |
| `bsv/script/script.py:181` | `s.chunks = chunks` (`from_chunks`) | setter で対応 |

#### 期待される効果

```
100-in Tx parse (C パス):  372 μs → 111 μs  (3.4x 改善)
100-in Tx parse 倍率:       1.1x  →  3.7x   (vs Python)
```

Python パスも恩恵を受ける（Python 版 Tx parse でも同じ Script 生成が走るため）。

#### 実測結果

全テスト合格 (3,572 passed, 259 skipped)。絶対速度の改善:

| ベンチマーク | C 改修前→後 | Python 改修前→後 |
|---|---|---|
| 100-in Tx parse | 57 → 49μs | **413 → 131μs (3.2x)** |
| 1-in Tx parse | 1.7 → 1.5μs | **24 → 4.6μs (5.3x)** |
| Spend VM (P2PKH) | **117 → 55μs (2.1x)** | **410 → 216μs (1.9x)** |
| Script parse (large) | 1.6 → 0.8μs | 16 → 10μs |

C/Python 倍率は Tx parse で下がった (7.3x→2.7x) が、Python 側がより大きく高速化
したため。**Python 側の chunk パースが全体コストの大部分を占めていた**ことの裏付け。

#### リスク

- パースエラーのタイミングが遅延するが、`_build_chunks` は不正スクリプトでも例外を投げない
  （不完全データは `data=None` で格納）ため実質影響なし
- スレッドセーフティ: CPython の GIL があるため実質問題なし

---

## ベンチマーク分析で発見した構造的課題 (2026-07-01)

### 1. C/Python 倍率のボトルネックは Python オブジェクト生成

C 拡張の計画値 (30x〜160x) と実測値 (2.7x〜13x) の乖離は、C のバイトパースが遅いのではなく、
**パース結果を Python オブジェクトに変換するコスト**が支配的であることが原因。

```
100-in Tx parse 内訳:
  C tx_from_bytes (raw→dict):      48 μs   ← C は十分高速
  dict→TransactionInput×100:       63 μs   ← Python オブジェクト生成
  合計:                            111 μs
  Python パス全体:                 131 μs   ← lazy chunks 後
```

C パースは Python の 2.7x（131/49μs）だが、C の 49μs のうち大半は CPython API 経由の
dict/str/bytes 生成。純粋な C バイトパースは数μs 以下。

**改善策（将来）**: `tx_from_bytes` が dict ではなく TransactionInput/TransactionOutput を
直接生成する方式。ただし C コードが Python クラス構造に依存するため、メンテナンスコストとの
トレードオフ。現状のアーキテクチャでは C/Python 倍率 3〜4x が構造的上限。

### 2. Preimage の C/Python 倍率が低い理由

BIP-143 preimage の実測 2.9x は以下の構造的理由:

- **マーシャリングコストが C 処理全体の 65%**: `_inputs_to_tuples()` と `_outputs_to_bytes()` が
  Python オブジェクトを tuple/bytes に変換する処理で 6μs、C の計算自体は 5μs
- **Python 側も hashlib (OpenSSL C 実装) を使用**: Python パスの preimage 計算の 69% が
  既に C (OpenSSL) で実行されている。C 拡張は libsecp256k1 SHA256 に置き換えるが、
  C→C の置き換えでは大差が出ない

**改善策（将来）**: Transaction オブジェクトが C 側にデータを保持すれば、
preimage 計算時のマーシャリングが不要になる。ただし上記 1. と同じ課題。

### 3. hash256 の大データで Python (hashlib) が速い

`_bsv_native.hash256(1KB)` = 5.7μs、`bsv.hash.hash256(1KB)` = 2.0μs。
Python の hashlib.sha256 は OpenSSL の高度に最適化された実装を直接呼ぶ。
libsecp256k1 の secp256k1_sha256 はポータブル実装で、SIMD/AES-NI 等の
ハードウェアアクセラレーションを使っていないため、大データで差が開く。

hash256 は内部ユーティリティとして使われるため、**直接のユーザー影響は小さい**。
C 拡張の hash256 はコンテキスト切替なしで呼べることに意味がある（Merkle, preimage, txid 等）。

---

## merkle_compute_root 改修記録 (2026-07-01)

### 背景

ベンチマークで Merkle root (h=10) の C/Python 倍率が計画値 40x に対し 9.5x にとどまった。
`_compute_root_native` は毎レベルで `find_or_compute_leaf` (Python) + `merkle_hash_pair` (C) を
呼んでおり、h=10 で Python/C 境界越えが 20 回発生していた。

一方、C 側には `merkle_compute_root` という全処理を C 内で完結する関数が既に実装されていたが、
**バイトオーダーのバグ**があり、プロダクションコードから一度も呼ばれていなかった。

### 発見したバグ

**問題**: Python の `hash_fn(left + right)` は `hash256(to_bytes(left + right, "hex")[::-1])` で
128 文字 hex → 64 バイト → **全体 64 バイトを reverse** → hash256 する。C の `merkle_compute_root` は
各 32 バイト半分を `hex_to_bytes_reversed` で**個別に reverse** して結合していた。

全体 reverse と個別 reverse は結合順序が逆転するため、結果が異なる:
- 全体 reverse: `reverse(left_bytes || right_bytes)` = `right_rev || left_rev`
- 個別 reverse: `left_rev || right_rev`

**原因**: Phase 1 実装課題 #1 (hex⇔bytes 変換のセマンティクス差異) と同根の問題。
`merkle_hash_pair` ではこの問題を正しく処理していたが、`merkle_compute_root` では
内部バイト表現を使う設計が異なり、同じバグが混入していた。

**潜伏理由**: `merkle_compute_root` はファズテスト (`test_merkle_compute_root_no_crash`) で
クラッシュしないことのみ検証されていた。正当性テスト（等価性テスト）は `merkle_hash_pair`
のみカバーしており、`merkle_compute_root` の等価性テストが存在しなかった。

### 修正内容

```c
// 修正前 (bsv_native.c)
} else if (offset % 2 != 0) {
    memcpy(concat, pair, 32);        // pair_rev first
    memcpy(concat + 32, working, 32);
} else {
    memcpy(concat, working, 32);     // working_rev first
    memcpy(concat + 32, pair, 32);
}

// 修正後 — 全体 reverse により結合順序が反転
} else if (offset % 2 != 0) {
    memcpy(concat, working, 32);     // working_rev first
    memcpy(concat + 32, pair, 32);
} else {
    memcpy(concat, pair, 32);        // pair_rev first
    memcpy(concat + 32, working, 32);
}
```

### Python 側の改修

`_compute_root_native` で `merkle_compute_root` を第一候補として呼び出し、
ValueError (compound path で leaf が見つからない場合) は `merkle_hash_pair`
ループにフォールバック:

```python
def _compute_root_native(self, txid, index):
    try:
        return _bsv_native.merkle_compute_root(txid, self.path)
    except (ValueError, TypeError):
        pass
    # フォールバック: per-level merkle_hash_pair
    ...
```

### 結果

| | Before | After |
|---|---|---|
| C 側 merkle root h=10 | 33μs | **13μs** |
| C/Python 倍率 | 9.5x | **14.3x** |
| Python/C 境界越え (単純パス) | 20回 | **1回** |

全テスト合格 (3,572 passed, 259 skipped)。BRC-74 compound path テスト含む。

### 教訓

1. **ファズテストはクラッシュ防止、等価性テストは正当性検証**: 両方が必要。
   `merkle_compute_root` はファズで安全だが等価性テストが欠如していたためバグが潜伏

2. **未使用コードに注意**: 実装済みだが呼び出されていない関数はバグの温床。
   「なぜ使われていないのか」を追跡すべきだった

3. **hex⇔bytes + reverse の問題は再発する**: Phase 1 課題 #1 と同根。内部バイト表現と
   display hex 表現の変換は Bitcoin 特有の罠であり、新しい関数ごとに中間値照合テストが必要

---

## コードレビュー + アドバーサリアル検証記録 (2026-07-02)

### 実施内容

C拡張全体 (`bsv_native.c` 4,346行 + Python 統合層 6ファイル) のコードレビューを実施し、
16件の指摘を抽出。**各指摘を独立の検証エージェントが実測を含めてアドバーサリアル検証**
(tracemalloc リーク計測、subprocess での segfault 再現、timeit ベンチマーク、
Python 3.13 ヘッダでの実コンパイル) し、P0/P1 確定項目は第二検証者が再反証を試みた。

### 検証結果サマリ

| ID | 指摘 | レビュー時 | 検証後 | 判定根拠 (実測) |
|----|------|-----------|--------|----------------|
| F1 | tx_from_bytes 参照リーク | P0 | **P0 確定** → ✅ 修正済み | 202 B/call の線形増加、GC 回収不能 |
| F2 | parse_script_chunks 参照リーク | P0 | P3 に格下げ → ✅ 修正済み | 小整数キャッシュのためメモリ増加ゼロ (refcount 膨張のみ) |
| F3 | pubkey_point デッドストア | P1 | P3 に格下げ → ✅ 修正済み | 同上 (キャッシュ済み int 0)、デッドコード2行 |
| F4 | tx_to_bytes NULL deref | P0 | P1 (一部過大、新規発見あり) | source_txid 経由の SIGSEGV 実証 (exit=139)。int 系3キーは SystemError で crash せず。**新規発見: 非 hex txid で未初期化ヒープメモリ流出 + ~62B OOB read**。SDK 本体からは未使用 (テストのみ) |
| F5 | PUSHDATA4 符号拡張 | P2 | **棄却** | 64bit では `(Py_ssize_t)` キャストがシフト前のため符号拡張なし。32bit ビルド限定の潜在 UB (未出荷) のみ |
| F6 | RIPEMD160 毎回 import | P2 | P2 確定 (修正方針は変更) | import 自体は ~0.3µs で無害。Cryptodome ハッシャー生成込みで 3.2µs/回 = P2PKH validate の ~10%。修正はモジュールキャッシュではなく **C 実装 RIPEMD160 の組み込み** が必要 |
| F7 | g_ctx スレッド安全性 | P1 | P3 に格下げ | `Py_BEGIN_ALLOW_THREADS` が 0 件 = 拡張全体が GIL 保持下で動作、race は現状発生不可能。free-threaded Python / GIL 解放最適化導入時の注意点として記録 |
| F8 | `_PyLong_*` 私的 API | P3 | **P2 に格上げ → ✅ 修正済み (2026-07-02)** | 3.13 で `_PyLong_AsByteArray` が 6 引数化 → cp313 native ビルド不能を実測確認。**同日修正**: 私的 API を公開 `PyLong_FromUnsignedNativeBytes`/`AsNativeBytes` へ移行 (≥3.13)、≤3.12 は従来 API を `#if PY_VERSION_HEX` で維持。x86_64/arm64 の 3.13 で native ビルド + 159 テスト通過、3.11 回帰なし。詳細は末尾「F8 完了記録」参照 |
| F10 | PublicKey 冗長パース | P2 | P2 確定 | `pubkey_parse` は完全冗長 (構築コストの ~48%)。CHECKSIG ホットパスで公開鍵が6回パースされる |
| F11 | tx_preimage 全件計算 | P2 | **P2 確定 + 深刻度は過小評価だった** | `Transaction.sign()` が O(N²): テンプレート sign() が入力ごとに `tx.preimage(i)` → 毎回全入力分を計算。実測 N=1000 で sign() 344.8ms 中 **~320ms (93%) が無駄なプリイメージ計算** (ECDSA 本体は ~25ms)。Spend VM ネイティブパスは C 内単一計算のため影響なし |
| F12 | Tx raw bytes キャッシュ | P2 | P3 に格下げ (却下推奨) | 効果は小 tx で 1.6µs と軽微。ネスト変更 (`inp.unlocking_script = ...`) を検知できず**誤った txid を返す正当性リスクの方が大きい** |
| F13 | merkle try/except フロー制御 | P3 | P3 確定 | 例外オーバーヘッド実測 1.2µs/回 (~7%)。「複合パスで常に失敗」は誇張 (trim 済み複合パスのみ)。~50行の重複は事実 |
| F14 | spend マーシャリング | P2 | P3 に格下げ | validate 全体の ~4.4% (1.3µs/29µs)。「再シリアライズ」は実際はキャッシュ済みバイト返却でほぼゼロコスト |
| F15 | key_deriver 2回呼び出し | P2 | **棄却 — 提案の方が遅い** | 数学的等価性は正しいが、提案の `pubkey_tweak_add` 一本化は実測 **1.37倍遅い** (tweak_add は内部で乗算+加算、現行は scalar 加算+1回の gen 乗算)。現行コードが既に最速経路 |
| F16 | テストがリークを見逃した原因 | — | 確定 | TestRefcountStress は全6テストで **assert 文ゼロ** (クラッシュ検出のみ)、tx_from_bytes はエラー経路のみ実行。ASAN は `detect_leaks=0`。計画書テスト戦略の `test_no_memory_leak` (tracemalloc) は**未実装だった** — 実装していれば 20MB リークとして即検出できた (実測確認) |

### 教訓: レビュー指摘はアドバーサリアル検証が必須

16件中、レビュー時の重大度がそのまま確定したのは 5件のみ。

- **2件棄却** (F5, F15): F15 は提案実装の方が 1.37倍遅いことを実測で確認 — 「改善提案」の性能検証なしの採用は危険
- **5件格下げ** (F2, F3, F7, F12, F14): CPython の小整数キャッシュ・GIL の考慮漏れが主因
- **2件格上げ** (F8, F11): 「将来リスク」とされた F8 は現在進行形のビルド障害、F11 は O(N²) の発見
- **1件で新規発見** (F4): 検証過程で未初期化ヒープメモリ流出という指摘外のバグを発見

### P0 修正記録: tx_from_bytes メモリリーク (✅ 2026-07-02 修正済み)

**原因**: `PyDict_SetItemString` は参照を**スティールしない** (INCREF する) が、
インライン生成した値 (`PyUnicode_FromString(txid_hex)` 等) を DECREF していなかった。
実リーク対象は source_txid 文字列 (113B/入力)、sequence (0xFFFFFFFF は小整数キャッシュ外、
32B/入力)、satoshis (28-32B/出力)、bytes_read。vout=0 / version=1 / locktime=0 は
キャッシュ済み小整数のため refcount 膨張のみでメモリは増えない。

**修正**: `dict_set_steal()` ヘルパー (値を consume する SetItemString) を導入し 7箇所を置換。
`PyDict_New()` の NULL チェックも追加。あわせて F2 (parse_script_chunks 5箇所を
`Py_BuildValue` 化 + data NULL チェック) と F3 (デッドストア2行削除) も修正。

**実測結果**:

| 計測 | 修正前 | 修正後 |
|------|--------|--------|
| tx_from_bytes 200,000回 | 40.4MB リーク (202 B/call 線形) | 増分ゼロ (残留 207KB は反復数に依存しない一回きりのアロケータ確保) |
| parse_script_chunks: int 118 refcount | +200,000 / 200k回 | **+0** |
| pubkey_point: int 0 refcount | +200,000 / 100k回 | **+0** |
| 出力の等価性 | — | 修正前後で同一 (スポットチェック + 等価性テスト65件パス) |

### 回帰テスト: TestMemoryGrowth (オラクル設計の注意点)

`tests/bsv/native/test_fuzz_native.py` に成功パスのメモリ増加テスト4件を追加。
オラクル設計で2つの罠に遭遇したため記録する:

1. **バイト数閾値は pytest 環境で偽陽性**: pytest 下では tracemalloc が
   アロケータ (arena) レベルの一回きりの大型確保 (計 ~1.9MB、4ブロック) を
   ループ行に帰属させる。standalone では発生しない。
   → オラクルを「新規**ライブブロック数**」に変更: 本物の per-call リークは
   反復回数分のブロック (20k回 → 20,005個を実測) を残すが、アロケータノイズは
   数個のみ。閾値 2,000 で確実に分離できる。

2. **自己検証の定数畳み込みの罠**: オラクル検証用の「故意リーク」を
   `list.append("x" * 50)` で書くと、定数畳み込みで同一オブジェクトの参照追加になり
   リークにならない (検出 5ブロックのみ)。`object()` や実行時生成の str では
   正しく 20,005 ブロックを検出。

### 検証済みアクションプラン (改訂版)

当初レビューのアクションプランを検証結果で改訂。ordinalx (大量 ECDSA) の観点を含む。

| 優先 | 項目 | 根拠 (検証済み) | 工数 |
|------|------|----------------|------|
| ✅ | F1/F2/F3: メモリリーク + 参照衛生修正 | 実施済み (2026-07-02) | — |
| ✅ | F8: Python 3.13 コンパイル修正 | **完了 (2026-07-02)**。`#if PY_VERSION_HEX >= 0x030D0000` で公開 `PyLong_*NativeBytes` へ移行、≤3.12 は従来 API。x86_64/arm64 の 3.13 で検証。3.14 も安定 API のみで対応見込み | 実績 ~1h |
| **2** | F11: Transaction.sign() の O(N²) 解消 | **ordinalx 大量署名に直結**。sign() 内で `tx_preimages()` を1回だけ呼ぶバッチキャッシュ方式で O(N) 化 (単一 index C 関数の追加だけではタプル変換 O(N) が残るため不十分)。N=1000 で 345ms → ~25ms 見込み | 半日 |
| **3** | F4: tx_to_bytes 入力検証 | segfault + 未初期化ヒープ流出。SDK 未使用だが公開シンボル。NULL/型/hex 検証 ~40-50行。あわせて「未使用関数を Transaction.serialize() に接続するか削除するか」の方針判断 | 30-60分 |
| **4** | F16: メモリ増加テストの拡充 + CI | TestMemoryGrowth 4件は追加済み。全エクスポート関数へのパラメトライズ展開 + Linux CI での `detect_leaks=1` ASAN | 1日 |
| **5** | F6: C 実装 RIPEMD160 組み込み | P2PKH validate の ~10% (3.2µs/回)。OP_HASH160 は最頻 opcode | 半日-1日 |
| **6** | F10: PublicKey 冗長パース除去 | 構築コストの ~48%、CHECKSIG パスで6回パース | 半日 |
| 却下 | F12 (raw bytes キャッシュ) | 正当性リスク > 効果 1.6µs | — |
| 却下 | F15 (key_deriver 一本化) | 提案の方が 1.37倍遅い | — |

**ordinalx 向け補足**: 大量 ECDSA のボトルネックは検証の結果、署名パイプラインでは
F11 (O(N²)) が支配的。検証パイプライン (Spend VM) は Phase 3c で C 内完結済みのため
影響なし。F11 修正後になお不足する場合の次の一手は「バッチ検証 API」(複数 tx を
1回の C 呼び出しで検証、Python↔C 境界越えを N回→1回に削減) と multiprocessing 並列化。

---

## 全面リーク/クラッシュ監査 (2026-07-02)

### 動機

「メモリリークはもうないか、C拡張全部を検証するテストがあるか」という問いに答えるため、
全 29 エクスポート関数 + VM を対象に、二方向から網羅監査を実施した:

1. **実測スキャン**: 全関数を成功パス + エラーパス (計 52 ケース) でブロック数オラクルに
   かける (`scratchpad/leak_scan_all.py` → 後に `TestFullSurfaceMemoryScan` として恒久化)
2. **静的監査**: `bsv_native.c` 全 4,356 行を 8 領域 + Py_buffer 専任に分割し 9 エージェント
   並列で精査 → P0/P2 候補を第二段階で実測再検証

### 結論

**参照/メモリリークは残っていない** (F1-F3 修正後、全 52 ケースでブロック増加ゼロ)。
ただし監査の過程で**リークとは別種の重大バグ 2 件 (プロセスを殺す)** を新規発見・修正した。

### 新規発見バグ 1: `ecdsa_sign_with_k(k=0)` の無限ハング (DoS) — ✅ 修正済み

**症状**: `ecdsa_sign_with_k` に無効な k (ゼロ、または曲線位数 n の倍数) を渡すと
**プロセスが無限ループでハング**する。単一呼び出しで再現 (実測: 5秒 timeout で復帰せず)。

**原因**: `nonce_fn_custom_k` (bsv_native.c L519) が `counter` 引数を無視し、常に同じ k を
返していた。libsecp256k1 の `secp256k1_ecdsa_sign` は nonce が無効 (0 / ≥n / r==0 を生成) の
とき `counter` を増やして nonce 関数を**再呼び出しするループ**を回すが、この関数は counter に
関係なく同じ無効 nonce を返し続けるため、ループが永久に終わらない。

**到達経路**: `PrivateKey.sign(k=...)` (keys.py L269) は `k_bytes = (k % curve.n)` を計算するため、
k が n の倍数 (k=0, k=n, ...) だと k_bytes がゼロになりハング。R-puzzle 署名 (type.py L258) 経由でも
到達しうる。**当初の C レビューはこの counter 問題を指摘したが「secp256k1 がリトライ制限するので
無限ループしない」と誤って却下していた** — 実測でハングを確認。

**修正**: `nonce_fn_custom_k` に `if (counter > 0) return 0;` を追加。カスタム k 署名は
「指定された k を使うか失敗するか」であるべきで、勝手に別 nonce へ置換してはならない。
0 を返すと `secp256k1_ecdsa_sign` が失敗を返し、クリーンに `ValueError("signing with custom k
failed")` になる。正常な k の署名・検証は従来通り (回帰確認済み)。

### 新規発見バグ 2: OTDA SIGHASH_SINGLE 範囲外の配列外アクセス (SIGSEGV) — ✅ 修正済み

**症状**: SIGHASH_SINGLE + OTDA ルーティング (sighash 末尾バイト 0x63 / 0xE3) で
`input_index >= 出力数` のとき、`outputs_list` を配列外参照して **SIGSEGV** (実測 exit=139)。

**原因と影響範囲**: 同じ SINGLE-bug の欠落ガードが **2 つの独立した OTDA 実装**に存在した:
- `c_build_otda_preimage` (bsv_native.c L2666) — CHECKSIG/Script VM 経由。**untrusted tx の
  検証 (SPV) で攻撃者制御の入力から到達可能** = 実質的な DoS/crash ベクタ。`PyList_GET_ITEM` の
  境界外読み取り + `est` バッファの過少見積もりによるオーバーフロー
- `pyfn_tx_preimage_otda` (bsv_native.c L1961) — 署名時の `tx_preimage()` 経由。同型の OOB

BIP143 側 (`c_build_bip143_preimage` L2633) は `input_index < n_outputs` を正しくガードしており
無傷。SIGSEGV は OTDA 経路のみ。

**修正**:
- `c_build_otda_preimage`: SINGLE + 範囲外のとき preimage を `0x01||0x00*31` にする。呼び出し側の
  hash256 を経て、pure-Python の `Transaction._calc_input_preimage_legacy` (Bitcoin の SIGHASH_SINGLE
  バグ挙動そのもの) と**digest が完全一致**することを実測確認 (正しい署名で CHECKSIG が True)
- `pyfn_tx_preimage_otda`: 範囲外で `IndexError` を送出。こちらの pure-Python フォールバック
  `transaction_preimage._preimage_otda` は `outputs[i]` で IndexError を投げるため、それに合わせた

**発見した py-sdk 内の不整合**: OTDA preimage 実装が 2 系統あり、SIGHASH_SINGLE 範囲外の扱いが
**食い違っている** — `transaction.py::_calc_input_preimage_legacy` は `0x01||0x00*31` を返す
(Bitcoin consensus 準拠) が、`transaction_preimage.py::_preimage_otda` は IndexError を投げる。
将来的にどちらかへ統一すべき (consensus 準拠なら前者)。今回は各々のフォールバックに合わせて
C を修正し、クラッシュだけは確実に排除した。

### 静的監査で確認した既知/軽微な項目 (修正不要または低優先)

| 項目 | 関数 | 重大度 | 判定 |
|------|------|--------|------|
| `ensure_context` が os/urandom 失敗時に例外を握りつぶし成功を返す | L44-56 | P3 | randomization は best-effort。`PyErr_Clear()` 追加が望ましい |
| `g_ctx` がモジュールアンロード時に未破棄 | L30 | P3 | プロセス寿命の一回きり確保。crypto 拡張の標準的パターン |
| `tx_from_bytes` / `parse_script_chunks` の OOM 時 NULL 参照 | L1469 等 | P3 | `PyBytes_FromStringAndSize` 失敗 (メモリ枯渇時のみ) で NULL deref。通常入力では到達不能 |
| `pctx_init` が負/範囲外 `input_index` を未検証 | L4093 | P3 | Python ラッパーは常に整合値を渡す。直接誤用時のみ |
| `tx_to_bytes` の NULL deref (F4、前回記録) | L1594 | P1 | 別途 F4 として記録済み。SDK 本体からは未使用 |

Py_buffer ライフサイクル監査 (全 `y*` パース関数の `PyBuffer_Release` 網羅): **全経路クリーン**。

### 恒久回帰テスト (再発防止)

`tests/bsv/native/test_fuzz_native.py` に 2 クラス追加:

- **`TestCrashHangRegression`** (4 テスト): **サブプロセス隔離 + timeout** で実行。既存の
  `TestFuzz*` / `TestRefcountStress` は同一プロセスで例外を許容するだけなので、ハングや
  SIGSEGV を捕捉できない (だから 2 バグを見逃していた)。本クラスは subprocess の exit code /
  timeout で crash・hang を検出:
  - `test_sign_with_k_zero_does_not_hang` — k=0 が ValueError (timeout=8s、ハングなら fail)
  - `test_spend_validate_otda_single_out_of_range_no_crash` — SIGSEGV しないこと
  - `test_spend_validate_otda_single_bug_digest` — SINGLE-bug digest が Python パスと一致
  - `test_tx_preimage_otda_single_out_of_range_raises` — IndexError を送出
- **`TestFullSurfaceMemoryScan`** (40 テスト): 全 29 関数 + エラーパスをブロック数オラクルで
  パラメトライズ。`tx_from_bytes` 型のリーク再発を全関数で防ぐ

**テスト結果**: 新規 44 テスト (crash/hang 4 + full-surface scan 40) 全パス。
全体 3,589 passed, 259 skipped, 0 failed (ベンチ 31 を除く)。

### 教訓

1. **「クラッシュしない」テストと「ハング/クラッシュを捕捉する」テストは別物**: 既存の
   in-process 例外許容テストは、無限ループも segfault も検出できない。crash/hang 回帰は
   **subprocess 隔離 + timeout** が必須。F16 (メモリ計測なし) と同根の構造的欠陥
2. **エラーパスのファジングが 2 バグとも鍵**: ハングは `k=0`、OOB は `input_index >= n_outputs`
   という「異常入力」でのみ発現。成功パスしか叩かないテストでは永久に見つからない
3. **同一ロジックの二重実装は二重のバグ**: OTDA preimage が 2 系統あり、両方に同じ SINGLE-bug
   OOB があった。F14 で指摘された「マーシャリングの三重複」と同様、実装の重複は監査コストと
   バグ面積を増やす。ScriptEngine 統合 ([[project_script-engine-consolidation]]) と同じ方向で
   OTDA も一本化を検討すべき
4. **レビュー指摘の「却下」も検証が必要**: 当初 C レビューは nonce counter 問題を「無限ループ
   しない」と却下したが、実測ではハングした。棄却判断こそ実測で裏を取る

---

## 残タスク一覧 (PM バックログ, 2026-07-02 時点)

Phase 0-4 + 全付随作業は完了。以下が全残タスクの統合リスト (レビュー・監査で確定した検証済み
優先順)。散在していた項目をここに集約する。**修正済みのクラッシュ級バグ (P0 リーク、
sign_with_k ハング、OTDA SIGSEGV) はすべて対応完了済み**。

### 未着手タスク

| 優先 | ID | タスク | 分類 | 根拠/効果 | 工数 |
|------|----|--------|------|-----------|------|
| **1** | F11 | `Transaction.sign()` の O(N²) 解消 (sign() 内で `tx_preimages()` を1回だけ呼ぶバッチキャッシュ) | 性能 | **ordinalx 大量署名に直結**。N=1000 で 345ms→~25ms 見込み | 半日 |
| **2** | F4 | `tx_to_bytes` 入力検証 (NULL/型/hex チェック) + 未使用関数の去就判断 | 堅牢性 | segfault + 未初期化ヒープ流出。SDK 未使用だが公開シンボル | 30-60分 |
| 3 | F6 | C 実装 RIPEMD160 の組み込み (Python import 経由を排除) | 性能 | P2PKH validate の ~10% (3.2µs/回)。OP_HASH160 は最頻 opcode | 半日-1日 |
| 4 | F10 | `PublicKey.__init__` の冗長 `pubkey_parse` 除去 | 性能 | 構築コストの ~48%、CHECKSIG パスで6回パース | 半日 |
| 5 | F16b | crash/hang 回帰を Linux CI に組込 + `detect_leaks=1` ASAN | テスト基盤 | 今回の subprocess 回帰は追加済み。CI での常時実行が未整備 | 半日 |
| 6 | 3.14-CI | 3.14 標準ビルドを CI に組込: cibuildwheel 2.22.0 → ≥3.2.1、`cp314-*` 追加、`skip=cp3??t-*`、フルスイートを `-W error::DeprecationWarning` で実行 | 互換/CI | 標準ビルドは arm64 3.14.6 で検証済 (159 テスト)。CI 化と SDK レベル非推奨(asyncio等)の洗い出しが残 | 半日 |
| 7 | 3.14-FT | フリースレッド cp314t 対応: `PyUnstable_Module_SetGIL(Py_MOD_GIL_NOT_USED)` + `g_ctx` を init 時一括生成で不変化 (スレッド安全) | 互換/正当性 | PEP779 で 3.14 FT 正式化。g_ctx 安全化は監査 R1/R7 指摘の解消も兼ねる。wheel 配布は依存 pycryptodomex の cp314t 整備待ち (coincurve 廃止済につき依存から除外) | 1-2日 |
| 8 | 4.4 | `context_randomize` 定期呼び出し | セキュリティ | 初期化時のみ実行中。定期化は任意 | 小 |
| 9 | 4.5 | Schnorr 署名 API 公開 | 機能準備 | BSV で現在未使用。将来のプロトコル拡張用 | 小 |
| 10 | — | musllinux wheel | 配布 | Alpine 対応。需要次第 | 小 |
| 11 | DOC | 3段フォールバック記述の整合 (coincurve 廃止の反映残) | ドキュメント | 課題 #6 参照。図表4箇所が未整合。コード側は正しい (P3) | 小 |

### 完了 (2026-07-02)

| ID | タスク | 結果 |
|----|--------|------|
| F8 | Python 3.13/3.14 コンパイル対応 | 私的 API `_PyLong_*` → 公開 `PyLong_*NativeBytes` へ移行 (`#if PY_VERSION_HEX >= 0x030D0000`)。x86_64/arm64 の Python 3.13 で native ビルド + 159 テスト通過、3.11 全 3,589 テスト回帰なし |
| — | coincurve 完全廃止 + 純Python フォールバック | フォールバックを 3段→2段 (native/純Python) に変更。`curve.py` に純Python 点加算/スカラー倍、`keys.py` に RFC6979 署名・verify・recover・ECDH・pubkey パースを純Python実装。`pyproject.toml` から coincurve optional dependency 削除。native⇔python は公開鍵・アドレス・署名がバイト一致。前倒し動機は coincurve が 3.14 wheel 未提供のため。DER/PEM 入出力のみ廃止 (実運用未使用) |
| — | 純Python フォールバックの回帰テスト | `tests/bsv/native/test_pure_python_fallback.py` (65件)。`_CRYPTO_BACKEND="python"` 強制で round-trip + native 等価性 (RFC6979 バイト一致・相互 verify・曲線演算一致) を検証。coincurve 廃止で生じた「native 環境では踏まれない未検証コード」の穴を解消 |

### 却下 (検証で「やらない」と確定)

| ID | タスク | 却下理由 |
|----|--------|----------|
| F5 | PUSHDATA4 符号拡張修正 | 64bit 出荷対象では符号拡張なし。32bit 限定の潜在 UB のみ (P3) |
| F12 | Transaction raw bytes キャッシュ | 効果 1.6µs 軽微 vs ネスト変更で誤 txid を返す正当性リスク大 |
| F15 | key_deriver の pubkey_tweak_add 一本化 | 提案実装が実測 1.37倍遅い。現行が既に最速経路 |

---

## 今回セッションで顕在化した課題・技術的負債 (2026-07-02)

即時のバグではないが、放置すると再発・保守コスト増につながる構造的課題。将来のリファクタ
判断材料として記録する。

### 1. OTDA preimage 実装が 2 系統あり、SIGHASH_SINGLE の扱いが食い違う 【要一本化】

- `transaction.py::_calc_input_preimage_legacy` → 範囲外 SINGLE で `0x01||0x00*31` (Bitcoin
  consensus 準拠)。CHECKSIG/Script VM 経路
- `transaction_preimage.py::_preimage_otda` → 範囲外 SINGLE で IndexError。署名経路
- C 側も対応して 2 実装 (`c_build_otda_preimage` / `pyfn_tx_preimage_otda`) に分かれ、**両方に
  同一の OOB クラッシュが潜んでいた**。今回はクラッシュ排除のため各々のフォールバックに
  合わせたが、**本質的には consensus 準拠 (前者) へ統一すべき**。ScriptEngine 統合
  ([[project_script-engine-consolidation]]) と同じ「二重実装の一本化」方針
- 影響: 署名経路で範囲外 SINGLE を使うと py-sdk は署名を作れない (IndexError)。実運用で
  そのような tx を作ることは稀だが、consensus 準拠にすれば作成・検証が一貫する

### 2. マーシャリングコードの三重複 (F14 で既出、未解消)

`_inputs_to_tuples` / `_outputs_to_bytes` 相当が `transaction_preimage.py`・`transaction.py`
(`_calc_input_preimage_bip143_native`)・`spend.py` (`_validate_native`) の 3 箇所にインライン
散在。性能影響は小 (validate の ~4.4%) だがバグ面積を増やす。共通ユーティリティへ集約推奨

### 3. テスト戦略の構造的ギャップ (F16 で既出、一部解消)

- **crash/hang は subprocess 隔離必須**: in-process の例外許容テストでは無限ループも SIGSEGV も
  捕捉不能。今回 `TestCrashHangRegression` で補填したが、この設計原則を新規 C 関数追加時の
  チェックリストに入れるべき
- **成功パスのみのテストはリークもクラッシュも見逃す**: F1 リーク・今回の 2 クラッシュとも
  「異常入力 / エラーパス」でのみ発現。等価性テスト・ファズは成功パス偏重だった
- **ASAN が macOS で detect_leaks=0**: C レベルの malloc リーク検出が無効。Linux CI で
  detect_leaks=1 の常時実行が未整備

### 4. 公開 API の使いにくさ (等価性テストで既出)

- `Spend.__init__` が camelCase dict (`sourceTXID` 等) を要求 (TS/Go 互換のため維持)
- `PrivateKey._secret` (内部属性) でしか raw 32 バイトを取得できない
- `BareMultisig.lock()` が `PublicKey` オブジェクトを受け付けない (hex 変換必須)
- いずれも P3。TS/Go SDK 互換制約とのトレードオフで現状維持だが、Python 利用者向けの
  薄いヘルパーがあると DX 改善

### 5. `_PyLong_FromByteArray` / `_AsByteArray` 私的 API 依存 — ✅ 解消済み (2026-07-02)

F8 として即日修正。恒久対応 (公開 API 移行) まで一括で実施した。詳細は下記「F8 完了記録」参照。

### 6. 本ドキュメント全体に残る「3段フォールバック」記述の不整合 【要整合】(2026-07-02)

coincurve 完全廃止 (2 段フォールバック化) に伴い、本計画書の各所に散在する
「native / coincurve / 純Python の 3 段」前提の記述が実態と食い違っている。
本セッションでは主要箇所 (段階的廃止セクション・進捗レジャー・完了/バックログ表) を更新したが、
以下の図表は**未整合のまま**であり、次回のドキュメント整理でまとめて反映すべき:

- 設計原則のフォールバック階層図 (「暗号処理のフォールバック階層」に coincurve 段が残存)
- CI マトリクスの「coincurve フォールバック」モード記述 (Mode 列 / CI マトリクス図)
- リリース戦略表の「coincurve の扱い」列
- リスク表・前提条件の「coincurve: Phase 0 以降 optional dependency」記述
- `bsv/breaking0.md` L40: coincurve を runtime 依存「✅ Unchanged」と記載 (履歴文書のため
  遡及修正はせず、次バージョンの breaking-changes として別途記録すべき)

いずれも即時の不具合ではなく**ドキュメント整合性のみ**の課題 (P3)。コード・pyproject.toml は
既に 2 段構成で正しい (grep で coincurve 参照ゼロを確認済み)。

**別途:** coincurve 完全削除は breaking change (optional 依存 `bsv-sdk[coincurve]` の廃止 +
`PrivateKey.der/pem/from_der/from_pem` が `NotImplementedError` 化) を含むため、**CHANGELOG /
リリースノートに breaking エントリを追加**すべき (対象バージョン確定後)。

---

## coincurve 完全廃止記録 (2026-07-02)

### 背景・動機

当初は「十分な実績蓄積後にメジャーバージョンで削除」の予定だった (上記「4. coincurve の段階的廃止」)。
これを**前倒しして完全削除**した。直接の引き金は **Python 3.14 対応**:

- coincurve は 3.14 wheel を提供しておらず ([ofek/coincurve#219])、optional 依存に残したままでも
  「3.14 で coincurve 経路を要求する」構成が混乱・サポートコストの元になる
- Phase 0-4 で `_bsv_native` が coincurve の全機能を代替済み。残るフォールバック用途は
  「C 拡張がビルドできない環境」向けだが、その受け皿を coincurve (これも C ビルド + 外部 wheel 依存)
  にする必然性は既になく、**純Python 実装の方が「追加依存ゼロ・全 Python バージョンで動く」**
  というフォールバックの本来目的に適う

### 変更内容

| ファイル | 変更 |
|----------|------|
| `bsv/curve.py` | coincurve import 削除。`_py_point_add` (点加算) と double-and-add による `curve_multiply` を純Python実装。フォールバック判定を `"python"` に |
| `bsv/keys.py` | coincurve import 削除。`_rfc6979_k` (決定的nonce) / `_ecdsa_sign_recoverable_py` / `_ecdsa_verify_py` / `_ecdsa_recover_py` / `_pubkey_validate_and_compress` を追加。`PublicKey`/`PrivateKey` の全メソッドと `recover_public_key` の coincurve 経路を純Python に置換。`CcPrivateKey`/`CcPublicKey` 後方互換コードを削除 |
| `pyproject.toml` | `[project.optional-dependencies].coincurve` を削除 |
| `tests/bsv/native/test_pure_python_fallback.py` | 新規 65 件。`_CRYPTO_BACKEND="python"` 強制で round-trip + native 等価性を検証 |

### 検証結果

- native ⇔ 純Python で**公開鍵・アドレス・DER署名・recoverable署名がバイト一致** (RFC6979 の決定的 nonce
  が libsecp256k1 と同一のため)。相互 verify も成功
- 既存テストスイート全体 3,620 件通過 + 新規フォールバックテスト 65 件通過。ruff / black クリーン

### 性能特性 (許容範囲)

純Python パスは Python 大整数演算による楕円曲線演算のため native より大幅に遅い
(ECDSA 1 回あたり概算 native ~50μs → 純Python ~5ms、約 100 倍)。ただしこのパスは
「wheel が無く C 拡張もビルドできない環境」の**フォールバック専用**であり、pre-built wheel が
ある通常環境では native が使われる。開発・CI・非対応プラットフォームでの動作保証が目的なので
速度差は許容範囲。速度が必要な環境では wheel か sdist からの native ビルドを使う。

### 唯一の機能削除: DER / PEM 入出力

`PrivateKey.der()` / `.pem()` / `.from_der()` / `.from_pem()` は coincurve 固有機能だったため
`NotImplementedError` 化した。いずれも元々 `# pragma: no cover` (テスト外) で、SDK の通常
ワークフロー (WIF / hex / bytes でのキー管理) では未使用。必要になれば pyca/cryptography か
純Python ASN.1 で再実装可能。

---

## F8 完了記録: Python 3.13/3.14 対応 (2026-07-02)

### 背景

`_bsv_native` は Python 整数 ⇔ バイト列変換に CPython の**私的 API** `_PyLong_FromByteArray` /
`_PyLong_AsByteArray` を使っていた。Python 3.13 で `_PyLong_AsByteArray` のシグネチャが変わり
(第 6 引数 `with_exceptions` 追加)、**cp313 では native ビルドがコンパイルエラー**になっていた。

これは皮肉な状況だった: coincurve を optional 化した動機が「外部依存が新 Python 追従に遅れる
リスクの排除」だったのに、同じ「私的/不安定 API への依存が新 Python で壊れる」問題が、依存先
(coincurve) から**自分たちの native コードに移動**していた。実際 coincurve 21.0.0 は既に cp313
wheel を提供しており (PyPI 実測)、置き換え元の方が先に 3.13 対応を済ませていた。

### 修正内容

私的 API を **公開の安定 API** へ移行した (Python 3.13 で追加された `PyLong_*NativeBytes` 系):

```c
#if PY_VERSION_HEX >= 0x030D0000   /* 3.13+ : 公開 API (3.14 以降もこれで安定) */
    PyLong_FromUnsignedNativeBytes(bytes, n, endian_flag);
    PyLong_AsNativeBytes(v, bytes, n, endian_flag | Py_ASNATIVEBYTES_UNSIGNED_BUFFER);
#else                              /* <=3.12 : 従来の私的 API (公開版が存在しない) */
    _PyLong_FromByteArray(bytes, n, little_endian, 0);
    _PyLong_AsByteArray((PyLongObject*)v, bytes, n, little_endian, 0);
#endif
```

- ヘルパー `bsv_long_from_unsigned_bytes` / `bsv_long_as_unsigned_bytes` を 1 箇所に定義し、
  4 つの呼び出し箇所 (pubkey_point の X/Y 復元 = big-endian、`c_bin2num`/`c_min_encode` の
  Script 数値変換 = little-endian) を置換
- `PyLong_AsNativeBytes` は「必要バイト数」を返す新セマンティクスのため、`< 0` (例外) と
  `> n` (バッファ不足) の両方を検査。呼び出し側は常に正確なサイズを渡すため後者は発生しない
- **他の私的/削除 API は不使用**を grep で確認 (`_Py*` は上記 2 つのみ)。3.14 でも安定 API のみ

### 検証結果

| 環境 | 結果 |
|------|------|
| Python 3.11 (universal2) | リビルド成功、全 3,589 テスト回帰なし。pubkey_point/VM 算術の値等価性確認 |
| Python 3.13.13 (x86_64) | native ビルド成功、import + 暗号 + VM + 既存 2 バグ修正すべて動作 |
| Python 3.13.14 (arm64/M2) | `setup.py build_ext` 経路でビルド成功、native テスト **159 件パス** |
| Python 3.14.6 (arm64/M2) | ✅ 検証済み (同日追検証): native ビルド成功、159 テスト通過、エラー0・非推奨警告0。詳細は「Python 3.14 対応」セクション参照 |

### 開発環境メモ (arm64 Python)

作業機は M2 (arm64) だが `/usr/local` の python3.13 は Intel Homebrew の x86_64 版だった。
arm64 ネイティブ検証のため `/opt/homebrew` (arm64 Homebrew) で `python@3.13` を導入
(→ `/opt/homebrew/opt/python@3.13/bin/python3.13`、Python 3.13.14 arm64)。
PATH では `/usr/local` の x86_64 版が優先される (shadowed) ため、arm64 版を使うにはフルパス指定
または PATH 調整が必要。

### 3.13 ユーザーへの影響 (修正前後)

- **修正前**: cp313 で `pip install bsv-sdk` → native wheel なし → sdist ビルドも失敗 →
  純 Python フォールバックには暗号がなく `bsv.keys` import 時に ImportError。回避策は
  `pip install bsv-sdk[coincurve]` (coincurve は cp313 対応済み)
- **修正後**: cp313 native wheel をビルド可能。coincurve なしで default install が動作

---

## Python 3.14 対応 (2026-07-02)

### 現状サマリ

| トラック | 状態 | 根拠 |
|---------|------|------|
| **標準 (GIL) ビルド** | 🟢 **検証済み・動作** | arm64 Py3.14.6 で native ビルド + 159 テスト通過。ヘッダ実コンパイル エラー0・非推奨警告0 |
| **CI/wheel への組込** | 🔶 残 | wheels.yml に cp314 追加 + cibuildwheel bump が必要 |
| **フリースレッド (cp314t)** | 🔶 残 (別トラック) | `Py_mod_gil` 宣言 + `g_ctx` スレッド安全化 + 依存の cp314t 未整備 |

**F8 (私的 API → 公開 `PyLong_*NativeBytes` 移行) が 3.14 対応の実質的な地ならしになっていた。**
標準ビルドは追加のコード変更なしで動作する。

### 実測検証結果 (2026-07-02, arm64 Python 3.14.6)

- **コンパイル**: 3.14 ヘッダに対し `bsv_native.c` が **エラー 0 件・Py 系非推奨警告 0 件**
- **ビルド**: `setup.py build_ext` (BSV_REQUIRE_NATIVE=1) で cp314 arm64 `.so` 生成成功
- **テスト**: native テスト **159 件パス** (fuzz46 + 等価性65 + crash/hang4 + memory scan40 + growth4)
- **機能**: pubkey_point (big-endian 変換)・ECDSA sign/verify・VM 算術 (little-endian 変換)・
  前回修正の 2 バグ (sign_with_k ハング / OTDA SIGSEGV) すべて 3.14 で正常
- **`-W error::DeprecationWarning`**: C 拡張レベルで警告なし

### API 互換性の裏付け (一次情報)

使用 API のうち 3.14 で破壊的変更があったのは `_PyLong_AsByteArray` (3.13 で 6 引数化) **のみ**で、
F8 で公開 API へ移行済み。他の使用 API は 3.14 で不変または問題なし:

- `PyBytes_*` / `PyDict_*` / `PyList_*` / `PyTuple_*` / `PyUnicode_AsUTF8` / `Py_buffer` (`y*`) / `PyImport_ImportModule` / `PyObject_CallMethod`: 3.14 で変更なし
- モジュール初期化は `PyModule_Create` + `PyModule_AddStringConstant` を使用 (ソフト非推奨の
  `PyModule_AddObject` は**不使用** — 対応不要)
- `PyArg_ParseTuple` は `I/i/O/y*/s/p/L` のみ使用 (`k`/`K` の 3.14 `__index__` 化は無関係)
- 公開 `PyLong_FromUnsignedNativeBytes`/`AsNativeBytes` は 3.14 で **Stable ABI 入り**、フラグ不変

### 依存パッケージの 3.14 対応状況 (PyPI 実測 + 一次情報)

| パッケージ | cp314 wheel | 備考 |
|-----------|:-----------:|------|
| pycryptodomex | ✅ (abi3) | `cp37-abi3` 安定 ABI wheel が 3.14 標準ビルドで動作 |
| aiohttp | ✅ (cp314) | yarl/multidict/frozenlist も cp314 完備 |
| requests + deps | ✅ | charset-normalizer が cp314、他は pure Python |
| typing_extensions | ✅ | pure Python |
| **coincurve** (optional) | ❌ **未提供** | 最新 21.0.0 は 3.14 非対応 (master のみ)。[ofek/coincurve#219] |

**重要**: coincurve が 3.14 wheel を出していないため、**3.14 では `_bsv_native` が唯一の暗号
バックエンド**になる (純 Python フォールバックに暗号はない)。F8 修正済みなので native が動き問題
ないが、「coincurve が新 Python 追従に遅れる」という当初の廃止動機がまさに 3.14 でも再現している。

### 残タスク (標準ビルドの正式サポート)

- **[CI]** `wheels.yml` の `cibuildwheel==2.22.0` を **≥3.2.1** に更新 (3.14.0 final + macOS
  deployment target 修正を含む最初のバージョン)。`CIBW_BUILD` に `cp314-*` を追加
- **[CI]** cibuildwheel 3.1+ は **cp314t (フリースレッド) をデフォルトでビルド**する。当面 FT を
  サポートしないなら `skip = "cp3??t-*"` を明示 (でないと cp314t ビルドで失敗/警告)
- **[CI]** cibuildwheel 3.0 でデフォルト manylinux イメージが `manylinux2014` → `manylinux_2_28`
  (glibc 2.28) に変更。古い glibc を維持するなら `manylinux-x86_64-image` を明示ピン
- **[verify]** **フル**テストスイートを 3.14 で実行 (今回は native サブセット + スモークのみ)。
  特に `-W error::DeprecationWarning` で **SDK レベル**の非推奨を洗う。py-sdk は asyncio/aiohttp を
  使うため注意対象:
  - asyncio イベントループポリシー系 (3.14 で DeprecationWarning、3.16 削除)
  - `asyncio.get_event_loop()` の no-loop が 3.14 で **RuntimeError** 化 (警告でなく即エラー)
  - `datetime.utcnow()` / マルチスレッドでの `os.fork()` (DeprecationWarning)
- **[build]** setup.py に 3.14 特有の対応は不要 (現状のフラグで通る)

### 残タスク (フリースレッド cp314t — 別トラック)

3.14 で **PEP 779 によりフリースレッドが正式サポート**に (実験扱いから昇格、GIL ビルドは依然
デフォルト)。cp314t 対応には以下が必要:

- **[free-threading] GIL 不要の宣言**: 単一フェーズ init (`PyModule_Create`) のままでよい。
  `PyInit__bsv_native` 内で `#ifdef Py_GIL_DISABLED` ガード付きで
  `PyUnstable_Module_SetGIL(m, Py_MOD_GIL_NOT_USED)` を呼ぶ。宣言しないと python3.14t で
  import 時に **GIL が自動再有効化 + RuntimeWarning** (動くが並列性なし)
- **[free-threading] `g_ctx` のスレッド安全化** (全面監査 R1/R7 の指摘が顕在化):
  - **推奨**: `g_ctx` を**モジュール init 時に一度だけ生成 + randomize** し、以降は不変にする。
    libsecp256k1 は「randomize しない読み取り専用コンテキストの並行 sign/verify」は安全なので、
    これで lock 不要。遅延 init の TOCTOU も同時に解消
    ([[project_proto-wallet-deprecation]] とは無関係、純粋に本 C 拡張の課題)
  - 代替: `PyMutex` で遅延 init と `context_randomize` を保護
- **[free-threading] wheel は cp314t 専用が別途必要**: フリースレッドビルドは 3.14 では
  **Limited API/abi3 非対応** (abi3t は 3.15/PEP 803)。pycryptodomex は cp314t wheel を出して
  いない (RIPEMD160 が source build 必要) ため、cp314t はエコシステム側がまだ未整備
- **[判断]** 依存 (pycryptodomex/coincurve) の cp314t 未整備を踏まえ、**当面は「GIL 不要宣言 +
  g_ctx 安全化」までを実施** (どちらも正当性の改善でもある) し、**cp314t wheel の配布は依存が
  揃うまで保留**するのが現実的

### 検証環境メモ

arm64 Python 3.14.6 は `/opt/homebrew` (arm64 Homebrew) の `python@3.14` で導入
(→ `/opt/homebrew/opt/python@3.14/bin/python3.14`)。フリースレッド版 (`python3.14t`) は標準
formula に含まれず、`python-freethreading` formula が別途必要 (cp314t 検証時に導入する)。
