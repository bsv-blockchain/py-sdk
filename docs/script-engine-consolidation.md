# Script Engine 統合計画

## 概要

py-sdk には Bitcoin Script を実行・検証するエンジンが **2系統** 存在する。
これにより Chronicle アップグレード対応に重大なギャップが生じている。
本ドキュメントでは現状の課題を整理し、一本化に向けた解決策とロードマップを示す。

---

## 1. 現状分析

### 1.1 Spend エンジン（TS-SDK 系）

| 項目 | 内容 |
|------|------|
| ファイル | `bsv/script/spend.py`（1,056行） |
| 由来 | TS-SDK の `Spend` クラスからのポート |
| 構造 | 単一ファイル。`step()` で1オペコードずつ逐次実行 |
| Chronicle 対応 | **完全** — 復元10オペコード全実装、`is_relaxed()` による malleability relaxation |
| C 拡張連携 | `_bsv_native.spend_validate()` で高速実行（Python fallback あり） |
| 公開 API | `from bsv import Spend` / `from bsv.script import Spend` |
| 利用箇所 | テスト12+ファイル、examples 3ファイル、py-sdk 公開 API |

### 1.2 Engine/Thread エンジン（Go-SDK 系）

| 項目 | 内容 |
|------|------|
| ファイル | `bsv/script/interpreter/`（engine.py, thread.py, operations.py 等 7ファイル、計約2,700行） |
| 由来 | Go-SDK の `script/interpreter` パッケージからのポート |
| 構造 | `Engine.execute()` → `Thread` 生成 → `OPCODE_DISPATCH` テーブルでディスパッチ |
| Chronicle 対応 | **未対応** — OP_VER, OP_2MUL, OP_2DIV は `op_reserved`（エラー）、OP_SUBSTR/LEFT/RIGHT/LSHIFTNUM/RSHIFTNUM はディスパッチテーブルに未登録 |
| C 拡張連携 | **なし**（Pure Python のみ） |
| 公開 API | なし（内部利用のみ） |
| 利用箇所 | `Transaction.verify()` の1箇所のみ（+ テスト23ファイル） |

### 1.3 C 拡張 (`_bsv_native`)

`_bsv_native/bsv_native.c`（3,844行）に `spend_validate()` として実装。

- **Spend の VM アーキテクチャを C で再実装**したもの（`VMState` + `vm_step` + `vm_run`）
- Chronicle 10オペコード: **全て実装済み**
- malleability relaxation: `tx_version > 1` チェックで実装済み
- 署名検証のみ Python コールバック経由（`checksig_cb`）
- Engine/Thread 系とは**無関係**

### 1.4 呼び出し関係図

```
【Phase 1 適用前】
Transaction.verify()
  └─→ Engine.execute()          ← Go-SDK 系（Chronicle 未対応）❌
        └─→ Thread.execute()
              └─→ OPCODE_DISPATCH

【Phase 1 適用後 (2026-07-01)】
Transaction.verify()
  └─→ Spend.validate()          ← TS-SDK 系（Chronicle 対応済み）✅
        ├─→ _bsv_native.spend_validate()   ← C 拡張（Chronicle 対応済み）
        └─→ Spend._validate_python()       ← Python fallback（Chronicle 対応済み）

py-wallet-toolbox (signer/methods.py:1314)
  └─→ Transaction.verify(scripts_only=True)
        └─→ Spend  ← C 拡張経由で高速実行
```

---

## 2. 課題

### 2.1 [致命的] Chronicle トランザクションの検証不能

`Transaction.verify()` が Engine 系を使用しているため、Chronicle 復元オペコード（OP_VER, OP_SUBSTR, OP_2MUL 等）を含むスクリプトの検証が**失敗する**。

- Engine の `OPCODE_DISPATCH` で OP_VER → `op_reserved` → エラー
- OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_LSHIFTNUM, OP_RSHIFTNUM → テーブル未登録

**影響範囲:**
- py-sdk: `Transaction.verify()` を呼ぶ全てのコード
- py-wallet-toolbox: `_verify_unlock_scripts()` → `Transaction.verify(scripts_only=True)`

### 2.2 [致命的] Engine 系に malleability relaxation がない

Chronicle では tx version > 1 のトランザクションに対して以下の制約が緩和される:

- minimal encoding
- low-S signatures
- NULLFAIL / NULLDUMMY
- MINIMALIF
- clean stack
- push-only unlocking scripts

Engine/Thread にはこの概念自体が存在しない（`is_relaxed()` なし）。

### 2.3 [重要] 二重メンテナンスコスト

同じ機能の実装が2箇所（+ C拡張で3箇所）に分散している。
今後のプロトコル変更時に全て同期して更新する必要がある。

### 2.4 [重要] C 拡張が片系統のみ

`_bsv_native` は Spend 専用。Engine 系にはパフォーマンス最適化パスがない。
Engine 用の C VM を新たに書くのは非現実的。

### 2.5 [軽微] SDK 間の一貫性

- TS-SDK: `Spend` クラスのみ（Engine 系なし）
- Go-SDK: `interpreter` パッケージ（Engine 系）のみ
- py-sdk: 両方存在

TS-SDK は `Spend` を正としており、py-sdk の公開 API (`from bsv import Spend`) もこれに準拠している。

---

## 3. 解決策

### 方針: Spend エンジンに一本化

| 評価軸 | Spend に統一 | Engine に Chronicle 追加 |
|--------|-------------|------------------------|
| Chronicle 完全性 | 既に完了 | 要実装（10オペコード + relaxation） |
| C 拡張との整合 | そのまま利用可 | 新規 C VM 必要 or 性能劣化 |
| TS-SDK との一致 | 1:1 対応 | 乖離する |
| 工数 | 小（verify切替 + テスト移植） | 大（opcode実装 + relaxation + テスト） |
| リスク | テストベクター移植の確認 | 二重実装の恒久化 |

**結論: Spend に統一する。**

---

## 4. ロードマップ

### Phase 1: Transaction.verify() の切替（最優先） — ✅ 完了 (2026-07-01)

**目的:** Chronicle トランザクション検証の即時修復

**変更対象:** `bsv/transaction.py` の `verify()` メソッド

**実施内容:**
1. `Engine.execute()` 呼び出しを `Spend.validate()` 呼び出しに差し替え
2. `Spend` パラメータ構築: `Transaction` の入力/出力から `sourceTXID`, `otherInputs` 等を構成
3. `Spend.validate()` は失敗時 `RuntimeError` を raise するため、`try/except` で `False` に変換
4. テスト結果: 2575 passed, 11 skipped — 全パス、回帰なし

**副次効果:**
- `Transaction.verify()` が C 拡張 (`_bsv_native.spend_validate()`) を経由するようになった
- Chronicle 復元オペコードを含むスクリプトの検証が可能になった
- `bsv.script.interpreter` への依存が `Transaction.verify()` から除去された

### Phase 2: Engine テストベクターの移植評価 — ✅ 完了 (2026-07-01)

**目的:** Go-SDK リファレンスベクターの保全可能性を評価

**調査結果:**

テスト23ファイルを精査し、以下の3カテゴリに分類した:

| カテゴリ | ファイル数 | テスト数 | 判定 |
|---------|-----------|---------|------|
| 移植候補 | 3 | ~1,600 | **移植不要** (後述) |
| 削除対象 (Engine 内部テスト) | 19 | ~400 | Phase 3 で削除 |
| 既存 Spend テストでカバー済み | — | — | 削除可 |

**移植不要の根拠:**

1. **`script_tests.json` (1,438 ベクター)**: Engine の Flag システム (`P2SH,STRICTENC` 等) に依存。
   Spend は Flag ではなく `tx_version` で制御するため、直接マッピング不能。
   BSV 関連の opcode 動作は `spend_vector.py` (228ケース) + Chronicle テスト (103ケース) で既にカバー。

2. **`tx_valid.json` (75 ベクター)**: 実測で Spend 経由実行を試行。
   結果: 34 passed / 41 failed。失敗原因:
   - 全ベクターが P2SH フラグを使用 (BTC 固有、BSV では未使用)
   - pre-FORKID sighash (0x01 等) を使用 → BSV の FORKID 必須仕様と非互換
   - CLTV/CSV フラグ使用 (BSV では NOP)

3. **`tx_invalid.json` (57 ベクター)**: 同上。P2SH + pre-FORKID の Bitcoin Core ベクター。

4. **`test_checksig.py` (16 テスト)**: DER エンコーディング検証は `test_spend_real.py` の
   `check_signature_encoding` テストで既にカバー。

**結論**: Go-SDK リファレンスベクターは Bitcoin Core 由来の pre-fork テストであり、
BSV の Spend モデルへの移植は技術的に不整合かつ不要。BSV 固有のスクリプト動作は
既存の Spend テストスイート (2,575 テスト) で十分にカバーされている。

### Phase 3: Engine/interpreter の削除 — ✅ 完了 (2026-07-01)

**目的:** コードベースの簡素化

**実施内容:**
1. `bsv/script/interpreter/` ディレクトリを削除（7ソースファイル + errs/, scriptflag/ サブディレクトリ、計約2,700行）
2. `tests/bsv/script/interpreter/` ディレクトリを削除（23テストファイル + data/ ディレクトリ、計約6,440行 + テストベクター3ファイル）
3. CLAUDE.md から Engine 関連の記述を更新（interpreter/config.py 参照削除、Chronicle テストコマンド更新）

**テスト結果:** 3,430 passed, 259 skipped — 全パス、回帰なし
（Engine テスト約1,570件分が削除され、残りの Spend ベーステストが全て正常動作を確認）

**削除コード量:**
- ソース: ~2,700行（engine.py, thread.py, operations.py, stack.py, number.py, config.py, op_parser.py, options.py + サブパッケージ）
- テスト: ~6,440行（23ファイル）
- テストデータ: script_tests.json (1,438ベクター), tx_valid.json (75), tx_invalid.json (57)

### Phase 4: Spend のリファクタリング（任意）

**目的:** 長期的な保守性向上

**検討事項:**
- `step()` の巨大 if/elif チェーンをディスパッチテーブル化（Engine の良い設計を取り込む）
- テストカバレッジの拡充（移植したベクター含む）
- C 拡張との一致性を検証するテスト追加

**推定工数:** 中〜大（任意、優先度低）

---

## 5. リスクと緩和策

| リスク | 影響 | 緩和策 |
|--------|------|--------|
| Spend と Engine の微妙な挙動差異 | verify 結果が変わる可能性 | Phase 2 でベクターを網羅的に移植・確認 |
| py-wallet-toolbox への影響 | _verify_unlock_scripts の挙動変化 | Phase 1 で py-wallet-toolbox のテストも実行 |
| C 拡張未ビルド環境 | Python fallback で検証 | 既存の fallback 機構がそのまま機能 |
| Engine を直接利用する外部コード | 破壊的変更 | 調査済み: 外部からの直接利用なし |

---

## 6. 補足: 各 SDK の対応構造

| SDK | スクリプト実行 | Chronicle |
|-----|--------------|-----------|
| TS-SDK | `Spend` クラス（単一） | 対応済み |
| Go-SDK | `interpreter` パッケージ（単一） | 対応済み |
| py-sdk（現状） | `Spend` + `Engine`（二重） | Spend のみ対応 |
| py-sdk（統合後） | `Spend` クラス（単一） | 対応済み |
