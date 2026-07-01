# Script Engine 統合 — 完了報告

**状態: ✅ 完了 (2026-07-01)**
**実施者: ken@yenpoint.jp + Claude**

py-sdk に存在した 2 系統の Script エンジン（Spend / Engine）を Spend に一本化した。
Chronicle アップグレード対応の致命的ギャップを解消し、コードベースを約 9,100 行削減した。

---

## 背景

py-sdk には Bitcoin Script を実行・検証するエンジンが **2 系統**存在していた。

| エンジン | 由来 | Chronicle | C 拡張 | 公開 API |
|---------|------|-----------|--------|---------|
| **Spend** (`bsv/script/spend.py`, 1,056行) | TS-SDK ポート | **対応済み** | `_bsv_native.spend_validate()` | `from bsv import Spend` |
| **Engine** (`bsv/script/interpreter/`, 7ファイル, ~2,700行) | Go-SDK ポート | **未対応** | なし | なし (内部のみ) |

`Transaction.verify()` が Engine を使用していたため、Chronicle 復元オペコード
（OP_VER, OP_SUBSTR, OP_2MUL 等）を含むスクリプトの検証が**失敗**していた。

### 課題一覧

| # | 深刻度 | 課題 | 解決 |
|---|--------|------|------|
| 1 | 致命的 | Chronicle トランザクションの検証不能 | Phase 1 で解消 |
| 2 | 致命的 | Engine に malleability relaxation がない | Phase 1 で解消 |
| 3 | 重要 | 二重メンテナンスコスト (~2,700行 + テスト ~6,440行) | Phase 3 で解消 |
| 4 | 重要 | C 拡張が Spend のみ対応 | Phase 3 で解消 (Engine 削除) |
| 5 | 軽微 | SDK 間の一貫性 (TS=Spend, Go=Engine, py=両方) | Phase 3 で解消 |

---

## 実施内容

### Phase 1: Transaction.verify() の切替 — ✅ 完了

`bsv/transaction.py` の `verify()` メソッドを `Engine.execute()` から `Spend.validate()` に差し替え。

- `Spend` パラメータ構築: Transaction の入力/出力から `sourceTXID`, `otherInputs` 等を構成
- `Spend.validate()` は失敗時 `RuntimeError` を raise → `try/except` で `False` に変換
- テスト結果: 2,575 passed, 11 skipped — 回帰なし

**副次効果:**
- `Transaction.verify()` が C 拡張経由で高速実行されるようになった
- Chronicle 復元オペコードの検証が即座に可能になった

### Phase 2: Engine テストベクター移植評価 — ✅ 完了 (移植不要)

Engine の 23 テストファイルを精査し、Go-SDK リファレンスベクターの移植可能性を評価した。

**結論: 移植不要。** 理由:

1. **`script_tests.json` (1,438 ベクター)**: Engine の Flag システム (`P2SH,STRICTENC` 等) に依存。Spend は `tx_version` で制御するため直接マッピング不能。BSV 関連動作は既存 Spend テスト (228+103 ケース) でカバー済み
2. **`tx_valid.json` (75 ベクター)**: 実測で 34 passed / 41 failed。全ベクターが P2SH + pre-FORKID sighash (BTC 固有) を使用し、BSV の FORKID 必須仕様と非互換
3. **`tx_invalid.json` (57 ベクター)**: 同上
4. **`test_checksig.py` (16 テスト)**: DER エンコーディング検証は `test_spend_real.py` でカバー済み

### Phase 3: Engine/interpreter の削除 — ✅ 完了

| 削除対象 | 内容 | 行数 |
|---------|------|------|
| `bsv/script/interpreter/` | ソース 7 ファイル + errs/, scriptflag/ | ~2,700行 |
| `tests/bsv/script/interpreter/` | テスト 23 ファイル + data/ | ~6,440行 |
| テストデータ | script_tests.json, tx_valid.json, tx_invalid.json | 1,570 ベクター |
| CLAUDE.md | Engine 関連記述の更新 | — |

テスト結果: 3,430 passed, 259 skipped — 回帰なし

### Phase 4: Spend リファクタリング — スキップ (C 拡張に吸収)

当初検討していた内容:
- `step()` のディスパッチテーブル化 → C 拡張 Phase 3a で `opcode_table[256]` として実現済み
- テストカバレッジ拡充 → C 拡張計画の品質テスト（等価性・ファズ）に統合
- C 拡張との一致性テスト → 同上

Python 側の `step()` は fallback 用途のため、構造変更は C/Python 等価性検証のリスクが上回る。

---

## 統合後のアーキテクチャ

```
Transaction.verify()
  └─→ Spend.validate()
        ├─→ _bsv_native.spend_validate()   ← C 拡張（推奨、高速）
        └─→ Spend._validate_python()       ← Python fallback

py-wallet-toolbox (signer/methods.py)
  └─→ Transaction.verify(scripts_only=True)
        └─→ Spend  ← C 拡張経由で高速実行
```

### 各 SDK の対応構造（統合後）

| SDK | スクリプト実行 | Chronicle |
|-----|--------------|-----------|
| TS-SDK | `Spend` クラス（単一） | 対応済み |
| Go-SDK | `interpreter` パッケージ（単一） | 対応済み |
| **py-sdk** | **`Spend` クラス（単一）** | **対応済み** |

---

## 関連ドキュメント

- C 拡張計画: `docs/c-extension-plan.md` — 課題 #6 に Engine 統合の記録あり
- CHECKMULTISIG バグ修正: `docs/c-extension-plan.md` 末尾の詳細調査報告
