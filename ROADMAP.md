# ROADMAP

Until version 1.0 of this library is released, the roadmap is being managed internally by the development team. Please reach out if you have
any questions.

## 直近の達成 (2026-08)

- **Script VM 全面パリティ監査完了** — BSV Node C++ (`interpreter.cpp`) を基準に
  全 87 オペコードを 1:1 照合。22 件の不一致を Python VM / native C 拡張の両方で修正。
  149 テストを `test_vm_parity.py` に集約（うち 95 テストが全オペコードのデュアルパス等価テスト）。
  TS-SDK / Go-SDK の問題 5 件も特定。詳細: [docs/vm-parity-audit-report.md](docs/vm-parity-audit-report.md)
  - ブランチ: `fix/vm-full-parity`（11 fixブランチを統合 + 追加修正 6 件）
  - 全テストスイート: 4,263 passed / 0 failed

## 達成済み (2026-07)

- **C拡張 `_bsv_native` (Phase 0-4 完了)** — libsecp256k1 統合、Tx パース/シリアライズ、
  Script チャンク、MerklePath、Preimage 構築、Script VM、BRC-42 鍵導出を C 化。
  全面的なリーク/クラッシュ監査 + ファズ/等価性テスト済み
- **coincurve 完全廃止** — フォールバックを 3段 (native/coincurve/純Python) →
  2段 (native/純Python) に簡素化。C拡張が無い環境でも**追加依存ゼロ**で動作し、
  Python 3.14 (coincurve が wheel 未提供) のブロッカーを解消
- **Python 3.13/3.14 コンパイル対応** — 私的 API を公開 API へ移行 (F8)

詳細な進捗・技術メモ・残タスクは [docs/c-extension-plan.md](docs/c-extension-plan.md) を参照。

## Upcoming — 次にやること

高頻度・実運用に近い順 (詳細と工数は c-extension-plan.md「残タスク一覧」参照):

- [ ] **Python 3.14 正式サポート** — CI に cp314 標準ビルドを組込 (cibuildwheel bump)、
      その後 free-threading (cp314t) 対応。標準ビルドは手元検証済み・CI 化が残
- [ ] **性能: `Transaction.sign()` の O(N²) 解消** (F11) — 大量署名 (ordinalx 等) に直結
- [x] **堅牢性: `tx_to_bytes` 入力検証** (F4) — version/locktime 範囲、script 型、source_txid 形式、dict キー欠落の全検証を追加。サブクラス安全な native dispatch に変更
- [ ] 性能・テスト基盤の追い込み — RIPEMD160 C 化 (F6)、冗長 pubkey_parse 除去 (F10)、
      crash/hang 回帰の CI 常時実行 (F16b)
- [ ] **ASan CI 実行** — Linux CI で `LD_PRELOAD` + ASan ビルドによる native テスト実行。UBSan はローカルでパス済み、ASan は macOS SIP 制限で未実行
- [ ] **Go SDK 固定ベクトル拡充** — Go SDK のテストベクトルを取り込み、クロス SDK 等価性を検証
- [ ] (任意) `context_randomize` 定期化 (4.4)、Schnorr 署名 API (4.5)、musllinux wheel
- [ ] C拡張された py-sdk を試す — `_bsv_native` モジュールによる高速化の検証・評価

## 既知の課題

- **TS SDK に同一の varint off-by-one バグ** — `ts-sdk` の `SatoshisPerKilobyte.ts` 内
  `getVarIntSize` が py-sdk と同じ `> 253` / `> 2**16` / `> 2**32` を使用。
  Go SDK は正しい。upstream への issue/PR が必要
- **TS-SDK: `OP_LSHIFTNUM` サイズ上限チェックなし** — BigInt の `<<` をそのまま使用。
  C++ は `CScriptNum::operator<<=` で事前にサイズ検証。コンセンサス乖離の可能性あり (HIGH)
- **Go-SDK: `OP_NOP11`+ を NOP 扱い** — `opcodeNop` にマッピングしているが、
  C++ では `SCRIPT_ERR_BAD_OPCODE` で即エラー。コンセンサス乖離 (HIGH)
- **Go-SDK: `OP_LSHIFTNUM` 上限の計算式が C++ と異なる** — `shift > MaxScriptNumberLength * 8`
  でチェックするが、C++ はシフト量ではなく結果サイズを検証 (MEDIUM)
- **py-sdk: スタックメモリ制限なし** — C++ はポリシーレベルで制限。DoS 保護の差異 (LOW)
- **py-sdk: `MAX_SCRIPT_ELEMENT_SIZE` が 1GB フラットキャップ** — C++ は Post-Genesis で
  スタック要素単体の上限なし (LOW)