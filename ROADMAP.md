# ROADMAP

Until version 1.0 of this library is released, the roadmap is being managed internally by the development team. Please reach out if you have
any questions.

## 直近の達成 (2026-07)

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
- [ ] **堅牢性: `tx_to_bytes` 入力検証** (F4) — 異常入力での segfault 防止
- [ ] 性能・テスト基盤の追い込み — RIPEMD160 C 化 (F6)、冗長 pubkey_parse 除去 (F10)、
      crash/hang 回帰の CI 常時実行 (F16b)
- [ ] (任意) `context_randomize` 定期化 (4.4)、Schnorr 署名 API (4.5)、musllinux wheel
- [ ] C拡張された py-sdk を試す — `_bsv_native` モジュールによる高速化の検証・評価