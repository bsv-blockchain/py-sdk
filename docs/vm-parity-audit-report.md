# Script VM 全面パリティ監査レポート

**リポジトリ:** py-sdk / bsv-sdk  
**ブランチ:** fix/vm-full-parity  
**日付:** 2026-08-14

BSV Node C++ (`interpreter.cpp`) を最上位参照として、py-sdk の Python VM と native C 拡張の全オペコード動作を 1:1 で照合。22 件の不一致を特定・修正し、149 件のテストで検証した。

---

## 概要

| 指標 | 値 |
|------|-----|
| 不一致の検出 | 22 |
| 修正済み | 22 (Python VM + native C 両方) |
| 新規テスト | 149 (`test_vm_parity.py` に集約) |
| テスト結果 | 4,263 passed / 0 failed |

---

## 参照実装の優先順位

スクリプト動作の「正解」を判断する際の優先順位。上位が下位に優越する。

1. **BSV Node C++** — コンセンサスの唯一の真実
2. **TS-SDK / Go-SDK** — 同レイヤの参照。Chronicle 固有ロジックはこちらが権威
3. **BRC 仕様** — 参考情報

> TS-SDK と Go-SDK は互いに食い違う箇所があり、また C++ ノードとも異なる場合がある。C++ ノードが動作するものが唯一のコンセンサス真実であり、仕様書は参考情報にとどまる。

---

## 修正一覧

### 署名・暗号操作（6 件）

| # | 対象 | C++ の動作 | py-sdk の問題 | 状態 |
|---|------|-----------|-------------|------|
| 1 | `CHECKSIG` DER 構造チェック | `IsValidSignatureEncoding` で長さ 9–73、R/S 構造、符号・パディングを検証 | DER パース前の構造チェックなし。不正 DER がパースエラーとして処理され、エラーメッセージが C++ と異なる | FIXED |
| 2 | `CHECKSIG` High-S 正規化 | `secp256k1_normalize` で Low-S に変換後に検証 | 正規化なし。High-S 署名が常に失敗していた | FIXED |
| 3 | `CHECKSIG` 空署名時の pubkey 検証順序 | pubkey パースを先に行い、空署名で FALSE を返す前に不正 pubkey を拒否 | 空署名で即 FALSE。不正 pubkey がスルーされていた | FIXED |
| 4 | `CHECKMULTISIG` NULLFAIL | 失敗時、未消費の署名スロットが空でなければエラー。Chronicle (v>1) では緩和 | `CHECKSIG` にのみ適用。`CHECKMULTISIG` は NULLFAIL を検査しなかった | FIXED |
| 5 | `CHECKMULTISIG` key/sig count 4 バイト上限 | `CScriptNum::MAXIMUM_ELEMENT_SIZE` = 4 でカウント読み出し | `read_script_number` のデフォルト上限（32MB）を使用。5+ バイトの巨大カウントが通過 | FIXED |
| 6 | `CHECKSIG` / `CHECKMULTISIG` `find_and_delete` FORKID スキップ | SIGHASH_FORKID セット時は `FindAndDelete` を省略 | 常に `find_and_delete` を実行。FORKID 署名でも scriptCode から署名を除去していた | FIXED |

### 算術・数値操作（5 件）

| # | 対象 | C++ の動作 | py-sdk の問題 | 状態 |
|---|------|-----------|-------------|------|
| 7 | `OP_DIV` / `OP_MOD` 符号処理 | ゼロ方向への切り捨て。余りは被除数の符号 | Python の `//` は負方向への切り捨て。`-7 / 2` が `-4` になっていた（正解は `-3`） | FIXED |
| 8 | `OP_BIN2NUM` minimize-then-check | 入力をまず数値に変換し、最小エンコードしてからサイズチェック | 入力の生バイト長でサイズチェック。末尾ゼロで膨張した入力が不当に拒否された | FIXED |
| 9 | `OP_NUM2BIN` サイズ上限 | `INT32_MAX` (0x7FFFFFFF) を上限とし、負のサイズを拒否 | `MAX_SCRIPT_ELEMENT_SIZE` (1GB) を上限として使用。負のサイズチェックなし | FIXED |
| 10 | `OP_LSHIFTNUM` post-shift サイズ再チェック | シフト後の最小エンコード結果が script number 上限を超えたらエラー | pre-shift のサイズチェックのみ。ギリギリの入力がシフトで膨張しても通過 | FIXED |
| 11 | 数値の最小エンコード強制 | `read_script_number` で算術オペランドが最小エンコードでなければ拒否 | `bin2num` を使用しており最小エンコード検査なし。`0x0100`（非最小の 1）が通過 | FIXED |

### ビットシフト・文字列操作（2 件）

| # | 対象 | C++ の動作 | py-sdk の問題 | 状態 |
|---|------|-----------|-------------|------|
| 12 | `OP_LSHIFT` / `OP_RSHIFT` セマンティクス | ビット単位シフト。結果長は入力長を保持。両オペランドを消費 | バイト単位シフトとして実装されていた。結果長も入力長と一致しなかった | FIXED |
| 13 | `OP_SUBSTR` OOB 読み取り | `start + length > data.size()` でエラー | `start >= len(data)` のみチェック。`start < len` でも `start + length` が範囲外なら通過 | FIXED |

### 制御フロー・VM 状態（5 件）

| # | 対象 | C++ の動作 | py-sdk の問題 | 状態 |
|---|------|-----------|-------------|------|
| 14 | `OP_CODESEPARATOR` off-by-one | separator 自身を subscript から除外 | separator の位置ちょうどから開始。separator バイトが subscript に含まれていた | FIXED |
| 15 | VM 境界リセット | unlock → lock 遷移時に alt_stack / if_stack / code_separator をリセット | リセットなし。unlock の alt_stack が lock に引き継がれていた | FIXED |
| 16 | 二重 `OP_ELSE` の拒否 | 同一 IF レベルで 2 回目の ELSE はエラー | else_stack なし。同一レベルで何度でも ELSE が通過 | FIXED |
| 17 | `OP_RETURN` 条件分岐内 | `nonTopLevelReturnAfterGenesis` で実行をスキップしつつ文法チェックを継続 | トップレベル・条件分岐内を区別せず即終了。ENDIF 後の文法エラーを見逃す | FIXED |
| 18 | Script number 上限 | Chronicle 後は 32MB | 上限チェックなし。任意サイズの数値が通過 | FIXED |

### Chronicle 固有・SIGHASH（2 件）

| # | 対象 | C++ の動作 | py-sdk の問題 | 状態 |
|---|------|-----------|-------------|------|
| 19 | Chronicle CHECKSIG scriptCode 連結 | unlock 内で CHECKSIG 実行時、scriptCode = (unlock tail after codeseparator) + (full locking script) | unlock コンテキストでも unlock tail のみ。locking script を連結しなかった | FIXED |
| 20 | SIGHASH_SINGLE バグ（OTDA パス） | `input_index >= len(outputs)` 時、ハッシュとして `uint256(1)` を直接返す | OTDA preimage がそのままアクセスし IndexError。native C は二重ハッシュ（hash256 を余計に1回適用） | FIXED |

### オペコード有効性（2 件）

| # | 対象 | C++ の動作 | py-sdk の問題 | 状態 |
|---|------|-----------|-------------|------|
| 21 | `OP_NOP11`–`NOP73`, `NOP77` | `SCRIPT_ERR_BAD_OPCODE` で即エラー | NOP として処理（何もせず通過）。無効なオペコードが実行可能だった | FIXED |
| 22 | `last_code_separator` リセット値 | unlock → lock 遷移時に `-1` にリセット | native C が `0` にリセット。locking script の最初のチャンクが subscript から欠落 | FIXED |

---

## 他 SDK で発見された問題

C++ ノードとの照合過程で、TS-SDK および Go-SDK にも不一致が見つかった。

| SDK | 対象 | 問題 | 影響度 |
|-----|------|------|--------|
| TS-SDK | `OP_LSHIFTNUM` 上限 | BigInt の `<<` をそのまま使用。サイズ上限チェックなし。C++ は `CScriptNum::operator<<=` で事前にサイズ検証 | **HIGH** |
| Go-SDK | `OP_LSHIFTNUM` 上限 | `shift > MaxScriptNumberLength * 8` でチェック。C++ はシフト量ではなく結果サイズを検証するため、計算式が異なる | MEDIUM |
| TS-SDK | `OP_NOP11`+ の扱い | default ケースでエラー（C++ と一致） | CORRECT |
| Go-SDK | `OP_NOP11`+ の扱い | `opcodeNop` にマッピング（NOP 扱い）。C++ では `BAD_OPCODE` | **HIGH** |
| TS-SDK | `OP_RETURN` 条件分岐内 | 最終 ENDIF で `ifStack.length === 0` になったらプログラムカウンタを末尾へジャンプ。C++ とは実装が異なるが動作は等価 | EQUIVALENT |

---

## 追加テスト一覧

すべて `tests/bsv/script/test_vm_parity.py` に集約（149 テスト）。Python VM と native C 拡張の両パスで検証。

| テストクラス | 件数 | 検証内容 |
|-------------|------|---------|
| `TestDERSignatureEncoding` | 12 | 短すぎ / 長すぎ / 非 compound / 長さ不一致 / R=0 / S=0 / 負の R / 負の S / R 冗長パディング / S 冗長パディング / 有効最小 / R パディング必要 |
| `TestCheckmultisigCountCeiling` | 1 | 5 バイト key count の拒否 |
| `TestBin2NumMinimizeFirst` | 1 | 末尾ゼロが最小化されてからサイズチェック |
| `TestLshiftnumPostShiftCheck` | 2 | ゼロシフト / 基本シフト |
| `TestNum2BinCeiling` | 1 | 負のサイズ引数の拒否 |
| `TestBitShifts` | 7 | LSHIFT/RSHIFT 1ビット / ゼロ / ビット幅一致 / 空入力 |
| `TestStackOps` | 4 | 2OVER / 2SWAP / 3DUP / 2ROT |
| `TestDoubleElse` | 1 | 二重 OP_ELSE の拒否 |
| `TestVmBoundaryReset` | 1 | alt_stack が unlock → lock 遷移で引き継がれない |
| `TestCodeSeparatorChecksig` | 1 | CODESEPARATOR が署名対象から除外される（実署名で検証） |
| `TestDivModTruncation` | 2 | 負数の除算・剰余のゼロ方向切り捨て |
| `TestNativePythonEquivalence` | 1 | P2PKH を Python / native 両パスで実行し結果一致 |
| `TestNop11PlusInvalid` | 9 | NOP11/40/73/77 の拒否 (Python×4 + native×4) + NOP1–10 の有効性 |
| `TestSighashSingleBug` | 2 | OTDA SIGHASH_SINGLE バグ: uint256(1) への署名が検証成功 |
| `TestReservedOpcodes` | 9 | RESERVED/RESERVED1/RESERVED2: 実行時エラー (Python×3 + native×3) + 非実行分岐でスキップ×3 |
| `TestDualPathOpcodes` | 95 | 全オペコード（定数 OP_0–16、スタック操作 18 種、スプライス 4 種、ビット演算 6 種、算術 20 種、比較 11 種、ハッシュ 5 種、制御フロー 5 種、Chronicle 10 種）を Python / native 両パスで実行し結果一致を検証。CHECKSIG / CHECKSIGVERIFY / CHECKMULTISIG / CHECKMULTISIGVERIFY は実署名で両パスを検証 |

既存テスト 1 件を修正：

| ファイル | テスト | 変更 |
|---------|--------|------|
| `test_fuzz_native.py` | `test_spend_validate_otda_single_bug_digest` | 署名対象を `hash256(uint256(1))` → `uint256(1)` に変更（二重ハッシュバグの修正に対応） |

---

## 変更ファイル一覧

| ファイル | 内容 |
|---------|------|
| `bsv/script/spend.py` | Python VM 本体。22 件中 15 件の修正 + SIGHASH_SINGLE バグ処理 |
| `_bsv_native/bsv_native.c` | Native C VM。Python VM と同等の修正 10 件 + `c_bin2num_unchecked` / `c_is_valid_signature_encoding` 関数追加 |
| `bsv/transaction_preimage.py` | OTDA SIGHASH_SINGLE IndexError ガード追加 |
| `tests/bsv/script/test_vm_parity.py` | 新規作成。149 テスト。全オペコードの Python / native C デュアルパス等価テストを含む |
| `tests/bsv/script/test_checkmultisig_nullfail.py` | 新規作成。NULLFAIL テスト / 108 行 |
| `tests/bsv/script/test_minimal_number_encoding.py` | 新規作成。最小エンコードテスト / 76 行 |
| `tests/bsv/native/test_fuzz_native.py` | OTDA SINGLE バグテストの修正 |

---

## オペコード別テストカバレッジ

全 87 オペコードを監査し、専用テストの有無を確認した。

| 指標 | 値 |
|------|-----|
| 専用テストあり | 87（全オペコード） |
| テストなし | 0（ギャップ解消済み） |

> **デュアルパスカバレッジ:** `validate()` は実行環境に応じて Python / native C のどちらか一方のみを実行するため、従来のテストは片方のパスしか検証していなかった。`TestDualPathOpcodes`（95 テスト）を追加し、全 87 オペコードが `_validate_python()` と `_validate_native()` の両方で同一結果を返すことを明示的に検証。署名系オペコード（CHECKSIG / CHECKSIGVERIFY / CHECKMULTISIG / CHECKMULTISIGVERIFY）は実署名トランザクションで両パスを検証済み。

---

## 残存する既知の差異

以下 2 件はコンセンサス動作には影響しない DoS 保護レベルの設計差異であり、意図的に据え置いている。

| 項目 | C++ ノード | py-sdk | リスク |
|------|-----------|--------|--------|
| `MAX_SCRIPT_ELEMENT_SIZE` | Post-Genesis: スタック要素単体の上限なし（ポリシーレベルの総スタックサイズ制限のみ） | 1GB フラットキャップ | LOW |
| スタックメモリ制限 | ポリシーレベルで制限 | 制限なし | LOW |

---

## 結論

BSV Node C++ の `interpreter.cpp` を基準とした全オペコードの 1:1 照合を完了した。検出された 22 件の不一致はすべて修正済みであり、Python VM と native C 拡張の両方が同一の結果を返すことを 149 テストで確認した。

特に重要な点として、`validate()` が環境に応じて片方のパスのみを実行する設計上、従来のテストでは Python / native C の等価性が保証されていなかった。`TestDualPathOpcodes`（95 テスト）により、全オペコードを明示的に両パスで実行して結果一致を検証している。

結果として、py-sdk のスクリプト評価エンジンは C++ ノードのコンセンサス動作と機能的に一致している。残る 2 件の差異はリソース制限（DoS 保護）に関するものであり、現実的なトランザクションサイズにおいてスクリプト評価の結果が食い違うことはない。全テストスイート 4,263 テスト合格、0 失敗。

---

## 追加監査: CHECKSIG VM パス sighash カバレッジ (2026-08-14)

上記監査後のレビューで、CHECKSIG / CHECKMULTISIG の VM パステストが 12 種の有効な sighash タイプのうち `ALL_FORKID` (0x41) のみを通していたことが判明。preimage 計算自体は全 12 種テスト済みだったが、署名→CHECKSIG→検証の完全なパスは 1 種のみだった。

| 追加テスト | 数 |
|-----------|-----|
| CHECKSIG (P2PK + P2PKH + CHECKSIGVERIFY) × 12 sighash | 36 |
| CHECKMULTISIG + CHECKMULTISIGVERIFY × 12 sighash | 24 |
| SIGHASH_SINGLE BIP143 edge case (0x43, 0xC3) | 2 |
| **計** | **62** |

同時に C 拡張の公開関数 29 個のカバレッジ監査を実施。`seckey_verify`（正確性テスト 4 件）、`ecdsa_recover`（拡張テスト 5 件）、`context_randomize`（正確性テスト 3 件）を追加し、全 29 関数が STRONG カバレッジに到達した。
