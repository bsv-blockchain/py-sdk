# Test Coverage Breakdown by Module

Detailed breakdown of coverage by module with specific recommendations.

## 📊 Overall Statistics

| Metric | Value |
|--------|-------|
| Total Statements | 22,314 |
| Covered | 14,833 (66%) |
| Missing | 7,481 (34%) |
| Total Branches | 5,320 |
| Partial Branches | 919 |
| Branch Coverage | ~76% |

## 🎯 Coverage by Top-Level Module

```
bsv/
├── utils/           [Mixed]  ⚠️  Critical gaps
├── wallet/          [62%]    ⚠️  Needs improvement
├── auth/            [Mixed]  ⚠️  Large gaps
├── identity/        [50%]    ⚠️  Needs work
├── script/          [68%]    ⚡  Moderate
├── transaction/     [72%]    ✅  Good
├── hd/              [97%]    ✅  Excellent
├── keys/            [94%]    ✅  Excellent
└── primitives/      [76%]    ⚡  Moderate
```

## 📁 Detailed Module Breakdown

### 🔴 Critical Priority (< 40% coverage)

#### bsv/utils.py (0% - 357 statements)
```
Status: ⚠️ CRITICAL - Zero coverage
Impact: 🔥 HIGH - Core utility functions
Effort: ⏱️ Medium (2-3 days)
Priority: 🎯 P0 - Must fix immediately

Functions missing coverage:
├── unsigned_to_varint()       [0/~20 lines]
├── varint_to_unsigned()       [0/~20 lines]
├── hex_to_bytes()             [0/~10 lines]
├── bytes_to_hex()             [0/~10 lines]
├── encode_pushdrop_token()    [0/~40 lines]
├── decode_pushdrop_token()    [0/~30 lines]
└── [+20 more functions]       [0/~227 lines]

Recommended Tests: 37 tests
Expected Gain: +286 statements
```

#### bsv/auth/peer_clean.py (0% - 932 statements)
```
Status: ⚠️ CRITICAL - Zero coverage
Impact: ❓ UNKNOWN - Needs investigation
Effort: ⏱️ High (5-7 days) OR Deprecate
Priority: 🎯 P1 - Investigate status first

Action Required:
1. Determine if this is active or legacy code
2. If active: Create comprehensive test suite
3. If legacy: Mark deprecated, exclude from coverage
4. If duplicate: Remove and use main implementation

Note: This appears to be an alternative implementation
of peer.py (which has 66% coverage). Investigation
needed to determine which should be canonical.
```

#### bsv/wallet/serializer/list_outputs.py (4% - 114 statements)
```
Status: ⚠️ CRITICAL - Almost no coverage
Impact: 🔥 HIGH - Core wallet functionality
Effort: ⏱️ Low (1 day)
Priority: 🎯 P0 - Quick win

Missing Coverage:
├── serialize_list_outputs_args()     [0/~35 lines]
├── deserialize_list_outputs_result() [0/~55 lines]
└── Helper functions                  [0/~20 lines]

Current Coverage: Only imports tested
Recommended Tests: 24 tests
Expected Gain: +92 statements
```

#### bsv/identity/client.py (13% - 172 statements)
```
Status: ⚠️ CRITICAL - Very low coverage
Impact: 🔥 HIGH - Identity service client
Effort: ⏱️ Medium (2 days)
Priority: 🎯 P0 - High impact

Coverage Gaps:
├── authenticate()            [0/~20 lines] ⚠️
├── get_identity()           [0/~15 lines] ⚠️
├── resolve()                [0/~18 lines] ⚠️
├── create_identity()        [0/~25 lines] ⚠️
├── update_identity()        [0/~20 lines] ⚠️
└── delete_identity()        [0/~15 lines] ⚠️

Current Coverage: Only __init__ tested
Recommended Tests: 31 tests
Expected Gain: +131 statements
```

#### bsv/wallet/cached_key_deriver.py (21% - 61 statements)
```
Status: ⚠️ LOW - Needs improvement
Impact: ⚡ MEDIUM - Performance optimization
Effort: ⏱️ Low (1 day)
Priority: 🎯 P1 - Moderate impact

Coverage Gaps:
├── cache_hit path           [0/~10 lines] ⚠️
├── cache_miss path          [0/~8 lines] ⚠️
├── cache_eviction           [0/~12 lines] ⚠️
└── derive_child_key         [2/~15 lines] ⚡

Recommended Tests: 12 tests
Expected Gain: +30 statements
```

### 🟡 Medium Priority (40-60% coverage)

#### bsv/script/interpreter/stack.py (46% - 141 statements)
```
Status: ⚡ MEDIUM - Half covered
Impact: 🔥 HIGH - Script execution
Effort: ⏱️ Medium (1-2 days)
Priority: 🎯 P2

Coverage Analysis:
├── Basic operations         [40/50 lines] ✅
├── Advanced operations      [10/40 lines] ⚠️
├── Error handling          [5/30 lines] ⚠️
└── Edge cases              [0/21 lines] ⚠️

Recommended Tests: 25 tests (focus on error paths)
Expected Gain: +64 statements
```

#### bsv/wallet/substrates/serializer.py (57% - 334 statements)
```
Status: ⚡ MEDIUM - Partial coverage
Impact: 🔥 HIGH - Wallet communication
Effort: ⏱️ High (3-4 days)
Priority: 🎯 P2

Coverage Analysis:
├── Reader class            [80/120 lines] ✅
├── Writer class            [70/120 lines] ⚡
├── Helper functions        [25/50 lines] ⚠️
└── Error handling          [10/44 lines] ⚠️

Recommended Tests: 40 tests
Expected Gain: +124 statements
```

#### bsv/overlay_tools/ship_broadcaster.py (49% - 163 statements)
```
Status: ⚡ MEDIUM - Half covered
Impact: ⚡ MEDIUM - Overlay network
Effort: ⏱️ Medium (2 days)
Priority: 🎯 P2

Coverage Analysis:
├── Broadcast operations    [35/60 lines] ⚡
├── Network handling        [15/50 lines] ⚠️
├── Error handling          [5/35 lines] ⚠️
└── State management        [10/18 lines] ⚡

Recommended Tests: 28 tests
Expected Gain: +75 statements
```

#### bsv/primitives/aescbc.py (52% - 57 statements)
```
Status: ⚡ MEDIUM - Half covered
Impact: 🔥 HIGH - Encryption
Effort: ⏱️ Low (1 day)
Priority: 🎯 P1

Coverage Analysis:
├── Encrypt operations      [15/25 lines] ⚡
├── Decrypt operations      [10/25 lines] ⚠️
└── Edge cases              [0/7 lines] ⚠️

Recommended Tests: 15 tests
Expected Gain: +25 statements
```

### 🟢 Good Coverage (60-80% coverage)

These modules have good coverage but could be improved:

#### bsv/auth/peer.py (66% - 945 statements)
```
Status: ✅ GOOD - Above average
Gaps: Error handling, edge cases
Recommended: +15 tests
Expected Gain: +273 statements
```

#### bsv/transaction/beef.py (76% - 323 statements)
```
Status: ✅ GOOD - Above average
Gaps: Error scenarios, malformed data
Recommended: +10 tests
Expected Gain: +69 statements
```

#### bsv/script/spend.py (75% - 571 statements)
```
Status: ✅ GOOD - Above average
Gaps: Complex unlock scenarios
Recommended: +20 tests
Expected Gain: +125 statements
```

### 🌟 Excellent Coverage (80-100% coverage)

These modules have excellent coverage:

#### bsv/hd/bip32.py (98% - 160 statements)
```
Status: 🌟 EXCELLENT
Missing: Only 2 statements
Action: Add edge case tests for completeness
```

#### bsv/hd/bip39.py (100% - 67 statements)
```
Status: 🌟 PERFECT
Action: Maintain current coverage
```

#### bsv/keys.py (94% - 231 statements)
```
Status: 🌟 EXCELLENT
Missing: 8 statements (error paths)
Action: Add negative tests
```

## 📈 Coverage Improvement Roadmap

### Phase 1: Critical Files (Week 1)
```
Target: 66% → 70% (+452 statements)

Files:
✓ bsv/utils.py                  [0% → 80%]  = +286 stmts
✓ bsv/wallet/serializer/list_outputs.py 
                                [4% → 85%]  = +92 stmts
✓ bsv/utils/binary.py           [31% → 85%] = +36 stmts
✓ bsv/utils/reader_writer.py    [39% → 80%] = +47 stmts

Tests to Write: ~100
Time: 2-3 days
```

### Phase 2: High-Impact Files (Week 2)
```
Target: 70% → 73% (+280 statements)

Files:
✓ bsv/identity/client.py        [13% → 70%] = +131 stmts
✓ bsv/auth/clients/auth_fetch.py 
                                [41% → 65%] = +95 stmts
✓ bsv/wallet/cached_key_deriver.py 
                                [21% → 70%] = +30 stmts
✓ bsv/script/interpreter/opcode_parser.py 
                                [31% → 70%] = +22 stmts

Tests to Write: ~80
Time: 3-4 days
```

### Phase 3: Medium Coverage (Week 3)
```
Target: 73% → 76% (+700 statements)

Files:
✓ bsv/script/interpreter/stack.py       [46% → 75%]
✓ bsv/wallet/substrates/serializer.py   [57% → 75%]
✓ bsv/overlay_tools/ship_broadcaster.py [49% → 75%]
✓ bsv/primitives/aescbc.py             [52% → 85%]
✓ [+8 more files]

Tests to Write: ~150
Time: 5-6 days
```

## 🎯 Quick Wins (Highest ROI)

| File | Current | Effort | Gain | ROI |
|------|---------|--------|------|-----|
| bsv/utils.py | 0% | Med | +286 | ⭐⭐⭐⭐⭐ |
| bsv/wallet/serializer/list_outputs.py | 4% | Low | +92 | ⭐⭐⭐⭐⭐ |
| bsv/identity/client.py | 13% | Med | +131 | ⭐⭐⭐⭐ |
| bsv/utils/binary.py | 31% | Low | +36 | ⭐⭐⭐⭐ |
| bsv/primitives/aescbc.py | 52% | Low | +25 | ⭐⭐⭐ |

## 📊 Coverage by Category

### Cryptography & Primitives (78% avg)
```
✅ bsv/keys.py                  [94%] - Excellent
✅ bsv/curve.py                 [100%] - Perfect
✅ bsv/hash.py                  [100%] - Perfect
✅ bsv/aes_cbc.py               [100%] - Perfect
⚡ bsv/aes_gcm.py               [94%] - Very Good
⚡ bsv/primitives/schnorr.py    [86%] - Good
⚡ bsv/primitives/drbg.py       [90%] - Excellent
⚠️ bsv/primitives/aescbc.py    [52%] - Needs Work
```

### Wallet & Key Derivation (69% avg)
```
✅ bsv/hd/bip39.py              [100%] - Perfect
✅ bsv/hd/bip32.py              [98%] - Excellent
✅ bsv/hd/bip44.py              [94%] - Excellent
⚡ bsv/wallet/key_deriver.py    [91%] - Excellent
⚡ bsv/wallet/wallet_impl.py    [69%] - Good
⚡ bsv/wallet/wallet_interface.py [81%] - Good
⚠️ bsv/wallet/cached_key_deriver.py [21%] - Critical
⚠️ bsv/wallet/substrates/serializer.py [57%] - Needs Work
```

### Script & Interpreter (67% avg)
```
✅ bsv/script/script.py         [94%] - Excellent
✅ bsv/script/bip276.py         [95%] - Excellent
⚡ bsv/script/type.py           [92%] - Excellent
⚡ bsv/script/spend.py          [75%] - Good
⚡ bsv/script/interpreter/number.py [98%] - Excellent
⚡ bsv/script/interpreter/thread.py [85%] - Good
⚡ bsv/script/interpreter/engine.py [82%] - Good
⚡ bsv/script/interpreter/operations.py [64%] - Moderate
⚠️ bsv/script/interpreter/stack.py [46%] - Needs Work
⚠️ bsv/script/interpreter/opcode_parser.py [31%] - Critical
```

### Transaction & BEEF (75% avg)
```
✅ bsv/transaction_input.py     [100%] - Perfect
✅ bsv/transaction_output.py    [100%] - Perfect
✅ bsv/merkle_path.py           [96%] - Excellent
⚡ bsv/transaction.py           [83%] - Good
⚡ bsv/transaction/beef_validate.py [83%] - Good
⚡ bsv/transaction/beef.py      [76%] - Good
⚡ bsv/transaction/beef_builder.py [72%] - Good
⚡ bsv/transaction/beef_tx.py   [66%] - Moderate
⚡ bsv/transaction/pushdrop.py  [67%] - Moderate
```

### Authentication (55% avg)
```
✅ bsv/auth/certificate.py      [97%] - Excellent
✅ bsv/auth/cert_encryption.py  [100%] - Perfect
✅ bsv/auth/session_manager.py  [96%] - Excellent
⚡ bsv/auth/master_certificate.py [76%] - Good
⚡ bsv/auth/utils.py            [71%] - Good
⚡ bsv/auth/verifiable_certificate.py [65%] - Moderate
⚡ bsv/auth/peer.py             [66%] - Moderate
⚠️ bsv/auth/requested_certificate_set.py [35%] - Critical
⚠️ bsv/auth/clients/auth_fetch.py [41%] - Needs Work
⚠️ bsv/auth/peer_clean.py      [0%] - ZERO COVERAGE
```

### Identity & Contacts (56% avg)
```
✅ bsv/identity/testable_client.py [100%] - Perfect
✅ bsv/identity/types.py        [100%] - Perfect
⚡ bsv/identity/contacts_manager.py [71%] - Good
⚠️ bsv/identity/client.py      [13%] - CRITICAL
```

### Utilities (Mixed - 45% avg)
```
✅ bsv/base58.py               [100%] - Perfect
✅ bsv/utils/encoding.py       [100%] - Perfect
✅ bsv/utils/pushdata.py       [100%] - Perfect
✅ bsv/utils/writer.py         [100%] - Perfect
⚡ bsv/utils/base58_utils.py   [96%] - Excellent
⚡ bsv/utils/reader.py         [86%] - Good
⚡ bsv/utils/legacy.py         [85%] - Good
⚡ bsv/utils/script.py         [78%] - Good
⚠️ bsv/utils/address.py        [65%] - Moderate
⚠️ bsv/utils/script_chunks.py  [57%] - Needs Work
⚠️ bsv/utils/reader_writer.py  [39%] - Critical
⚠️ bsv/utils/binary.py         [31%] - Critical
⚠️ bsv/utils.py                [0%] - ZERO COVERAGE
```

## 🎓 Lessons Learned

### Common Patterns in Low Coverage
1. **Error handling paths** - Often untested
2. **Edge cases** - Empty inputs, None, max values
3. **Alternative branches** - If/else not both tested
4. **Serialization error paths** - Only happy path tested
5. **Network error handling** - Timeout, connection errors

### High Coverage Indicators
1. **Well-defined scope** - Clear, focused modules
2. **Good documentation** - Tests serve as examples
3. **Active development** - Recent changes include tests
4. **Simple interfaces** - Easy to test
5. **Few dependencies** - Less mocking needed

## 📞 Getting Started

1. **Pick a file** from Critical Priority section
2. **Read the relevant plan:**
   - Strategic: `COVERAGE_IMPROVEMENT_PLAN.md`
   - Tactical: `COVERAGE_TACTICAL_PLAN.md`
   - Quick Ref: `COVERAGE_QUICK_REFERENCE.md`
3. **Create test file** using templates
4. **Write tests** following patterns
5. **Run & verify** coverage improvement
6. **Submit PR** with tests

## 📚 Resources

- **Coverage Report:** `htmlcov/index.html`
- **Run Tests:** `pytest --cov=bsv --cov-report=html`
- **Check Module:** `pytest --cov=bsv.module --cov-report=term-missing`

---

*Coverage Breakdown v1.0 - November 18, 2024*
*Last Coverage Run: November 18, 2024 15:52 JST*

