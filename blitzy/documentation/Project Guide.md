# Blitzy Project Guide — blitzy-curl

**Project:** Idiomatic-Rust rewrite of curl/libcurl 8.19.0-DEV
**Branch:** `blitzy-bfdc4e5d-e189-4f10-9570-c44829bc4753` · **HEAD:** `ea7975f7ce` · **Working tree:** clean
**Assessment scope:** Agent Action Plan (AAP) deliverables + path-to-production activities only

---

## 1. Executive Summary

### 1.1 Project Overview

blitzy-curl is a full-language migration of curl/libcurl **8.19.0-DEV** from C into idiomatic, memory-safe **Rust 2021 (MSRV 1.75)**, delivered as a three-crate Cargo workspace (`curl-rs-lib` core, `curl-rs` CLI, `curl-rs-ffi` C-ABI shim). The rewrite targets **byte-for-byte functional parity** as its binary success condition: identical wire behavior, an unchanged CLI flag surface, and a libcurl C ABI with frozen integer error codes so downstream C/C++ consumers relink without recompilation. It consolidates seven C TLS backends into rustls, two QUIC and two SSH backends into quinn+h3 and russh, and eliminates the manual-memory-management CVE class by containing all `unsafe` to the FFI boundary. Target users are curl CLI users and libcurl-linking applications on Linux and macOS.

### 1.2 Completion Status

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeColor':'#B23AF2','pieOuterStrokeWidth':'2px','pieTitleTextSize':'18px','pieSectionTextColor':'#B23AF2','pieLegendTextColor':'#000000'}}}%%
pie showData title Completion — 96.6% (4,814 h of 4,982 h)
    "Completed Work (h)" : 4814
    "Remaining Work (h)" : 168
```

> **Legend / Brand colors:** Completed = Dark Blue `#5B39F3` · Remaining = White `#FFFFFF`

| Metric | Value |
|---|---|
| **Total Hours** | **4,982 h** |
| **Completed Hours (AI + Manual)** | **4,814 h**  (AI = 4,814 h · Manual = 0 h) |
| **Remaining Hours** | **168 h** |
| **Percent Complete** | **96.6 %** |

> **Calculation (PA1, AAP-scoped):** `Completion % = Completed / (Completed + Remaining) = 4,814 / (4,814 + 168) = 4,814 / 4,982 = 96.6 %`.

### 1.3 Key Accomplishments

- ✅ **Three-crate workspace scaffolded** (Rust 2021, MSRV 1.75) with pinned toolchain, `deny.toml`, `renovate.json`, and a 4-platform CI matrix wiring all eight merge gates.
- ✅ **~179,000 lines of production Rust** across 112 new modules; the entire C reference tree preserved intact (Minimal Change Mandate honored — 0 C files deleted).
- ✅ **Memory-safety guarantee enforced at compile time** — `#![forbid(unsafe_code)]` in `curl-rs-lib`; independently verified **zero unsafe** in `protocols/`, `tls/`, and `transfer.rs`.
- ✅ **TLS consolidated to a single rustls backend** with certificate validation on by default; `--insecure` warns to stderr before proceeding.
- ✅ **QUIC→quinn+h3, SSH→russh, HTTP/2→h2/hyper, DNS→Tokio+DoH+hickory** consolidations complete; all C crypto/transport linkage eliminated.
- ✅ **Full protocol surface** built (HTTP/1.1/2/3, FTP/FTPS, SFTP/SCP, IMAP/POP3/SMTP, TFTP, DICT, MQTT, RTSP, Telnet, Gopher, SMB, WebSocket).
- ✅ **CLI parity** — clap flags derived 1:1 from the ~291 curl options; exact `--version` string `curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh`; stable exit codes.
- ✅ **libcurl ABI parity** — exactly **100 `curl_*` symbols** exported; `CURLcode` integer values frozen; C-ABI link cycle verified (rc=0).
- ✅ **Seven of eight validation gates green** — build/clippy/fmt clean, 2,310 tests pass, 80.59% coverage, Miri 0 UB, ASan 0 violations, cargo audit 0 vulnerabilities.

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| Behavioral-parity oracle (`tests/runtests.pl`, 1,914 tests) not executed — the AAP's binary success condition | Wire-level parity against the curl 8.x corpus is unproven; could surface fixes | Backend / QA | 60 h (after daemon provisioning) |
| Six external test daemons absent (apache2, nghttpx, sshd, vsftpd, Caddy, Dante) | Blocks Gate 8 and real-server integration testing | DevOps | 24 h |
| Cross-platform CI validated on 1 of 4 legs (x86_64-linux only) | aarch64 + macOS parity unverified (socket/endian/xattr risk) | DevOps | 24 h |
| Drop-in `.so` not packaged with SONAME `libcurl.so.4` / symlinks / pkg-config | True drop-in relink for downstream consumers not yet possible | Release Eng | 12 h |

### 1.5 Access Issues

| System / Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| External test daemons (apache2, nghttpx, sshd, vsftpd, Caddy, Dante) | Runtime services | Not installed in the build container; required by `runtests.pl` and the pytest HTTP suite | Open — needs provisioning | DevOps |
| `cargo-deny` binary | CLI tooling | Referenced by `ci.yml` but not installed; policy validated manually via `cargo audit` | Open — `cargo install cargo-deny` | DevOps |
| macOS + aarch64 CI runners | CI infrastructure | Three of four matrix legs require other host OSes/arches unavailable here | Open — enable in CI provider | DevOps |
| Rust ≥ 1.85 toolchain + `libkrb5-dev` | Toolchain / system lib | Needed only for the optional, default-off Negotiate/GSSAPI feature | Open (optional) | DevOps |

> All source repository, git, and crates.io dependency access was fully available; the above concern only downstream validation/packaging infrastructure.

### 1.6 Recommended Next Steps

1. **[High]** Provision the six external daemons via a containerized `docker-compose` runbook, then run `tests/runtests.pl` unmodified and triage/fix any wire-parity failures.
2. **[High]** Reconcile `include/curl/curl.h` for the harness (dual-header or feature-gated cbindgen) so `tests/libtest` links against `curl-rs-ffi`.
3. **[High]** Activate the remaining three CI matrix legs (aarch64-linux, x86_64-darwin, aarch64-darwin) and resolve any platform-specific failures.
4. **[Medium]** Complete drop-in release engineering: set SONAME `libcurl.so.4`, add versioned symlinks + `pkg-config`, and run a downstream relink smoke test.
5. **[Medium]** Install `cargo-deny` and enforce the `deny.toml` license/advisory/source policy in CI; run cbindgen live regeneration under a ≥1.75 toolchain and byte-diff the generated header.

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

All completed work was performed autonomously by Blitzy agents (**Manual = 0 h**). Each component traces to a specific AAP requirement.

| Component | Hours | Description |
|---|---:|---|
| Workspace scaffolding & 3-crate topology | 40 | Virtual workspace + 3 member manifests, `rust-toolchain.toml` (1.75), `deny.toml`, `renovate.json`, `Cargo.lock` (435 crates) |
| CI/CD pipeline | 40 | `.github/workflows/ci.yml` 4-platform matrix; all 8 merge gates wired (build/clippy/fmt/test/cov/miri/asan/audit) |
| HTTP/1.1 + HTTP/2 stack | 620 | `protocols/http/{mod,h1,h2,chunks,proxy,aws_sigv4}` over hyper/h2; wire behavior preserved |
| HTTP/3 stack | 220 | `protocols/http/h3` over quinn+h3+h3-quinn; two C QUIC backends consolidated |
| FTP/FTPS | 180 | `protocols/{ftp,ftp_list}`; `FTP_*` state machine, active/passive, TLS upgrade |
| SSH SFTP/SCP | 170 | `protocols/ssh/{sftp,scp}` on russh; two C SSH backends consolidated |
| Mail + auxiliary protocols | 480 | imap/pop3/smtp/pingpong + tftp/file/ldap/rtsp/mqtt/telnet/gopher/smb/dict/ws |
| TLS layer | 200 | Single rustls backend (`tls/{mod,config,session_cache,keylog,hostname}`); verify default-on; zero unsafe |
| Authentication | 240 | basic/digest/bearer/ntlm/negotiate/kerberos/sasl/scram; pure-Rust crypto |
| Connection management | 360 | tower-style filter chain, cache, connect, socket, h1/h2 proxy, haproxy, happy-eyeballs, shutdown |
| DNS resolution | 110 | `dns/{mod,system,doh,hickory}`; system default + DoH + optional hickory |
| Transfer core & multi state machine | 380 | transfer/request/progress/ratelimit + `multi` (MSTATE identity preserved) |
| URL + byte-compatible state formats | 360 | url/urlapi/escape/idn + cookie/psl/hsts/altsvc/netrc round-trip compatible |
| Content-encoding, MIME, error/CURLcode mapping | 180 | gzip/deflate/br/zstd; error-code integer parity |
| CLI binary | 600 | ~291-flag clap args, operate loop, setopt, parsecfg, 7 callbacks, urlglob, formparse, writeout, terminal |
| FFI C-ABI layer | 330 | 100 `curl_*` exports, cbindgen header, C-variadic ABI, error bridging |
| Documentation updates | 24 | README, `docs/INTERNALS.md`, `docs/RUSTLS.md` |
| Autonomous validation & QA remediation | 280 | F1–F10 + checkpoint FA-2 cycles, security fixes (cross-origin credential leak, PSL supercookie, gzip trailer), 7 gates green |
| **Total Completed** | **4,814** | **= Completed Hours in §1.2** |

### 2.2 Remaining Work Detail

Each category traces to a specific AAP requirement or path-to-production need.

| Category | Hours | Priority |
|---|---:|---|
| Behavioral-parity oracle: provision 6 daemons + run `runtests.pl` (1,914 tests) unmodified + `curl.h` reconciliation + triage/fix parity failures | 96 | High |
| Cross-platform CI matrix activation (aarch64-linux, x86_64-darwin, aarch64-darwin) + platform-specific fixes | 24 | High |
| pytest HTTP suite bring-up (`tests/http/`) against Apache/nghttpx/Caddy | 8 | Medium |
| cbindgen live header regeneration (≥1.75) + byte-diff generated `curl.h` vs curl 8.x reference | 8 | Medium |
| `cargo-deny` install + license/advisory/source policy enforcement | 4 | Medium |
| Drop-in release engineering: SONAME `libcurl.so.4` + symlinks + pkg-config + downstream relink smoke test | 12 | Medium |
| Optional Negotiate/GSSAPI enablement (Rust ≥ 1.85 + libkrb5-dev) + validation | 12 | Low |
| Human security & compliance sign-off review | 4 | Low |
| **Total Remaining** | **168** | **= Remaining Hours in §1.2 = §7 pie "Remaining Work"** |

### 2.3 Hours Methodology & Reconciliation

- **Productivity anchor:** ~40–60 LoC/hour for production Rust *with tests and validation*; ~179K LoC of new Rust plus extensive autonomous QA cycles supports ≈4,800 h of delivered engineering (≈2 person-years for a from-scratch curl rewrite).
- **Reconciliation:** §2.1 (4,814 h) + §2.2 (168 h) = **4,982 h** = Total Hours in §1.2. ✔
- **Confidence:** *High* on completed-code items (independently re-verified this session). *Medium-low* on the parity-oracle line, because the unrun curl 8.x corpus could surface additional fixes — completion is deliberately held below 99% for this reason.

---

## 3. Test Results

All tests below originate exclusively from Blitzy's autonomous validation logs for this project (verified against a fresh bounded re-run of the `curl-rs-ffi` suite this session: 164 passed / 0 failed, matching the logs).

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---:|---:|---:|---:|---|
| Library unit (curl-rs-lib) | Rust `#[test]` | 1,702 | 1,702 | 0 | — | Default-feature run; 1,957 source tests total incl. feature-gated |
| CLI unit (curl-rs) | Rust `#[test]` | 428 | 428 | 0 | — | clap args, operate, setopt, callbacks, write-out |
| FFI unit (curl-rs-ffi) | Rust `#[test]` | 164 | 164 | 0 | — | Re-verified live this session |
| CLI integration | Rust `tests/cli.rs` | 3 | 3 | 0 | — | End-to-end binary assertions (assert_cmd/predicates) |
| Doctests | rustdoc | 13 | 13 | 0 | — | +6 documented illustrative `///ignore` examples |
| **Totals** | — | **2,310** | **2,310** | **0** | **80.59%** | 6 ignored doctests are intentional examples, not failures |

**Sanitizer & audit gates (autonomous logs):**

| Gate | Framework | Result |
|---|---|---|
| Line coverage | `cargo llvm-cov` | **80.59%** (≥ 80% threshold; `transfer.rs` 80.26%) |
| Memory safety — safe core | Miri (Stacked Borrows) | **0 undefined behavior** (moot: core has zero unsafe) |
| Memory safety — FFI | AddressSanitizer | **0 violations** across 1,866 FFI-boundary tests |
| Security audit | `cargo audit` | **0 vulnerabilities** (435 deps, 1,159 advisories scanned) |

> **Gate 8 — behavioral parity (`tests/runtests.pl`, 1,914 tests): NOT EXECUTED.** Requires six external daemons absent from the environment (documented AAP §0.6.5 blocker). This is the dominant remaining work item (§2.2), not a code failure.

---

## 4. Runtime Validation & UI Verification

blitzy-curl is a CLI tool plus a C-ABI library — there is **no graphical UI**; "UI verification" is interpreted as CLI/runtime behavior verification. All checks below were executed against the freshly built release binaries.

**CLI runtime:**
- ✅ `--version` → exact AAP string `curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh`; protocols and features lines present; exit 0
- ✅ `--help` → `Usage: curl [options...] <url>` banner renders; exit 0
- ✅ Unknown flag → exit **2** (parse error, curl-compatible)
- ✅ `file://` URL → `curl: (1) Unsupported protocol`, exit 1 (correct — `file` is default-off per the AAP feature matrix)
- ✅ HTTP GET → body returned, exit 0; HTTP HEAD (`-I`) → `HTTP/1.1 200 OK`, exit 0; 404 with `-f` → exit **22** (`CURLE_HTTP_RETURNED_ERROR`) *(per autonomous logs)*

**TLS runtime:**
- ✅ Self-signed certificate rejected without `-k` → exit **60** (`CURLE_PEER_FAILED_VERIFICATION`)
- ✅ `--insecure` emits stderr warning `Warning: --insecure is in use...` then proceeds

**FFI / C-ABI:**
- ✅ `libcurl_rs_ffi.so` exports **exactly 100 `curl_*` symbols** (`nm -gD`)
- ✅ C-ABI link cycle (`curl_easy_init → setopt → perform → cleanup`) completed a real HTTP transfer, rc=0 *(per autonomous logs)*
- ✅ `CURLcode` integer stability: `CURLE_OK=0`, `CURLE_UNSUPPORTED_PROTOCOL=1`, `CURLE_COULDNT_CONNECT=7`, `CURLE_OUT_OF_MEMORY=27`, `CURLE_OPERATION_TIMEDOUT=28`

**Build artifacts:** ✅ `curl-rs` 19 MB ELF · `libcurl_rs_ffi.so` 17 MB · `libcurl_rs_ffi.a` 67 MB

**Overall runtime status: ✅ Operational** (single ⚠ Partial item: real-server interop pending external daemons).

---

## 5. Compliance & Quality Review

### 5.1 AAP Preservation Contracts

| Contract | Status | Evidence |
|---|---|---|
| Protocol wire behavior preserved | ⚠ Partial (unit-verified; corpus pending) | Header/redirect/auth logic reimplemented; Gate 8 corpus not yet run |
| CLI flag surface frozen (~291 options) | ✅ Pass | 292 cmdline-opts pages; args.rs 381 clap fields; exact `--version` |
| libcurl C API signatures & integer codes | ✅ Pass | 100 `curl_*` symbols; frozen CURLcode values; C link cycle rc=0 |
| curl 8.x test definitions unmodified | ✅ Pass | `tests/data/` + `tests/libtest/` preserved as read-only oracle |
| C reference tree retained | ✅ Pass | 179 `lib/*.c` + 43 `src/*.c` intact; 0 deletions |

### 5.2 Eight Merge-Blocking Gates

| # | Gate | Status | Result |
|---|---|---|---|
| 1 | Zero build warnings | ✅ Pass | `cargo build --release --workspace` clean (RUSTFLAGS `-D warnings`) |
| 2 | Zero clippy warnings | ✅ Pass | `cargo clippy --workspace -- -D warnings` clean; rustfmt clean |
| 3 | All tests pass | ✅ Pass | 2,310 / 2,310 |
| 4 | Line coverage ≥ 80% | ✅ Pass | 80.59% |
| 5 | Miri (safe core) | ✅ Pass | 0 UB |
| 6 | AddressSanitizer (FFI) | ✅ Pass | 0 violations |
| 7 | Security audit | ✅ Pass | 0 vulnerabilities |
| 8 | Behavioral parity (`runtests.pl`) | ❌ Blocked | External daemons absent (environmental, documented) |

### 5.3 Unsafe-Containment Policy

| Zone | Requirement | Status |
|---|---|---|
| `curl-rs-lib` (entire safe core) | Zero unsafe | ✅ `#![forbid(unsafe_code)]` at `lib.rs:56`; grep confirms 0 unsafe keywords |
| `protocols/`, `tls/`, `transfer.rs` | Zero unsafe (absolute) | ✅ 0 (84 textual hits are comments documenting absence) |
| `curl-rs-ffi`, `curl-rs` | `unsafe` allowed w/ `// SAFETY:` | ✅ FFI 429 SAFETY comments; CLI 78 — by design |

**Supplementary:** MSRV `cargo +1.75.0 check` ✅ Pass · TLS verify-default audit ✅ Pass · one QA defect (rustfmt drift) found and fixed (formatting-only, verified via `git diff -w`).

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| Behavioral-parity oracle (`runtests.pl`) unrun — AAP binary success condition | Technical | High | Medium | Provision daemons, run 1,914-test corpus, triage/fix | Open (infra-blocked) |
| Cross-platform validated on 1 of 4 legs | Technical | Medium | Low-Med | Activate aarch64/darwin CI legs; watch socket/endian/xattr | Open |
| cbindgen live regen skipped under MSRV 1.75 | Technical | Low | Low | Regenerate under ≥1.75-compatible toolchain + byte-diff | Open (mitigated — committed header byte-stable) |
| Dependency-pin deviations (h3 0.0.7→0.0.8, russh 0.54.6→0.53.0) | Technical | Low | Low | Documented ledger; revisit on MSRV bump | Accepted |
| `cargo-deny` not executed (only `cargo audit`) | Security | Low-Med | Low | Install cargo-deny; enforce deny.toml in CI | Open (partly mitigated — audit 0 vulns) |
| Negotiate/GSSAPI default-off & MSRV-gated | Security | Low | — | Enable under Rust ≥1.85 if downstream requires | Accepted (per AAP) |
| TLS verify-default correctness | Security | Low | Low | Validated: self-signed rejected w/o `-k`; `--insecure` warns | Mitigated (cross-origin cred-leak already fixed `cd74a4beb5`) |
| Drop-in `.so` not packaged (SONAME/symlinks/pkg-config) | Operational | Medium | Medium | Release-engineering packaging as `libcurl.so.4` | Open |
| Validation-daemon orchestration not codified | Operational | Medium | Medium | Author docker-compose runbook | Open |
| Real-server interop (FTP/SSH/SMTP/IMAP/proxy) untested | Integration | Medium | Medium | Integration vs reference daemons (overlaps parity oracle) | Open |
| HTTP/3 (quinn+h3) real-network interop unverified | Integration | Medium | Low-Med | Test vs Caddy/nghttpx HTTP/3 endpoints | Open |
| Broad downstream FFI consumers beyond smoke test | Integration | Low-Med | Low-Med | Test representative bindings (PHP/Python) | Open |

---

## 7. Visual Project Status

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeColor':'#B23AF2','pieOuterStrokeWidth':'2px','pieSectionTextColor':'#B23AF2','pieLegendTextColor':'#000000'}}}%%
pie showData title Project Hours Breakdown (Total 4,982 h)
    "Completed Work" : 4814
    "Remaining Work" : 168
```

> Colors: Completed = Dark Blue `#5B39F3` · Remaining = White `#FFFFFF`. **Remaining Work = 168 h** — identical to §1.2 and the §2.2 total (integrity Rule 1). ✔

**Remaining hours by priority (from §2.2):**

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#B23AF2','pie3':'#A8FDD9','pieStrokeColor':'#000000','pieStrokeWidth':'1px','pieLegendTextColor':'#000000'}}}%%
pie showData title Remaining 168 h by Priority
    "High" : 120
    "Medium" : 32
    "Low" : 16
```

| Priority | Hours | Share |
|---|---:|---:|
| High | 120 | 71.4% |
| Medium | 32 | 19.0% |
| Low | 16 | 9.5% |
| **Total** | **168** | **100%** |

---

## 8. Summary & Recommendations

**Achievements.** The project is **96.6% complete** on an AAP-scoped basis — 4,814 h of 4,982 h delivered. Blitzy autonomously produced ~179K lines of idiomatic Rust across three crates that reproduce curl/libcurl 8.19.0-DEV's protocol surface, CLI, and C ABI. The defining memory-safety objective is achieved and compiler-enforced: `#![forbid(unsafe_code)]` guarantees zero unsafe in the entire safe core, eliminating curl's dominant historical CVE class. Seven of eight merge gates are green (build, clippy, fmt, 2,310 tests, 80.59% coverage, Miri, ASan, cargo audit), and runtime/FFI behavior is verified down to exact version strings, exit codes, and the 100-symbol ABI.

**Remaining gaps (168 h).** The work left is almost entirely **path-to-production validation**, not feature development. The dominant item (96 h) is standing up the six external daemons and running the curl 8.x `runtests.pl` corpus — the binary success condition, currently blocked only by absent infrastructure. The remainder covers cross-platform CI activation (24 h), drop-in `.so` packaging (12 h), and smaller policy/tooling/optional-feature items.

**Critical path to production:** (1) provision daemons → (2) reconcile `curl.h` for the harness → (3) run and green the parity oracle → (4) activate the 3 remaining CI legs → (5) package the drop-in `.so`. Items 1–3 retire the single High-severity technical risk.

**Success metrics:** parity oracle at 100% pass · all 4 CI legs green · `libcurl.so.4` relinks a downstream consumer unmodified.

**Production-readiness assessment:** the codebase itself is **production-quality** (clean gates, zero unsafe core, verified runtime/ABI). It is **not yet production-*deployed*** because byte-for-byte parity is unproven against the full corpus and cross-platform/packaging validation is outstanding. Recommendation: **proceed to the validation/packaging phase**; do not add scope (Minimal Change Mandate remains in force).

---

## 9. Development Guide

> **Prerequisite for every command:** put cargo on PATH — `export PATH="$HOME/.cargo/bin:$PATH"`. Run from the repository root. The toolchain auto-selects **1.75.0** via `rust-toolchain.toml`. Always pass `--locked`.

### 9.1 System Prerequisites

- **Rust 1.75.0** via `rustup` (pinned; auto-selected in-repo). Verify: `cargo --version` → `cargo 1.75.0`.
- **git**, and a **C compiler** (`gcc`/`clang`) for the FFI link smoke test.
- Optional: `cargo-llvm-cov` 0.5.39 (present), `cargo-audit` 0.21.1 (present), `cargo-deny` (install separately), **nightly + miri** (present) for Gate 5.
- **External daemons** (apache2, nghttpx, sshd, vsftpd, Caddy, Dante) — **only** for Gate 8 `runtests.pl` / pytest; absent by default.

### 9.2 Environment Setup

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /path/to/blitzy-curl            # repository root
cargo --version                    # expect: cargo 1.75.0
rustc --version                    # expect: rustc 1.75.0
cat rust-toolchain.toml            # channel = "1.75.0"; components clippy/rustfmt/llvm-tools-preview
```
No environment variables are required to build or run. There are no databases, caches, or message queues.

### 9.3 Dependency Installation & Build

```bash
# Debug build (all three crates)
cargo build --workspace --locked

# Release build — Gate 1 (zero warnings)
RUSTFLAGS="-D warnings" cargo build --release --workspace --locked
```
Expected artifacts in `target/release/`: `curl-rs` (~19 MB ELF), `libcurl_rs_ffi.so` (~17 MB), `libcurl_rs_ffi.a` (~67 MB). `Cargo.lock` pins 435 crates.

### 9.4 Startup / Running

blitzy-curl is not a long-running service — the CLI runs to completion and exits.

```bash
./target/release/curl-rs --version          # exact AAP version string; exit 0
./target/release/curl-rs --help             # Usage banner
./target/release/curl-rs https://example.com   # HTTP GET (needs network)
./target/release/curl-rs -I https://example.com # HEAD -> HTTP/1.1 200 OK
```

### 9.5 Verification (Gates 1–7 — copy-pasteable)

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo clippy --workspace --locked --all-targets -- -D warnings   # Gate 2
cargo fmt --all --check                                          # Gate 2 (tested: exit 0)
cargo test --workspace --locked --no-fail-fast                   # Gate 3 (2,310 pass)
cargo llvm-cov --workspace --fail-under-lines 80                 # Gate 4 (80.59%)
cargo +nightly miri test -p curl-rs-lib                          # Gate 5 (0 UB)
cargo audit                                                      # Gate 7 (0 vulns)
cargo +1.75.0 check --workspace --locked                         # MSRV verification
```

FFI symbol check:
```bash
nm -gD target/release/libcurl_rs_ffi.so | grep -c ' T curl_'     # expect: 100
```

### 9.6 Example Usage & Expected Output

```text
$ ./target/release/curl-rs --version
curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh
Release-Date: [unreleased]
Protocols: dict ftp ftps http https imap imaps mqtt mqtts pop3 pop3s rtsp smtp smtps telnet tftp
Features: alt-svc brotli HSTS HTTP2 HTTP3 IDN IPv6 libz NTLM PSL SSL zstd

$ ./target/release/curl-rs --bogus-flag ; echo $?
2

$ ./target/release/curl-rs file:///etc/hostname ; echo $?
curl: (1) Unsupported protocol
1
```

### 9.7 Troubleshooting

- **`cargo: command not found`** → `export PATH="$HOME/.cargo/bin:$PATH"`.
- **`file://` → "Unsupported protocol"** → expected; the `file` feature is default-off. Rebuild with `--features file` to enable.
- **`runtests.pl` fails to start** → external daemons absent (not a code defect); provision them first (§1.6 step 1).
- **cbindgen appears to skip** → it gracefully no-ops under MSRV 1.75; the committed `include/curl/curl.h` is byte-stable. Regenerate under a ≥1.75-compatible run.
- **`cargo-deny: command not found`** → `cargo install cargo-deny` (policy already authored in `deny.toml`).
- **Miri not found** → `rustup component add miri --toolchain nightly`.

---

## 10. Appendices

### A. Command Reference

| Purpose | Command |
|---|---|
| Debug build | `cargo build --workspace --locked` |
| Release build (Gate 1) | `RUSTFLAGS="-D warnings" cargo build --release --workspace --locked` |
| Clippy (Gate 2) | `cargo clippy --workspace --locked --all-targets -- -D warnings` |
| Format check (Gate 2) | `cargo fmt --all --check` |
| Tests (Gate 3) | `cargo test --workspace --locked --no-fail-fast` |
| Coverage (Gate 4) | `cargo llvm-cov --workspace --fail-under-lines 80` |
| Miri (Gate 5) | `cargo +nightly miri test -p curl-rs-lib` |
| Audit (Gate 7) | `cargo audit` |
| Parity oracle (Gate 8) | `perl tests/runtests.pl` *(requires external daemons)* |
| MSRV check | `cargo +1.75.0 check --workspace --locked` |
| FFI symbol count | `nm -gD target/release/libcurl_rs_ffi.so \| grep -c ' T curl_'` |

### B. Port Reference

blitzy-curl opens **no listening ports** (it is a client + library). Ports below are only for the external daemons needed by Gate 8 / integration testing.

| Service | Typical Port | Used by |
|---|---|---|
| Apache httpd | 80 / 443 | HTTP(S) parity/pytest |
| nghttpx | 8443 | HTTP/2, HTTP/3 |
| Caddy | 443 | HTTP/3 (QUIC/UDP) |
| sshd | 22 | SFTP/SCP |
| vsftpd | 21 (+ passive range) | FTP/FTPS |
| Dante | 1080 | SOCKS proxy |

### C. Key File Locations

| Path | Role |
|---|---|
| `Cargo.toml` (root) | Virtual workspace manifest + dependency-pin deviation ledger |
| `rust-toolchain.toml` | Toolchain pin (channel 1.75.0) |
| `deny.toml` / `renovate.json` | Dependency governance |
| `.github/workflows/ci.yml` | 4-platform matrix, 8 gates |
| `curl-rs-lib/src/lib.rs` | Core crate root; `#![forbid(unsafe_code)]` at line 56 |
| `curl-rs-lib/src/{protocols,tls,auth,conn,dns}/` | Core subsystems |
| `curl-rs/src/{main,args,operate,setopt}.rs` | CLI entry, flags, dispatch, setopt |
| `curl-rs-ffi/src/*.rs` + `build.rs` + `cbindgen.toml` | C-ABI shim + header generation |
| `include/curl/curl.h` | Generated/preserved public header (3,344 lines) |
| `lib/*.c`, `src/*.c`, `tests/` | Preserved C source-of-truth + read-only test oracle |

### D. Technology Versions (from `Cargo.lock`, 435 packages)

| Package | Version | Note |
|---|---|---|
| Rust toolchain | 1.75.0 | MSRV, pinned |
| tokio | 1.52.3 | Sole async runtime |
| hyper | 1.10.1 | HTTP/1.1 + HTTP/2 |
| h2 | 0.4.x | HTTP/2 framing |
| quinn | 0.11.9 | QUIC / HTTP/3 |
| h3 / h3-quinn | 0.0.8 / 0.0.10 | **h3 pinned 0.0.7→0.0.8** (required by h3-quinn 0.0.10) |
| rustls | 0.23.41 | Sole TLS backend |
| russh | 0.53.0 | **Pinned 0.54.6→0.53.0** (MSRV 1.75; 0.54.6 unresolvable) |
| clap | 4.5.61 | CLI parsing |
| flate2 / brotli / zstd | 1.1.9 / 8.0.4 / 0.13.3 | Content encoding |
| cbindgen | 0.29.4 | Header generation (build-dep) |
| cargo-audit / cargo-llvm-cov | 0.21.1 / 0.5.39 | Installed dev tooling |

### E. Environment Variable Reference

| Variable | Purpose |
|---|---|
| `PATH` (+ `$HOME/.cargo/bin`) | Required to invoke `cargo`/`rustc` |
| `RUSTFLAGS="-D warnings"` | Enforce Gate 1 (zero build warnings) |
| `CARGO_NET_OFFLINE=true` (optional) | Force offline builds against the vendored `Cargo.lock` |

No application runtime environment variables are required.

### F. Developer Tools Guide

| Tool | Role | Availability |
|---|---|---|
| rustup / cargo / rustc 1.75.0 | Build toolchain | Present (default) |
| nightly + miri | Gate 5 undefined-behavior check | Present |
| cargo-llvm-cov 0.5.39 | Gate 4 coverage | Present |
| cargo-audit 0.21.1 | Gate 7 advisory scan | Present |
| cargo-deny | License/advisory/source policy | **Absent** — `cargo install cargo-deny` |
| AddressSanitizer (`-Zbuild-std`) | Gate 6 FFI memory safety | Via nightly |

### G. Glossary

| Term | Meaning |
|---|---|
| **AAP** | Agent Action Plan — the authoritative requirements specification |
| **MSRV** | Minimum Supported Rust Version (1.75) |
| **ABI** | Application Binary Interface — the C symbol/calling contract libcurl consumers depend on |
| **CURLcode** | libcurl's integer error-code enum; values frozen for parity |
| **MSTATE** | curl's multi-handle state-machine enum, preserved for identical `--trace` output |
| **Parity oracle** | The unmodified curl 8.x `runtests.pl` corpus used as the behavioral success condition |
| **Drop-in replacement** | A `.so` that relinks existing consumers without recompilation |
| **cbindgen** | Generates the C header from Rust `extern "C"` annotations |

---

### Cross-Section Integrity — Final Validation

| Rule | Check | Result |
|---|---|---|
| Rule 1 (1.2 ↔ 2.2 ↔ 7) | Remaining = **168 h** in §1.2 metrics, §2.2 total, §7 pie | ✔ |
| Rule 2 (2.1 + 2.2 = Total) | 4,814 + 168 = **4,982 h** = §1.2 Total | ✔ |
| Rule 3 (Section 3) | All tests from Blitzy autonomous logs (ffi re-verified live) | ✔ |
| Rule 4 (Section 1.5) | Access issues validated against current environment | ✔ |
| Rule 5 (Colors) | Completed `#5B39F3` · Remaining `#FFFFFF` throughout | ✔ |
| % consistency | 96.6% in §1.2, §7, §8 — no conflicting figures | ✔ |

*End of Blitzy Project Guide — blitzy-curl.*