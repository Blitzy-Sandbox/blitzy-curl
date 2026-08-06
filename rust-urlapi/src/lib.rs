// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! A binary-compatible Rust port of curl's URL API, `lib/urlapi.c`.
//!
//! The crate compiles to a static library, a shared library and an `rlib`. The
//! archive is the deliverable: it is linked in place of the object file that
//! `lib/urlapi.c` produces, it exports the same C symbols with the same
//! signatures that `include/curl/urlapi.h` L34-L149 declares, and it changes no
//! observable behaviour. Where the C implementation does something surprising,
//! this one does the same surprising thing and says so at the site.
//!
//! Nothing outside this directory is created, edited, moved or deleted.
//! `lib/urlapi.c` and `include/curl/urlapi.h` in particular stay byte for byte
//! as they are, deliberately, so that they remain available as the comparison
//! baseline the parity run diffs against.
//!
//! # The exported surface
//!
//! Eight symbols, not six. Five are the public functions
//! `include/curl/urlapi.h` declares; the other three are internal entry points
//! `lib/urlapi-int.h` L28-L33 declares and other translation units of libcurl
//! call. The object file being replaced defines all eight, so a crate
//! exporting only the public five could not stand in for it.
//!
//! | Symbol | Declared at | Called from |
//! |--------|-------------|-------------|
//! | `curl_url` | `include/curl/urlapi.h` L113 | `lib/url.c`, `lib/http.c`, `lib/http1.c` |
//! | `curl_url_cleanup` | L120 | `lib/url.c`, `lib/http.c`, `lib/http1.c` |
//! | `curl_url_dup` | L126 | `lib/http.c`, `lib/url.c` |
//! | `curl_url_get` | L133 | `lib/http.c`, `lib/imap.c`, `lib/transfer.c`, `lib/url.c` |
//! | `curl_url_set` | L141 | `lib/url.c`, `lib/http.c`, `lib/http1.c` |
//! | `Curl_is_absolute_url` | `lib/urlapi-int.h` L28 | `lib/http1.c` L220, `lib/url.c` L1661, `lib/http.c` L1177 |
//! | `Curl_url_set_authority` | `lib/urlapi-int.h` L31 | `lib/http2.c` L739 |
//! | `Curl_junkscan` | `lib/urlapi-int.h` L33 | `lib/doh.c` L1127 |
//!
//! Two further symbols are feature gated, and both are off in the drop-in
//! configuration because libcurl already defines them there:
//!
//! - `curl_url_strerror`, under `strerror`. It is not implemented in
//!   `lib/urlapi.c` at all. It lives in `lib/strerror.c` L420-L531, which is
//!   out of scope, so exporting it beside a real libcurl would duplicate a
//!   symbol the link already has.
//! - `curl_free`, under `cfree`. Likewise defined out of scope, at
//!   `lib/escape.c` L189-L192. The standalone configuration needs it because
//!   the documented contract of `curl_url_get` obliges the caller to release
//!   the returned buffer with it.
//!
//! `Curl_parse_port` is deliberately *not* exported. `lib/urlapi.c` defines it
//! for unit-test builds only, behind the conditional marker at
//! `lib/urlapi-int.h` L36, and satisfying `tests/unit/unit1653.c` would demand
//! a ninth symbol plus bit-compatible interoperation with C's dynamic-buffer
//! structure. That is reported as a limitation of the drop-in rather than
//! worked around.
//!
//! # Build configurations
//!
//! Six Cargo features stand in for the C preprocessor switches, which is how
//! this port expresses `#ifdef` in the target language. Four are on by
//! default, two are off.
//!
//! | Feature | Default | Effect |
//! |---------|---------|--------|
//! | `strerror` | on | Export `curl_url_strerror` and the 33 message strings |
//! | `cfree` | on | Export `curl_free` |
//! | `scheme-table` | on | Compile a scheme table into the crate |
//! | `idn-libidn2` | on | Bind libidn2 directly, as `lib/idn.c` does |
//! | `idn-pure` | off | Use the `idna` crate instead, outside the parity claim |
//! | `genheader` | off | Check the mirror header against the crate's ABI |
//!
//! `genheader` is a check, which its name understates. It never rewrites
//! `include/curl_urlapi_rs.h`. `build.rs` generates a second mirror with
//! cbindgen's library API into `OUT_DIR`, reduces both that file and the
//! committed one to an ABI projection -- constant name and value pairs,
//! function signatures with parameter names dropped, typedef names -- and
//! warns on any difference between the two. The projection is blind to
//! comments, layout, declaration order, parameter names and the
//! enum-versus-macro spelling of a constant, which is what makes it an ABI
//! check rather than a diff: the two files are never byte-equal and are not
//! meant to be, and `cbindgen.toml` records the shape differences that
//! account for it.
//!
//! Exactly two configurations are intended to be built and validated, and the
//! validation half is the parity workflow that `rust-urlapi/scripts/` is to
//! carry. Those scripts are a later deliverable and do not exist yet, so what
//! follows describes the two link modes rather than reporting a run of them.
//!
//! ```text
//! cargo build --release --no-default-features --features idn-libidn2
//! ```
//!
//! Mode A, the drop-in and authoritative one. It links beside a real libcurl
//! whose `urlapi.c.o` has been deleted from the archive, so the crate must not
//! define anything libcurl still defines: `strerror`, `cfree` and
//! `scheme-table` are all off, and `src/scheme.rs` imports `Curl_get_scheme`
//! from `lib/url.c` instead of compiling its own table. Of those three,
//! `scheme-table` is the one to watch, because leaving it on produces no
//! duplicate symbol and no link error at all -- only a silently wrong table.
//!
//! ```text
//! cargo build --release
//! ```
//!
//! Mode B, standalone. No libcurl takes part, so the crate supplies the error
//! strings, the free function and a scheme table itself, alongside the small C
//! shims for the `curl_mprintf` family in `harness/shims.c`.
//!
//! # Module tree
//!
//! One C translation unit of 1,998 lines becomes fifteen modules. Each is
//! named for what it owns rather than for where the C put it, and the
//! rightmost column is where to look in the C for the behaviour it reproduces.
//!
//! | Module | Responsibility | Ported from |
//! |--------|----------------|-------------|
//! | [`abi`] | The 60 ABI constants, as explicit integers | `include/curl/urlapi.h` L34-L105 |
//! | `alloc` | The C-allocator adapter and the owned buffer | `lib/escape.c` L189-L192 |
//! | `ctype` | Character classification, hex, case folding | `lib/curl_ctype.h` L47-L49, `lib/strcase.c` L106 |
//! | `decode` | Percent-decoding with control-byte rejection | `lib/escape.c` L105 |
//! | `dynbuf` | The growable buffer and its ownership transfer | `lib/curlx/dynbuf.c` |
//! | `encode` | Percent-encoding, both directions | `lib/urlapi.c` L104-L180, L1779-L1803 |
//! | `error` | Code translation and the 33 message strings | `lib/strerror.c` L420-L531 |
//! | [`ffi`] | The exported symbols and the crate's only `unsafe` | `lib/urlapi.c`, `lib/urlapi-int.h` |
//! | `getset` | Serialisation and the part get and set rules | `lib/urlapi.c` L1357-L1998 |
//! | `handle` | The owned handle replacing `struct Curl_URL` | `lib/urlapi.c` L67-L102 |
//! | `idn` | Internationalised-domain conversion | `lib/idn.c` L223-L344 |
//! | `inet` | Address parsing and formatting | `lib/curlx/inet_pton.c`, `inet_ntop.c` |
//! | `parse` | The parser stages, in the C's order | `lib/urlapi.c` L182-L1286 |
//! | `scheme` | Scheme resolution and the default ports | `lib/url.c` L1469-L1471 |
//! | `strparse` | Numeric scanners with curl's exact semantics | `lib/curlx/strparse.c` L195 |
//!
//! `parse` is a directory rather than a file. Its root, `src/parse/mod.rs`,
//! declares the ten stage modules it orchestrates -- `junk`, `scheme`,
//! `authority`, `host`, `ipv6`, `port`, `path`, `query`, `file` and `redirect`,
//! eleven files counting the root itself -- and runs them in the order
//! `lib/urlapi.c` L1110-L1192 does. That order is behaviour rather than style,
//! because an earlier stage mutates the buffer a later one reads.
//!
//! # Import discipline
//!
//! Every cross-module reference is written out at its use site, by name, and
//! never by glob. In C this was a single translation unit whose file-scope
//! `static` helpers were implicitly visible throughout it; here each helper is
//! a crate-visible item in the module that owns it, so a reader of any one file
//! can see from its `use` lines exactly where every helper comes from. Nothing
//! is re-exported from this root.
//!
//! # Unsafe policy
//!
//! All `unsafe` lives in `src/ffi.rs`, and every block there carries a
//! `// SAFETY:` comment giving the reason the operation is sound. That is a
//! checked property rather than a convention: every other module declares
//! `#![forbid(unsafe_code)]` for itself, and this root denies
//! `clippy::undocumented_unsafe_blocks` and `unsafe_op_in_unsafe_fn` for the
//! whole crate, so an undocumented block or an unguarded operation inside an
//! `unsafe fn` fails the build rather than the review.
//!
//! # Panic posture
//!
//! A panic must never escape into C. Declaring every export `extern "C"`
//! already makes that outcome defined rather than undefined, because the
//! unwind runtime aborts when unwinding would leave such a frame, and
//! `[profile.release]` sets `panic = "abort"` outright besides. But an abort is
//! not a recoverable outcome, and a library that aborts curl is not a drop-in
//! replacement for one that returns an error code.
//!
//! Catching panics is not the answer either. `catch_unwind` appears nowhere in
//! this crate, on purpose: substituting a `CURLUcode` for a panic would hide
//! exactly the class of port defect the parity diff exists to expose. So the
//! panicking constructs are designed out instead. `unwrap`, `expect`, `panic!`,
//! direct indexing and unchecked arithmetic are denied below, for all fifteen
//! modules and all ten parser stages at once. Every lookahead in this crate is
//! a `get`, `first`, `last` or `split_last`, and every arithmetic step that
//! could overflow in principle is a `checked_*`, `wrapping_*` or `saturating_*`
//! call carrying the reason it cannot in practice.
//!
//! Test modules relax those denials, enumerated one at a time rather than
//! blanket, because a test's whole job is to panic when an assertion fails and
//! no test crosses the C boundary.
//!
//! # Memory ownership
//!
//! `docs/libcurl/curl_url_get.md` L45 and `include/curl/urlapi.h` L130-L131
//! both state that the content pointer `curl_url_get` hands back must be freed
//! with `curl_free`. That rules out the idiomatic Rust conversion: a pointer
//! from `CString::into_raw` has to return to Rust to be released, so
//! `CString::into_raw` appears nowhere in this crate.
//!
//! Instead every buffer that crosses into C originates in `src/alloc.rs` and is
//! allocated with the C allocator, which makes a plain `free` -- and therefore
//! libcurl's `curl_free`, whichever of its three resolutions is in force --
//! correct by construction rather than by discipline at each site. Two
//! consequences are reported rather than worked around, and
//! `docs/MEMORY-OWNERSHIP.md` sets out the whole chain: a memory-debug build of
//! libcurl validates pointers against its own allocation table and would
//! reject these, and an application that installs its own allocators would
//! release them with the wrong deallocator.
//!
//! # ABI parity is positional
//!
//! No line of C anywhere states that `CURLUE_BAD_IPV6` is 22. It is 22 because
//! it is the twenty-third enumerator declared at `include/curl/urlapi.h` L34,
//! and C numbers enumerators sequentially from zero when no explicit value is
//! given. The same holds for `CURLUPart` at L70-L82. Callers switch on those
//! numbers, so inserting, removing or reordering one entry silently breaks
//! every already-compiled caller.
//!
//! [`abi`] therefore writes all 60 values out as explicit integer constants
//! rather than as a Rust `enum`, whose discriminants would be exactly as
//! implicit as C's. The assertion block at the bottom of this file re-checks
//! every one of them at compile time, so an edit that reorders a constant
//! fails the build rather than the parity run. The run-time half of the same
//! check is `rust-urlapi/tests/abi_constants.rs`, one of the crate's five
//! Cargo integration tests: it reads the constants back through the `pub`
//! [`abi`] module and adds the structural properties the literals cannot show
//! on their own -- that the ordinals are contiguous and unique and that the
//! sixteen flag bits are distinct and union to the expected mask.
//!
//! # Faithfully reproduced findings
//!
//! Six places where the C does something surprising are reproduced rather than
//! fixed, because the port's job is parity and a silent improvement is a
//! divergence. `docs/KNOWN-DIVERGENCES.md` gives each in full, with the C lines
//! and the observable consequence.
//!
//! "Reproduced" below means *reproduced in the behaviour the API can observe*.
//! Two of the six findings are leaks as well as behaviours, and a leak is not
//! API-visible: no sequence of `curl_url_get()` and `curl_url_dup()` calls can
//! tell a leaked buffer from a released one. The `Effect` column therefore
//! separates the two.
//!
//! | Finding | What it is | Effect | Carried by |
//! |---------|------------|--------|------------|
//! | `FB1` | Handle duplication drops the guessed-scheme flag | Reproduced entire | `src/handle.rs` |
//! | `FB2` | The credential exit path nulls three fields without freeing them | The three parts read back absent; the leak is **not** reproduced | `src/parse/authority.rs` |
//! | `FB3` | The zone identifier is stored over an existing value and never cleared | The stale zone stays readable; the leak is **not** reproduced | `src/parse/ipv6.rs` |
//! | `FB4` | A colon with no digits after it is accepted, if a scheme is present | Reproduced entire | `src/parse/port.rs` |
//! | `FB5` | One declaration in the public header names no parameter | Reproduced entire | `include/curl_urlapi_rs.h` |
//! | `FB6` | Two writes land one byte past the logical length | Reproduced entire | `src/parse/ipv6.rs` over `src/dynbuf.rs` |
//!
//! The two leaks are omitted rather than overlooked. `Drop` on the owned
//! buffer releases the displaced value on the path where the C abandons it,
//! and reinstating the leak would mean suppressing `Drop` deliberately. The
//! divergence document records both omissions under `FB2` and `FB3`.
//!
//! `FB1` is worth singling out, because it is observable through the public API
//! and the upstream suite cannot catch it: the duplication sub-test of
//! `tests/libtest/lib1560.c` compares original against copy with flags of
//! zero, never with `CURLU_NO_GUESS_SCHEME`, which is the one flag that would
//! expose it.
//!
//! # Further reading
//!
//! - `docs/PORTING-NOTES.md`, the function-by-function mapping back to
//!   `lib/urlapi.c` with C line references.
//! - `docs/MEMORY-OWNERSHIP.md`, every C-side ownership assumption in one
//!   place.
//! - `docs/KNOWN-DIVERGENCES.md`, the six findings above and every residual
//!   divergence, the optional pure-Rust backend included.
//!
//! # Toolchain
//!
//! Edition 2021, pinned rather than incidental: under it the export attribute
//! is the plain `#[no_mangle]` and not the `#[unsafe(no_mangle)]` form later
//! editions require. The minimum supported version is 1.75, and the default and
//! drop-in configurations both hold to it. Selecting `idn-pure` raises the
//! effective minimum to 1.86 through its dependency tree, which is one reason
//! it is not the default; the other is that it falls outside the bit-for-bit
//! parity claim. This crate is not `no_std`: it allocates C-visible memory
//! through `libc` but is an ordinary `std` crate otherwise.

// DEAD-CODE POLICY. There is no crate-level allowance, deliberately.
//
// A blanket `#![allow(dead_code)]` here is tempting, because the feature matrix
// does make some items unreachable in some configuration: a build with no IDN
// backend never folds an IDN result code, and the drop-in build must not export
// `curl_url_strerror`. It is still the wrong remedy. Measured with
// `--force-warn dead_code`, a blanket allowance hides three dozen items across
// this crate's configurations, and among them two helpers carried comments
// claiming production callers they did not have -- which is to say that the one
// diagnostic able to catch a false claim was switched off in order to silence
// the items that were expected.
//
// So every item answers for itself, one of four ways:
//
// * **Wired.** An item can be dead only because nothing evaluates it -- a
//   compile-time proof held in a `const` that no code names. Such proofs are
//   written as anonymous `const _: () = ..` items, which a current rustc counts
//   as live, so the proof runs AND the item is not dead. The ABI parity block
//   below is one; `src/ffi.rs` has the other, and that one is named and
//   referenced from the allocation path, which is what roots a proof on the
//   declared floor as well.
// * **`#[cfg]`-gated narrowly.** An item reachable only on one target, under
//   one feature, or from the tests carries that condition instead of being
//   allowed everywhere.
// * **Removed.** A convenience wrapper with no caller is deleted rather than
//   excused.
// * **Allowed at the item, with the reason at the item.** What is left is a
//   deliberately complete compatibility surface: a table or an operation the
//   ported C module's own callers use, kept whole so that the port describes
//   the contract rather than the subset this crate happens to exercise. Each
//   one carries `#[allow(dead_code)]` and a sentence naming the caller it does
//   not have and the contract that keeps it.
//
// The point of the last case is that it is auditable: `grep` for the attribute
// and every occurrence has a justification beside it, which is not true of one
// blanket line at the crate root.
// The panic denials the "Panic posture" section above explains. `deny` rather
// than `forbid` so that a test module can relax one for its own assertions,
// which is the only place in this crate that does; production code never
// relaxes them, and a sibling module that cannot compile under one is a
// sibling module to fix, not a denial to weaken.
//
// `clippy::integer_arithmetic` is deliberately absent. It named this same
// check once and was renamed to `clippy::arithmetic_side_effects`; on the
// pinned toolchain, naming the old spelling emits a rename warning, and a
// warning is a build failure under the zero-warning requirement. Denying the
// current name is the whole of the coverage, not half of it.
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::expect_used)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
// The documentation denials, listed alphabetically like the group above. Named
// individually rather than by position, because each does a different job.
//
//   `clippy::missing_safety_doc` requires every `unsafe fn` to carry a
//   "# Safety" section stating its preconditions.
//   `clippy::undocumented_unsafe_blocks` requires every `unsafe` block to carry
//   a `// SAFETY:` comment. Together with the line above it, this is what makes
//   the specification's safety-comment requirement a compiler-checked fact
//   rather than a convention the review has to enforce.
//   `missing_docs` requires a doc comment on every item reachable from outside
//   the crate. That is a small set here -- this root, `abi` and its constants,
//   and `ffi` itself -- but it is the set a consumer reads.
//   `unsafe_op_in_unsafe_fn` stops an `unsafe fn` body from being implicitly
//   unsafe throughout, so each operation inside `src/ffi.rs` has to be pointed
//   at, and therefore commented, individually. It is `allow` by default in this
//   edition, so denying it is a deliberate tightening.
//
// `clippy::multiple_unsafe_ops_per_block` is not denied, and that is a
// judgement rather than an oversight: `curl_url_cleanup` runs the handle's
// `Drop` and releases its block in one operation pair whose safety argument is
// genuinely single, and splitting it would produce two comments restating one
// reason.
#![deny(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

// The module tree, in the order the plan fixes: alphabetical, fifteen entries,
// fourteen resolving to sibling files and `parse` to `src/parse/mod.rs`. There
// is no sixteenth; a helper that feels homeless belongs in the module that
// owns the behaviour it serves.
//
// Two are public and thirteen are not.
//
// `abi` is public because the ABI constants are not cross-module helpers.
// They mirror the public C header and are part of what this crate promises,
// and `rust-urlapi/tests/abi_constants.rs` is a Cargo integration test, which
// links this crate as an external crate and can therefore name only `pub`
// items. That file reads every one of the 60 constants back through this
// module, so the `pub` is load-bearing rather than anticipatory: making it
// private again breaks the run-time half of the ABI verification.
// `rust-urlapi/tests/ffi_surface.rs` reaches it the same way. `ffi` is public
// because it is the facade.
//
// Neither widens the C ABI, which is the reasonable first worry about a `pub
// mod` in a crate whose export set is audited. A cdylib exposes symbols the
// way an executable does: a plain `pub fn foo() {}` is not an exported symbol,
// and only an annotated `#[no_mangle] pub extern "C" fn foo() {}` is. Rust
// visibility and C linkage are separate mechanisms, so making a module `pub`
// adds nothing to the symbol table, which is a property any symbol-set check
// over the archive will see -- `nm -g --defined-only` today, and
// `rust-urlapi/scripts/check-abi.sh` once that script lands. `src/ffi.rs`
// demonstrates the same point from the other side: every item it declares is
// `pub(crate)`, its exports included, and they reach the symbol table purely
// by attribute.
pub mod abi;
mod alloc;
mod ctype;
mod decode;
mod dynbuf;
mod encode;
mod error;
pub mod ffi;
mod getset;
mod handle;
mod idn;
mod inet;
mod parse;
mod scheme;
mod strparse;

// The two C integer widths the assertion block below needs, imported by name
// like every other dependency in this crate. `CURLUcode` and `CURLUPart` are
// both aliases of `c_int` in `abi`, which is why one helper serves both.
use ::core::ffi::{c_int, c_uint};

/// True when `values` holds `first`, `first + 1`, `first + 2` and so on with no
/// gap and no repeat.
///
/// The first of the three small helpers that are the whole of the machinery in
/// this file. It exists to make a structural claim the per-constant assertions
/// cannot make on their own: that a run of enumerators really is a contiguous
/// run.
///
/// Slice patterns rather than an index, so the crate's
/// `clippy::indexing_slicing` denial holds here too, and `wrapping_add` rather
/// than `+`, so its `clippy::arithmetic_side_effects` denial does as well.
/// Neither could actually trigger -- the longest run this is asked about is 33
/// -- but the file that sets the denials is the last place that should need an
/// exception to them.
// Called only from the anonymous parity block below, which every rustc
// evaluates but which rustc 1.75 -- the floor `Cargo.toml` declares -- does not
// count as a *use* of what it calls. So the proof runs on the floor and the
// three helpers are reported dead there; the allowance is a compatibility
// allowance with that version, spelled the same way the block's own
// `clippy::assertions_on_constants` allowance is, and not an excuse for a
// disconnected helper. Removing it on a newer toolchain would reintroduce three
// warnings on the declared floor, which the zero-warning requirement forbids.
#[allow(dead_code)]
const fn ascends_from(values: &[c_int], first: c_int) -> bool {
    match values {
        [] => true,
        [head, tail @ ..] => *head == first && ascends_from(tail, first.wrapping_add(1)),
    }
}

/// The bitwise union of `flags`.
// Called from the parity block below only, and allowed for the reason
// `ascends_from` above states in full.
#[allow(dead_code)]
const fn or_all(flags: &[c_uint]) -> c_uint {
    match flags {
        [] => 0,
        [head, tail @ ..] => *head | or_all(tail),
    }
}

/// True when every entry of `flags` has exactly one bit set.
// Called from the parity block below only, and allowed for the reason
// `ascends_from` above states in full.
#[allow(dead_code)]
const fn all_single_bit(flags: &[c_uint]) -> bool {
    match flags {
        [] => true,
        [head, tail @ ..] => head.count_ones() == 1 && all_single_bit(tail),
    }
}

/// Compile-time re-check of every number that crosses the C boundary.
///
/// The values themselves are documented on the constants in [`abi`]; the claim
/// here is only that they are these numbers and no others. It is worth making
/// twice because parity is positional, as the "ABI parity is positional"
/// section of the crate documentation explains: the ordinals appear nowhere in
/// the C source, they emerge from declaration order, and callers switch on them
/// numerically. Writing the positions out a second time turns an accidental
/// reorder in [`abi`] into a build failure instead of a silent ABI break.
///
/// `const` assertions rather than tests, so that they hold for every build of
/// every feature configuration and target, including builds that never run
/// `cargo test`. No dependency is involved: `assert!` has worked in a constant
/// since well before this crate's minimum supported version, so no
/// static-assertion crate is needed and none is added.
///
/// Two kinds of check are here and they catch different mistakes. The
/// per-constant assertions catch a typo in one value. The relationship
/// assertions that follow them catch a systematic error a per-constant list
/// cannot see: an entry deleted along with its assertion, an entry inserted, or
/// a whole block shifted by one.
///
/// Clippy releases up to and including 1.75, the crate's declared minimum,
/// report a constant assertion as `assert!(true)` that "will be optimized out
/// by the compiler" even inside a `const` item, where it is the opposite of
/// what happens: the expression is evaluated at compile time and nothing
/// survives to optimize. Later releases exempt const contexts. Measured on the
/// declared floor, every one of the assertions below is reported, so
/// `cargo +1.75.0 clippy --locked --all-targets -- -D warnings` fails with 64
/// errors for the lib target and 65 for the lib-test target without this
/// allowance. It is therefore a compatibility allowance with the declared
/// floor, spelled the same way `src/inet.rs`, `src/ffi.rs`, `src/encode.rs`
/// and `src/parse/{file,ipv6}.rs` spell theirs, and not a suppressed finding:
/// removing the assertions to satisfy the lint would delete the compile-time
/// half of the ABI parity check that the crate documentation's "ABI parity is
/// positional" section requires, and `rust-urlapi/tests/abi_constants.rs` is
/// the run-time half rather than a substitute for it.
// Anonymous rather than named: a current rustc treats an anonymous `const _`
// item as live, so the block itself is never reported as dead code, while a
// named item is -- and a named item's body does not count as a use of what it
// calls either. On rustc 1.75, the floor `Cargo.toml` declares, even the
// anonymous form does not root what it calls, which is why the three helpers
// above carry an allowance naming that version. The evaluation happens on every
// version regardless -- a `const` whose body fails an assertion fails the build
// whatever its name -- so the spelling changes only the diagnostics, and it
// changes them in the direction of telling the truth.
#[allow(clippy::assertions_on_constants)]
const _: () = {
    // The 33 `CURLUcode` values, `include/curl/urlapi.h` L34-L68. The header
    // carries the ordinal as a trailing comment for 1 through 31 but not for
    // the first or the last, so those two are the ones to check against the
    // source: `CURLUE_OK` is 0 because it is declared first, and `CURLUE_LAST`
    // is 32 because 32 enumerators precede it.
    assert!(abi::CURLUE_OK == 0);
    assert!(abi::CURLUE_BAD_HANDLE == 1);
    assert!(abi::CURLUE_BAD_PARTPOINTER == 2);
    assert!(abi::CURLUE_MALFORMED_INPUT == 3);
    assert!(abi::CURLUE_BAD_PORT_NUMBER == 4);
    assert!(abi::CURLUE_UNSUPPORTED_SCHEME == 5);
    assert!(abi::CURLUE_URLDECODE == 6);
    assert!(abi::CURLUE_OUT_OF_MEMORY == 7);
    assert!(abi::CURLUE_USER_NOT_ALLOWED == 8);
    assert!(abi::CURLUE_UNKNOWN_PART == 9);
    assert!(abi::CURLUE_NO_SCHEME == 10);
    assert!(abi::CURLUE_NO_USER == 11);
    assert!(abi::CURLUE_NO_PASSWORD == 12);
    assert!(abi::CURLUE_NO_OPTIONS == 13);
    assert!(abi::CURLUE_NO_HOST == 14);
    assert!(abi::CURLUE_NO_PORT == 15);
    assert!(abi::CURLUE_NO_QUERY == 16);
    assert!(abi::CURLUE_NO_FRAGMENT == 17);
    assert!(abi::CURLUE_NO_ZONEID == 18);
    assert!(abi::CURLUE_BAD_FILE_URL == 19);
    assert!(abi::CURLUE_BAD_FRAGMENT == 20);
    assert!(abi::CURLUE_BAD_HOSTNAME == 21);
    assert!(abi::CURLUE_BAD_IPV6 == 22);
    assert!(abi::CURLUE_BAD_LOGIN == 23);
    assert!(abi::CURLUE_BAD_PASSWORD == 24);
    assert!(abi::CURLUE_BAD_PATH == 25);
    assert!(abi::CURLUE_BAD_QUERY == 26);
    assert!(abi::CURLUE_BAD_SCHEME == 27);
    assert!(abi::CURLUE_BAD_SLASHES == 28);
    assert!(abi::CURLUE_BAD_USER == 29);
    assert!(abi::CURLUE_LACKS_IDN == 30);
    assert!(abi::CURLUE_TOO_LARGE == 31);
    assert!(abi::CURLUE_LAST == 32);

    // The 11 `CURLUPart` values, L70-L82. The header gives no ordinals at all
    // here, so every one of these is positional.
    assert!(abi::CURLUPART_URL == 0);
    assert!(abi::CURLUPART_SCHEME == 1);
    assert!(abi::CURLUPART_USER == 2);
    assert!(abi::CURLUPART_PASSWORD == 3);
    assert!(abi::CURLUPART_OPTIONS == 4);
    assert!(abi::CURLUPART_HOST == 5);
    assert!(abi::CURLUPART_PORT == 6);
    assert!(abi::CURLUPART_PATH == 7);
    assert!(abi::CURLUPART_QUERY == 8);
    assert!(abi::CURLUPART_FRAGMENT == 9);
    assert!(abi::CURLUPART_ZONEID == 10);

    // The 16 `CURLU_*` flag bits, L84-L105. These the header does spell out,
    // as `1 << n`, so the shift is repeated here in the same form rather than
    // resolved to a decimal that would have to be trusted.
    assert!(abi::CURLU_DEFAULT_PORT == 1 << 0);
    assert!(abi::CURLU_NO_DEFAULT_PORT == 1 << 1);
    assert!(abi::CURLU_DEFAULT_SCHEME == 1 << 2);
    assert!(abi::CURLU_NON_SUPPORT_SCHEME == 1 << 3);
    assert!(abi::CURLU_PATH_AS_IS == 1 << 4);
    assert!(abi::CURLU_DISALLOW_USER == 1 << 5);
    assert!(abi::CURLU_URLDECODE == 1 << 6);
    assert!(abi::CURLU_URLENCODE == 1 << 7);
    assert!(abi::CURLU_APPENDQUERY == 1 << 8);
    assert!(abi::CURLU_GUESS_SCHEME == 1 << 9);
    assert!(abi::CURLU_NO_AUTHORITY == 1 << 10);
    assert!(abi::CURLU_ALLOW_SPACE == 1 << 11);
    assert!(abi::CURLU_PUNYCODE == 1 << 12);
    assert!(abi::CURLU_PUNY2IDN == 1 << 13);
    assert!(abi::CURLU_GET_EMPTY == 1 << 14);
    assert!(abi::CURLU_NO_GUESS_SCHEME == 1 << 15);

    // The four supporting constants the module borrows from elsewhere in
    // libcurl: `MAX_SCHEME_LEN` at `lib/urlapi.c` L55, `DEFAULT_SCHEME` at
    // L84, `CURL_MAX_INPUT_LENGTH` at `lib/urldata.h` L131 and
    // `PROTOPT_URLOPTIONS` at `lib/urldata.h` L545. The last is bit 10 and
    // that is not an off-by-one: `lib/urldata.h` L544 records bit 9 as retired,
    // so the sequence of defined bits has a hole just below this one.
    assert!(abi::MAX_SCHEME_LEN == 40);
    assert!(abi::CURL_MAX_INPUT_LENGTH == 8_000_000);
    assert!(abi::PROTOPT_URLOPTIONS == 1 << 10);

    // `DEFAULT_SCHEME` is the one supporting constant that is a string, and
    // `==` cannot be used on it here: `PartialEq` is not a `const` trait, so
    // comparing two `&str` values is not allowed in a constant. A byte-string
    // pattern is, and says the same thing.
    //
    // Both spellings are checked, because `abi` keeps a NUL-terminated
    // companion for the one call site that needs a C string and the point of
    // having it there is that the two cannot drift apart.
    assert!(matches!(abi::DEFAULT_SCHEME.as_bytes(), b"https"));
    assert!(matches!(abi::DEFAULT_SCHEME_CSTR, b"https\0"));

    // The relationship checks. Each array's length is written into its type, so
    // an entry added to or removed from one of these lists fails to compile
    // here even if the corresponding per-constant assertion above were removed
    // along with it. That is the count pinned; what follows pins the shape.
    const CODES: [c_int; 33] = [
        abi::CURLUE_OK,
        abi::CURLUE_BAD_HANDLE,
        abi::CURLUE_BAD_PARTPOINTER,
        abi::CURLUE_MALFORMED_INPUT,
        abi::CURLUE_BAD_PORT_NUMBER,
        abi::CURLUE_UNSUPPORTED_SCHEME,
        abi::CURLUE_URLDECODE,
        abi::CURLUE_OUT_OF_MEMORY,
        abi::CURLUE_USER_NOT_ALLOWED,
        abi::CURLUE_UNKNOWN_PART,
        abi::CURLUE_NO_SCHEME,
        abi::CURLUE_NO_USER,
        abi::CURLUE_NO_PASSWORD,
        abi::CURLUE_NO_OPTIONS,
        abi::CURLUE_NO_HOST,
        abi::CURLUE_NO_PORT,
        abi::CURLUE_NO_QUERY,
        abi::CURLUE_NO_FRAGMENT,
        abi::CURLUE_NO_ZONEID,
        abi::CURLUE_BAD_FILE_URL,
        abi::CURLUE_BAD_FRAGMENT,
        abi::CURLUE_BAD_HOSTNAME,
        abi::CURLUE_BAD_IPV6,
        abi::CURLUE_BAD_LOGIN,
        abi::CURLUE_BAD_PASSWORD,
        abi::CURLUE_BAD_PATH,
        abi::CURLUE_BAD_QUERY,
        abi::CURLUE_BAD_SCHEME,
        abi::CURLUE_BAD_SLASHES,
        abi::CURLUE_BAD_USER,
        abi::CURLUE_LACKS_IDN,
        abi::CURLUE_TOO_LARGE,
        abi::CURLUE_LAST,
    ];
    const PARTS: [c_int; 11] = [
        abi::CURLUPART_URL,
        abi::CURLUPART_SCHEME,
        abi::CURLUPART_USER,
        abi::CURLUPART_PASSWORD,
        abi::CURLUPART_OPTIONS,
        abi::CURLUPART_HOST,
        abi::CURLUPART_PORT,
        abi::CURLUPART_PATH,
        abi::CURLUPART_QUERY,
        abi::CURLUPART_FRAGMENT,
        abi::CURLUPART_ZONEID,
    ];
    const FLAGS: [c_uint; 16] = [
        abi::CURLU_DEFAULT_PORT,
        abi::CURLU_NO_DEFAULT_PORT,
        abi::CURLU_DEFAULT_SCHEME,
        abi::CURLU_NON_SUPPORT_SCHEME,
        abi::CURLU_PATH_AS_IS,
        abi::CURLU_DISALLOW_USER,
        abi::CURLU_URLDECODE,
        abi::CURLU_URLENCODE,
        abi::CURLU_APPENDQUERY,
        abi::CURLU_GUESS_SCHEME,
        abi::CURLU_NO_AUTHORITY,
        abi::CURLU_ALLOW_SPACE,
        abi::CURLU_PUNYCODE,
        abi::CURLU_PUNY2IDN,
        abi::CURLU_GET_EMPTY,
        abi::CURLU_NO_GUESS_SCHEME,
    ];

    // Contiguity. Both C enumerations run from zero with no gap, which is what
    // makes their ordinals positions in the first place, and the lists above
    // are in header declaration order. A block shifted by one, or a value
    // repeated, fails here.
    assert!(ascends_from(&CODES, 0));
    assert!(ascends_from(&PARTS, 0));

    // Distinctness and completeness of the flag set. Sixteen entries, each with
    // exactly one bit set, whose union is all sixteen low bits: with sixteen
    // single-bit values covering sixteen distinct positions, no two of them can
    // be the same bit, so this is the pairwise-distinctness claim as well as the
    // completeness one. A block shifted by one would union to `0x1fffe` and
    // fail.
    assert!(all_single_bit(&FLAGS));
    assert!(or_all(&FLAGS) == 0xffff);
};
