// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! A binary-compatible Rust port of curl's URL API, `lib/urlapi.c`.
//!
//! The crate builds as a static library, a shared library and an `rlib`, and
//! the first of those is meant to be linked in place of the object file
//! `lib/urlapi.c` produces. It exports the same C symbols with the same
//! signatures, declared by `include/curl/urlapi.h` L34-L149, and it changes no
//! observable behaviour: where the C implementation does something surprising,
//! this one does the same surprising thing and says so at the site.
//!
//! # Module tree
//!
//! | Module | Responsibility | Ported from |
//! |--------|----------------|-------------|
//! | [`abi`] | The 60 ABI constants, as explicit integers | `include/curl/urlapi.h` L34-L105 |
//! | [`alloc`] | The C-allocator adapter and the owned buffer | `lib/escape.c` L189-L192 |
//! | [`ctype`] | Character classification, hex, case folding | `lib/curl_ctype.h`, `lib/strcase.c` |
//! | [`decode`] | Percent-decoding with control-byte rejection | `lib/escape.c` L105 |
//! | [`dynbuf`] | The growable buffer | `lib/curlx/dynbuf.c` |
//! | [`encode`] | Percent-encoding, both directions | `lib/urlapi.c` L104-L180, L1779-L1803 |
//! | [`error`] | Code translation and the 33 message strings | `lib/strerror.c` L420-L531 |
//! | `ffi` | The exported symbols and the crate's only `unsafe` | `lib/urlapi.c`, `lib/urlapi-int.h` |
//! | [`getset`] | Serialization and the part get/set rules | `lib/urlapi.c` L1357-L1998 |
//! | [`handle`] | The owned handle replacing `struct Curl_URL` | `lib/urlapi.c` L67-L102 |
//! | [`idn`] | Internationalized-domain conversion | `lib/idn.c` L223-L344 |
//! | [`inet`] | Address parsing and formatting | `lib/curlx/inet_pton.c`, `inet_ntop.c` |
//! | [`parse`] | The eleven parser stages, in the C's order | `lib/urlapi.c` L182-L1286 |
//! | [`scheme`] | Scheme resolution and default ports | `lib/url.c` L1469-L1471 |
//! | [`strparse`] | Numeric scanners with curl's exact semantics | `lib/curlx/strparse.c` L195 |
//!
//! Nothing is re-exported. Every cross-module reference is written out at its
//! use site, by name and never by glob, so that a reader of any one file can
//! see where each helper comes from.
//!
//! # Lint policy, and why it is what it is
//!
//! A panic that reaches an `extern "C"` frame aborts the calling process: RFC
//! 2945 makes that a defined outcome rather than undefined behaviour, but it
//! is not a recoverable one, and a library that aborts curl is not a drop-in
//! replacement for one that returns an error code. Catching panics is not the
//! answer either, because substituting an error code for a panic would hide
//! exactly the class of port defect the parity diff exists to expose.
//!
//! So the panicking constructs are **designed out**: `unwrap`, `expect`,
//! `panic!`, direct indexing and unchecked arithmetic are denied crate-wide
//! below. Every lookahead in this crate is a `get`, `first`, `last` or
//! `split_last`, and every arithmetic step that could overflow in principle is
//! a `checked_*` or `saturating_*` call with the reason it cannot in practice.
//!
//! Test modules relax the denials, enumerated rather than blanket, because a
//! test's whole job is to panic when an assertion fails and no test crosses
//! the C boundary.
//!
//! # Unsafe policy
//!
//! All `unsafe` lives in one module, `src/ffi.rs`, and every block there
//! carries a `// SAFETY:` comment. Every other module states the guarantee in
//! a form the compiler enforces, with its own `#![forbid(unsafe_code)]`, so
//! the single-unsafe-island property is checked rather than merely intended.
//!
//! # ABI parity
//!
//! `include/curl/urlapi.h` numbers its three enumerations implicitly, so
//! parity is positional: the numbers are nowhere in the C source and emerge
//! from declaration order. [`abi`] therefore writes them as explicit integers,
//! and the assertion block at the bottom of this file re-checks all 60 of them
//! at compile time. `rust-urlapi/tests/abi_constants.rs` checks the same set at
//! run time. Two independent checks of one transcription is the point: an
//! edit that reorders a constant fails the build rather than the parity run.

// DEAD-CODE POLICY. Stated once, here, for the whole crate.
//
// Which items this crate reaches depends on its feature set and its target:
// `src/scheme.rs` and `src/idn.rs` each compile one of several backends,
// `src/error.rs` holds a message table that only the `strerror`-gated export
// consults, `src/alloc.rs` and `src/dynbuf.rs` are deliberately complete
// adapters so that no other module has a reason to reach past them, and
// `src/inet.rs` is reached only from the bracketed-address stage. A crate held
// to zero warnings cannot build clean across that matrix without an
// allowance, and mirroring the feature matrix in `#[cfg]` attributes on each
// item would make every one of those tables invisible to `cargo test` in some
// configuration.
//
// So the allowance is stated once, with its reason, rather than repeated per
// module or decided by the feature matrix. It is scoped to this one lint.
#![allow(dead_code)]
// The panic denials the module documentation above explains. `deny` rather
// than `forbid` so that a test module can relax them for its own assertions,
// which is the only place in this crate that does.
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::expect_used)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]

mod abi;
mod alloc;
mod ctype;
mod decode;
mod dynbuf;
mod encode;
mod error;
mod ffi;
mod getset;
mod handle;
mod idn;
mod inet;
mod parse;
mod scheme;
mod strparse;

/// Compile-time re-check of every value in `include/curl/urlapi.h` L34-L105.
///
/// The header numbers its enumerations implicitly, so each constant's value is
/// its position. This block writes the positions out a second time and refuses
/// to build if the two transcriptions disagree, which is what makes an
/// accidental reordering in [`abi`] a build failure instead of a silent ABI
/// break. `const` assertions rather than tests, so that they hold for every
/// build of every configuration, including one that never runs `cargo test`.
///
/// The values themselves are documented on the constants in [`abi`]; the point
/// here is only that they are these numbers and no others.
const _ABI_PARITY: () = {
    // The 33 `CURLUcode` values, `include/curl/urlapi.h` L34-L68.
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

    // The 11 `CURLUPart` values, L70-L82.
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

    // The 16 `CURLU_*` flag bits, L84-L105.
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

    // The four supporting constants the module borrows from elsewhere:
    // `MAX_SCHEME_LEN` at `lib/urlapi.c` L55, `DEFAULT_SCHEME` at L84,
    // `CURL_MAX_INPUT_LENGTH` at `lib/urldata.h` L131 and
    // `PROTOPT_URLOPTIONS` at `lib/urldata.h` L545.
    assert!(abi::MAX_SCHEME_LEN == 40);
    assert!(abi::CURL_MAX_INPUT_LENGTH == 8_000_000);
    assert!(abi::PROTOPT_URLOPTIONS == 1 << 10);
};
