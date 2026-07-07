// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `curl_slist_*` C ABI entry points (derived from `include/curl/curl.h`; string linked list).
//
// NOTE: Compile-time placeholder module. The concrete `#[no_mangle] pub extern "C"`
// entry points that this module owns are authored by that module's dedicated agent
// (build-order step b, AAP §0.7.3). It is declared by the crate root (`lib.rs`) so the
// FFI crate compiles and cbindgen can parse the full module tree as a unit; the shared
// boundary helpers live in `lib.rs` and are consumed here once the entry points land.
