//! `curlinfo` — the test-harness capability probe.
//!
//! This is the Rust analog of the C `src/curlinfo.c` helper. `tests/runtests.pl`
//! drives feature-gated test selection from **two** sources: the `curl --version`
//! capability line (handled by the `curl-rs` binary) **and** this separate
//! `curlinfo` helper, which reports the `CURL_DISABLE_*` / build gates that are
//! intentionally *not* surfaced by `curl -V` — `cookies`, `proxy`, `Mime`,
//! `HTTP-auth`, `form-api`, `digest`, `netrc`, and so on.
//!
//! The harness (`runtests.pl::checksystemfeatures`) opens this binary as a
//! subprocess and parses each stdout line with the regex `/([^:]*): ([ONF]*)/`,
//! recording `ON` capabilities into its `%feature` map and `OFF` ones into a
//! disabled list. When the helper is missing, every one of those flags is left
//! unset and the matching tests are **silently skipped** — a "green" run that is
//! not actually trustworthy (AAP §0.7.3). Shipping this companion binary is thus
//! a requirement of the G7 test-suite-parity goal.
//!
//! The capability table is owned by [`curl_rs_lib::version::curlinfo_capabilities`]
//! so the reported values stay in lockstep with the library crate's compiled
//! feature set (e.g. disabling the `cookies` Cargo feature flips `cookies: OFF`
//! here in the same build). The output order and exact casing mirror
//! `src/curlinfo.c` because the harness matches these names verbatim against the
//! `<features>` tags in `tests/data`.

fn main() {
    // One `name: ON|OFF` line per capability, matching the C helper's `puts()`
    // loop. `curlinfo_capabilities()` yields the entries in `src/curlinfo.c`
    // order with values derived from the crate's compile-time configuration.
    for &(name, enabled) in curl_rs_lib::version::curlinfo_capabilities() {
        println!("{name}: {}", if enabled { "ON" } else { "OFF" });
    }
}
