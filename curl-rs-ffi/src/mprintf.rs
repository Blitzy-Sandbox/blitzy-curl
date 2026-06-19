//! The public `curl_mprintf` printf family — curl's portable `*printf`
//! replacements (`include/curl/mprintf.h`, enumerated in `lib/libcurl.def`).
//!
//! This module accounts for the ten exported printf symbols of the libcurl C
//! ABI. Unlike the sibling FFI modules, **it defines none of them in Rust** —
//! it documents *why* and points at where the symbols actually come from.
//!
//! # The ten symbols (`include/curl/mprintf.h:L56-L76`)
//!
//! | Symbol             | C signature                                                     | Family   |
//! |--------------------|-----------------------------------------------------------------|----------|
//! | `curl_mprintf`     | `int curl_mprintf(const char *fmt, ...)`                        | variadic |
//! | `curl_mfprintf`    | `int curl_mfprintf(FILE *fd, const char *fmt, ...)`             | variadic |
//! | `curl_msprintf`    | `int curl_msprintf(char *buf, const char *fmt, ...)`            | variadic |
//! | `curl_msnprintf`   | `int curl_msnprintf(char *buf, size_t max, const char *fmt, ...)`| variadic |
//! | `curl_mvprintf`    | `int curl_mvprintf(const char *fmt, va_list ap)`                | va_list  |
//! | `curl_mvfprintf`   | `int curl_mvfprintf(FILE *fd, const char *fmt, va_list ap)`     | va_list  |
//! | `curl_mvsprintf`   | `int curl_mvsprintf(char *buf, const char *fmt, va_list ap)`    | va_list  |
//! | `curl_mvsnprintf`  | `int curl_mvsnprintf(char *buf, size_t max, const char *fmt, va_list ap)` | va_list |
//! | `curl_maprintf`    | `char *curl_maprintf(const char *fmt, ...)`                     | variadic |
//! | `curl_mvaprintf`   | `char *curl_mvaprintf(const char *fmt, va_list ap)`             | va_list  |
//!
//! (The header has eleven `CURL_EXTERN`-adjacent lines; the eleventh is the
//! `#include "curl.h"` at `mprintf.h:L29`, not a function.)
//!
//! # Why nothing is defined in Rust here
//!
//! On stable Rust (workspace MSRV 1.75, edition 2021) the ABI of *every* symbol
//! above is inexpressible:
//!
//! * the `curl_m*printf` group is **C-variadic** (`fn(fmt, ...)`), and defining
//!   a variadic `extern "C"` function requires the nightly-only `c_variadic`
//!   feature; and
//! * the `curl_mv*printf` group takes a **`va_list`**, and there is no stable
//!   `va_list` type (`core::ffi::VaList` is unstable).
//!
//! A `#[no_mangle] pub extern "C" fn` definition is therefore impossible for all
//! ten. (Note: *importing* / *calling* a C-variadic function from Rust **is**
//! stable — only *defining* one is not — which is what the test module below
//! relies on.)
//!
//! # Where the symbols come from — the C trampoline (AAP §0.7.2)
//!
//! The ten functions are defined in [`csrc/mprintf.c`], a tiny C translation
//! unit compiled by [`build.rs`] via the `cc` crate and linked into the
//! `libcurl`-compatible `cdylib` / `staticlib` with the `+whole-archive`
//! modifier (so the unreferenced objects are retained and their default-
//! visibility symbols reach the exported symbol table). They are real exported
//! `curl_*` symbols and are counted by the `nm` / `objdump` parity gate against
//! `lib/libcurl.def`, exactly like a Rust-defined export. The C compiler handles
//! both the variadic and `va_list` ABIs natively on all four targets (linux
//! x86_64/aarch64, macOS x86_64/arm64).
//!
//! [`csrc/mprintf.c`]: ../../../curl-rs-ffi/csrc/mprintf.c
//! [`build.rs`]: ../../../curl-rs-ffi/build.rs
//!
//! # Documented no-C-mandate exception (AAP §0.8.2 / §0.8.3)
//!
//! AAP §0.8.2 forbids C linkage against `libcurl` / `libssl` / C TLS libraries
//! and C protocol/TLS backends. The trampoline is **none** of those: it is a
//! dependency-free, calling-convention-only adapter that forwards each call
//! straight to the platform C library's standard `printf` family. It links no
//! third-party C library and implements no protocol or TLS logic, so it is the
//! established, minimal mechanism for a C ABI that stable Rust provably cannot
//! express — and is documented as such in `build.rs` and both `Cargo.toml`
//! files, per AAP §0.8.3. It does not weaken the memory-safety mandate: all
//! raw-pointer handling already lives in this single FFI crate (AAP §0.7.1).
//!
//! # Behavioral parity (oracle: `lib/mprintf.c`)
//!
//! curl ships its own formatter in `lib/mprintf.c`. For the **standard** format
//! directives the test suite exercises (`%d`, `%u`, `%ld`, `%lld`, `%zd`,
//! `%x`/`%X`, `%o`, `%c`, `%s`, `%p`, `%e`/`%E`, `%f`, `%g`/`%G`, the width /
//! precision / flag grammar, and `%%`), that engine reproduces ISO C `printf`
//! semantics — precisely what the platform `v*printf` functions the trampoline
//! forwards to provide. Forwarding is thus behavior-preserving for the
//! specifiers the suite relies on.
//!
//! One return-value detail is normalised in [`csrc/mprintf.c`] to match the
//! oracle exactly: curl's `curl_msnprintf` / `curl_mvsnprintf` return the number
//! of bytes *actually stored* (excluding the NUL) — capped at `maxlength - 1` on
//! truncation, `0` when `maxlength == 0` — rather than ISO C99's *would-be*
//! length. The trampoline transforms `vsnprintf`'s C99 return value accordingly,
//! a difference confirmed against curl's shipped `libcurl` as a differential
//! oracle. The formatted buffer contents are identical either way.
//!
//! # Memory ownership (`curl_maprintf` / `curl_mvaprintf`)
//!
//! These two return a heap buffer the **caller** releases with
//! [`curl_free`](crate::global::curl_free). Because `curl_free` wraps
//! `libc::free` (see [`crate::global`]) and the trampoline allocates with
//! `vasprintf` / `malloc` from that same C heap, the allocate-here / free-there
//! contract is consistent — matching curl's own `curl_maprintf` ownership rule
//! ("anything allocated by the library is freed via `curl_free`").
//!
//! # Future direction
//!
//! If the project later ports curl's own `lib/mprintf.c` engine to safe Rust
//! (eliminating the C trampoline entirely), this module is the home for that
//! formatter: the Rust core would expose a safe `format`-style API, and only the
//! ten variadic / `va_list` ABI entry points would remain in C (or move to a
//! nightly `c_variadic` definition). For parity now, the platform-`printf`
//! trampoline is correct and sufficient.

// This module intentionally contains no runtime Rust items: the ten printf
// symbols are provided by `csrc/mprintf.c` (see the module docs above). Defining
// any of them here with `#[no_mangle]` would create duplicate-symbol link
// errors against the C trampoline, so it is deliberately avoided.

#[cfg(test)]
mod tests {
    //! Behavioral tests for the C printf trampoline.
    //!
    //! These exercise the **real** exported symbols (linked from
    //! `csrc/mprintf.c` via `build.rs`) by *importing* them — importing a
    //! C-variadic function is stable Rust even though defining one is not. The
    //! buffer-based and allocating variants have observable results, so they are
    //! the focus; the `FILE*` / stdout and `va_list` variants are thin one-line
    //! forwards verified at the C level. `curl_maprintf` internally delegates to
    //! `curl_mvaprintf`, so testing it also exercises the `va_list` allocator.

    use core::ffi::{c_char, c_int, c_void, CStr};

    // Import the variadic entry points defined by the C trampoline. (Only the
    // `...`-variadic members are importable in stable Rust; the `va_list`
    // members are not, for lack of a stable `va_list` type.)
    extern "C" {
        fn curl_msnprintf(
            buffer: *mut c_char,
            maxlength: libc::size_t,
            format: *const c_char,
            ...
        ) -> c_int;
        fn curl_msprintf(buffer: *mut c_char, format: *const c_char, ...) -> c_int;
        fn curl_maprintf(format: *const c_char, ...) -> *mut c_char;
    }

    // NUL-terminated format literals. `b"...\0"` byte strings (rather than the
    // `c"..."` C-string literals stabilized only in Rust 1.77) keep these tests
    // within the workspace MSRV of 1.75 (edition 2021).
    const FMT_D_S_X: &[u8] = b"%d-%s-%x\0";
    const FMT_S: &[u8] = b"%s\0";
    const FMT_05D: &[u8] = b"%05d\0";
    const FMT_D_S: &[u8] = b"%d-%s\0";
    const ARG_X: &[u8] = b"x\0";
    const ARG_ABCDEF: &[u8] = b"abcdef\0";

    /// `curl_msnprintf` formats exactly like curl's `lib/mprintf.c`. With a
    /// large-enough buffer (no truncation) the return value is the formatted
    /// length — which is identical to both curl and the C library `snprintf`.
    /// Curl's deliberately non-C99 *truncation* return value is covered by the
    /// dedicated test below.
    #[test]
    fn msnprintf_matches_snprintf_semantics() {
        let mut buf = [0u8; 64];
        // SAFETY: `buf` is a 64-byte writable buffer; the format string is a
        // NUL-terminated literal whose three conversions (`%d`, `%s`, `%x`)
        // match the trailing `c_int`, NUL-terminated `*const c_char`, and
        // `c_int` arguments. All byte-string literals are NUL-terminated.
        let n = unsafe {
            curl_msnprintf(
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                FMT_D_S_X.as_ptr() as *const c_char,
                7_i32,
                ARG_X.as_ptr() as *const c_char,
                255_i32,
            )
        };
        assert_eq!(n, 6, "return value is the formatted length");
        // SAFETY: the trampoline NUL-terminated the buffer within `buf.len()`.
        let s = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
        assert_eq!(s.to_str().unwrap(), "7-x-ff");
    }

    /// On truncation curl's `curl_msnprintf` returns the number of bytes
    /// ACTUALLY stored — excluding the NUL, i.e. `maxlength - 1` — NOT the C99
    /// would-be length. This mirrors curl's `lib/mprintf.c` exactly (verified
    /// against curl's shipped `libcurl` as a differential oracle: `("%s",
    /// "abcdef")` with `n=4` yields `3`/`"abc"`) and is the wire/behavioral
    /// parity contract that `tests/libtest` consumers (e.g. `lib556.c`, which
    /// captures the return value) rely on.
    #[test]
    fn msnprintf_truncates_with_curl_semantics() {
        let mut buf = [0u8; 4]; // room for 3 chars + NUL
        // SAFETY: 4-byte writable buffer; single `%s` conversion paired with one
        // NUL-terminated `*const c_char` argument; literals are NUL-terminated.
        let n = unsafe {
            curl_msnprintf(
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                FMT_S.as_ptr() as *const c_char,
                ARG_ABCDEF.as_ptr() as *const c_char,
            )
        };
        assert_eq!(
            n, 3,
            "curl reports bytes actually stored (maxlength - 1) on truncation, \
             not the C99 would-be length"
        );
        // SAFETY: buffer is NUL-terminated by the trampoline.
        let s = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
        assert_eq!(s.to_str().unwrap(), "abc");
    }

    /// `curl_msprintf` writes into a caller buffer and returns the length.
    #[test]
    fn msprintf_writes_and_returns_length() {
        let mut buf = [0u8; 32];
        // SAFETY: 32-byte writable buffer; `%05d` consumes one `c_int`; the
        // format literal is NUL-terminated and the buffer is large enough.
        let n = unsafe {
            curl_msprintf(
                buf.as_mut_ptr() as *mut c_char,
                FMT_05D.as_ptr() as *const c_char,
                42_i32,
            )
        };
        assert_eq!(n, 5);
        // SAFETY: buffer NUL-terminated by the trampoline.
        let s = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
        assert_eq!(s.to_str().unwrap(), "00042");
    }

    /// `curl_maprintf` returns a freshly heap-allocated string that the caller
    /// frees with `curl_free` (the crate-wide `libc::free` contract).
    #[test]
    fn maprintf_allocates_freeable_string() {
        // SAFETY: `%d-%s` pairs with one `c_int` and one NUL-terminated
        // `*const c_char`; the format literal is NUL-terminated.
        let p = unsafe {
            curl_maprintf(
                FMT_D_S.as_ptr() as *const c_char,
                7_i32,
                ARG_X.as_ptr() as *const c_char,
            )
        };
        assert!(!p.is_null(), "curl_maprintf must not return NULL on success");
        // SAFETY: `p` is a non-NULL, NUL-terminated C string owned by us.
        let owned = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
        assert_eq!(owned, "7-x");
        // SAFETY: `p` was allocated by the trampoline's `vasprintf`/`malloc`,
        // i.e. the same C heap `curl_free` (== `libc::free`) reclaims; it is
        // non-NULL and freed exactly once here.
        unsafe { crate::global::curl_free(p as *mut c_void) };
    }
}
