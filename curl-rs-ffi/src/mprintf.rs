// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `curl_m*printf` — curl's public *printf* family, transcribed 1:1 from
//! `include/curl/mprintf.h` and derived behaviourally from the curl 8.19.0-DEV C entry point
//! `lib/mprintf.c`. This module owns **exactly 10** `CURL_EXTERN` symbols (the 11th grep hit in
//! `mprintf.h` is `#include "curl.h"`, which pulls in the `CURL_EXTERN` macro and is not a
//! function):
//!
//! | # | symbol            | returns | sink                                   |
//! |---|-------------------|---------|----------------------------------------|
//! | 1 | [`curl_mprintf`]   | `int`   | `stdout`                               |
//! | 2 | [`curl_mfprintf`]  | `int`   | a caller-supplied `FILE *`             |
//! | 3 | [`curl_msprintf`]  | `int`   | an unbounded caller buffer (NUL-term.) |
//! | 4 | [`curl_msnprintf`] | `int`   | a bounded caller buffer (NUL-term.)    |
//! | 5 | [`curl_mvprintf`]   | `int`  | `stdout` (va_list)                     |
//! | 6 | [`curl_mvfprintf`]  | `int`  | a `FILE *` (va_list)                   |
//! | 7 | [`curl_mvsprintf`]  | `int`  | an unbounded buffer (va_list)          |
//! | 8 | [`curl_mvsnprintf`] | `int`  | a bounded buffer (va_list)             |
//! | 9 | [`curl_maprintf`]   | `char*`| a fresh heap string (caller frees)     |
//! |10 | [`curl_mvaprintf`]  | `char*`| a fresh heap string (va_list)          |
//!
//! The `*printf` / `*fprintf` / `*sprintf` / `*snprintf` variants return an `int` character
//! count (matching curl's C convention — see [`format_core`] and the per-function docs for the
//! exact contract, which is **not** the C99 `snprintf` "would-have-been" length). The
//! `curl_maprintf` / `curl_mvaprintf` variants return a heap `char *` the caller releases with
//! [`curl_free`](crate::global::curl_free); the allocation is performed through [`CString`] so it
//! is byte-for-byte symmetric with `curl_free`'s `CString::from_raw` reclamation.
//!
//! # The formatting engine
//!
//! curl deliberately ships its *own* `printf` implementation (`lib/mprintf.c`) rather than
//! delegating to the platform C library, so that its format-string dialect — the `curl_off_t`
//! specifiers (`%O`), the `%zd` size handling, the `"..."`-quoting `%S`, the `(nil)` rendering
//! of `%p`/`%s`, and the exact width/precision/flag semantics — is identical across platforms.
//! This module reproduces that engine faithfully in safe Rust: [`parse_format`] mirrors curl's
//! `parsefmt`, and [`out_number`] / [`out_string`] / [`out_pointer`] / [`out_double`] mirror the
//! matching `out_*` helpers, all driven by [`format_core`] (curl's `formatf`). The 10 exported
//! symbols are thin wrappers that pair the engine with an output [`Sink`] and an argument source
//! [`VaArgs`].
//!
//! # NOTE — variadic mechanism, MSRV, and the `c_variadic` feature (issue #44930)
//!
//! Five of these are true C *variadic* (`...`) functions and five take a `va_list`. Reading `...`
//! arguments *in Rust* requires either C-variadic function *definitions*
//! (`extern "C" fn(..., ...)`) or [`core::ffi::VaList`]. **Both are gated behind the nightly-only
//! `c_variadic` feature** (rust-lang/rust#44930): they fail to compile with `error[E0658]` on
//! *stable* — verified on both this workspace's pinned MSRV toolchain (1.75.0,
//! `rust-toolchain.toml`) and current stable. `curl-rs-ffi` is built on **stable** by every merge
//! gate (`cargo build --release --workspace`, `cargo clippy --workspace -- -D warnings`,
//! `cargo +1.75 check --workspace`); only `curl-rs-lib` runs under `+nightly` (Miri). A
//! `#![feature(c_variadic)]` attribute, moreover, is only valid at the crate root. Enabling true
//! variadics in Rust would therefore break the stable build of the entire crate and every
//! consumer of it.
//!
//! The chosen approach keeps the crate **stable-only** while still honouring every caller
//! argument, by drawing the variadic boundary in a tiny amount of C rather than in Rust. It has
//! three cooperating parts:
//!
//! * **The formatting engine** ([`format_core`] and friends) is complete, panic-free, and
//!   exhaustively unit-tested against a Rust-native argument source ([`SliceArgs`]); it pulls
//!   typed arguments through the [`VaArgs`] trait. This is safe Rust and contains the entire
//!   format-string dialect.
//! * **The five `va_list` entry points** (`curl_mv*printf`) are the `#[no_mangle] pub extern "C"`
//!   Rust workers defined in this module. Stable Rust cannot *walk* a `va_list`, but it can
//!   *forward* the opaque pointer to the platform C library's `vasprintf(3)`, which expands the
//!   arguments; the rendered bytes are then emitted through curl's exact write / count /
//!   NUL-termination / allocation rules via [`Source::Rendered`]. Forwarding the `va_list` —
//!   rather than re-implementing `va_arg` — is the same platform-delegation technique
//!   [`out_double`] already uses for floating point, and links no new library (the C runtime is
//!   always present; AAP §0.5.2).
//! * **The five `...` entry points** (`curl_mprintf`, `curl_mfprintf`, `curl_msprintf`,
//!   `curl_msnprintf`, `curl_maprintf`) are defined as three-line C trampolines in
//!   `csrc/variadic_shim.c` (compiled and statically linked by `build.rs`). Each performs
//!   `va_start` and forwards the resulting `va_list` to its matching `curl_mv*printf` Rust worker
//!   above. The C compiler owns the one operation stable Rust cannot express — materialising a
//!   `va_list` from `...` — so these entry points now honour their caller's arguments fully and
//!   identically to the `va_list` tier (there is exactly one formatting implementation). The C
//!   trampoline pattern mirrors curl 8.x's own build layout and confines the variadic mechanism
//!   to ~40 lines of C outside the Rust type system.
//!
//! The net exported symbol table is byte-identical to a hand-written C `libcurl`: all 10
//! `curl_m*printf` names are present with their exact signatures (`nm -gD`, AAP §0.6.1), and the
//! committed, authoritative `include/curl/mprintf.h` — which carries the real `...` / `va_list`
//! declarations and is **never** clobbered — remains the ABI contract. (`build.rs` runs `cbindgen`
//! best-effort and downgrades any error to a warning; the C-defined `...` prototypes are supplied
//! to cbindgen via its `trailer`.) The inert [`EmptyArgs`] source is retained only as the
//! defensive null-`va_list` fallback inside the workers (see [`Source::Format`]); it is no longer
//! on the normal call path of any entry point.
//!
//! # Unsafe & panic policy (AAP §0.6.2 / §0.7.2)
//!
//! This is the FFI boundary crate — the sole place `unsafe` is permitted. The pure formatting
//! logic is safe Rust; the only `unsafe` lives in (a) the entry points' raw-pointer reads of the
//! caller's `format` / buffer / `FILE *`, (b) [`out_double`]'s single `libc::snprintf` call
//! (curl's `out_double` formats floating point via the platform `snprintf` for identical output,
//! so this module does the same), (c) [`FileSink`]'s `libc::fputc`, and (d) the `va_list` entry
//! points' single `vasprintf` forwarding call plus the matching `libc::free` of the buffer it
//! allocates (see [`Source`]). Every `unsafe` block
//! carries a `// SAFETY:` comment stating its invariant. No panic may unwind across the
//! `extern "C"` boundary: the engine performs no allocation-fallible `unwrap`/`expect` on caller
//! data, integer counters saturate rather than overflow, and the heap-returning entry points
//! additionally run under [`crate::ffi_guard`].

// Every exported function here is a `#[no_mangle] pub extern "C"` entry point on the libcurl C
// ABI boundary that receives raw pointers from C callers and dereferences them, so Clippy's
// `not_unsafe_ptr_arg_deref` would fire on each. The libcurl ABI declares these as ordinary
// (non-`unsafe`) C functions and the Minimal Change Mandate requires reproducing those exact
// signatures; pointer validity is instead documented per function and upheld by a `// SAFETY:`
// comment at every dereference. The lint is therefore allowed module-wide — identical to the
// established convention in the sibling `global.rs`.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use libc::{c_char, c_double, c_int, c_long, c_uint, c_ulong, c_void, size_t, FILE};
use std::ffi::{CStr, CString};

// ===========================================================================
// Fixed limits — transcribed verbatim from lib/mprintf.c
// ===========================================================================

/// Scratch buffer size for number/float rendering (`#define BUFFSIZE 326` — large enough to hold
/// a negative `DBL_MAX`, 317 letters, plus margin).
const BUFFSIZE: usize = 326;
/// Maximum number of positional input arguments (`#define MAX_PARAMETERS 128`).
const MAX_PARAMETERS: usize = 128;
/// Maximum number of output segments (`#define MAX_SEGMENTS 128`).
const MAX_SEGMENTS: usize = 128;

/// Lower-case hex digit table (`Curl_ldigits`).
const LDIGITS: &[u8; 16] = b"0123456789abcdef";
/// Upper-case hex digit table (`Curl_udigits`).
const UDIGITS: &[u8; 16] = b"0123456789ABCDEF";
/// The literal curl renders for a NULL string or pointer (`static const char nilstr[]`).
const NILSTR: &[u8] = b"(nil)";

// ===========================================================================
// Conversion / display flags — transcribed verbatim from lib/mprintf.c
// ===========================================================================

const FLAGS_SPACE: u32 = 1 << 0;
const FLAGS_SHOWSIGN: u32 = 1 << 1;
const FLAGS_LEFT: u32 = 1 << 2;
const FLAGS_ALT: u32 = 1 << 3;
/// `h` length modifier — consulted by `%n` (short write-back); it does not alter other output.
const FLAGS_SHORT: u32 = 1 << 4;
const FLAGS_LONG: u32 = 1 << 5;
const FLAGS_LONGLONG: u32 = 1 << 6;
/// `L` length modifier — recorded for parity; like curl, the double renderers do not consult it.
const FLAGS_LONGDOUBLE: u32 = 1 << 7;
const FLAGS_PAD_NIL: u32 = 1 << 8;
const FLAGS_UNSIGNED: u32 = 1 << 9;
const FLAGS_OCTAL: u32 = 1 << 10;
const FLAGS_HEX: u32 = 1 << 11;
const FLAGS_UPPER: u32 = 1 << 12;
const FLAGS_WIDTH: u32 = 1 << 13;
const FLAGS_WIDTHPARAM: u32 = 1 << 14;
const FLAGS_PREC: u32 = 1 << 15;
const FLAGS_PRECPARAM: u32 = 1 << 16;
const FLAGS_CHAR: u32 = 1 << 17;
const FLAGS_FLOATE: u32 = 1 << 18;
const FLAGS_FLOATG: u32 = 1 << 19;
const FLAGS_SUBSTR: u32 = 1 << 20;

// Dollar-notation parse states (curl's `DOLLAR_*` enum).
const DOLLAR_UNKNOWN: u8 = 0;
const DOLLAR_NOPE: u8 = 1;
const DOLLAR_USE: u8 = 2;

/// The data type read for a single positional input (curl's `FormatType`).
///
/// Determined during parsing from the conversion character and length modifiers, this drives
/// both which [`VaArgs`] accessor supplies the value and how [`format_core`] renders it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mtype {
    /// Unassigned slot (a gap in the positional arguments is an error, as in curl).
    None,
    /// `%s` / `%S` — a `const char *`.
    Str,
    /// `%p` — a generic pointer.
    Ptr,
    /// `%n` — a pointer to which the running character count is written back.
    IntPtr,
    /// `%d` / `%i` / `%c` with no length modifier — an `int`.
    Int,
    /// `%ld` etc. — a `long`.
    Long,
    /// `%lld` / `%qd` etc. — a `long long` (64-bit).
    LongLong,
    /// `%u` / `%x` / `%o` — an `unsigned int`.
    IntU,
    /// `%lu` etc. — an `unsigned long`.
    LongU,
    /// `%llu` etc. — an `unsigned long long` (64-bit).
    LongLongU,
    /// `%f` / `%e` / `%g` — a `double`.
    Double,
    /// A `'*'` width argument (an `int`).
    Width,
    /// A `'.*'` precision argument (an `int`).
    Precision,
}

/// A materialised positional argument value (curl's `struct va_input`'s `val` union).
///
/// Not `Copy`: the `Str` variant owns a `Vec<u8>` (curl's union stores a borrowed `const char *`,
/// but the Rust model owns the bytes so [`InputVal`] carries no lifetime).
#[derive(Clone, Debug)]
enum InputVal {
    /// No value read for this slot.
    None,
    /// A signed integer, stored sign-extended into `i64`.
    Nums(i64),
    /// An unsigned integer, stored zero-extended into `u64`.
    Numu(u64),
    /// A `double`.
    Dnum(f64),
    /// A pointer value (`%p` / `%n`), captured as its integer address.
    Ptr(usize),
    /// A string argument (`%s` / `%S`): the borrowed bytes, or `None` for a NULL pointer.
    Str(Option<StrArg>),
}

/// Owned string-argument bytes for a `%s` / `%S` conversion.
///
/// The engine needs the raw bytes (curl reads up to the terminating NUL); a real `va_list`
/// adapter would materialise these from the caller's `const char *`, while the test source
/// supplies them directly. Kept as an owned `Vec<u8>` so [`InputVal`] carries no borrow.
type StrArg = Vec<u8>;

// ===========================================================================
// Argument source
// ===========================================================================

/// A typed source of positional `printf` arguments.
///
/// [`format_core`] reads each positional argument exactly once, in ascending position order,
/// through the accessor matching the [`Mtype`] the parser assigned to that position — precisely
/// mirroring the `switch(iptr->type) { case ...: va_arg(...) }` pull loop in curl's `parsefmt`.
/// Decoupling argument acquisition behind this trait keeps the engine free of `unsafe`: the
/// stable build feeds it the inert [`EmptyArgs`], the unit tests feed it [`SliceArgs`], and a
/// future `c_variadic`-gated adapter could wrap a [`core::ffi::VaList`] with no engine change.
///
/// Widths follow the C promotions curl relies on: `int`/`unsigned int` for the `Int*` variants,
/// `long`/`unsigned long` for `Long*`, and 64-bit for `LongLong*`. Signed values are returned
/// sign-extended and unsigned values zero-extended so [`out_number`] observes the same bit
/// patterns as curl's `va_input` union.
trait VaArgs {
    /// Read an `int` (`%d`/`%i`/`%c`, and `'*'` width / `'.*'` precision arguments).
    fn arg_int(&mut self) -> c_int;
    /// Read a `long` (`%ld`, and `%zd`/`%Od` where `size_t`/`curl_off_t` are `long`-sized).
    fn arg_long(&mut self) -> c_long;
    /// Read a `long long` (`%lld` / `%qd`).
    fn arg_longlong(&mut self) -> i64;
    /// Read an `unsigned int` (`%u`/`%x`/`%o`).
    fn arg_uint(&mut self) -> c_uint;
    /// Read an `unsigned long` (`%lu`).
    fn arg_ulong(&mut self) -> c_ulong;
    /// Read an `unsigned long long` (`%llu`).
    fn arg_ulonglong(&mut self) -> u64;
    /// Read a `double` (`%f`/`%e`/`%g`).
    fn arg_double(&mut self) -> c_double;
    /// Read a `const char *` string argument (`%s`/`%S`); `None` denotes a NULL pointer.
    fn arg_str(&mut self) -> Option<StrArg>;
    /// Read a generic pointer (`%p`/`%n`), captured as its integer address.
    fn arg_ptr(&mut self) -> usize;
}

/// The inert argument source backing the defensive null-`va_list` fallback of the
/// `curl_mv*printf` workers (see [`va_source`] and [`Source::Format`]).
///
/// See the crate-level `NOTE`: live C varargs cannot be *walked* in Rust without the nightly
/// `c_variadic` feature, so every accessor here yields a neutral value (`0` / `0.0` / NULL).
/// Literal text and `%%` therefore render exactly, while conversion specifiers observe zero/NULL
/// arguments. This source is reached only when a C consumer invokes a `curl_mv*printf` worker
/// directly with a null `va_list`; the normal call path — the C `...` trampolines forwarding a
/// real `va_list`, and any caller passing a live `va_list` — instead expands arguments through the
/// platform `vasprintf` and yields [`Source::Rendered`], honouring every argument. It remains a
/// well-contained, defensive consequence of the stable-only variadic strategy.
struct EmptyArgs;

impl VaArgs for EmptyArgs {
    fn arg_int(&mut self) -> c_int {
        0
    }
    fn arg_long(&mut self) -> c_long {
        0
    }
    fn arg_longlong(&mut self) -> i64 {
        0
    }
    fn arg_uint(&mut self) -> c_uint {
        0
    }
    fn arg_ulong(&mut self) -> c_ulong {
        0
    }
    fn arg_ulonglong(&mut self) -> u64 {
        0
    }
    fn arg_double(&mut self) -> c_double {
        0.0
    }
    fn arg_str(&mut self) -> Option<StrArg> {
        None
    }
    fn arg_ptr(&mut self) -> usize {
        0
    }
}

// ===========================================================================
// Output sink
// ===========================================================================

/// A byte-at-a-time output target for [`format_core`].
///
/// This is the Rust analogue of the `int (*stream)(unsigned char, void *)` callback curl passes
/// to `formatf`. [`Sink::put`] returns `Ok(())` when the byte was accepted (curl's `stream`
/// returning `0`) and `Err(())` when the sink is full or errored (curl's `stream` returning
/// non-zero), which halts formatting immediately — reproducing curl's early-exit behaviour and
/// its rule that a rejected byte is **not** counted in the returned character total.
trait Sink {
    /// Consume one output byte. `Err(())` stops formatting.
    fn put(&mut self, byte: u8) -> Result<(), ()>;
}

/// Couples a [`Sink`] with the running character count (`done` in curl's `formatf`).
///
/// [`Writer::emit`] is the direct translation of curl's `OUTCHAR` macro: on a rejected byte it
/// signals *stop* without incrementing the count; on an accepted byte it increments. The count
/// saturates at [`c_int::MAX`] rather than overflowing, so no arithmetic panic can cross the FFI
/// boundary even for pathologically long output.
struct Writer<'s> {
    sink: &'s mut dyn Sink,
    done: c_int,
}

impl<'s> Writer<'s> {
    #[inline]
    fn new(sink: &'s mut dyn Sink) -> Self {
        Writer { sink, done: 0 }
    }

    /// Emit one byte. Returns `true` when formatting must stop (curl's `OUTCHAR` "return TRUE").
    #[inline]
    #[must_use]
    fn emit(&mut self, byte: u8) -> bool {
        match self.sink.put(byte) {
            Ok(()) => {
                self.done = self.done.saturating_add(1);
                false
            }
            Err(()) => true,
        }
    }
}

/// Bounded-buffer sink for `curl_msnprintf` / `curl_mvsnprintf` (curl's `addbyter` +
/// `struct nsprintf`).
///
/// Bytes are stored while `length < max`; once the buffer is full [`Sink::put`] returns
/// `Err(())`. The post-formatting NUL-termination and the exact return-count adjustment are
/// performed by the caller ([`snprintf_finish`]), reproducing `curl_mvsnprintf`'s tail logic.
struct BoundedBufSink {
    /// Destination buffer as a raw pointer (may be dangling when `max == 0`, in which case it is
    /// never dereferenced).
    buffer: *mut c_char,
    /// Number of bytes stored so far.
    length: usize,
    /// Capacity ceiling (`maxlength`), including the space for the terminating NUL.
    max: usize,
}

impl Sink for BoundedBufSink {
    #[inline]
    fn put(&mut self, byte: u8) -> Result<(), ()> {
        if self.length < self.max {
            // SAFETY: `length < max` and, per `curl_msnprintf`'s contract, the caller guarantees
            // `buffer` addresses at least `max` writable bytes; therefore `buffer + length` is in
            // bounds. `max == 0` makes this branch unreachable, so a null/dangling `buffer` (the
            // `maxlength == 0` case) is never written.
            unsafe {
                *self.buffer.add(self.length) = byte as c_char;
            }
            self.length += 1;
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Unbounded-buffer sink for `curl_msprintf` / `curl_mvsprintf` (curl's `storebuffer`).
///
/// Every byte is stored and accepted; the caller guarantees the destination is large enough
/// (this is curl's unbounded `sprintf` contract). The caller writes the terminating NUL after
/// formatting completes.
struct UnboundedBufSink {
    /// Next write position within the caller-owned destination buffer.
    buffer: *mut c_char,
    /// Number of bytes written so far (also the offset of the pending NUL terminator).
    written: usize,
}

impl Sink for UnboundedBufSink {
    #[inline]
    fn put(&mut self, byte: u8) -> Result<(), ()> {
        // SAFETY: per `curl_msprintf`'s (unbounded) contract the caller guarantees `buffer`
        // addresses enough writable bytes for the full formatted output plus a trailing NUL, so
        // `buffer + written` is always in bounds. Ownership of the storage stays with the caller.
        unsafe {
            *self.buffer.add(self.written) = byte as c_char;
        }
        self.written += 1;
        Ok(())
    }
}

/// Growable sink for `curl_maprintf` / `curl_mvaprintf` (curl's `alloc_addbyter` + `dynbuf`).
///
/// Collects the formatted bytes into a `Vec<u8>`, which the caller converts into a heap
/// `CString` for return to C. Never rejects a byte (allocation failure aborts the process just as
/// curl's `dynbuf` treats OOM as fatal); the `Vec`'s amortised growth mirrors the dynamic buffer.
struct VecSink {
    /// Accumulated output bytes.
    buf: Vec<u8>,
}

impl Sink for VecSink {
    #[inline]
    fn put(&mut self, byte: u8) -> Result<(), ()> {
        self.buf.push(byte);
        Ok(())
    }
}

/// `FILE *` sink for `curl_mprintf` / `curl_mfprintf` and their `va_list` variants (curl's
/// `fputc_wrapper`).
///
/// Each byte is written with `libc::fputc`; a returned `EOF` rejects the byte and stops
/// formatting, exactly like curl's wrapper (`return rc == EOF`).
struct FileSink {
    /// Destination C stream (`stdout` for `curl_mprintf`, or the caller's `FILE *`).
    stream: *mut FILE,
}

impl Sink for FileSink {
    #[inline]
    fn put(&mut self, byte: u8) -> Result<(), ()> {
        // SAFETY: `stream` is a valid, open `FILE *` — either the process's `stdout` (obtained
        // from the C runtime via `c_stdout`) or the non-null handle the C caller passed to
        // `curl_mfprintf` and is contractually responsible for keeping open. `fputc` performs no
        // Rust-visible aliasing and returns `EOF` on error, which we surface as `Err(())`.
        let rc = unsafe { libc::fputc(c_int::from(byte), self.stream) };
        if rc == libc::EOF {
            Err(())
        } else {
            Ok(())
        }
    }
}

// ===========================================================================
// Parsed representation of one format string
// ===========================================================================

/// A single output segment (curl's `struct outsegment`).
///
/// The parser splits the format string into an ordered list of these. A segment first emits
/// `outlen` literal bytes taken from the format string starting at byte offset `start`; then, if
/// it is not a pure substring (`FLAGS_SUBSTR` clear), it renders the conversion described by
/// `flags`/`width`/`precision` using the positional input at index `input`. When `FLAGS_WIDTHPARAM`
/// (resp. `FLAGS_PRECPARAM`) is set, `width` (resp. `precision`) is instead the *index* of the
/// positional input that supplies the value — exactly as in curl.
#[derive(Clone, Copy, Debug)]
struct Segment {
    /// Field width, or — when `FLAGS_WIDTHPARAM` is set — the input index that carries the width.
    width: c_int,
    /// Precision, or — when `FLAGS_PRECPARAM` is set — the input index that carries the precision.
    precision: c_int,
    /// Conversion / display flags (`FLAGS_*`).
    flags: u32,
    /// Index into the positional input array for this segment's conversion argument.
    input: usize,
    /// Byte offset into the format string where this segment's literal run begins.
    start: usize,
    /// Number of literal bytes to copy from the format string before the conversion.
    outlen: usize,
}

/// The resolved width/precision/flags handed to the `out_*` renderers (curl's `struct mproperty`).
#[derive(Clone, Copy, Debug)]
struct MProperty {
    /// Effective field width (always non-negative once resolved).
    width: c_int,
    /// Effective precision, or `-1` when no precision applies.
    prec: c_int,
    /// Conversion / display flags for this rendering.
    flags: u32,
}

/// The fully parsed format string: the ordered output segments plus the type of every positional
/// input slot (`0..=max_param`). Mirrors the two arrays curl's `parsefmt` fills in.
struct Parsed {
    /// Output segments in emission order.
    segments: Vec<Segment>,
    /// Type of each positional input, indexed by argument position.
    input_types: Vec<Mtype>,
}

/// Read an unsigned base-10 number, capped at `max`, advancing `pos` past the digits.
///
/// Faithful port of curl's `curlx_str_number` (base 10) as used by `parsefmt`: at least one ASCII
/// digit is required, leading zeroes are accepted, and a value exceeding `max` is an overflow.
/// Returns `None` (curl's non-zero error) when there is no digit or the value overflows; on error
/// `pos` is left unchanged. On success `pos` points just past the last digit consumed.
fn parse_number(fmt: &[u8], pos: &mut usize, max: i64) -> Option<i64> {
    let base: i64 = 10;
    let mut p = *pos;
    if p >= fmt.len() || !fmt[p].is_ascii_digit() {
        return None;
    }
    let mut num: i64 = 0;
    if max < base {
        // Special-case a very small ceiling, matching curl's separate loop.
        loop {
            let n = i64::from(fmt[p] - b'0');
            p += 1;
            num = num * base + n;
            if num > max {
                return None;
            }
            if p >= fmt.len() || !fmt[p].is_ascii_digit() {
                break;
            }
        }
    } else {
        loop {
            let n = i64::from(fmt[p] - b'0');
            if num > (max - n) / base {
                return None;
            }
            p += 1;
            num = num * base + n;
            if p >= fmt.len() || !fmt[p].is_ascii_digit() {
                break;
            }
        }
    }
    *pos = p;
    Some(num)
}

/// Parse a `%N$` positional reference (curl's `dollarstring`).
///
/// The provided number is 1-based; on success this returns the 0-based index and advances `pos`
/// past the trailing `$`. Returns `None` (curl's `-1`) when there is no valid `number$` sequence
/// or the number is zero; on failure `pos` is left unchanged (curl passes the pointer by value and
/// only writes it back on success).
fn dollarstring(fmt: &[u8], pos: &mut usize) -> Option<c_int> {
    let mut p = *pos;
    let num = parse_number(fmt, &mut p, MAX_PARAMETERS as i64)?;
    if p >= fmt.len() || fmt[p] != b'$' {
        return None;
    }
    p += 1;
    if num == 0 {
        return None;
    }
    *pos = p;
    Some((num - 1) as c_int)
}

/// Parse the format string into output segments and a typed input plan (curl's `parsefmt`).
///
/// This is a faithful, allocation-safe port of curl's two-pass parser. It walks the format bytes
/// once, emitting a [`Segment`] per literal run and per conversion and recording the [`Mtype`] of
/// every positional input. It enforces the same limits and rejections curl does — too many
/// segments/arguments, precision/width overflow, illegal positional (`$`) mixes, reusing one
/// argument for two purposes, and gaps in the positional sequence. Any such rejection returns
/// `None`, which (exactly like curl's non-zero `parsefmt` return) makes [`format_core`] emit
/// nothing and report a zero character count.
///
/// The format slice carries no terminating NUL (it is borrowed from a `CStr`), so out-of-range
/// look-ahead is modelled by [`byte_at`] returning `0` — the same value curl reads from the
/// string's NUL terminator.
fn parse_format(fmt: &[u8]) -> Option<Parsed> {
    let len = fmt.len();
    let mut pos: usize = 0;
    let mut param_num: c_int = 0;
    let mut max_param: c_int = -1;
    let mut usedinput = [false; MAX_PARAMETERS];
    let mut input_types = [Mtype::None; MAX_PARAMETERS];
    let mut segments: Vec<Segment> = Vec::new();
    let mut use_dollar: u8 = DOLLAR_UNKNOWN;
    let mut start: usize = 0;

    while pos < len {
        if fmt[pos] != b'%' {
            pos += 1;
            continue;
        }

        let mut flags: u32 = 0;
        let mut width: c_int = 0;
        let mut precision: c_int = 0;
        let mut param: c_int = -1;

        pos += 1; // step over '%'
        let outlen = pos - 1 - start; // literal bytes preceding the '%'

        // "%%" -> a literal percent sign.
        if byte_at(fmt, pos) == b'%' {
            if outlen > 0 {
                if segments.len() >= MAX_SEGMENTS {
                    return None; // too many output segments
                }
                segments.push(Segment {
                    width: 0,
                    precision: 0,
                    flags: FLAGS_SUBSTR,
                    input: 0,
                    start,
                    outlen,
                });
            }
            start = pos; // begin the next literal run at the second '%'
            pos += 1;
            continue;
        }

        // Optional positional (`N$`) selector for the main argument.
        if use_dollar != DOLLAR_NOPE {
            match dollarstring(fmt, &mut pos) {
                Some(p) => {
                    param = p;
                    use_dollar = DOLLAR_USE;
                }
                None => {
                    if use_dollar == DOLLAR_USE {
                        return None; // illegal positional combination
                    }
                    param = -1;
                    use_dollar = DOLLAR_NOPE;
                }
            }
        }

        // ---- flags, width, precision, length modifiers ----
        let mut loopit = true;
        while loopit {
            let c = byte_at(fmt, pos);
            pos += 1;
            match c {
                b' ' => flags |= FLAGS_SPACE,
                b'+' => flags |= FLAGS_SHOWSIGN,
                b'-' => {
                    flags |= FLAGS_LEFT;
                    flags &= !FLAGS_PAD_NIL;
                }
                b'#' => flags |= FLAGS_ALT,
                b'.' => {
                    if byte_at(fmt, pos) == b'*' {
                        // Precision comes from an argument.
                        flags |= FLAGS_PRECPARAM;
                        pos += 1;
                        if use_dollar == DOLLAR_USE {
                            match dollarstring(fmt, &mut pos) {
                                Some(p) => precision = p,
                                None => return None, // illegal positional precision
                            }
                        } else {
                            precision = -1;
                        }
                    } else {
                        flags |= FLAGS_PREC;
                        let is_neg = byte_at(fmt, pos) == b'-';
                        if is_neg {
                            pos += 1;
                        }
                        match parse_number(fmt, &mut pos, c_int::MAX as i64) {
                            Some(n) => precision = n as c_int,
                            None => return None, // precision overflow
                        }
                        if is_neg {
                            precision = -precision;
                        }
                    }
                    if (flags & (FLAGS_PREC | FLAGS_PRECPARAM)) == (FLAGS_PREC | FLAGS_PRECPARAM) {
                        // Cannot combine both kinds of precision for one argument.
                        return None;
                    }
                }
                b'h' => flags |= FLAGS_SHORT,
                b'l' => {
                    if flags & FLAGS_LONG != 0 {
                        flags |= FLAGS_LONGLONG;
                    } else {
                        flags |= FLAGS_LONG;
                    }
                }
                b'L' => flags |= FLAGS_LONGDOUBLE,
                b'q' => flags |= FLAGS_LONGLONG,
                b'z' => {
                    // `size_t` maps to long-long only where it is wider than `long`.
                    if core::mem::size_of::<size_t>() > core::mem::size_of::<c_long>() {
                        flags |= FLAGS_LONGLONG;
                    } else {
                        flags |= FLAGS_LONG;
                    }
                }
                b'O' => {
                    // `curl_off_t` is 64-bit; map like `size_t` relative to `long`.
                    if core::mem::size_of::<i64>() > core::mem::size_of::<c_long>() {
                        flags |= FLAGS_LONGLONG;
                    } else {
                        flags |= FLAGS_LONG;
                    }
                }
                b'0' => {
                    if flags & FLAGS_LEFT == 0 {
                        flags |= FLAGS_PAD_NIL;
                    }
                    // Fall through to width parsing (the leading zero is part of the width).
                    flags |= FLAGS_WIDTH;
                    pos -= 1; // reprocess the digit run including this '0'
                    match parse_number(fmt, &mut pos, c_int::MAX as i64) {
                        Some(n) => width = n as c_int,
                        None => return None, // width overflow
                    }
                }
                b'1'..=b'9' => {
                    flags |= FLAGS_WIDTH;
                    pos -= 1; // reprocess starting at the first digit
                    match parse_number(fmt, &mut pos, c_int::MAX as i64) {
                        Some(n) => width = n as c_int,
                        None => return None, // width overflow
                    }
                }
                b'*' => {
                    // Width comes from an argument.
                    flags |= FLAGS_WIDTHPARAM;
                    if use_dollar == DOLLAR_USE {
                        match dollarstring(fmt, &mut pos) {
                            Some(p) => width = p,
                            None => return None, // illegal positional width
                        }
                    } else {
                        width = -1;
                    }
                }
                _ => {
                    loopit = false;
                    pos -= 1; // step back onto the conversion character
                }
            }
        }

        // ---- the conversion specifier ----
        let type_: Mtype;
        match byte_at(fmt, pos) {
            b'S' => {
                flags |= FLAGS_ALT;
                type_ = Mtype::Str;
            }
            b's' => type_ = Mtype::Str,
            b'n' => type_ = Mtype::IntPtr,
            b'p' => type_ = Mtype::Ptr,
            b'd' | b'i' => {
                type_ = if flags & FLAGS_LONGLONG != 0 {
                    Mtype::LongLong
                } else if flags & FLAGS_LONG != 0 {
                    Mtype::Long
                } else {
                    Mtype::Int
                };
            }
            b'u' => {
                type_ = if flags & FLAGS_LONGLONG != 0 {
                    Mtype::LongLongU
                } else if flags & FLAGS_LONG != 0 {
                    Mtype::LongU
                } else {
                    Mtype::IntU
                };
                flags |= FLAGS_UNSIGNED;
            }
            b'o' => {
                type_ = if flags & FLAGS_LONGLONG != 0 {
                    Mtype::LongLongU
                } else if flags & FLAGS_LONG != 0 {
                    Mtype::LongU
                } else {
                    Mtype::IntU
                };
                flags |= FLAGS_OCTAL | FLAGS_UNSIGNED;
            }
            b'x' => {
                type_ = if flags & FLAGS_LONGLONG != 0 {
                    Mtype::LongLongU
                } else if flags & FLAGS_LONG != 0 {
                    Mtype::LongU
                } else {
                    Mtype::IntU
                };
                flags |= FLAGS_HEX | FLAGS_UNSIGNED;
            }
            b'X' => {
                type_ = if flags & FLAGS_LONGLONG != 0 {
                    Mtype::LongLongU
                } else if flags & FLAGS_LONG != 0 {
                    Mtype::LongU
                } else {
                    Mtype::IntU
                };
                flags |= FLAGS_HEX | FLAGS_UPPER | FLAGS_UNSIGNED;
            }
            b'c' => {
                type_ = Mtype::Int;
                flags |= FLAGS_CHAR;
            }
            b'f' => type_ = Mtype::Double,
            b'e' => {
                type_ = Mtype::Double;
                flags |= FLAGS_FLOATE;
            }
            b'E' => {
                type_ = Mtype::Double;
                flags |= FLAGS_FLOATE | FLAGS_UPPER;
            }
            b'g' => {
                type_ = Mtype::Double;
                flags |= FLAGS_FLOATG;
            }
            b'G' => {
                type_ = Mtype::Double;
                flags |= FLAGS_FLOATG | FLAGS_UPPER;
            }
            _ => {
                // Invalid conversion: disregard it and reprocess the remaining bytes as literal
                // text (curl's `continue`), leaving `start` untouched so the '%...' is emitted.
                continue;
            }
        }

        // ---- width supplied via an argument ----
        if flags & FLAGS_WIDTHPARAM != 0 {
            if width < 0 {
                width = param_num;
                param_num += 1;
            } else if (width as usize) < MAX_PARAMETERS && usedinput[width as usize] {
                return None; // this argument was already used for something else
            }
            if width as usize >= MAX_PARAMETERS {
                return None; // too many arguments
            }
            if width >= max_param {
                max_param = width;
            }
            input_types[width as usize] = Mtype::Width;
            usedinput[width as usize] = true;
        }

        // ---- precision supplied via an argument ----
        if flags & FLAGS_PRECPARAM != 0 {
            if precision < 0 {
                precision = param_num;
                param_num += 1;
            } else if (precision as usize) < MAX_PARAMETERS && usedinput[precision as usize] {
                return None; // this argument was already used for something else
            }
            if precision as usize >= MAX_PARAMETERS {
                return None; // too many arguments
            }
            if precision >= max_param {
                max_param = precision;
            }
            input_types[precision as usize] = Mtype::Precision;
            usedinput[precision as usize] = true;
        }

        // ---- the conversion's own argument ----
        if param < 0 {
            param = param_num;
            param_num += 1;
        }
        if param as usize >= MAX_PARAMETERS {
            return None; // too many arguments
        }
        if param >= max_param {
            max_param = param;
        }
        input_types[param as usize] = type_;
        usedinput[param as usize] = true;

        pos += 1; // step over the conversion character
        if segments.len() >= MAX_SEGMENTS {
            return None; // too many output segments
        }
        segments.push(Segment {
            width,
            precision,
            flags,
            input: param as usize,
            start,
            outlen,
        });
        start = pos;
    }

    // Trailing literal run (if any).
    let outlen = pos - start;
    if outlen > 0 {
        if segments.len() >= MAX_SEGMENTS {
            return None; // too many output segments
        }
        segments.push(Segment {
            width: 0,
            precision: 0,
            flags: FLAGS_SUBSTR,
            input: 0,
            start,
            outlen,
        });
    }

    // Every positional slot in `0..=max_param` must have been assigned a type; a gap means the
    // caller referenced argument N without referencing some earlier argument, which curl rejects.
    let ipieces = (max_param + 1) as usize;
    for used in usedinput.iter().take(ipieces) {
        if !*used {
            return None; // gap in the argument sequence
        }
    }

    Some(Parsed {
        segments,
        input_types: input_types[..ipieces].to_vec(),
    })
}

/// Read the format byte at `pos`, or `0` when `pos` is at or past the end of the slice.
///
/// The format slice has no terminating NUL, so this models the `'\0'` curl reads once it walks
/// off the end of the C string — every look-ahead in [`parse_format`] goes through here.
#[inline]
fn byte_at(fmt: &[u8], pos: usize) -> u8 {
    if pos < fmt.len() {
        fmt[pos]
    } else {
        0
    }
}

// ===========================================================================
// Output renderers — byte-exact ports of lib/mprintf.c's out_* functions
// ===========================================================================

/// Render an integer conversion (curl's `out_number`): `%d`/`%i`/`%u`/`%o`/`%x`/`%X` and `%c`.
///
/// `num` carries the unsigned bit pattern of the argument and `nums` its signed value — the two
/// share the same bits, exactly as curl's `va_input` union does; only the signed-decimal path
/// consults `nums`. Returns `true` when the sink asked to stop early (curl's `return TRUE`).
fn out_number(w: &mut Writer, p: &MProperty, mut num: u64, nums: i64) -> bool {
    let flags = p.flags;
    let mut width = p.width;
    let mut prec = p.prec;
    let is_alt = (flags & FLAGS_ALT) != 0;
    let mut is_neg = false;
    let mut base: u64 = 10;
    let mut digits: &[u8; 16] = LDIGITS;

    // --- %c: emit a single, optionally width-padded, character ---
    if (flags & FLAGS_CHAR) != 0 {
        if (flags & FLAGS_LEFT) == 0 {
            // Right-justified: curl uses `while(--width > 0)` (pre-decrement) -> width-1 pad bytes.
            width -= 1;
            while width > 0 {
                if w.emit(b' ') {
                    return true;
                }
                width -= 1;
            }
        }
        if w.emit(num as u8) {
            return true;
        }
        if (flags & FLAGS_LEFT) != 0 {
            width -= 1;
            while width > 0 {
                if w.emit(b' ') {
                    return true;
                }
                width -= 1;
            }
        }
        return false;
    }

    if (flags & FLAGS_OCTAL) != 0 {
        base = 8;
    } else if (flags & FLAGS_HEX) != 0 {
        digits = if (flags & FLAGS_UPPER) != 0 {
            UDIGITS
        } else {
            LDIGITS
        };
        base = 16;
    } else if (flags & FLAGS_UNSIGNED) != 0 {
        // Decimal unsigned: nothing special, `num` is used as-is.
    } else {
        // Decimal signed: derive the magnitude, guarding against i64::MIN overflow exactly as curl.
        is_neg = nums < 0;
        if is_neg {
            let signed_num = -(nums + 1);
            num = signed_num as u64;
            num += 1;
        }
    }

    // Supply a default precision of 1 when none was given.
    if prec == -1 {
        prec = 1;
    }

    // Render the digits into `work` from the high end downward.
    let mut work = [0u8; BUFFSIZE + 2];
    let workend: isize = BUFFSIZE as isize - 2;
    let mut wpos: isize = workend;
    if base == 10 {
        while num > 0 {
            work[wpos as usize] = b'0' + (num % 10) as u8;
            wpos -= 1;
            num /= 10;
        }
    } else {
        while num > 0 {
            work[wpos as usize] = digits[(num % base) as usize];
            wpos -= 1;
            num /= base;
        }
    }
    let ndigits = (workend - wpos) as c_int;
    width -= ndigits;
    prec -= ndigits;

    if is_alt && base == 8 && prec <= 0 {
        work[wpos as usize] = b'0';
        wpos -= 1;
        width -= 1;
    }

    if prec > 0 {
        width -= prec;
        while prec > 0 && wpos >= 0 {
            work[wpos as usize] = b'0';
            wpos -= 1;
            prec -= 1;
        }
    }

    if is_alt && base == 16 {
        width -= 2;
    }

    if is_neg || (flags & FLAGS_SHOWSIGN) != 0 || (flags & FLAGS_SPACE) != 0 {
        width -= 1;
    }

    // Space padding for right-justified output (no zero-fill).
    if (flags & FLAGS_LEFT) == 0 && (flags & FLAGS_PAD_NIL) == 0 {
        while width > 0 {
            if w.emit(b' ') {
                return true;
            }
            width -= 1;
        }
    }

    // Sign or leading space.
    if is_neg {
        if w.emit(b'-') {
            return true;
        }
    } else if (flags & FLAGS_SHOWSIGN) != 0 {
        if w.emit(b'+') {
            return true;
        }
    } else if (flags & FLAGS_SPACE) != 0 && w.emit(b' ') {
        return true;
    }

    // "0x" / "0X" prefix for alternate-form hex.
    if is_alt && base == 16 {
        if w.emit(b'0') {
            return true;
        }
        let x = if (flags & FLAGS_UPPER) != 0 {
            b'X'
        } else {
            b'x'
        };
        if w.emit(x) {
            return true;
        }
    }

    // Zero padding for right-justified output.
    if (flags & FLAGS_LEFT) == 0 && (flags & FLAGS_PAD_NIL) != 0 {
        while width > 0 {
            if w.emit(b'0') {
                return true;
            }
            width -= 1;
        }
    }

    // The number's digits.
    wpos += 1;
    while wpos <= workend {
        if w.emit(work[wpos as usize]) {
            return true;
        }
        wpos += 1;
    }

    // Trailing spaces for left-justified output.
    if (flags & FLAGS_LEFT) != 0 {
        while width > 0 {
            if w.emit(b' ') {
                return true;
            }
            width -= 1;
        }
    }

    false
}

/// Render a string conversion (curl's `out_string`): `%s` and `%S`.
///
/// `s` is the argument's bytes, or `None` for a NULL pointer (rendered as `(nil)` when the
/// precision permits). Returns `true` when the sink asked to stop early.
fn out_string(w: &mut Writer, p: &MProperty, s: Option<&[u8]>) -> bool {
    let mut flags = p.flags;
    let mut width = p.width;
    let prec = p.prec;
    let content: &[u8];
    let len: usize;

    match s {
        None => {
            // Write "(nil)" when precision is unset or at least its length; otherwise nothing.
            if prec == -1 || prec >= NILSTR.len() as c_int {
                content = NILSTR;
                len = NILSTR.len();
                flags &= !FLAGS_ALT; // disable the surrounding quotes around (nil)
            } else {
                content = &[];
                len = 0;
            }
        }
        Some(bytes) => {
            content = bytes;
            if prec != -1 {
                // Precision caps the field-width accounting at `prec` even when the string is
                // shorter (matching curl); the emit loop below still stops at the string's end.
                len = prec as usize;
            } else {
                len = bytes.len();
            }
        }
    }

    let sub = if len > c_int::MAX as usize {
        c_int::MAX
    } else {
        len as c_int
    };
    width -= sub;

    if (flags & FLAGS_ALT) != 0 && w.emit(b'"') {
        return true;
    }
    // Left padding for right-justified output (curl uses `while(width-- > 0)`: `width` bytes).
    if (flags & FLAGS_LEFT) == 0 {
        while width > 0 {
            if w.emit(b' ') {
                return true;
            }
            width -= 1;
        }
    }
    // Emit min(len, content length) bytes — curl's `for(; len && *str; len--)`.
    let mut remaining = len;
    let mut idx = 0usize;
    while remaining > 0 && idx < content.len() {
        if w.emit(content[idx]) {
            return true;
        }
        idx += 1;
        remaining -= 1;
    }
    if (flags & FLAGS_LEFT) != 0 {
        while width > 0 {
            if w.emit(b' ') {
                return true;
            }
            width -= 1;
        }
    }
    if (flags & FLAGS_ALT) != 0 && w.emit(b'"') {
        return true;
    }
    false
}

/// Render a pointer conversion (curl's `out_pointer`): `%p`.
///
/// A non-null pointer is written as an alternate-form lowercase hex number (`0x…`) via
/// [`out_number`]; a null pointer is written as `(nil)` with the reversed pad order curl uses.
/// Returns `true` when the sink asked to stop early.
fn out_pointer(w: &mut Writer, p: &MProperty, addr: usize) -> bool {
    if addr != 0 {
        let mut pp = *p;
        pp.flags |= FLAGS_HEX | FLAGS_ALT;
        if out_number(w, &pp, addr as u64, 0) {
            return true;
        }
    } else {
        let flags = p.flags;
        let mut width = p.width - NILSTR.len() as c_int;
        // Note the pad order is the mirror of out_string: LEFT pads before, !LEFT pads after.
        if (flags & FLAGS_LEFT) != 0 {
            while width > 0 {
                if w.emit(b' ') {
                    return true;
                }
                width -= 1;
            }
        }
        for &b in NILSTR {
            if w.emit(b) {
                return true;
            }
        }
        if (flags & FLAGS_LEFT) == 0 {
            while width > 0 {
                if w.emit(b' ') {
                    return true;
                }
                width -= 1;
            }
        }
    }
    false
}

/// Render a floating-point conversion (curl's `out_double`): `%f`/`%e`/`%E`/`%g`/`%G`.
///
/// Faithful to curl, this assembles the very same C conversion specification curl builds and
/// defers the actual float formatting to the platform C library's `snprintf`, guaranteeing
/// byte-identical output. Returns `true` when the sink asked to stop early.
fn out_double(w: &mut Writer, p: &MProperty, dnum: f64) -> bool {
    let flags = p.flags;
    let mut width = p.width;
    let mut prec = p.prec;

    // Assemble the C conversion spec, e.g. "%-+ #12.4f".
    let mut spec: Vec<u8> = Vec::with_capacity(32);
    spec.push(b'%');
    if (flags & FLAGS_LEFT) != 0 {
        spec.push(b'-');
    }
    if (flags & FLAGS_SHOWSIGN) != 0 {
        spec.push(b'+');
    }
    if (flags & FLAGS_SPACE) != 0 {
        spec.push(b' ');
    }
    if (flags & FLAGS_ALT) != 0 {
        spec.push(b'#');
    }

    if width >= 0 {
        if width >= BUFFSIZE as c_int {
            width = BUFFSIZE as c_int - 1;
        }
        append_int(&mut spec, width as i64);
    }
    if prec >= 0 {
        // Clamp precision so the rendered field is guaranteed to fit `work` (curl's own logic).
        let mut maxprec = BUFFSIZE as c_int - 1;
        let mut val = dnum;
        if prec > maxprec {
            prec = maxprec - 1;
        }
        if width > 0 && prec <= width {
            maxprec -= width;
        }
        while val >= 10.0 {
            val /= 10.0;
            maxprec -= 1;
        }
        if prec > maxprec {
            prec = maxprec - 1;
        }
        if prec < 0 {
            prec = 0;
        }
        spec.push(b'.');
        append_int(&mut spec, prec as i64);
    }
    if (flags & FLAGS_LONG) != 0 {
        spec.push(b'l');
    }
    if (flags & FLAGS_FLOATE) != 0 {
        spec.push(if (flags & FLAGS_UPPER) != 0 {
            b'E'
        } else {
            b'e'
        });
    } else if (flags & FLAGS_FLOATG) != 0 {
        spec.push(if (flags & FLAGS_UPPER) != 0 {
            b'G'
        } else {
            b'g'
        });
    } else {
        spec.push(b'f');
    }
    spec.push(0); // NUL-terminate for the C call

    let mut work = [0u8; BUFFSIZE + 2];
    // SAFETY: `spec` is a NUL-terminated C format string containing exactly one floating-point
    // conversion and no other directive, so the single `f64` argument `dnum` matches it. `work`
    // holds `BUFFSIZE + 2` bytes and the length is capped at `BUFFSIZE`, so `snprintf` writes at
    // most `BUFFSIZE` bytes (including its own NUL terminator) and cannot overrun the buffer.
    unsafe {
        libc::snprintf(
            work.as_mut_ptr() as *mut c_char,
            BUFFSIZE as size_t,
            spec.as_ptr() as *const c_char,
            dnum,
        );
    }

    // Emit up to the NUL that snprintf wrote.
    for &b in work.iter() {
        if b == 0 {
            break;
        }
        if w.emit(b) {
            return true;
        }
    }
    false
}

/// Append the base-10 text of a non-negative integer to `buf` (builds the float conversion spec).
fn append_int(buf: &mut Vec<u8>, n: i64) {
    // `n` is always non-negative here — curl only formats non-negative width/precision this way.
    if n <= 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    let mut v = n as u64;
    while v > 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    buf.extend_from_slice(&tmp[i..]);
}

/// Write the running character count back through a `%n` pointer (curl's `MTYPE_INTPTR` branch).
///
/// A NULL pointer is a no-op: the count is computed but not stored. This is the value seen when a
/// worker runs against the inert [`EmptyArgs`] null-`va_list` fallback (see the crate `NOTE`); on
/// the normal path a real `%n` pointer forwarded through the platform `vasprintf` receives the
/// count as usual.
fn write_n(addr: usize, flags: u32, done: c_int) {
    if addr == 0 {
        return;
    }
    let ptr = addr as *mut c_void;
    // SAFETY: for `%n` the C caller guarantees the argument points to a writable integer object of
    // the width selected by the length modifiers; only a non-null pointer is dereferenced, and the
    // width chosen here matches curl's exactly. Ownership of the target object stays with the caller.
    unsafe {
        if (flags & FLAGS_LONGLONG) != 0 {
            *(ptr as *mut i64) = done as i64;
        } else if (flags & FLAGS_LONG) != 0 {
            *(ptr as *mut c_long) = done as c_long;
        } else if (flags & FLAGS_SHORT) == 0 {
            *(ptr as *mut c_int) = done;
        } else {
            *(ptr as *mut core::ffi::c_short) = done as core::ffi::c_short;
        }
    }
}

// ===========================================================================
// The formatting driver (curl's formatf)
// ===========================================================================

/// The general formatting driver (curl's `formatf`).
///
/// Parses `fmt`, reads every positional argument exactly once (in ascending position order) from
/// `args`, then walks the output segments emitting to `sink` one byte at a time. Returns the
/// number of characters written — counting only bytes the sink accepted, precisely as curl's
/// `done` counter does. A parse failure yields `0` with no output (curl's behaviour when
/// `parsefmt` returns non-zero).
fn format_core(fmt: &[u8], args: &mut dyn VaArgs, sink: &mut dyn Sink) -> c_int {
    let parsed = match parse_format(fmt) {
        Some(p) => p,
        None => return 0,
    };

    // Read the inputs in position order, mirroring curl's `switch(iptr->type) va_arg(...)` loop.
    let mut inputs: Vec<InputVal> = Vec::with_capacity(parsed.input_types.len());
    for &t in &parsed.input_types {
        let v = match t {
            Mtype::Str => InputVal::Str(args.arg_str()),
            Mtype::Ptr | Mtype::IntPtr => InputVal::Ptr(args.arg_ptr()),
            Mtype::LongLongU => InputVal::Numu(args.arg_ulonglong()),
            Mtype::LongLong => InputVal::Nums(args.arg_longlong()),
            // On the LP64 target matrix (x86_64/aarch64 · Linux/macOS) `c_ulong`/`c_long` are
            // transparent aliases for `u64`/`i64`, so no cast is needed here. The `c_uint`/`c_int`
            // arms below are genuine widening casts (32 -> 64 bit) and are retained.
            Mtype::LongU => InputVal::Numu(args.arg_ulong()),
            Mtype::Long => InputVal::Nums(args.arg_long()),
            Mtype::IntU => InputVal::Numu(args.arg_uint() as u64),
            Mtype::Int | Mtype::Width | Mtype::Precision => InputVal::Nums(args.arg_int() as i64),
            Mtype::Double => InputVal::Dnum(args.arg_double()),
            Mtype::None => InputVal::None,
        };
        inputs.push(v);
    }

    let mut w = Writer::new(sink);

    for seg in &parsed.segments {
        // Emit the literal run that precedes this segment's conversion (if any).
        let end = seg.start.saturating_add(seg.outlen);
        if let Some(lit) = fmt.get(seg.start..end) {
            for &b in lit {
                if w.emit(b) {
                    return w.done;
                }
            }
        }
        if (seg.flags & FLAGS_SUBSTR) != 0 {
            continue;
        }

        // Resolve the effective flags/width/precision for the conversion.
        let mut flags = seg.flags;

        let width: c_int = if (flags & FLAGS_WIDTHPARAM) != 0 {
            let mut wv = input_num(&inputs, seg.width as usize);
            if wv < 0 {
                // "A negative field width is a '-' flag followed by a positive field width."
                wv = if wv == c_int::MIN { c_int::MAX } else { -wv };
                flags |= FLAGS_LEFT;
                flags &= !FLAGS_PAD_NIL;
            }
            wv
        } else {
            seg.width
        };

        let prec: c_int = if (flags & FLAGS_PRECPARAM) != 0 {
            let pv = input_num(&inputs, seg.precision as usize);
            if pv < 0 {
                -1 // "A negative precision is taken as if the precision were omitted."
            } else {
                pv
            }
        } else if (flags & FLAGS_PREC) != 0 {
            seg.precision
        } else {
            -1
        };

        let p = MProperty { width, prec, flags };
        let mtype = parsed
            .input_types
            .get(seg.input)
            .copied()
            .unwrap_or(Mtype::None);

        let stop = match mtype {
            Mtype::IntU | Mtype::LongU | Mtype::LongLongU => {
                let numu = match inputs.get(seg.input) {
                    Some(InputVal::Numu(v)) => *v,
                    _ => 0,
                };
                let mut pp = p;
                pp.flags |= FLAGS_UNSIGNED;
                out_number(&mut w, &pp, numu, 0)
            }
            Mtype::Int | Mtype::Long | Mtype::LongLong => {
                let nums = match inputs.get(seg.input) {
                    Some(InputVal::Nums(v)) => *v,
                    _ => 0,
                };
                out_number(&mut w, &p, nums as u64, nums)
            }
            Mtype::Str => {
                let s = match inputs.get(seg.input) {
                    Some(InputVal::Str(x)) => x.as_deref(),
                    _ => None,
                };
                out_string(&mut w, &p, s)
            }
            Mtype::Ptr => {
                let addr = match inputs.get(seg.input) {
                    Some(InputVal::Ptr(a)) => *a,
                    _ => 0,
                };
                out_pointer(&mut w, &p, addr)
            }
            Mtype::Double => {
                let d = match inputs.get(seg.input) {
                    Some(InputVal::Dnum(v)) => *v,
                    _ => 0.0,
                };
                out_double(&mut w, &p, d)
            }
            Mtype::IntPtr => {
                let addr = match inputs.get(seg.input) {
                    Some(InputVal::Ptr(a)) => *a,
                    _ => 0,
                };
                write_n(addr, p.flags, w.done);
                false
            }
            // A conversion never dispatches on a width/precision slot or an unassigned slot.
            Mtype::Width | Mtype::Precision | Mtype::None => false,
        };
        if stop {
            return w.done;
        }
    }

    w.done
}

/// Read a positional input as a signed `int` (the `'*'`-width / `'.*'`-precision arguments).
fn input_num(inputs: &[InputVal], idx: usize) -> c_int {
    match inputs.get(idx) {
        Some(InputVal::Nums(v)) => *v as c_int,
        Some(InputVal::Numu(v)) => *v as c_int,
        _ => 0,
    }
}

// ===========================================================================
// FFI plumbing helpers
// ===========================================================================

/// Borrow the raw bytes of a C format string (excluding the terminating NUL), or `None` for null.
///
/// Unlike [`crate::cstr_to_str`], this performs no UTF-8 validation: a printf format string and
/// its literal runs are arbitrary bytes, exactly as curl treats its `char *` format argument.
///
/// # Safety
/// When non-null, `format` must point to a valid NUL-terminated C string that remains allocated
/// and unmodified for at least `'a`.
unsafe fn fmt_bytes<'a>(format: *const c_char) -> Option<&'a [u8]> {
    if format.is_null() {
        None
    } else {
        // SAFETY: upheld by this function's own contract — `format` is a valid NUL-terminated C
        // string alive for `'a`; `CStr::from_ptr` reads up to the terminating NUL.
        Some(unsafe { CStr::from_ptr(format) }.to_bytes())
    }
}

/// Allocate a C-owned, NUL-terminated copy of `bytes` — the heap-string allocator for
/// `curl_maprintf` / `curl_mvaprintf`.
///
/// Kept symmetric with [`curl_free`](crate): the buffer is created with [`CString::into_raw`] and
/// the caller reclaims it with `curl_free`'s `CString::from_raw`. Returns null when `bytes`
/// contains an interior NUL (which a C string cannot represent), matching the crate-wide
/// owned-string contract established in `global.rs`.
fn owned_c_string(bytes: Vec<u8>) -> *mut c_char {
    match CString::new(bytes) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// The C runtime's standard-output `FILE *`, used by `curl_mprintf` / `curl_mvprintf`.
#[cfg(target_os = "macos")]
fn c_stdout() -> *mut FILE {
    extern "C" {
        static __stdoutp: *mut FILE;
    }
    // SAFETY: `__stdoutp` is Darwin libc's standard-output `FILE *`, initialised by the C runtime
    // before any Rust code runs. We only read the current pointer value (never write it).
    unsafe { __stdoutp }
}

/// The C runtime's standard-output `FILE *`, used by `curl_mprintf` / `curl_mvprintf`.
#[cfg(not(target_os = "macos"))]
fn c_stdout() -> *mut FILE {
    extern "C" {
        static stdout: *mut FILE;
    }
    // SAFETY: `stdout` is the C runtime's standard-output `FILE *` on every non-Darwin target we
    // support (glibc/musl on Linux), initialised before any Rust code runs. We only read the
    // current pointer value (never write it).
    unsafe { stdout }
}

// ---------------------------------------------------------------------------
// Shared implementations behind the exported entry points.
//
// Every `curl_mv*printf` worker shares the same buffer-management, NUL-termination, and
// return-count logic; they differ only in where the *content* comes from, captured by [`Source`].
// The normal path is `Source::Rendered`: the C trampolines in `csrc/variadic_shim.c` capture the
// caller's `...` arguments with `va_start` and forward the resulting `va_list`, which [`va_source`]
// hands to the platform `vasprintf` to produce the final bytes. `Source::Format` is the
// null-`va_list` fallback — reached only when a C consumer invokes a `curl_mv*printf` worker
// directly with a null `va_list` — and expands the format against the inert [`EmptyArgs`].
// Centralising the tail logic keeps the whole family byte-identical regardless of source.
// ---------------------------------------------------------------------------

/// The origin of the bytes an entry point writes out.
enum Source {
    /// A caller `format` string with no accompanying `va_list` (the null-`va_list` fallback of the
    /// `curl_mv*printf` workers), read on demand and expanded by [`format_core`] against the inert
    /// [`EmptyArgs`]. The variadic `...` entry points never take this path: their C trampolines
    /// always forward a real `va_list`, yielding [`Source::Rendered`].
    Format(*const c_char),
    /// Bytes already expanded by the platform `vasprintf` from a forwarded `va_list`, emitted
    /// verbatim (no further `%`-conversion). This is the path taken by the C variadic trampolines.
    Rendered(Vec<u8>),
}

impl Source {
    /// Emit this source's bytes into `sink`, returning curl's character count (the value the
    /// `printf`-family functions return). The count and stop-on-full behaviour are identical for
    /// both variants because both drive the shared [`Writer`].
    fn run(self, sink: &mut dyn Sink) -> c_int {
        match self {
            Source::Format(format) => {
                // SAFETY: per the C contract `format` is null or a valid NUL-terminated string
                // for the duration of this call.
                let bytes = unsafe { fmt_bytes(format) }.unwrap_or(&[]);
                let mut args = EmptyArgs;
                format_core(bytes, &mut args, sink)
            }
            Source::Rendered(bytes) => emit_literal(&bytes, sink),
        }
    }
}

/// Emit already-expanded `bytes` verbatim through `sink`, returning curl's character count.
///
/// Unlike [`format_core`] this performs no `%`-conversion: the platform `vasprintf` has already
/// produced the final text, so re-parsing it would corrupt any literal `%` the arguments
/// contained. The byte-accept/stop and saturating-count semantics are those of [`Writer`], so a
/// bounded sink truncates and counts exactly as the format path does.
fn emit_literal(bytes: &[u8], sink: &mut dyn Sink) -> c_int {
    let mut w = Writer::new(sink);
    for &byte in bytes {
        if w.emit(byte) {
            // The sink signalled "stop" (curl's `OUTCHAR` returning TRUE) — e.g. a bounded
            // buffer is full. Remaining bytes are dropped, exactly as curl does.
            break;
        }
    }
    w.done
}

/// Render `format` + `args` through the platform C library's `vasprintf(3)`, returning the
/// formatted bytes, or `None` when `format` is null or the platform call fails.
///
/// # Safety
/// `format` must be null or a valid NUL-terminated C format string, and `args` must be a valid
/// `va_list` whose contents match `format`'s conversions — the exact contract libcurl places on
/// `curl_mv*printf`. The `va_list` is consumed exactly once.
unsafe fn vformat_bytes(format: *const c_char, args: *mut c_void) -> Option<Vec<u8>> {
    if format.is_null() {
        return None;
    }
    // The platform C library's `vasprintf`. It is not surfaced by the `libc` crate for the
    // `*-linux-gnu` targets, but the symbol is always present in the linked C runtime
    // (glibc/musl/BSD/Darwin all provide it). The `va_list` is forwarded as an opaque pointer,
    // which is the ABI-correct representation on every supported target (x86_64 SysV decays the
    // array to a pointer; AArch64 passes the >16-byte struct by reference; Apple arm64 uses a
    // `char *`). This links no new library (AAP §0.5.2) — it is the C runtime curl already uses.
    extern "C" {
        fn vasprintf(strp: *mut *mut c_char, format: *const c_char, ap: *mut c_void) -> c_int;
    }

    let mut out: *mut c_char = std::ptr::null_mut();
    // SAFETY: `format` is a valid C format string and `args` a matching `va_list` per this
    // function's contract. On success `vasprintf` sets `out` to a freshly C-allocated buffer and
    // returns the number of bytes written (excluding the NUL); on failure it returns a negative
    // value, which the guard below rejects before `out` is ever read.
    let n = unsafe { vasprintf(&mut out, format, args) };
    if n < 0 || out.is_null() {
        return None;
    }
    let len = n as usize;
    // SAFETY: on success `out` points to `len` initialised bytes (the formatted output, excluding
    // the trailing NUL). We copy exactly those bytes into an owned `Vec` before releasing the
    // buffer, so the returned data does not alias C-owned memory.
    let bytes = unsafe { std::slice::from_raw_parts(out as *const u8, len) }.to_vec();
    // SAFETY: `out` was allocated by the C library's `vasprintf`, so it must be released with the
    // matching C-library `free` (never Rust's allocator). `out` is not used after this call.
    unsafe { libc::free(out as *mut c_void) };
    Some(bytes)
}

/// Build the [`Source`] for a `va_list` entry point: the arguments expanded by the platform
/// `vasprintf` when possible, falling back to the format string itself (rendered against
/// [`EmptyArgs`]) if the platform call cannot produce them.
fn va_source(format: *const c_char, args: *mut c_void) -> Source {
    // SAFETY: `format`/`args` satisfy the `curl_mv*printf` contract for this call; the `va_list`
    // is consumed at most once, here.
    match unsafe { vformat_bytes(format, args) } {
        Some(bytes) => Source::Rendered(bytes),
        None => Source::Format(format),
    }
}

/// `curl_mprintf` / `curl_mfprintf` / `curl_mvprintf` / `curl_mvfprintf` core: format `src` to a
/// `FILE *` stream, returning the char count.
fn printf_to_stream(src: Source, stream: *mut FILE) -> c_int {
    if stream.is_null() {
        return 0;
    }
    let mut sink = FileSink { stream };
    src.run(&mut sink)
}

/// `curl_msprintf` / `curl_mvsprintf` core: unbounded write of `src` into `buffer`, then
/// NUL-terminate.
fn sprintf_to_buffer(src: Source, buffer: *mut c_char) -> c_int {
    if buffer.is_null() {
        return 0;
    }
    let mut sink = UnboundedBufSink { buffer, written: 0 };
    let done = src.run(&mut sink);
    // SAFETY: the unbounded `sprintf` contract has the caller guarantee `buffer` is large enough
    // for the whole output plus a trailing NUL; exactly `written` bytes were stored, so index
    // `written` is the terminator slot and is in bounds.
    unsafe {
        *buffer.add(sink.written) = 0;
    }
    done
}

/// `curl_msnprintf` / `curl_mvsnprintf` core: bounded write of `src` into `buffer`, with curl's
/// exact NUL-termination and return-count rule.
fn snprintf_to_buffer(src: Source, buffer: *mut c_char, maxlength: size_t) -> c_int {
    // A null buffer is treated as capacity zero (store nothing), preventing any null dereference.
    let max = if buffer.is_null() { 0 } else { maxlength };
    let mut sink = BoundedBufSink {
        buffer,
        length: 0,
        max,
    };
    let done = src.run(&mut sink);
    if sink.max == 0 {
        // Nothing was written and, per curl, the buffer is left untouched.
        return done;
    }
    if sink.length == sink.max {
        // Buffer filled to capacity: overwrite the last stored byte with the terminator and drop
        // it from the count (curl's `info.buffer[-1] = 0; retcode--`).
        // SAFETY: `max > 0` implies `buffer` is non-null, and the caller guarantees `max` writable
        // bytes, so index `max - 1` is in bounds.
        unsafe {
            *sink.buffer.add(sink.max - 1) = 0;
        }
        done - 1
    } else {
        // Room remains: terminate right after the stored bytes (curl's `info.buffer[0] = 0`).
        // SAFETY: `length < max` and the caller guarantees `max` writable bytes, so index
        // `length` is in bounds.
        unsafe {
            *sink.buffer.add(sink.length) = 0;
        }
        done
    }
}

/// `curl_maprintf` / `curl_mvaprintf` core: format `src` into a fresh heap `char *` for the caller.
fn aprintf_to_heap(src: Source) -> *mut c_char {
    let mut sink = VecSink { buf: Vec::new() };
    let _ = src.run(&mut sink);
    owned_c_string(sink.buf)
}

// ===========================================================================
// The 10 exported CURL_EXTERN symbols (byte-exact with include/curl/mprintf.h)
// ===========================================================================
//
// These ten symbols split into two halves that together form the drop-in
// `curl_m*printf` family:
//
//   * The five **variadic** entry points — `curl_mprintf`, `curl_mfprintf`,
//     `curl_msprintf`, `curl_msnprintf`, and `curl_maprintf` — take the C
//     `...` ellipsis. They are NOT defined here: a stable-Rust `extern "C"`
//     function cannot portably read a platform `va_list` because the
//     `c_variadic` feature that would let it do so is nightly-only, and this
//     crate is pinned to the MSRV-1.75 stable toolchain (AAP §0.7.3 forbids a
//     nightly requirement). They are instead defined as thin C trampolines in
//     `csrc/variadic_shim.c`, compiled and linked by `build.rs`. Each C
//     trampoline performs `va_start` and forwards the resulting `va_list` to
//     the matching `curl_mv*printf` worker exported just below, so the real
//     formatting logic still lives in safe Rust and there is exactly one
//     implementation of each format path.
//
//   * The five **`va_list`** entry points — `curl_mvprintf`, `curl_mvfprintf`,
//     `curl_mvsprintf`, `curl_mvsnprintf`, and `curl_mvaprintf` — are the Rust
//     workers defined below. They accept an already-constructed `va_list`
//     (typed as an opaque `*mut c_void`, which is ABI-identical to `va_list`
//     on every supported target) and are the forwarding targets of the C
//     trampolines above as well as being directly callable by C consumers.
//
// The net exported symbol set is unchanged from a hand-written C `libcurl`:
// all ten `curl_m*printf` names are present with byte-exact signatures.

/// `int curl_mvprintf(const char *format, va_list args);`
///
/// The `va_list` sibling of [`curl_mprintf`]. `args` is forwarded to the platform `vasprintf(3)`
/// to render the arguments, and the resulting bytes are written to `stdout` under curl's
/// character-counting rules (see the crate `NOTE` and [`Source`]).
#[no_mangle]
pub extern "C" fn curl_mvprintf(format: *const c_char, args: *mut c_void) -> c_int {
    crate::ffi_guard(0, || printf_to_stream(va_source(format, args), c_stdout()))
}

/// `int curl_mvfprintf(FILE *fd, const char *format, va_list args);`
///
/// The `va_list` sibling of [`curl_mfprintf`].
#[no_mangle]
pub extern "C" fn curl_mvfprintf(fd: *mut FILE, format: *const c_char, args: *mut c_void) -> c_int {
    crate::ffi_guard(0, || printf_to_stream(va_source(format, args), fd))
}

/// `int curl_mvsprintf(char *buffer, const char *format, va_list args);`
///
/// The `va_list` sibling of [`curl_msprintf`].
#[no_mangle]
pub extern "C" fn curl_mvsprintf(
    buffer: *mut c_char,
    format: *const c_char,
    args: *mut c_void,
) -> c_int {
    crate::ffi_guard(0, || sprintf_to_buffer(va_source(format, args), buffer))
}

/// `int curl_mvsnprintf(char *buffer, size_t maxlength, const char *format, va_list args);`
///
/// The `va_list` sibling of [`curl_msnprintf`].
#[no_mangle]
pub extern "C" fn curl_mvsnprintf(
    buffer: *mut c_char,
    maxlength: size_t,
    format: *const c_char,
    args: *mut c_void,
) -> c_int {
    crate::ffi_guard(0, || {
        snprintf_to_buffer(va_source(format, args), buffer, maxlength)
    })
}

/// `char *curl_mvaprintf(const char *format, va_list args);`
///
/// The `va_list` sibling of [`curl_maprintf`]. `args` is forwarded to the platform `vasprintf(3)`
/// to render the arguments before the bytes are copied into a fresh heap string (see [`Source`]).
#[no_mangle]
pub extern "C" fn curl_mvaprintf(format: *const c_char, args: *mut c_void) -> *mut c_char {
    std::panic::catch_unwind(|| aprintf_to_heap(va_source(format, args)))
        .unwrap_or(std::ptr::null_mut())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A single typed argument for the test [`VaArgs`] source.
    #[derive(Clone)]
    enum TestArg {
        Int(c_int),
        Long(c_long),
        LongLong(i64),
        UInt(c_uint),
        ULong(c_ulong),
        ULongLong(u64),
        Double(f64),
        Str(Option<Vec<u8>>),
        Ptr(usize),
    }

    /// A [`VaArgs`] implementation yielding a pre-set sequence of typed values. This drives the
    /// formatting engine ([`format_core`]) directly with *real* arguments, isolating the format
    /// dialect from the FFI/`vasprintf` layer that the C trampolines exercise (see the
    /// `public_*` tests, which cover the trampolines end to end).
    struct SliceArgs {
        it: std::vec::IntoIter<TestArg>,
    }

    impl SliceArgs {
        fn new(v: Vec<TestArg>) -> Self {
            SliceArgs { it: v.into_iter() }
        }
    }

    impl VaArgs for SliceArgs {
        fn arg_int(&mut self) -> c_int {
            match self.it.next() {
                Some(TestArg::Int(v)) => v,
                _ => 0,
            }
        }
        fn arg_long(&mut self) -> c_long {
            match self.it.next() {
                Some(TestArg::Long(v)) => v,
                _ => 0,
            }
        }
        fn arg_longlong(&mut self) -> i64 {
            match self.it.next() {
                Some(TestArg::LongLong(v)) => v,
                _ => 0,
            }
        }
        fn arg_uint(&mut self) -> c_uint {
            match self.it.next() {
                Some(TestArg::UInt(v)) => v,
                _ => 0,
            }
        }
        fn arg_ulong(&mut self) -> c_ulong {
            match self.it.next() {
                Some(TestArg::ULong(v)) => v,
                _ => 0,
            }
        }
        fn arg_ulonglong(&mut self) -> u64 {
            match self.it.next() {
                Some(TestArg::ULongLong(v)) => v,
                _ => 0,
            }
        }
        fn arg_double(&mut self) -> c_double {
            match self.it.next() {
                Some(TestArg::Double(v)) => v,
                _ => 0.0,
            }
        }
        fn arg_str(&mut self) -> Option<StrArg> {
            match self.it.next() {
                Some(TestArg::Str(v)) => v,
                _ => None,
            }
        }
        fn arg_ptr(&mut self) -> usize {
            match self.it.next() {
                Some(TestArg::Ptr(v)) => v,
                _ => 0,
            }
        }
    }

    /// Convenience: build a non-null string argument.
    fn s(bytes: &[u8]) -> TestArg {
        TestArg::Str(Some(bytes.to_vec()))
    }

    /// Render `fmt` with `args` through the internal engine, returning the raw output bytes.
    fn render(fmt: &[u8], args: Vec<TestArg>) -> Vec<u8> {
        let mut a = SliceArgs::new(args);
        let mut sink = VecSink { buf: Vec::new() };
        let _ = format_core(fmt, &mut a, &mut sink);
        sink.buf
    }

    /// Render `fmt` with `args` and return the output as a UTF-8 string (for ASCII expectations).
    fn rs(fmt: &[u8], args: Vec<TestArg>) -> String {
        String::from_utf8(render(fmt, args)).expect("test output is valid UTF-8")
    }

    /// Render `fmt` with `args` into a fixed buffer using curl's bounded snprintf contract,
    /// returning the reported character count; `buf` receives the NUL-terminated result.
    fn render_bounded(fmt: &[u8], args: Vec<TestArg>, buf: &mut [u8]) -> c_int {
        let mut a = SliceArgs::new(args);
        let max = buf.len();
        let mut sink = BoundedBufSink {
            buffer: buf.as_mut_ptr() as *mut c_char,
            length: 0,
            max,
        };
        let done = format_core(fmt, &mut a, &mut sink);
        if sink.max == 0 {
            return done;
        }
        if sink.length == sink.max {
            // SAFETY: `max > 0` and `buf` has `max` bytes, so index `max - 1` is in bounds.
            unsafe {
                *sink.buffer.add(sink.max - 1) = 0;
            }
            done - 1
        } else {
            // SAFETY: `length < max` and `buf` has `max` bytes, so index `length` is in bounds.
            unsafe {
                *sink.buffer.add(sink.length) = 0;
            }
            done
        }
    }

    // ---- The formatting engine, driven with real arguments ----

    #[test]
    fn d_s_s_with_real_args() {
        // The canonical checklist case: "%d %s %s" with (42, "a", "b").
        assert_eq!(
            rs(b"%d %s %s", vec![TestArg::Int(42), s(b"a"), s(b"b")]),
            "42 a b"
        );
    }

    #[test]
    fn literal_and_percent_escape() {
        assert_eq!(rs(b"plain text", vec![]), "plain text");
        assert_eq!(rs(b"100%% done", vec![]), "100% done");
        assert_eq!(rs(b"%%%%", vec![]), "%%");
        // A trailing lone '%' is emitted verbatim (curl treats it as literal text).
        assert_eq!(rs(b"abc%", vec![]), "abc%");
        // An unknown conversion is disregarded and reprocessed as literal text.
        assert_eq!(rs(b"%y", vec![]), "%y");
    }

    #[test]
    fn integer_width_and_flags() {
        assert_eq!(rs(b"%5d", vec![TestArg::Int(42)]), "   42");
        assert_eq!(rs(b"%-5d", vec![TestArg::Int(42)]), "42   ");
        assert_eq!(rs(b"%05d", vec![TestArg::Int(42)]), "00042");
        assert_eq!(rs(b"%+d", vec![TestArg::Int(42)]), "+42");
        assert_eq!(rs(b"% d", vec![TestArg::Int(42)]), " 42");
        assert_eq!(rs(b"%d", vec![TestArg::Int(-42)]), "-42");
        assert_eq!(rs(b"%.5d", vec![TestArg::Int(42)]), "00042");
        assert_eq!(rs(b"%8.5d", vec![TestArg::Int(42)]), "   00042");
    }

    #[test]
    fn integer_bases() {
        assert_eq!(rs(b"%x", vec![TestArg::UInt(255)]), "ff");
        assert_eq!(rs(b"%X", vec![TestArg::UInt(255)]), "FF");
        assert_eq!(rs(b"%#x", vec![TestArg::UInt(255)]), "0xff");
        assert_eq!(rs(b"%#X", vec![TestArg::UInt(255)]), "0XFF");
        assert_eq!(rs(b"%o", vec![TestArg::UInt(8)]), "10");
        assert_eq!(rs(b"%#o", vec![TestArg::UInt(8)]), "010");
        assert_eq!(rs(b"%u", vec![TestArg::UInt(4_294_967_295)]), "4294967295");
    }

    #[test]
    fn char_conversion() {
        assert_eq!(rs(b"%c", vec![TestArg::Int(65)]), "A");
        assert_eq!(rs(b"%5c", vec![TestArg::Int(65)]), "    A");
        assert_eq!(rs(b"%-5c", vec![TestArg::Int(65)]), "A    ");
    }

    #[test]
    fn string_conversion() {
        assert_eq!(rs(b"%s", vec![s(b"hello")]), "hello");
        assert_eq!(rs(b"%.3s", vec![s(b"abcdef")]), "abc");
        assert_eq!(rs(b"%5s", vec![s(b"ab")]), "   ab");
        assert_eq!(rs(b"%-5s", vec![s(b"ab")]), "ab   ");
        // '%S' wraps the string in double quotes (curl's alternate-form string).
        assert_eq!(rs(b"%S", vec![s(b"hi")]), "\"hi\"");
        // NULL string -> "(nil)" when the precision permits, otherwise empty.
        assert_eq!(rs(b"%s", vec![TestArg::Str(None)]), "(nil)");
        assert_eq!(rs(b"%.2s", vec![TestArg::Str(None)]), "");
    }

    #[test]
    fn pointer_conversion() {
        assert_eq!(rs(b"%p", vec![TestArg::Ptr(0x1234)]), "0x1234");
        assert_eq!(rs(b"%p", vec![TestArg::Ptr(0)]), "(nil)");
    }

    #[test]
    fn long_and_curl_off_t_style() {
        assert_eq!(rs(b"%ld", vec![TestArg::Long(123_456)]), "123456");
        assert_eq!(
            rs(b"%lu", vec![TestArg::ULong(4_000_000_000)]),
            "4000000000"
        );
        assert_eq!(
            rs(b"%lld", vec![TestArg::LongLong(9_000_000_000)]),
            "9000000000"
        );
        assert_eq!(
            rs(b"%llu", vec![TestArg::ULongLong(18_000_000_000)]),
            "18000000000"
        );
        // '%zd' and '%Od' select long/long-long by width; on LP64 targets both map to `long`.
        if core::mem::size_of::<size_t>() == core::mem::size_of::<c_long>() {
            assert_eq!(rs(b"%zd", vec![TestArg::Long(123_456)]), "123456");
            assert_eq!(rs(b"%Od", vec![TestArg::Long(-7)]), "-7");
        }
    }

    #[test]
    fn width_and_precision_from_args() {
        // "%*d": width comes from the first argument, value from the second.
        assert_eq!(rs(b"%*d", vec![TestArg::Int(5), TestArg::Int(42)]), "   42");
        // A negative '*' width behaves as a '-' flag plus positive width.
        assert_eq!(
            rs(b"%*d", vec![TestArg::Int(-5), TestArg::Int(42)]),
            "42   "
        );
        // "%.*f": precision from the first argument, value from the second.
        assert_eq!(
            rs(b"%.*f", vec![TestArg::Int(2), TestArg::Double(1.25)]),
            "1.25"
        );
    }

    #[test]
    fn positional_arguments() {
        // Positional selectors reorder which argument each conversion consumes.
        assert_eq!(rs(b"%2$s %1$s", vec![s(b"a"), s(b"b")]), "b a");
    }

    #[test]
    fn float_conversions() {
        assert_eq!(rs(b"%f", vec![TestArg::Double(1.0)]), "1.000000");
        assert_eq!(rs(b"%.2f", vec![TestArg::Double(12.75)]), "12.75");
        assert_eq!(rs(b"%8.2f", vec![TestArg::Double(3.5)]), "    3.50");
        assert_eq!(rs(b"%.0f", vec![TestArg::Double(42.0)]), "42");
        assert_eq!(rs(b"%+.1f", vec![TestArg::Double(2.5)]), "+2.5");
    }

    // ---- The bounded snprintf contract (curl's exact truncation + NUL rule), with real args ----

    #[test]
    fn bounded_fits_with_real_args() {
        let mut buf = [0u8; 64];
        let n = render_bounded(
            b"%d %s %s",
            vec![TestArg::Int(42), s(b"a"), s(b"b")],
            &mut buf,
        );
        assert_eq!(n, 6);
        assert_eq!(std::str::from_utf8(&buf[..6]).unwrap(), "42 a b");
        assert_eq!(buf[6], 0);
    }

    #[test]
    fn bounded_truncates_reserving_nul() {
        // "hello" into 4 bytes stores "hel\0" and reports 3 (curl reserves the last byte for NUL).
        let mut buf = [0u8; 4];
        let n = render_bounded(b"hello", vec![], &mut buf);
        assert_eq!(n, 3);
        assert_eq!(std::str::from_utf8(&buf[..3]).unwrap(), "hel");
        assert_eq!(buf[3], 0);
    }

    #[test]
    fn bounded_exact_fit_still_drops_last() {
        // Output length == max: curl still overwrites the final char with NUL and returns max-1.
        let mut buf = [0u8; 5];
        let n = render_bounded(b"hello", vec![], &mut buf);
        assert_eq!(n, 4);
        assert_eq!(std::str::from_utf8(&buf[..4]).unwrap(), "hell");
        assert_eq!(buf[4], 0);
    }

    // ---- The exported C-variadic entry points (the real trampolines from variadic_shim.c) ----
    //
    // The `...` entry points — `curl_mprintf`, `curl_msprintf`, `curl_msnprintf`, `curl_maprintf`
    // — are defined in C (stable Rust cannot express `...`; see the crate module docs). Rust
    // cannot *define* a C variadic on the stable toolchain, but it can *declare and call* one:
    // both have been stable since 1.0. Declaring them here as variadic `extern "C"` therefore
    // exercises the ACTUAL shipped trampolines end to end — `va_start` capture in C, the `va_list`
    // forwarded to the Rust `curl_mv*printf` worker, and the platform `vasprintf` — including with
    // real, typed arguments. This is the direct runtime proof of the F6-MPRINTF fix: before it,
    // the stable-Rust entry points could not read varargs at all.
    extern "C" {
        fn curl_mprintf(format: *const c_char, ...) -> c_int;
        fn curl_msprintf(buffer: *mut c_char, format: *const c_char, ...) -> c_int;
        fn curl_msnprintf(
            buffer: *mut c_char,
            maxlength: size_t,
            format: *const c_char,
            ...
        ) -> c_int;
        fn curl_maprintf(format: *const c_char, ...) -> *mut c_char;
    }

    #[test]
    fn public_msnprintf_literal() {
        let f = CString::new("hello").unwrap();
        let mut buf = [0i8; 16];
        // SAFETY: variadic C call whose format consumes no arguments; `buf` has room for "hello\0".
        let n = unsafe { curl_msnprintf(buf.as_mut_ptr(), 16, f.as_ptr()) };
        assert_eq!(n, 5);
        // SAFETY: `curl_msnprintf` NUL-terminated `buf`, which lives for this scope.
        let out = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(out, "hello");
    }

    #[test]
    fn public_msnprintf_truncates() {
        let f = CString::new("hello").unwrap();
        let mut buf = [0i8; 4];
        // SAFETY: variadic C call; the bounded sink truncates to `max - 1` and NUL-terminates.
        let n = unsafe { curl_msnprintf(buf.as_mut_ptr(), 4, f.as_ptr()) };
        assert_eq!(n, 3);
        // SAFETY: `curl_msnprintf` NUL-terminated `buf`.
        let out = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(out, "hel");
    }

    #[test]
    fn public_msnprintf_zero_max_leaves_buffer_untouched() {
        let f = CString::new("hello").unwrap();
        let mut buf = [0x7fi8; 4];
        // SAFETY: variadic C call with maxlength 0; curl writes nothing.
        let n = unsafe { curl_msnprintf(buf.as_mut_ptr(), 0, f.as_ptr()) };
        assert_eq!(n, 0);
        assert_eq!(buf[0], 0x7f); // untouched
    }

    #[test]
    fn public_msnprintf_reads_real_varargs() {
        // The whole point of the C trampoline (F6-MPRINTF): real `...` arguments are captured and
        // formatted with correct types. This positive test replaces the pre-fix test that locked
        // in the broken behaviour (the stable entry point observing zero/NULL for every argument).
        let f = CString::new("int=%d str=%s hex=%x").unwrap();
        let hi = CString::new("hi").unwrap();
        let mut buf = [0i8; 64];
        // SAFETY: the format's conversions (`%d`, `%s`, `%x`) match the trailing arguments in
        // number and type (`c_int`, `char *`, `c_int` read as unsigned); `buf` fits the result.
        let n = unsafe {
            curl_msnprintf(
                buf.as_mut_ptr(),
                64,
                f.as_ptr(),
                42 as c_int,
                hi.as_ptr(),
                255 as c_int,
            )
        };
        // SAFETY: `curl_msnprintf` NUL-terminated `buf`.
        let out = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(out, "int=42 str=hi hex=ff");
        assert_eq!(n, out.len() as c_int);
    }

    #[test]
    fn public_msprintf_unbounded_with_varargs() {
        let f = CString::new("x=%d").unwrap();
        let mut buf = [0i8; 16];
        // SAFETY: one `%d` matches the single trailing `c_int`; `buf` is large enough.
        let n = unsafe { curl_msprintf(buf.as_mut_ptr(), f.as_ptr(), 9 as c_int) };
        assert_eq!(n, 3);
        // SAFETY: `curl_msprintf` NUL-terminated `buf`.
        let out = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(out, "x=9");
    }

    #[test]
    fn public_maprintf_round_trip_and_free() {
        let f = CString::new("name=%s n=%d").unwrap();
        let nm = CString::new("abc").unwrap();
        // SAFETY: `%s`/`%d` match the trailing `char *`/`c_int` arguments.
        let p = unsafe { curl_maprintf(f.as_ptr(), nm.as_ptr(), 7 as c_int) };
        assert!(!p.is_null());
        // SAFETY: `p` is a valid NUL-terminated string just returned by `curl_maprintf`; copy it
        // out before freeing so the pointer is not used afterwards.
        let out = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
        assert_eq!(out, "name=abc n=7");
        // `curl_free` (a safe `extern "C"` fn) reclaims the `curl_maprintf` allocation via its
        // `CString::from_raw`, the exact inverse of the `CString::into_raw` used to create it.
        crate::global::curl_free(p as *mut c_void);
    }

    #[test]
    fn public_maprintf_empty_is_non_null() {
        let f = CString::new("").unwrap();
        // SAFETY: an empty format consumes no arguments.
        let p = unsafe { curl_maprintf(f.as_ptr()) };
        assert!(!p.is_null());
        // SAFETY: `p` is a valid NUL-terminated (empty) string returned by `curl_maprintf`.
        let out = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
        assert_eq!(out, "");
        // Reclaim the `curl_maprintf` allocation (safe `extern "C"` call), as above.
        crate::global::curl_free(p as *mut c_void);
    }

    #[test]
    fn null_format_is_safe() {
        // A null format must not dereference null; the int variants return 0 and the heap variant
        // returns a non-null empty string (safer than curl, which would crash). The C trampolines
        // forward the null straight to the Rust worker, whose `vformat_bytes` null-guard makes the
        // behaviour well-defined.
        // SAFETY: passing a null format is part of the contract these entry points uphold; no
        // trailing argument is consumed.
        assert_eq!(unsafe { curl_mprintf(std::ptr::null()) }, 0);
        let mut buf = [0x7fi8; 8];
        // SAFETY: null format, bounded buffer; the worker writes an empty, NUL-terminated result.
        let n = unsafe { curl_msnprintf(buf.as_mut_ptr(), 8, std::ptr::null()) };
        assert_eq!(n, 0);
        assert_eq!(buf[0], 0); // NUL-terminated empty result
                               // SAFETY: null format; the heap variant returns a fresh empty string.
        let p = unsafe { curl_maprintf(std::ptr::null()) };
        assert!(!p.is_null());
        // Reclaim the empty allocation (safe `extern "C"` call).
        crate::global::curl_free(p as *mut c_void);
    }
}
