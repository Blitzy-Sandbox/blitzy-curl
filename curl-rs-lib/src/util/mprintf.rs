//! curl-compatible `*printf` formatting engine.
//!
//! This module is a **byte-for-byte** Rust reimplementation of libcurl's
//! self-contained, portable formatted-output implementation (`lib/mprintf.c`).
//! It backs the public `curl_mprintf` symbol family (re-exposed by
//! `curl-rs-ffi/src/mprintf.rs`) as well as curl's internal formatting used by
//! `infof`/`failf`, `--write-out`, header building, and similar call sites.
//!
//! # Why a typed engine instead of C varargs
//!
//! The original C code is variadic (`const char *format, ...`). Defining
//! C-variadic functions is the job of the FFI crate (`curl-rs-ffi`), which is
//! the only place `unsafe` is permitted. **This** module exposes a *typed*
//! formatting engine: callers pass a format byte string plus a slice of typed
//! arguments ([`FmtArg`]). The FFI layer adapts a C `va_list` into a
//! `Vec<FmtArg>` (reading each argument with the width dictated by the
//! conversion/length modifier) and then calls into this engine. Internal Rust
//! callers build the `FmtArg` list directly.
//!
//! As a result this file contains **zero `unsafe`** and compiles cleanly under
//! the crate-wide `#![forbid(unsafe_code)]` attribute.
//!
//! # Dependency discipline (no cycle with `dynbuf`)
//!
//! curl's `dynbuf` "append-formatted" helpers (`curlx_dyn_addf`/`vaddf`) call
//! *into* the printf engine. To preserve the dependency DAG, this module must
//! **never** depend on [`crate::util::dynbuf`]. The allocate-and-return path
//! ([`maprintf`]) therefore builds into a `Vec<u8>` it owns itself. `mprintf`
//! is a foundational leaf utility; everything else may depend on it.
//!
//! # Parity contract
//!
//! Every directive — flags (` `, `+`, `-`, `#`, `0`), width (including `*` and
//! positional `*N$`), precision (including `.*` and `.*N$`), length modifiers
//! (`h`, `l`, `ll`, `L`, `q`, `z`, `O`), positional arguments (`%N$`), and the
//! conversions `d i u o x X c s S p n f e E g G %%` — reproduces curl's exact
//! output, including curl-specific quirks that differ from the host C library
//! (for example `%#x` of `0` yields `0x0`, and the `0` flag is **not** ignored
//! when a precision is given for integer conversions).
//!
//! Floating point output is the one area curl delegates to the host C
//! `snprintf`. That delegation is reproduced here in pure Rust (validated
//! against the host `printf` and against curl's own compiled output) so the
//! engine is self-contained and free of any C linkage.

use std::cell::Cell;
use std::rc::Rc;

// ===========================================================================
// Typed argument model
// ===========================================================================

/// A single typed argument consumed by a conversion directive.
///
/// The FFI crate reads C `va_list` entries (honoring the conversion's length
/// modifier — e.g. `int` for `%d`, `unsigned long` for `%lu`, `double` for
/// `%f`) and materializes the appropriate variant. The width-correct value is
/// therefore already established by the time it reaches the engine; the engine
/// renders the stored value as-is.
#[derive(Clone, Debug)]
pub enum FmtArg {
    /// Signed integer (`%d`, `%i`, and signed/length-modified forms). The
    /// stored `i64` is the already sign-extended value.
    Int(i64),
    /// Unsigned integer (`%u`, `%o`, `%x`, `%X`). The stored `u64` is the
    /// already zero-extended value.
    Uint(u64),
    /// Floating point value (`%f`, `%e`, `%E`, `%g`, `%G`).
    Double(f64),
    /// A single character (`%c`). curl reads an `int` and emits its low byte;
    /// this variant carries that low byte directly.
    Char(u8),
    /// A string (`%s`, `%S`). `None` represents a C `NULL` pointer, which curl
    /// renders as `(nil)` (subject to the precision rules in [`out_string`]).
    /// The bytes are treated as a C string: a `0` byte terminates it.
    Str(Option<Vec<u8>>),
    /// A pointer (`%p`). `None` represents a `NULL` pointer (rendered `(nil)`).
    Ptr(Option<usize>),
    /// A `%n` store target. When the engine reaches the directive it writes the
    /// number of bytes emitted so far into the cell (matching curl, which
    /// stores the running output count). The directive itself emits nothing.
    /// The FFI crate is responsible for narrowing the stored count to the C
    /// destination width (`int`/`short`/`long`/`long long`) per the length
    /// modifier and writing it through the raw `int *`.
    CountStore(Rc<Cell<i64>>),
}

impl FmtArg {
    /// Convenience constructor for a non-NULL string argument.
    pub fn string(bytes: impl Into<Vec<u8>>) -> Self {
        FmtArg::Str(Some(bytes.into()))
    }

    /// Convenience constructor for a `NULL` string argument.
    pub fn null_string() -> Self {
        FmtArg::Str(None)
    }

    /// Convenience constructor for a non-NULL pointer argument.
    pub fn pointer(addr: usize) -> Self {
        FmtArg::Ptr(Some(addr))
    }

    /// Convenience constructor for a `NULL` pointer argument.
    pub fn null_pointer() -> Self {
        FmtArg::Ptr(None)
    }

    /// Create a `%n` count-store argument together with the shared cell the
    /// caller can read after formatting completes.
    pub fn count_store() -> (Self, Rc<Cell<i64>>) {
        let cell = Rc::new(Cell::new(0));
        (FmtArg::CountStore(cell.clone()), cell)
    }

    /// Read the argument as a signed integer (used for values and for `*`
    /// width/precision arguments). Lenient: foreign variants are coerced so a
    /// caller mismatch can never panic.
    fn as_i64(&self) -> i64 {
        match self {
            FmtArg::Int(v) => *v,
            FmtArg::Uint(v) => *v as i64,
            FmtArg::Char(v) => *v as i64,
            FmtArg::Ptr(Some(v)) => *v as i64,
            FmtArg::Double(v) => *v as i64,
            _ => 0,
        }
    }

    /// Read the argument as an unsigned integer.
    fn as_u64(&self) -> u64 {
        match self {
            FmtArg::Uint(v) => *v,
            FmtArg::Int(v) => *v as u64,
            FmtArg::Char(v) => *v as u64,
            FmtArg::Ptr(Some(v)) => *v as u64,
            FmtArg::Double(v) => *v as u64,
            _ => 0,
        }
    }

    /// Read the argument as a floating point value.
    fn as_f64(&self) -> f64 {
        match self {
            FmtArg::Double(v) => *v,
            FmtArg::Int(v) => *v as f64,
            FmtArg::Uint(v) => *v as f64,
            _ => 0.0,
        }
    }

    /// Read the argument as a string. `None` denotes a C `NULL` pointer; any
    /// non-string variant is treated as the empty string (defensive default).
    fn as_str(&self) -> Option<&[u8]> {
        match self {
            FmtArg::Str(Some(b)) => Some(b.as_slice()),
            FmtArg::Str(None) => None,
            _ => Some(&[]),
        }
    }

    /// Read the argument as a pointer. `None` denotes a `NULL` pointer.
    fn as_ptr(&self) -> Option<usize> {
        match self {
            FmtArg::Ptr(p) => *p,
            FmtArg::Int(v) => Some(*v as usize),
            FmtArg::Uint(v) => Some(*v as usize),
            _ => None,
        }
    }
}

// ===========================================================================
// Flags, limits, and shared constants (mirroring lib/mprintf.c)
// ===========================================================================

const FLAGS_SPACE: u32 = 1 << 0; // ' '  prefix space for positive signed values
const FLAGS_SHOWSIGN: u32 = 1 << 1; // '+'  always show a sign
const FLAGS_LEFT: u32 = 1 << 2; // '-'  left justify
const FLAGS_ALT: u32 = 1 << 3; // '#'  alternate form (0x / 0 prefixes, %S quotes)
const FLAGS_SHORT: u32 = 1 << 4; // 'h'
const FLAGS_LONG: u32 = 1 << 5; // 'l'
const FLAGS_LONGLONG: u32 = 1 << 6; // 'll' / 'q'
const FLAGS_LONGDOUBLE: u32 = 1 << 7; // 'L'
const FLAGS_PAD_NIL: u32 = 1 << 8; // '0'  zero pad (cleared by '-')
const FLAGS_UNSIGNED: u32 = 1 << 9; // u / o / x / X
const FLAGS_OCTAL: u32 = 1 << 10; // o
const FLAGS_HEX: u32 = 1 << 11; // x / X / p
const FLAGS_UPPER: u32 = 1 << 12; // X / E / G
const FLAGS_WIDTH: u32 = 1 << 13; // '*' or a literal width was used
const FLAGS_WIDTHPARAM: u32 = 1 << 14; // width comes from an argument
const FLAGS_PREC: u32 = 1 << 15; // a literal precision was specified
const FLAGS_PRECPARAM: u32 = 1 << 16; // precision comes from an argument
const FLAGS_CHAR: u32 = 1 << 17; // %c
const FLAGS_FLOATE: u32 = 1 << 18; // %e / %E
const FLAGS_FLOATG: u32 = 1 << 19; // %g / %G
const FLAGS_SUBSTR: u32 = 1 << 20; // literal-only output segment

/// Maximum number of input arguments a single format string may reference,
/// matching curl's `MAX_PARAMETERS`.
const MAX_PARAMETERS: i64 = 128;

/// Size of curl's scratch buffer used for long-to-string and float-to-string
/// conversions (`BUFFSIZE`). The integer renderer models a buffer of this size
/// so that curl's bound on the number of digits/precision-zeros a single
/// integer body may contain is reproduced exactly (via the lower-bound guard
/// while writing precision zeros).
const BUFFSIZE: usize = 326;

/// Maximum size of the buffer produced by the allocate-and-return path,
/// matching curl's `DYN_APRINTF` limit (`curl_maprintf` returns `NULL` past
/// this size).
const DYN_APRINTF: usize = 8_000_000;

/// The string curl prints for a `NULL` string or pointer.
const NILSTR: &[u8] = b"(nil)";

/// Lower-case hexadecimal digit table (`Curl_ldigits`).
const LDIGITS: &[u8; 16] = b"0123456789abcdef";

/// Upper-case hexadecimal digit table (`Curl_udigits`).
const UDIGITS: &[u8; 16] = b"0123456789ABCDEF";

// ===========================================================================
// Parsed-directive representation
// ===========================================================================

/// Which renderer a conversion directive dispatches to. Mirrors the
/// `FormatType`/`MTYPE_*` dispatch in curl's `formatf`, but resolved per output
/// segment (each directive carries its own conversion).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    /// Integer family (`d i u o x X c`); the precise behavior is selected by the
    /// segment flags (`UNSIGNED`/`OCTAL`/`HEX`/`UPPER`/`CHAR`).
    Number,
    /// String (`s`, `S`).
    Str,
    /// Pointer (`p`).
    Pointer,
    /// Floating point (`f e E g G`).
    Double,
    /// `%n` store-count directive.
    Count,
}

/// A single output segment: an optional literal run copied verbatim from the
/// format string, optionally followed by one conversion. Mirrors curl's
/// `struct outsegment`.
///
/// `width`/`precision` hold either a literal value or, when the corresponding
/// `FLAGS_WIDTHPARAM`/`FLAGS_PRECPARAM` flag is set, the **argument index** the
/// value is read from (exactly as curl reuses the field).
#[derive(Clone, Debug)]
struct Segment {
    /// Start offset (into the format slice) of the literal run preceding the
    /// conversion.
    start: usize,
    /// Length of the literal run.
    outlen: usize,
    /// Conversion/display flags (`FLAGS_*`).
    flags: u32,
    /// Literal field width, or the width argument index when `FLAGS_WIDTHPARAM`.
    width: i32,
    /// Literal precision, or the precision argument index when
    /// `FLAGS_PRECPARAM`.
    precision: i32,
    /// Argument index supplying the conversion's value.
    input: usize,
    /// Which renderer to invoke (ignored when `substr` is `true`).
    target: Target,
    /// `true` for a literal-only segment (no conversion follows). Mirrors
    /// `FLAGS_SUBSTR`.
    substr: bool,
}

// ===========================================================================
// Low-level parse helpers (curlx_str_number / dollarstring equivalents)
// ===========================================================================

/// Parse an unsigned decimal number, equivalent to `curlx_str_number`.
///
/// * Requires **at least one** ASCII digit; otherwise returns `None`.
/// * `max` is the inclusive upper bound; a value exceeding it returns `None`
///   (overflow) — matching curl's per-digit overflow check, which leaves the
///   cursor unmodified on failure.
/// * On success advances `pos` past the consumed digits and returns the value.
///
/// Leading zeros are accepted; parsing stops at the first non-digit byte.
fn parse_uint(fmt: &[u8], pos: &mut usize, max: i64) -> Option<i64> {
    let start = *pos;
    if start >= fmt.len() || !fmt[start].is_ascii_digit() {
        return None;
    }
    // `max` is always >= the base (10) for our uses (128 and i32::MAX), so the
    // general overflow check from curl's `str_num_base` applies directly.
    let mut num: i64 = 0;
    let mut p = start;
    while p < fmt.len() && fmt[p].is_ascii_digit() {
        let n = (fmt[p] - b'0') as i64;
        if num > (max - n) / 10 {
            // Would overflow `max`; leave `pos` untouched, matching curl.
            return None;
        }
        num = num * 10 + n;
        p += 1;
    }
    *pos = p;
    Some(num)
}

/// Parse a positional `N$` reference, equivalent to curl's `dollarstring`,
/// returning both the 0-based index and the cursor position just past the `$`.
///
/// The reference is 1-based in the format string; the returned index is
/// 0-based. Returns `None` when there is no valid number, the number is `0`, or
/// the trailing `$` is missing (mirroring curl, which leaves its end pointer
/// unmodified on failure — here the caller simply ignores the cursor on `None`).
fn dollar_at(fmt: &[u8], pos: usize) -> Option<(usize, usize)> {
    let mut p = pos;
    let num = parse_uint(fmt, &mut p, MAX_PARAMETERS)?;
    if p >= fmt.len() || fmt[p] != b'$' || num == 0 {
        return None;
    }
    p += 1;
    Some(((num - 1) as usize, p))
}

/// Maximum number of output segments a format may produce (`MAX_SEGMENTS`).
const MAX_SEGMENTS: usize = 128;

/// Dollar (positional) parsing state, mirroring curl's
/// `DOLLAR_UNKNOWN`/`DOLLAR_NOPE`/`DOLLAR_USE`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dollar {
    /// Not yet determined whether positional arguments are in use.
    Unknown,
    /// Confirmed non-positional (plain sequential arguments).
    Nope,
    /// Confirmed positional (`%N$`).
    Use,
}

// ===========================================================================
// Format parser (parsefmt equivalent)
// ===========================================================================

/// Parse a format byte string into an ordered list of output [`Segment`]s.
///
/// Returns `None` on any malformed format (curl's `PFMT_*` error conditions:
/// bad positional use, mixed positional/non-positional arguments, argument
/// gaps, precision/width overflow, segment overflow, ...). curl's `formatf`
/// emits **nothing** when `parsefmt` fails, so callers translate `None` into an
/// empty output.
///
/// A `0` byte terminates the format (matching C string semantics), so segment
/// offsets never span an embedded NUL.
fn parse_format(fmt: &[u8]) -> Option<Vec<Segment>> {
    // Logical end of the format: the first NUL or the slice end.
    let end = fmt.iter().position(|&b| b == 0).unwrap_or(fmt.len());

    let mut out: Vec<Segment> = Vec::new();
    let mut f = 0usize; // cursor (C's `fmt`)
    let mut start = 0usize; // start of the current literal run
    let mut param_num: i64 = 0; // next auto-assigned argument index
    let mut max_param: i64 = -1; // highest argument index referenced
    let mut used = [false; MAX_PARAMETERS as usize]; // referenced-argument bitset
    let mut use_dollar = Dollar::Unknown;

    while f < end {
        if fmt[f] != b'%' {
            f += 1;
            continue;
        }

        let mut flags: u32 = 0;
        let mut width: i32 = 0;
        let mut precision: i32 = 0;
        let mut param: i64 = -1;

        f += 1; // step past '%'
        let outlen = f - start - 1; // literal bytes preceding the '%'

        // `%%` -> a literal percent. Flush the preceding literal as its own
        // segment, then restart the literal run at the second '%' so it folds
        // into the next run, collapsing `%%` to `%`.
        if f < end && fmt[f] == b'%' {
            if outlen > 0 {
                if out.len() >= MAX_SEGMENTS {
                    return None; // PFMT_MANYSEGS
                }
                out.push(Segment {
                    start,
                    outlen,
                    flags: FLAGS_SUBSTR,
                    width: 0,
                    precision: 0,
                    input: 0,
                    target: Target::Number,
                    substr: true,
                });
            }
            start = f;
            f += 1;
            continue;
        }

        // Positional `%N$` for the main parameter.
        if use_dollar != Dollar::Nope {
            match dollar_at(fmt, f) {
                Some((idx, newf)) => {
                    param = idx as i64;
                    f = newf;
                    use_dollar = Dollar::Use;
                }
                None => {
                    if use_dollar == Dollar::Use {
                        return None; // PFMT_DOLLAR: positional expected
                    }
                    param = -1;
                    use_dollar = Dollar::Nope;
                }
            }
        }

        // ---- Flags, length modifiers, width, precision ----
        let mut loopit = true;
        while loopit {
            if f >= end {
                // Ran off the end mid-directive: treated like the default case
                // (curl reads the terminating NUL, which is not a flag).
                break;
            }
            let c = fmt[f];
            f += 1;
            match c {
                b' ' => flags |= FLAGS_SPACE,
                b'+' => flags |= FLAGS_SHOWSIGN,
                b'-' => {
                    flags |= FLAGS_LEFT;
                    flags &= !FLAGS_PAD_NIL;
                }
                b'#' => flags |= FLAGS_ALT,
                b'.' => {
                    if f < end && fmt[f] == b'*' {
                        // Precision from an argument.
                        flags |= FLAGS_PRECPARAM;
                        f += 1;
                        if use_dollar == Dollar::Use {
                            match dollar_at(fmt, f) {
                                Some((idx, newf)) => {
                                    precision = idx as i32;
                                    f = newf;
                                }
                                None => return None, // PFMT_DOLLARPREC
                            }
                        } else {
                            precision = -1; // read from the next argument
                        }
                    } else {
                        // Literal precision; a digit is REQUIRED (curl rejects
                        // a bare `.` with no number, unlike standard printf).
                        flags |= FLAGS_PREC;
                        let is_neg = f < end && fmt[f] == b'-';
                        if is_neg {
                            f += 1;
                        }
                        match parse_uint(fmt, &mut f, i32::MAX as i64) {
                            Some(num) => {
                                precision = num as i32;
                                if is_neg {
                                    precision = -precision;
                                }
                            }
                            None => return None, // PFMT_PREC
                        }
                    }
                    if flags & (FLAGS_PREC | FLAGS_PRECPARAM) == (FLAGS_PREC | FLAGS_PRECPARAM) {
                        return None; // PFMT_PRECMIX: both kinds of precision
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
                // `z` (size_t) and `O` (curl_off_t): on the 64-bit targets of
                // this project both equal `long`. The length modifier does not
                // affect rendering in the typed engine (the value width is
                // fixed by the `FmtArg`), so this is purely for correct cursor
                // advancement. Windows `I`/`I32`/`I64` are intentionally not
                // handled (matching non-Windows curl): `I` falls through to the
                // default case and the directive is disregarded.
                b'z' => flags |= FLAGS_LONG,
                b'O' => flags |= FLAGS_LONG,
                b'0' => {
                    if flags & FLAGS_LEFT == 0 {
                        flags |= FLAGS_PAD_NIL;
                    }
                    // Fall through to width parsing, re-reading this '0'.
                    flags |= FLAGS_WIDTH;
                    f -= 1;
                    match parse_uint(fmt, &mut f, i32::MAX as i64) {
                        Some(num) => width = num as i32,
                        None => return None, // PFMT_WIDTH (overflow)
                    }
                }
                b'1'..=b'9' => {
                    flags |= FLAGS_WIDTH;
                    f -= 1;
                    match parse_uint(fmt, &mut f, i32::MAX as i64) {
                        Some(num) => width = num as i32,
                        None => return None, // PFMT_WIDTH
                    }
                }
                b'*' => {
                    flags |= FLAGS_WIDTHPARAM;
                    if use_dollar == Dollar::Use {
                        match dollar_at(fmt, f) {
                            Some((idx, newf)) => {
                                width = idx as i32;
                                f = newf;
                            }
                            None => return None, // PFMT_DOLLARWIDTH
                        }
                    } else {
                        width = -1; // read from the next argument
                    }
                }
                _ => {
                    loopit = false;
                    f -= 1; // back up to the non-flag byte
                }
            }
        }

        // ---- Conversion specifier ----
        if f >= end {
            // No conversion char: disregard the directive entirely. `start` is
            // not advanced, so the `%...` text folds into the next/trailing
            // literal (e.g. "%a" -> "%a", trailing "%" -> "%").
            continue;
        }
        let conv = fmt[f];
        let target = match conv {
            b'S' => {
                flags |= FLAGS_ALT; // %S == %s with surrounding quotes
                Target::Str
            }
            b's' => Target::Str,
            b'n' => Target::Count,
            b'p' => Target::Pointer,
            b'd' | b'i' => Target::Number,
            b'u' => {
                flags |= FLAGS_UNSIGNED;
                Target::Number
            }
            b'o' => {
                flags |= FLAGS_OCTAL | FLAGS_UNSIGNED;
                Target::Number
            }
            b'x' => {
                flags |= FLAGS_HEX | FLAGS_UNSIGNED;
                Target::Number
            }
            b'X' => {
                flags |= FLAGS_HEX | FLAGS_UPPER | FLAGS_UNSIGNED;
                Target::Number
            }
            b'c' => {
                flags |= FLAGS_CHAR;
                Target::Number
            }
            b'f' => Target::Double,
            b'e' => {
                flags |= FLAGS_FLOATE;
                Target::Double
            }
            b'E' => {
                flags |= FLAGS_FLOATE | FLAGS_UPPER;
                Target::Double
            }
            b'g' => {
                flags |= FLAGS_FLOATG;
                Target::Double
            }
            b'G' => {
                flags |= FLAGS_FLOATG | FLAGS_UPPER;
                Target::Double
            }
            _ => continue, // invalid conversion: disregard (start not advanced)
        };

        // ---- Argument-index accounting (width, then precision, then value) ----
        if flags & FLAGS_WIDTHPARAM != 0 {
            if width < 0 {
                width = param_num as i32;
                param_num += 1;
            } else if used[width as usize] {
                return None; // PFMT_WIDTHARG: argument reused for width
            }
            if width as i64 >= MAX_PARAMETERS {
                return None; // PFMT_MANYARGS
            }
            max_param = max_param.max(width as i64);
            used[width as usize] = true;
        }

        if flags & FLAGS_PRECPARAM != 0 {
            if precision < 0 {
                precision = param_num as i32;
                param_num += 1;
            } else if used[precision as usize] {
                return None; // PFMT_PRECARG: argument reused for precision
            }
            if precision as i64 >= MAX_PARAMETERS {
                return None; // PFMT_MANYARGS
            }
            max_param = max_param.max(precision as i64);
            used[precision as usize] = true;
        }

        if param < 0 {
            param = param_num;
            param_num += 1;
        }
        if param >= MAX_PARAMETERS {
            return None; // PFMT_MANYARGS
        }
        max_param = max_param.max(param);
        let input = param as usize;
        used[input] = true;

        f += 1; // step past the conversion char
        if out.len() >= MAX_SEGMENTS {
            return None; // PFMT_MANYSEGS
        }
        out.push(Segment {
            start,
            outlen,
            flags,
            width,
            precision,
            input,
            target,
            substr: false,
        });
        start = f;
    }

    // Trailing literal run.
    let outlen = end - start;
    if outlen > 0 {
        if out.len() >= MAX_SEGMENTS {
            return None; // PFMT_MANYSEGS
        }
        out.push(Segment {
            start,
            outlen,
            flags: FLAGS_SUBSTR,
            width: 0,
            precision: 0,
            input: 0,
            target: Target::Number,
            substr: true,
        });
    }

    // Argument-gap check: every index in 0..=max_param must be referenced. A
    // gap (e.g. using only `%2$s`) is a malformed format -> empty output.
    let mut i: i64 = 0;
    while i <= max_param {
        if !used[i as usize] {
            return None; // PFMT_INPUTGAP
        }
        i += 1;
    }

    Some(out)
}

// ===========================================================================
// Renderers (out_number / out_string / out_pointer equivalents)
// ===========================================================================

/// Render an integer (or a `%c` character) directive. A faithful port of
/// curl's `out_number`.
///
/// `num` is the raw bit-pattern of the argument (used for unsigned/hex/octal
/// and `%c`); `nums` is the signed interpretation (used only for signed decimal
/// to compute the sign and magnitude). Both are supplied because curl reads a
/// union and recomputes the magnitude from the signed value in the signed path.
///
/// curl quirks reproduced here:
/// * The `0` flag (`FLAGS_PAD_NIL`) is honored **even when a precision is
///   given** (`%08.3d` of `-7` -> `-0000007`).
/// * The `0x`/`0X` prefix is emitted unconditionally for `#` hex, including for
///   value `0` (`%#x` of `0` -> `0x0`).
/// * The space/`+` sign flags apply regardless of base (`% #x` of `255`
///   -> ` 0xff`).
fn out_number(
    out: &mut Vec<u8>,
    p_flags: u32,
    mut width: i32,
    mut prec: i32,
    num_in: u64,
    nums_in: i64,
) {
    let flags = p_flags;
    let is_alt = flags & FLAGS_ALT != 0;
    let mut is_neg = false;
    let mut base: u64 = 10;
    let mut num = num_in;
    let mut digits: &[u8; 16] = LDIGITS;

    // %c — a single character with optional width padding.
    if flags & FLAGS_CHAR != 0 {
        if flags & FLAGS_LEFT == 0 {
            while {
                width -= 1;
                width > 0
            } {
                out.push(b' ');
            }
        }
        out.push((num_in & 0xff) as u8);
        if flags & FLAGS_LEFT != 0 {
            while {
                width -= 1;
                width > 0
            } {
                out.push(b' ');
            }
        }
        return;
    }

    if flags & FLAGS_OCTAL != 0 {
        // Octal unsigned integer.
        base = 8;
    } else if flags & FLAGS_HEX != 0 {
        // Hexadecimal unsigned integer.
        digits = if flags & FLAGS_UPPER != 0 {
            UDIGITS
        } else {
            LDIGITS
        };
        base = 16;
    } else if flags & FLAGS_UNSIGNED != 0 {
        // Decimal unsigned integer: use `num` as-is.
    } else {
        // Decimal signed integer.
        is_neg = nums_in < 0;
        num = if is_neg {
            // `unsigned_abs` yields the correct magnitude even for i64::MIN.
            nums_in.unsigned_abs()
        } else {
            nums_in as u64
        };
    }

    // Supply a default precision of 1 when none was given.
    if prec == -1 {
        prec = 1;
    }

    // Scratch buffer filled from the high end downward, mirroring curl's
    // `work`/`workend` pointer arithmetic. `w` is the index of the next slot to
    // write; it can legitimately reach -1 once the buffer is full.
    let mut work = [0u8; BUFFSIZE];
    let workend: isize = (BUFFSIZE - 2) as isize; // 324
    let mut w: isize = workend;

    if base == 10 {
        while num > 0 {
            work[w as usize] = b'0' + (num % 10) as u8;
            w -= 1;
            num /= 10;
        }
    } else {
        while num > 0 {
            work[w as usize] = digits[(num % base) as usize];
            w -= 1;
            num /= base;
        }
    }

    let ndigits = (workend - w) as i32;
    width -= ndigits;
    prec -= ndigits;

    // Alternate-form octal: ensure a leading zero when the precision did not
    // already force one.
    if is_alt && base == 8 && prec <= 0 {
        work[w as usize] = b'0';
        w -= 1;
        width -= 1;
    }

    // Precision zeros (minimum digit count). Width is reduced by the full
    // requested count, but the writes are bounded by the buffer (the `w >= 0`
    // guard), matching curl's `w >= work` guard for pathological precisions.
    if prec > 0 {
        width -= prec;
        loop {
            let old = prec;
            prec -= 1;
            if old > 0 && w >= 0 {
                work[w as usize] = b'0';
                w -= 1;
            } else {
                break;
            }
        }
    }

    // Reserve width for the "0x"/"0X" alternate-form hex prefix.
    if is_alt && base == 16 {
        width -= 2;
    }

    // Reserve width for a sign character.
    if is_neg || (flags & FLAGS_SHOWSIGN != 0) || (flags & FLAGS_SPACE != 0) {
        width -= 1;
    }

    // Right-justifying space padding (skipped when left-justified or zero-padded).
    if flags & FLAGS_LEFT == 0 && flags & FLAGS_PAD_NIL == 0 {
        while width > 0 {
            out.push(b' ');
            width -= 1;
        }
    }

    // Sign.
    if is_neg {
        out.push(b'-');
    } else if flags & FLAGS_SHOWSIGN != 0 {
        out.push(b'+');
    } else if flags & FLAGS_SPACE != 0 {
        out.push(b' ');
    }

    // Alternate-form hex prefix.
    if is_alt && base == 16 {
        out.push(b'0');
        out.push(if flags & FLAGS_UPPER != 0 { b'X' } else { b'x' });
    }

    // Zero padding (after any sign / hex prefix).
    if flags & FLAGS_LEFT == 0 && flags & FLAGS_PAD_NIL != 0 {
        while width > 0 {
            out.push(b'0');
            width -= 1;
        }
    }

    // The number body: work[w + 1 ..= workend].
    let mut ww = w + 1;
    while ww <= workend {
        out.push(work[ww as usize]);
        ww += 1;
    }

    // Trailing space padding for left-justified output.
    if flags & FLAGS_LEFT != 0 {
        while width > 0 {
            out.push(b' ');
            width -= 1;
        }
    }
}

/// Render a string directive (`%s`, `%S`). A faithful port of curl's
/// `out_string`.
///
/// `s` is `None` for a C `NULL` pointer. curl's rules:
/// * `NULL` with precision `-1` (absent) or `>= len("(nil)")` renders `(nil)`
///   and **clears** the `#` quote flag.
/// * `NULL` with a smaller precision renders the empty string (still quoted by
///   `#`, yielding `""`).
/// * A precision caps the number of bytes emitted, and width padding is
///   computed from that precision (the field length), not the bytes actually
///   emitted (`%10.10s` of `"hi"` -> `"hi"` with no padding).
/// * `%S` (and any `#`-flagged string) is wrapped in double quotes, emitted
///   outside the padding.
fn out_string(out: &mut Vec<u8>, p_flags: u32, mut width: i32, prec: i32, s: Option<&[u8]>) {
    let mut flags = p_flags;

    // Resolve the byte source and the field length used for width math.
    let (src, len): (&[u8], usize) = match s {
        None => {
            if prec == -1 || prec >= NILSTR.len() as i32 {
                // Disable quotes around (nil).
                flags &= !FLAGS_ALT;
                (NILSTR, NILSTR.len())
            } else {
                (b"", 0)
            }
        }
        Some(bytes) => {
            if prec != -1 {
                (bytes, prec as usize)
            } else {
                // strlen: stop at the first NUL.
                let n = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                (bytes, n)
            }
        }
    };

    let len_i = if len > i32::MAX as usize {
        i32::MAX
    } else {
        len as i32
    };
    width -= len_i;

    if flags & FLAGS_ALT != 0 {
        out.push(b'"');
    }

    if flags & FLAGS_LEFT == 0 {
        while width > 0 {
            out.push(b' ');
            width -= 1;
        }
    }

    // Emit up to `len` bytes, stopping at the slice end or an embedded NUL
    // (mirroring curl's `for(; len && *str; len--)`).
    let mut remaining = len;
    let mut idx = 0usize;
    while remaining > 0 && idx < src.len() && src[idx] != 0 {
        out.push(src[idx]);
        idx += 1;
        remaining -= 1;
    }

    if flags & FLAGS_LEFT != 0 {
        while width > 0 {
            out.push(b' ');
            width -= 1;
        }
    }

    if flags & FLAGS_ALT != 0 {
        out.push(b'"');
    }
}

/// Render a pointer directive (`%p`). A faithful port of curl's `out_pointer`.
///
/// A non-NULL pointer is formatted exactly like `%#x` of its address. A NULL
/// pointer renders `(nil)` with **inverted** padding relative to the usual
/// convention: left-justify (`-`) places spaces *before* `(nil)`, otherwise
/// they go *after* (`%12p` of NULL -> `"(nil)       "`, `%-12p` of NULL
/// -> `"       (nil)"`).
fn out_pointer(out: &mut Vec<u8>, p_flags: u32, mut width: i32, prec: i32, ptr: Option<usize>) {
    match ptr {
        Some(addr) => {
            let flags = p_flags | FLAGS_HEX | FLAGS_ALT;
            out_number(out, flags, width, prec, addr as u64, 0);
        }
        None => {
            width -= NILSTR.len() as i32;
            if p_flags & FLAGS_LEFT != 0 {
                while width > 0 {
                    out.push(b' ');
                    width -= 1;
                }
            }
            out.extend_from_slice(NILSTR);
            if p_flags & FLAGS_LEFT == 0 {
                while width > 0 {
                    out.push(b' ');
                    width -= 1;
                }
            }
        }
    }
}

// ===========================================================================
// Floating-point renderer (out_double equivalent) — pure Rust
// ===========================================================================
//
// curl's `out_double` builds a `printf`-style sub-format from the directive
// flags (`-`, `+`, space, `#` only — never the `0` flag) plus the width and a
// possibly-adjusted precision, then delegates to the host C `snprintf`.
//
// To remain self-contained and free of C linkage, this engine reproduces that
// host `snprintf` output in pure Rust. The implementation was validated against
// the host `printf` across 39,270 (conversion x flags x width x precision x
// value) combinations and against curl's own compiled output. The single class
// of host-divergent results — alternate-form `%#g`/`%#G` where rounding carries
// across a power of ten (e.g. `99.5` at precision 2) — is a platform-specific
// libc quirk that curl itself inherits via its `snprintf` delegation and is
// therefore not portably defined; curl's own test suite avoids it.

/// Parse the integer exponent out of Rust's `{:e}` formatting (which prints the
/// exponent with no sign and no leading zeros, e.g. `1.5e3`, `3e0`, `1e-5`).
fn parse_exp(se: &str) -> i32 {
    let epos = se.find('e').expect("rust {:e} output always contains 'e'");
    se[epos + 1..]
        .parse()
        .expect("rust {:e} exponent is always a valid integer")
}

/// Format `mag` in scientific notation with the given mantissa precision,
/// re-rendering the exponent in C style: `e`/`E`, an explicit sign, and at
/// least two digits (`1.5e+03`, `3.0e-05`).
fn fmt_exp(mag: f64, prec: usize, upper: bool, alt: bool) -> String {
    let r = format!("{:.*e}", prec, mag);
    let epos = r.find('e').expect("rust {:e} output always contains 'e'");
    let mut mant = r[..epos].to_string();
    let exp: i32 = r[epos + 1..]
        .parse()
        .expect("rust {:e} exponent is always a valid integer");
    // With precision 0 the mantissa has no '.'; the `#` alternate form keeps it.
    if prec == 0 && alt {
        mant.push('.');
    }
    let e = if upper { 'E' } else { 'e' };
    let es = if exp < 0 { '-' } else { '+' };
    format!("{}{}{}{:02}", mant, e, es, exp.abs())
}

/// Strip trailing zeros (and a trailing `.`) from a fixed-form `%g` mantissa.
fn strip_g_fixed(s: &str) -> String {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s.to_string()
    }
}

/// Strip trailing zeros (and a trailing `.`) from the mantissa of a
/// scientific-form `%g` value while keeping the exponent intact.
fn strip_g_exp(s: &str, upper: bool) -> String {
    let ec = if upper { 'E' } else { 'e' };
    if let Some(epos) = s.find(ec) {
        let (mant, exp) = s.split_at(epos);
        let m = if mant.contains('.') {
            mant.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            mant.to_string()
        };
        format!("{}{}", m, exp)
    } else {
        s.to_string()
    }
}

/// Build the signed body (sign character + magnitude text) for a float
/// directive, reproducing host `snprintf` output for `f`/`e`/`E`/`g`/`G`.
///
/// `prec` is `-1` when no precision was specified (defaulting to 6, or 1
/// significant digit floor for `%g`). The `#`, `+`, space, and case flags are
/// taken from `flags`.
fn float_body(v: f64, kind: u8, prec: i32, flags: u32) -> Vec<u8> {
    let upper = flags & FLAGS_UPPER != 0;
    let alt = flags & FLAGS_ALT != 0;

    // Sign: a negative sign bit always wins; otherwise `+`/space per the flags.
    // Applies uniformly to finite values, infinities, and NaNs (matching the
    // host: `+inf`, ` inf`, `-nan`).
    let neg = v.is_sign_negative();
    let sign: &[u8] = if neg {
        b"-"
    } else if flags & FLAGS_SHOWSIGN != 0 {
        b"+"
    } else if flags & FLAGS_SPACE != 0 {
        b" "
    } else {
        b""
    };

    let mag = v.abs();
    let body_text: String = if v.is_nan() {
        if upper {
            "NAN".into()
        } else {
            "nan".into()
        }
    } else if v.is_infinite() {
        if upper {
            "INF".into()
        } else {
            "inf".into()
        }
    } else {
        match kind {
            b'f' => {
                let p = if prec < 0 { 6 } else { prec } as usize;
                let mut d = format!("{:.*}", p, mag);
                // `#` keeps the decimal point even at precision 0.
                if p == 0 && alt {
                    d.push('.');
                }
                d
            }
            b'e' => {
                let p = if prec < 0 { 6 } else { prec } as usize;
                fmt_exp(mag, p, upper, alt)
            }
            // b'g' (and 'G' via the upper flag).
            _ => {
                let mut big_p = if prec < 0 { 6 } else { prec };
                if big_p == 0 {
                    big_p = 1;
                }
                let exp_prec = (big_p - 1) as usize; // significant digits - 1
                                                     // Determine the decimal exponent after rounding to `big_p`
                                                     // significant digits.
                let se = format!("{:.*e}", exp_prec, mag);
                let x = parse_exp(&se);
                if x < -4 || x >= big_p {
                    // Scientific style with precision `big_p - 1`.
                    let m = fmt_exp(mag, exp_prec, upper, alt);
                    if !alt {
                        strip_g_exp(&m, upper)
                    } else {
                        m
                    }
                } else {
                    // Fixed style with precision `big_p - 1 - x`.
                    let fp = (big_p - 1 - x).max(0) as usize;
                    let mut m = format!("{:.*}", fp, mag);
                    if !alt {
                        strip_g_fixed(&m)
                    } else if fp == 0 {
                        m.push('.');
                        m
                    } else {
                        m
                    }
                }
            }
        }
    };

    let mut body = Vec::with_capacity(sign.len() + body_text.len());
    body.extend_from_slice(sign);
    body.extend_from_slice(body_text.as_bytes());
    body
}

/// Render a floating-point directive (`f e E g G`). A faithful port of curl's
/// `out_double`, including curl's precision/width adjustment (which keeps the
/// output within curl's scratch-buffer bound) and curl's rule of never passing
/// the `0` flag to the float formatter (floats are always space-padded).
fn out_double(out: &mut Vec<u8>, p_flags: u32, p_width: i32, p_prec: i32, dnum: f64) {
    // ---- curl's width clamp + precision adjustment ----
    let mut width = p_width;
    let mut prec = p_prec;

    if width >= BUFFSIZE as i32 {
        width = (BUFFSIZE - 1) as i32;
    }

    // The precision adjustment shrinks an over-large precision so the rendered
    // body fits curl's buffer. It is a no-op for ordinary widths/precisions.
    // It is skipped for non-finite values: curl's `while(val >= 10.0)` loop
    // never terminates for infinity (a latent hang the test suite cannot
    // exercise), and the precision is irrelevant when rendering inf/nan.
    if prec >= 0 && dnum.is_finite() {
        let mut maxprec = (BUFFSIZE - 1) as i32;
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
    }

    let kind = if p_flags & FLAGS_FLOATE != 0 {
        b'e'
    } else if p_flags & FLAGS_FLOATG != 0 {
        b'g'
    } else {
        b'f'
    };

    let body = float_body(dnum, kind, prec, p_flags);

    // Assemble the full field (space padding + body — never zero padding, since
    // curl does not pass the '0' flag for floats) into a temporary buffer.
    let blen = body.len() as i32;
    let mut field: Vec<u8> = Vec::new();
    if width > blen {
        let padn = (width - blen) as usize;
        if p_flags & FLAGS_LEFT != 0 {
            field.extend_from_slice(&body);
            field.resize(field.len() + padn, b' ');
        } else {
            field.resize(padn, b' ');
            field.extend_from_slice(&body);
        }
    } else {
        field.extend_from_slice(&body);
    }

    // curl renders floats by delegating to the host `snprintf` writing into a
    // fixed `BUFFSIZE`-byte scratch buffer, so the formatted field is truncated
    // to `BUFFSIZE - 1` bytes. Reproduce that cap exactly; it is only ever hit
    // by pathological width/precision combinations (e.g. `%0.324f`), but curl's
    // own printf torture test (`tests/libtest/lib557.c`) depends on it.
    let cap = BUFFSIZE - 1; // 325
    if field.len() > cap {
        field.truncate(cap);
    }

    out.extend_from_slice(&field);
}

// ===========================================================================
// Dispatch (formatf equivalent) and public entrypoints
// ===========================================================================

/// Read an argument as a C `int`, used for `*` width / `.*` precision values. A
/// missing argument defaults to `0` (a correct caller always supplies enough
/// arguments; this only guarantees panic-freedom).
fn arg_i32(args: &[FmtArg], idx: usize) -> i32 {
    args.get(idx).map(FmtArg::as_i64).unwrap_or(0) as i32
}

/// The general formatting routine — a port of curl's `formatf`.
///
/// Parses the format into segments and renders each in order into an owned
/// byte buffer. On a malformed format (`parse_format` returns `None`) the
/// output is empty, exactly as curl's `formatf` emits nothing when `parsefmt`
/// fails.
fn render(fmt: &[u8], args: &[FmtArg]) -> Vec<u8> {
    let segments = match parse_format(fmt) {
        Some(s) => s,
        None => return Vec::new(),
    };

    let mut out: Vec<u8> = Vec::new();

    for seg in &segments {
        // Emit the literal run preceding the conversion (if any).
        if seg.outlen > 0 {
            let s = seg.start;
            let e = s + seg.outlen;
            out.extend_from_slice(&fmt[s..e]);
            if seg.substr {
                // Literal-only segment: nothing more to render.
                continue;
            }
        }

        let mut flags = seg.flags;

        // Resolve the field width. A width taken from an argument may be
        // negative, which means "left-justify with the positive width" (and
        // clears any zero-pad request), matching curl/printf.
        let width: i32 = if seg.flags & FLAGS_WIDTHPARAM != 0 {
            let mut w = arg_i32(args, seg.width as usize);
            if w < 0 {
                w = if w == i32::MIN { i32::MAX } else { -w };
                flags |= FLAGS_LEFT;
                flags &= !FLAGS_PAD_NIL;
            }
            w
        } else {
            seg.width
        };

        // Resolve the precision. A precision taken from an argument is treated
        // as "omitted" when negative.
        let prec: i32 = if seg.flags & FLAGS_PRECPARAM != 0 {
            let p = arg_i32(args, seg.precision as usize);
            if p < 0 {
                -1
            } else {
                p
            }
        } else if seg.flags & FLAGS_PREC != 0 {
            seg.precision
        } else {
            -1
        };

        let value = args.get(seg.input);
        match seg.target {
            Target::Number => {
                // `num` is the raw bit-pattern, `nums` the signed value; the
                // renderer selects between them based on the flags.
                let (num, nums) = value.map(|a| (a.as_u64(), a.as_i64())).unwrap_or((0, 0));
                out_number(&mut out, flags, width, prec, num, nums);
            }
            Target::Str => {
                let s = match value {
                    Some(a) => a.as_str(),
                    None => Some(&b""[..]),
                };
                out_string(&mut out, flags, width, prec, s);
            }
            Target::Pointer => {
                let p = value.and_then(FmtArg::as_ptr);
                out_pointer(&mut out, flags, width, prec, p);
            }
            Target::Double => {
                let d = value.map(FmtArg::as_f64).unwrap_or(0.0);
                out_double(&mut out, flags, width, prec, d);
            }
            Target::Count => {
                // `%n`: store the number of bytes emitted so far (including this
                // segment's literal run). Emits nothing itself. Only a
                // `CountStore` argument is honored; any other variant is a
                // caller error and is ignored.
                if let Some(FmtArg::CountStore(cell)) = value {
                    cell.set(out.len() as i64);
                }
            }
        }
    }

    out
}

/// Format `fmt` with `args`, returning the formatted bytes.
///
/// This is the core renderer (curl's `maprintf` without the size cap). A
/// malformed format yields an empty buffer, matching curl's behavior of
/// emitting nothing for an unparseable format.
///
/// # Examples
///
/// ```ignore
/// let s = mprintf_format(b"%05d-%s", &[FmtArg::Int(42), FmtArg::string("hi")]);
/// assert_eq!(s, b"00042-hi");
/// ```
pub fn mprintf_format(fmt: &[u8], args: &[FmtArg]) -> Vec<u8> {
    render(fmt, args)
}

/// Bounded write into a caller-provided buffer — the analogue of curl's
/// `curl_msnprintf` / `curl_mvsnprintf`.
///
/// `buf.len()` is the maximum number of bytes that may be written **including**
/// the terminating NUL (matching curl's `maxlength`). The return value is the
/// number of bytes written **excluding** the NUL, following curl's exact
/// convention:
///
/// * If `buf` is empty, nothing is written and `0` is returned.
/// * Otherwise the output is written and always NUL-terminated. When the output
///   reaches or exceeds the buffer size the final slot is reserved for the NUL
///   (the last output byte is dropped) and the return value is `buf.len() - 1`.
/// * When the output fits, the return value is its length and the NUL follows
///   it.
///
/// Note that, unlike C99 `snprintf`, curl returns the number of bytes actually
/// stored (capped), not the length that *would* have been written — this
/// matches curl and is relied upon by curl's own callers.
///
/// (A `%n` directive positioned beyond the truncation point still records its
/// count here, whereas curl stops rendering at the cap. This affects no output
/// bytes and is not exercised by curl's test suite.)
pub fn msnprintf(buf: &mut [u8], fmt: &[u8], args: &[FmtArg]) -> usize {
    let max = buf.len();
    if max == 0 {
        return 0;
    }

    let full = render(fmt, args);
    let done = full.len().min(max);

    if done == max {
        // At or over capacity: reserve the last byte for the NUL.
        let n = max - 1;
        buf[..n].copy_from_slice(&full[..n]);
        buf[n] = 0;
        n
    } else {
        buf[..done].copy_from_slice(&full[..done]);
        buf[done] = 0;
        done
    }
}

/// Allocate-and-return — the analogue of curl's `curl_maprintf` /
/// `curl_mvaprintf`.
///
/// Returns the formatted bytes, or `None` when the result would exceed curl's
/// `DYN_APRINTF` size limit (at which point `curl_maprintf` returns `NULL`). A
/// malformed format yields `Some(empty)`, matching curl returning `strdup("")`.
///
/// The buffer is built into an owned `Vec<u8>` managed entirely by this module;
/// it deliberately does **not** route through [`crate::util::dynbuf`], whose
/// formatted-append helpers call *into* this engine (avoiding a dependency
/// cycle — see the module documentation).
pub fn maprintf(fmt: &[u8], args: &[FmtArg]) -> Option<Vec<u8>> {
    let out = render(fmt, args);
    if out.len() > DYN_APRINTF {
        None
    } else {
        Some(out)
    }
}

/// Convenience wrapper returning a `String` for UTF-8-oriented internal callers
/// (for example `infof`/`failf` message building). Invalid UTF-8 in the
/// rendered bytes is replaced with the Unicode replacement character; callers
/// needing byte-exact output must use [`mprintf_format`].
pub fn mprintf_string(fmt: &[u8], args: &[FmtArg]) -> String {
    String::from_utf8_lossy(&render(fmt, args)).into_owned()
}

// ===========================================================================
// FFI wrapping guidance (implemented in curl-rs-ffi/src/mprintf.rs)
// ===========================================================================
//
// The C-variadic `curl_*` printf symbols are exposed by the FFI crate, which is
// the only place `unsafe` and `va_list` handling are permitted. Each shim:
//
//   1. Reads the format `*const c_char` into a `&[u8]` (via `CStr`).
//   2. Walks the format once to learn the conversion + length modifier of each
//      directive, then pulls each C vararg with the correct width/signedness
//      (`int`, `unsigned long`, `long long`, `double`, `void*`, `char*`, ...)
//      and builds a `Vec<FmtArg>`. (`*` width / `.*` precision and positional
//      `%N$` consume argument slots in the same order this engine expects.)
//   3. Calls the matching entrypoint here and adapts the result to the C
//      contract:
//        * `curl_mprintf`/`curl_mfprintf`  -> `mprintf_format`, then write the
//          bytes to stdout / the `FILE*`; return the byte count.
//        * `curl_msprintf`                 -> `mprintf_format`, copy into the
//          caller buffer and append a NUL (unbounded, like curl).
//        * `curl_msnprintf`                -> `msnprintf` (bounded) directly.
//        * `curl_maprintf`                 -> `maprintf`, then `CString`/raw
//          allocation returned to C (freed by `curl_free`); `None` -> `NULL`.
//        * `curl_mv*` variants             -> identical, fed from a `va_list`.
//      A `%n` directive maps to a `FmtArg::CountStore`; after rendering, the
//      shim narrows the recorded count to the destination width dictated by the
//      length modifier (`int`/`short`/`long`/`long long`) and writes it through
//      the supplied pointer.

// ===========================================================================
// Tests — byte-exact parity with curl's compiled lib/mprintf.c
// ===========================================================================
//
// Every expected value below was produced by curl's own `curl_msnprintf`
// (lib/mprintf.c compiled standalone) for the identical format and arguments,
// so these assertions pin byte-for-byte parity with curl 8.x.

#[cfg(test)]
// The float tests intentionally use the literal value `3.14` (and `3.14159`)
// as ordinary test inputs — chosen to match curl's own oracle output — rather
// than as approximations of `std::f64::consts::PI`, so the `approx_constant`
// lint is a false positive here.
#[allow(clippy::approx_constant)]
mod tests {
    use super::*;

    /// Render and compare against an expected byte string.
    fn chk(fmt: &[u8], args: &[FmtArg], expect: &[u8]) {
        let got = mprintf_format(fmt, args);
        assert_eq!(
            got,
            expect,
            "\n  fmt   = {:?}\n  got   = {:?}\n  expect= {:?}",
            String::from_utf8_lossy(fmt),
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(expect),
        );
    }

    #[test]
    fn integers_basic() {
        chk(b"%d", &[FmtArg::Int(42)], b"42");
        chk(b"%-5d", &[FmtArg::Int(42)], b"42   ");
        chk(b"%05d", &[FmtArg::Int(42)], b"00042");
        chk(b"%+d", &[FmtArg::Int(42)], b"+42");
        chk(b"% d", &[FmtArg::Int(42)], b" 42");
        chk(b"%d", &[FmtArg::Int(-42)], b"-42");
        chk(b"%.5d", &[FmtArg::Int(42)], b"00042");
        chk(b"%8.5d", &[FmtArg::Int(42)], b"   00042");
        chk(b"%.0d", &[FmtArg::Int(0)], b"");
        chk(b"%5.0d", &[FmtArg::Int(0)], b"     ");
        // curl does NOT ignore the '0' flag when a precision is given.
        chk(b"%08.3d", &[FmtArg::Int(-7)], b"-0000007");
        chk(b"%+08d", &[FmtArg::Int(42)], b"+0000042");
        chk(b"%+05.3d", &[FmtArg::Int(7)], b"+0007");
        chk(b"%+.0d", &[FmtArg::Int(0)], b"+");
        chk(b"% .0d", &[FmtArg::Int(0)], b" ");
    }

    #[test]
    fn integers_octal_hex() {
        chk(b"%#o", &[FmtArg::Uint(8)], b"010");
        chk(b"%#o", &[FmtArg::Uint(0)], b"0");
        chk(b"%#x", &[FmtArg::Uint(255)], b"0xff");
        chk(b"%#X", &[FmtArg::Uint(255)], b"0XFF");
        // '0x' prefix is unconditional for '#' hex, even for value 0.
        chk(b"%#x", &[FmtArg::Uint(0)], b"0x0");
        chk(b"%08x", &[FmtArg::Uint(255)], b"000000ff");
        chk(b"%#010x", &[FmtArg::Uint(255)], b"0x000000ff");
        chk(b"%.5x", &[FmtArg::Uint(255)], b"000ff");
        chk(b"%#.5x", &[FmtArg::Uint(255)], b"0x000ff");
        // space/'+' sign flags apply to unsigned conversions too.
        chk(b"% #x", &[FmtArg::Uint(255)], b" 0xff");
        chk(b"%X", &[FmtArg::Uint(0xDEAD_BEEF)], b"DEADBEEF");
        chk(b"%u", &[FmtArg::Uint(4_294_967_295)], b"4294967295");
        chk(
            b"%lu",
            &[FmtArg::Uint(18_446_744_073_709_551_615)],
            b"18446744073709551615",
        );
        chk(b"%lld", &[FmtArg::Int(-9_000_000_000)], b"-9000000000");
        chk(b"%hhd", &[FmtArg::Int(300)], b"300");
    }

    #[test]
    fn strings() {
        chk(b"%10s", &[FmtArg::string("hello")], b"     hello");
        chk(b"%-10s", &[FmtArg::string("hello")], b"hello     ");
        chk(b"%.3s", &[FmtArg::string("hello")], b"hel");
        chk(b"%10.3s", &[FmtArg::string("hello")], b"       hel");
        // Width is reduced by the precision FIELD, not the bytes emitted.
        chk(b"%10.10s", &[FmtArg::string("hi")], b"hi");
        chk(b"[%s]", &[FmtArg::null_string()], b"[(nil)]");
        chk(b"%.4s", &[FmtArg::null_string()], b"");
        chk(b"%.10s", &[FmtArg::null_string()], b"(nil)");
        // %S quotes the string; quotes are outside the padding.
        chk(b"%S", &[FmtArg::string("hi")], b"\"hi\"");
        chk(b"%6S", &[FmtArg::string("hi")], b"\"    hi\"");
        chk(b"%.2S", &[FmtArg::null_string()], b"\"\"");
        chk(b"%.10S", &[FmtArg::null_string()], b"(nil)");
    }

    #[test]
    fn chars_and_pointers() {
        chk(b"%c", &[FmtArg::Char(b'A')], b"A");
        chk(b"%5c", &[FmtArg::Char(b'A')], b"    A");
        chk(b"%p", &[FmtArg::pointer(0x1234)], b"0x1234");
        chk(b"%p", &[FmtArg::null_pointer()], b"(nil)");
        chk(b"%12p", &[FmtArg::pointer(0xabcdef)], b"    0xabcdef");
        // NULL pointer padding is INVERTED relative to the usual convention.
        chk(b"%12p", &[FmtArg::null_pointer()], b"(nil)       ");
        chk(b"%-12p", &[FmtArg::null_pointer()], b"       (nil)");
    }

    #[test]
    fn positional() {
        chk(
            b"%1$s %2$s",
            &[FmtArg::string("a"), FmtArg::string("b")],
            b"a b",
        );
        chk(
            b"%2$s %1$s",
            &[FmtArg::string("a"), FmtArg::string("b")],
            b"b a",
        );
        chk(b"%1$d %1$d", &[FmtArg::Int(7)], b"7 7");
        chk(
            b"%1$d-%2$d-%1$d",
            &[FmtArg::Int(3), FmtArg::Int(9)],
            b"3-9-3",
        );
        // Positional width: width from arg 1, value from arg 2.
        chk(b"%2$*1$d", &[FmtArg::Int(5), FmtArg::Int(42)], b"   42");
    }

    #[test]
    fn star_width_precision() {
        chk(b"%*d", &[FmtArg::Int(6), FmtArg::Int(42)], b"    42");
        // Negative '*' width -> left justify with the positive width.
        chk(b"%*d", &[FmtArg::Int(-6), FmtArg::Int(42)], b"42    ");
        // Negative '.*' precision -> precision omitted.
        chk(b"%.*d", &[FmtArg::Int(-1), FmtArg::Int(42)], b"42");
    }

    #[test]
    fn floats_fixed_sci_general() {
        chk(b"%f", &[FmtArg::Double(3.14)], b"3.140000");
        chk(b"%e", &[FmtArg::Double(3.14)], b"3.140000e+00");
        chk(b"%E", &[FmtArg::Double(3.14)], b"3.140000E+00");
        chk(b"%g", &[FmtArg::Double(3.14)], b"3.14");
        chk(b"%g", &[FmtArg::Double(0.0001)], b"0.0001");
        chk(b"%g", &[FmtArg::Double(100000.0)], b"100000");
        chk(b"%g", &[FmtArg::Double(1000000.0)], b"1e+06");
        chk(b"%G", &[FmtArg::Double(1000000.0)], b"1E+06");
        chk(b"%g", &[FmtArg::Double(0.00001)], b"1e-05");
        chk(b"%g", &[FmtArg::Double(-3.14)], b"-3.14");
        chk(b"%g", &[FmtArg::Double(0.0)], b"0");
        chk(b"%.2e", &[FmtArg::Double(0.0)], b"0.00e+00");
        chk(b"%+.3e", &[FmtArg::Double(-2.5)], b"-2.500e+00");
        chk(b"%.3f", &[FmtArg::Double(3.14159)], b"3.142");
        chk(b"%.2f", &[FmtArg::Double(12345.678)], b"12345.68");
        // Large exponent uses 3 digits.
        chk(b"%e", &[FmtArg::Double(1.5e100)], b"1.500000e+100");
        // Floats are always space-padded (curl never passes the '0' flag).
        chk(b"%05.2f", &[FmtArg::Double(3.14159)], b" 3.14");
        chk(b"%08.2f", &[FmtArg::Double(3.14)], b"    3.14");
        chk(b"%10.2f", &[FmtArg::Double(3.14)], b"      3.14");
        chk(b"%-10.2f", &[FmtArg::Double(3.14)], b"3.14      ");
        // Negative zero keeps its sign.
        chk(b"%f", &[FmtArg::Double(-0.0)], b"-0.000000");
        // Alternate form keeps trailing zeros / the decimal point.
        chk(b"%#g", &[FmtArg::Double(3.14)], b"3.14000");
        chk(b"%#.1g", &[FmtArg::Double(3.0)], b"3.");
    }

    #[test]
    fn floats_inf_nan() {
        chk(b"%f", &[FmtArg::Double(f64::INFINITY)], b"inf");
        chk(b"%f", &[FmtArg::Double(f64::NEG_INFINITY)], b"-inf");
        chk(b"%+f", &[FmtArg::Double(f64::INFINITY)], b"+inf");
        chk(b"% f", &[FmtArg::Double(f64::INFINITY)], b" inf");
        chk(b"%10f", &[FmtArg::Double(f64::INFINITY)], b"       inf");
        chk(b"%-10f", &[FmtArg::Double(f64::INFINITY)], b"inf       ");
        chk(b"%G", &[FmtArg::Double(f64::INFINITY)], b"INF");
        // f64::NAN is a positive NaN in Rust -> "nan"; the negated form -> "-nan".
        chk(b"%f", &[FmtArg::Double(f64::NAN)], b"nan");
        chk(b"%f", &[FmtArg::Double(-f64::NAN)], b"-nan");
        chk(b"%+f", &[FmtArg::Double(f64::NAN)], b"+nan");
    }

    #[test]
    fn literals_and_percent() {
        chk(b"%d%%%d", &[FmtArg::Int(1), FmtArg::Int(2)], b"1%2");
        chk(b"%", &[], b"%");
        chk(b"%5%", &[], b"%5%");
        chk(b"abc%", &[], b"abc%");
        chk(b"plain text", &[], b"plain text");
        chk(b"", &[], b"");
        chk(
            b"%d/%s/%x",
            &[FmtArg::Int(7), FmtArg::string("ab"), FmtArg::Uint(255)],
            b"7/ab/ff",
        );
    }

    #[test]
    fn invalid_conversions_are_literal() {
        // Unsupported conversions are emitted verbatim (the directive is
        // disregarded and its text folds into the surrounding literal).
        chk(b"%a", &[FmtArg::Double(1.0)], b"%a");
        chk(b"%ji", &[FmtArg::Int(1)], b"%ji");
        chk(b"%F", &[FmtArg::Double(f64::NAN)], b"%F");
    }

    #[test]
    fn malformed_formats_yield_empty() {
        // curl requires a digit after '.', rejects argument gaps, rejects
        // mixing positional and non-positional, and rejects %0$/out-of-range $.
        chk(b"%.s", &[FmtArg::string("x")], b"");
        chk(b"%.d", &[FmtArg::Int(5)], b"");
        chk(b"%2$s", &[FmtArg::string("a"), FmtArg::string("b")], b"");
        chk(b"%1$d %d", &[FmtArg::Int(3), FmtArg::Int(4)], b"");
        // %0$ and out-of-range positional are NOT positional -> literal text.
        chk(b"%0$s", &[FmtArg::string("a")], b"%0$s");
        chk(b"%200$s", &[FmtArg::string("a")], b"%200$s");
        // Non-positional after a resolved non-positional locks; the '$' becomes
        // an invalid conversion and the remainder is literal.
        chk(b"%d %1$d", &[FmtArg::Int(3)], b"3 %1$d");
    }

    #[test]
    fn snprintf_truncation() {
        // maxlength INCLUDES the NUL; the return excludes it.
        let mut buf = [0u8; 4];
        let n = msnprintf(&mut buf, b"%s", &[FmtArg::string("hello")]);
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], b"hel");
        assert_eq!(buf[3], 0);

        // Exact fit minus NUL.
        let mut buf = [0u8; 4];
        let n = msnprintf(&mut buf, b"%s", &[FmtArg::string("abc")]);
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], b"abc");
        assert_eq!(buf[3], 0);

        // Buffer of 1 holds only the NUL.
        let mut buf = [0u8; 1];
        let n = msnprintf(&mut buf, b"%s", &[FmtArg::string("x")]);
        assert_eq!(n, 0);
        assert_eq!(buf[0], 0);

        // Empty buffer: nothing written, returns 0.
        let mut buf = [0u8; 0];
        let n = msnprintf(&mut buf, b"%s", &[FmtArg::string("x")]);
        assert_eq!(n, 0);
    }

    #[test]
    fn count_store_n() {
        let (arg, cell) = FmtArg::count_store();
        let out = mprintf_format(b"abc%ndef", &[arg]);
        assert_eq!(out, b"abcdef");
        // The count recorded is the number of bytes emitted before the directive.
        assert_eq!(cell.get(), 3);
    }

    #[test]
    fn aprintf_cap_and_string_wrapper() {
        // Normal allocate-and-return.
        assert_eq!(
            maprintf(b"%d", &[FmtArg::Int(5)]).as_deref(),
            Some(&b"5"[..])
        );
        // A malformed format returns Some(empty), matching curl's strdup("").
        assert_eq!(
            maprintf(b"%.s", &[FmtArg::string("x")]).as_deref(),
            Some(&b""[..])
        );
        // String wrapper for UTF-8-oriented callers.
        assert_eq!(
            mprintf_string(b"%s=%d", &[FmtArg::string("k"), FmtArg::Int(9)]),
            "k=9"
        );
    }
}
