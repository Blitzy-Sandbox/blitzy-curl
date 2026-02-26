//! `printf` family — Rust replacement for C `lib/mprintf.c`.
//!
//! Curl's bespoke `printf` engine (1,229 C lines) handles positional
//! arguments (`n$`), all standard C conversion specifiers, and length
//! modifiers. In idiomatic Rust most formatting uses `format!()` / `write!()`
//! directly, so this module exists primarily as an **FFI compatibility layer**
//! that the `curl-rs-ffi` crate wraps to expose the 11 `CURL_EXTERN`
//! printf-family symbols from `include/curl/mprintf.h`.
//!
//! # C Correspondence
//!
//! | Rust                     | C                          |
//! |--------------------------|----------------------------|
//! | [`curl_format()`]        | `curl_msnprintf()` core    |
//! | [`parse_format_string()`]| internal `parsefmt()`      |
//! | [`formatf()`]            | `formatf()`                |
//! | [`dyn_vprintf()`]        | `curlx_dyn_vprintf()`      |
//! | [`FormatArg`]            | `struct va_input` union    |
//! | [`FormatSegment`]        | `struct outsegment`        |
//!
//! # Design Notes
//!
//! The implementation parses a C-style format string into a sequence of
//! [`FormatSegment`] values (literal text or conversion specifications) and
//! then renders each segment against the supplied [`FormatArg`] slice. The
//! parser supports the full set of POSIX conversion specifiers used by curl,
//! including positional arguments (`%n$`), width/precision from arguments
//! (`*`/`.*`), and the curl-specific `%S` (quoted string).

use std::fmt::{self, Write as FmtWrite};
use std::io::{self, Write as IoWrite};

use crate::error::CurlError;
use crate::util::dynbuf::DynBuf;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Internal format-output buffer size (bytes).
///
/// Sized to accommodate the longest possible formatted number string
/// (negative `DBL_MAX` is 317 characters, plus sign and padding).
pub const BUFFSIZE: usize = 1024;

/// Maximum number of format arguments (matches C `MAX_PARAMETERS`).
pub const MAX_PARAMETERS: usize = 128;

/// Maximum number of parsed segments in a single format string.
pub const MAX_SEGMENTS: usize = 128;

/// Lower-case hex digit table (`0`–`9`, `a`–`f`).
pub const LOWER_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Upper-case hex digit table (`0`–`9`, `A`–`F`).
pub const UPPER_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

/// String emitted for null/nil pointers and missing string arguments.
const NIL_STR: &str = "(nil)";

// ---------------------------------------------------------------------------
// FormatArg
// ---------------------------------------------------------------------------

/// A single dynamically-typed argument that can be referenced by a format
/// string conversion specifier.
///
/// Mirrors the C `struct va_input` union. The FFI crate extracts values from
/// a C `va_list` into this enum before passing them to the safe formatting
/// functions.
#[derive(Debug, Clone)]
pub enum FormatArg {
    /// Signed integer (`%d`, `%i`, `%ld`, `%lld`).
    Int(i64),
    /// Unsigned integer (`%u`, `%o`, `%x`, `%X`, `%lu`, `%llu`).
    Uint(u64),
    /// Floating point (`%f`, `%e`, `%E`, `%g`, `%G`).
    Float(f64),
    /// String (`%s`, `%S`).
    Str(String),
    /// Raw pointer address (`%p`). Stored as `usize` to avoid `unsafe`.
    Ptr(usize),
    /// `curl_off_t` value (`%Od` / `%Ou` in curl).
    OffT(i64),
}

impl fmt::Display for FormatArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatArg::Int(v) => write!(f, "{v}"),
            FormatArg::Uint(v) => write!(f, "{v}"),
            FormatArg::Float(v) => write!(f, "{v}"),
            FormatArg::Str(v) => f.write_str(v),
            FormatArg::Ptr(v) => {
                if *v == 0 {
                    f.write_str(NIL_STR)
                } else {
                    write!(f, "0x{v:x}")
                }
            }
            FormatArg::OffT(v) => write!(f, "{v}"),
        }
    }
}

// ---------------------------------------------------------------------------
// MprintfError
// ---------------------------------------------------------------------------

/// Errors that can occur during format-string processing.
///
/// Maps to the C `MERR_*` constants in `curl_printf.h`:
/// - `MERR_OK`        (0) → [`MprintfError::Ok`]
/// - `MERR_MEM`       (1) → [`MprintfError::Mem`]
/// - `MERR_TOO_LARGE` (2) → [`MprintfError::TooLarge`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MprintfError {
    /// Success (no error). Maps to `MERR_OK`.
    Ok,
    /// Memory allocation failure. Maps to `MERR_MEM`.
    Mem,
    /// Output exceeds size limit. Maps to `MERR_TOO_LARGE`.
    TooLarge,
}

impl fmt::Display for MprintfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MprintfError::Ok => f.write_str("ok"),
            MprintfError::Mem => f.write_str("out of memory"),
            MprintfError::TooLarge => f.write_str("output too large"),
        }
    }
}

impl From<MprintfError> for CurlError {
    fn from(e: MprintfError) -> Self {
        match e {
            MprintfError::Ok => CurlError::Ok,
            MprintfError::Mem => CurlError::OutOfMemory,
            MprintfError::TooLarge => CurlError::TooLarge,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal format flags (matching C `FLAGS_*` constants from mprintf.c)
// ---------------------------------------------------------------------------

const FLAGS_SPACE: u32 = 1 << 0;
const FLAGS_SHOWSIGN: u32 = 1 << 1;
const FLAGS_LEFT: u32 = 1 << 2;
const FLAGS_ALT: u32 = 1 << 3;
#[allow(dead_code)]
const FLAGS_SHORT: u32 = 1 << 4;
#[allow(dead_code)]
const FLAGS_LONG: u32 = 1 << 5;
#[allow(dead_code)]
const FLAGS_LONGLONG: u32 = 1 << 6;
#[allow(dead_code)]
const FLAGS_LONGDOUBLE: u32 = 1 << 7;
const FLAGS_PAD_NIL: u32 = 1 << 8;
const FLAGS_UNSIGNED: u32 = 1 << 9;
const FLAGS_OCTAL: u32 = 1 << 10;
const FLAGS_HEX: u32 = 1 << 11;
const FLAGS_UPPER: u32 = 1 << 12;
#[allow(dead_code)]
const FLAGS_WIDTH: u32 = 1 << 13;
const FLAGS_WIDTHPARAM: u32 = 1 << 14;
const FLAGS_PREC: u32 = 1 << 15;
const FLAGS_PRECPARAM: u32 = 1 << 16;
const FLAGS_CHAR: u32 = 1 << 17;
const FLAGS_FLOATE: u32 = 1 << 18;
const FLAGS_FLOATG: u32 = 1 << 19;
const FLAGS_SUBSTR: u32 = 1 << 20;

// ---------------------------------------------------------------------------
// FormatSegment
// ---------------------------------------------------------------------------

/// One piece of a parsed format string — either a literal run of characters
/// or a conversion specification.
///
/// The fields inside the `Conversion` variant use the same semantic encoding
/// as the C `struct outsegment`:
/// - `flags` is a bitmask of internal `FLAGS_*` constants.
/// - `width` and `precision` are either literal values or (when
///   `FLAGS_WIDTHPARAM` / `FLAGS_PRECPARAM` is set) indices into the argument
///   array from which the value should be read at render time.
#[derive(Debug, Clone)]
pub enum FormatSegment {
    /// Verbatim text (no conversion).
    Literal(String),

    /// A `%`-conversion with all parsed metadata.
    Conversion {
        /// Internal format flags (combination of `FLAGS_*` bits).
        flags: u32,
        /// Field width (literal value or arg index when `FLAGS_WIDTHPARAM`).
        width: i32,
        /// Precision (literal value or arg index when `FLAGS_PRECPARAM`).
        /// A value of `-1` means "unset / use default".
        precision: i32,
        /// Conversion character (`d`, `s`, `x`, …).
        type_spec: char,
        /// Argument index (0-based).
        arg_index: usize,
    },
}

// ---------------------------------------------------------------------------
// Dollar-sign positional helper
// ---------------------------------------------------------------------------

/// Attempt to parse a `<digits>$` positional specifier starting at `pos`.
///
/// On success returns `Some((0-based_index, new_pos))`.
/// On failure returns `None` (the caller should rewind).
fn parse_dollar(chars: &[u8], pos: usize) -> Option<(usize, usize)> {
    let mut i = pos;
    if i >= chars.len() || !chars[i].is_ascii_digit() || chars[i] == b'0' {
        return None;
    }
    let mut n: usize = 0;
    while i < chars.len() && chars[i].is_ascii_digit() {
        n = n.saturating_mul(10).saturating_add((chars[i] - b'0') as usize);
        i += 1;
        if n > MAX_PARAMETERS {
            return None;
        }
    }
    if i < chars.len() && chars[i] == b'$' && n > 0 {
        Some((n - 1, i + 1)) // 1-based → 0-based
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Parser — parse_format_string
// ---------------------------------------------------------------------------

/// Parse a C-style `printf` format string into a vector of [`FormatSegment`]s.
///
/// Supports the full POSIX and curl-specific format specifier syntax:
/// - Positional arguments (`%1$d`, `%2$s`)
/// - Flag characters (`-`, `+`, ` `, `0`, `#`)
/// - Field width (literal number or `*` / `*n$` from argument)
/// - Precision (`.N`, `.*`, `.*n$`)
/// - Length modifiers (`h`, `hh`, `l`, `ll`, `L`, `z`, `q`, `O`)
/// - Conversion specifiers: `d`, `i`, `u`, `o`, `x`, `X`, `f`, `e`, `E`,
///   `g`, `G`, `c`, `s`, `S`, `p`, `n`, `%`
///
/// Returns at most [`MAX_SEGMENTS`] segments.  Returns an empty vector on
/// parse error (matching C `parsefmt()` returning non-zero).
pub fn parse_format_string(fmt: &str) -> Vec<FormatSegment> {
    let bytes = fmt.as_bytes();
    let len = bytes.len();
    let mut segments: Vec<FormatSegment> = Vec::new();
    let mut i: usize = 0;
    let mut param_num: usize = 0; // next sequential argument index
    let mut start: usize = 0; // start of the current literal run

    // Dollar-sign state: Unknown → Nope (no positional) or Use (positional).
    const DOLLAR_UNKNOWN: u8 = 0;
    const DOLLAR_NOPE: u8 = 1;
    const DOLLAR_USE: u8 = 2;
    let mut use_dollar: u8 = DOLLAR_UNKNOWN;

    while i < len {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }

        // --- Found a '%' ---------------------------------------------------

        // Emit any preceding literal text.
        let literal_len = i - start;
        i += 1; // skip the '%'

        if i >= len {
            // Trailing '%' at end of string — treat as literal '%'.
            if segments.len() < MAX_SEGMENTS {
                let mut lit: String = String::from(&fmt[start..start + literal_len]);
                lit.push('%');
                segments.push(FormatSegment::Literal(lit));
            }
            return segments;
        }

        // '%%' — literal percent
        if bytes[i] == b'%' {
            if literal_len > 0 && segments.len() < MAX_SEGMENTS {
                segments.push(FormatSegment::Literal(
                    fmt[start..start + literal_len].to_string(),
                ));
            }
            // The literal '%' starts a new run from this position
            start = i;
            i += 1;
            continue;
        }

        // Emit preceding literal (before the conversion)
        if literal_len > 0 && segments.len() < MAX_SEGMENTS {
            segments.push(FormatSegment::Literal(
                fmt[start..start + literal_len].to_string(),
            ));
        }

        // --- Parse optional positional `n$` for the main argument ----------
        let mut param: i32 = -1; // -1 means "use sequential"
        if use_dollar != DOLLAR_NOPE {
            if let Some((idx, new_i)) = parse_dollar(bytes, i) {
                param = idx as i32;
                i = new_i;
                use_dollar = DOLLAR_USE;
            } else if use_dollar == DOLLAR_USE {
                // Mixing positional and non-positional is illegal; bail out.
                return segments;
            } else {
                use_dollar = DOLLAR_NOPE;
            }
        }

        // --- Parse flags ---------------------------------------------------
        let mut flags: u32 = 0;
        let mut width: i32 = 0;
        let mut precision: i32 = 0;
        let mut loopit = true;

        while loopit && i < len {
            match bytes[i] {
                b' ' => flags |= FLAGS_SPACE,
                b'+' => flags |= FLAGS_SHOWSIGN,
                b'-' => {
                    flags |= FLAGS_LEFT;
                    flags &= !FLAGS_PAD_NIL;
                }
                b'#' => flags |= FLAGS_ALT,
                b'.' => {
                    i += 1;
                    if i < len && bytes[i] == b'*' {
                        // Precision from argument
                        flags |= FLAGS_PRECPARAM;
                        i += 1;
                        if use_dollar == DOLLAR_USE {
                            if let Some((idx, new_i)) = parse_dollar(bytes, i) {
                                precision = idx as i32;
                                i = new_i;
                            } else {
                                return segments; // bad dollar
                            }
                        } else {
                            precision = -1; // sequential
                        }
                    } else {
                        // Literal precision
                        flags |= FLAGS_PREC;
                        let is_neg = i < len && bytes[i] == b'-';
                        if is_neg {
                            i += 1;
                        }
                        let mut n: i32 = 0;
                        while i < len && bytes[i].is_ascii_digit() {
                            n = n.saturating_mul(10).saturating_add((bytes[i] - b'0') as i32);
                            i += 1;
                        }
                        precision = if is_neg { -n } else { n };
                    }
                    // Check for illegal combination of both precision types
                    if (flags & FLAGS_PREC != 0) && (flags & FLAGS_PRECPARAM != 0) {
                        return segments; // PFMT_PRECMIX
                    }
                    continue; // do NOT advance i further
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
                b'z' | b'O' => {
                    // size_t / curl_off_t — on 64-bit, same as long long
                    if std::mem::size_of::<usize>() > std::mem::size_of::<u32>() {
                        flags |= FLAGS_LONGLONG;
                    } else {
                        flags |= FLAGS_LONG;
                    }
                }
                b'0' => {
                    if flags & FLAGS_LEFT == 0 {
                        flags |= FLAGS_PAD_NIL;
                    }
                    // Also could be start of width — fall through to digit parsing
                    i += 1;
                    // Parse width digits starting from '0'
                    let mut n: i32 = 0;
                    while i < len && bytes[i].is_ascii_digit() {
                        n = n.saturating_mul(10).saturating_add((bytes[i] - b'0') as i32);
                        i += 1;
                    }
                    if n > 0 {
                        flags |= FLAGS_WIDTH;
                        width = n;
                    }
                    continue; // already advanced
                }
                b'1'..=b'9' => {
                    flags |= FLAGS_WIDTH;
                    let mut n: i32 = (bytes[i] - b'0') as i32;
                    i += 1;
                    while i < len && bytes[i].is_ascii_digit() {
                        n = n.saturating_mul(10).saturating_add((bytes[i] - b'0') as i32);
                        i += 1;
                    }
                    width = n;
                    continue; // already advanced
                }
                b'*' => {
                    // Width from argument
                    flags |= FLAGS_WIDTHPARAM;
                    i += 1;
                    if use_dollar == DOLLAR_USE {
                        if let Some((idx, new_i)) = parse_dollar(bytes, i) {
                            width = idx as i32;
                            i = new_i;
                        } else {
                            return segments; // bad dollar
                        }
                    } else {
                        width = -1; // sequential
                    }
                    continue; // already advanced
                }
                _ => {
                    loopit = false;
                    continue; // do NOT advance — current char is the specifier
                }
            }
            i += 1;
        }

        if i >= len {
            start = i;
            break;
        }

        // --- Parse conversion specifier ------------------------------------
        let type_spec = bytes[i] as char;
        let spec_flags = match type_spec {
            'S' => {
                flags |= FLAGS_ALT | FLAGS_SUBSTR;
                's' // Fall through to string handling
            }
            's' => 's',
            'n' => 'n',
            'p' => 'p',
            'd' | 'i' => 'd',
            'u' => {
                flags |= FLAGS_UNSIGNED;
                'u'
            }
            'o' => {
                flags |= FLAGS_OCTAL | FLAGS_UNSIGNED;
                'o'
            }
            'x' => {
                flags |= FLAGS_HEX | FLAGS_UNSIGNED;
                'x'
            }
            'X' => {
                flags |= FLAGS_HEX | FLAGS_UPPER | FLAGS_UNSIGNED;
                'X'
            }
            'c' => {
                flags |= FLAGS_CHAR;
                'c'
            }
            'f' => 'f',
            'e' => {
                flags |= FLAGS_FLOATE;
                'e'
            }
            'E' => {
                flags |= FLAGS_FLOATE | FLAGS_UPPER;
                'E'
            }
            'g' => {
                flags |= FLAGS_FLOATG;
                'g'
            }
            'G' => {
                flags |= FLAGS_FLOATG | FLAGS_UPPER;
                'G'
            }
            _ => {
                // Unknown specifier — skip and continue
                i += 1;
                start = i;
                continue;
            }
        };

        // --- Resolve width argument index ----------------------------------
        if flags & FLAGS_WIDTHPARAM != 0 {
            if width < 0 {
                width = param_num as i32;
                param_num += 1;
            }
            if width as usize >= MAX_PARAMETERS {
                return segments; // too many args
            }
        }

        // --- Resolve precision argument index ------------------------------
        if flags & FLAGS_PRECPARAM != 0 {
            if precision < 0 {
                precision = param_num as i32;
                param_num += 1;
            }
            if precision as usize >= MAX_PARAMETERS {
                return segments;
            }
        }

        // --- Resolve main argument index -----------------------------------
        if param < 0 {
            param = param_num as i32;
            param_num += 1;
        }
        if param as usize >= MAX_PARAMETERS {
            return segments;
        }

        i += 1; // advance past the specifier character
        start = i;

        if segments.len() >= MAX_SEGMENTS {
            break;
        }

        segments.push(FormatSegment::Conversion {
            flags,
            width,
            precision,
            type_spec: spec_flags,
            arg_index: param as usize,
        });
    }

    // --- Trailing literal text ---------------------------------------------
    if start < len && segments.len() < MAX_SEGMENTS {
        segments.push(FormatSegment::Literal(fmt[start..].to_string()));
    }

    segments
}

// ---------------------------------------------------------------------------
// Format engine — formatf
// ---------------------------------------------------------------------------

/// Render a C-style format string with typed arguments into a
/// [`fmt::Write`] sink.
///
/// This is the core formatting function. It parses the format string via
/// [`parse_format_string`], resolves argument references, and renders each
/// segment into `output`.
///
/// Returns the total number of characters written on success.
///
/// # Errors
///
/// - [`CurlError::OutOfMemory`] if the output sink fails.
/// - [`CurlError::TooLarge`] if the segment count exceeds internal limits.
pub fn formatf(
    fmt: &str,
    args: &[FormatArg],
    output: &mut dyn FmtWrite,
) -> Result<usize, CurlError> {
    let segments = parse_format_string(fmt);
    let mut written: usize = 0;

    for seg in &segments {
        match seg {
            FormatSegment::Literal(text) => {
                output.write_str(text).map_err(|_| CurlError::OutOfMemory)?;
                written += text.len();
            }
            FormatSegment::Conversion {
                flags,
                width,
                precision,
                type_spec,
                arg_index,
            } => {
                // Resolve effective width (may come from an argument).
                let mut eff_flags = *flags;
                let eff_width = if eff_flags & FLAGS_WIDTHPARAM != 0 {
                    let w = get_signed_arg(args, *width as usize);
                    if w < 0 {
                        eff_flags |= FLAGS_LEFT;
                        eff_flags &= !FLAGS_PAD_NIL;
                        if w == i32::MIN as i64 {
                            i32::MAX
                        } else {
                            (-w) as i32
                        }
                    } else {
                        w as i32
                    }
                } else {
                    *width
                };

                // Resolve effective precision (may come from an argument).
                let eff_prec = if eff_flags & FLAGS_PRECPARAM != 0 {
                    let p = get_signed_arg(args, *precision as usize);
                    if p < 0 { -1 } else { p as i32 }
                } else if eff_flags & FLAGS_PREC != 0 {
                    *precision
                } else {
                    -1 // unset
                };

                let n = render_conversion(
                    eff_flags, eff_width, eff_prec, *type_spec, *arg_index, args, output,
                )?;
                written += n;
            }
        }
    }

    Ok(written)
}

/// Extract a signed integer value from args at `idx`, defaulting to 0.
fn get_signed_arg(args: &[FormatArg], idx: usize) -> i64 {
    match args.get(idx) {
        Some(FormatArg::Int(v)) => *v,
        Some(FormatArg::Uint(v)) => *v as i64,
        Some(FormatArg::OffT(v)) => *v,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// High-level convenience — curl_format
// ---------------------------------------------------------------------------

/// Format a C-style format string with typed args, returning a `String`.
///
/// This is the idiomatic Rust entry point, equivalent to the C
/// `curl_maprintf()` function.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::mprintf::{curl_format, FormatArg};
///
/// let result = curl_format("Hello %s, you are %d", &[
///     FormatArg::Str("world".into()),
///     FormatArg::Int(42),
/// ]);
/// assert_eq!(result, "Hello world, you are 42");
/// ```
pub fn curl_format(fmt: &str, args: &[FormatArg]) -> String {
    let mut buf = String::with_capacity(BUFFSIZE.min(fmt.len().saturating_mul(2)));
    let _ = formatf(fmt, args, &mut buf);
    buf
}

// ---------------------------------------------------------------------------
// DynBuf integration — dyn_vprintf
// ---------------------------------------------------------------------------

/// Format directly into a [`DynBuf`], matching C `curlx_dyn_vprintf()`.
///
/// On error the buffer is freed (matching C semantics where
/// `curlx_dyn_free` is called on failure).
///
/// # Errors
///
/// - [`CurlError::OutOfMemory`] on allocation failure.
/// - [`CurlError::TooLarge`] if the formatted output exceeds the buffer's
///   size ceiling.
pub fn dyn_vprintf(
    buf: &mut DynBuf,
    fmt: &str,
    args: &[FormatArg],
) -> Result<(), CurlError> {
    let formatted = curl_format(fmt, args);
    let data = formatted.as_bytes();
    let prev_len = buf.len();

    match buf.add(data) {
        Ok(()) => {
            // Verify the data was appended correctly by checking length.
            debug_assert!(buf.len() >= prev_len + data.len());
            Ok(())
        }
        Err(e) => {
            // On error, free the buffer matching C curlx_dyn_vprintf behaviour.
            buf.free();
            match e {
                CurlError::TooLarge => Err(CurlError::TooLarge),
                _ => Err(CurlError::OutOfMemory),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FFI-facing helpers (for curl-rs-ffi to wrap)
// ---------------------------------------------------------------------------

/// Format and write to stdout — backing implementation for `curl_mprintf`.
///
/// Returns the number of bytes written, or an error.
pub fn format_to_stdout(fmt: &str, args: &[FormatArg]) -> Result<usize, CurlError> {
    let formatted = curl_format(fmt, args);
    let mut stdout = io::stdout();
    stdout
        .write_all(formatted.as_bytes())
        .map_err(|_| CurlError::OutOfMemory)?;
    Ok(formatted.len())
}

/// Format and write to any [`io::Write`] target — backing implementation
/// for `curl_mfprintf`.
///
/// Returns the number of bytes written, or an error.
pub fn format_to_writer(
    writer: &mut dyn IoWrite,
    fmt: &str,
    args: &[FormatArg],
) -> Result<usize, CurlError> {
    let formatted = curl_format(fmt, args);
    writer
        .write_all(formatted.as_bytes())
        .map_err(|_| CurlError::OutOfMemory)?;
    Ok(formatted.len())
}

/// Format into a fixed-size byte buffer — backing implementation for
/// `curl_msnprintf`.
///
/// Writes at most `max_len - 1` bytes followed by a NUL terminator.
/// Returns the number of bytes written (not counting NUL).
pub fn format_to_buffer(
    buf: &mut [u8],
    fmt: &str,
    args: &[FormatArg],
) -> usize {
    if buf.is_empty() {
        return 0;
    }
    let formatted = curl_format(fmt, args);
    let src = formatted.as_bytes();
    let max_data = buf.len() - 1; // reserve space for NUL
    let copy_len = src.len().min(max_data);
    buf[..copy_len].copy_from_slice(&src[..copy_len]);
    buf[copy_len] = 0; // NUL terminator
    copy_len
}

/// Format using Rust's standard [`fmt::Arguments`] into a [`DynBuf`].
///
/// This bridges the Rust `format_args!()` macro with the DynBuf accumulator,
/// used by protocol handlers that mix Rust-native formatting with curl's
/// buffer management.
pub fn dynbuf_write_fmt(
    buf: &mut DynBuf,
    args: fmt::Arguments<'_>,
) -> Result<(), CurlError> {
    buf.add_fmt(args)
}

// ---------------------------------------------------------------------------
// Conversion renderer (private)
// ---------------------------------------------------------------------------

/// Render a single conversion specifier into `output`.
///
/// Returns the number of characters written.
fn render_conversion(
    flags: u32,
    width: i32,
    prec: i32,
    spec: char,
    arg_idx: usize,
    args: &[FormatArg],
    output: &mut dyn FmtWrite,
) -> Result<usize, CurlError> {
    let arg = args.get(arg_idx);

    match spec {
        // -- Signed decimal integers ----------------------------------------
        'd' | 'i' => {
            let val = match arg {
                Some(FormatArg::Int(v)) => *v,
                Some(FormatArg::Uint(v)) => *v as i64,
                Some(FormatArg::OffT(v)) => *v,
                _ => 0,
            };
            out_number(output, flags & !FLAGS_UNSIGNED, width, prec, val as u64, val)
        }

        // -- Unsigned decimal / octal / hex ---------------------------------
        'u' | 'o' | 'x' | 'X' => {
            let val = match arg {
                Some(FormatArg::Uint(v)) => *v,
                Some(FormatArg::Int(v)) => *v as u64,
                Some(FormatArg::OffT(v)) => *v as u64,
                _ => 0,
            };
            out_number(output, flags, width, prec, val, 0)
        }

        // -- Character ------------------------------------------------------
        'c' => {
            let ch = match arg {
                Some(FormatArg::Int(v)) => {
                    char::from_u32(*v as u32).unwrap_or('\0')
                }
                Some(FormatArg::Uint(v)) => {
                    char::from_u32(*v as u32).unwrap_or('\0')
                }
                _ => '\0',
            };
            out_char(output, flags, width, ch)
        }

        // -- String ---------------------------------------------------------
        's' => {
            let val = match arg {
                Some(FormatArg::Str(s)) => Some(s.as_str()),
                _ => None,
            };
            out_string(output, flags, width, prec, val)
        }

        // -- Pointer --------------------------------------------------------
        'p' => {
            let val = match arg {
                Some(FormatArg::Ptr(p)) => *p,
                Some(FormatArg::Uint(v)) => *v as usize,
                _ => 0,
            };
            out_pointer(output, flags, width, prec, val)
        }

        // -- Floating point -------------------------------------------------
        'f' | 'e' | 'E' | 'g' | 'G' => {
            let val = match arg {
                Some(FormatArg::Float(v)) => *v,
                Some(FormatArg::Int(v)) => *v as f64,
                Some(FormatArg::Uint(v)) => *v as f64,
                _ => 0.0,
            };
            out_double(output, flags, width, prec, val)
        }

        // -- %n: store character count (safe stub — no pointer writes) ------
        'n' => {
            // In safe Rust we cannot write to an arbitrary pointer.
            // The FFI crate handles actual %n semantics in unsafe code.
            Ok(0)
        }

        // -- Unknown: should not appear (parser filters) --------------------
        _ => Ok(0),
    }
}

// ---------------------------------------------------------------------------
// Integer output — out_number
// ---------------------------------------------------------------------------

/// Format an integer (signed or unsigned) with full C printf semantics.
///
/// Handles base-10, base-8 (octal), and base-16 (hex) output, sign/prefix,
/// precision (minimum digits), width, padding (spaces or zeros), and
/// left/right alignment.
fn out_number(
    output: &mut dyn FmtWrite,
    flags: u32,
    width: i32,
    prec: i32,
    num: u64,
    nums: i64,
) -> Result<usize, CurlError> {
    let is_alt = flags & FLAGS_ALT != 0;
    let mut is_neg = false;

    // Determine base
    let base: u64 = if flags & FLAGS_OCTAL != 0 {
        8
    } else if flags & FLAGS_HEX != 0 {
        16
    } else {
        10
    };

    // Select digit table
    let digits: &[u8; 16] = if flags & FLAGS_UPPER != 0 {
        UPPER_DIGITS
    } else {
        LOWER_DIGITS
    };

    // Handle character output (%c)
    if flags & FLAGS_CHAR != 0 {
        let ch = char::from_u32(num as u32).unwrap_or('\0');
        return out_char(output, flags, width, ch);
    }

    // Determine the actual unsigned magnitude and sign
    let mut magnitude = num;
    if flags & FLAGS_UNSIGNED == 0 {
        // Signed integer
        is_neg = nums < 0;
        if is_neg {
            // Convert negative to positive magnitude carefully (handles i64::MIN)
            let signed_num = nums.wrapping_add(1);
            magnitude = ((-signed_num) as u64).wrapping_add(1);
        } else {
            magnitude = nums as u64;
        }
    }

    // Convert number to digits (reversed, then reversed back)
    let mut digit_buf = [0u8; 80]; // enough for any 64-bit number in any base
    let mut dlen: usize = 0;
    if magnitude == 0 {
        // Special case: zero — only emit '0' if precision != 0
        let default_prec = if prec < 0 { 1 } else { prec };
        if default_prec > 0 {
            digit_buf[0] = b'0';
            dlen = 1;
        }
    } else {
        let mut tmp = magnitude;
        while tmp > 0 {
            digit_buf[dlen] = digits[(tmp % base) as usize];
            dlen += 1;
            tmp /= base;
        }
        // Reverse the digits
        digit_buf[..dlen].reverse();
    }

    // Apply precision: pad with leading zeros to reach minimum digit count
    let min_digits = if prec < 0 { 1 } else { prec as usize };
    let leading_zeros = min_digits.saturating_sub(dlen);

    // Compute prefix for octal alt and hex alt
    let prefix: &str =
        if is_alt && base == 8 && leading_zeros == 0 && (dlen == 0 || digit_buf[0] != b'0') {
            "0"
        } else if is_alt && base == 16 && magnitude != 0 {
            if flags & FLAGS_UPPER != 0 {
                "0X"
            } else {
                "0x"
            }
        } else {
            ""
        };

    // Compute sign character
    let sign: &str = if is_neg {
        "-"
    } else if flags & FLAGS_SHOWSIGN != 0 {
        "+"
    } else if flags & FLAGS_SPACE != 0 {
        " "
    } else {
        ""
    };

    // Total content width: sign + prefix + leading_zeros + digits
    let content_len = sign.len() + prefix.len() + leading_zeros + dlen;

    let w = if width > 0 { width as usize } else { 0 };
    let padding = w.saturating_sub(content_len);

    let left_align = flags & FLAGS_LEFT != 0;
    let zero_pad = (flags & FLAGS_PAD_NIL != 0) && !left_align && prec < 0;

    let mut written: usize = 0;

    // Right-aligned space padding
    if !left_align && !zero_pad {
        for _ in 0..padding {
            output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
            written += 1;
        }
    }

    // Sign
    if !sign.is_empty() {
        output.write_str(sign).map_err(|_| CurlError::OutOfMemory)?;
        written += sign.len();
    }

    // Prefix (0x, 0X, 0)
    if !prefix.is_empty() {
        output
            .write_str(prefix)
            .map_err(|_| CurlError::OutOfMemory)?;
        written += prefix.len();
    }

    // Zero padding (goes AFTER sign and prefix, matching C behaviour)
    if zero_pad {
        for _ in 0..padding {
            output.write_char('0').map_err(|_| CurlError::OutOfMemory)?;
            written += 1;
        }
    }

    // Precision-driven leading zeros
    for _ in 0..leading_zeros {
        output.write_char('0').map_err(|_| CurlError::OutOfMemory)?;
        written += 1;
    }

    // Digits
    if dlen > 0 {
        let digit_str = std::str::from_utf8(&digit_buf[..dlen]).unwrap_or("0");
        output
            .write_str(digit_str)
            .map_err(|_| CurlError::OutOfMemory)?;
        written += dlen;
    }

    // Left-aligned trailing padding
    if left_align {
        for _ in 0..padding {
            output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
            written += 1;
        }
    }

    Ok(written)
}

// ---------------------------------------------------------------------------
// Character output — out_char
// ---------------------------------------------------------------------------

/// Format a single character with width and alignment.
fn out_char(
    output: &mut dyn FmtWrite,
    flags: u32,
    width: i32,
    ch: char,
) -> Result<usize, CurlError> {
    let w = if width > 0 { width as usize } else { 0 };
    let ch_len = ch.len_utf8();
    let padding = w.saturating_sub(ch_len);
    let left = flags & FLAGS_LEFT != 0;
    let mut written: usize = 0;

    if !left {
        for _ in 0..padding {
            output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
            written += 1;
        }
    }

    output.write_char(ch).map_err(|_| CurlError::OutOfMemory)?;
    written += ch_len;

    if left {
        for _ in 0..padding {
            output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
            written += 1;
        }
    }

    Ok(written)
}

// ---------------------------------------------------------------------------
// String output — out_string
// ---------------------------------------------------------------------------

/// Format a string with optional precision (truncation), width, padding,
/// and the curl-specific `FLAGS_ALT` quoting (`%S` → `"string"`).
fn out_string(
    output: &mut dyn FmtWrite,
    flags: u32,
    width: i32,
    prec: i32,
    val: Option<&str>,
) -> Result<usize, CurlError> {
    let mut eff_flags = flags;

    // Resolve the string value — missing arg becomes "(nil)" or "" depending
    // on precision.
    let (str_val, len) = match val {
        Some(s) => {
            if prec >= 0 {
                let p = prec as usize;
                let end = s
                    .char_indices()
                    .take(p)
                    .last()
                    .map_or(0, |(idx, c)| idx + c.len_utf8())
                    .min(s.len());
                (&s[..end], end)
            } else {
                (s, s.len())
            }
        }
        None => {
            if prec < 0 || prec >= NIL_STR.len() as i32 {
                eff_flags &= !FLAGS_ALT; // Disable quoting around (nil)
                (NIL_STR, NIL_STR.len())
            } else {
                ("", 0)
            }
        }
    };

    let quote = eff_flags & FLAGS_ALT != 0;
    let content_len = len + if quote { 2 } else { 0 };
    let w = if width > 0 { width as usize } else { 0 };
    let padding = w.saturating_sub(content_len);
    let left = eff_flags & FLAGS_LEFT != 0;
    let mut written: usize = 0;

    if quote {
        output.write_char('"').map_err(|_| CurlError::OutOfMemory)?;
        written += 1;
    }

    if !left {
        for _ in 0..padding {
            output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
            written += 1;
        }
    }

    output
        .write_str(str_val)
        .map_err(|_| CurlError::OutOfMemory)?;
    written += len;

    if left {
        for _ in 0..padding {
            output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
            written += 1;
        }
    }

    if quote {
        output.write_char('"').map_err(|_| CurlError::OutOfMemory)?;
        written += 1;
    }

    Ok(written)
}

// ---------------------------------------------------------------------------
// Pointer output — out_pointer
// ---------------------------------------------------------------------------

/// Format a pointer value. Non-null pointers are rendered as `0x<hex>`;
/// null pointers are rendered as `(nil)`.
fn out_pointer(
    output: &mut dyn FmtWrite,
    flags: u32,
    width: i32,
    prec: i32,
    ptr: usize,
) -> Result<usize, CurlError> {
    if ptr != 0 {
        let pf = flags | FLAGS_HEX | FLAGS_ALT | FLAGS_UNSIGNED;
        out_number(output, pf, width, prec, ptr as u64, 0)
    } else {
        let w = if width > 0 { width as usize } else { 0 };
        let content_len = NIL_STR.len();
        let padding = w.saturating_sub(content_len);
        let left = flags & FLAGS_LEFT != 0;
        let mut written: usize = 0;

        if !left {
            for _ in 0..padding {
                output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
                written += 1;
            }
        }

        output
            .write_str(NIL_STR)
            .map_err(|_| CurlError::OutOfMemory)?;
        written += content_len;

        if left {
            for _ in 0..padding {
                output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
                written += 1;
            }
        }

        Ok(written)
    }
}

// ---------------------------------------------------------------------------
// Float output — out_double
// ---------------------------------------------------------------------------

/// Format a floating-point value using Rust's standard formatting.
///
/// Supports `%f` (decimal), `%e`/`%E` (scientific), and `%g`/`%G`
/// (general). Sign, width, and zero-padding are handled.
fn out_double(
    output: &mut dyn FmtWrite,
    flags: u32,
    width: i32,
    prec: i32,
    val: f64,
) -> Result<usize, CurlError> {
    let precision = if prec < 0 { 6 } else { prec as usize };
    let show_sign = flags & FLAGS_SHOWSIGN != 0;
    let space = flags & FLAGS_SPACE != 0;
    let left = flags & FLAGS_LEFT != 0;
    let zero_pad = (flags & FLAGS_PAD_NIL != 0) && !left;

    // Clamp precision to avoid extremely long output
    let clamped_prec = precision.min(BUFFSIZE.saturating_sub(20));

    // Format the number using Rust's standard formatting
    let body = if flags & FLAGS_FLOATE != 0 {
        if flags & FLAGS_UPPER != 0 {
            format!("{val:.clamped_prec$E}")
        } else {
            format!("{val:.clamped_prec$e}")
        }
    } else if flags & FLAGS_FLOATG != 0 {
        let use_e = if val == 0.0 {
            false
        } else {
            let exp = val.abs().log10().floor() as i64;
            exp < -4 || exp >= clamped_prec as i64
        };
        if use_e {
            if flags & FLAGS_UPPER != 0 {
                format!("{val:.clamped_prec$E}")
            } else {
                format!("{val:.clamped_prec$e}")
            }
        } else {
            format!("{val:.clamped_prec$}")
        }
    } else {
        format!("{val:.clamped_prec$}")
    };

    // Rust's formatter already inserts '-' for negative values.
    let prefix = if val.is_sign_negative() && !val.is_nan() {
        ""
    } else if show_sign {
        "+"
    } else if space {
        " "
    } else {
        ""
    };

    let content = if prefix.is_empty() {
        body
    } else {
        format!("{prefix}{body}")
    };

    let w = if width > 0 { width as usize } else { 0 };
    let content_len = content.len();
    let padding = w.saturating_sub(content_len);
    let mut written: usize = 0;

    if zero_pad && !content.is_empty() {
        // Zero padding: sign goes first, then zeros, then number body.
        let (sign_part, num_part) = if content.starts_with('-')
            || content.starts_with('+')
            || content.starts_with(' ')
        {
            content.split_at(1)
        } else {
            ("", content.as_str())
        };

        if !sign_part.is_empty() {
            output
                .write_str(sign_part)
                .map_err(|_| CurlError::OutOfMemory)?;
            written += sign_part.len();
        }
        for _ in 0..padding {
            output.write_char('0').map_err(|_| CurlError::OutOfMemory)?;
            written += 1;
        }
        output
            .write_str(num_part)
            .map_err(|_| CurlError::OutOfMemory)?;
        written += num_part.len();
    } else if left {
        output
            .write_str(&content)
            .map_err(|_| CurlError::OutOfMemory)?;
        written += content_len;
        for _ in 0..padding {
            output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
            written += 1;
        }
    } else {
        for _ in 0..padding {
            output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
            written += 1;
        }
        output
            .write_str(&content)
            .map_err(|_| CurlError::OutOfMemory)?;
        written += content_len;
    }

    Ok(written)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_c() {
        assert_eq!(BUFFSIZE, 1024);
        assert_eq!(MAX_PARAMETERS, 128);
        assert_eq!(MAX_SEGMENTS, 128);
        assert_eq!(LOWER_DIGITS, b"0123456789abcdef");
        assert_eq!(UPPER_DIGITS, b"0123456789ABCDEF");
    }

    #[test]
    fn mprintf_error_display() {
        assert_eq!(MprintfError::Ok.to_string(), "ok");
        assert_eq!(MprintfError::Mem.to_string(), "out of memory");
        assert_eq!(MprintfError::TooLarge.to_string(), "output too large");
    }

    #[test]
    fn mprintf_error_to_curlerror() {
        assert_eq!(CurlError::from(MprintfError::Ok), CurlError::Ok);
        assert_eq!(CurlError::from(MprintfError::Mem), CurlError::OutOfMemory);
        assert_eq!(CurlError::from(MprintfError::TooLarge), CurlError::TooLarge);
    }

    #[test]
    fn format_arg_display() {
        assert_eq!(FormatArg::Int(-42).to_string(), "-42");
        assert_eq!(FormatArg::Uint(100).to_string(), "100");
        assert_eq!(FormatArg::Ptr(0).to_string(), "(nil)");
        assert_eq!(FormatArg::Ptr(0xdead).to_string(), "0xdead");
        assert_eq!(FormatArg::OffT(-99).to_string(), "-99");
    }

    #[test]
    fn parse_empty_string() {
        assert!(parse_format_string("").is_empty());
    }

    #[test]
    fn parse_plain_literal() {
        let segs = parse_format_string("hello world");
        assert_eq!(segs.len(), 1);
        if let FormatSegment::Literal(s) = &segs[0] {
            assert_eq!(s, "hello world");
        } else {
            panic!("expected Literal");
        }
    }

    #[test]
    fn parse_percent_literal() {
        let segs = parse_format_string("100%%");
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn parse_single_conversion() {
        let segs = parse_format_string("value: %d end");
        assert_eq!(segs.len(), 3);
    }

    #[test]
    fn parse_positional_arg() {
        let segs = parse_format_string("%2$s");
        assert_eq!(segs.len(), 1);
        if let FormatSegment::Conversion { arg_index, type_spec, .. } = &segs[0] {
            assert_eq!(*arg_index, 1);
            assert_eq!(*type_spec, 's');
        } else {
            panic!("expected Conversion");
        }
    }

    #[test]
    fn parse_width_and_precision() {
        let segs = parse_format_string("%10.5d");
        assert_eq!(segs.len(), 1);
        if let FormatSegment::Conversion { width, precision, .. } = &segs[0] {
            assert_eq!(*width, 10);
            assert_eq!(*precision, 5);
        } else {
            panic!("expected Conversion");
        }
    }

    #[test]
    fn format_simple_string() {
        assert_eq!(curl_format("Hello %s", &[FormatArg::Str("world".into())]), "Hello world");
    }

    #[test]
    fn format_integer() {
        assert_eq!(curl_format("val=%d", &[FormatArg::Int(42)]), "val=42");
    }

    #[test]
    fn format_negative_integer() {
        assert_eq!(curl_format("%d", &[FormatArg::Int(-7)]), "-7");
    }

    #[test]
    fn format_unsigned() {
        assert_eq!(curl_format("%u", &[FormatArg::Uint(4294967295)]), "4294967295");
    }

    #[test]
    fn format_hex_lower() {
        assert_eq!(curl_format("%x", &[FormatArg::Uint(255)]), "ff");
    }

    #[test]
    fn format_hex_upper() {
        assert_eq!(curl_format("%X", &[FormatArg::Uint(255)]), "FF");
    }

    #[test]
    fn format_hex_alt() {
        assert_eq!(curl_format("%#x", &[FormatArg::Uint(255)]), "0xff");
    }

    #[test]
    fn format_hex_alt_upper() {
        assert_eq!(curl_format("%#X", &[FormatArg::Uint(255)]), "0XFF");
    }

    #[test]
    fn format_hex_alt_zero() {
        assert_eq!(curl_format("%#x", &[FormatArg::Uint(0)]), "0");
    }

    #[test]
    fn format_octal() {
        assert_eq!(curl_format("%o", &[FormatArg::Uint(8)]), "10");
    }

    #[test]
    fn format_octal_alt() {
        assert_eq!(curl_format("%#o", &[FormatArg::Uint(8)]), "010");
    }

    #[test]
    fn format_float_default() {
        assert_eq!(curl_format("%f", &[FormatArg::Float(3.14)]), "3.140000");
    }

    #[test]
    fn format_float_precision() {
        let mut buf = String::new();
        formatf("%.2f", &[FormatArg::Float(3.14159)], &mut buf).unwrap();
        assert_eq!(buf, "3.14");
    }

    #[test]
    fn format_float_scientific() {
        let result = curl_format("%.2e", &[FormatArg::Float(12345.0)]);
        // Rust's scientific notation uses e.g. "1.23e4" (no '+' in exponent)
        assert!(
            result.contains('e') || result.contains('E'),
            "unexpected: {result}"
        );
    }

    #[test]
    fn format_string_precision_truncation() {
        assert_eq!(curl_format("%.3s", &[FormatArg::Str("Hello".into())]), "Hel");
    }

    #[test]
    fn format_string_null() {
        assert_eq!(curl_format("%s", &[]), "(nil)");
    }

    #[test]
    fn format_pointer_nil() {
        assert_eq!(curl_format("%p", &[FormatArg::Ptr(0)]), "(nil)");
    }

    #[test]
    fn format_pointer_nonzero() {
        assert_eq!(curl_format("%p", &[FormatArg::Ptr(0xDEAD)]), "0xdead");
    }

    #[test]
    fn format_character() {
        assert_eq!(curl_format("%c", &[FormatArg::Int(65)]), "A");
    }

    #[test]
    fn format_literal_percent() {
        assert_eq!(curl_format("100%%", &[]), "100%");
    }

    #[test]
    fn format_no_args() {
        assert_eq!(curl_format("plain text", &[]), "plain text");
    }

    #[test]
    fn format_empty() {
        assert_eq!(curl_format("", &[]), "");
    }

    #[test]
    fn format_multiple_args() {
        let result = curl_format(
            "%s=%d (%u)",
            &[FormatArg::Str("key".into()), FormatArg::Int(10), FormatArg::Uint(20)],
        );
        assert_eq!(result, "key=10 (20)");
    }

    #[test]
    fn format_right_padded_string() {
        assert_eq!(curl_format("%10s", &[FormatArg::Str("hi".into())]), "        hi");
    }

    #[test]
    fn format_left_padded_string() {
        assert_eq!(curl_format("%-10s", &[FormatArg::Str("hi".into())]), "hi        ");
    }

    #[test]
    fn format_zero_padded_int() {
        assert_eq!(curl_format("%05d", &[FormatArg::Int(42)]), "00042");
    }

    #[test]
    fn format_zero_padded_negative() {
        assert_eq!(curl_format("%08d", &[FormatArg::Int(-42)]), "-0000042");
    }

    #[test]
    fn format_sign_positive() {
        assert_eq!(curl_format("%+d", &[FormatArg::Int(42)]), "+42");
    }

    #[test]
    fn format_space_positive() {
        assert_eq!(curl_format("% d", &[FormatArg::Int(42)]), " 42");
    }

    #[test]
    fn format_width_right_align_int() {
        assert_eq!(curl_format("%8d", &[FormatArg::Int(42)]), "      42");
    }

    #[test]
    fn format_width_left_align_int() {
        assert_eq!(curl_format("%-8d", &[FormatArg::Int(42)]), "42      ");
    }

    #[test]
    fn format_int_precision() {
        assert_eq!(curl_format("%.5d", &[FormatArg::Int(42)]), "00042");
    }

    #[test]
    fn format_int_precision_zero_value() {
        assert_eq!(curl_format("%.0d", &[FormatArg::Int(0)]), "");
    }

    #[test]
    fn format_int_width_and_precision() {
        assert_eq!(curl_format("%8.5d", &[FormatArg::Int(42)]), "   00042");
    }

    #[test]
    fn format_positional_args() {
        let result = curl_format(
            "%2$s %1$d",
            &[FormatArg::Int(10), FormatArg::Str("hello".into())],
        );
        assert_eq!(result, "hello 10");
    }

    #[test]
    fn format_quoted_string() {
        assert_eq!(curl_format("%S", &[FormatArg::Str("test".into())]), "\"test\"");
    }

    #[test]
    fn format_quoted_null_string() {
        assert_eq!(curl_format("%S", &[]), "(nil)");
    }

    #[test]
    fn dyn_vprintf_basic() {
        let mut buf = DynBuf::new();
        dyn_vprintf(&mut buf, "hello %s", &[FormatArg::Str("world".into())]).unwrap();
        assert_eq!(buf.as_bytes(), b"hello world");
        assert_eq!(buf.len(), 11);
    }

    #[test]
    fn dyn_vprintf_error_frees_buffer() {
        let mut buf = DynBuf::with_max(5);
        let result = dyn_vprintf(
            &mut buf,
            "%s",
            &[FormatArg::Str("this string is too long".into())],
        );
        assert!(result.is_err());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn format_to_buffer_basic() {
        let mut buf = [0u8; 32];
        let n = format_to_buffer(&mut buf, "hello %d", &[FormatArg::Int(42)]);
        assert_eq!(n, 8);
        assert_eq!(&buf[..n], b"hello 42");
        assert_eq!(buf[n], 0);
    }

    #[test]
    fn format_to_buffer_truncation() {
        let mut buf = [0u8; 6];
        let n = format_to_buffer(&mut buf, "hello world", &[]);
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(buf[n], 0);
    }

    #[test]
    fn format_to_buffer_empty() {
        let mut buf = [0u8; 0];
        let n = format_to_buffer(&mut buf, "test", &[]);
        assert_eq!(n, 0);
    }

    #[test]
    fn dynbuf_write_fmt_basic() {
        let mut buf = DynBuf::new();
        dynbuf_write_fmt(&mut buf, format_args!("count: {}", 42)).unwrap();
        assert_eq!(buf.as_bytes(), b"count: 42");
    }

    #[test]
    fn format_i64_min() {
        assert_eq!(curl_format("%d", &[FormatArg::Int(i64::MIN)]), i64::MIN.to_string());
    }

    #[test]
    fn format_u64_max() {
        assert_eq!(curl_format("%u", &[FormatArg::Uint(u64::MAX)]), u64::MAX.to_string());
    }

    #[test]
    fn format_off_t() {
        assert_eq!(curl_format("%d", &[FormatArg::OffT(-123456)]), "-123456");
    }

    #[test]
    fn format_float_zero() {
        assert_eq!(curl_format("%.1f", &[FormatArg::Float(0.0)]), "0.0");
    }

    #[test]
    fn format_float_negative() {
        assert_eq!(curl_format("%.2f", &[FormatArg::Float(-1.5)]), "-1.50");
    }

    #[test]
    fn format_many_segments() {
        let fmt_str = "%d ".repeat(MAX_SEGMENTS + 10);
        let args: Vec<FormatArg> = (0..(MAX_SEGMENTS + 10)).map(|i| FormatArg::Int(i as i64)).collect();
        let result = curl_format(&fmt_str, &args);
        assert!(!result.is_empty());
    }

    #[test]
    fn format_missing_arg() {
        assert_eq!(curl_format("%d %d", &[FormatArg::Int(1)]), "1 0");
    }

    #[test]
    fn format_character_with_width() {
        assert_eq!(curl_format("%5c", &[FormatArg::Int(65)]), "    A");
        assert_eq!(curl_format("%-5c", &[FormatArg::Int(65)]), "A    ");
    }

    #[test]
    fn format_pointer_with_width() {
        assert_eq!(curl_format("%20p", &[FormatArg::Ptr(0)]), "               (nil)");
    }

    #[test]
    fn format_zero_pad_float() {
        assert_eq!(curl_format("%010.2f", &[FormatArg::Float(3.14)]), "0000003.14");
    }

    #[test]
    fn format_zero_pad_negative_float() {
        assert_eq!(curl_format("%010.2f", &[FormatArg::Float(-3.14)]), "-000003.14");
    }
}
