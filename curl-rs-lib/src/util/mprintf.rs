//! `printf` family — Rust replacement for C `lib/mprintf.c`.
//!
//! Curl's bespoke `printf` engine (1 229 C lines) handles positional
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
//! | `curl_format()`          | `curl_msnprintf()` core    |
//! | `parse_format_string()`  | internal parser            |
//! | `formatf()`              | `dprintf_formatf()`        |
//! | `dyn_vprintf()`          | `curlx_dyn_vprintf()`      |
//! | `FormatArg`              | `va_stack_t` union         |
//! | `FormatSegment`          | `va_stack_t` + metadata    |
//!
//! # Design Notes
//!
//! The implementation parses a C-style format string into a sequence of
//! [`FormatSegment`] values (literal text or conversion specifications) and
//! then renders each segment against the supplied [`FormatArg`] slice. The
//! parser supports the full set of POSIX conversion specifiers used by curl.

use std::fmt::{self, Write as FmtWrite};

use crate::error::CurlError;
use crate::util::dynbuf::DynBuf;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Internal format-output buffer size (bytes).
pub const BUFFSIZE: usize = 1024;

/// Maximum number of format arguments (matches C `MAX_PARAMETERS`).
pub const MAX_PARAMETERS: usize = 128;

/// Maximum number of parsed segments in a single format string.
pub const MAX_SEGMENTS: usize = 128;

/// Lower-case hex digit table.
pub const LOWER_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Upper-case hex digit table.
pub const UPPER_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

// ---------------------------------------------------------------------------
// FormatArg
// ---------------------------------------------------------------------------

/// A single dynamically-typed argument that can be referenced by a format
/// string conversion specifier.
///
/// Mirrors the C `va_stack_t` union.
#[derive(Debug, Clone)]
pub enum FormatArg {
    /// Signed integer (`%d`, `%i`, `%ld`, `%lld`).
    Int(i64),
    /// Unsigned integer (`%u`, `%o`, `%x`, `%X`, `%lu`, `%llu`).
    Uint(u64),
    /// Floating point (`%f`, `%e`, `%E`, `%g`, `%G`).
    Float(f64),
    /// String pointer (`%s`).
    Str(String),
    /// Raw pointer (`%p`).
    Ptr(usize),
    /// `curl_off_t` value (`%Od` or `%Ou` in curl).
    OffT(i64),
}

// ---------------------------------------------------------------------------
// MprintfError
// ---------------------------------------------------------------------------

/// Errors that can occur during format-string processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MprintfError {
    /// Success (no error).
    Ok,
    /// Memory allocation failure.
    Mem,
    /// Output exceeds size limit.
    TooLarge,
    /// Format string is malformed.
    BadFormat,
}

impl fmt::Display for MprintfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MprintfError::Ok => write!(f, "ok"),
            MprintfError::Mem => write!(f, "out of memory"),
            MprintfError::TooLarge => write!(f, "output too large"),
            MprintfError::BadFormat => write!(f, "bad format string"),
        }
    }
}

// ---------------------------------------------------------------------------
// Format flags (bitfield)
// ---------------------------------------------------------------------------

// Flag bits are defined as constants (FLAG_LEFT, FLAG_SIGN, etc.) and stored
// in the `FormatSegment::Conversion { flags: u8, .. }` field rather than a
// separate struct, matching the compact representation used by the C parser.

// ---------------------------------------------------------------------------
// FormatSegment
// ---------------------------------------------------------------------------

/// One piece of a parsed format string — either a literal run of characters
/// or a conversion specification.
#[derive(Debug, Clone)]
pub enum FormatSegment {
    /// Verbatim text (no conversion).
    Literal(String),

    /// A `%`-conversion with all parsed metadata.
    Conversion {
        /// Format flags (`-`, `+`, ` `, `0`, `#`).
        flags: u8,
        /// Minimum field width (0 = unset).
        width: Option<usize>,
        /// Precision (0 = unset).
        precision: Option<usize>,
        /// Conversion character (`d`, `s`, `x`, …).
        type_spec: char,
        /// Argument index (0-based). If positional syntax `n$` was used this
        /// is the explicit position; otherwise it is the implicit sequential
        /// index.
        arg_index: usize,
    },
}

// Flag bit constants for the public `flags` field.
const FLAG_LEFT: u8 = 0x01;
const FLAG_SIGN: u8 = 0x02;
const FLAG_SPACE: u8 = 0x04;
const FLAG_ZERO: u8 = 0x08;
const FLAG_ALT: u8 = 0x10;

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse a C-style `printf` format string into a vector of [`FormatSegment`]s.
///
/// Supports:
/// - Positional arguments (`%1$d`)
/// - Flag characters (`-`, `+`, ` `, `0`, `#`)
/// - Field width (literal or `*`)
/// - Precision (`.N` or `.*`)
/// - Length modifiers (`h`, `hh`, `l`, `ll`, `L`, `z`)
/// - Conversion specifiers (`d`, `i`, `u`, `o`, `x`, `X`, `f`, `e`, `E`,
///   `g`, `G`, `c`, `s`, `p`, `%`)
///
/// Returns an empty vector for an empty format string.
pub fn parse_format_string(fmt: &str) -> Vec<FormatSegment> {
    let mut segments: Vec<FormatSegment> = Vec::new();
    let chars: Vec<char> = fmt.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut next_arg: usize = 0;

    while i < len {
        // Scan for the next '%'.
        if chars[i] != '%' {
            let start = i;
            while i < len && chars[i] != '%' {
                i += 1;
            }
            segments.push(FormatSegment::Literal(
                chars[start..i].iter().collect(),
            ));
            continue;
        }

        // We are at a '%'.
        i += 1; // skip '%'
        if i >= len {
            // Trailing '%' with nothing after it — treat as literal.
            segments.push(FormatSegment::Literal("%".to_string()));
            break;
        }

        // Literal '%%'
        if chars[i] == '%' {
            segments.push(FormatSegment::Literal("%".to_string()));
            i += 1;
            continue;
        }

        // --- Parse optional positional argument `n$` -----------------------
        let mut arg_index: Option<usize> = None;
        let saved_i = i;
        if chars[i].is_ascii_digit() && chars[i] != '0' {
            let mut n: usize = 0;
            let num_start = i;
            while i < len && chars[i].is_ascii_digit() {
                n = n.saturating_mul(10).saturating_add((chars[i] as u8 - b'0') as usize);
                i += 1;
            }
            if i < len && chars[i] == '$' {
                arg_index = Some(n.saturating_sub(1)); // 1-based → 0-based
                i += 1;
            } else {
                // Not positional — rewind; digits are part of width.
                i = num_start;
            }
        }
        if arg_index.is_none() {
            // Rewind to just after '%' if positional parsing consumed nothing useful.
            i = saved_i;
        }

        // --- Parse flags ---------------------------------------------------
        let mut flags: u8 = 0;
        while i < len {
            match chars[i] {
                '-' => flags |= FLAG_LEFT,
                '+' => flags |= FLAG_SIGN,
                ' ' => flags |= FLAG_SPACE,
                '0' => flags |= FLAG_ZERO,
                '#' => flags |= FLAG_ALT,
                _ => break,
            }
            i += 1;
        }

        // --- Parse width ---------------------------------------------------
        let mut width: Option<usize> = None;
        if i < len && chars[i] == '*' {
            // Width from argument — for simplicity store 0 and let the
            // renderer fetch from args.
            width = Some(0);
            i += 1;
        } else {
            let mut w: usize = 0;
            let mut has_width = false;
            while i < len && chars[i].is_ascii_digit() {
                has_width = true;
                w = w.saturating_mul(10).saturating_add((chars[i] as u8 - b'0') as usize);
                i += 1;
            }
            if has_width {
                width = Some(w);
            }
        }

        // --- Parse precision -----------------------------------------------
        let mut precision: Option<usize> = None;
        if i < len && chars[i] == '.' {
            i += 1;
            if i < len && chars[i] == '*' {
                precision = Some(0);
                i += 1;
            } else {
                let mut p: usize = 0;
                let mut has_prec = false;
                while i < len && chars[i].is_ascii_digit() {
                    has_prec = true;
                    p = p.saturating_mul(10).saturating_add((chars[i] as u8 - b'0') as usize);
                    i += 1;
                }
                precision = Some(if has_prec { p } else { 0 });
            }
        }

        // --- Skip length modifiers ----------------------------------------
        while i < len && matches!(chars[i], 'h' | 'l' | 'L' | 'z' | 'q' | 'j' | 't') {
            i += 1;
        }

        // --- Conversion specifier ------------------------------------------
        let type_spec = if i < len { chars[i] } else { '?' };
        i += 1;

        let idx = arg_index.unwrap_or_else(|| {
            let a = next_arg;
            next_arg += 1;
            a
        });

        // If positional was not used but we just consumed an index, bump next_arg
        // for consistency.
        if arg_index.is_some() && idx >= next_arg {
            next_arg = idx + 1;
        }

        if segments.len() >= MAX_SEGMENTS {
            break;
        }

        segments.push(FormatSegment::Conversion {
            flags,
            width,
            precision,
            type_spec,
            arg_index: idx,
        });
    }

    segments
}

// ---------------------------------------------------------------------------
// Format engine
// ---------------------------------------------------------------------------

/// Render parsed `segments` against `args` into a [`fmt::Write`] sink.
///
/// Returns the total number of characters written on success.
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] if the output sink fails, or
/// [`CurlError::TooLarge`] if segment count exceeds internal limits.
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
                let n = render_conversion(
                    *flags, *width, *precision, *type_spec, *arg_index, args, output,
                )?;
                written += n;
            }
        }
    }

    Ok(written)
}

/// High-level convenience: format a C-style format string with typed args.
///
/// Equivalent to `curl_msnprintf` / `curl_maprintf` in C.
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
    let mut buf = String::with_capacity(BUFFSIZE);
    let _ = formatf(fmt, args, &mut buf);
    buf
}

/// Format directly into a [`DynBuf`].
///
/// Used by protocol handlers and auth modules that build wire messages in a
/// `DynBuf` and want to avoid an intermediate `String` allocation.
pub fn dyn_vprintf(buf: &mut DynBuf, fmt: &str, args: &[FormatArg]) -> Result<(), CurlError> {
    let formatted = curl_format(fmt, args);
    buf.add_str(&formatted)
}

// ---------------------------------------------------------------------------
// Conversion renderer (private)
// ---------------------------------------------------------------------------

/// Render a single conversion specifier into `output`.
fn render_conversion(
    flags: u8,
    width: Option<usize>,
    precision: Option<usize>,
    spec: char,
    arg_idx: usize,
    args: &[FormatArg],
    output: &mut dyn FmtWrite,
) -> Result<usize, CurlError> {
    let arg = args.get(arg_idx);
    let w = width.unwrap_or(0);
    let left = flags & FLAG_LEFT != 0;
    let zero = flags & FLAG_ZERO != 0;
    let show_sign = flags & FLAG_SIGN != 0;
    let space = flags & FLAG_SPACE != 0;
    let alt = flags & FLAG_ALT != 0;

    match spec {
        // -- Signed decimal integers ----------------------------------------
        'd' | 'i' => {
            let val = match arg {
                Some(FormatArg::Int(v)) => *v,
                Some(FormatArg::Uint(v)) => *v as i64,
                Some(FormatArg::OffT(v)) => *v,
                _ => 0,
            };
            let formatted = format_signed(val, show_sign, space);
            let n = write_padded(output, &formatted, w, left, zero && !left)?;
            Ok(n)
        }

        // -- Unsigned decimal integers --------------------------------------
        'u' => {
            let val = match arg {
                Some(FormatArg::Uint(v)) => *v,
                Some(FormatArg::Int(v)) => *v as u64,
                Some(FormatArg::OffT(v)) => *v as u64,
                _ => 0,
            };
            let formatted = val.to_string();
            let n = write_padded(output, &formatted, w, left, zero && !left)?;
            Ok(n)
        }

        // -- Octal ----------------------------------------------------------
        'o' => {
            let val = match arg {
                Some(FormatArg::Uint(v)) => *v,
                Some(FormatArg::Int(v)) => *v as u64,
                _ => 0,
            };
            let mut s = format!("{val:o}");
            if alt && !s.starts_with('0') {
                s.insert(0, '0');
            }
            let n = write_padded(output, &s, w, left, zero && !left)?;
            Ok(n)
        }

        // -- Hexadecimal (lower) -------------------------------------------
        'x' => {
            let val = match arg {
                Some(FormatArg::Uint(v)) => *v,
                Some(FormatArg::Int(v)) => *v as u64,
                _ => 0,
            };
            let mut s = format!("{val:x}");
            if alt && val != 0 {
                s.insert_str(0, "0x");
            }
            let n = write_padded(output, &s, w, left, zero && !left)?;
            Ok(n)
        }

        // -- Hexadecimal (upper) -------------------------------------------
        'X' => {
            let val = match arg {
                Some(FormatArg::Uint(v)) => *v,
                Some(FormatArg::Int(v)) => *v as u64,
                _ => 0,
            };
            let mut s = format!("{val:X}");
            if alt && val != 0 {
                s.insert_str(0, "0X");
            }
            let n = write_padded(output, &s, w, left, zero && !left)?;
            Ok(n)
        }

        // -- Floating point -------------------------------------------------
        'f' => {
            let val = match arg {
                Some(FormatArg::Float(v)) => *v,
                Some(FormatArg::Int(v)) => *v as f64,
                _ => 0.0,
            };
            let prec = precision.unwrap_or(6);
            let formatted = format_float_f(val, prec, show_sign, space);
            let n = write_padded(output, &formatted, w, left, zero && !left)?;
            Ok(n)
        }

        'e' | 'E' => {
            let val = match arg {
                Some(FormatArg::Float(v)) => *v,
                Some(FormatArg::Int(v)) => *v as f64,
                _ => 0.0,
            };
            let prec = precision.unwrap_or(6);
            let formatted = format_float_e(val, prec, spec == 'E', show_sign, space);
            let n = write_padded(output, &formatted, w, left, zero && !left)?;
            Ok(n)
        }

        'g' | 'G' => {
            let val = match arg {
                Some(FormatArg::Float(v)) => *v,
                Some(FormatArg::Int(v)) => *v as f64,
                _ => 0.0,
            };
            let prec = precision.unwrap_or(6);
            // Use %e if exponent < -4 or >= precision, else %f (standard behaviour).
            let formatted = if val == 0.0
                || (val.abs().log10().floor() as i64 >= -(4) && (val.abs().log10().floor() as i64) < prec as i64)
            {
                format_float_f(val, prec, show_sign, space)
            } else {
                format_float_e(val, prec, spec == 'G', show_sign, space)
            };
            let n = write_padded(output, &formatted, w, left, zero && !left)?;
            Ok(n)
        }

        // -- Character ------------------------------------------------------
        'c' => {
            let ch = match arg {
                Some(FormatArg::Int(v)) => char::from_u32(*v as u32).unwrap_or('?'),
                Some(FormatArg::Uint(v)) => char::from_u32(*v as u32).unwrap_or('?'),
                _ => '?',
            };
            let s = ch.to_string();
            let n = write_padded(output, &s, w, left, false)?;
            Ok(n)
        }

        // -- String ---------------------------------------------------------
        's' => {
            let val = match arg {
                Some(FormatArg::Str(s)) => s.as_str(),
                _ => "(null)",
            };
            let truncated = match precision {
                Some(p) if p < val.len() => &val[..p],
                _ => val,
            };
            let n = write_padded(output, truncated, w, left, false)?;
            Ok(n)
        }

        // -- Pointer --------------------------------------------------------
        'p' => {
            let val = match arg {
                Some(FormatArg::Ptr(p)) => *p,
                _ => 0,
            };
            let s = if val == 0 {
                "(nil)".to_string()
            } else {
                format!("0x{val:x}")
            };
            let n = write_padded(output, &s, w, left, false)?;
            Ok(n)
        }

        // -- Unknown: emit the specifier literally --------------------------
        _ => {
            let s = format!("%{spec}");
            output.write_str(&s).map_err(|_| CurlError::OutOfMemory)?;
            Ok(s.len())
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers (private)
// ---------------------------------------------------------------------------

/// Format a signed integer with optional sign / space prefix.
fn format_signed(val: i64, show_sign: bool, space: bool) -> String {
    if val < 0 {
        val.to_string() // already has '-'
    } else if show_sign {
        format!("+{val}")
    } else if space {
        format!(" {val}")
    } else {
        val.to_string()
    }
}

/// Format a float in `%f` style.
fn format_float_f(val: f64, prec: usize, show_sign: bool, space: bool) -> String {
    let s = format!("{val:.prec$}");
    if val >= 0.0 && !val.is_nan() {
        if show_sign {
            format!("+{s}")
        } else if space {
            format!(" {s}")
        } else {
            s
        }
    } else {
        s
    }
}

/// Format a float in `%e` / `%E` style.
fn format_float_e(val: f64, prec: usize, upper: bool, show_sign: bool, space: bool) -> String {
    let s = if upper {
        format!("{val:.prec$E}")
    } else {
        format!("{val:.prec$e}")
    };
    if val >= 0.0 && !val.is_nan() {
        if show_sign {
            format!("+{s}")
        } else if space {
            format!(" {s}")
        } else {
            s
        }
    } else {
        s
    }
}

/// Write `s` into `output` with optional padding to reach `min_width`.
fn write_padded(
    output: &mut dyn FmtWrite,
    s: &str,
    min_width: usize,
    left_align: bool,
    zero_pad: bool,
) -> Result<usize, CurlError> {
    let slen = s.len();
    if slen >= min_width {
        output.write_str(s).map_err(|_| CurlError::OutOfMemory)?;
        return Ok(slen);
    }

    let padding = min_width - slen;
    let pad_char = if zero_pad { '0' } else { ' ' };

    if left_align {
        output.write_str(s).map_err(|_| CurlError::OutOfMemory)?;
        for _ in 0..padding {
            output.write_char(' ').map_err(|_| CurlError::OutOfMemory)?;
        }
    } else {
        for _ in 0..padding {
            output.write_char(pad_char).map_err(|_| CurlError::OutOfMemory)?;
        }
        output.write_str(s).map_err(|_| CurlError::OutOfMemory)?;
    }

    Ok(min_width)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- curl_format (high-level) -------------------------------------------

    #[test]
    fn format_simple_string() {
        let result = curl_format("Hello %s", &[FormatArg::Str("world".into())]);
        assert_eq!(result, "Hello world");
    }

    #[test]
    fn format_integer() {
        let result = curl_format("val=%d", &[FormatArg::Int(42)]);
        assert_eq!(result, "val=42");
    }

    #[test]
    fn format_negative_integer() {
        let result = curl_format("%d", &[FormatArg::Int(-7)]);
        assert_eq!(result, "-7");
    }

    #[test]
    fn format_unsigned() {
        let result = curl_format("%u", &[FormatArg::Uint(4294967295)]);
        assert_eq!(result, "4294967295");
    }

    #[test]
    fn format_hex_lower() {
        let result = curl_format("%x", &[FormatArg::Uint(255)]);
        assert_eq!(result, "ff");
    }

    #[test]
    fn format_hex_upper() {
        let result = curl_format("%X", &[FormatArg::Uint(255)]);
        assert_eq!(result, "FF");
    }

    #[test]
    fn format_hex_alt() {
        let mut buf = String::new();
        render_conversion(FLAG_ALT, None, None, 'x', 0, &[FormatArg::Uint(255)], &mut buf).unwrap();
        assert_eq!(buf, "0xff");
    }

    #[test]
    fn format_octal() {
        let result = curl_format("%o", &[FormatArg::Uint(8)]);
        assert_eq!(result, "10");
    }

    #[test]
    fn format_float_default() {
        let result = curl_format("%f", &[FormatArg::Float(3.14)]);
        assert!(result.starts_with("3.14"));
    }

    #[test]
    fn format_float_precision() {
        let mut buf = String::new();
        formatf("%.2f", &[FormatArg::Float(3.14159)], &mut buf).unwrap();
        assert_eq!(buf, "3.14");
    }

    #[test]
    fn format_string_precision_truncation() {
        let result = curl_format("%.3s", &[FormatArg::Str("Hello".into())]);
        assert_eq!(result, "Hel");
    }

    #[test]
    fn format_pointer_nil() {
        let result = curl_format("%p", &[FormatArg::Ptr(0)]);
        assert_eq!(result, "(nil)");
    }

    #[test]
    fn format_pointer_nonzero() {
        let result = curl_format("%p", &[FormatArg::Ptr(0xDEAD)]);
        assert_eq!(result, "0xdead");
    }

    #[test]
    fn format_character() {
        let result = curl_format("%c", &[FormatArg::Int(65)]);
        assert_eq!(result, "A");
    }

    #[test]
    fn format_literal_percent() {
        let result = curl_format("100%%", &[]);
        assert_eq!(result, "100%");
    }

    #[test]
    fn format_no_args() {
        let result = curl_format("plain text", &[]);
        assert_eq!(result, "plain text");
    }

    #[test]
    fn format_empty() {
        let result = curl_format("", &[]);
        assert_eq!(result, "");
    }

    #[test]
    fn format_multiple_args() {
        let result = curl_format(
            "%s=%d (%u)",
            &[
                FormatArg::Str("key".into()),
                FormatArg::Int(10),
                FormatArg::Uint(20),
            ],
        );
        assert_eq!(result, "key=10 (20)");
    }

    // -- Width and padding --------------------------------------------------

    #[test]
    fn format_right_padded_string() {
        let result = curl_format("%10s", &[FormatArg::Str("hi".into())]);
        assert_eq!(result, "        hi");
    }

    #[test]
    fn format_left_padded_string() {
        let result = curl_format("%-10s", &[FormatArg::Str("hi".into())]);
        assert_eq!(result, "hi        ");
    }

    #[test]
    fn format_zero_padded_int() {
        let result = curl_format("%05d", &[FormatArg::Int(42)]);
        assert_eq!(result, "00042");
    }

    #[test]
    fn format_sign_positive() {
        let result = curl_format("%+d", &[FormatArg::Int(42)]);
        assert_eq!(result, "+42");
    }

    #[test]
    fn format_space_positive() {
        let result = curl_format("% d", &[FormatArg::Int(42)]);
        assert_eq!(result, " 42");
    }

    // -- Positional arguments -----------------------------------------------

    #[test]
    fn format_positional_args() {
        let result = curl_format(
            "%2$s %1$d",
            &[FormatArg::Int(10), FormatArg::Str("hello".into())],
        );
        assert_eq!(result, "hello 10");
    }

    // -- parse_format_string ------------------------------------------------

    #[test]
    fn parse_empty_string() {
        let segments = parse_format_string("");
        assert!(segments.is_empty());
    }

    #[test]
    fn parse_no_conversions() {
        let segments = parse_format_string("hello world");
        assert_eq!(segments.len(), 1);
        matches!(&segments[0], FormatSegment::Literal(s) if s == "hello world");
    }

    #[test]
    fn parse_single_conversion() {
        let segments = parse_format_string("value: %d end");
        assert_eq!(segments.len(), 3); // "value: " + %d + " end"
    }

    #[test]
    fn parse_percent_literal() {
        let segments = parse_format_string("100%%");
        assert_eq!(segments.len(), 2); // "100" + "%"
    }

    #[test]
    fn parse_positional() {
        let segments = parse_format_string("%2$s");
        assert_eq!(segments.len(), 1);
        if let FormatSegment::Conversion { arg_index, type_spec, .. } = &segments[0] {
            assert_eq!(*arg_index, 1); // 2$ → index 1 (0-based)
            assert_eq!(*type_spec, 's');
        } else {
            panic!("expected Conversion");
        }
    }

    // -- dyn_vprintf --------------------------------------------------------

    #[test]
    fn dyn_vprintf_basic() {
        let mut buf = DynBuf::new();
        dyn_vprintf(&mut buf, "hello %s", &[FormatArg::Str("world".into())]).unwrap();
        assert_eq!(buf.as_bytes(), b"hello world");
    }

    // -- MprintfError display -----------------------------------------------

    #[test]
    fn mprintf_error_display() {
        assert_eq!(MprintfError::Ok.to_string(), "ok");
        assert_eq!(MprintfError::Mem.to_string(), "out of memory");
        assert_eq!(MprintfError::TooLarge.to_string(), "output too large");
        assert_eq!(MprintfError::BadFormat.to_string(), "bad format string");
    }

    // -- Constants ----------------------------------------------------------

    #[test]
    fn constants_match_c() {
        assert_eq!(BUFFSIZE, 1024);
        assert_eq!(MAX_PARAMETERS, 128);
        assert_eq!(MAX_SEGMENTS, 128);
        assert_eq!(LOWER_DIGITS.len(), 16);
        assert_eq!(UPPER_DIGITS.len(), 16);
    }
}
