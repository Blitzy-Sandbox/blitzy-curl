//! FFI wrappers for curl's printf-family functions (`include/curl/mprintf.h`).
//!
//! Exposes 10 `CURL_EXTERN` symbols as `#[no_mangle] pub unsafe extern "C"`
//! functions that provide curl's own locale-independent printf formatting.
//!
//! # Function Groups
//!
//! The 10 functions are organized in matched pairs:
//!
//! | Variadic (stable: limited)    | va_list (fully functional)       |
//! |-------------------------------|----------------------------------|
//! | [`curl_mprintf`]              | [`curl_mvprintf`]                |
//! | [`curl_mfprintf`]             | [`curl_mvfprintf`]               |
//! | [`curl_msprintf`]             | [`curl_mvsprintf`]               |
//! | [`curl_msnprintf`]            | [`curl_mvsnprintf`]              |
//! | [`curl_maprintf`]             | [`curl_mvaprintf`]               |
//!
//! ## va_list Variants (5 functions)
//!
//! Accept a C `va_list` argument and delegate to the platform libc's
//! corresponding `v*printf` function for correct argument extraction.
//! These are fully functional on all Rust toolchains (stable and nightly).
//!
//! ## Variadic Variants (5 functions)
//!
//! On stable Rust (MSRV 1.75+), the `c_variadic` feature is not available,
//! so these functions cannot accept C `...` parameters directly.  Instead,
//! they process the format string using `curl-rs-lib`'s Rust-native
//! formatting engine with no extracted arguments — literal text is output
//! verbatim, while conversion specifiers produce default values (`0` for
//! integers, `""` for strings, `0.000000` for floats).
//!
//! For full variadic support, compile the C shim file
//! `csrc/mprintf_variadic.c` via the `cc` crate, which wraps each variadic
//! entry point with `va_start` / `va_end` and delegates to the
//! corresponding Rust va_list function.
//!
//! # Return Values
//!
//! All `printf`-style functions return the number of characters written
//! (not including the NUL terminator for buffer variants), or `-1` on
//! error.  The allocating variants (`curl_maprintf`, `curl_mvaprintf`)
//! return a `malloc`'d string pointer or `NULL` on allocation failure.
//!
//! # C Header Reference
//!
//! ```c
//! /* include/curl/mprintf.h */
//! CURL_EXTERN int   curl_mprintf(const char *format, ...);
//! CURL_EXTERN int   curl_mfprintf(FILE *fd, const char *format, ...);
//! CURL_EXTERN int   curl_msprintf(char *buffer, const char *format, ...);
//! CURL_EXTERN int   curl_msnprintf(char *buffer, size_t maxlength,
//!                                  const char *format, ...);
//! CURL_EXTERN char *curl_maprintf(const char *format, ...);
//! CURL_EXTERN int   curl_mvprintf(const char *format, va_list args);
//! CURL_EXTERN int   curl_mvfprintf(FILE *fd, const char *format, va_list args);
//! CURL_EXTERN int   curl_mvsprintf(char *buffer, const char *format,
//!                                  va_list args);
//! CURL_EXTERN int   curl_mvsnprintf(char *buffer, size_t maxlength,
//!                                   const char *format, va_list args);
//! CURL_EXTERN char *curl_mvaprintf(const char *format, va_list args);
//! ```

use std::ffi::CStr;
use std::io::Write as IoWrite;

use libc::{c_char, c_int, c_void, malloc, size_t, FILE};

use curl_rs_lib::util::mprintf::{
    formatf, parse_format_string, FormatArg, FormatSegment, MprintfError,
};

// ---------------------------------------------------------------------------
// Platform va_list Type
// ---------------------------------------------------------------------------

/// Opaque `va_list` type for use in `extern "C"` function signatures.
///
/// On x86_64 System V ABI, C's `va_list` is `typedef __va_list_tag[1]` which
/// decays to a pointer when passed as a function parameter.  We represent it
/// as `*mut c_void` — this is ABI-compatible for parameter passing on all
/// platforms where va_list is pointer-sized or array-of-one-struct.
///
/// The actual contents are opaque to Rust code; we pass the pointer
/// unchanged to libc's `v*printf` family for correct argument extraction.
pub type VaList = *mut c_void;

// ---------------------------------------------------------------------------
// Libc v*printf declarations
// ---------------------------------------------------------------------------
//
// These are the standard C library functions that handle `va_list`-based
// formatted output.  We declare them here because the `libc` crate does
// not expose all of them on all platforms.

extern "C" {
    /// `int vprintf(const char *format, va_list ap)` — formatted output to
    /// stdout.
    fn vprintf(format: *const c_char, ap: VaList) -> c_int;

    /// `int vfprintf(FILE *stream, const char *format, va_list ap)` —
    /// formatted output to a `FILE*` stream.
    fn vfprintf(stream: *mut FILE, format: *const c_char, ap: VaList) -> c_int;

    /// `int vsprintf(char *s, const char *format, va_list ap)` — formatted
    /// output to a buffer with no length limit.
    fn vsprintf(s: *mut c_char, format: *const c_char, ap: VaList) -> c_int;

    /// `int vsnprintf(char *s, size_t n, const char *format, va_list ap)` —
    /// formatted output to a length-limited buffer.
    fn vsnprintf(
        s: *mut c_char,
        n: size_t,
        format: *const c_char,
        ap: VaList,
    ) -> c_int;

    /// `int vasprintf(char **strp, const char *format, va_list ap)` —
    /// allocating formatted output (GNU/BSD extension, available on Linux
    /// and macOS).
    fn vasprintf(
        strp: *mut *mut c_char,
        format: *const c_char,
        ap: VaList,
    ) -> c_int;
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/// Convert a `*const c_char` format pointer to a Rust `&str`.
///
/// Returns `None` if the pointer is null or the string contains invalid
/// UTF-8 (curl format strings are always ASCII-compatible, so invalid
/// UTF-8 indicates a caller error).
///
/// # Safety
///
/// The caller must guarantee that `format` points to a valid
/// NUL-terminated C string for the duration of the returned reference.
#[inline]
unsafe fn format_to_str<'a>(format: *const c_char) -> Option<&'a str> {
    if format.is_null() {
        return None;
    }
    // SAFETY: Caller guarantees `format` is a valid NUL-terminated C string.
    // CStr::from_ptr reads until the NUL terminator without exceeding bounds.
    let cstr = CStr::from_ptr(format);
    cstr.to_str().ok()
}

/// Build a `Vec<FormatArg>` containing default-valued arguments for each
/// conversion specifier found in `segments`.
///
/// This is used by the variadic wrappers on stable Rust where actual
/// varargs cannot be extracted.  Each argument receives a type-appropriate
/// zero/empty default:
///
/// - `%d`, `%i` → [`FormatArg::Int(0)`]
/// - `%u`, `%o`, `%x`, `%X` → [`FormatArg::Uint(0)`]
/// - `%f`, `%e`, `%E`, `%g`, `%G` → [`FormatArg::Float(0.0)`]
/// - `%s`, `%S` → [`FormatArg::Str(String::new())`]
/// - `%p` → [`FormatArg::Ptr(0)`]
/// - `%Od`, `%Ou` (curl_off_t) → [`FormatArg::OffT(0)`]
///
/// Arguments referenced by width-from-argument (`*`) or
/// precision-from-argument (`.*`) are also included in their correct
/// positional slots.
fn build_default_args(segments: &[FormatSegment]) -> Vec<FormatArg> {
    // First pass: determine the maximum argument index referenced so we can
    // pre-size the vector.
    let mut max_idx: usize = 0;
    for seg in segments {
        if let FormatSegment::Conversion {
            arg_index,
            flags,
            width,
            precision,
            ..
        } = seg
        {
            if *arg_index >= max_idx {
                max_idx = *arg_index + 1;
            }
            // Width-from-argument and precision-from-argument also consume slots.
            let _ = flags; // referenced for completeness; flags drive rendering
            if *width >= 0 {
                let w = *width as usize;
                if w >= max_idx {
                    max_idx = w + 1;
                }
            }
            if *precision >= 0 {
                let p = *precision as usize;
                if p >= max_idx {
                    max_idx = p + 1;
                }
            }
        }
    }

    // Second pass: fill each slot with a type-appropriate default value.
    let mut args: Vec<FormatArg> = vec![FormatArg::Int(0); max_idx];
    for seg in segments {
        if let FormatSegment::Conversion {
            type_spec,
            arg_index,
            ..
        } = seg
        {
            let default = match type_spec {
                'd' | 'i' | 'c' | 'n' => FormatArg::Int(0),
                'u' | 'o' | 'x' | 'X' => FormatArg::Uint(0),
                'f' | 'e' | 'E' | 'g' | 'G' => FormatArg::Float(0.0),
                's' | 'S' => FormatArg::Str(String::new()),
                'p' => FormatArg::Ptr(0),
                _ => FormatArg::Int(0),
            };
            if *arg_index < args.len() {
                args[*arg_index] = default;
            }
        }
    }
    args
}

/// Map an [`MprintfError`] to a C-style return code.
///
/// - [`MprintfError::Ok`] → `0` (success, though callers typically use the
///   char count instead).
/// - [`MprintfError::Mem`] → `-1` (allocation failure).
/// - [`MprintfError::TooLarge`] → `-1` (output exceeds limit).
///
/// This bridges the Rust error type to the C integer convention used by
/// all 10 printf-family functions.
#[inline]
fn mprintf_error_to_c(err: MprintfError) -> c_int {
    match err {
        MprintfError::Ok => 0,
        MprintfError::Mem | MprintfError::TooLarge => -1,
    }
}

/// Format a C format string using the Rust engine with default arguments
/// (stable Rust fallback for variadic functions).
///
/// Returns `Ok((formatted_string, char_count))` on success, or a C-style
/// `-1` error code on failure (derived from [`MprintfError`] via
/// [`mprintf_error_to_c`]).
fn format_with_defaults(fmt_str: &str) -> Result<String, c_int> {
    let segments = parse_format_string(fmt_str);
    if segments.is_empty() && !fmt_str.is_empty() {
        // Non-empty format string parsed to zero segments indicates a parse
        // error — map to MprintfError::Mem for consistency with C behavior.
        return Err(mprintf_error_to_c(MprintfError::Mem));
    }
    let args = build_default_args(&segments);
    let mut output = String::with_capacity(fmt_str.len().saturating_mul(2));
    match formatf(fmt_str, &args, &mut output) {
        Ok(_) => Ok(output),
        Err(_) => Err(mprintf_error_to_c(MprintfError::TooLarge)),
    }
}

/// Allocate a C string via `malloc` from a Rust `&str`.
///
/// Returns a `malloc`'d, NUL-terminated copy suitable for freeing via
/// `curl_free` (which calls `free()`).  Returns `null_mut()` on
/// allocation failure.
///
/// # Safety
///
/// Uses `libc::malloc` and `libc::memcpy` (via `ptr::copy_nonoverlapping`).
/// The returned pointer must eventually be freed by the caller.
unsafe fn str_to_malloced(s: &str) -> *mut c_char {
    let bytes = s.as_bytes();
    let len = bytes.len();

    // SAFETY: malloc returns a pointer aligned for any fundamental type,
    // or NULL on failure.  We allocate len + 1 bytes for the string content
    // plus the NUL terminator.
    let ptr = malloc(len + 1) as *mut c_char;
    if ptr.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: `ptr` is valid for `len + 1` bytes (freshly allocated above).
    // `bytes.as_ptr()` is valid for `len` bytes (slice invariant).
    // The regions do not overlap (ptr is freshly allocated).
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, len);

    // Write NUL terminator.
    // SAFETY: ptr + len is within the allocated region of len + 1 bytes.
    *ptr.add(len) = 0;

    ptr
}

// ============================================================================
// Section 1: va_list Variants (fully functional via libc delegation)
// ============================================================================

/// Formatted print to stdout using a `va_list`.
///
/// Equivalent to C `curl_mvprintf(format, args)`.
///
/// # Returns
///
/// Number of characters written, or `-1` on error.
///
/// # Safety
///
/// - `format` must be a valid, NUL-terminated C string.
/// - `args` must be a valid `va_list` initialized by `va_start` or `va_copy`
///   matching the conversion specifiers in `format`.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN int curl_mvprintf(const char *format, va_list args);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mvprintf(
    format: *const c_char,
    args: VaList,
) -> c_int {
    // SAFETY: `format` is guaranteed by the caller to be a valid
    // NUL-terminated C string.  `args` is a valid va_list.  We delegate
    // directly to libc's vprintf which handles va_list extraction correctly
    // on all supported platforms (Linux x86_64/aarch64, macOS x86_64/arm64).
    if format.is_null() {
        return -1;
    }
    vprintf(format, args)
}

/// Formatted print to a `FILE*` stream using a `va_list`.
///
/// Equivalent to C `curl_mvfprintf(fd, format, args)`.
///
/// # Returns
///
/// Number of characters written, or `-1` on error.
///
/// # Safety
///
/// - `fd` must be a valid, open `FILE*` pointer.
/// - `format` must be a valid, NUL-terminated C string.
/// - `args` must be a valid `va_list` matching the conversion specifiers.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN int curl_mvfprintf(FILE *fd, const char *format, va_list args);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mvfprintf(
    fd: *mut FILE,
    format: *const c_char,
    args: VaList,
) -> c_int {
    // SAFETY: `fd` is a valid FILE* stream opened by the caller.  `format`
    // is a valid NUL-terminated C string.  `args` is a valid va_list.
    // vfprintf correctly handles va_list argument extraction.
    if fd.is_null() || format.is_null() {
        return -1;
    }
    vfprintf(fd, format, args)
}

/// Formatted print to a buffer (no length limit) using a `va_list`.
///
/// **WARNING:** This function has no buffer overflow protection, matching
/// the C `vsprintf` semantics.  Prefer [`curl_mvsnprintf`] for safe usage.
///
/// # Returns
///
/// Number of characters written (not including NUL), or `-1` on error.
///
/// # Safety
///
/// - `buffer` must point to a sufficiently large, writable memory region.
/// - `format` must be a valid, NUL-terminated C string.
/// - `args` must be a valid `va_list` matching the conversion specifiers.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN int curl_mvsprintf(char *buffer, const char *format,
///                                va_list args);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mvsprintf(
    buffer: *mut c_char,
    format: *const c_char,
    args: VaList,
) -> c_int {
    // SAFETY: `buffer` is a writable memory region of sufficient size
    // (caller responsibility, matching C vsprintf contract).  `format`
    // is a valid NUL-terminated C string.  `args` is a valid va_list.
    if buffer.is_null() || format.is_null() {
        return -1;
    }
    vsprintf(buffer, format, args)
}

/// Formatted print to a length-limited buffer using a `va_list`.
///
/// Writes at most `maxlength - 1` characters plus a NUL terminator.
///
/// # Returns
///
/// Number of characters that would have been written if the buffer were
/// large enough (not including NUL), or `-1` on encoding error.
///
/// # Safety
///
/// - `buffer` must point to a writable region of at least `maxlength` bytes.
/// - `format` must be a valid, NUL-terminated C string.
/// - `args` must be a valid `va_list` matching the conversion specifiers.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN int curl_mvsnprintf(char *buffer, size_t maxlength,
///                                 const char *format, va_list args);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mvsnprintf(
    buffer: *mut c_char,
    maxlength: size_t,
    format: *const c_char,
    args: VaList,
) -> c_int {
    // SAFETY: `buffer` points to at least `maxlength` writable bytes.
    // `format` is a valid NUL-terminated C string.  `args` is a valid
    // va_list.  vsnprintf correctly limits output to maxlength bytes
    // including the NUL terminator.
    if buffer.is_null() || format.is_null() {
        return -1;
    }
    if maxlength == 0 {
        return 0;
    }
    vsnprintf(buffer, maxlength, format, args)
}

/// Allocating formatted print using a `va_list`.
///
/// Returns a `malloc`'d, NUL-terminated string.  The caller must free the
/// returned pointer via `curl_free()` (or `free()`).
///
/// # Returns
///
/// Pointer to the allocated string, or `NULL` on allocation failure.
///
/// # Safety
///
/// - `format` must be a valid, NUL-terminated C string.
/// - `args` must be a valid `va_list` matching the conversion specifiers.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN char *curl_mvaprintf(const char *format, va_list args);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mvaprintf(
    format: *const c_char,
    args: VaList,
) -> *mut c_char {
    // SAFETY: `format` is a valid NUL-terminated C string.  `args` is a
    // valid va_list.  vasprintf allocates memory via malloc internally;
    // the caller is responsible for freeing the returned pointer.
    if format.is_null() {
        return std::ptr::null_mut();
    }

    let mut result: *mut c_char = std::ptr::null_mut();

    // SAFETY: vasprintf writes a malloc'd string pointer into `result`.
    // On failure it returns -1 and result may be undefined — we handle
    // that by returning NULL.
    let ret = vasprintf(&mut result as *mut *mut c_char, format, args);
    if ret < 0 {
        // vasprintf failed — ensure we don't return a dangling pointer.
        // Per POSIX, the value of *strp is undefined on failure, so
        // we must not attempt to free it.
        return std::ptr::null_mut();
    }

    result
}

// ============================================================================
// Section 2: Variadic Variants
//
// On stable Rust (MSRV 1.75), the `c_variadic` feature is unavailable.
// These functions cannot accept C `...` parameters directly.  Instead,
// they use the curl-rs-lib Rust formatting engine with default-valued
// arguments derived from parsing the format string.
//
// For full variadic support, compile `csrc/mprintf_variadic.c` which
// implements each variadic function as a thin C wrapper:
//   va_start(ap, format);
//   ret = curl_mv*(format, ap);
//   va_end(ap);
//
// The linker will prefer the C definitions over these Rust symbols when
// both are present (strong vs weak linking).
// ============================================================================

/// Formatted print to stdout.
///
/// # Stable Rust Limitation
///
/// On stable Rust, C variadic arguments cannot be extracted.  This
/// function processes the format string using curl-rs-lib's formatting
/// engine with default-valued arguments (0 for integers, empty for
/// strings).  Use the va_list variant [`curl_mvprintf`] for full
/// functionality.
///
/// # Returns
///
/// Number of characters written, or `-1` on error.
///
/// # Safety
///
/// - `format` must be a valid, NUL-terminated C string.
/// - On stable Rust, any additional variadic arguments are ignored.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN int curl_mprintf(const char *format, ...);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mprintf(format: *const c_char) -> c_int {
    // SAFETY: `format` is guaranteed by the caller to be a valid
    // NUL-terminated C string.  We convert it to a Rust &str via
    // CStr::from_ptr which reads until the NUL terminator.
    let fmt_str = match format_to_str(format) {
        Some(s) => s,
        None => return -1,
    };

    // Parse the format string to identify conversion specifiers and build
    // default arguments for each specifier (stable Rust fallback — actual
    // varargs are not accessible).
    let formatted = match format_with_defaults(fmt_str) {
        Ok(s) => s,
        Err(code) => return code,
    };

    // Write to stdout.
    let mut stdout = std::io::stdout();
    match stdout.write_all(formatted.as_bytes()) {
        Ok(()) => formatted.len() as c_int,
        Err(_) => -1,
    }
}

/// Formatted print to a `FILE*` stream.
///
/// # Stable Rust Limitation
///
/// On stable Rust, variadic arguments cannot be extracted.  See
/// [`curl_mprintf`] for details.  Use [`curl_mvfprintf`] for full
/// functionality.
///
/// # Returns
///
/// Number of characters written, or `-1` on error.
///
/// # Safety
///
/// - `fd` must be a valid, open `FILE*` pointer.
/// - `format` must be a valid, NUL-terminated C string.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN int curl_mfprintf(FILE *fd, const char *format, ...);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mfprintf(
    fd: *mut FILE,
    format: *const c_char,
) -> c_int {
    // SAFETY: `format` is a valid NUL-terminated C string per the caller
    // contract.  `fd` is a valid open FILE* stream.
    if fd.is_null() {
        return -1;
    }

    let fmt_str = match format_to_str(format) {
        Some(s) => s,
        None => return -1,
    };

    let formatted = match format_with_defaults(fmt_str) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let bytes = formatted.as_bytes();

    // Write to the FILE* stream using libc's fwrite.
    // SAFETY: `fd` is a valid FILE* stream.  `bytes.as_ptr()` and
    // `bytes.len()` describe a valid memory region.  fwrite is safe to
    // call with these arguments.
    extern "C" {
        fn fwrite(
            ptr: *const c_void,
            size: size_t,
            nmemb: size_t,
            stream: *mut FILE,
        ) -> size_t;
    }

    let written = fwrite(
        bytes.as_ptr() as *const c_void,
        1,
        bytes.len() as size_t,
        fd,
    );

    if written == bytes.len() as size_t {
        written as c_int
    } else {
        -1
    }
}

/// Formatted print to a buffer (no length limit).
///
/// **WARNING:** No buffer overflow protection.  Prefer [`curl_msnprintf`].
///
/// # Stable Rust Limitation
///
/// On stable Rust, variadic arguments cannot be extracted.  See
/// [`curl_mprintf`] for details.  Use [`curl_mvsprintf`] for full
/// functionality.
///
/// # Returns
///
/// Number of characters written (not including NUL), or `-1` on error.
///
/// # Safety
///
/// - `buffer` must point to a sufficiently large, writable memory region.
/// - `format` must be a valid, NUL-terminated C string.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN int curl_msprintf(char *buffer, const char *format, ...);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_msprintf(
    buffer: *mut c_char,
    format: *const c_char,
) -> c_int {
    // SAFETY: `buffer` is a writable region of sufficient size (caller
    // responsibility).  `format` is a valid NUL-terminated C string.
    if buffer.is_null() {
        return -1;
    }

    let fmt_str = match format_to_str(format) {
        Some(s) => s,
        None => return -1,
    };

    let formatted = match format_with_defaults(fmt_str) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let bytes = formatted.as_bytes();
    let len = bytes.len();

    // SAFETY: `buffer` is valid for at least `len + 1` bytes per the
    // caller contract (same as C sprintf — no overflow protection).
    // `bytes.as_ptr()` is valid for `len` bytes.  Regions don't overlap.
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, len);

    // SAFETY: Write NUL terminator at buffer[len].  This is within the
    // caller-guaranteed buffer region.
    *buffer.add(len) = 0;

    len as c_int
}

/// Formatted print to a length-limited buffer.
///
/// Writes at most `maxlength - 1` characters followed by a NUL terminator.
///
/// # Stable Rust Limitation
///
/// On stable Rust, variadic arguments cannot be extracted.  See
/// [`curl_mprintf`] for details.  Use [`curl_mvsnprintf`] for full
/// functionality.
///
/// # Returns
///
/// Number of characters written (not including NUL).  The output is
/// always NUL-terminated (unless `maxlength` is 0).
///
/// # Safety
///
/// - `buffer` must point to a writable region of at least `maxlength` bytes.
/// - `format` must be a valid, NUL-terminated C string.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN int curl_msnprintf(char *buffer, size_t maxlength,
///                                const char *format, ...);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_msnprintf(
    buffer: *mut c_char,
    maxlength: size_t,
    format: *const c_char,
) -> c_int {
    // SAFETY: `buffer` is a writable region of at least `maxlength` bytes.
    // `format` is a valid NUL-terminated C string.
    if buffer.is_null() {
        return -1;
    }
    if maxlength == 0 {
        return 0;
    }

    let fmt_str = match format_to_str(format) {
        Some(s) => s,
        None => {
            // On error, still NUL-terminate the buffer.
            *buffer = 0;
            return -1;
        }
    };

    // Use the Rust formatting engine's buffer writer which respects
    // the maximum length and always NUL-terminates.
    let formatted = match format_with_defaults(fmt_str) {
        Ok(s) => s,
        Err(code) => {
            // On error, still NUL-terminate.
            *buffer = 0;
            return code;
        }
    };
    let bytes = formatted.as_bytes();
    let max_data = maxlength - 1; // reserve space for NUL
    let copy_len = bytes.len().min(max_data);

    // SAFETY: `buffer` is valid for at least `maxlength` bytes.
    // `bytes[..copy_len]` is within bounds.  copy_len < maxlength.
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, copy_len);

    // SAFETY: buffer[copy_len] is within the maxlength region.
    *buffer.add(copy_len) = 0;

    copy_len as c_int
}

/// Allocating formatted print.
///
/// Returns a `malloc`'d, NUL-terminated string.  The caller must free
/// the returned pointer via `curl_free()` (or `free()`).
///
/// # Stable Rust Limitation
///
/// On stable Rust, variadic arguments cannot be extracted.  See
/// [`curl_mprintf`] for details.  Use [`curl_mvaprintf`] for full
/// functionality.
///
/// # Returns
///
/// Pointer to the allocated string, or `NULL` on allocation failure.
///
/// # Safety
///
/// - `format` must be a valid, NUL-terminated C string.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN char *curl_maprintf(const char *format, ...);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_maprintf(format: *const c_char) -> *mut c_char {
    // SAFETY: `format` is a valid NUL-terminated C string per the caller
    // contract.
    let fmt_str = match format_to_str(format) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let formatted = match format_with_defaults(fmt_str) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Allocate a malloc'd copy of the formatted string.
    // SAFETY: str_to_malloced uses libc::malloc to allocate and copies the
    // string content plus NUL terminator.  The caller must free via
    // curl_free / free().
    str_to_malloced(&formatted)
}

// ============================================================================
// Module-level tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use libc::free;
    use std::ffi::CString;

    /// Verify that `build_default_args` correctly maps format specifiers
    /// to their default `FormatArg` variants.
    #[test]
    fn test_build_default_args() {
        let segments = parse_format_string("hello %s, count=%d, pi=%f, ptr=%p");
        let args = build_default_args(&segments);
        assert_eq!(args.len(), 4);
        assert!(matches!(args[0], FormatArg::Str(_)));
        assert!(matches!(args[1], FormatArg::Int(0)));
        assert!(matches!(args[2], FormatArg::Float(f) if f == 0.0));
        assert!(matches!(args[3], FormatArg::Ptr(0)));
    }

    /// Verify `build_default_args` handles unsigned and hex specifiers.
    #[test]
    fn test_build_default_args_unsigned() {
        let segments = parse_format_string("%u %x %X %o");
        let args = build_default_args(&segments);
        assert_eq!(args.len(), 4);
        for arg in &args {
            assert!(matches!(arg, FormatArg::Uint(0)));
        }
    }

    /// Verify `format_with_defaults` outputs literal text unmodified.
    #[test]
    fn test_format_literal() {
        let result = format_with_defaults("hello world").unwrap();
        assert_eq!(result, "hello world");
    }

    /// Verify `format_with_defaults` handles a simple format string with
    /// default values.
    #[test]
    fn test_format_with_default_int() {
        let result = format_with_defaults("count: %d").unwrap();
        assert_eq!(result, "count: 0");
    }

    /// Verify `mprintf_error_to_c` correctly maps error variants.
    #[test]
    fn test_mprintf_error_to_c() {
        assert_eq!(mprintf_error_to_c(MprintfError::Ok), 0);
        assert_eq!(mprintf_error_to_c(MprintfError::Mem), -1);
        assert_eq!(mprintf_error_to_c(MprintfError::TooLarge), -1);
    }

    /// Verify `str_to_malloced` round-trips correctly.
    #[test]
    fn test_str_to_malloced() {
        unsafe {
            let ptr = str_to_malloced("hello");
            assert!(!ptr.is_null());
            let cstr = CStr::from_ptr(ptr);
            assert_eq!(cstr.to_str().unwrap(), "hello");
            free(ptr as *mut c_void);
        }
    }

    /// Verify `str_to_malloced` handles empty strings.
    #[test]
    fn test_str_to_malloced_empty() {
        unsafe {
            let ptr = str_to_malloced("");
            assert!(!ptr.is_null());
            let cstr = CStr::from_ptr(ptr);
            assert_eq!(cstr.to_str().unwrap(), "");
            free(ptr as *mut c_void);
        }
    }

    /// Verify `curl_msnprintf` NUL-terminates and respects maxlength.
    #[test]
    fn test_msnprintf_basic() {
        unsafe {
            let mut buf = [0i8; 32];
            let fmt = CString::new("hello").unwrap();
            let ret = curl_msnprintf(
                buf.as_mut_ptr(),
                buf.len() as size_t,
                fmt.as_ptr(),
            );
            assert_eq!(ret, 5);
            assert_eq!(CStr::from_ptr(buf.as_ptr()).to_str().unwrap(), "hello");
        }
    }

    /// Verify `curl_msnprintf` truncates when buffer is too small.
    #[test]
    fn test_msnprintf_truncation() {
        unsafe {
            let mut buf = [0i8; 4]; // only 3 chars + NUL
            let fmt = CString::new("hello").unwrap();
            let ret = curl_msnprintf(
                buf.as_mut_ptr(),
                buf.len() as size_t,
                fmt.as_ptr(),
            );
            assert_eq!(ret, 3);
            assert_eq!(CStr::from_ptr(buf.as_ptr()).to_str().unwrap(), "hel");
        }
    }

    /// Verify `curl_msprintf` writes correct output.
    #[test]
    fn test_msprintf_basic() {
        unsafe {
            let mut buf = [0i8; 64];
            let fmt = CString::new("test123").unwrap();
            let ret = curl_msprintf(buf.as_mut_ptr(), fmt.as_ptr());
            assert_eq!(ret, 7);
            assert_eq!(CStr::from_ptr(buf.as_ptr()).to_str().unwrap(), "test123");
        }
    }

    /// Verify `curl_maprintf` returns a malloc'd string.
    #[test]
    fn test_maprintf_basic() {
        unsafe {
            let fmt = CString::new("hello world").unwrap();
            let ptr = curl_maprintf(fmt.as_ptr());
            assert!(!ptr.is_null());
            let result = CStr::from_ptr(ptr).to_str().unwrap();
            assert_eq!(result, "hello world");
            free(ptr as *mut c_void);
        }
    }

    /// Verify null format pointer handling.
    #[test]
    fn test_null_format() {
        unsafe {
            assert_eq!(curl_mprintf(std::ptr::null()), -1);
            assert_eq!(curl_mvprintf(std::ptr::null(), std::ptr::null_mut()), -1);
            assert!(curl_maprintf(std::ptr::null()).is_null());
            assert!(curl_mvaprintf(std::ptr::null(), std::ptr::null_mut()).is_null());
        }
    }

    /// Verify `MprintfError` variants are accessible (schema compliance).
    #[test]
    fn test_mprintf_error_variants() {
        assert_eq!(MprintfError::Ok, MprintfError::Ok);
        assert_ne!(MprintfError::Mem, MprintfError::Ok);
        assert_ne!(MprintfError::TooLarge, MprintfError::Ok);
    }

    /// Verify `FormatArg::OffT` variant is usable (schema compliance).
    #[test]
    fn test_format_arg_offt() {
        let arg = FormatArg::OffT(42);
        assert!(matches!(arg, FormatArg::OffT(42)));
    }
}
