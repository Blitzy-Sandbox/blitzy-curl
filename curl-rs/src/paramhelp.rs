// -----------------------------------------------------------------------
// curl-rs/src/paramhelp.rs — Parameter Validation Helpers
//
// Rust rewrite of src/tool_paramhlp.c and src/tool_paramhlp.h from curl
// 8.19.0-DEV.  Provides parameter validation, file reading, numeric
// parsing, protocol normalization, header management, and credential
// helpers for the CLI argument processing pipeline.
//
// # Source Mapping
//
// | Rust function/type     | C origin                                  |
// |------------------------|-------------------------------------------|
// | `GetOut` (re-export)   | `struct getout` in `tool_sdecls.h`        |
// | `new_getout`           | `new_getout()` in `tool_paramhlp.c:35`    |
// | `file2string`          | `file2string()` in `tool_paramhlp.c:86`   |
// | `file2memory`          | `file2memory()` in `tool_paramhlp.c:193`  |
// | `file2memory_range`    | `file2memory_range()` :120                |
// | `str2num`              | `str2num()` in `tool_paramhlp.c:206`      |
// | `str2unum`             | `str2unum()` :252                         |
// | `str2unummax`          | `str2unummax()` :273                      |
// | `str2offset`           | `str2offset()` :539                       |
// | `secs2ms`              | `secs2ms()` :297                          |
// | `oct2nummax`           | `oct2nummax()` :223                       |
// | `proto2num`            | `proto2num()` :395                        |
// | `check_protocol`       | `check_protocol()` :521                   |
// | `str2tls_max`          | `str2tls_max()` :710                      |
// | `checkpasswd`          | `checkpasswd()` :548                      |
// | `add2list`             | `add2list()` :601                         |
// | `inlist`               | `inlist()` :658                           |
// | `get_args`             | `get_args()` :673                         |
// | `ftpfilemethod`        | `ftpfilemethod()` :612                    |
// | `ftpcccmethod`         | `ftpcccmethod()` :626                     |
// | `delegation`           | `delegation()` :638                       |
// | `FtpFileMethod`        | `CURLFTPMETHOD_*` constants               |
// | `FtpCccMethod`         | `CURLFTPSSL_CCC_*` constants              |
// | `GssapiDelegation`     | `CURLGSSAPI_DELEGATION_*` constants       |
// | `MAX_USERPWDLENGTH`    | `#define MAX_USERPWDLENGTH` :547          |
//
// Zero `unsafe` blocks.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicI64, Ordering};

use anyhow::{bail, Context, Result};

use crate::config::{GlobalConfig, OperationConfig, MAX_FILE2MEMORY};
use crate::getpass::getpass_r;
use crate::libinfo::{is_proto_supported, proto_token, LibCurlInfo};
use crate::msgs::warnf;

// Re-export `GetOut` from `config.rs`.  This module is the primary
// interface for `GetOut` node management (via `new_getout`), so
// consumers import it from here for convenience.
pub use crate::config::GetOut;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a `user:password` credential string (100 KiB).
///
/// Matches the C `#define MAX_USERPWDLENGTH (100 * 1024)` in
/// `src/tool_paramhlp.c` line 547.
pub const MAX_USERPWDLENGTH: usize = 100 * 1024;

/// Maximum file size for file-to-string reads.  Mirrors the C
/// `#define MAX_FILE2STRING MAX_FILE2MEMORY`.
const MAX_FILE2STRING: usize = MAX_FILE2MEMORY;

/// Maximum number of protocols in a protocol set.
///
/// Matches the C `#define MAX_PROTOS 34`.  The Rust version uses 50
/// for headroom (matching the agent prompt specification).
const MAX_PROTOS: usize = 50;

/// Maximum byte length for the protocol list output string.
///
/// Matches the C `#define MAX_PROTOSTRING (MAX_PROTOS * 11)`.
const MAX_PROTOSTRING: usize = MAX_PROTOS * 11;

/// Size of read buffer for file I/O operations (4 KiB).
///
/// Matches the C `char buffer[4096]` used in `file2string` and
/// `file2memory_range`.
const READ_BUFFER_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// FTP file method selection for `--ftp-method`.
///
/// Maps to the C `CURLFTPMETHOD_*` constants:
/// - `CURLFTPMETHOD_MULTICWD`  → [`FtpFileMethod::MultiCwd`] (1, default)
/// - `CURLFTPMETHOD_SINGLECWD` → [`FtpFileMethod::SingleCwd`] (2)
/// - `CURLFTPMETHOD_NOCWD`     → [`FtpFileMethod::NoCwd`] (3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum FtpFileMethod {
    /// Multiple CWD commands (default).
    MultiCwd = 1,
    /// Single CWD command with full path.
    SingleCwd = 2,
    /// No CWD — use full path in FTP commands.
    NoCwd = 3,
}

/// FTP SSL CCC (Clear Command Channel) method for `--ftp-ssl-ccc-mode`.
///
/// Maps to the C `CURLFTPSSL_CCC_*` constants:
/// - `CURLFTPSSL_CCC_PASSIVE` → [`FtpCccMethod::Passive`] (1, default)
/// - `CURLFTPSSL_CCC_ACTIVE`  → [`FtpCccMethod::Active`] (2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpCccMethod {
    /// Passive CCC — wait for server to initiate (default).
    Passive = 1,
    /// Active CCC — client initiates shutdown.
    Active = 2,
}

/// GSSAPI delegation level for `--delegation`.
///
/// Maps to the C `CURLGSSAPI_DELEGATION_*` constants:
/// - `CURLGSSAPI_DELEGATION_NONE`        → [`GssapiDelegation::None`] (0)
/// - `CURLGSSAPI_DELEGATION_POLICY_FLAG` → [`GssapiDelegation::PolicyFlag`] (1)
/// - `CURLGSSAPI_DELEGATION_FLAG`        → [`GssapiDelegation::Flag`] (2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GssapiDelegation {
    /// No delegation.
    None = 0,
    /// Delegate if permitted by policy.
    PolicyFlag = 1,
    /// Always delegate (unconditional).
    Flag = 2,
}

// ---------------------------------------------------------------------------
// Static counter for GetOut node numbering
// ---------------------------------------------------------------------------

/// Monotonic counter for GetOut node numbering, matching the C static
/// variable `static int outnum = 0;` inside `new_getout()`.
///
/// Uses `AtomicI64` for thread safety (required even though the CLI is
/// single-threaded, because the library may be called from tests or
/// concurrent contexts).
static GETOUT_COUNTER: AtomicI64 = AtomicI64::new(0);

// ---------------------------------------------------------------------------
// GetOut Node Management
// ---------------------------------------------------------------------------

/// Allocates a new [`GetOut`] node, appends it to `config.url_list`, and
/// returns a mutable reference to the newly created node.
///
/// This is the Rust equivalent of C `new_getout()` in `tool_paramhlp.c`.
/// The C version:
/// 1. `calloc`s a `struct getout`
/// 2. Appends it to the `url_list` / `url_last` linked list
/// 3. Inherits `config->remote_name_all` into `node->useremote`
/// 4. Assigns a monotonically increasing `outnum`
///
/// The Rust version replaces the linked list with `Vec::push` and the
/// `calloc` with [`GetOut::new()`].
///
/// # Arguments
///
/// * `config` — The operation configuration whose URL list receives the
///   new node.
///
/// # Returns
///
/// A mutable reference to the newly appended `GetOut` node.
pub fn new_getout(config: &mut OperationConfig) -> &mut GetOut {
    let mut node = GetOut::new();
    node.use_remote = config.remote_name_all;
    node.num = GETOUT_COUNTER.fetch_add(1, Ordering::Relaxed);
    config.url_list.push(node);
    config
        .url_list
        .last_mut()
        .expect("url_list is non-empty after push")
}

// ---------------------------------------------------------------------------
// File Reading Helpers — Internal utilities
// ---------------------------------------------------------------------------

/// Returns `true` if the byte is a CR (`\r`), LF (`\n`), or NUL (`\0`).
///
/// Matches the C macro `#define ISCRLF(x)` in `tool_paramhlp.c` line 57.
#[inline]
fn is_crlf(b: u8) -> bool {
    b == b'\r' || b == b'\n' || b == 0
}

/// Counts leading bytes that are (or are not) in the CR/LF/NUL set.
///
/// Rust equivalent of the C static function `memcrlf()` in
/// `tool_paramhlp.c` lines 69–82.
///
/// - `count_crlf = false` → count non-CRLF bytes from the start
/// - `count_crlf = true`  → count CRLF bytes from the start
fn memcrlf(data: &[u8], count_crlf: bool) -> usize {
    for (i, &b) in data.iter().enumerate() {
        let crlf = is_crlf(b);
        if count_crlf ^ crlf {
            return i;
        }
    }
    data.len()
}

// ---------------------------------------------------------------------------
// File Reading Helpers — Public API
// ---------------------------------------------------------------------------

/// Reads a file into a string, stripping CR/LF/NUL delimiter sequences.
///
/// This is the Rust equivalent of C `file2string()` in `tool_paramhlp.c`.
/// The file is read in 4 KiB chunks.  Non-CRLF content is appended to
/// the output buffer; consecutive CR/LF/NUL bytes between content chunks
/// are skipped entirely, matching the C `memcrlf()` stripping behavior.
///
/// If `path` is `"-"`, reads from stdin.
///
/// # Arguments
///
/// * `path` — File path to read, or `"-"` for stdin.
///
/// # Returns
///
/// The file contents as a `String` with all CR/LF/NUL sequences removed.
///
/// # Errors
///
/// Returns an error if the file cannot be opened, a read error occurs, or
/// the data exceeds [`MAX_FILE2STRING`] bytes.
pub fn file2string(path: &str) -> Result<String> {
    let mut result = String::new();

    if path == "-" {
        let stdin_handle = io::stdin();
        let mut reader = BufReader::new(stdin_handle.lock());
        read_string_stripped(&mut reader, &mut result)?;
    } else {
        // Check file size before reading
        let meta = fs::metadata(path)
            .with_context(|| format!("cannot stat file '{}'", path))?;
        if meta.len() as usize > MAX_FILE2STRING {
            bail!(
                "file '{}' is too large ({} bytes, max {})",
                path,
                meta.len(),
                MAX_FILE2STRING
            );
        }
        let file =
            File::open(path).with_context(|| format!("cannot open file '{}'", path))?;
        let mut reader = BufReader::new(file);
        read_string_stripped(&mut reader, &mut result)?;
    }

    Ok(result)
}

/// Internal helper: reads from a reader in 4 KiB chunks, stripping
/// CRLF/NUL sequences as per the C `file2string` loop.
fn read_string_stripped<R: Read>(reader: &mut R, output: &mut String) -> Result<()> {
    let mut total_size: usize = 0;
    let mut buffer = [0u8; READ_BUFFER_SIZE];

    loop {
        let nread = reader.read(&mut buffer).context("error reading file")?;
        if nread == 0 {
            break;
        }

        total_size = total_size.saturating_add(nread);
        if total_size > MAX_FILE2STRING {
            bail!("file data exceeds maximum size ({})", MAX_FILE2STRING);
        }

        let mut data = &buffer[..nread];
        while !data.is_empty() {
            // Count non-CRLF bytes (content to keep)
            let nlen = memcrlf(data, false);
            if nlen > 0 {
                // Append content bytes.  Use lossy conversion for non-UTF-8
                // data (matching C behavior of treating bytes as-is).
                output.push_str(&String::from_utf8_lossy(&data[..nlen]));
            }
            data = &data[nlen..];

            if !data.is_empty() {
                // Count and skip CRLF/NUL bytes
                let skip = memcrlf(data, true);
                data = &data[skip..];
            }
        }
    }
    Ok(())
}

/// Reads an entire file into a byte buffer (binary-safe).
///
/// This is the Rust equivalent of C `file2memory()` in `tool_paramhlp.c`.
/// Delegates to [`file2memory_range`] with the full range
/// `[0, i64::MAX]`.
///
/// If `path` is `"-"`, reads from stdin.
///
/// # Arguments
///
/// * `path` — File path to read, or `"-"` for stdin.
///
/// # Returns
///
/// The file contents as a byte vector.
///
/// # Errors
///
/// Returns an error if the file cannot be opened, a read error occurs, or
/// the data exceeds [`MAX_FILE2MEMORY`].
pub fn file2memory(path: &str) -> Result<Vec<u8>> {
    file2memory_range(path, 0, i64::MAX)
}

/// Reads a specified byte range from a file into a byte buffer.
///
/// This is the Rust equivalent of C `file2memory_range()` in
/// `tool_paramhlp.c`.  For regular files, the function seeks to `start`.
/// For stdin (path `"-"`), it reads and discards `start` bytes before
/// collecting the desired range.
///
/// # Arguments
///
/// * `path`  — File path to read, or `"-"` for stdin.
/// * `start` — Starting byte offset (0-based, inclusive).
/// * `end`   — Ending byte offset (inclusive).
///
/// # Returns
///
/// The byte range as a `Vec<u8>`.
///
/// # Errors
///
/// Returns an error if the file cannot be opened, a read error occurs, or
/// the collected data exceeds [`MAX_FILE2MEMORY`].
pub fn file2memory_range(path: &str, start: i64, end: i64) -> Result<Vec<u8>> {
    let mut result = Vec::new();

    if path == "-" {
        let stdin_handle = io::stdin();
        let mut reader = BufReader::new(stdin_handle.lock());
        read_range_no_seek(&mut reader, start, end, &mut result)?;
    } else {
        let file =
            File::open(path).with_context(|| format!("cannot open file '{}'", path))?;
        let mut reader = BufReader::new(file);

        // Seek to start position for regular files
        if start > 0 {
            reader
                .seek(SeekFrom::Start(start as u64))
                .with_context(|| format!("failed to seek in file '{}'", path))?;
        }

        read_range_from_offset(&mut reader, start, end, &mut result)?;
    }

    Ok(result)
}

/// Reads a byte range from a non-seekable reader (stdin), discarding
/// `start` leading bytes before collecting data up to `end`.
///
/// Matches the C `throwaway` logic in `file2memory_range()`.
fn read_range_no_seek<R: Read>(
    reader: &mut R,
    start: i64,
    end: i64,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut offset: i64 = 0;
    let mut throwaway: i64 = start;
    let mut buffer = [0u8; READ_BUFFER_SIZE];

    loop {
        let nread = reader.read(&mut buffer).context("error reading file")?;
        if nread == 0 {
            break;
        }

        let mut n_add = nread;
        let mut ptr_start: usize = 0;

        if throwaway > 0 {
            if throwaway >= nread as i64 {
                throwaway -= nread as i64;
                offset += nread as i64;
                continue;
            } else {
                n_add = nread - throwaway as usize;
                ptr_start = throwaway as usize;
                offset += throwaway;
                throwaway = 0;
            }
        }

        if n_add > 0 {
            if (n_add as i64 + offset) > end {
                n_add = (end - offset + 1) as usize;
            }

            if output.len() + n_add > MAX_FILE2MEMORY {
                bail!("file data exceeds maximum size ({})", MAX_FILE2MEMORY);
            }

            output.extend_from_slice(&buffer[ptr_start..ptr_start + n_add]);
            offset += n_add as i64;

            if offset > end {
                break;
            }
        }
    }

    Ok(())
}

/// Reads a byte range from a seekable reader, starting from the current
/// file position (assumed to be at `initial_offset` after seeking).
fn read_range_from_offset<R: Read>(
    reader: &mut R,
    initial_offset: i64,
    end: i64,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut offset = initial_offset;
    let mut buffer = [0u8; READ_BUFFER_SIZE];

    loop {
        let nread = reader.read(&mut buffer).context("error reading file")?;
        if nread == 0 {
            break;
        }

        let mut n_add = nread;

        if (n_add as i64 + offset) > end {
            n_add = (end - offset + 1).max(0) as usize;
        }

        if n_add == 0 {
            break;
        }

        if output.len() + n_add > MAX_FILE2MEMORY {
            bail!("file data exceeds maximum size ({})", MAX_FILE2MEMORY);
        }

        output.extend_from_slice(&buffer[..n_add]);
        offset += n_add as i64;

        if offset > end {
            break;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Numeric Parsing
// ---------------------------------------------------------------------------

/// Parses a decimal integer string into an `i64`.
///
/// Rust equivalent of C `str2num()` in `tool_paramhlp.c`.
/// Accepts an optional leading `-` sign followed by digits.  The entire
/// string (after trimming) must be consumed — trailing non-digit
/// characters are rejected.
///
/// # Arguments
///
/// * `input` — The string to parse.
///
/// # Returns
///
/// The parsed integer value.
///
/// # Errors
///
/// Returns `Err` (equivalent to C `PARAM_BAD_NUMERIC`) if the string
/// is empty, contains invalid characters, or overflows `i64`.
pub fn str2num(input: &str) -> Result<i64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("bad numeric value: empty string");
    }

    trimmed
        .parse::<i64>()
        .with_context(|| format!("bad numeric value: '{}'", input))
}

/// Parses a non-negative decimal integer string into a `u64`.
///
/// Rust equivalent of C `str2unum()`.  Rejects negative numbers (returns
/// the equivalent of C `PARAM_NEGATIVE_NUMERIC`).
///
/// # Arguments
///
/// * `input` — The string to parse.
///
/// # Returns
///
/// The parsed unsigned value.
///
/// # Errors
///
/// Returns an error if parsing fails or the value is negative.
pub fn str2unum(input: &str) -> Result<u64> {
    let val = str2num(input)?;
    if val < 0 {
        bail!("negative number not allowed: '{}'", input);
    }
    Ok(val as u64)
}

/// Parses a non-negative decimal integer string bounded by `max`.
///
/// Rust equivalent of C `str2unummax()`.
///
/// # Arguments
///
/// * `input` — The string to parse.
/// * `max`   — Maximum allowed value (inclusive).
///
/// # Errors
///
/// Returns an error (equivalent to C `PARAM_NUMBER_TOO_LARGE`) if the
/// parsed value exceeds `max`.
pub fn str2unummax(input: &str, max: u64) -> Result<u64> {
    let val = str2unum(input)?;
    if val > max {
        bail!("number too large: {} (max {})", val, max);
    }
    Ok(val)
}

/// Parses a non-negative offset value (equivalent to C `curl_off_t`).
///
/// Rust equivalent of C `str2offset()`.  The value CANNOT be negative.
///
/// # Arguments
///
/// * `input` — The string to parse.
///
/// # Returns
///
/// The parsed non-negative offset as `i64`.
///
/// # Errors
///
/// Returns an error if the string is not a valid non-negative integer.
pub fn str2offset(input: &str) -> Result<i64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("bad numeric value: empty string");
    }

    // Reject leading minus sign (offset cannot be negative)
    if trimmed.starts_with('-') {
        bail!("bad numeric value (negative not allowed): '{}'", input);
    }

    trimmed
        .parse::<i64>()
        .with_context(|| format!("bad numeric value: '{}'", input))
}

/// Parses a fractional seconds value into milliseconds.
///
/// Rust equivalent of C `secs2ms()` in `tool_paramhlp.c`.
/// Accepts values like `"1.5"` (→ 1500), `"0.1"` (→ 100), `"30"` (→
/// 30000).  The fractional part is truncated to millisecond precision.
///
/// # Arguments
///
/// * `input` — The time string in seconds (with optional decimal fraction).
///
/// # Returns
///
/// The equivalent value in milliseconds as `i64`.
///
/// # Errors
///
/// Returns an error if parsing fails or the value overflows.
pub fn secs2ms(input: &str) -> Result<i64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("bad numeric value: empty string");
    }

    // Digit multiplier table — matches the C `digs[]` array exactly.
    // Index `n` holds 10^n, used to convert the fractional digit string
    // of length `len` into a millisecond contribution.
    let digs: [u64; 9] = [
        1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000,
    ];

    // Guard: seconds must not overflow when multiplied by 1000.
    // Matches C: `LONG_MAX / 1000 - 1`.
    let max_secs: i64 = i64::MAX / 1000 - 1;

    let (secs_str, frac_str) = match trimmed.split_once('.') {
        Some((s, f)) => (s, Some(f)),
        None => (trimmed, None),
    };

    // Parse the integer seconds part
    let secs: i64 = if secs_str.is_empty() {
        0
    } else {
        secs_str
            .parse::<i64>()
            .with_context(|| format!("bad numeric value: '{}'", input))?
    };

    if secs < 0 || secs > max_secs {
        bail!("number too large: '{}'", input);
    }

    // Parse the fractional part to millisecond precision
    let ms: i64 = if let Some(frac) = frac_str {
        if frac.is_empty() {
            0
        } else {
            let mut fracs: u64 = frac
                .parse::<u64>()
                .with_context(|| format!("bad fractional value: '{}'", input))?;
            let mut len = frac.len();

            // Scale down if the fractional part is too long or too large,
            // matching the C loop:
            //   while((len > ARRAYSIZE(digs)) || (fracs > LONG_MAX / 100))
            while len > digs.len() || fracs > (i64::MAX as u64 / 100) {
                fracs /= 10;
                len = len.saturating_sub(1);
            }

            if len == 0 {
                0
            } else {
                ((fracs * 100) / digs[len - 1]) as i64
            }
        }
    } else {
        0
    };

    Ok(secs * 1000 + ms)
}

/// Parses an octal integer string bounded by `max`.
///
/// Rust equivalent of C `oct2nummax()` in `tool_paramhlp.c`.
///
/// # Arguments
///
/// * `input` — The string containing an octal number (without `0o` prefix).
/// * `max`   — Maximum allowed value (inclusive).
///
/// # Returns
///
/// The parsed value as `u64`.
///
/// # Errors
///
/// Returns an error if the string is not valid octal, the value is
/// negative, or exceeds `max`.
pub fn oct2nummax(input: &str, max: u64) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("bad numeric value: empty string");
    }

    // Parse as octal (base 8)
    let val = i64::from_str_radix(trimmed, 8)
        .with_context(|| format!("bad octal numeric value: '{}'", input))?;

    if val < 0 {
        bail!("negative number not allowed: '{}'", input);
    }

    let uval = val as u64;
    if uval > max {
        bail!("number too large: {} (max {})", uval, max);
    }

    Ok(uval)
}

// ---------------------------------------------------------------------------
// Protocol Normalization — Internal helpers
// ---------------------------------------------------------------------------

/// Internal action enum for protocol set manipulation in [`proto2num`].
///
/// Matches the C `enum e_action { allow, deny, set }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoAction {
    /// Add protocol to the active set.
    Allow,
    /// Remove protocol from the active set.
    Deny,
    /// Clear the set and add only this protocol.
    Set,
}

// ---------------------------------------------------------------------------
// Protocol Normalization — Public API
// ---------------------------------------------------------------------------

/// Parses a comma-separated protocol specification string and returns a
/// canonical, alphabetically sorted protocol list.
///
/// Rust equivalent of C `proto2num()` in `tool_paramhlp.c`.
///
/// The input string supports the following modifiers per token:
/// - `+proto` — add protocol to set (allow)
/// - `-proto` — remove protocol from set (deny)
/// - `=proto` — clear set, then add only this protocol
/// - `proto` (bare, no modifier) — same as `+proto`
/// - `all` keyword — refers to all built-in protocols
///
/// The initial protocol set is populated from `info.protocols` (the
/// library's built-in protocol list), matching the C behavior of
/// initializing from the `val` array parameter.
///
/// # Arguments
///
/// * `val`    — The user-specified protocol string (e.g., `"+http,-ftp"`).
/// * `info`   — Library capability info providing the built-in protocol list.
/// * `global` — Global config for warning output on unrecognized protocols.
///
/// # Returns
///
/// A comma-separated, case-preserved, alphabetically sorted string of
/// enabled protocols.
///
/// # Errors
///
/// Returns an error if all protocols are denied (empty result set) or the
/// result string exceeds [`MAX_PROTOSTRING`].
pub fn proto2num(val: &str, info: &LibCurlInfo, global: &GlobalConfig) -> Result<String> {
    // Initialize protocol set from built-in protocols, matching the C
    // loop that copies `*val` entries via `protoset_set()`.
    let mut protoset: Vec<String> = info.protocols.clone();

    // Process each comma-separated token
    for raw_token in val.split(',') {
        let token = raw_token.trim();
        if token.is_empty() {
            continue;
        }

        // Determine action and extract the protocol name, matching the C
        // switch on the first character: '=' → set, '-' → deny, '+' → allow,
        // default → allow with no modifier consumed.
        let (action, proto_name) = match token.as_bytes().first() {
            Some(b'=') => (ProtoAction::Set, &token[1..]),
            Some(b'-') => (ProtoAction::Deny, &token[1..]),
            Some(b'+') => (ProtoAction::Allow, &token[1..]),
            _ => (ProtoAction::Allow, token),
        };

        if proto_name.eq_ignore_ascii_case("all") {
            // Special-case the `all` keyword
            match action {
                ProtoAction::Deny => {
                    protoset.clear();
                }
                ProtoAction::Allow | ProtoAction::Set => {
                    protoset = info.protocols.clone();
                }
            }
        } else {
            // Look up the canonical protocol name
            match proto_token(proto_name) {
                Some(canonical) => match action {
                    ProtoAction::Deny => {
                        protoset.retain(|p| !p.eq_ignore_ascii_case(&canonical));
                    }
                    ProtoAction::Set => {
                        protoset.clear();
                        protoset.push(canonical);
                    }
                    ProtoAction::Allow => {
                        // Only add if not already present
                        if !protoset
                            .iter()
                            .any(|p| p.eq_ignore_ascii_case(&canonical))
                        {
                            protoset.push(canonical);
                        }
                    }
                },
                None => {
                    // Unknown protocol — warn and handle `set` action
                    if action == ProtoAction::Set {
                        protoset.clear();
                    }
                    warnf(
                        global,
                        &format!("unrecognized protocol '{}'", proto_name),
                    );
                }
            }
        }
    }

    // Sort alphabetically (case-insensitive) for CI test requirements.
    // Matches the C `qsort(..., struplocompare4sort)`.
    protoset.sort_by_key(|a| a.to_ascii_lowercase());
    protoset.dedup_by(|a, b| a.eq_ignore_ascii_case(b));

    if protoset.is_empty() {
        bail!("no protocols enabled (bad use of --proto)");
    }

    // Build the comma-separated output string
    let result = protoset.join(",");
    if result.len() > MAX_PROTOSTRING {
        bail!("protocol string too long ({} > {})", result.len(), MAX_PROTOSTRING);
    }

    Ok(result)
}

/// Checks if a protocol scheme is supported by the library.
///
/// Rust equivalent of C `check_protocol()` in `tool_paramhlp.c`.
///
/// # Arguments
///
/// * `scheme` — Protocol scheme to validate (e.g., `"https"`, `"ftp"`).
/// * `_info`  — Library capability info (reserved for future use; the
///   check currently delegates to [`is_proto_supported`]).
///
/// # Returns
///
/// `true` if the protocol is recognized and supported, `false` otherwise.
pub fn check_protocol(scheme: &str, _info: &LibCurlInfo) -> bool {
    is_proto_supported(scheme)
}

/// Maps a TLS version string to a version code byte.
///
/// Rust equivalent of C `str2tls_max()` in `tool_paramhlp.c`.
///
/// # Arguments
///
/// * `input` — TLS version string: `"default"`, `"1.0"`, `"1.1"`,
///   `"1.2"`, or `"1.3"`.
///
/// # Returns
///
/// The TLS version code (`0`–`4`), or `None` if the input is unrecognized.
pub fn str2tls_max(input: &str) -> Option<u8> {
    match input {
        "default" => Some(0),
        "1.0" => Some(1),
        "1.1" => Some(2),
        "1.2" => Some(3),
        "1.3" => Some(4),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Credential and Header Helpers
// ---------------------------------------------------------------------------

/// Detects a missing password in a `user:password` credential string and
/// prompts the user interactively if needed.
///
/// Rust equivalent of C `static CURLcode checkpasswd()` in
/// `tool_paramhlp.c`.
///
/// Logic (matching C exactly):
/// 1. If the string is empty, return immediately.
/// 2. Search for `:` (password separator) and `;` (options separator).
/// 3. If no `:` is found AND the string doesn't start with `;`:
///    a. Extract the username (up to `;` if present).
///    b. Build a prompt message including `kind` and the username.
///    c. Call [`getpass_r`] to read the password with echo disabled.
///    d. Rebuild the string as `user:password[;options]`.
/// 4. Enforce [`MAX_USERPWDLENGTH`].
///
/// # Arguments
///
/// * `kind`    — Credential type label for the prompt (e.g., `"host"`,
///   `"proxy"`).
/// * `i`       — Operation index (0-based) for multi-URL prompts.
/// * `last`    — `true` if this is the last operation (simplifies prompt).
/// * `userpwd` — The credential string to check and potentially modify.
///
/// # Errors
///
/// Returns an error if the rebuilt string exceeds [`MAX_USERPWDLENGTH`]
/// or if password input fails.
pub fn checkpasswd(
    kind: &str,
    i: usize,
    last: bool,
    userpwd: &mut String,
) -> Result<()> {
    if userpwd.is_empty() {
        return Ok(());
    }

    // Search for the password separator (':')
    let has_colon = userpwd.contains(':');
    // Check for options separator at the start
    let starts_with_semi = userpwd.starts_with(';');

    if !has_colon && !starts_with_semi {
        // No password present — prompt for one.

        // Extract username (everything before ';' options, if present)
        let (username, options_suffix) = match userpwd.find(';') {
            Some(pos) => (&userpwd[..pos], Some(userpwd[pos..].to_string())),
            None => (userpwd.as_str(), None),
        };
        let username_owned = username.to_string();

        // Build a descriptive prompt matching C format exactly:
        //   "Enter <kind> password for user '<user>':"
        //   "Enter <kind> password for user '<user>' on URL #<n>:"
        let prompt = if i == 0 && last {
            format!(
                "Enter {} password for user '{}':",
                kind, username_owned
            )
        } else {
            format!(
                "Enter {} password for user '{}' on URL #{}:",
                kind, username_owned, i + 1
            )
        };

        // Read password with echo disabled
        let passwd = getpass_r(&prompt)?;

        // Rebuild the credential string: user:password[;options]
        let mut new_userpwd = String::with_capacity(
            username_owned.len()
                + 1
                + passwd.len()
                + options_suffix.as_ref().map_or(0, |s| s.len()),
        );
        new_userpwd.push_str(&username_owned);
        new_userpwd.push(':');
        new_userpwd.push_str(&passwd);
        if let Some(ref opts) = options_suffix {
            new_userpwd.push_str(opts);
        }

        if new_userpwd.len() > MAX_USERPWDLENGTH {
            bail!(
                "credential string exceeds maximum length ({})",
                MAX_USERPWDLENGTH
            );
        }

        *userpwd = new_userpwd;
    }

    Ok(())
}

/// Appends a string value to a header list.
///
/// Rust equivalent of C `add2list()` in `tool_paramhlp.c`.  The C
/// version wraps `curl_slist_append`; the Rust version simply pushes
/// onto a `Vec<String>`.
///
/// # Arguments
///
/// * `list`  — The header list to append to.
/// * `value` — The header string to add.
///
/// # Returns
///
/// `Ok(())` on success.  This function cannot fail in the Rust
/// implementation (no OOM with the standard allocator), but the
/// `Result` return type is preserved for API compatibility with the
/// C `ParameterError` return convention.
pub fn add2list(list: &mut Vec<String>, value: &str) -> Result<()> {
    list.push(value.to_string());
    Ok(())
}

/// Checks whether a header name exists in a header list (case-insensitive).
///
/// Rust equivalent of C `inlist()` in `tool_paramhlp.c`.
///
/// The header name is matched case-insensitively against each list entry
/// up to a `:` or `;` separator character.  This is the standard HTTP
/// header separator detection used throughout curl's CLI code.
///
/// # Arguments
///
/// * `list` — Slice of header strings (e.g., `["Content-Type: text/html"]`).
/// * `name` — Header name to search for (without trailing `:` or `;`).
///
/// # Returns
///
/// `true` if a matching header is found in the list.
pub fn inlist(list: &[String], name: &str) -> bool {
    debug_assert!(!name.is_empty(), "header name must not be empty");
    debug_assert!(
        !name.ends_with(':'),
        "header name must not end with ':'"
    );

    let name_len = name.len();

    for entry in list {
        let entry_bytes = entry.as_bytes();
        // The entry must be longer than the name (to have a separator)
        if entry_bytes.len() > name_len {
            let separator = entry_bytes[name_len];
            // Check for header separator (`:` or `;`) at the right position,
            // then compare the name prefix case-insensitively.
            // Matches C: `isheadersep(head->data[thislen])`
            if (separator == b':' || separator == b';')
                && entry[..name_len].eq_ignore_ascii_case(name)
            {
                return true;
            }
        }
    }

    false
}

/// Injects JSON-related headers and prompts for missing passwords.
///
/// Rust equivalent of C `get_args()` in `tool_paramhlp.c`.
///
/// When `config.jsoned` is `true` (set by `--json`), this function
/// adds `Content-Type: application/json` and `Accept: application/json`
/// headers if they are not already present in `config.headers`.
///
/// Then it checks `config.userpwd` and `config.proxyuserpwd` for
/// missing passwords, prompting interactively if needed.
///
/// # Arguments
///
/// * `config` — The operation configuration to process.
/// * `i`      — Operation index (0-based).
/// * `last`   — Whether this is the last operation in the chain.
///
/// # Errors
///
/// Returns an error if header addition or password prompting fails.
pub fn get_args(config: &mut OperationConfig, i: usize, last: bool) -> Result<()> {
    // --json implies Content-Type and Accept headers, if not already set
    if config.jsoned {
        if !inlist(&config.headers, "Content-Type") {
            add2list(&mut config.headers, "Content-Type: application/json")?;
        }
        if !inlist(&config.headers, "Accept") {
            add2list(&mut config.headers, "Accept: application/json")?;
        }
    }

    // Check for missing host password (skip if OAuth bearer is set)
    if config.userpwd.is_some() && config.oauth_bearer.is_none() {
        let mut userpwd = config.userpwd.take().unwrap();
        checkpasswd("host", i, last, &mut userpwd)?;
        config.userpwd = Some(userpwd);
    }

    // Check for missing proxy password
    if config.proxyuserpwd.is_some() {
        let mut proxypwd = config.proxyuserpwd.take().unwrap();
        checkpasswd("proxy", i, last, &mut proxypwd)?;
        config.proxyuserpwd = Some(proxypwd);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// FTP / Delegation Helpers
// ---------------------------------------------------------------------------

/// Maps a CLI string to an [`FtpFileMethod`] enum value.
///
/// Rust equivalent of C `ftpfilemethod()` in `tool_paramhlp.c`.
/// Comparison is case-insensitive.  Warns on unrecognized values and
/// returns the default ([`FtpFileMethod::MultiCwd`]).
///
/// # Arguments
///
/// * `input`  — CLI string: `"singlecwd"`, `"nocwd"`, or `"multicwd"`.
/// * `global` — Global config for warning output.
///
/// # Returns
///
/// The matched FTP file method, or [`FtpFileMethod::MultiCwd`] if
/// unrecognized.
pub fn ftpfilemethod(input: &str, global: &GlobalConfig) -> FtpFileMethod {
    if input.eq_ignore_ascii_case("singlecwd") {
        FtpFileMethod::SingleCwd
    } else if input.eq_ignore_ascii_case("nocwd") {
        FtpFileMethod::NoCwd
    } else if input.eq_ignore_ascii_case("multicwd") {
        FtpFileMethod::MultiCwd
    } else {
        warnf(
            global,
            &format!("unrecognized ftp file method '{}', using default", input),
        );
        FtpFileMethod::MultiCwd
    }
}

/// Maps a CLI string to an [`FtpCccMethod`] enum value.
///
/// Rust equivalent of C `ftpcccmethod()` in `tool_paramhlp.c`.
/// Comparison is case-insensitive.  Warns on unrecognized values and
/// returns the default ([`FtpCccMethod::Passive`]).
///
/// # Arguments
///
/// * `input`  — CLI string: `"passive"` or `"active"`.
/// * `global` — Global config for warning output.
///
/// # Returns
///
/// The matched FTP CCC method, or [`FtpCccMethod::Passive`] if
/// unrecognized.
pub fn ftpcccmethod(input: &str, global: &GlobalConfig) -> FtpCccMethod {
    if input.eq_ignore_ascii_case("passive") {
        FtpCccMethod::Passive
    } else if input.eq_ignore_ascii_case("active") {
        FtpCccMethod::Active
    } else {
        warnf(
            global,
            &format!("unrecognized ftp CCC method '{}', using default", input),
        );
        FtpCccMethod::Passive
    }
}

/// Maps a CLI string to a [`GssapiDelegation`] enum value.
///
/// Rust equivalent of C `delegation()` in `tool_paramhlp.c`.
/// Comparison is case-insensitive.  Warns on unrecognized values and
/// returns the default ([`GssapiDelegation::None`]).
///
/// # Arguments
///
/// * `input`  — CLI string: `"none"`, `"policy"`, or `"always"`.
/// * `global` — Global config for warning output.
///
/// # Returns
///
/// The matched GSSAPI delegation level, or [`GssapiDelegation::None`] if
/// unrecognized.
pub fn delegation(input: &str, global: &GlobalConfig) -> GssapiDelegation {
    if input.eq_ignore_ascii_case("none") {
        GssapiDelegation::None
    } else if input.eq_ignore_ascii_case("policy") {
        GssapiDelegation::PolicyFlag
    } else if input.eq_ignore_ascii_case("always") {
        GssapiDelegation::Flag
    } else {
        warnf(
            global,
            &format!("unrecognized delegation method '{}', using none", input),
        );
        GssapiDelegation::None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OperationConfig;
    use crate::libinfo::get_libcurl_info;

    // -- GetOut struct -------------------------------------------------------

    #[test]
    fn getout_has_required_fields() {
        let g = GetOut::new();
        assert!(g.url.is_none());
        assert!(g.outfile.is_none());
        assert!(g.infile.is_none());
        assert!(!g.use_remote);
        assert!(!g.url_set);
        assert!(!g.out_set);
        assert!(!g.upload_set);
        assert!(!g.no_upload);
        assert!(!g.no_glob);
        assert!(!g.out_null);
    }

    // -- Enum discriminant values -------------------------------------------

    #[test]
    fn ftp_file_method_values() {
        assert_eq!(FtpFileMethod::MultiCwd as i32, 1);
        assert_eq!(FtpFileMethod::SingleCwd as i32, 2);
        assert_eq!(FtpFileMethod::NoCwd as i32, 3);
    }

    #[test]
    fn ftp_ccc_method_values() {
        assert_eq!(FtpCccMethod::Passive as i32, 1);
        assert_eq!(FtpCccMethod::Active as i32, 2);
    }

    #[test]
    fn gssapi_delegation_values() {
        assert_eq!(GssapiDelegation::None as i32, 0);
        assert_eq!(GssapiDelegation::PolicyFlag as i32, 1);
        assert_eq!(GssapiDelegation::Flag as i32, 2);
    }

    // -- Constants ----------------------------------------------------------

    #[test]
    fn max_userpwdlength_matches_c() {
        assert_eq!(MAX_USERPWDLENGTH, 100 * 1024);
    }

    // -- str2num ------------------------------------------------------------

    #[test]
    fn str2num_positive() {
        assert_eq!(str2num("42").unwrap(), 42);
        assert_eq!(str2num("0").unwrap(), 0);
        assert_eq!(str2num("1000000").unwrap(), 1_000_000);
    }

    #[test]
    fn str2num_negative() {
        assert_eq!(str2num("-1").unwrap(), -1);
        assert_eq!(str2num("-100").unwrap(), -100);
    }

    #[test]
    fn str2num_empty_fails() {
        assert!(str2num("").is_err());
        assert!(str2num("  ").is_err());
    }

    #[test]
    fn str2num_non_numeric_fails() {
        assert!(str2num("abc").is_err());
        assert!(str2num("12abc").is_err());
    }

    // -- str2unum -----------------------------------------------------------

    #[test]
    fn str2unum_positive() {
        assert_eq!(str2unum("42").unwrap(), 42);
        assert_eq!(str2unum("0").unwrap(), 0);
    }

    #[test]
    fn str2unum_negative_fails() {
        assert!(str2unum("-1").is_err());
    }

    // -- str2unummax --------------------------------------------------------

    #[test]
    fn str2unummax_within_range() {
        assert_eq!(str2unummax("100", 200).unwrap(), 100);
        assert_eq!(str2unummax("200", 200).unwrap(), 200);
    }

    #[test]
    fn str2unummax_over_max_fails() {
        assert!(str2unummax("201", 200).is_err());
    }

    // -- str2offset ---------------------------------------------------------

    #[test]
    fn str2offset_positive() {
        assert_eq!(str2offset("100").unwrap(), 100);
        assert_eq!(str2offset("0").unwrap(), 0);
    }

    #[test]
    fn str2offset_negative_fails() {
        assert!(str2offset("-5").is_err());
    }

    // -- secs2ms ------------------------------------------------------------

    #[test]
    fn secs2ms_integer() {
        assert_eq!(secs2ms("1").unwrap(), 1000);
        assert_eq!(secs2ms("30").unwrap(), 30000);
        assert_eq!(secs2ms("0").unwrap(), 0);
    }

    #[test]
    fn secs2ms_fractional() {
        assert_eq!(secs2ms("1.5").unwrap(), 1500);
        assert_eq!(secs2ms("0.1").unwrap(), 100);
        assert_eq!(secs2ms("0.01").unwrap(), 10);
        assert_eq!(secs2ms("0.001").unwrap(), 1);
    }

    #[test]
    fn secs2ms_zero_point_zero() {
        assert_eq!(secs2ms("0.0").unwrap(), 0);
    }

    #[test]
    fn secs2ms_empty_fails() {
        assert!(secs2ms("").is_err());
    }

    // -- oct2nummax ---------------------------------------------------------

    #[test]
    fn oct2nummax_valid() {
        assert_eq!(oct2nummax("644", 0o777).unwrap(), 0o644);
        assert_eq!(oct2nummax("777", 0o777).unwrap(), 0o777);
        assert_eq!(oct2nummax("0", 100).unwrap(), 0);
    }

    #[test]
    fn oct2nummax_over_max_fails() {
        assert!(oct2nummax("777", 100).is_err());
    }

    #[test]
    fn oct2nummax_invalid_chars_fails() {
        assert!(oct2nummax("89", 1000).is_err());
        assert!(oct2nummax("abc", 1000).is_err());
    }

    // -- str2tls_max --------------------------------------------------------

    #[test]
    fn str2tls_max_known_values() {
        assert_eq!(str2tls_max("default"), Some(0));
        assert_eq!(str2tls_max("1.0"), Some(1));
        assert_eq!(str2tls_max("1.1"), Some(2));
        assert_eq!(str2tls_max("1.2"), Some(3));
        assert_eq!(str2tls_max("1.3"), Some(4));
    }

    #[test]
    fn str2tls_max_unknown() {
        assert_eq!(str2tls_max("2.0"), None);
        assert_eq!(str2tls_max(""), None);
        assert_eq!(str2tls_max("foo"), None);
    }

    // -- inlist -------------------------------------------------------------

    #[test]
    fn inlist_found() {
        let headers = vec![
            "Content-Type: text/html".to_string(),
            "Accept: */*".to_string(),
        ];
        assert!(inlist(&headers, "Content-Type"));
        assert!(inlist(&headers, "Accept"));
    }

    #[test]
    fn inlist_case_insensitive() {
        let headers = vec!["Content-Type: text/html".to_string()];
        assert!(inlist(&headers, "content-type"));
        assert!(inlist(&headers, "CONTENT-TYPE"));
    }

    #[test]
    fn inlist_not_found() {
        let headers = vec!["Content-Type: text/html".to_string()];
        assert!(!inlist(&headers, "Accept"));
        assert!(!inlist(&headers, "Authorization"));
    }

    #[test]
    fn inlist_semicolon_separator() {
        let headers = vec!["X-Custom; boundary=stuff".to_string()];
        assert!(inlist(&headers, "X-Custom"));
    }

    #[test]
    fn inlist_empty_list() {
        let headers: Vec<String> = vec![];
        assert!(!inlist(&headers, "Content-Type"));
    }

    // -- add2list -----------------------------------------------------------

    #[test]
    fn add2list_basic() {
        let mut list: Vec<String> = Vec::new();
        add2list(&mut list, "Content-Type: application/json").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], "Content-Type: application/json");
    }

    // -- file2string --------------------------------------------------------

    #[test]
    fn file2string_basic() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_f2s_basic.txt");
        std::fs::write(&path, "hello world").unwrap();
        let result = file2string(path.to_str().unwrap()).unwrap();
        assert_eq!(result, "hello world");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file2string_strips_crlf() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_f2s_crlf.txt");
        std::fs::write(&path, "line1\r\nline2\r\n").unwrap();
        let result = file2string(path.to_str().unwrap()).unwrap();
        assert_eq!(result, "line1line2");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file2string_nonexistent_fails() {
        assert!(file2string("/nonexistent/path/blitzy_test_nope.txt").is_err());
    }

    #[test]
    fn file2string_strips_nul() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_f2s_nul.txt");
        std::fs::write(&path, b"before\x00after").unwrap();
        let result = file2string(path.to_str().unwrap()).unwrap();
        assert_eq!(result, "beforeafter");
        let _ = std::fs::remove_file(&path);
    }

    // -- file2memory --------------------------------------------------------

    #[test]
    fn file2memory_basic() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_f2m_basic.bin");
        std::fs::write(&path, b"binary\x00data").unwrap();
        let result = file2memory(path.to_str().unwrap()).unwrap();
        assert_eq!(result, b"binary\x00data");
        let _ = std::fs::remove_file(&path);
    }

    // -- file2memory_range --------------------------------------------------

    #[test]
    fn file2memory_range_subset() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_f2mr.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let result = file2memory_range(path.to_str().unwrap(), 2, 5).unwrap();
        assert_eq!(result, b"2345");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file2memory_range_full() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_f2mr_full.bin");
        std::fs::write(&path, b"all data here").unwrap();
        let result = file2memory_range(path.to_str().unwrap(), 0, i64::MAX).unwrap();
        assert_eq!(result, b"all data here");
        let _ = std::fs::remove_file(&path);
    }

    // -- check_protocol -----------------------------------------------------

    #[test]
    fn check_protocol_http() {
        let info = get_libcurl_info();
        assert!(check_protocol("http", &info));
        assert!(check_protocol("https", &info));
        assert!(check_protocol("ftp", &info));
    }

    #[test]
    fn check_protocol_unknown() {
        let info = get_libcurl_info();
        assert!(!check_protocol("nonexistent_proto", &info));
    }

    // -- new_getout ---------------------------------------------------------

    #[test]
    fn new_getout_appends_to_url_list() {
        let mut config = OperationConfig::new();
        assert!(config.url_list.is_empty());
        let node = new_getout(&mut config);
        node.url = Some("https://example.com".to_string());
        assert_eq!(config.url_list.len(), 1);
    }

    #[test]
    fn new_getout_inherits_remote_name_all() {
        let mut config = OperationConfig::new();
        config.remote_name_all = true;
        let node = new_getout(&mut config);
        assert!(node.use_remote);
    }

    #[test]
    fn new_getout_monotonic_num() {
        let mut config = OperationConfig::new();
        let n1 = new_getout(&mut config).num;
        let n2 = new_getout(&mut config).num;
        assert!(n2 > n1, "num should increase: {} > {}", n2, n1);
    }

    // -- get_args (JSON headers) --------------------------------------------

    #[test]
    fn get_args_injects_json_headers() {
        let mut config = OperationConfig::new();
        config.jsoned = true;
        get_args(&mut config, 0, true).unwrap();
        assert!(inlist(&config.headers, "Content-Type"));
        assert!(inlist(&config.headers, "Accept"));
        assert_eq!(config.headers.len(), 2);
    }

    #[test]
    fn get_args_does_not_duplicate_json_headers() {
        let mut config = OperationConfig::new();
        config.jsoned = true;
        config.headers.push("Content-Type: text/xml".to_string());
        get_args(&mut config, 0, true).unwrap();
        assert_eq!(config.headers.len(), 2);
    }

    #[test]
    fn get_args_no_json_no_headers() {
        let mut config = OperationConfig::new();
        config.jsoned = false;
        get_args(&mut config, 0, true).unwrap();
        assert!(config.headers.is_empty());
    }

    // -- memcrlf internal helper tests --------------------------------------

    #[test]
    fn memcrlf_non_crlf_count() {
        assert_eq!(memcrlf(b"hello\r\n", false), 5);
        assert_eq!(memcrlf(b"\r\nhello", false), 0);
        assert_eq!(memcrlf(b"abc", false), 3);
    }

    #[test]
    fn memcrlf_crlf_count() {
        assert_eq!(memcrlf(b"\r\nhello", true), 2);
        assert_eq!(memcrlf(b"hello", true), 0);
        assert_eq!(memcrlf(b"\r\n\r\n", true), 4);
    }

    #[test]
    fn memcrlf_nul_is_crlf() {
        assert_eq!(memcrlf(b"\x00hello", true), 1);
        assert_eq!(memcrlf(b"a\x00b", false), 1);
    }
}
