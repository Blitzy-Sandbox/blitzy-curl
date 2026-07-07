//! FTP directory-listing (`LIST`) parser — the memory-safe Rust port of curl's
//! `lib/ftplistparser.c` for the byte-for-byte functional-parity rewrite of
//! curl / libcurl **8.19.0-DEV**.
//!
//! When a transfer uses FTP wildcard matching (`CURLOPT_WILDCARDMATCH`), libcurl
//! issues an FTP `LIST` command and feeds the server's textual directory listing
//! to this parser as it streams in over the data connection. The parser turns
//! that text into structured [`FileInfo`] records (the Rust analogue of
//! `struct curl_fileinfo` from `include/curl/curl.h`) which drive the
//! `CURL_CHUNK_BGN`/`CURL_CHUNK_END` callbacks and pattern matching in the FTP
//! protocol handler.
//!
//! # Supported listing formats
//!
//! Exactly the two formats curl 8.x understands are reproduced, with the same
//! detection heuristic and the same character-by-character state machines:
//!
//! * **Unix `ls -l`** — `perms links owner group size month day time/year name`,
//!   optionally `-> symlink-target` for symlinks; the date field is either
//!   `HH:MM` (recent) or `YYYY` (older). An optional leading `total N` summary
//!   line is consumed and discarded.
//! * **Windows NT / DOS** — `MM-DD-YY HH:MMAM/PM <DIR>|size name`.
//!
//! The format is chosen from the first byte of the listing: a leading ASCII
//! digit selects the Windows-NT parser, anything else selects the Unix parser
//! (mirroring `Curl_ftp_parselist`).
//!
//! # Streaming
//!
//! [`FtpListParser`] is fed arbitrary byte chunks via [`FtpListParser::parse`]
//! and maintains all state across chunk boundaries, so a single listing line may
//! be split across any number of network reads. Each time a complete record is
//! recognized it is handed to the caller-supplied `on_file` callback. Pattern
//! matching (`fnmatch`) and the wildcard file list are intentionally **not** the
//! responsibility of this module — it is a leaf that only turns bytes into
//! records; the FTP protocol handler owns filtering and dispatch.
//!
//! # Fidelity notes
//!
//! * The `flags` bitmask records which fields parsed successfully using the
//!   frozen `CURLFINFOFLAG_KNOWN_*` ABI bits. Matching curl exactly, this parser
//!   sets only [`CURLFINFOFLAG_KNOWN_PERM`], [`CURLFINFOFLAG_KNOWN_HLINKCOUNT`],
//!   and [`CURLFINFOFLAG_KNOWN_SIZE`]; it never sets the filename/filetype/time/
//!   uid/gid bits even though those fields are populated.
//! * Malformed lines reproduce curl's `CURLE_FTP_BAD_FILE_LIST`
//!   ([`CurlCode::FtpBadFileList`]) at exactly the same points; a single record
//!   larger than [`MAX_FTPLIST_BUFFER`] reproduces curl's out-of-memory abort
//!   ([`CurlCode::OutOfMemory`]).
//!
//! # Safety
//!
//! This module is written entirely in safe Rust — no raw pointers, no FFI,
//! and no panicking unwraps in its parsing paths — every fallible step
//! returns an [`Error`]. It is a leaf module and depends only on
//! [`crate::error`].

use crate::error::{CurlCode, Error, Result};

/// Bit in [`FileInfo::flags`] marking [`FileInfo::filename`] as known.
///
/// Value transcribed verbatim from `CURLFINFOFLAG_KNOWN_FILENAME`
/// (`include/curl/curl.h`). Note: this parser never sets this bit (matching
/// curl 8.x), even though the filename is always populated.
pub const CURLFINFOFLAG_KNOWN_FILENAME: u32 = 1 << 0;

/// Bit marking [`FileInfo::filetype`] as known (`CURLFINFOFLAG_KNOWN_FILETYPE`).
///
/// This parser never sets this bit (matching curl 8.x).
pub const CURLFINFOFLAG_KNOWN_FILETYPE: u32 = 1 << 1;

/// Bit marking the modification time as known (`CURLFINFOFLAG_KNOWN_TIME`).
///
/// This parser never sets this bit (matching curl 8.x); the textual time is
/// nonetheless captured in [`FileInfoStrings::time`].
pub const CURLFINFOFLAG_KNOWN_TIME: u32 = 1 << 2;

/// Bit marking [`FileInfo::perm`] as known (`CURLFINFOFLAG_KNOWN_PERM`).
pub const CURLFINFOFLAG_KNOWN_PERM: u32 = 1 << 3;

/// Bit marking [`FileInfo::uid`] as known (`CURLFINFOFLAG_KNOWN_UID`).
///
/// This parser never sets this bit (the Unix listing carries a user *name*, not
/// a numeric uid), matching curl 8.x.
pub const CURLFINFOFLAG_KNOWN_UID: u32 = 1 << 4;

/// Bit marking [`FileInfo::gid`] as known (`CURLFINFOFLAG_KNOWN_GID`).
///
/// This parser never sets this bit, matching curl 8.x.
pub const CURLFINFOFLAG_KNOWN_GID: u32 = 1 << 5;

/// Bit marking [`FileInfo::size`] as known (`CURLFINFOFLAG_KNOWN_SIZE`).
pub const CURLFINFOFLAG_KNOWN_SIZE: u32 = 1 << 6;

/// Bit marking [`FileInfo::hardlinks`] as known
/// (`CURLFINFOFLAG_KNOWN_HLINKCOUNT`).
pub const CURLFINFOFLAG_KNOWN_HLINKCOUNT: u32 = 1 << 7;

/// Maximum number of bytes buffered for a single listing record.
///
/// Mirrors the `MAX_FTPLIST_BUFFER` guard in `lib/ftplistparser.c`, enforced
/// against the same dynamic-buffer accounting curl uses (`len + used + 1`). A
/// record whose accumulated bytes would exceed this bound aborts the listing
/// with [`CurlCode::OutOfMemory`], exactly as curl does.
pub const MAX_FTPLIST_BUFFER: usize = 10000;

/// The type of a listed file, mirroring the C `curlfiletype` enumeration in
/// `include/curl/curl.h`.
///
/// The discriminants are transcribed verbatim from `CURLFILETYPE_*` and are a
/// frozen part of the public ABI, so they must never be reordered or renumbered.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// `CURLFILETYPE_FILE` — a regular file.
    File = 0,
    /// `CURLFILETYPE_DIRECTORY` — a directory.
    Directory = 1,
    /// `CURLFILETYPE_SYMLINK` — a symbolic link (see [`FileInfoStrings::target`]).
    Symlink = 2,
    /// `CURLFILETYPE_DEVICE_BLOCK` — a block device.
    DeviceBlock = 3,
    /// `CURLFILETYPE_DEVICE_CHAR` — a character device.
    DeviceChar = 4,
    /// `CURLFILETYPE_NAMEDPIPE` — a named pipe (FIFO).
    NamedPipe = 5,
    /// `CURLFILETYPE_SOCKET` — a socket.
    Socket = 6,
    /// `CURLFILETYPE_DOOR` — a Solaris door.
    Door = 7,
    /// `CURLFILETYPE_UNKNOWN` — should never occur for a successfully parsed
    /// record; present for ABI completeness.
    Unknown = 8,
}

impl Default for FileType {
    /// A freshly-allocated record starts as [`FileType::File`], matching the
    /// zero-initialized `struct fileinfo` in curl (`CURLFILETYPE_FILE == 0`).
    fn default() -> Self {
        FileType::File
    }
}

impl FileType {
    /// Returns the frozen `CURLFILETYPE_*` integer value for this file type.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// The textual field slices of a [`FileInfo`], mirroring the anonymous
/// `strings` sub-struct of `struct curl_fileinfo`.
///
/// Each field is `Some` only when the corresponding token was present in the
/// listing line. For a Windows-NT listing only [`time`](Self::time) is
/// populated; the Unix listing populates [`time`](Self::time),
/// [`perm`](Self::perm), [`user`](Self::user), and [`group`](Self::group), plus
/// [`target`](Self::target) for symlinks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileInfoStrings {
    /// The raw textual date/time token(s) (`curl_fileinfo.strings.time`). For
    /// Unix this is e.g. `"Jan 29 23:32"` or `"Jan 29 1997"`; for Windows-NT it
    /// is the whole `"MM-DD-YY HH:MMAM/PM"` prefix.
    pub time: Option<String>,
    /// The 9-character Unix permission string, e.g. `"rwxr-xr-x"`
    /// (`curl_fileinfo.strings.perm`); `None` for Windows-NT listings.
    pub perm: Option<String>,
    /// The owner/user token (`curl_fileinfo.strings.user`); `None` for
    /// Windows-NT listings.
    pub user: Option<String>,
    /// The group token (`curl_fileinfo.strings.group`); `None` for Windows-NT
    /// listings.
    pub group: Option<String>,
    /// The symlink target (`curl_fileinfo.strings.target`); `Some` only for
    /// [`FileType::Symlink`] records.
    pub target: Option<String>,
}

/// A single parsed directory entry, the Rust analogue of
/// `struct curl_fileinfo` (`include/curl/curl.h`).
///
/// The numeric fields ([`perm`](Self::perm), [`size`](Self::size),
/// [`hardlinks`](Self::hardlinks), …) are meaningful only when their
/// corresponding `CURLFINFOFLAG_KNOWN_*` bit is set in [`flags`](Self::flags);
/// [`size`](Self::size) and [`hardlinks`](Self::hardlinks) additionally surface
/// their known-ness as `Option`. The private C buffer fields (`b_data`,
/// `b_size`, `b_used`) are intentionally not modeled: owned Rust strings replace
/// them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileInfo {
    /// The file name (`curl_fileinfo.filename`). Always populated for an emitted
    /// record. Non-UTF-8 bytes are decoded lossily.
    pub filename: String,
    /// The file type (`curl_fileinfo.filetype`).
    pub filetype: FileType,
    /// Numeric modification time (`curl_fileinfo.time`, a `time_t`). curl
    /// documents this field as "always zero"; this parser never derives a
    /// numeric mtime, so it is always `None`. The textual time is available in
    /// [`FileInfoStrings::time`].
    pub time: Option<i64>,
    /// Unix permission bits (`curl_fileinfo.perm`). Valid only when
    /// [`CURLFINFOFLAG_KNOWN_PERM`] is set in [`flags`](Self::flags); `0`
    /// otherwise (e.g. for Windows-NT listings).
    pub perm: u32,
    /// Numeric owner id (`curl_fileinfo.uid`). This parser never derives it (the
    /// Unix listing carries a user *name*), so it is always `None`.
    pub uid: Option<i32>,
    /// Numeric group id (`curl_fileinfo.gid`). This parser never derives it, so
    /// it is always `None`.
    pub gid: Option<i32>,
    /// File size in bytes (`curl_fileinfo.size`). `Some` iff
    /// [`CURLFINFOFLAG_KNOWN_SIZE`] is set in [`flags`](Self::flags).
    pub size: Option<u64>,
    /// Hard-link count (`curl_fileinfo.hardlinks`). `Some` iff
    /// [`CURLFINFOFLAG_KNOWN_HLINKCOUNT`] is set in [`flags`](Self::flags).
    pub hardlinks: Option<u64>,
    /// The `CURLFINFOFLAG_KNOWN_*` bitmask recording which fields parsed
    /// successfully. This is the authoritative source of field validity, matching
    /// curl's `curl_fileinfo.flags`.
    pub flags: u32,
    /// The textual field slices (`curl_fileinfo.strings`).
    pub strings: FileInfoStrings,
}

// ===========================================================================
// Internal parsing state
// ===========================================================================

/// Sentinel bit OR-ed into the computed permission value when a permission
/// character is not valid for its position, mirroring `FTP_LP_MALFORMATED_PERM`
/// in `lib/ftplistparser.c`.
const FTP_LP_MALFORMATED_PERM: u32 = 0x0100_0000;

/// The largest `curl_off_t` value, i.e. C `CURL_OFF_T_MAX`. On the supported
/// LP64 targets `curl_off_t` is a signed 64-bit integer.
const CURL_OFF_T_MAX: i64 = i64::MAX;

/// The C `LONG_MAX` used as the ceiling for the hard-link count parse. On the
/// supported LP64 targets `long` is a signed 64-bit integer.
const LONG_MAX: i64 = i64::MAX;

/// Top-level parser state, encoding both the detected server format and the
/// position within its state machine.
///
/// This flattens the C parser's `os_type` discriminator plus the per-format
/// nested `main`/`sub` state unions into a single idiomatic enum. Before the
/// first non-empty byte arrives the format is [`State::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Format not yet detected (no bytes seen).
    Unknown,
    /// Unix `ls -l` parser, at the given sub-state.
    Unix(UnixState),
    /// Windows-NT parser, at the given sub-state.
    WinNt(WinNtState),
}

/// The combined `main`+`sub` state of the Unix `ls -l` parser, flattening the
/// `pl_unix_mainstate` / `pl_unix_substate` pair from `lib/ftplistparser.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnixState {
    /// `PL_UNIX_TOTALSIZE` / `PL_UNIX_TOTALSIZE_INIT`.
    TotalSizeInit,
    /// `PL_UNIX_TOTALSIZE` / `PL_UNIX_TOTALSIZE_READING`.
    TotalSizeReading,
    /// `PL_UNIX_FILETYPE`.
    FileType,
    /// `PL_UNIX_PERMISSION`.
    Permission,
    /// `PL_UNIX_HLINKS` / `PL_UNIX_HLINKS_PRESPACE`.
    HlinksPrespace,
    /// `PL_UNIX_HLINKS` / `PL_UNIX_HLINKS_NUMBER`.
    HlinksNumber,
    /// `PL_UNIX_USER` / `PL_UNIX_USER_PRESPACE`.
    UserPrespace,
    /// `PL_UNIX_USER` / `PL_UNIX_USER_PARSING`.
    UserParsing,
    /// `PL_UNIX_GROUP` / `PL_UNIX_GROUP_PRESPACE`.
    GroupPrespace,
    /// `PL_UNIX_GROUP` / `PL_UNIX_GROUP_NAME`.
    GroupName,
    /// `PL_UNIX_SIZE` / `PL_UNIX_SIZE_PRESPACE`.
    SizePrespace,
    /// `PL_UNIX_SIZE` / `PL_UNIX_SIZE_NUMBER`.
    SizeNumber,
    /// `PL_UNIX_TIME` / `PL_UNIX_TIME_PREPART1`.
    TimePrepart1,
    /// `PL_UNIX_TIME` / `PL_UNIX_TIME_PART1`.
    TimePart1,
    /// `PL_UNIX_TIME` / `PL_UNIX_TIME_PREPART2`.
    TimePrepart2,
    /// `PL_UNIX_TIME` / `PL_UNIX_TIME_PART2`.
    TimePart2,
    /// `PL_UNIX_TIME` / `PL_UNIX_TIME_PREPART3`.
    TimePrepart3,
    /// `PL_UNIX_TIME` / `PL_UNIX_TIME_PART3`.
    TimePart3,
    /// `PL_UNIX_FILENAME` / `PL_UNIX_FILENAME_PRESPACE`.
    FilenamePrespace,
    /// `PL_UNIX_FILENAME` / `PL_UNIX_FILENAME_NAME`.
    FilenameName,
    /// `PL_UNIX_FILENAME` / `PL_UNIX_FILENAME_WINDOWSEOL`.
    FilenameWindowsEol,
    /// `PL_UNIX_SYMLINK` / `PL_UNIX_SYMLINK_PRESPACE`.
    SymlinkPrespace,
    /// `PL_UNIX_SYMLINK` / `PL_UNIX_SYMLINK_NAME`.
    SymlinkName,
    /// `PL_UNIX_SYMLINK` / `PL_UNIX_SYMLINK_PRETARGET1`.
    SymlinkPretarget1,
    /// `PL_UNIX_SYMLINK` / `PL_UNIX_SYMLINK_PRETARGET2`.
    SymlinkPretarget2,
    /// `PL_UNIX_SYMLINK` / `PL_UNIX_SYMLINK_PRETARGET3`.
    SymlinkPretarget3,
    /// `PL_UNIX_SYMLINK` / `PL_UNIX_SYMLINK_PRETARGET4`.
    SymlinkPretarget4,
    /// `PL_UNIX_SYMLINK` / `PL_UNIX_SYMLINK_TARGET`.
    SymlinkTarget,
    /// `PL_UNIX_SYMLINK` / `PL_UNIX_SYMLINK_WINDOWSEOL`.
    SymlinkWindowsEol,
}

/// The combined `main`+`sub` state of the Windows-NT parser, flattening the
/// `pl_winNT_mainstate` / `pl_winNT_substate` pair from `lib/ftplistparser.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WinNtState {
    /// `PL_WINNT_DATE`.
    Date,
    /// `PL_WINNT_TIME` / `PL_WINNT_TIME_PRESPACE`.
    TimePrespace,
    /// `PL_WINNT_TIME` / `PL_WINNT_TIME_TIME`.
    TimeTime,
    /// `PL_WINNT_DIRORSIZE` / `PL_WINNT_DIRORSIZE_PRESPACE`.
    DirOrSizePrespace,
    /// `PL_WINNT_DIRORSIZE` / `PL_WINNT_DIRORSIZE_CONTENT`.
    DirOrSizeContent,
    /// `PL_WINNT_FILENAME` / `PL_WINNT_FILENAME_PRESPACE`.
    FilenamePrespace,
    /// `PL_WINNT_FILENAME` / `PL_WINNT_FILENAME_CONTENT`.
    FilenameContent,
    /// `PL_WINNT_FILENAME` / `PL_WINNT_FILENAME_WINEOL`.
    FilenameWinEol,
}

/// The record currently being assembled, the counterpart of the transient
/// `struct fileinfo` curl allocates per entry. Fields are filled in as their
/// tokens are recognized and the whole thing is turned into a [`FileInfo`] by
/// [`RecordBuilder::build`] when the record completes.
#[derive(Debug, Default)]
struct RecordBuilder {
    filetype: FileType,
    perm: u32,
    size: Option<u64>,
    hardlinks: Option<u64>,
    flags: u32,
    filename: Option<String>,
    time: Option<String>,
    perm_str: Option<String>,
    user: Option<String>,
    group: Option<String>,
    target: Option<String>,
}

impl RecordBuilder {
    /// Consumes the builder and produces the final [`FileInfo`] record.
    ///
    /// `filename` is always set by the time a record completes (its terminating
    /// newline is what triggers completion); should that invariant ever be
    /// violated it degrades gracefully to an empty name rather than panicking.
    fn build(self) -> FileInfo {
        FileInfo {
            filename: self.filename.unwrap_or_default(),
            filetype: self.filetype,
            time: None,
            perm: self.perm,
            uid: None,
            gid: None,
            size: self.size,
            hardlinks: self.hardlinks,
            flags: self.flags,
            strings: FileInfoStrings {
                time: self.time,
                perm: self.perm_str,
                user: self.user,
                group: self.group,
                target: self.target,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Byte-class helpers (mirror the ISDIGIT / ISALNUM / ISBLANK macros of
// lib/curl_ctype.h, operating on raw bytes exactly like curl's `char` tests).
// ---------------------------------------------------------------------------

/// Equivalent of curl's `ISDIGIT`: an ASCII decimal digit `'0'..='9'`.
#[inline]
fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// Equivalent of curl's `ISALNUM`: an ASCII letter or decimal digit.
#[inline]
fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// Equivalent of curl's `ISBLANK`: a space or horizontal tab.
#[inline]
fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// Computes the Unix permission bits from the 9-character permission string,
/// mirroring `ftp_pl_get_permission` in `lib/ftplistparser.c` bit-for-bit.
///
/// `perm` must be the nine characters following the file-type character (for
/// example the `"rwxr-xr-x"` of `"drwxr-xr-x"`). If any character is invalid for
/// its position the [`FTP_LP_MALFORMATED_PERM`] sentinel bit is set in the
/// returned value, which the caller treats as a malformed listing.
fn ftp_pl_get_permission(perm: &[u8]) -> u32 {
    // The state machine guarantees exactly nine permission bytes reach here, but
    // guard defensively so a short slice can never index out of bounds.
    if perm.len() < 9 {
        return FTP_LP_MALFORMATED_PERM;
    }
    let mut permissions: u32 = 0;

    // USER
    if perm[0] == b'r' {
        permissions |= 1 << 8;
    } else if perm[0] != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if perm[1] == b'w' {
        permissions |= 1 << 7;
    } else if perm[1] != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if perm[2] == b'x' {
        permissions |= 1 << 6;
    } else if perm[2] == b's' {
        permissions |= 1 << 6;
        permissions |= 1 << 11;
    } else if perm[2] == b'S' {
        permissions |= 1 << 11;
    } else if perm[2] != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }

    // GROUP
    if perm[3] == b'r' {
        permissions |= 1 << 5;
    } else if perm[3] != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if perm[4] == b'w' {
        permissions |= 1 << 4;
    } else if perm[4] != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if perm[5] == b'x' {
        permissions |= 1 << 3;
    } else if perm[5] == b's' {
        permissions |= 1 << 3;
        permissions |= 1 << 10;
    } else if perm[5] == b'S' {
        permissions |= 1 << 10;
    } else if perm[5] != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }

    // OTHERS
    if perm[6] == b'r' {
        permissions |= 1 << 2;
    } else if perm[6] != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if perm[7] == b'w' {
        permissions |= 1 << 1;
    } else if perm[7] != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if perm[8] == b'x' {
        permissions |= 1;
    } else if perm[8] == b't' {
        permissions |= 1;
        permissions |= 1 << 9;
    } else if perm[8] == b'T' {
        permissions |= 1 << 9;
    } else if perm[8] != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }

    permissions
}

/// Parses an unsigned base-10 integer from the leading digits of `bytes`,
/// mirroring curl's `curlx_str_number` / `str_num_base` semantics.
///
/// Returns `Some(value)` on success, consuming only the leading run of ASCII
/// digits. Returns `None` when there is no leading digit (curl's `STRE_NO_NUM`)
/// or when the accumulated value would exceed `max` (curl's `STRE_OVERFLOW`),
/// using the same pre-multiply overflow guard curl uses.
fn parse_decimal(bytes: &[u8], max: i64) -> Option<i64> {
    let mut it = bytes.iter().copied();
    let first = it.next()?;
    if !is_digit(first) {
        return None;
    }
    let mut num: i64 = i64::from(first - b'0');
    for c in it {
        if !is_digit(c) {
            break;
        }
        let n = i64::from(c - b'0');
        // Overflow guard identical to curl: reject before `num*10 + n` wraps.
        if num > (max - n) / 10 {
            return None;
        }
        num = num * 10 + n;
    }
    Some(num)
}

/// Parses an unsigned base-10 integer after skipping leading blanks, mirroring
/// `curlx_str_numblanks` (leading `curlx_str_passblanks`, then a
/// `CURL_OFF_T_MAX`-bounded `curlx_str_number`).
fn parse_decimal_blanks(bytes: &[u8]) -> Option<i64> {
    let mut start = 0;
    while start < bytes.len() && is_blank(bytes[start]) {
        start += 1;
    }
    parse_decimal(&bytes[start..], CURL_OFF_T_MAX)
}

/// Decodes a raw listing field into an owned [`String`], lossily replacing any
/// non-UTF-8 bytes. curl stores file names as raw bytes; the Rust API surfaces
/// [`String`] per the module design, which is lossless for the ASCII/UTF-8
/// listings that FTP servers emit in practice.
#[inline]
fn field_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Builds the `CURLE_FTP_BAD_FILE_LIST` error — curl's return value at every
/// point where a listing line cannot be parsed.
#[inline]
fn bad_file_list() -> Error {
    Error::Code(CurlCode::FtpBadFileList)
}

/// Reproduces the truthiness of C `strchr(set, c)` used by the parser's
/// character-class guards.
///
/// The C standard says the terminating NUL is part of the searched string, so
/// `strchr(set, '\0')` returns non-NULL — i.e. a NUL byte counts as "found".
/// curl relies on this incidentally (`if(!strchr("rwx-tTsS", c))` does not treat
/// an embedded NUL as invalid), so we mirror it exactly for byte-for-byte parity
/// on pathological input.
#[inline]
fn char_in_set(set: &[u8], c: u8) -> bool {
    c == 0 || set.contains(&c)
}

// ===========================================================================
// The streaming parser
// ===========================================================================

/// Incremental parser for FTP `LIST` responses.
///
/// Create one with [`FtpListParser::new`], feed it data-connection bytes with
/// [`FtpListParser::parse`] (which invokes a callback for every complete record),
/// and call [`FtpListParser::end`] once the listing is fully received. All state
/// — the detected format, the position in the state machine, and the bytes of
/// the record currently being assembled — is retained across calls, so a chunk
/// boundary may fall anywhere, even in the middle of a line.
///
/// This is the direct analogue of curl's `struct ftp_parselist_data` together
/// with the `Curl_ftp_parselist` write callback.
///
/// # Example
///
/// ```
/// use curl_rs_lib::protocols::ftp_list::{FileType, FtpListParser};
///
/// let mut parser = FtpListParser::new();
/// let mut names = Vec::new();
/// parser
///     .parse(b"drwxr-xr-x 2 user group 4096 Jan 29 1997 mydir\n", &mut |f| {
///         names.push((f.filename, f.filetype));
///         Ok(())
///     })
///     .unwrap();
/// parser.end().unwrap();
///
/// assert_eq!(names, vec![("mydir".to_string(), FileType::Directory)]);
/// ```
#[derive(Debug)]
pub struct FtpListParser {
    /// Current position in the (format-specific) state machine.
    state: State,
    /// Sticky error: once set, further [`parse`](FtpListParser::parse) calls are
    /// no-ops that re-report it, mirroring curl's `parser->error` short-circuit.
    error: Option<CurlCode>,
    /// Bytes accumulated for the record currently being assembled.
    buf: Vec<u8>,
    /// Start offset (within [`buf`](Self::buf)) of the token being scanned.
    item_offset: usize,
    /// Length (in [`buf`](Self::buf)) of the token being scanned, including the
    /// delimiter byte that terminates it.
    item_length: usize,
    /// Whether a record is currently being assembled (curl's non-NULL
    /// `file_data`). When `false`, the next byte starts a fresh record.
    file_active: bool,
    /// The record being assembled.
    cur: RecordBuilder,
}

impl Default for FtpListParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FtpListParser {
    /// Creates a new, empty parser with no format yet detected.
    #[must_use]
    pub fn new() -> Self {
        FtpListParser {
            state: State::Unknown,
            error: None,
            buf: Vec::new(),
            item_offset: 0,
            item_length: 0,
            file_active: false,
            cur: RecordBuilder::default(),
        }
    }

    /// Feeds a chunk of `LIST` response bytes to the parser, invoking `on_file`
    /// once for every complete record recognized within (and spanning into)
    /// this chunk.
    ///
    /// State is preserved across calls, so `chunk` may begin or end in the
    /// middle of a listing line. The `on_file` callback receives each finished
    /// [`FileInfo`]; returning `Err` from it aborts parsing, stores the error as
    /// sticky, and propagates it out of this call.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::FtpBadFileList`] when the listing cannot be parsed
    /// (the same points at which curl returns `CURLE_FTP_BAD_FILE_LIST`), or
    /// [`CurlCode::OutOfMemory`] if a single record exceeds
    /// [`MAX_FTPLIST_BUFFER`]. Once any error occurs it becomes sticky and is
    /// re-reported by subsequent calls.
    pub fn parse(
        &mut self,
        chunk: &[u8],
        on_file: &mut dyn FnMut(FileInfo) -> Result<()>,
    ) -> Result<()> {
        // A previous call already failed: short-circuit exactly like curl, which
        // skips the FSM entirely when `parser->error` is set.
        if let Some(code) = self.error {
            return Err(Error::Code(code));
        }

        // Detect the server format from the first byte of the first non-empty
        // chunk (curl: `ISDIGIT(buffer[0]) ? OS_TYPE_WIN_NT : OS_TYPE_UNIX`).
        if self.state == State::Unknown && !chunk.is_empty() {
            self.state = if is_digit(chunk[0]) {
                State::WinNt(WinNtState::Date)
            } else {
                State::Unix(UnixState::TotalSizeInit)
            };
        }

        for &c in chunk {
            if let Err(e) = self.feed_byte(c, on_file) {
                // Persist the sticky error (curl stores it in `parser->error`)
                // and discard the half-built record, as curl does on `fail:`.
                self.error = Some(e.code());
                self.reset_record();
                self.file_active = false;
                return Err(e);
            }
        }

        Ok(())
    }

    /// Finalizes the listing once all bytes have been delivered.
    ///
    /// curl completes a record only on its terminating newline, so a trailing
    /// line with no newline yields no record; this method mirrors that by
    /// discarding any partially-assembled record. It re-reports a sticky error
    /// if one is pending.
    ///
    /// # Errors
    ///
    /// Returns the pending sticky error, if any (see [`parse`](Self::parse)).
    pub fn end(&mut self) -> Result<()> {
        if let Some(code) = self.error {
            return Err(Error::Code(code));
        }
        // Any bytes still buffered belong to an unterminated final line, which
        // curl never turns into a record. Drop them.
        self.reset_record();
        self.file_active = false;
        Ok(())
    }

    /// Processes a single byte through the active state machine, appending it to
    /// the record buffer first (as curl appends to `infop->buf` before parsing).
    fn feed_byte(&mut self, c: u8, on_file: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()> {
        // Lazily begin a fresh record (curl allocates `file_data` when NULL).
        if !self.file_active {
            self.reset_record();
            self.file_active = true;
        }

        // Enforce the per-record buffer ceiling using curl's dynamic-buffer
        // accounting: a single-byte append needs `len + 1 + 1` bytes to fit.
        if self.buf.len() + 2 > MAX_FTPLIST_BUFFER {
            return Err(Error::OutOfMemory);
        }
        self.buf.push(c);

        match self.state {
            State::Unix(s) => self.parse_unix(s, c, on_file),
            State::WinNt(s) => self.parse_winnt(s, c, on_file),
            // Unreachable in practice: the format is fixed before the loop when
            // the chunk is non-empty, and an empty chunk never reaches here.
            State::Unknown => Err(Error::Code(CurlCode::FtpBadFileList)),
        }
    }

    /// Clears the per-record scratch state, readying the buffer for a new entry.
    /// The state machine position is intentionally left untouched: curl keeps
    /// `parser->state` across records.
    fn reset_record(&mut self) {
        self.buf.clear();
        self.item_offset = 0;
        self.item_length = 0;
        self.cur = RecordBuilder::default();
    }

    /// Extracts the token bytes `buf[item_offset .. item_offset + len]`.
    ///
    /// `len` is the token length excluding its delimiter (the caller passes
    /// `item_length - 1`, or `item_length - 4` for the symlink link name). The
    /// bounds are clamped defensively so a malformed state can never panic.
    fn token(&self, len: usize) -> &[u8] {
        let start = self.item_offset.min(self.buf.len());
        let end = start.saturating_add(len).min(self.buf.len());
        &self.buf[start..end]
    }

    /// Finalizes the current record and hands it to `on_file`, then marks the
    /// parser ready to begin the next one (curl sets `file_data = NULL`).
    fn emit(&mut self, on_file: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()> {
        let record = std::mem::take(&mut self.cur).build();
        self.file_active = false;
        on_file(record)
    }

    /// Maps a Unix file-type character (curl's `unix_filetype`) and, on success,
    /// advances into permission parsing.
    ///
    /// This is the shared target of the `TotalSize` → `FileType` fall-through
    /// and the steady-state `FileType`, exactly like the C dispatcher's
    /// `FALLTHROUGH()` into `case PL_UNIX_FILETYPE`. An unrecognized character
    /// (including the `'\n'` that terminates a `total` line) yields
    /// [`CurlCode::FtpBadFileList`], which is why curl rejects `total` lines.
    fn handle_unix_filetype(&mut self, c: u8) -> Result<()> {
        let filetype = match c {
            b'-' => FileType::File,
            b'd' => FileType::Directory,
            b'l' => FileType::Symlink,
            b'p' => FileType::NamedPipe,
            b's' => FileType::Socket,
            b'c' => FileType::DeviceChar,
            b'b' => FileType::DeviceBlock,
            b'D' => FileType::Door,
            _ => return Err(bad_file_list()),
        };
        self.cur.filetype = filetype;
        self.state = State::Unix(UnixState::Permission);
        self.item_length = 0;
        self.item_offset = 1;
        Ok(())
    }

    /// Drives one byte through the Unix `ls -l` state machine (curl's
    /// `parse_unix` plus its per-`main`-state helper functions), flattened into a
    /// single match over the combined [`UnixState`]. `c` has already been
    /// appended to [`buf`](Self::buf), so `len` below equals `buf.len()`.
    fn parse_unix(
        &mut self,
        s: UnixState,
        c: u8,
        on_file: &mut dyn FnMut(FileInfo) -> Result<()>,
    ) -> Result<()> {
        let len = self.buf.len();
        match s {
            // ---- optional leading "total N" summary line (first line only) ----
            UnixState::TotalSizeInit => {
                if c == b't' {
                    self.state = State::Unix(UnixState::TotalSizeReading);
                    self.item_length += 1;
                } else {
                    // Not a total line: this first byte is the file-type char.
                    // curl sets main=FILETYPE and FALLS THROUGH to process `c`.
                    self.state = State::Unix(UnixState::FileType);
                    return self.handle_unix_filetype(c);
                }
                Ok(())
            }
            UnixState::TotalSizeReading => {
                self.item_length += 1;
                if c == b'\r' {
                    // Drop the CR from both the counter and the buffer, exactly
                    // like curl's `item_length--` + `dyn_setlen(len-1)`.
                    self.item_length -= 1;
                    if !self.buf.is_empty() {
                        self.buf.pop();
                    }
                    Ok(())
                } else if c == b'\n' {
                    // Validate the "total <blanks><digits>" shape as curl does,
                    // then FALL THROUGH to the file-type handler with this same
                    // '\n'. curl's `unix_filetype('\n')` rejects it, so a real
                    // total line always ends in CURLE_FTP_BAD_FILE_LIST (this
                    // matches observed curl 8.x behavior byte-for-byte).
                    let line = &self.buf[..self.buf.len().saturating_sub(1)];
                    let valid = line.starts_with(b"total ") && {
                        let rest = &line[6..];
                        let mut i = 0;
                        while i < rest.len() && is_blank(rest[i]) {
                            i += 1;
                        }
                        rest[i..].iter().all(|&b| is_digit(b))
                    };
                    if !valid {
                        return Err(bad_file_list());
                    }
                    self.state = State::Unix(UnixState::FileType);
                    self.buf.clear();
                    self.item_offset = 0;
                    self.item_length = 0;
                    self.handle_unix_filetype(c)
                } else {
                    Ok(())
                }
            }

            // ---- file type ----
            UnixState::FileType => self.handle_unix_filetype(c),

            // ---- permission string (e.g. "rwxr-xr-x") ----
            UnixState::Permission => {
                self.item_length += 1;
                if self.item_length <= 9 {
                    if !char_in_set(b"rwx-tTsS", c) {
                        return Err(bad_file_list());
                    }
                } else if self.item_length == 10 {
                    if c != b' ' {
                        return Err(bad_file_list());
                    }
                    // The nine permission bytes are buf[item_offset..+9].
                    let perm_bytes = self.token(9);
                    let perm = ftp_pl_get_permission(perm_bytes);
                    if perm & FTP_LP_MALFORMATED_PERM != 0 {
                        return Err(bad_file_list());
                    }
                    let perm_string = field_to_string(perm_bytes);
                    self.cur.flags |= CURLFINFOFLAG_KNOWN_PERM;
                    self.cur.perm = perm;
                    self.cur.perm_str = Some(perm_string);
                    self.item_length = 0;
                    self.state = State::Unix(UnixState::HlinksPrespace);
                }
                Ok(())
            }

            // ---- hard-link count ----
            UnixState::HlinksPrespace => {
                if c != b' ' {
                    if is_digit(c) {
                        self.item_offset = len - 1;
                        self.item_length = 1;
                        self.state = State::Unix(UnixState::HlinksNumber);
                    } else {
                        return Err(bad_file_list());
                    }
                }
                Ok(())
            }
            UnixState::HlinksNumber => {
                self.item_length += 1;
                if c == b' ' {
                    // curl always advances to USER here, whether or not the
                    // number parsed (an overflow simply leaves hardlinks unset).
                    let parsed = parse_decimal(self.token(self.item_length - 1), LONG_MAX);
                    if let Some(hlinks) = parsed {
                        self.cur.flags |= CURLFINFOFLAG_KNOWN_HLINKCOUNT;
                        self.cur.hardlinks = Some(hlinks as u64);
                    }
                    self.item_length = 0;
                    self.item_offset = 0;
                    self.state = State::Unix(UnixState::UserPrespace);
                } else if !is_digit(c) {
                    return Err(bad_file_list());
                }
                Ok(())
            }

            // ---- owner (user) ----
            UnixState::UserPrespace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.state = State::Unix(UnixState::UserParsing);
                }
                Ok(())
            }
            UnixState::UserParsing => {
                self.item_length += 1;
                if c == b' ' {
                    let user = field_to_string(self.token(self.item_length - 1));
                    self.cur.user = Some(user);
                    self.item_offset = 0;
                    self.item_length = 0;
                    self.state = State::Unix(UnixState::GroupPrespace);
                }
                Ok(())
            }

            // ---- group ----
            UnixState::GroupPrespace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.state = State::Unix(UnixState::GroupName);
                }
                Ok(())
            }
            UnixState::GroupName => {
                self.item_length += 1;
                if c == b' ' {
                    let group = field_to_string(self.token(self.item_length - 1));
                    self.cur.group = Some(group);
                    self.item_offset = 0;
                    self.item_length = 0;
                    self.state = State::Unix(UnixState::SizePrespace);
                }
                Ok(())
            }

            // ---- size ----
            UnixState::SizePrespace => {
                if c != b' ' {
                    if is_digit(c) {
                        self.item_offset = len - 1;
                        self.item_length = 1;
                        self.state = State::Unix(UnixState::SizeNumber);
                    } else {
                        return Err(bad_file_list());
                    }
                }
                Ok(())
            }
            UnixState::SizeNumber => {
                self.item_length += 1;
                if c == b' ' {
                    let parsed = parse_decimal_blanks(self.token(self.item_length - 1));
                    if let Some(fsize) = parsed {
                        // The field is all-digits (the FSM rejects non-digits),
                        // so curl's `p[0] == '\0'` guard always holds; only the
                        // CURL_OFF_T_MAX sentinel gate remains meaningful.
                        if fsize != CURL_OFF_T_MAX {
                            self.cur.flags |= CURLFINFOFLAG_KNOWN_SIZE;
                            self.cur.size = Some(fsize as u64);
                        }
                        self.item_length = 0;
                        self.item_offset = 0;
                        self.state = State::Unix(UnixState::TimePrepart1);
                    }
                    // On overflow curl performs no transition and stays here; the
                    // next non-digit byte then trips the BAD path below.
                } else if !is_digit(c) {
                    return Err(bad_file_list());
                }
                Ok(())
            }

            // ---- modification time: three blank-separated tokens ----
            UnixState::TimePrepart1 => {
                if c != b' ' {
                    if is_alnum(c) {
                        self.item_offset = len - 1;
                        self.item_length = 1;
                        self.state = State::Unix(UnixState::TimePart1);
                    } else {
                        return Err(bad_file_list());
                    }
                }
                Ok(())
            }
            UnixState::TimePart1 => {
                self.item_length += 1;
                if c == b' ' {
                    self.state = State::Unix(UnixState::TimePrepart2);
                } else if !is_alnum(c) && c != b'.' {
                    return Err(bad_file_list());
                }
                Ok(())
            }
            UnixState::TimePrepart2 => {
                self.item_length += 1;
                if c != b' ' {
                    if is_alnum(c) {
                        self.state = State::Unix(UnixState::TimePart2);
                    } else {
                        return Err(bad_file_list());
                    }
                }
                Ok(())
            }
            UnixState::TimePart2 => {
                self.item_length += 1;
                if c == b' ' {
                    self.state = State::Unix(UnixState::TimePrepart3);
                } else if !is_alnum(c) && c != b'.' {
                    return Err(bad_file_list());
                }
                Ok(())
            }
            UnixState::TimePrepart3 => {
                self.item_length += 1;
                if c != b' ' {
                    if is_alnum(c) {
                        self.state = State::Unix(UnixState::TimePart3);
                    } else {
                        return Err(bad_file_list());
                    }
                }
                Ok(())
            }
            UnixState::TimePart3 => {
                self.item_length += 1;
                if c == b' ' {
                    let time = field_to_string(self.token(self.item_length - 1));
                    self.cur.time = Some(time);
                    if self.cur.filetype == FileType::Symlink {
                        self.state = State::Unix(UnixState::SymlinkPrespace);
                    } else {
                        self.state = State::Unix(UnixState::FilenamePrespace);
                    }
                } else if !is_alnum(c) && c != b'.' && c != b':' {
                    return Err(bad_file_list());
                }
                Ok(())
            }

            // ---- filename (regular, non-symlink entry) ----
            UnixState::FilenamePrespace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.state = State::Unix(UnixState::FilenameName);
                }
                Ok(())
            }
            UnixState::FilenameName => {
                self.item_length += 1;
                if c == b'\r' {
                    self.state = State::Unix(UnixState::FilenameWindowsEol);
                    Ok(())
                } else if c == b'\n' {
                    let name = field_to_string(self.token(self.item_length - 1));
                    self.cur.filename = Some(name);
                    self.state = State::Unix(UnixState::FileType);
                    self.emit(on_file)
                } else {
                    Ok(())
                }
            }
            UnixState::FilenameWindowsEol => {
                if c == b'\n' {
                    let name = field_to_string(self.token(self.item_length - 1));
                    self.cur.filename = Some(name);
                    self.state = State::Unix(UnixState::FileType);
                    self.emit(on_file)
                } else {
                    Err(bad_file_list())
                }
            }

            // ---- symlink: "name -> target" ----
            UnixState::SymlinkPrespace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.state = State::Unix(UnixState::SymlinkName);
                }
                Ok(())
            }
            UnixState::SymlinkName => {
                self.item_length += 1;
                if c == b' ' {
                    self.state = State::Unix(UnixState::SymlinkPretarget1);
                    Ok(())
                } else if c == b'\r' || c == b'\n' {
                    Err(bad_file_list())
                } else {
                    Ok(())
                }
            }
            UnixState::SymlinkPretarget1 => {
                self.item_length += 1;
                if c == b'-' {
                    self.state = State::Unix(UnixState::SymlinkPretarget2);
                    Ok(())
                } else if c == b'\r' || c == b'\n' {
                    Err(bad_file_list())
                } else {
                    // A '-' that is not part of " -> " rewinds to name scanning.
                    self.state = State::Unix(UnixState::SymlinkName);
                    Ok(())
                }
            }
            UnixState::SymlinkPretarget2 => {
                self.item_length += 1;
                if c == b'>' {
                    self.state = State::Unix(UnixState::SymlinkPretarget3);
                    Ok(())
                } else if c == b'\r' || c == b'\n' {
                    Err(bad_file_list())
                } else {
                    self.state = State::Unix(UnixState::SymlinkName);
                    Ok(())
                }
            }
            UnixState::SymlinkPretarget3 => {
                self.item_length += 1;
                if c == b' ' {
                    // Link name is buf[item_offset..+item_length-4], excluding
                    // the trailing " ->" and this delimiting space.
                    let name = field_to_string(self.token(self.item_length.saturating_sub(4)));
                    self.cur.filename = Some(name);
                    self.item_length = 0;
                    self.item_offset = 0;
                    self.state = State::Unix(UnixState::SymlinkPretarget4);
                    Ok(())
                } else if c == b'\r' || c == b'\n' {
                    Err(bad_file_list())
                } else {
                    self.state = State::Unix(UnixState::SymlinkName);
                    Ok(())
                }
            }
            UnixState::SymlinkPretarget4 => {
                if c != b'\r' && c != b'\n' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.state = State::Unix(UnixState::SymlinkTarget);
                    Ok(())
                } else {
                    Err(bad_file_list())
                }
            }
            UnixState::SymlinkTarget => {
                self.item_length += 1;
                if c == b'\r' {
                    self.state = State::Unix(UnixState::SymlinkWindowsEol);
                    Ok(())
                } else if c == b'\n' {
                    let target = field_to_string(self.token(self.item_length - 1));
                    self.cur.target = Some(target);
                    self.state = State::Unix(UnixState::FileType);
                    self.emit(on_file)
                } else {
                    Ok(())
                }
            }
            UnixState::SymlinkWindowsEol => {
                if c == b'\n' {
                    let target = field_to_string(self.token(self.item_length - 1));
                    self.cur.target = Some(target);
                    self.state = State::Unix(UnixState::FileType);
                    self.emit(on_file)
                } else {
                    Err(bad_file_list())
                }
            }
        }
    }

    /// Drives one byte through the Windows-NT / DOS state machine (curl's
    /// `parse_winnt`), flattened into a single match over [`WinNtState`]. The
    /// byte `c` has already been appended to [`buf`](Self::buf), so `len` equals
    /// `buf.len()`.
    ///
    /// A Windows-NT line has the shape `MM-DD-YY HH:MMAM/PM <DIR>|<size> name`.
    /// Only [`CURLFINFOFLAG_KNOWN_SIZE`] is recorded (matching curl); the
    /// date/time is captured whole into [`FileInfoStrings::time`].
    fn parse_winnt(
        &mut self,
        s: WinNtState,
        c: u8,
        on_file: &mut dyn FnMut(FileInfo) -> Result<()>,
    ) -> Result<()> {
        let len = self.buf.len();
        match s {
            // ---- date "MM-DD-YY" (exactly eight chars, then a space) ----
            WinNtState::Date => {
                self.item_length += 1;
                if self.item_length < 9 {
                    if !char_in_set(b"0123456789-", c) {
                        return Err(bad_file_list());
                    }
                } else if self.item_length == 9 {
                    if c == b' ' {
                        self.state = State::WinNt(WinNtState::TimePrespace);
                    } else {
                        return Err(bad_file_list());
                    }
                } else {
                    return Err(bad_file_list());
                }
                Ok(())
            }

            // ---- time "HH:MMAM/PM" (item_length keeps counting from the date,
            //      so the captured string is the whole "date time" prefix) ----
            WinNtState::TimePrespace => {
                self.item_length += 1;
                if !is_blank(c) {
                    self.state = State::WinNt(WinNtState::TimeTime);
                }
                Ok(())
            }
            WinNtState::TimeTime => {
                self.item_length += 1;
                if c == b' ' {
                    // item_offset is still 0, so this captures "MM-DD-YY HH:MMAM".
                    let time = field_to_string(self.token(self.item_length - 1));
                    self.cur.time = Some(time);
                    self.item_length = 0;
                    self.state = State::WinNt(WinNtState::DirOrSizePrespace);
                } else if !char_in_set(b"APM0123456789:", c) {
                    return Err(bad_file_list());
                }
                Ok(())
            }

            // ---- "<DIR>" marker or a numeric size ----
            WinNtState::DirOrSizePrespace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.state = State::WinNt(WinNtState::DirOrSizeContent);
                }
                Ok(())
            }
            WinNtState::DirOrSizeContent => {
                self.item_length += 1;
                if c == b' ' {
                    let content = self.token(self.item_length - 1);
                    let is_dir = content == b"<DIR>";
                    // Parse the size only when it is not the "<DIR>" marker; the
                    // borrow of `content` ends with this binding.
                    let parsed = if is_dir {
                        None
                    } else {
                        parse_decimal_blanks(content)
                    };
                    if is_dir {
                        self.cur.filetype = FileType::Directory;
                        self.cur.size = Some(0);
                    } else {
                        match parsed {
                            Some(size) => {
                                self.cur.size = Some(size as u64);
                                self.cur.filetype = FileType::File;
                            }
                            // A non-"<DIR>", non-numeric field is malformed.
                            None => return Err(bad_file_list()),
                        }
                    }
                    self.cur.flags |= CURLFINFOFLAG_KNOWN_SIZE;
                    self.item_length = 0;
                    self.state = State::WinNt(WinNtState::FilenamePrespace);
                }
                Ok(())
            }

            // ---- filename ----
            WinNtState::FilenamePrespace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.state = State::WinNt(WinNtState::FilenameContent);
                }
                Ok(())
            }
            WinNtState::FilenameContent => {
                self.item_length += 1;
                // Faithful to curl's `if(!len) return BAD;`; `len` is always
                // >= 1 here (the byte was just appended), so this never fires,
                // but it is preserved for exact parity.
                if len == 0 {
                    return Err(bad_file_list());
                }
                if c == b'\r' {
                    self.state = State::WinNt(WinNtState::FilenameWinEol);
                    Ok(())
                } else if c == b'\n' {
                    let name = field_to_string(self.token(self.item_length - 1));
                    self.cur.filename = Some(name);
                    self.state = State::WinNt(WinNtState::Date);
                    self.emit(on_file)
                } else {
                    Ok(())
                }
            }
            WinNtState::FilenameWinEol => {
                if c == b'\n' {
                    let name = field_to_string(self.token(self.item_length - 1));
                    self.cur.filename = Some(name);
                    self.state = State::WinNt(WinNtState::Date);
                    self.emit(on_file)
                } else {
                    Err(bad_file_list())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds the whole `input` in one chunk, then finalizes. Returns the emitted
    /// records and, if parsing or finalizing failed, the resulting error code.
    fn run(input: &[u8]) -> (Vec<FileInfo>, Option<CurlCode>) {
        run_chunks(&[input])
    }

    /// Feeds `input` split into the given chunks (to exercise state carried
    /// across chunk boundaries), then finalizes.
    fn run_chunks(chunks: &[&[u8]]) -> (Vec<FileInfo>, Option<CurlCode>) {
        let mut parser = FtpListParser::new();
        let mut records: Vec<FileInfo> = Vec::new();
        let err = {
            let mut push = |f: FileInfo| -> Result<()> {
                records.push(f);
                Ok(())
            };
            let mut e = None;
            for chunk in chunks {
                if let Err(err) = parser.parse(chunk, &mut push) {
                    e = Some(err);
                    break;
                }
            }
            if e.is_none() {
                e = parser.end().err();
            }
            e
        };
        (records, err.map(|e| e.code()))
    }

    // ---- ABI constant parity (must match include/curl/curl.h exactly) ----

    #[test]
    fn abi_known_flag_bits() {
        assert_eq!(CURLFINFOFLAG_KNOWN_FILENAME, 1 << 0);
        assert_eq!(CURLFINFOFLAG_KNOWN_FILETYPE, 1 << 1);
        assert_eq!(CURLFINFOFLAG_KNOWN_TIME, 1 << 2);
        assert_eq!(CURLFINFOFLAG_KNOWN_PERM, 1 << 3);
        assert_eq!(CURLFINFOFLAG_KNOWN_UID, 1 << 4);
        assert_eq!(CURLFINFOFLAG_KNOWN_GID, 1 << 5);
        assert_eq!(CURLFINFOFLAG_KNOWN_SIZE, 1 << 6);
        assert_eq!(CURLFINFOFLAG_KNOWN_HLINKCOUNT, 1 << 7);
    }

    #[test]
    fn abi_filetype_discriminants() {
        assert_eq!(FileType::File.as_u32(), 0);
        assert_eq!(FileType::Directory.as_u32(), 1);
        assert_eq!(FileType::Symlink.as_u32(), 2);
        assert_eq!(FileType::DeviceBlock.as_u32(), 3);
        assert_eq!(FileType::DeviceChar.as_u32(), 4);
        assert_eq!(FileType::NamedPipe.as_u32(), 5);
        assert_eq!(FileType::Socket.as_u32(), 6);
        assert_eq!(FileType::Door.as_u32(), 7);
        assert_eq!(FileType::Unknown.as_u32(), 8);
    }

    // ---- Unix `ls -l` ----

    #[test]
    fn unix_regular_file_all_fields() {
        let (recs, err) = run(b"-rw-r--r-- 1 owner grp 1035 Jun 25 10:44 README\r\n");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        let f = &recs[0];
        assert_eq!(f.filename, "README");
        assert_eq!(f.filetype, FileType::File);
        assert_eq!(f.perm, 0o644);
        assert_eq!(f.size, Some(1035));
        assert_eq!(f.hardlinks, Some(1));
        // Numeric uid/gid/time are never derived (parity with curl).
        assert_eq!(f.uid, None);
        assert_eq!(f.gid, None);
        assert_eq!(f.time, None);
        // Only PERM | SIZE | HLINKCOUNT are recorded as known.
        assert_eq!(
            f.flags,
            CURLFINFOFLAG_KNOWN_PERM | CURLFINFOFLAG_KNOWN_SIZE | CURLFINFOFLAG_KNOWN_HLINKCOUNT
        );
        assert_eq!(f.strings.perm.as_deref(), Some("rw-r--r--"));
        assert_eq!(f.strings.user.as_deref(), Some("owner"));
        assert_eq!(f.strings.group.as_deref(), Some("grp"));
        assert_eq!(f.strings.time.as_deref(), Some("Jun 25 10:44"));
        assert_eq!(f.strings.target, None);
    }

    #[test]
    fn unix_directory_year_date_lf_only() {
        // A directory, "YYYY" date field, and a bare LF terminator.
        let (recs, err) = run(b"drwxr-xr-x 2 root root 4096 Jan 29 1997 mydir\n");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        let f = &recs[0];
        assert_eq!(f.filename, "mydir");
        assert_eq!(f.filetype, FileType::Directory);
        assert_eq!(f.perm, 0o755);
        assert_eq!(f.size, Some(4096));
        assert_eq!(f.hardlinks, Some(2));
        assert_eq!(f.strings.time.as_deref(), Some("Jan 29 1997"));
        assert_eq!(f.strings.perm.as_deref(), Some("rwxr-xr-x"));
    }

    #[test]
    fn unix_symlink_with_target() {
        let (recs, err) = run(b"lrwxrwxrwx 1 u g 7 Jan 1 2020 link -> target1\r\n");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        let f = &recs[0];
        assert_eq!(f.filename, "link");
        assert_eq!(f.filetype, FileType::Symlink);
        assert_eq!(f.perm, 0o777);
        assert_eq!(f.strings.perm.as_deref(), Some("rwxrwxrwx"));
        assert_eq!(f.strings.target.as_deref(), Some("target1"));
        assert_eq!(f.size, Some(7));
    }

    #[test]
    fn unix_symlink_multi_arrow_target_kept_whole() {
        // curl splits on the first " -> " and keeps the remainder (including
        // further arrows) as the target; the FTP handler filters it later.
        let (recs, err) = run(b"lrwxrwxrwx 1 u g 3 Jan 1 2020 a -> b -> c\r\n");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].filename, "a");
        assert_eq!(recs[0].strings.target.as_deref(), Some("b -> c"));
    }

    #[test]
    fn unix_two_records() {
        let input = b"-rw-r--r-- 1 u g 10 Jan 1 2020 a.txt\r\n\
                      drwxr-xr-x 2 u g 4096 Feb 2 2021 dir\r\n";
        let (recs, err) = run(input);
        assert_eq!(err, None);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].filename, "a.txt");
        assert_eq!(recs[0].filetype, FileType::File);
        assert_eq!(recs[0].size, Some(10));
        assert_eq!(recs[1].filename, "dir");
        assert_eq!(recs[1].filetype, FileType::Directory);
        assert_eq!(recs[1].size, Some(4096));
    }

    #[test]
    fn unix_hhmm_time_preserves_internal_spacing() {
        // Two spaces between month and day must survive in the time string.
        let (recs, err) = run(b"-rw-rw-rw- 1 u g 5 Feb  1 08:00 chmod2\n");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].strings.time.as_deref(), Some("Feb  1 08:00"));
        assert_eq!(recs[0].perm, 0o666);
    }

    #[test]
    fn unix_special_permission_bits() {
        // setuid + setgid + sticky, all with execute (lowercase s/s/t).
        let (recs, err) = run(b"-rwsr-sr-t 1 u g 5 Jan 1 2020 f\r\n");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].perm, 0o7755);
        assert_eq!(recs[0].strings.perm.as_deref(), Some("rwsr-sr-t"));
    }

    // ---- Windows-NT / DOS ----

    #[test]
    fn winnt_directory_marker() {
        let (recs, err) = run(b"01-11-10  10:00AM       <DIR>          mydir\r\n");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        let f = &recs[0];
        assert_eq!(f.filename, "mydir");
        assert_eq!(f.filetype, FileType::Directory);
        assert_eq!(f.size, Some(0));
        assert_eq!(f.flags, CURLFINFOFLAG_KNOWN_SIZE);
        assert_eq!(f.strings.time.as_deref(), Some("01-11-10  10:00AM"));
        // Windows-NT listings carry no perm/user/group/target.
        assert_eq!(f.perm, 0);
        assert_eq!(f.strings.perm, None);
        assert_eq!(f.strings.user, None);
        assert_eq!(f.strings.group, None);
        assert_eq!(f.strings.target, None);
        assert_eq!(f.hardlinks, None);
    }

    #[test]
    fn winnt_sized_file() {
        let (recs, err) = run(b"05-04-10  04:31AM              1276 file.txt\r\n");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        let f = &recs[0];
        assert_eq!(f.filename, "file.txt");
        assert_eq!(f.filetype, FileType::File);
        assert_eq!(f.size, Some(1276));
        assert_eq!(f.flags, CURLFINFOFLAG_KNOWN_SIZE);
        assert_eq!(f.strings.time.as_deref(), Some("05-04-10  04:31AM"));
    }

    #[test]
    fn winnt_two_records() {
        let input = b"01-11-10  10:00AM       <DIR>          d1\r\n\
                      05-04-10  04:31AM              1276 f.txt\r\n";
        let (recs, err) = run(input);
        assert_eq!(err, None);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].filename, "d1");
        assert_eq!(recs[0].filetype, FileType::Directory);
        assert_eq!(recs[1].filename, "f.txt");
        assert_eq!(recs[1].size, Some(1276));
    }

    // ---- OS-type detection ----

    #[test]
    fn os_detection_digit_selects_winnt() {
        // A leading digit picks the Windows-NT parser; a Unix line fed to it
        // would fail, so success here proves the dispatch.
        let (recs, err) = run(b"12-31-99  11:59PM              1 x\r\n");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].filename, "x");
    }

    // ---- streaming across chunk boundaries ----

    #[test]
    fn split_across_chunk_boundary() {
        // The boundary falls in the middle of the owner token.
        let (recs, err) = run_chunks(&[b"drwxr-xr-x 2 us", b"er grp 4096 Jan 29 1997 sub\r\n"]);
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].filename, "sub");
        assert_eq!(recs[0].strings.user.as_deref(), Some("user"));
        assert_eq!(recs[0].strings.group.as_deref(), Some("grp"));
        assert_eq!(recs[0].size, Some(4096));
    }

    #[test]
    fn split_every_byte() {
        // Feeding one byte at a time must yield the identical record.
        let line = b"-rw-r--r-- 1 u g 42 Jan 1 2020 tiny\r\n";
        let chunks: Vec<&[u8]> = line.iter().map(std::slice::from_ref).collect();
        let (recs, err) = run_chunks(&chunks);
        assert_eq!(err, None);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].filename, "tiny");
        assert_eq!(recs[0].size, Some(42));
    }

    // ---- trailing / empty input ----

    #[test]
    fn trailing_line_without_newline_is_dropped() {
        // curl completes a record only on its newline; a final unterminated
        // line yields no record and no error.
        let (recs, err) = run(b"-rw-r--r-- 1 u g 5 Jan 1 2020 noeol");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 0);
    }

    #[test]
    fn empty_input_yields_nothing() {
        let (recs, err) = run(b"");
        assert_eq!(err, None);
        assert_eq!(recs.len(), 0);
    }

    #[test]
    fn end_without_any_data() {
        let mut parser = FtpListParser::new();
        assert!(parser.end().is_ok());
    }

    // ---- the "total" summary line: curl rejects it (verified behavior) ----

    #[test]
    fn total_line_crlf_is_rejected() {
        let (recs, err) = run(b"total 8\r\ndrwxr-xr-x 1 u g 4 Jan 1 2020 d\r\n");
        assert_eq!(err, Some(CurlCode::FtpBadFileList));
        assert_eq!(recs.len(), 0);
    }

    #[test]
    fn total_line_lf_is_rejected() {
        let (recs, err) = run(b"total 8\ndrwxr-xr-x 1 u g 4 Jan 1 2020 d\n");
        assert_eq!(err, Some(CurlCode::FtpBadFileList));
        assert_eq!(recs.len(), 0);
    }

    #[test]
    fn total_line_alone_is_rejected() {
        let (recs, err) = run(b"total 8\r\n");
        assert_eq!(err, Some(CurlCode::FtpBadFileList));
        assert_eq!(recs.len(), 0);
    }

    // ---- malformed listings reproduce CURLE_FTP_BAD_FILE_LIST ----

    #[test]
    fn bad_permission_char_is_rejected() {
        let (recs, err) = run(b"drwxr-xr-Q 1 u g 5 Jan 1 2020 x\r\n");
        assert_eq!(err, Some(CurlCode::FtpBadFileList));
        assert_eq!(recs.len(), 0);
    }

    #[test]
    fn bad_filetype_char_is_rejected() {
        // A non-digit first byte selects Unix; an invalid file-type char then
        // fails immediately via the TotalSize->FileType fall-through.
        let (recs, err) = run(b"hello world\r\n");
        assert_eq!(err, Some(CurlCode::FtpBadFileList));
        assert_eq!(recs.len(), 0);
    }

    #[test]
    fn winnt_bad_date_is_rejected() {
        // A tenth date character (no space at position 9) is malformed.
        let (recs, err) = run(b"0123456789 stuff\r\n");
        assert_eq!(err, Some(CurlCode::FtpBadFileList));
        assert_eq!(recs.len(), 0);
    }

    #[test]
    fn sticky_error_is_reported_on_subsequent_calls() {
        let mut parser = FtpListParser::new();
        let mut sink = |_f: FileInfo| -> Result<()> { Ok(()) };
        let first = parser.parse(b"hello\r\n", &mut sink);
        assert!(matches!(first, Err(Error::Code(CurlCode::FtpBadFileList))));
        // A second call must re-report the same sticky error and parse nothing.
        let second = parser.parse(b"drwxr-xr-x 1 u g 4 Jan 1 2020 d\r\n", &mut sink);
        assert!(matches!(second, Err(Error::Code(CurlCode::FtpBadFileList))));
        // end() also re-reports it.
        assert!(matches!(
            parser.end(),
            Err(Error::Code(CurlCode::FtpBadFileList))
        ));
    }

    // ---- per-record buffer ceiling reproduces the out-of-memory abort ----

    #[test]
    fn oversized_record_aborts_with_out_of_memory() {
        let mut input = b"-rw-r--r-- 1 u g 5 Jan 1 2020 ".to_vec();
        // Pad the record past the per-record buffer ceiling. `resize` avoids the
        // `manual_repeat_n` clippy lint while staying compatible with MSRV 1.75
        // (`std::iter::repeat_n` was only stabilized in 1.82).
        input.resize(input.len() + MAX_FTPLIST_BUFFER + 100, b'x');
        let (recs, err) = run(&input);
        assert_eq!(err, Some(CurlCode::OutOfMemory));
        assert_eq!(recs.len(), 0);
    }

    #[test]
    fn callback_error_propagates_and_becomes_sticky() {
        // An error returned by the on_file callback aborts parsing and is stored.
        let mut parser = FtpListParser::new();
        let mut fail_once =
            |_f: FileInfo| -> Result<()> { Err(Error::Code(CurlCode::FtpBadFileList)) };
        let r = parser.parse(b"-rw-r--r-- 1 u g 5 Jan 1 2020 f\r\n", &mut fail_once);
        assert!(r.is_err());
        // Subsequent calls short-circuit with the stored error.
        let mut sink = |_f: FileInfo| -> Result<()> { Ok(()) };
        assert!(parser.parse(b"more\r\n", &mut sink).is_err());
    }
}
