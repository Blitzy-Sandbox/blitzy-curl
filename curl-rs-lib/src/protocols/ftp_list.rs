//! FTP LIST response parser for wildcard directory listings.
//!
//! This module is a Rust rewrite of `lib/ftplistparser.c` — an FTP wildcard
//! LIST directory listing parser supporting Unix and Windows NT formats, with
//! file info extraction and `fnmatch`-based filename filtering.
//!
//! # Supported Formats
//!
//! ## Unix (several variants)
//! ```text
//! drwxr-xr-x 1 user01 ftp  512 Jan 29 23:32 prog
//! drwxr-xr-x 1 user01 ftp  512 Jan 29 1997  prog
//! drwxr-xr-x 1      1   1  512 Jan 29 23:32 prog
//! lrwxr-xr-x 1 user01 ftp  512 Jan 29 23:32 prog -> prog2000
//! ```
//!
//! ## Windows NT (DOS-style)
//! ```text
//! 01-29-97 11:32PM <DIR> prog
//! 01-29-97 11:32PM       1234 file.txt
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use curl_rs_lib::protocols::ftp_list::{FtpListParser, FileInfo};
//!
//! let mut parser = FtpListParser::new();
//! let data = b"drwxr-xr-x 1 user ftp 512 Jan 29 23:32 mydir\n";
//! let entries = parser.parse(data).unwrap();
//! assert_eq!(entries.len(), 1);
//! assert_eq!(entries[0].filename, "mydir");
//! ```

use crate::error::{CurlError, CurlResult};
use crate::util::fnmatch::{curl_fnmatch, FnMatchResult};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum allowed buffer size for a single FTP LIST line (bytes).
/// Matches the C `MAX_FTPLIST_BUFFER` constant.
const MAX_FTPLIST_BUFFER: usize = 10_000;

/// Sentinel bit indicating a malformed permission character was found.
/// If this bit is set in the result of [`ftp_pl_get_permission`], the
/// permission string is invalid.
const FTP_LP_MALFORMED_PERM: u32 = 0x0100_0000;

// ---------------------------------------------------------------------------
// FtpListFormat — detected listing format
// ---------------------------------------------------------------------------

/// The detected format of an FTP LIST response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FtpListFormat {
    /// Format has not yet been determined (no data processed).
    #[default]
    Unknown,
    /// Unix `ls -l` style listing.
    Unix,
    /// Windows NT / DOS-style listing.
    WinNT,
}

// ---------------------------------------------------------------------------
// FileType — type of a listed file entry
// ---------------------------------------------------------------------------

/// The type of a file entry parsed from an FTP LIST response.
///
/// Variant integer values match the C `curlfiletype` enum for FFI parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum FileType {
    /// Regular file.
    File = 0,
    /// Directory.
    Directory = 1,
    /// Symbolic link.
    SymLink = 2,
    /// Block device.
    DeviceBlock = 3,
    /// Character device.
    DeviceChar = 4,
    /// Named pipe (FIFO).
    NamedPipe = 5,
    /// Unix domain socket.
    Socket = 6,
    /// Solaris door.
    Door = 7,
    /// Unknown file type.
    #[default]
    Unknown = 8,
}

// ---------------------------------------------------------------------------
// FileInfoFlags — bitflags indicating which fields are known/valid
// ---------------------------------------------------------------------------

/// Bitflags indicating which fields of a [`FileInfo`] are known/valid.
///
/// Integer flag values match the C `CURLFINFOFLAG_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileInfoFlags(u32);

impl FileInfoFlags {
    /// Filename is known.
    pub const KNOWN_FILENAME: Self = Self(1 << 0);
    /// File type is known.
    pub const KNOWN_FILETYPE: Self = Self(1 << 1);
    /// Modification time string is known.
    pub const KNOWN_TIME: Self = Self(1 << 2);
    /// Permission bits are known.
    pub const KNOWN_PERM: Self = Self(1 << 3);
    /// Owner UID is known.
    pub const KNOWN_UID: Self = Self(1 << 4);
    /// Group GID is known.
    pub const KNOWN_GID: Self = Self(1 << 5);
    /// File size is known.
    pub const KNOWN_SIZE: Self = Self(1 << 6);
    /// Hard link count is known.
    pub const KNOWN_HLINKCOUNT: Self = Self(1 << 7);

    /// Returns an empty (zero) flag set.
    #[inline]
    pub fn empty() -> Self {
        Self(0)
    }

    /// Returns `true` if all bits in `other` are set in `self`.
    #[inline]
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for FileInfoFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for FileInfoFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ---------------------------------------------------------------------------
// FileInfo — parsed file entry
// ---------------------------------------------------------------------------

/// A single file entry parsed from an FTP LIST response.
///
/// All string fields are extracted from the raw listing data. Optional fields
/// default to empty strings or `None` when not present in the listing format.
#[derive(Debug, Clone, Default)]
pub struct FileInfo {
    /// Filename (always present for valid entries).
    pub filename: String,
    /// Detected file type (file, directory, symlink, etc.).
    pub filetype: FileType,
    /// Numeric permission bits (Unix octal style, e.g. 0o755).
    pub perm: u32,
    /// Owner user ID (numeric, 0 if unknown).
    pub uid: u32,
    /// Group ID (numeric, 0 if unknown).
    pub gid: u32,
    /// File size in bytes (-1 if unknown).
    pub size: i64,
    /// Hard link count (0 if unknown).
    pub hardlinks: i64,
    /// Bitflags indicating which fields are known/valid.
    pub flags: FileInfoFlags,
    /// Time/date string as it appears in the listing.
    pub time_str: String,
    /// Permission string (e.g. "rwxr-xr-x").
    pub perm_str: String,
    /// User/owner name string.
    pub user_str: String,
    /// Group name string.
    pub group_str: String,
    /// Symlink target path (only for symlinks).
    pub symlink_target: Option<String>,
}

// ---------------------------------------------------------------------------
// WildcardState — wildcard download process states
// ---------------------------------------------------------------------------

/// States for the FTP wildcard download process.
///
/// Integer values match the C `wildcard_states` enum (`CURLWC_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
#[repr(u8)]
pub enum WildcardState {
    /// Initial cleared state.
    Clear = 0,
    /// Initialized and ready.
    #[default]
    Init = 1,
    /// Matching files against pattern.
    Matching = 2,
    /// Downloading matched files.
    Downloading = 3,
    /// Cleaning up resources.
    Clean = 4,
    /// Skipping a file.
    Skip = 5,
    /// Error state.
    Error = 6,
    /// Processing complete.
    Done = 7,
}

// ---------------------------------------------------------------------------
// WildcardData — wildcard download data
// ---------------------------------------------------------------------------

/// Data structure for FTP wildcard download processing.
///
/// Holds the directory path, glob pattern, accumulated file list, and the
/// current state of the wildcard state machine.
#[derive(Debug, Clone, Default)]
pub struct WildcardData {
    /// Path to the directory being listed.
    pub path: String,
    /// Wildcard pattern for filename matching.
    pub pattern: String,
    /// Accumulated list of matching [`FileInfo`] entries.
    pub filelist: Vec<FileInfo>,
    /// Current state of the wildcard download process.
    pub state: WildcardState,
}

impl WildcardData {
    /// Creates a new, empty `WildcardData` in the `Init` state.
    pub fn new() -> Self {
        Self {
            path: String::new(),
            pattern: String::new(),
            filelist: Vec::new(),
            state: WildcardState::Init,
        }
    }

    /// Initializes the wildcard data with a path and pattern, resetting state.
    pub fn init(&mut self, path: String, pattern: String) {
        self.path = path;
        self.pattern = pattern;
        self.filelist.clear();
        self.state = WildcardState::Init;
    }
}

// ===========================================================================
// Internal state machine types
// ===========================================================================

// ---------------------------------------------------------------------------
// Unix format states
// ---------------------------------------------------------------------------

/// Main states for the Unix LIST format parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnixMainState {
    /// Detecting or reading "total NNN" header line.
    TotalSize,
    /// Reading the single file-type character (d, -, l, …).
    FileType,
    /// Reading the 9-character permission string.
    Permission,
    /// Reading the hard link count.
    HardLinks,
    /// Reading the owner/user field.
    User,
    /// Reading the group field.
    Group,
    /// Reading the file size.
    Size,
    /// Reading the modification time (three parts).
    Time,
    /// Reading the filename.
    Filename,
    /// Reading symlink name and target (for 'l' type entries).
    Symlink,
}

/// Sub-states for the Unix LIST format parser.
///
/// Each main state may have one or more sub-states that track fine-grained
/// progress within that field. Only one sub-state is meaningful at a time,
/// determined by the current [`UnixMainState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnixSubState {
    // -- TotalSize sub-states --
    /// Waiting for first character to decide if this is a "total" line.
    TotalSizeInit,
    /// Reading the "total NNN" line content.
    TotalSizeReading,

    // -- HardLinks sub-states --
    /// Consuming leading spaces before the hard link count.
    HLinksPreSpace,
    /// Reading hard link count digits.
    HLinksNumber,

    // -- User sub-states --
    /// Consuming leading spaces before the user field.
    UserPreSpace,
    /// Reading user name characters.
    UserParsing,

    // -- Group sub-states --
    /// Consuming leading spaces before the group field.
    GroupPreSpace,
    /// Reading group name characters.
    GroupName,

    // -- Size sub-states --
    /// Consuming leading spaces before the size field.
    SizePreSpace,
    /// Reading size digits.
    SizeNumber,

    // -- Time sub-states (three parts: "MMM DD HH:MM" or "MMM DD YYYY") --
    /// Consuming spaces before part 1 (month).
    TimePrePart1,
    /// Reading part 1 (month name).
    TimePart1,
    /// Consuming spaces between part 1 and part 2.
    TimePrePart2,
    /// Reading part 2 (day).
    TimePart2,
    /// Consuming spaces between part 2 and part 3.
    TimePrePart3,
    /// Reading part 3 (time or year).
    TimePart3,

    // -- Filename sub-states --
    /// Consuming leading spaces before the filename.
    FilenamePreSpace,
    /// Reading filename characters.
    FilenameName,
    /// Saw '\r', expecting '\n' (Windows-style EOL).
    FilenameWindowsEol,

    // -- Symlink sub-states --
    /// Consuming leading spaces before symlink name.
    SymlinkPreSpace,
    /// Reading symlink name characters.
    SymlinkName,
    /// After space in name — checking for " -> " (saw ' ').
    SymlinkPreTarget1,
    /// Checking for '-' in " -> ".
    SymlinkPreTarget2,
    /// Checking for '>' in " -> ".
    SymlinkPreTarget3,
    /// Confirmed " -> ", waiting for target start.
    SymlinkPreTarget4,
    /// Reading target path characters.
    SymlinkTarget,
    /// Saw '\r' in target, expecting '\n'.
    SymlinkWindowsEol,
}

// ---------------------------------------------------------------------------
// Windows NT format states
// ---------------------------------------------------------------------------

/// Main states for the Windows NT LIST format parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WinNtMainState {
    /// Reading the date field (MM-DD-YY).
    Date,
    /// Reading the time field (HH:MMPP).
    Time,
    /// Reading `<DIR>` or numeric size.
    DirOrSize,
    /// Reading the filename.
    Filename,
}

/// Sub-states for the Windows NT LIST format parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WinNtSubState {
    // -- Time sub-states --
    /// Consuming spaces before the time field.
    TimePreSpace,
    /// Reading time characters.
    TimeTime,

    // -- DirOrSize sub-states --
    /// Consuming spaces before `<DIR>` or size.
    DirOrSizePreSpace,
    /// Reading `<DIR>` or size content.
    DirOrSizeContent,

    // -- Filename sub-states --
    /// Consuming spaces before the filename.
    FilenamePreSpace,
    /// Reading filename characters.
    FilenameContent,
    /// Saw '\r', expecting '\n'.
    FilenameWindowsEol,
}

// ===========================================================================
// FtpListParser — the main parser struct
// ===========================================================================

/// FTP LIST response parser.
///
/// Processes raw FTP LIST response bytes through a character-by-character
/// state machine. Supports streaming: data can arrive in arbitrarily-sized
/// chunks across multiple calls to [`parse`](Self::parse).
///
/// # Examples
///
/// ```ignore
/// let mut parser = FtpListParser::new();
/// let entries = parser.parse(b"-rw-r--r-- 1 user grp 1024 Jan 15 10:30 hello.txt\n")?;
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].filename, "hello.txt");
/// ```
pub struct FtpListParser {
    /// Detected listing format.
    format: FtpListFormat,

    /// Stored error from a previous parse call. Once set, all subsequent
    /// parse calls return immediately.
    error: Option<CurlError>,

    /// Accumulation buffer for the current entry's raw line data.
    buffer: Vec<u8>,

    /// Offset of the current field being parsed within [`buffer`](Self::buffer).
    item_offset: usize,

    /// Running length of the current field (includes the delimiter when
    /// the field boundary is reached).
    item_length: usize,

    // -- Unix format state --
    unix_main: UnixMainState,
    unix_sub: UnixSubState,

    // -- WinNT format state --
    winnt_main: WinNtMainState,
    winnt_sub: WinNtSubState,

    // -- Current entry fields (populated during parsing) --
    entry_filetype: FileType,
    entry_perm: u32,
    entry_size: i64,
    entry_hardlinks: i64,
    entry_flags: FileInfoFlags,

    // -- Extracted field strings for the current entry --
    entry_perm_str: String,
    entry_user_str: String,
    entry_group_str: String,
    entry_time_str: String,
    entry_filename: String,
    entry_symlink_target: Option<String>,

    /// Optional wildcard pattern for filename filtering.
    pattern: Option<String>,

    /// Whether we are currently inside an active entry (buffer allocated).
    has_entry: bool,
}

// ===========================================================================
// Helper functions
// ===========================================================================

/// Parse a 9-character Unix permission string into a numeric bitmask.
///
/// Bit layout (matching POSIX `st_mode`):
/// - Bits 8..6: owner rwx
/// - Bits 5..3: group rwx
/// - Bits 2..0: others rwx
/// - Bit 11: setuid
/// - Bit 10: setgid
/// - Bit 9: sticky
///
/// Returns the permission bitmask. If [`FTP_LP_MALFORMED_PERM`] is set in
/// the return value, the string contained an invalid character.
fn ftp_pl_get_permission(s: &[u8]) -> u32 {
    if s.len() < 9 {
        return FTP_LP_MALFORMED_PERM;
    }
    let mut perm: u32 = 0;

    // --- USER ---
    match s[0] {
        b'r' => perm |= 1 << 8,
        b'-' => {}
        _ => perm |= FTP_LP_MALFORMED_PERM,
    }
    match s[1] {
        b'w' => perm |= 1 << 7,
        b'-' => {}
        _ => perm |= FTP_LP_MALFORMED_PERM,
    }
    match s[2] {
        b'x' => perm |= 1 << 6,
        b's' => {
            perm |= 1 << 6;
            perm |= 1 << 11;
        }
        b'S' => perm |= 1 << 11,
        b'-' => {}
        _ => perm |= FTP_LP_MALFORMED_PERM,
    }

    // --- GROUP ---
    match s[3] {
        b'r' => perm |= 1 << 5,
        b'-' => {}
        _ => perm |= FTP_LP_MALFORMED_PERM,
    }
    match s[4] {
        b'w' => perm |= 1 << 4,
        b'-' => {}
        _ => perm |= FTP_LP_MALFORMED_PERM,
    }
    match s[5] {
        b'x' => perm |= 1 << 3,
        b's' => {
            perm |= 1 << 3;
            perm |= 1 << 10;
        }
        b'S' => perm |= 1 << 10,
        b'-' => {}
        _ => perm |= FTP_LP_MALFORMED_PERM,
    }

    // --- OTHERS ---
    match s[6] {
        b'r' => perm |= 1 << 2,
        b'-' => {}
        _ => perm |= FTP_LP_MALFORMED_PERM,
    }
    match s[7] {
        b'w' => perm |= 1 << 1,
        b'-' => {}
        _ => perm |= FTP_LP_MALFORMED_PERM,
    }
    match s[8] {
        b'x' => perm |= 1,
        b't' => {
            perm |= 1;
            perm |= 1 << 9;
        }
        b'T' => perm |= 1 << 9,
        b'-' => {}
        _ => perm |= FTP_LP_MALFORMED_PERM,
    }

    perm
}

/// Map a single character to a [`FileType`], as used by Unix LIST format.
///
/// Returns `Err(CurlError::FtpBadFileList)` for unrecognised characters.
fn unix_filetype(c: u8) -> CurlResult<FileType> {
    match c {
        b'-' => Ok(FileType::File),
        b'd' => Ok(FileType::Directory),
        b'l' => Ok(FileType::SymLink),
        b'p' => Ok(FileType::NamedPipe),
        b's' => Ok(FileType::Socket),
        b'c' => Ok(FileType::DeviceChar),
        b'b' => Ok(FileType::DeviceBlock),
        b'D' => Ok(FileType::Door),
        _ => Err(CurlError::FtpBadFileList),
    }
}

/// Extract a UTF-8 string from a byte slice, replacing invalid sequences.
#[inline]
fn buf_to_string(buf: &[u8]) -> String {
    String::from_utf8_lossy(buf).into_owned()
}

/// Returns `true` if the byte is an ASCII alphanumeric character.
#[inline]
fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// Returns `true` if the byte is an ASCII digit.
#[inline]
fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// Returns `true` if the byte is an ASCII blank (space or tab).
#[inline]
fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

// ===========================================================================
// FtpListParser implementation
// ===========================================================================

impl FtpListParser {
    /// Creates a new parser with default (empty) state.
    pub fn new() -> Self {
        Self {
            format: FtpListFormat::Unknown,
            error: None,
            buffer: Vec::with_capacity(256),
            item_offset: 0,
            item_length: 0,
            unix_main: UnixMainState::TotalSize,
            unix_sub: UnixSubState::TotalSizeInit,
            winnt_main: WinNtMainState::Date,
            winnt_sub: WinNtSubState::TimePreSpace,
            entry_filetype: FileType::Unknown,
            entry_perm: 0,
            entry_size: 0,
            entry_hardlinks: 0,
            entry_flags: FileInfoFlags::empty(),
            entry_perm_str: String::new(),
            entry_user_str: String::new(),
            entry_group_str: String::new(),
            entry_time_str: String::new(),
            entry_filename: String::new(),
            entry_symlink_target: None,
            pattern: None,
            has_entry: false,
        }
    }

    /// Returns the stored error from a previous parse call, if any.
    pub fn get_error(&self) -> Option<CurlError> {
        self.error
    }

    /// Resets the parser to its initial state, discarding all accumulated
    /// data and clearing any stored error.
    pub fn reset(&mut self) {
        self.format = FtpListFormat::Unknown;
        self.error = None;
        self.buffer.clear();
        self.item_offset = 0;
        self.item_length = 0;
        self.unix_main = UnixMainState::TotalSize;
        self.unix_sub = UnixSubState::TotalSizeInit;
        self.winnt_main = WinNtMainState::Date;
        self.winnt_sub = WinNtSubState::TimePreSpace;
        self.reset_entry_fields();
        self.has_entry = false;
    }

    /// Sets the wildcard pattern for filename filtering during parsing.
    /// When set, only entries whose filenames match the pattern (via
    /// `fnmatch`) are included in the results.
    pub fn set_pattern(&mut self, pattern: Option<String>) {
        self.pattern = pattern;
    }

    /// Parse a chunk of raw FTP LIST response data.
    ///
    /// Returns a vector of completed [`FileInfo`] entries found in this chunk.
    /// Data may span multiple calls; the parser maintains state between calls.
    ///
    /// # Errors
    ///
    /// Returns `Err(CurlError::FtpBadFileList)` if the listing data is
    /// malformed, or `Err(CurlError::OutOfMemory)` if the internal buffer
    /// exceeds the maximum allowed size.
    pub fn parse(&mut self, data: &[u8]) -> CurlResult<Vec<FileInfo>> {
        // If a previous call stored an error, return it immediately.
        if let Some(err) = self.error {
            return Err(err);
        }

        let mut results = Vec::new();

        // Auto-detect format from the first byte of input.
        if self.format == FtpListFormat::Unknown && !data.is_empty() {
            self.format = if data[0].is_ascii_digit() {
                FtpListFormat::WinNT
            } else {
                FtpListFormat::Unix
            };
        }

        for &c in data {
            // Ensure we have an active entry buffer.
            if !self.has_entry {
                self.start_new_entry();
            }

            // Append byte to accumulation buffer.
            if self.buffer.len() >= MAX_FTPLIST_BUFFER {
                self.error = Some(CurlError::OutOfMemory);
                self.cleanup_entry();
                return Err(CurlError::OutOfMemory);
            }
            self.buffer.push(c);

            // Dispatch to the appropriate format parser.
            let result = match self.format {
                FtpListFormat::Unix => self.parse_unix_char(c),
                FtpListFormat::WinNT => self.parse_winnt_char(c),
                FtpListFormat::Unknown => {
                    // Should not happen — format is detected above.
                    Err(CurlError::FtpBadFileList)
                }
            };

            match result {
                Ok(Some(info)) => {
                    // A complete entry was produced. Apply pattern filtering.
                    if let Some(filtered) = self.apply_pattern_filter(info) {
                        results.push(filtered);
                    }
                }
                Ok(None) => {
                    // Parsing continues; no complete entry yet.
                }
                Err(err) => {
                    self.error = Some(err);
                    self.cleanup_entry();
                    return Err(err);
                }
            }
        }

        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Entry lifecycle helpers
    // -----------------------------------------------------------------------

    /// Prepare for a new entry by resetting per-entry state.
    fn start_new_entry(&mut self) {
        self.buffer.clear();
        self.item_offset = 0;
        self.item_length = 0;
        self.reset_entry_fields();
        self.has_entry = true;
    }

    /// Reset the extracted field values for a new entry.
    fn reset_entry_fields(&mut self) {
        self.entry_filetype = FileType::Unknown;
        self.entry_perm = 0;
        self.entry_size = 0;
        self.entry_hardlinks = 0;
        self.entry_flags = FileInfoFlags::empty();
        self.entry_perm_str.clear();
        self.entry_user_str.clear();
        self.entry_group_str.clear();
        self.entry_time_str.clear();
        self.entry_filename.clear();
        self.entry_symlink_target = None;
    }

    /// Discard the current in-progress entry.
    fn cleanup_entry(&mut self) {
        self.buffer.clear();
        self.has_entry = false;
    }

    /// Assemble a completed [`FileInfo`] from the currently accumulated fields,
    /// then reset for the next entry.
    fn finish_entry(&mut self) -> FileInfo {
        let info = FileInfo {
            filename: std::mem::take(&mut self.entry_filename),
            filetype: self.entry_filetype,
            perm: self.entry_perm,
            uid: 0,
            gid: 0,
            size: self.entry_size,
            hardlinks: self.entry_hardlinks,
            flags: self.entry_flags,
            time_str: std::mem::take(&mut self.entry_time_str),
            perm_str: std::mem::take(&mut self.entry_perm_str),
            user_str: std::mem::take(&mut self.entry_user_str),
            group_str: std::mem::take(&mut self.entry_group_str),
            symlink_target: self.entry_symlink_target.take(),
        };
        self.buffer.clear();
        self.item_offset = 0;
        self.item_length = 0;
        self.has_entry = false;
        info
    }

    /// Apply wildcard pattern filtering to a completed entry.
    ///
    /// Returns `Some(info)` if the entry should be included, `None` otherwise.
    fn apply_pattern_filter(&self, info: FileInfo) -> Option<FileInfo> {
        if let Some(ref pat) = self.pattern {
            // Use fnmatch to match pattern against filename.
            let result: FnMatchResult = curl_fnmatch(pat, &info.filename);
            if result == FnMatchResult::Match {
                // Discard symlinks whose target contains " -> " (multiple arrows).
                if info.filetype == FileType::SymLink {
                    if let Some(ref target) = info.symlink_target {
                        if target.contains(" -> ") {
                            return None;
                        }
                    }
                }
                Some(info)
            } else {
                None
            }
        } else {
            // No pattern — include all entries.
            Some(info)
        }
    }

    // -----------------------------------------------------------------------
    // Field extraction helpers
    // -----------------------------------------------------------------------

    /// Extract a substring from the buffer at `[offset .. offset+len-1)`.
    /// The `len` parameter includes the delimiter character, which is excluded
    /// from the extracted string (mirroring the C NUL-termination pattern).
    fn extract_field(&self, offset: usize, len: usize) -> String {
        if len <= 1 || offset >= self.buffer.len() {
            return String::new();
        }
        let end = (offset + len - 1).min(self.buffer.len());
        let start = offset.min(end);
        buf_to_string(&self.buffer[start..end])
    }

    // =======================================================================
    // Internal action enum for TotalSize state transitions
    // =======================================================================
}

/// Internal result from parsing the "total NNN" line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TotalSizeAction {
    /// Stay in TotalSize state, continue reading.
    Continue,
    /// First character was not 't' — fall through to FileType processing.
    FallthroughToFiletype,
    /// "total NNN" line complete — buffer cleared, ready for file entries.
    LineCompleted,
}

impl FtpListParser {
    // =======================================================================
    // Unix format parsing
    // =======================================================================

    /// Process a single character in Unix format mode.
    ///
    /// Returns `Ok(Some(FileInfo))` when a complete entry line has been parsed,
    /// `Ok(None)` when more data is needed, or `Err` on malformed input.
    fn parse_unix_char(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        // The TotalSize state may transition to FileType and require the same
        // character to be reprocessed by the FileType handler. We use a loop
        // with a reprocess flag to handle this cleanly (matching the C
        // FALLTHROUGH behaviour for the INIT case only).
        let mut reprocess = false;
        loop {
            let result = match self.unix_main {
                UnixMainState::TotalSize => {
                    let action = self.parse_unix_totalsize(c)?;
                    match action {
                        TotalSizeAction::Continue => Ok(None),
                        TotalSizeAction::FallthroughToFiletype => {
                            // Non-'t' first char — reprocess as filetype.
                            reprocess = true;
                            Ok(None)
                        }
                        TotalSizeAction::LineCompleted => {
                            // "total NNN" line done. Buffer was cleared.
                            // Do NOT reprocess '\n' in FileType.
                            Ok(None)
                        }
                    }
                }
                UnixMainState::FileType => {
                    let ft = unix_filetype(c)?;
                    self.entry_filetype = ft;
                    self.entry_flags |= FileInfoFlags::KNOWN_FILETYPE;
                    self.unix_main = UnixMainState::Permission;
                    self.unix_sub = UnixSubState::TotalSizeInit; // sub unused here
                    self.item_length = 0;
                    // Permission string starts at position 1 in the buffer
                    // (position 0 is the filetype character).
                    self.item_offset = self.buffer.len();
                    Ok(None)
                }
                UnixMainState::Permission => self.parse_unix_permission(c),
                UnixMainState::HardLinks => self.parse_unix_hlinks(c),
                UnixMainState::User => self.parse_unix_user(c),
                UnixMainState::Group => self.parse_unix_group(c),
                UnixMainState::Size => self.parse_unix_size(c),
                UnixMainState::Time => self.parse_unix_time(c),
                UnixMainState::Filename => self.parse_unix_filename(c),
                UnixMainState::Symlink => self.parse_unix_symlink(c),
            };

            if reprocess {
                reprocess = false;
                continue;
            }
            return result;
        }
    }

    // -----------------------------------------------------------------------
    // Unix: TotalSize
    // -----------------------------------------------------------------------

    /// Handle the "total NNN" header line or detect immediate filetype.
    fn parse_unix_totalsize(&mut self, c: u8) -> CurlResult<TotalSizeAction> {
        match self.unix_sub {
            UnixSubState::TotalSizeInit => {
                if c == b't' {
                    self.unix_sub = UnixSubState::TotalSizeReading;
                    self.item_length += 1;
                    Ok(TotalSizeAction::Continue)
                } else {
                    // Not a "total" line — this char is a filetype character.
                    self.unix_main = UnixMainState::FileType;
                    Ok(TotalSizeAction::FallthroughToFiletype)
                }
            }
            UnixSubState::TotalSizeReading => {
                self.item_length += 1;
                if c == b'\r' {
                    // Strip '\r' from buffer (Windows-style EOL).
                    self.item_length -= 1;
                    if !self.buffer.is_empty() {
                        self.buffer.pop();
                    }
                    Ok(TotalSizeAction::Continue)
                } else if c == b'\n' {
                    // Validate "total NNN" content.
                    let content_end = self.item_length - 1;
                    if content_end > self.buffer.len() {
                        return Err(CurlError::FtpBadFileList);
                    }
                    let content = &self.buffer[..content_end];
                    if content.len() >= 6 && &content[..6] == b"total " {
                        // Skip leading blanks after "total ".
                        let rest = &content[6..];
                        let trimmed = rest
                            .iter()
                            .skip_while(|&&b| b == b' ' || b == b'\t')
                            .copied()
                            .collect::<Vec<u8>>();
                        // Validate remaining chars are all digits.
                        let all_digits = !trimmed.is_empty()
                            && trimmed.iter().all(|b| b.is_ascii_digit());
                        if !all_digits && !trimmed.is_empty() {
                            return Err(CurlError::FtpBadFileList);
                        }
                        // Total line validated — reset for file entries.
                        self.unix_main = UnixMainState::FileType;
                        self.unix_sub = UnixSubState::TotalSizeInit;
                        self.buffer.clear();
                        self.item_offset = 0;
                        self.item_length = 0;
                        self.has_entry = false;
                        Ok(TotalSizeAction::LineCompleted)
                    } else {
                        Err(CurlError::FtpBadFileList)
                    }
                } else {
                    Ok(TotalSizeAction::Continue)
                }
            }
            // Other sub-states are not valid in TotalSize main state.
            _ => Err(CurlError::FtpBadFileList),
        }
    }

    // -----------------------------------------------------------------------
    // Unix: Permission
    // -----------------------------------------------------------------------

    /// Parse the 9-character permission string (e.g. "rwxr-xr-x").
    fn parse_unix_permission(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        self.item_length += 1;

        if self.item_length <= 9 {
            // Validate each permission character.
            if !matches!(c, b'r' | b'w' | b'x' | b'-' | b't' | b'T' | b's' | b'S') {
                return Err(CurlError::FtpBadFileList);
            }
        } else if self.item_length == 10 {
            // 10th character must be a space (after the 9 perm chars).
            if c != b' ' {
                return Err(CurlError::FtpBadFileList);
            }

            // Extract and validate the permission string.
            let perm_start = self.item_offset;
            let perm_end = perm_start + 9;
            if perm_end > self.buffer.len() {
                return Err(CurlError::FtpBadFileList);
            }
            let perm_bytes = &self.buffer[perm_start..perm_end];
            let perm_val = ftp_pl_get_permission(perm_bytes);
            if perm_val & FTP_LP_MALFORMED_PERM != 0 {
                return Err(CurlError::FtpBadFileList);
            }

            self.entry_flags |= FileInfoFlags::KNOWN_PERM;
            self.entry_perm = perm_val;
            self.entry_perm_str = buf_to_string(perm_bytes);

            // Transition to HardLinks state.
            self.item_length = 0;
            self.unix_main = UnixMainState::HardLinks;
            self.unix_sub = UnixSubState::HLinksPreSpace;
        }

        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Unix: HardLinks
    // -----------------------------------------------------------------------

    /// Parse the hard link count field.
    fn parse_unix_hlinks(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        match self.unix_sub {
            UnixSubState::HLinksPreSpace => {
                if c != b' ' {
                    if is_digit(c) && !self.buffer.is_empty() {
                        self.item_offset = self.buffer.len() - 1;
                        self.item_length = 1;
                        self.unix_sub = UnixSubState::HLinksNumber;
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
            UnixSubState::HLinksNumber => {
                self.item_length += 1;
                if c == b' ' {
                    // Extract hard link count string and parse it.
                    let field = self.extract_field(self.item_offset, self.item_length);
                    if let Ok(val) = field.trim().parse::<i64>() {
                        self.entry_flags |= FileInfoFlags::KNOWN_HLINKCOUNT;
                        self.entry_hardlinks = val;
                    }
                    self.item_length = 0;
                    self.item_offset = 0;
                    self.unix_main = UnixMainState::User;
                    self.unix_sub = UnixSubState::UserPreSpace;
                } else if !is_digit(c) {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            _ => return Err(CurlError::FtpBadFileList),
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Unix: User
    // -----------------------------------------------------------------------

    /// Parse the owner/user name field.
    fn parse_unix_user(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        match self.unix_sub {
            UnixSubState::UserPreSpace => {
                if c != b' ' && !self.buffer.is_empty() {
                    self.item_offset = self.buffer.len() - 1;
                    self.item_length = 1;
                    self.unix_sub = UnixSubState::UserParsing;
                }
            }
            UnixSubState::UserParsing => {
                self.item_length += 1;
                if c == b' ' {
                    self.entry_user_str =
                        self.extract_field(self.item_offset, self.item_length);
                    self.unix_main = UnixMainState::Group;
                    self.unix_sub = UnixSubState::GroupPreSpace;
                    self.item_offset = 0;
                    self.item_length = 0;
                }
            }
            _ => return Err(CurlError::FtpBadFileList),
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Unix: Group
    // -----------------------------------------------------------------------

    /// Parse the group name field.
    fn parse_unix_group(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        match self.unix_sub {
            UnixSubState::GroupPreSpace => {
                if c != b' ' && !self.buffer.is_empty() {
                    self.item_offset = self.buffer.len() - 1;
                    self.item_length = 1;
                    self.unix_sub = UnixSubState::GroupName;
                }
            }
            UnixSubState::GroupName => {
                self.item_length += 1;
                if c == b' ' {
                    self.entry_group_str =
                        self.extract_field(self.item_offset, self.item_length);
                    self.unix_main = UnixMainState::Size;
                    self.unix_sub = UnixSubState::SizePreSpace;
                    self.item_offset = 0;
                    self.item_length = 0;
                }
            }
            _ => return Err(CurlError::FtpBadFileList),
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Unix: Size
    // -----------------------------------------------------------------------

    /// Parse the file size field.
    fn parse_unix_size(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        match self.unix_sub {
            UnixSubState::SizePreSpace => {
                if c != b' ' {
                    if is_digit(c) && !self.buffer.is_empty() {
                        self.item_offset = self.buffer.len() - 1;
                        self.item_length = 1;
                        self.unix_sub = UnixSubState::SizeNumber;
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
            UnixSubState::SizeNumber => {
                self.item_length += 1;
                if c == b' ' {
                    let field = self.extract_field(self.item_offset, self.item_length);
                    if let Ok(val) = field.trim().parse::<i64>() {
                        if val != i64::MAX {
                            self.entry_flags |= FileInfoFlags::KNOWN_SIZE;
                            self.entry_size = val;
                        }
                    }
                    self.item_length = 0;
                    self.item_offset = 0;
                    self.unix_main = UnixMainState::Time;
                    self.unix_sub = UnixSubState::TimePrePart1;
                } else if !is_digit(c) {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            _ => return Err(CurlError::FtpBadFileList),
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Unix: Time (three-part: "MMM DD HH:MM" or "MMM DD  YYYY")
    // -----------------------------------------------------------------------

    /// Parse the modification time field (three whitespace-separated parts).
    fn parse_unix_time(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        match self.unix_sub {
            UnixSubState::TimePrePart1 => {
                if c != b' ' {
                    if is_alnum(c) && !self.buffer.is_empty() {
                        self.item_offset = self.buffer.len() - 1;
                        self.item_length = 1;
                        self.unix_sub = UnixSubState::TimePart1;
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
            UnixSubState::TimePart1 => {
                self.item_length += 1;
                if c == b' ' {
                    self.unix_sub = UnixSubState::TimePrePart2;
                } else if !is_alnum(c) && c != b'.' {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            UnixSubState::TimePrePart2 => {
                self.item_length += 1;
                if c != b' ' {
                    if is_alnum(c) {
                        self.unix_sub = UnixSubState::TimePart2;
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
            UnixSubState::TimePart2 => {
                self.item_length += 1;
                if c == b' ' {
                    self.unix_sub = UnixSubState::TimePrePart3;
                } else if !is_alnum(c) && c != b'.' {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            UnixSubState::TimePrePart3 => {
                self.item_length += 1;
                if c != b' ' {
                    if is_alnum(c) {
                        self.unix_sub = UnixSubState::TimePart3;
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
            UnixSubState::TimePart3 => {
                self.item_length += 1;
                if c == b' ' {
                    // Time field complete — extract the string.
                    self.entry_time_str =
                        self.extract_field(self.item_offset, self.item_length);
                    self.entry_flags |= FileInfoFlags::KNOWN_TIME;

                    // Choose next state based on file type.
                    if self.entry_filetype == FileType::SymLink {
                        self.unix_main = UnixMainState::Symlink;
                        self.unix_sub = UnixSubState::SymlinkPreSpace;
                    } else {
                        self.unix_main = UnixMainState::Filename;
                        self.unix_sub = UnixSubState::FilenamePreSpace;
                    }
                } else if !is_alnum(c) && c != b'.' && c != b':' {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            _ => return Err(CurlError::FtpBadFileList),
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Unix: Filename
    // -----------------------------------------------------------------------

    /// Parse the filename field (terminated by newline).
    fn parse_unix_filename(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        match self.unix_sub {
            UnixSubState::FilenamePreSpace => {
                if c != b' ' && !self.buffer.is_empty() {
                    self.item_offset = self.buffer.len() - 1;
                    self.item_length = 1;
                    self.unix_sub = UnixSubState::FilenameName;
                }
            }
            UnixSubState::FilenameName => {
                self.item_length += 1;
                if c == b'\r' {
                    self.unix_sub = UnixSubState::FilenameWindowsEol;
                } else if c == b'\n' {
                    self.entry_filename =
                        self.extract_field(self.item_offset, self.item_length);
                    self.entry_flags |= FileInfoFlags::KNOWN_FILENAME;
                    // Reset Unix state for next entry.
                    self.unix_main = UnixMainState::FileType;
                    return Ok(Some(self.finish_entry()));
                }
            }
            UnixSubState::FilenameWindowsEol => {
                if c == b'\n' {
                    // item_length already includes the '\r'; NUL replaces '\r'.
                    self.entry_filename =
                        self.extract_field(self.item_offset, self.item_length);
                    self.entry_flags |= FileInfoFlags::KNOWN_FILENAME;
                    self.unix_main = UnixMainState::FileType;
                    return Ok(Some(self.finish_entry()));
                } else {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            _ => return Err(CurlError::FtpBadFileList),
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Unix: Symlink (name -> target)
    // -----------------------------------------------------------------------

    /// Parse symlink name and target (e.g. "link -> /path/to/target").
    fn parse_unix_symlink(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        match self.unix_sub {
            UnixSubState::SymlinkPreSpace => {
                if c != b' ' && !self.buffer.is_empty() {
                    self.item_offset = self.buffer.len() - 1;
                    self.item_length = 1;
                    self.unix_sub = UnixSubState::SymlinkName;
                }
            }
            UnixSubState::SymlinkName => {
                self.item_length += 1;
                if c == b' ' {
                    self.unix_sub = UnixSubState::SymlinkPreTarget1;
                } else if c == b'\r' || c == b'\n' {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            UnixSubState::SymlinkPreTarget1 => {
                self.item_length += 1;
                if c == b'-' {
                    self.unix_sub = UnixSubState::SymlinkPreTarget2;
                } else if c == b'\r' || c == b'\n' {
                    return Err(CurlError::FtpBadFileList);
                } else {
                    // Space was part of the filename (filenames can have spaces).
                    self.unix_sub = UnixSubState::SymlinkName;
                }
            }
            UnixSubState::SymlinkPreTarget2 => {
                self.item_length += 1;
                if c == b'>' {
                    self.unix_sub = UnixSubState::SymlinkPreTarget3;
                } else if c == b'\r' || c == b'\n' {
                    return Err(CurlError::FtpBadFileList);
                } else {
                    self.unix_sub = UnixSubState::SymlinkName;
                }
            }
            UnixSubState::SymlinkPreTarget3 => {
                self.item_length += 1;
                if c == b' ' {
                    // Confirmed " -> " sequence. Extract filename (everything
                    // before the " -> ": offset to offset + item_length - 4).
                    let name_end = self.item_offset + self.item_length.saturating_sub(4);
                    let name_start = self.item_offset;
                    if name_end > name_start && name_end <= self.buffer.len() {
                        self.entry_filename =
                            buf_to_string(&self.buffer[name_start..name_end]);
                    }
                    self.entry_flags |= FileInfoFlags::KNOWN_FILENAME;
                    self.item_length = 0;
                    self.item_offset = 0;
                    self.unix_sub = UnixSubState::SymlinkPreTarget4;
                } else if c == b'\r' || c == b'\n' {
                    return Err(CurlError::FtpBadFileList);
                } else {
                    self.unix_sub = UnixSubState::SymlinkName;
                }
            }
            UnixSubState::SymlinkPreTarget4 => {
                if c != b'\r' && c != b'\n' && !self.buffer.is_empty() {
                    self.unix_sub = UnixSubState::SymlinkTarget;
                    self.item_offset = self.buffer.len() - 1;
                    self.item_length = 1;
                } else {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            UnixSubState::SymlinkTarget => {
                self.item_length += 1;
                if c == b'\r' {
                    self.unix_sub = UnixSubState::SymlinkWindowsEol;
                } else if c == b'\n' {
                    let target =
                        self.extract_field(self.item_offset, self.item_length);
                    self.entry_symlink_target = Some(target);
                    self.unix_main = UnixMainState::FileType;
                    return Ok(Some(self.finish_entry()));
                }
            }
            UnixSubState::SymlinkWindowsEol => {
                if c == b'\n' {
                    // item_length includes '\r' but not '\n'.
                    let target =
                        self.extract_field(self.item_offset, self.item_length);
                    self.entry_symlink_target = Some(target);
                    self.unix_main = UnixMainState::FileType;
                    return Ok(Some(self.finish_entry()));
                } else {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            _ => return Err(CurlError::FtpBadFileList),
        }
        Ok(None)
    }

    // =======================================================================
    // Windows NT format parsing
    // =======================================================================

    /// Process a single character in Windows NT format mode.
    fn parse_winnt_char(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        match self.winnt_main {
            WinNtMainState::Date => self.parse_winnt_date(c),
            WinNtMainState::Time => self.parse_winnt_time(c),
            WinNtMainState::DirOrSize => self.parse_winnt_dirorsize(c),
            WinNtMainState::Filename => self.parse_winnt_filename(c),
        }
    }

    // -----------------------------------------------------------------------
    // WinNT: Date (MM-DD-YY format, 8 characters + space)
    // -----------------------------------------------------------------------

    /// Parse the date field (e.g. "01-29-97 ").
    fn parse_winnt_date(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        self.item_length += 1;
        if self.item_length < 9 {
            if !matches!(c, b'0'..=b'9' | b'-') {
                return Err(CurlError::FtpBadFileList);
            }
        } else if self.item_length == 9 {
            if c == b' ' {
                self.winnt_main = WinNtMainState::Time;
                self.winnt_sub = WinNtSubState::TimePreSpace;
            } else {
                return Err(CurlError::FtpBadFileList);
            }
        } else {
            return Err(CurlError::FtpBadFileList);
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // WinNT: Time (HH:MMPP format)
    // -----------------------------------------------------------------------

    /// Parse the time field (e.g. "11:32PM ").
    fn parse_winnt_time(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        self.item_length += 1;
        match self.winnt_sub {
            WinNtSubState::TimePreSpace => {
                if !is_blank(c) {
                    self.winnt_sub = WinNtSubState::TimeTime;
                }
            }
            WinNtSubState::TimeTime => {
                if c == b' ' {
                    self.entry_time_str =
                        self.extract_field(self.item_offset, self.item_length);
                    self.entry_flags |= FileInfoFlags::KNOWN_TIME;
                    self.winnt_main = WinNtMainState::DirOrSize;
                    self.winnt_sub = WinNtSubState::DirOrSizePreSpace;
                    self.item_length = 0;
                } else if !matches!(c, b'A' | b'P' | b'M' | b'0'..=b'9' | b':') {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            _ => return Err(CurlError::FtpBadFileList),
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // WinNT: DirOrSize (<DIR> or numeric size)
    // -----------------------------------------------------------------------

    /// Parse the directory indicator or file size.
    fn parse_winnt_dirorsize(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        match self.winnt_sub {
            WinNtSubState::DirOrSizePreSpace => {
                if c != b' ' && !self.buffer.is_empty() {
                    self.item_offset = self.buffer.len() - 1;
                    self.item_length = 1;
                    self.winnt_sub = WinNtSubState::DirOrSizeContent;
                }
            }
            WinNtSubState::DirOrSizeContent => {
                self.item_length += 1;
                if c == b' ' {
                    let field =
                        self.extract_field(self.item_offset, self.item_length);
                    if field == "<DIR>" {
                        self.entry_filetype = FileType::Directory;
                        self.entry_size = 0;
                    } else {
                        let trimmed = field.trim();
                        match trimmed.parse::<i64>() {
                            Ok(sz) => {
                                self.entry_filetype = FileType::File;
                                self.entry_size = sz;
                            }
                            Err(_) => {
                                return Err(CurlError::FtpBadFileList);
                            }
                        }
                    }
                    self.entry_flags |=
                        FileInfoFlags::KNOWN_SIZE | FileInfoFlags::KNOWN_FILETYPE;
                    self.item_length = 0;
                    self.winnt_main = WinNtMainState::Filename;
                    self.winnt_sub = WinNtSubState::FilenamePreSpace;
                }
            }
            _ => return Err(CurlError::FtpBadFileList),
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // WinNT: Filename
    // -----------------------------------------------------------------------

    /// Parse the filename field in WinNT format.
    fn parse_winnt_filename(&mut self, c: u8) -> CurlResult<Option<FileInfo>> {
        match self.winnt_sub {
            WinNtSubState::FilenamePreSpace => {
                if c != b' ' && !self.buffer.is_empty() {
                    self.item_offset = self.buffer.len() - 1;
                    self.item_length = 1;
                    self.winnt_sub = WinNtSubState::FilenameContent;
                }
            }
            WinNtSubState::FilenameContent => {
                self.item_length += 1;
                if self.buffer.is_empty() {
                    return Err(CurlError::FtpBadFileList);
                }
                if c == b'\r' {
                    self.winnt_sub = WinNtSubState::FilenameWindowsEol;
                } else if c == b'\n' {
                    self.entry_filename =
                        self.extract_field(self.item_offset, self.item_length);
                    self.entry_flags |= FileInfoFlags::KNOWN_FILENAME;
                    self.winnt_main = WinNtMainState::Date;
                    self.winnt_sub = WinNtSubState::FilenamePreSpace;
                    self.item_length = 0;
                    return Ok(Some(self.finish_entry()));
                }
            }
            WinNtSubState::FilenameWindowsEol => {
                if c == b'\n' {
                    self.entry_filename =
                        self.extract_field(self.item_offset, self.item_length);
                    self.entry_flags |= FileInfoFlags::KNOWN_FILENAME;
                    self.winnt_main = WinNtMainState::Date;
                    self.winnt_sub = WinNtSubState::FilenamePreSpace;
                    self.item_length = 0;
                    return Ok(Some(self.finish_entry()));
                } else {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            _ => return Err(CurlError::FtpBadFileList),
        }
        Ok(None)
    }
}

// ===========================================================================
// Default impl for FtpListParser
// ===========================================================================

impl Default for FtpListParser {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_info_flags_empty() {
        let flags = FileInfoFlags::empty();
        assert!(!flags.contains(FileInfoFlags::KNOWN_FILENAME));
        assert!(!flags.contains(FileInfoFlags::KNOWN_SIZE));
    }

    #[test]
    fn test_file_info_flags_combine() {
        let mut flags = FileInfoFlags::empty();
        flags |= FileInfoFlags::KNOWN_FILENAME;
        flags |= FileInfoFlags::KNOWN_SIZE;
        assert!(flags.contains(FileInfoFlags::KNOWN_FILENAME));
        assert!(flags.contains(FileInfoFlags::KNOWN_SIZE));
        assert!(!flags.contains(FileInfoFlags::KNOWN_PERM));
    }

    #[test]
    fn test_permission_parser_rwxrwxrwx() {
        let perm = ftp_pl_get_permission(b"rwxrwxrwx");
        assert_eq!(perm, 0o777);
    }

    #[test]
    fn test_permission_parser_rw_r_r() {
        let perm = ftp_pl_get_permission(b"rw-r--r--");
        assert_eq!(perm, 0o644);
    }

    #[test]
    fn test_permission_parser_setuid() {
        let perm = ftp_pl_get_permission(b"rws------");
        assert_eq!(perm & 0o7777, 0o4700);
    }

    #[test]
    fn test_permission_parser_sticky() {
        let perm = ftp_pl_get_permission(b"rwxrwxrwt");
        assert_eq!(perm & 0o7777, 0o1777);
    }

    #[test]
    fn test_permission_parser_malformed() {
        let perm = ftp_pl_get_permission(b"rwxZwxrwx");
        assert_ne!(perm & FTP_LP_MALFORMED_PERM, 0);
    }

    #[test]
    fn test_unix_filetype_detection() {
        assert_eq!(unix_filetype(b'-').unwrap(), FileType::File);
        assert_eq!(unix_filetype(b'd').unwrap(), FileType::Directory);
        assert_eq!(unix_filetype(b'l').unwrap(), FileType::SymLink);
        assert_eq!(unix_filetype(b'p').unwrap(), FileType::NamedPipe);
        assert_eq!(unix_filetype(b's').unwrap(), FileType::Socket);
        assert_eq!(unix_filetype(b'c').unwrap(), FileType::DeviceChar);
        assert_eq!(unix_filetype(b'b').unwrap(), FileType::DeviceBlock);
        assert_eq!(unix_filetype(b'D').unwrap(), FileType::Door);
        assert!(unix_filetype(b'?').is_err());
    }

    #[test]
    fn test_parse_unix_regular_file() {
        let mut parser = FtpListParser::new();
        let line = b"-rw-r--r-- 1 user grp 1024 Jan 15 10:30 hello.txt\n";
        let entries = parser.parse(line).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.filename, "hello.txt");
        assert_eq!(e.filetype, FileType::File);
        assert_eq!(e.perm, 0o644);
        assert_eq!(e.size, 1024);
        assert_eq!(e.hardlinks, 1);
        assert!(e.flags.contains(FileInfoFlags::KNOWN_FILENAME));
        assert!(e.flags.contains(FileInfoFlags::KNOWN_PERM));
        assert!(e.flags.contains(FileInfoFlags::KNOWN_SIZE));
        assert!(e.flags.contains(FileInfoFlags::KNOWN_HLINKCOUNT));
        assert!(e.flags.contains(FileInfoFlags::KNOWN_TIME));
        assert_eq!(e.user_str, "user");
        assert_eq!(e.group_str, "grp");
        assert_eq!(e.perm_str, "rw-r--r--");
    }

    #[test]
    fn test_parse_unix_directory() {
        let mut parser = FtpListParser::new();
        let line = b"drwxr-xr-x 2 root root 4096 Feb 20 2024 mydir\n";
        let entries = parser.parse(line).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "mydir");
        assert_eq!(entries[0].filetype, FileType::Directory);
    }

    #[test]
    fn test_parse_unix_symlink() {
        let mut parser = FtpListParser::new();
        let line = b"lrwxrwxrwx 1 user grp 10 Mar 05 12:00 link -> target\n";
        let entries = parser.parse(line).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "link");
        assert_eq!(entries[0].filetype, FileType::SymLink);
        assert_eq!(entries[0].symlink_target.as_deref(), Some("target"));
    }

    #[test]
    fn test_parse_unix_with_total_line() {
        let mut parser = FtpListParser::new();
        let data =
            b"total 1234\n-rw-r--r-- 1 user grp 100 Jan 01 00:00 file.txt\n";
        let entries = parser.parse(data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "file.txt");
    }

    #[test]
    fn test_parse_unix_multiple_entries() {
        let mut parser = FtpListParser::new();
        let data = b"-rw-r--r-- 1 user grp 100 Jan 01 00:00 a.txt\ndrwxr-xr-x 2 user grp 4096 Feb 02 12:00 subdir\n";
        let entries = parser.parse(data).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename, "a.txt");
        assert_eq!(entries[1].filename, "subdir");
    }

    #[test]
    fn test_parse_unix_windows_eol() {
        let mut parser = FtpListParser::new();
        let line = b"-rw-r--r-- 1 user grp 256 Dec 25 14:30 xmas.txt\r\n";
        let entries = parser.parse(line).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "xmas.txt");
    }

    #[test]
    fn test_parse_winnt_directory() {
        let mut parser = FtpListParser::new();
        let line = b"01-29-97 11:32PM <DIR> prog\n";
        let entries = parser.parse(line).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "prog");
        assert_eq!(entries[0].filetype, FileType::Directory);
        assert_eq!(entries[0].size, 0);
    }

    #[test]
    fn test_parse_winnt_file() {
        let mut parser = FtpListParser::new();
        let line = b"12-05-23 03:45PM       1234 readme.txt\n";
        let entries = parser.parse(line).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "readme.txt");
        assert_eq!(entries[0].filetype, FileType::File);
        assert_eq!(entries[0].size, 1234);
    }

    #[test]
    fn test_parse_winnt_windows_eol() {
        let mut parser = FtpListParser::new();
        let line = b"01-01-24 10:00AM <DIR> mydir\r\n";
        let entries = parser.parse(line).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "mydir");
    }

    #[test]
    fn test_pattern_filter_match() {
        let mut parser = FtpListParser::new();
        parser.set_pattern(Some("*.txt".to_string()));
        let data = b"-rw-r--r-- 1 user grp 100 Jan 01 00:00 file.txt\n-rw-r--r-- 1 user grp 200 Jan 01 00:00 file.rs\n";
        let entries = parser.parse(data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "file.txt");
    }

    #[test]
    fn test_pattern_filter_no_match() {
        let mut parser = FtpListParser::new();
        parser.set_pattern(Some("*.jpg".to_string()));
        let line = b"-rw-r--r-- 1 user grp 100 Jan 01 00:00 file.txt\n";
        let entries = parser.parse(line).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_malformed_unix_permission() {
        let mut parser = FtpListParser::new();
        let line = b"-rZ-r--r-- 1 user grp 100 Jan 01 00:00 file.txt\n";
        assert!(parser.parse(line).is_err());
    }

    #[test]
    fn test_error_persists() {
        let mut parser = FtpListParser::new();
        let bad = b"XXXXXXXXX\n";
        let _ = parser.parse(bad);
        assert!(parser.get_error().is_some());
        assert!(parser.parse(b"more data").is_err());
    }

    #[test]
    fn test_reset_clears_error() {
        let mut parser = FtpListParser::new();
        let _ = parser.parse(b"XXXXXXXXX\n");
        assert!(parser.get_error().is_some());
        parser.reset();
        assert!(parser.get_error().is_none());
    }

    #[test]
    fn test_wildcard_data_new() {
        let wd = WildcardData::new();
        assert_eq!(wd.state, WildcardState::Init);
        assert!(wd.filelist.is_empty());
        assert!(wd.path.is_empty());
        assert!(wd.pattern.is_empty());
    }

    #[test]
    fn test_wildcard_data_init() {
        let mut wd = WildcardData::new();
        wd.init("/pub/".to_string(), "*.txt".to_string());
        assert_eq!(wd.path, "/pub/");
        assert_eq!(wd.pattern, "*.txt");
        assert_eq!(wd.state, WildcardState::Init);
    }

    #[test]
    fn test_ftp_list_format_default() {
        assert_eq!(FtpListFormat::default(), FtpListFormat::Unknown);
    }

    #[test]
    fn test_wildcard_state_default() {
        assert_eq!(WildcardState::default(), WildcardState::Init);
    }

    #[test]
    fn test_parse_streaming_chunks() {
        let mut parser = FtpListParser::new();
        let full = b"-rw-r--r-- 1 user grp 512 Jan 15 10:30 streamed.dat\n";
        let chunk1 = &full[..15];
        let chunk2 = &full[15..35];
        let chunk3 = &full[35..];
        let e1 = parser.parse(chunk1).unwrap();
        assert!(e1.is_empty());
        let e2 = parser.parse(chunk2).unwrap();
        assert!(e2.is_empty());
        let e3 = parser.parse(chunk3).unwrap();
        assert_eq!(e3.len(), 1);
        assert_eq!(e3[0].filename, "streamed.dat");
    }

    #[test]
    fn test_parse_unix_large_size() {
        let mut parser = FtpListParser::new();
        let line = b"-rw-r--r-- 1 user grp 9999999999 Jan 15 10:30 big.bin\n";
        let entries = parser.parse(line).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].size, 9_999_999_999);
    }

    #[test]
    fn test_symlink_with_space_in_name() {
        let mut parser = FtpListParser::new();
        let line = b"lrwxrwxrwx 1 user grp 10 Mar 05 12:00 my link -> target\n";
        let entries = parser.parse(line).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "my link");
        assert_eq!(entries[0].symlink_target.as_deref(), Some("target"));
    }

    #[test]
    fn test_default_parser() {
        let parser = FtpListParser::default();
        assert_eq!(parser.format, FtpListFormat::Unknown);
        assert!(parser.get_error().is_none());
    }

    #[test]
    fn test_fnmatch_usage_explicit() {
        let result = curl_fnmatch("*.txt", "hello.txt");
        assert_eq!(result, FnMatchResult::Match);
        let result2 = curl_fnmatch("*.txt", "hello.rs");
        assert_ne!(result2, FnMatchResult::Match);
    }
}
