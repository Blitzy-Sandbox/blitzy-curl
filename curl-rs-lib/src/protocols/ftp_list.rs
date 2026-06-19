//! FTP `LIST` directory-output parser and wildcard (glob) transfer driver.
//!
//! This module is the Rust analog of curl's `lib/ftplistparser.c` plus the
//! [`curl_fileinfo`] carrier defined in `lib/fileinfo.c` /
//! `include/curl/curl.h`. It turns the raw bytes of an FTP `LIST` response into
//! a sequence of structured [`FileInfo`] entries and provides the wildcard
//! selection machinery ([`WildcardData`] / [`WildcardState`]) that the FTP
//! protocol handler (`ftp.rs`) drives between the `Matching` and `Downloading`
//! phases of a `CURLOPT_WILDCARDMATCH` transfer.
//!
//! # Supported listing formats
//!
//! Exactly the two formats that curl 8.x's parser recognizes are implemented,
//! reproducing its per-byte state machine verbatim so the extracted fields are
//! byte-for-byte identical:
//!
//! * **UNIX `ls -l`** — `drwxr-xr-x 1 user group 512 Jan 29 23:32 name`,
//!   including the `name -> target` symlink form and an optional leading
//!   `total N` directory-size line.
//! * **Windows / DOS** — `MM-DD-YY  HH:MMAM <DIR>|size name`.
//!
//! The output style is auto-detected from the **first byte** of the response,
//! exactly as curl does: a leading ASCII digit selects the Windows/DOS engine,
//! anything else selects the UNIX engine (`Curl_ftp_parselist`). curl
//! 8.19.0-DEV ships **no** EPLF engine — there is no EPLF code in `lib/` and no
//! EPLF test fixture — so none is added here; doing so would change observable
//! behavior (a `+`-prefixed line is routed to, and rejected by, the UNIX
//! engine) and break wire/behavioral parity.
//!
//! # Relationship to the public ABI
//!
//! [`FileInfo`], [`FileType`], and the `FINFOFLAG_KNOWN_*` constants mirror the
//! **public** `curl_fileinfo` struct, the `curlfiletype` enum, and the
//! `CURLFINFOFLAG_KNOWN_*` flags. Their discriminants and bit values are kept
//! exact because this carrier is surfaced to the `CURLOPT_CHUNK_BGN_FUNCTION`
//! callback and, ultimately, to the FFI `#[repr(C)] curl_fileinfo` that
//! `curl-rs-ffi` builds from it. The private C allocation fields
//! (`b_data`/`b_size`/`b_used`) are intentionally **not** mirrored: the owned
//! [`String`]/[`Vec`] fields replace that hand-rolled buffer.
//!
//! # Memory safety (AAP §0.7.1)
//!
//! Compiled under the crate-root `#![forbid(unsafe_code)]`; this module
//! contains **zero** `unsafe`. The C parser's single growing `dynbuf` with
//! in-place `NUL` terminators and integer field offsets is reproduced with a
//! safe [`Vec<u8>`] line buffer plus recorded offsets, and the C linked list of
//! results becomes a [`Vec<FileInfo>`].

use crate::error::{CurlError, Result};
use crate::util::fnmatch::{curl_fnmatch, FnMatch};

// ===========================================================================
// Public ABI mirrors — flags, file type, and the `FileInfo` carrier.
// ===========================================================================

/// `CURLFINFOFLAG_KNOWN_FILENAME` — the [`FileInfo::filename`] field is set.
pub const FINFOFLAG_KNOWN_FILENAME: u32 = 1 << 0;
/// `CURLFINFOFLAG_KNOWN_FILETYPE` — the [`FileInfo::filetype`] field is set.
pub const FINFOFLAG_KNOWN_FILETYPE: u32 = 1 << 1;
/// `CURLFINFOFLAG_KNOWN_TIME` — the (numeric) time field is set.
pub const FINFOFLAG_KNOWN_TIME: u32 = 1 << 2;
/// `CURLFINFOFLAG_KNOWN_PERM` — the [`FileInfo::perm`] field is set.
pub const FINFOFLAG_KNOWN_PERM: u32 = 1 << 3;
/// `CURLFINFOFLAG_KNOWN_UID` — the [`FileInfo::uid`] field is set.
pub const FINFOFLAG_KNOWN_UID: u32 = 1 << 4;
/// `CURLFINFOFLAG_KNOWN_GID` — the [`FileInfo::gid`] field is set.
pub const FINFOFLAG_KNOWN_GID: u32 = 1 << 5;
/// `CURLFINFOFLAG_KNOWN_SIZE` — the [`FileInfo::size`] field is set.
pub const FINFOFLAG_KNOWN_SIZE: u32 = 1 << 6;
/// `CURLFINFOFLAG_KNOWN_HLINKCOUNT` — the [`FileInfo::hardlinks`] field is set.
pub const FINFOFLAG_KNOWN_HLINKCOUNT: u32 = 1 << 7;

/// Internal sentinel OR-ed into a parsed permission value when a malformed
/// permission character is encountered. Mirrors curl's
/// `FTP_LP_MALFORMATED_PERM` (`0x01000000`). It is never stored in a published
/// [`FileInfo`]: its presence makes the parser reject the line.
const FTP_LP_MALFORMATED_PERM: u32 = 0x0100_0000;

/// Upper bound (in bytes) for a single accumulated `LIST` line, mirroring
/// curl's `MAX_FTPLIST_BUFFER`. A line that would exceed it aborts parsing
/// with [`CurlError::OutOfMemory`], matching curl's `dynbuf` cap behavior and
/// bounding memory against a hostile server.
const MAX_FTPLIST_BUFFER: usize = 10000;

/// File type of a listed entry — the Rust mirror of curl's public
/// `curlfiletype` enum (`CURLFILETYPE_*`).
///
/// The discriminants are fixed by the public ABI and must not change: the FFI
/// `curl_fileinfo.filetype` field and the chunk callback both observe them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileType {
    /// `CURLFILETYPE_FILE` — a regular file.
    #[default]
    File = 0,
    /// `CURLFILETYPE_DIRECTORY` — a directory.
    Directory = 1,
    /// `CURLFILETYPE_SYMLINK` — a symbolic link (see [`FileInfoStrings::target`]).
    Symlink = 2,
    /// `CURLFILETYPE_DEVICE_BLOCK` — a block device.
    DeviceBlock = 3,
    /// `CURLFILETYPE_DEVICE_CHAR` — a character device.
    DeviceChar = 4,
    /// `CURLFILETYPE_NAMEDPIPE` — a FIFO / named pipe.
    NamedPipe = 5,
    /// `CURLFILETYPE_SOCKET` — a socket.
    Socket = 6,
    /// `CURLFILETYPE_DOOR` — a Solaris door.
    Door = 7,
    /// `CURLFILETYPE_UNKNOWN` — should never occur for a parsed entry.
    Unknown = 8,
}

impl FileType {
    /// Returns the public-ABI integer discriminant (`CURLFILETYPE_*`).
    #[inline]
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// The human-readable string fields of a [`FileInfo`].
///
/// Each is `Some` only when the corresponding token was present in the listing.
/// This mirrors the `strings` sub-struct of the public `curl_fileinfo`, where
/// the equivalent C pointers are non-`NULL` only when the field is known. The
/// [`time`](Self::time) string is the *human-readable* timestamp from the
/// listing (e.g. `"Jan 29 23:32"`); the numeric `curl_fileinfo.time` is always
/// zero (see [`FileInfo::time`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileInfoStrings {
    /// The raw human-readable time token, e.g. `"Apr 27  5:12"`.
    pub time: Option<String>,
    /// The raw permission token, e.g. `"rwxr-xr-x"` (UNIX listings only).
    pub perm: Option<String>,
    /// The owning-user token (UNIX listings only).
    pub user: Option<String>,
    /// The owning-group token (UNIX listings only).
    pub group: Option<String>,
    /// For a [`FileType::Symlink`], the link target filename.
    pub target: Option<String>,
}

/// Information about a single listed file — the Rust mirror of the public
/// `struct curl_fileinfo` used during FTP wildcard matching.
///
/// Field semantics match curl exactly so the FFI layer can build a
/// `#[repr(C)] curl_fileinfo` from this and the chunk callback observes
/// identical values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileInfo {
    /// The entry's filename (for a symlink, the link name, not the target).
    pub filename: String,
    /// The entry's [`FileType`].
    pub filetype: FileType,
    /// Numeric modification time. **Always zero**, preserving curl's documented
    /// quirk (`time_t time; /* always zero! */`): the human-readable timestamp
    /// is carried by [`FileInfoStrings::time`] instead.
    pub time: i64,
    /// POSIX permission bits parsed from a UNIX permission string (e.g.
    /// `"rw-r--r--"` → `0o644`). Valid only when [`FINFOFLAG_KNOWN_PERM`] is set
    /// in [`flags`](Self::flags).
    pub perm: u32,
    /// Owning user id. Never populated by the listing parser (kept for ABI
    /// parity); valid only when [`FINFOFLAG_KNOWN_UID`] is set.
    pub uid: i32,
    /// Owning group id. Never populated by the listing parser (kept for ABI
    /// parity); valid only when [`FINFOFLAG_KNOWN_GID`] is set.
    pub gid: i32,
    /// File size in bytes (curl's `curl_off_t`). Valid only when
    /// [`FINFOFLAG_KNOWN_SIZE`] is set.
    pub size: i64,
    /// Hard-link count. Valid only when [`FINFOFLAG_KNOWN_HLINKCOUNT`] is set.
    pub hardlinks: i64,
    /// The human-readable string fields (see [`FileInfoStrings`]).
    pub strings: FileInfoStrings,
    /// Bitset of `FINFOFLAG_KNOWN_*` flags indicating which fields are valid.
    pub flags: u32,
}

// ===========================================================================
// Wildcard transfer state — mirror of C `WildcardData` + `wildcard_states`.
// ===========================================================================

/// The wildcard-download state machine, mirroring curl's `wildcard_states`
/// (`CURLWC_*`). The FTP handler advances a [`WildcardData`] through these
/// states while performing a `CURLOPT_WILDCARDMATCH` transfer. Discriminants
/// match the C enum exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WildcardState {
    /// `CURLWC_CLEAR` — uninitialized / freshly zeroed.
    #[default]
    Clear = 0,
    /// `CURLWC_INIT` — initialized, ready to begin matching.
    Init = 1,
    /// `CURLWC_MATCHING` — retrieving and parsing the directory listing.
    Matching = 2,
    /// `CURLWC_DOWNLOADING` — downloading the selected (matched) entries.
    Downloading = 3,
    /// `CURLWC_CLEAN` — releasing resources and resetting per-transfer settings.
    Clean = 4,
    /// `CURLWC_SKIP` — skipping the current entry.
    Skip = 5,
    /// `CURLWC_ERROR` — an error occurred.
    Error = 6,
    /// `CURLWC_DONE` — the wildcard loop is finished.
    Done = 7,
}

impl WildcardState {
    /// Returns the public integer discriminant (`CURLWC_*`).
    #[inline]
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// State for a single wildcard (glob) download, the Rust mirror of curl's
/// `struct WildcardData`.
///
/// The C `Curl_llist filelist` of `curl_fileinfo` becomes a [`Vec<FileInfo>`],
/// and the C destructor function-pointer is replaced by ordinary [`Drop`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WildcardData {
    /// Path to the directory being matched (everything up to the last `/`).
    pub path: String,
    /// The wildcard pattern (the last path segment containing glob characters).
    pub pattern: String,
    /// The list of entries selected for download (filled by [`Self::select_matches`]).
    pub filelist: Vec<FileInfo>,
    /// Current state in the wildcard download state machine.
    pub state: WildcardState,
}

impl WildcardData {
    /// Creates a wildcard context for `path`/`pattern` in the [`WildcardState::Init`]
    /// state (mirrors `Curl_wildcard_init`, which sets `CURLWC_INIT`).
    #[must_use]
    pub fn new(path: impl Into<String>, pattern: impl Into<String>) -> Self {
        WildcardData {
            path: path.into(),
            pattern: pattern.into(),
            filelist: Vec::new(),
            state: WildcardState::Init,
        }
    }

    /// Initializes the context: clears the file list and enters
    /// [`WildcardState::Init`] (← `Curl_wildcard_init`).
    pub fn init(&mut self) {
        self.filelist.clear();
        self.state = WildcardState::Init;
    }

    /// Resets the context for reuse: clears the file list, path, and pattern and
    /// returns to [`WildcardState::Init`]. Memory is reclaimed automatically via
    /// [`Drop`] (← `Curl_wildcard_dtor`).
    pub fn reset(&mut self) {
        self.filelist.clear();
        self.path.clear();
        self.pattern.clear();
        self.state = WildcardState::Init;
    }

    /// Selects, from `entries`, those whose filename matches [`Self::pattern`],
    /// storing the survivors in [`Self::filelist`] (replacing any prior
    /// contents).
    ///
    /// This is the wildcard selection step that the FTP handler runs between the
    /// `Matching` and `Downloading` phases. Matching uses curl's own
    /// [`curl_fnmatch`] (never a generic glob crate) for byte-exact pattern
    /// parity. As in curl's `ftp_pl_insert_finfo`, a symlink whose target itself
    /// contains `" -> "` (an ambiguous link) is discarded even if its name
    /// matches.
    pub fn select_matches<I>(&mut self, entries: I)
    where
        I: IntoIterator<Item = FileInfo>,
    {
        let pattern = self.pattern.clone();
        self.filelist = entries
            .into_iter()
            .filter(|fi| Self::matches(pattern.as_bytes(), fi))
            .collect();
    }

    /// Returns `true` if `finfo` should be selected for `pattern`.
    ///
    /// Equivalent to curl's filter in `ftp_pl_insert_finfo`: the name must match
    /// the pattern, and an ambiguous symlink (target containing `" -> "`) is
    /// rejected.
    #[must_use]
    pub fn matches(pattern: &[u8], finfo: &FileInfo) -> bool {
        if curl_fnmatch(pattern, finfo.filename.as_bytes()) != FnMatch::Match {
            return false;
        }
        if finfo.filetype == FileType::Symlink {
            if let Some(target) = finfo.strings.target.as_deref() {
                if target.contains(" -> ") {
                    return false;
                }
            }
        }
        true
    }
}

// ===========================================================================
// Parser internal state types (private) — mirror of C `ftp_parselist_data`.
// ===========================================================================

/// Detected listing style, mirroring the C `os_type` discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum OsType {
    /// Not yet determined (no bytes seen).
    #[default]
    Unknown,
    /// UNIX `ls -l` style.
    Unix,
    /// Windows / DOS style.
    WinNt,
}

/// Byte offsets, into the current line buffer, of each captured field. A value
/// of `0` means "not captured" for the optional fields (`perm`/`user`/`group`/
/// `symlink_target`); `filename` and `time` are always captured for a complete
/// line. Mirrors the C `parser->offsets` struct.
#[derive(Debug, Clone, Copy, Default)]
struct Offsets {
    filename: usize,
    user: usize,
    group: usize,
    time: usize,
    perm: usize,
    symlink_target: usize,
}

/// The in-progress entry: the accumulating line buffer plus the scalar fields
/// set while parsing. Mirrors the C `struct fileinfo` (its `info` + `buf`).
#[derive(Debug, Default)]
struct Working {
    /// The raw bytes of the current line accumulated so far. Field boundaries
    /// are marked in place with `NUL` bytes, exactly as curl's `dynbuf` does.
    buf: Vec<u8>,
    /// The scalar fields (perm, size, hardlinks, filetype, flags) filled during
    /// parsing; the string fields are filled at line completion from the buffer
    /// and [`Offsets`].
    info: FileInfo,
}

// ---- UNIX engine main/sub states (mirror C `pl_unix_mainstate`/substates) --

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnixState {
    TotalSize(TotalSub),
    FileType,
    Permission,
    HLinks(HLinksSub),
    User(UserSub),
    Group(GroupSub),
    Size(SizeSub),
    Time(TimeSub),
    Filename(FilenameSub),
    Symlink(SymlinkSub),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TotalSub {
    Init,
    Reading,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HLinksSub {
    PreSpace,
    Number,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserSub {
    PreSpace,
    Parsing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupSub {
    PreSpace,
    Name,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SizeSub {
    PreSpace,
    Number,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeSub {
    PrePart1,
    Part1,
    PrePart2,
    Part2,
    PrePart3,
    Part3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilenameSub {
    PreSpace,
    Name,
    WindowsEol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymlinkSub {
    PreSpace,
    Name,
    PreTarget1,
    PreTarget2,
    PreTarget3,
    PreTarget4,
    Target,
    WindowsEol,
}

// ---- Windows/NT engine main/sub states (mirror C `pl_winNT_*state`) --------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NtState {
    Date,
    Time(NtTimeSub),
    DirOrSize(NtDirSub),
    Filename(NtFnSub),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NtTimeSub {
    PreSpace,
    Time,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NtDirSub {
    PreSpace,
    Content,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NtFnSub {
    PreSpace,
    Content,
    WinEol,
}

// ===========================================================================
// `FtpParseListData` — the incremental LIST parser (mirror of C
// `Curl_ftp_parselist` + `struct ftp_parselist_data`).
// ===========================================================================

/// Incremental parser for FTP `LIST` output.
///
/// Feed it the response in arbitrary byte chunks via [`parse_chunk`]; each
/// completed line is decoded into a [`FileInfo`] and appended to an internal
/// list retrievable with [`entries`] / [`take_entries`]. This is the Rust
/// analog of curl's `Curl_ftp_parselist` `WRITEFUNCTION` and the
/// `ftp_parselist_data` it threads through.
///
/// The parser is a faithful port of curl's per-character finite state machine:
/// it keeps the partial-line bytes in a single buffer, marks field boundaries
/// with in-place `NUL` terminators, and records byte offsets — so the extracted
/// field strings are byte-for-byte identical to curl's.
///
/// [`parse_chunk`]: Self::parse_chunk
/// [`entries`]: Self::entries
/// [`take_entries`]: Self::take_entries
#[derive(Debug, Default)]
pub struct FtpParseListData {
    /// Detected listing style (set from the first byte seen).
    os_type: OsType,
    /// Current UNIX-engine state (valid while `os_type == Unix`).
    unix_state: UnixState,
    /// Current Windows/NT-engine state (valid while `os_type == WinNt`).
    nt_state: NtState,
    /// Offset of the field currently being captured, into [`Working::buf`].
    item_offset: usize,
    /// Length of the field currently being captured.
    item_length: usize,
    /// Recorded byte offsets of completed fields for the current line.
    offsets: Offsets,
    /// The entry under construction, or `None` between lines.
    working: Option<Working>,
    /// Set by a sub-state when the current line is complete and its
    /// [`Working`] should be finalized into a [`FileInfo`].
    complete: bool,
    /// Completed entries, in listing order.
    entries: Vec<FileInfo>,
    /// The first parse error encountered, if any (← `parser->error`).
    error: Option<CurlError>,
}

impl Default for UnixState {
    #[inline]
    fn default() -> Self {
        // C zero-init: main = PL_UNIX_TOTALSIZE, sub.total_dirsize = INIT.
        UnixState::TotalSize(TotalSub::Init)
    }
}

impl Default for NtState {
    #[inline]
    fn default() -> Self {
        // C zero-init: main = PL_WINNT_DATE.
        NtState::Date
    }
}

impl FtpParseListData {
    /// Creates a fresh parser (← `Curl_ftp_parselist_data_alloc`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the first captured parse error, if any (←
    /// `Curl_ftp_parselist_geterror`).
    #[must_use]
    pub fn geterror(&self) -> Option<CurlError> {
        self.error
    }

    /// Returns the entries parsed so far, in listing order.
    #[must_use]
    pub fn entries(&self) -> &[FileInfo] {
        &self.entries
    }

    /// Removes and returns all parsed entries, leaving the internal list empty.
    #[must_use]
    pub fn take_entries(&mut self) -> Vec<FileInfo> {
        core::mem::take(&mut self.entries)
    }

    /// Feeds a chunk of `LIST` response bytes to the parser (← the
    /// `Curl_ftp_parselist` `WRITEFUNCTION`).
    ///
    /// Lines may be split across chunk boundaries; partial lines are buffered
    /// until complete. Each completed entry is appended to the internal list.
    ///
    /// # Errors
    ///
    /// Returns the captured [`CurlError`] (also retrievable via [`geterror`]) on
    /// the first malformed line ([`CurlError::FtpBadFileList`]) or if a single
    /// line exceeds [`MAX_FTPLIST_BUFFER`] ([`CurlError::OutOfMemory`]). Once an
    /// error has been recorded, subsequent calls short-circuit and return it,
    /// mirroring curl's "skip on prior error" behavior.
    ///
    /// [`geterror`]: Self::geterror
    pub fn parse_chunk(&mut self, buffer: &[u8]) -> Result<()> {
        // A prior error means every later chunk is a no-op that re-surfaces it
        // (curl checks `parser->error` first and bails).
        if let Some(err) = self.error {
            return Err(err);
        }

        // Detect the listing style from the very first byte, exactly as curl:
        // a leading digit => Windows/DOS, otherwise UNIX.
        if self.os_type == OsType::Unknown && !buffer.is_empty() {
            self.os_type = if buffer[0].is_ascii_digit() {
                OsType::WinNt
            } else {
                OsType::Unix
            };
        }

        for &c in buffer {
            // Allocate a fresh per-line working buffer if needed, resetting the
            // per-line item bookkeeping and field offsets (curl resets
            // item_offset/item_length on a new file_data; we additionally clear
            // the offsets so an entry never inherits a previous symlink target).
            let mut working = match self.working.take() {
                Some(w) => w,
                None => {
                    self.item_offset = 0;
                    self.item_length = 0;
                    self.offsets = Offsets::default();
                    Working::default()
                }
            };

            // Enforce the per-line buffer cap before appending (curl's dynbuf
            // refuses growth past MAX_FTPLIST_BUFFER, which the parser maps to
            // CURLE_OUT_OF_MEMORY). `fit = new + old + 1` mirrors dyn_nappend.
            let fit = working.buf.len() + 1 + 1;
            if fit > MAX_FTPLIST_BUFFER {
                self.error = Some(CurlError::OutOfMemory);
                return Err(CurlError::OutOfMemory);
            }

            // curl appends the byte to the buffer *before* dispatching, so the
            // state handlers see the current char already present at the tail.
            working.buf.push(c);

            let result = match self.os_type {
                OsType::Unix => self.parse_unix(&mut working, c),
                OsType::WinNt => self.parse_winnt(&mut working, c),
                // Unreachable once a non-empty chunk has set the style; guarded
                // defensively without panicking.
                OsType::Unknown => Err(CurlError::FtpBadFileList),
            };

            if let Err(err) = result {
                self.error = Some(err);
                // curl frees the in-progress file_data on failure; dropping
                // `working` here does the same.
                return Err(err);
            }

            if self.complete {
                self.complete = false;
                let finfo = self.finish_file(working);
                self.entries.push(finfo);
                // Leave `self.working` as None so the next byte starts a fresh
                // entry (curl sets file_data = NULL after inserting).
            } else {
                self.working = Some(working);
            }
        }

        Ok(())
    }

    /// Builds the final [`FileInfo`] for a completed line from the accumulated
    /// buffer and recorded [`Offsets`] (← curl's `ftp_pl_insert_finfo` pointer
    /// fix-up). Consumes the [`Working`] state.
    fn finish_file(&self, working: Working) -> FileInfo {
        let buf = &working.buf;
        let mut info = working.info;

        // filename and time are always captured for a complete line; the rest
        // are present only when their offset is non-zero (curl's NULL guard).
        info.filename = cstr_at(buf, self.offsets.filename);
        info.strings.time = Some(cstr_at(buf, self.offsets.time));
        info.strings.perm = nonzero_cstr_at(buf, self.offsets.perm);
        info.strings.user = nonzero_cstr_at(buf, self.offsets.user);
        info.strings.group = nonzero_cstr_at(buf, self.offsets.group);
        info.strings.target = nonzero_cstr_at(buf, self.offsets.symlink_target);

        info
    }
}

// ===========================================================================
// UNIX `ls -l` engine (mirror of C `parse_unix` + its sub-handlers).
// ===========================================================================

impl FtpParseListData {
    /// Dispatches one byte to the active UNIX sub-state (← C `parse_unix`).
    fn parse_unix(&mut self, w: &mut Working, c: u8) -> Result<()> {
        match self.unix_state {
            UnixState::TotalSize(sub) => {
                self.parse_unix_totalsize(w, sub, c)?;
                // curl FALLs THROUGH to FILETYPE in the same character whenever
                // the total-size handler advanced the main state to FILETYPE
                // (both the "first char is not 't'" and the "matched a `total`
                // line" cases).
                if matches!(self.unix_state, UnixState::FileType) {
                    self.parse_unix_filetype(w, c)?;
                }
                Ok(())
            }
            UnixState::FileType => self.parse_unix_filetype(w, c),
            UnixState::Permission => self.parse_unix_permission(w, c),
            UnixState::HLinks(sub) => self.parse_unix_hlinks(w, sub, c),
            UnixState::User(sub) => self.parse_unix_user(w, sub, c),
            UnixState::Group(sub) => self.parse_unix_group(w, sub, c),
            UnixState::Size(sub) => self.parse_unix_size(w, sub, c),
            UnixState::Time(sub) => self.parse_unix_time(w, sub, c),
            UnixState::Filename(sub) => self.parse_unix_filename(w, sub, c),
            UnixState::Symlink(sub) => self.parse_unix_symlink(w, sub, c),
        }
    }

    /// Optional leading `total N` directory-size line (← `parse_unix_totalsize`).
    fn parse_unix_totalsize(&mut self, w: &mut Working, sub: TotalSub, c: u8) -> Result<()> {
        match sub {
            TotalSub::Init => {
                if c == b't' {
                    self.unix_state = UnixState::TotalSize(TotalSub::Reading);
                    self.item_length += 1;
                } else {
                    // Not a "total" line — this byte is the file-type char.
                    self.unix_state = UnixState::FileType;
                }
            }
            TotalSub::Reading => {
                self.item_length += 1;
                if c == b'\r' {
                    self.item_length -= 1;
                    if !w.buf.is_empty() {
                        w.buf.pop();
                    }
                } else if c == b'\n' {
                    // The accumulated line excluding the trailing '\n'.
                    let line_end = self.item_length - 1;
                    let line = &w.buf[..line_end];
                    if line.starts_with(b"total ") {
                        // Validate: optional blanks then digits then nothing.
                        let mut p = 6;
                        while p < line.len() && is_blank(line[p]) {
                            p += 1;
                        }
                        while p < line.len() && line[p].is_ascii_digit() {
                            p += 1;
                        }
                        if p != line.len() {
                            return Err(CurlError::FtpBadFileList);
                        }
                        self.unix_state = UnixState::FileType;
                        w.buf.clear();
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
        }
        Ok(())
    }

    /// The single file-type character (← the `PL_UNIX_FILETYPE` case).
    fn parse_unix_filetype(&mut self, w: &mut Working, c: u8) -> Result<()> {
        w.info.filetype = unix_filetype(c)?;
        self.unix_state = UnixState::Permission;
        self.item_length = 0;
        self.item_offset = 1;
        Ok(())
    }

    /// The 9-character permission string (← `parse_unix_permission`).
    fn parse_unix_permission(&mut self, w: &mut Working, c: u8) -> Result<()> {
        self.item_length += 1;
        if self.item_length <= 9 {
            if !matches!(c, b'r' | b'w' | b'x' | b'-' | b't' | b'T' | b's' | b'S') {
                return Err(CurlError::FtpBadFileList);
            }
        } else if self.item_length == 10 {
            if c != b' ' {
                return Err(CurlError::FtpBadFileList);
            }
            // Terminate the 10-char "type+perm" prefix; the perm string starts
            // at item_offset (== 1, just after the type char).
            if w.buf.len() > 10 {
                w.buf[10] = 0;
            }
            let perm = ftp_pl_get_permission(&w.buf[self.item_offset..]);
            if perm & FTP_LP_MALFORMATED_PERM != 0 {
                return Err(CurlError::FtpBadFileList);
            }
            w.info.flags |= FINFOFLAG_KNOWN_PERM;
            w.info.perm = perm;
            self.offsets.perm = self.item_offset;

            self.item_length = 0;
            self.unix_state = UnixState::HLinks(HLinksSub::PreSpace);
        }
        Ok(())
    }

    /// The hard-link count (← `parse_unix_hlinks`).
    fn parse_unix_hlinks(&mut self, w: &mut Working, sub: HLinksSub, c: u8) -> Result<()> {
        let len = w.buf.len();
        match sub {
            HLinksSub::PreSpace => {
                if c != b' ' {
                    if c.is_ascii_digit() && len > 0 {
                        self.item_offset = len - 1;
                        self.item_length = 1;
                        self.unix_state = UnixState::HLinks(HLinksSub::Number);
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
            HLinksSub::Number => {
                self.item_length += 1;
                if c == b' ' {
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    if let Some((hlinks, _)) = str_number(&w.buf[self.item_offset..], i64::MAX) {
                        w.info.flags |= FINFOFLAG_KNOWN_HLINKCOUNT;
                        w.info.hardlinks = hlinks;
                    }
                    self.item_length = 0;
                    self.item_offset = 0;
                    self.unix_state = UnixState::User(UserSub::PreSpace);
                } else if !c.is_ascii_digit() {
                    return Err(CurlError::FtpBadFileList);
                }
            }
        }
        Ok(())
    }

    /// The owning-user token (← `parse_unix_user`).
    fn parse_unix_user(&mut self, w: &mut Working, sub: UserSub, c: u8) -> Result<()> {
        let len = w.buf.len();
        match sub {
            UserSub::PreSpace => {
                if c != b' ' && len > 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.unix_state = UnixState::User(UserSub::Parsing);
                }
            }
            UserSub::Parsing => {
                self.item_length += 1;
                if c == b' ' {
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    self.offsets.user = self.item_offset;
                    self.unix_state = UnixState::Group(GroupSub::PreSpace);
                    self.item_offset = 0;
                    self.item_length = 0;
                }
            }
        }
        Ok(())
    }

    /// The owning-group token (← `parse_unix_group`).
    fn parse_unix_group(&mut self, w: &mut Working, sub: GroupSub, c: u8) -> Result<()> {
        let len = w.buf.len();
        match sub {
            GroupSub::PreSpace => {
                if c != b' ' && len > 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.unix_state = UnixState::Group(GroupSub::Name);
                }
            }
            GroupSub::Name => {
                self.item_length += 1;
                if c == b' ' {
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    self.offsets.group = self.item_offset;
                    self.unix_state = UnixState::Size(SizeSub::PreSpace);
                    self.item_offset = 0;
                    self.item_length = 0;
                }
            }
        }
        Ok(())
    }

    /// The size in bytes (← `parse_unix_size`).
    fn parse_unix_size(&mut self, w: &mut Working, sub: SizeSub, c: u8) -> Result<()> {
        let len = w.buf.len();
        match sub {
            SizeSub::PreSpace => {
                if c != b' ' {
                    if c.is_ascii_digit() && len > 0 {
                        self.item_offset = len - 1;
                        self.item_length = 1;
                        self.unix_state = UnixState::Size(SizeSub::Number);
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
            SizeSub::Number => {
                self.item_length += 1;
                if c == b' ' {
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    // curl parses with leading-blank skipping and requires the
                    // whole field be consumed and not overflow to OFF_T_MAX.
                    if let Some((fsize, consumed)) = str_numblanks(&w.buf[self.item_offset..end]) {
                        if consumed == end - self.item_offset && fsize != i64::MAX {
                            w.info.flags |= FINFOFLAG_KNOWN_SIZE;
                            w.info.size = fsize;
                        }
                        self.item_length = 0;
                        self.item_offset = 0;
                        self.unix_state = UnixState::Time(TimeSub::PrePart1);
                    }
                } else if !c.is_ascii_digit() {
                    return Err(CurlError::FtpBadFileList);
                }
            }
        }
        Ok(())
    }
}

// ===========================================================================
// UNIX engine, continued: the date/time, filename and symlink sub-parsers.
// ===========================================================================

impl FtpParseListData {
    /// The three-token date/time field, e.g. `Apr 27  5:12` or `Apr 27 2021`
    /// (← `parse_unix_time`). curl never converts this to a numeric timestamp:
    /// `info.time` is left at 0 and only the human-readable string is kept.
    fn parse_unix_time(&mut self, w: &mut Working, sub: TimeSub, c: u8) -> Result<()> {
        let len = w.buf.len();
        match sub {
            TimeSub::PrePart1 => {
                // Leading blanks are skipped without counting; the first
                // alphanumeric byte opens the time field. (PrePart1 does NOT
                // increment item_length — only the PART/PREPART2+ states do.)
                if c != b' ' {
                    if c.is_ascii_alphanumeric() && len > 0 {
                        self.item_offset = len - 1;
                        self.item_length = 1;
                        self.unix_state = UnixState::Time(TimeSub::Part1);
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
            TimeSub::Part1 => {
                self.item_length += 1;
                if c == b' ' {
                    self.unix_state = UnixState::Time(TimeSub::PrePart2);
                } else if !c.is_ascii_alphanumeric() && c != b'.' {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            TimeSub::PrePart2 => {
                self.item_length += 1;
                if c != b' ' {
                    if c.is_ascii_alphanumeric() {
                        self.unix_state = UnixState::Time(TimeSub::Part2);
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
            TimeSub::Part2 => {
                self.item_length += 1;
                if c == b' ' {
                    self.unix_state = UnixState::Time(TimeSub::PrePart3);
                } else if !c.is_ascii_alphanumeric() && c != b'.' {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            TimeSub::PrePart3 => {
                self.item_length += 1;
                if c != b' ' {
                    if c.is_ascii_alphanumeric() {
                        self.unix_state = UnixState::Time(TimeSub::Part3);
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                }
            }
            TimeSub::Part3 => {
                self.item_length += 1;
                if c == b' ' {
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    self.offsets.time = self.item_offset;
                    // A symlink (`l` type char) routes to the symlink parser so
                    // its `name -> target` tail is split; everything else is a
                    // plain filename.
                    if w.info.filetype == FileType::Symlink {
                        self.unix_state = UnixState::Symlink(SymlinkSub::PreSpace);
                    } else {
                        self.unix_state = UnixState::Filename(FilenameSub::PreSpace);
                    }
                } else if !c.is_ascii_alphanumeric() && c != b'.' && c != b':' {
                    return Err(CurlError::FtpBadFileList);
                }
            }
        }
        Ok(())
    }

    /// The trailing filename for a non-symlink entry (← `parse_unix_filename`).
    /// On the line-ending newline the entry is marked [`Self::complete`] and the
    /// main state rewinds to [`UnixState::FileType`] for the next line.
    fn parse_unix_filename(&mut self, w: &mut Working, sub: FilenameSub, c: u8) -> Result<()> {
        let len = w.buf.len();
        match sub {
            FilenameSub::PreSpace => {
                if c != b' ' && len > 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.unix_state = UnixState::Filename(FilenameSub::Name);
                }
            }
            FilenameSub::Name => {
                self.item_length += 1;
                if c == b'\r' {
                    self.unix_state = UnixState::Filename(FilenameSub::WindowsEol);
                } else if c == b'\n' {
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    self.offsets.filename = self.item_offset;
                    self.unix_state = UnixState::FileType;
                    self.complete = true;
                }
            }
            FilenameSub::WindowsEol => {
                if c == b'\n' {
                    // item_length already counts the preceding '\r'; terminate
                    // there (one byte before the just-pushed '\n').
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    self.offsets.filename = self.item_offset;
                    self.unix_state = UnixState::FileType;
                    self.complete = true;
                } else {
                    return Err(CurlError::FtpBadFileList);
                }
            }
        }
        Ok(())
    }

    /// The `name -> target` field for a symlink entry (← `parse_unix_symlink`).
    /// The `" -> "` separator is located, the name terminated before it, then
    /// the target captured up to the newline.
    fn parse_unix_symlink(&mut self, w: &mut Working, sub: SymlinkSub, c: u8) -> Result<()> {
        let len = w.buf.len();
        match sub {
            SymlinkSub::PreSpace => {
                if c != b' ' && len > 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.unix_state = UnixState::Symlink(SymlinkSub::Name);
                }
            }
            SymlinkSub::Name => {
                self.item_length += 1;
                if c == b' ' {
                    self.unix_state = UnixState::Symlink(SymlinkSub::PreTarget1);
                } else if c == b'\r' || c == b'\n' {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            SymlinkSub::PreTarget1 => {
                self.item_length += 1;
                if c == b'-' {
                    self.unix_state = UnixState::Symlink(SymlinkSub::PreTarget2);
                } else if c == b'\r' || c == b'\n' {
                    return Err(CurlError::FtpBadFileList);
                } else {
                    self.unix_state = UnixState::Symlink(SymlinkSub::Name);
                }
            }
            SymlinkSub::PreTarget2 => {
                self.item_length += 1;
                if c == b'>' {
                    self.unix_state = UnixState::Symlink(SymlinkSub::PreTarget3);
                } else if c == b'\r' || c == b'\n' {
                    return Err(CurlError::FtpBadFileList);
                } else {
                    self.unix_state = UnixState::Symlink(SymlinkSub::Name);
                }
            }
            SymlinkSub::PreTarget3 => {
                self.item_length += 1;
                if c == b' ' {
                    self.unix_state = UnixState::Symlink(SymlinkSub::PreTarget4);
                    // The collected span ends with " -> " (4 bytes); terminate
                    // the name just before that separator.
                    let end = (self.item_offset + self.item_length).saturating_sub(4);
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    self.offsets.filename = self.item_offset;
                    self.item_length = 0;
                    self.item_offset = 0;
                } else if c == b'\r' || c == b'\n' {
                    return Err(CurlError::FtpBadFileList);
                } else {
                    self.unix_state = UnixState::Symlink(SymlinkSub::Name);
                }
            }
            SymlinkSub::PreTarget4 => {
                if c != b'\r' && c != b'\n' && len > 0 {
                    self.unix_state = UnixState::Symlink(SymlinkSub::Target);
                    self.item_offset = len - 1;
                    self.item_length = 1;
                } else {
                    return Err(CurlError::FtpBadFileList);
                }
            }
            SymlinkSub::Target => {
                self.item_length += 1;
                if c == b'\r' {
                    self.unix_state = UnixState::Symlink(SymlinkSub::WindowsEol);
                } else if c == b'\n' {
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    self.offsets.symlink_target = self.item_offset;
                    self.unix_state = UnixState::FileType;
                    self.complete = true;
                }
            }
            SymlinkSub::WindowsEol => {
                if c == b'\n' {
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    self.offsets.symlink_target = self.item_offset;
                    self.unix_state = UnixState::FileType;
                    self.complete = true;
                } else {
                    return Err(CurlError::FtpBadFileList);
                }
            }
        }
        Ok(())
    }
}

// ===========================================================================
// Windows / DOS engine (mirror of C `parse_winnt`).
//
// Format: `MM-DD-YY[YY]  HH:MM(AM|PM) (<DIR>|size) name`, e.g.
//   `11-30-21  08:39PM       <DIR>          newdir`
//   `11-30-21  08:39PM                  151 newfile.txt`
// ===========================================================================

impl FtpParseListData {
    /// Dispatches one byte to the active Windows/NT sub-state (← `parse_winnt`).
    fn parse_winnt(&mut self, w: &mut Working, c: u8) -> Result<()> {
        match self.nt_state {
            NtState::Date => self.parse_winnt_date(w, c),
            NtState::Time(sub) => self.parse_winnt_time(w, sub, c),
            NtState::DirOrSize(sub) => self.parse_winnt_dirorsize(w, sub, c),
            NtState::Filename(sub) => self.parse_winnt_filename(w, sub, c),
        }
    }

    /// The 8-character `MM-DD-YY` date followed by a single space (← the
    /// `PL_WINNT_DATE` case). `item_offset` is intentionally never moved so the
    /// captured time string later spans from the start of the line.
    fn parse_winnt_date(&mut self, _w: &mut Working, c: u8) -> Result<()> {
        self.item_length += 1;
        if self.item_length < 9 {
            // The 8 date bytes must be digits or '-'.
            if !(c.is_ascii_digit() || c == b'-') {
                return Err(CurlError::FtpBadFileList);
            }
        } else if self.item_length == 9 {
            if c == b' ' {
                self.nt_state = NtState::Time(NtTimeSub::PreSpace);
            } else {
                return Err(CurlError::FtpBadFileList);
            }
        } else {
            return Err(CurlError::FtpBadFileList);
        }
        Ok(())
    }

    /// The `HH:MM(AM|PM)` time token (← the `PL_WINNT_TIME` case). The whole
    /// leading `date + time` span (from offset 0) becomes `strings.time`.
    fn parse_winnt_time(&mut self, w: &mut Working, sub: NtTimeSub, c: u8) -> Result<()> {
        self.item_length += 1;
        match sub {
            NtTimeSub::PreSpace => {
                // Skip the run of blanks separating date and time.
                if !is_blank(c) {
                    self.nt_state = NtState::Time(NtTimeSub::Time);
                }
            }
            NtTimeSub::Time => {
                if c == b' ' {
                    self.offsets.time = self.item_offset;
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    self.nt_state = NtState::DirOrSize(NtDirSub::PreSpace);
                    self.item_length = 0;
                } else if !matches!(c, b'A' | b'P' | b'M' | b'0'..=b'9' | b':') {
                    return Err(CurlError::FtpBadFileList);
                }
            }
        }
        Ok(())
    }

    /// The `<DIR>` marker or the numeric byte size (← the `PL_WINNT_DIRORSIZE`
    /// case). Sets the filetype accordingly and flags the size as known.
    fn parse_winnt_dirorsize(&mut self, w: &mut Working, sub: NtDirSub, c: u8) -> Result<()> {
        let len = w.buf.len();
        match sub {
            NtDirSub::PreSpace => {
                if c != b' ' && len > 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.nt_state = NtState::DirOrSize(NtDirSub::Content);
                }
            }
            NtDirSub::Content => {
                self.item_length += 1;
                if c == b' ' {
                    let end = self.item_offset + self.item_length - 1;
                    if end < w.buf.len() {
                        w.buf[end] = 0;
                    }
                    let field_end = end.min(w.buf.len());
                    let start = self.item_offset.min(field_end);
                    let field = &w.buf[start..field_end];
                    if field == b"<DIR>" {
                        w.info.filetype = FileType::Directory;
                        w.info.size = 0;
                    } else if let Some((size, _)) = str_numblanks(field) {
                        w.info.size = size;
                        w.info.filetype = FileType::File;
                    } else {
                        return Err(CurlError::FtpBadFileList);
                    }
                    w.info.flags |= FINFOFLAG_KNOWN_SIZE;
                    self.item_length = 0;
                    self.nt_state = NtState::Filename(NtFnSub::PreSpace);
                }
            }
        }
        Ok(())
    }

    /// The trailing filename (← the `PL_WINNT_FILENAME` case). Marks the entry
    /// [`Self::complete`] and rewinds to [`NtState::Date`] for the next line.
    fn parse_winnt_filename(&mut self, w: &mut Working, sub: NtFnSub, c: u8) -> Result<()> {
        let len = w.buf.len();
        match sub {
            NtFnSub::PreSpace => {
                if c != b' ' && len > 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.nt_state = NtState::Filename(NtFnSub::Content);
                }
            }
            NtFnSub::Content => {
                self.item_length += 1;
                if len == 0 {
                    return Err(CurlError::FtpBadFileList);
                }
                if c == b'\r' {
                    // Terminate the filename at the just-pushed '\r'.
                    w.buf[len - 1] = 0;
                    self.nt_state = NtState::Filename(NtFnSub::WinEol);
                } else if c == b'\n' {
                    self.offsets.filename = self.item_offset;
                    w.buf[len - 1] = 0;
                    self.nt_state = NtState::Date;
                    self.complete = true;
                }
            }
            NtFnSub::WinEol => {
                if c == b'\n' {
                    // The '\r' already NUL-terminated the name in Content.
                    self.offsets.filename = self.item_offset;
                    self.nt_state = NtState::Date;
                    self.complete = true;
                } else {
                    return Err(CurlError::FtpBadFileList);
                }
            }
        }
        Ok(())
    }
}

// ===========================================================================
// Inline helpers (ports of `lib/curlx/strparse.c`, `lib/curl_ctype.h`, and the
// `ftp_pl_get_permission` / `unix_filetype` statics in `ftplistparser.c`).
//
// These mirror curl's own routines byte-for-byte so the parser's numeric and
// permission handling is identical. They are intentionally local: `strparse`
// is not a dependency of this crate, and re-implementing the tiny subset used
// here keeps the import surface minimal.
// ===========================================================================

/// `ISBLANK` from `lib/curl_ctype.h`: an ASCII space or horizontal tab.
#[inline]
fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// Parses an unsigned base-10 integer with no leading sign or blanks (←
/// `curlx_str_number` / `str_num_base` with `base == 10`).
///
/// Requires at least one digit and rejects values that would overflow `max`
/// (using curl's `num > (max - n) / base` test, valid because every caller
/// passes `i64::MAX`, which is `>= base`). Returns the parsed value together
/// with the number of digit bytes consumed, or `None` on "no digits" /
/// "overflow" — matching curl's `STRE_NO_NUM` / `STRE_OVERFLOW`.
fn str_number(s: &[u8], max: i64) -> Option<(i64, usize)> {
    const BASE: i64 = 10;
    if s.is_empty() || !s[0].is_ascii_digit() {
        return None;
    }
    let mut num: i64 = 0;
    let mut i = 0usize;
    while i < s.len() && s[i].is_ascii_digit() {
        let n = i64::from(s[i] - b'0');
        // Overflow-safe form (curl's `max >= base` branch).
        if num > (max - n) / BASE {
            return None;
        }
        num = num * BASE + n;
        i += 1;
    }
    Some((num, i))
}

/// Parses an unsigned base-10 integer after skipping leading blanks (←
/// `curlx_str_numblanks`, which `passblanks` then `str_number` with
/// `CURL_OFF_T_MAX`). Returns the value and the total bytes consumed (the
/// skipped blanks plus the digits).
fn str_numblanks(s: &[u8]) -> Option<(i64, usize)> {
    let mut blanks = 0usize;
    while blanks < s.len() && is_blank(s[blanks]) {
        blanks += 1;
    }
    let (num, consumed) = str_number(&s[blanks..], i64::MAX)?;
    Some((num, blanks + consumed))
}

/// Translates a 9-character `rwxrwxrwx`-style permission string into curl's
/// packed permission bits (← `ftp_pl_get_permission`). Unrecognized characters
/// set the [`FTP_LP_MALFORMATED_PERM`] sentinel bit, exactly as curl does, so
/// the caller can reject the line. The bit layout matches POSIX mode bits
/// (setuid `1<<11`, setgid `1<<10`, sticky `1<<9`, then `rwxrwxrwx`).
fn ftp_pl_get_permission(s: &[u8]) -> u32 {
    if s.len() < 9 {
        return FTP_LP_MALFORMATED_PERM;
    }
    let mut p: u32 = 0;

    // ---- owner ----
    match s[0] {
        b'r' => p |= 1 << 8,
        b'-' => {}
        _ => p |= FTP_LP_MALFORMATED_PERM,
    }
    match s[1] {
        b'w' => p |= 1 << 7,
        b'-' => {}
        _ => p |= FTP_LP_MALFORMATED_PERM,
    }
    match s[2] {
        b'x' => p |= 1 << 6,
        b's' => p |= (1 << 6) | (1 << 11),
        b'S' => p |= 1 << 11,
        b'-' => {}
        _ => p |= FTP_LP_MALFORMATED_PERM,
    }

    // ---- group ----
    match s[3] {
        b'r' => p |= 1 << 5,
        b'-' => {}
        _ => p |= FTP_LP_MALFORMATED_PERM,
    }
    match s[4] {
        b'w' => p |= 1 << 4,
        b'-' => {}
        _ => p |= FTP_LP_MALFORMATED_PERM,
    }
    match s[5] {
        b'x' => p |= 1 << 3,
        b's' => p |= (1 << 3) | (1 << 10),
        b'S' => p |= 1 << 10,
        b'-' => {}
        _ => p |= FTP_LP_MALFORMATED_PERM,
    }

    // ---- others ----
    match s[6] {
        b'r' => p |= 1 << 2,
        b'-' => {}
        _ => p |= FTP_LP_MALFORMATED_PERM,
    }
    match s[7] {
        b'w' => p |= 1 << 1,
        b'-' => {}
        _ => p |= FTP_LP_MALFORMATED_PERM,
    }
    match s[8] {
        b'x' => p |= 1,
        b't' => p |= 1 | (1 << 9),
        b'T' => p |= 1 << 9,
        b'-' => {}
        _ => p |= FTP_LP_MALFORMATED_PERM,
    }

    p
}

/// Maps the UNIX listing file-type character to a [`FileType`] (←
/// `unix_filetype`). Unknown characters are a malformed line.
fn unix_filetype(c: u8) -> Result<FileType> {
    Ok(match c {
        b'-' => FileType::File,
        b'd' => FileType::Directory,
        b'l' => FileType::Symlink,
        b'p' => FileType::NamedPipe,
        b's' => FileType::Socket,
        b'c' => FileType::DeviceChar,
        b'b' => FileType::DeviceBlock,
        b'D' => FileType::Door,
        _ => return Err(CurlError::FtpBadFileList),
    })
}

/// Reads a NUL-terminated field starting at `offset` from the line buffer and
/// returns it as an owned `String` (lossily decoding any non-UTF-8 bytes). This
/// is the Rust equivalent of curl's `str + offset` pointer into the dynbuf,
/// where field boundaries are marked with in-place NUL bytes. An out-of-range
/// offset yields an empty string.
fn cstr_at(buf: &[u8], offset: usize) -> String {
    if offset >= buf.len() {
        return String::new();
    }
    let rest = &buf[offset..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

/// Like [`cstr_at`], but treats a `0` offset as "field absent" and returns
/// `None` — mirroring curl's `parser->offsets.X ? str + X : NULL` guard for the
/// optional `perm` / `user` / `group` / `symlink_target` strings.
fn nonzero_cstr_at(buf: &[u8], offset: usize) -> Option<String> {
    if offset == 0 {
        return None;
    }
    Some(cstr_at(buf, offset))
}

// ===========================================================================
// Unit tests
//
// LIST samples follow the byte-exact semantics of curl's own FTP test fixtures
// (`tests/directories.pm` / `tests/data`); they are reconstructed here rather
// than read from `tests/` (which is the immutable parity oracle and must not be
// modified or depended upon).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a complete `LIST` payload in one shot and returns the entries.
    fn parse_all(input: &[u8]) -> Result<Vec<FileInfo>> {
        let mut p = FtpParseListData::new();
        p.parse_chunk(input)?;
        Ok(p.take_entries())
    }

    // ---- ABI-stability checks -------------------------------------------

    #[test]
    fn filetype_discriminants_match_public_abi() {
        // CURLFILETYPE_* must keep these exact integer values.
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

    #[test]
    fn finfoflag_bit_values_match_public_abi() {
        assert_eq!(FINFOFLAG_KNOWN_FILENAME, 1 << 0);
        assert_eq!(FINFOFLAG_KNOWN_FILETYPE, 1 << 1);
        assert_eq!(FINFOFLAG_KNOWN_TIME, 1 << 2);
        assert_eq!(FINFOFLAG_KNOWN_PERM, 1 << 3);
        assert_eq!(FINFOFLAG_KNOWN_UID, 1 << 4);
        assert_eq!(FINFOFLAG_KNOWN_GID, 1 << 5);
        assert_eq!(FINFOFLAG_KNOWN_SIZE, 1 << 6);
        assert_eq!(FINFOFLAG_KNOWN_HLINKCOUNT, 1 << 7);
    }

    #[test]
    fn wildcard_state_discriminants_match_public_abi() {
        assert_eq!(WildcardState::Clear.as_u32(), 0);
        assert_eq!(WildcardState::Init.as_u32(), 1);
        assert_eq!(WildcardState::Matching.as_u32(), 2);
        assert_eq!(WildcardState::Downloading.as_u32(), 3);
        assert_eq!(WildcardState::Clean.as_u32(), 4);
        assert_eq!(WildcardState::Skip.as_u32(), 5);
        assert_eq!(WildcardState::Error.as_u32(), 6);
        assert_eq!(WildcardState::Done.as_u32(), 7);
    }

    // ---- helper-function parity -----------------------------------------

    #[test]
    fn permission_string_to_bits() {
        // Plain rwx triplets -> standard octal modes.
        assert_eq!(ftp_pl_get_permission(b"rwxr-xr-x"), 0o755);
        assert_eq!(ftp_pl_get_permission(b"rw-r--r--"), 0o644);
        assert_eq!(ftp_pl_get_permission(b"rwxrwxrwx"), 0o777);
        assert_eq!(ftp_pl_get_permission(b"---------"), 0);

        // setuid (s in owner-exec), setgid (s in group-exec), sticky (t).
        assert_eq!(ftp_pl_get_permission(b"rwsr-xr-x"), 0o4755);
        assert_eq!(ftp_pl_get_permission(b"rwxr-sr-x"), 0o2755);
        assert_eq!(ftp_pl_get_permission(b"rwxr-xr-t"), 0o1755);
        // Capital S/T mean the high bit set without the execute bit.
        assert_eq!(ftp_pl_get_permission(b"rwSr-xr-x"), 0o4655);
        assert_eq!(ftp_pl_get_permission(b"rwxr-xr-T"), 0o1754);

        // A character that is valid in the alphabet but wrong for its slot
        // (e.g. 't' in the owner-read slot) sets the malformed sentinel.
        assert_ne!(
            ftp_pl_get_permission(b"trwr--r--") & FTP_LP_MALFORMATED_PERM,
            0
        );
        // Too-short input is malformed, never a panic.
        assert_ne!(ftp_pl_get_permission(b"rwx") & FTP_LP_MALFORMATED_PERM, 0);
    }

    #[test]
    fn number_parsers() {
        assert_eq!(str_number(b"0", i64::MAX), Some((0, 1)));
        assert_eq!(str_number(b"4604", i64::MAX), Some((4604, 4)));
        // Stops at the first non-digit, reporting how many digits it consumed.
        assert_eq!(str_number(b"151 x", i64::MAX), Some((151, 3)));
        assert_eq!(str_number(b"", i64::MAX), None);
        assert_eq!(str_number(b"abc", i64::MAX), None);
        // Overflow past i64::MAX is rejected.
        assert_eq!(str_number(b"99999999999999999999", i64::MAX), None);

        // numblanks skips only leading blanks (space/tab), counting them.
        assert_eq!(str_numblanks(b"   42"), Some((42, 5)));
        assert_eq!(str_numblanks(b"\t7"), Some((7, 2)));
        assert_eq!(str_numblanks(b"   "), None);
    }

    #[test]
    fn unix_filetype_mapping() {
        assert_eq!(unix_filetype(b'-').unwrap(), FileType::File);
        assert_eq!(unix_filetype(b'd').unwrap(), FileType::Directory);
        assert_eq!(unix_filetype(b'l').unwrap(), FileType::Symlink);
        assert_eq!(unix_filetype(b'p').unwrap(), FileType::NamedPipe);
        assert_eq!(unix_filetype(b's').unwrap(), FileType::Socket);
        assert_eq!(unix_filetype(b'c').unwrap(), FileType::DeviceChar);
        assert_eq!(unix_filetype(b'b').unwrap(), FileType::DeviceBlock);
        assert_eq!(unix_filetype(b'D').unwrap(), FileType::Door);
        assert_eq!(unix_filetype(b'z'), Err(CurlError::FtpBadFileList));
    }

    // ---- UNIX `ls -l` engine --------------------------------------------

    #[test]
    fn unix_regular_file() {
        let entries =
            parse_all(b"-rw-r--r-- 1 user group 4604 Jan 29 23:32 index.html\r\n").unwrap();
        assert_eq!(entries.len(), 1);
        let fi = &entries[0];
        assert_eq!(fi.filename, "index.html");
        assert_eq!(fi.filetype, FileType::File);
        assert_eq!(fi.perm, 0o644);
        assert_eq!(fi.size, 4604);
        assert_eq!(fi.hardlinks, 1);
        // time is intentionally always zero; the string carries the date.
        assert_eq!(fi.time, 0);
        assert_eq!(fi.strings.time.as_deref(), Some("Jan 29 23:32"));
        assert_eq!(fi.strings.perm.as_deref(), Some("rw-r--r--"));
        assert_eq!(fi.strings.user.as_deref(), Some("user"));
        assert_eq!(fi.strings.group.as_deref(), Some("group"));
        assert_eq!(fi.strings.target, None);
        // Exactly PERM | HLINKCOUNT | SIZE are known (uid/gid/filename/filetype
        // flags are never set by curl's parser).
        assert_eq!(
            fi.flags,
            FINFOFLAG_KNOWN_PERM | FINFOFLAG_KNOWN_HLINKCOUNT | FINFOFLAG_KNOWN_SIZE
        );
    }

    #[test]
    fn unix_directory() {
        let entries = parse_all(b"drwxr-xr-x 2 ftp ftp 4096 Jan 29 23:32 subdir\r\n").unwrap();
        assert_eq!(entries.len(), 1);
        let fi = &entries[0];
        assert_eq!(fi.filename, "subdir");
        assert_eq!(fi.filetype, FileType::Directory);
        assert_eq!(fi.perm, 0o755);
        assert_eq!(fi.size, 4096);
        assert_eq!(fi.hardlinks, 2);
    }

    #[test]
    fn unix_symlink_splits_name_and_target() {
        let entries =
            parse_all(b"lrwxrwxrwx 1 ftp ftp 11 Jan 29 23:32 link -> target.txt\r\n").unwrap();
        assert_eq!(entries.len(), 1);
        let fi = &entries[0];
        assert_eq!(fi.filetype, FileType::Symlink);
        assert_eq!(fi.filename, "link");
        assert_eq!(fi.strings.target.as_deref(), Some("target.txt"));
        assert_eq!(fi.perm, 0o777);
    }

    #[test]
    fn unix_lf_only_line_ending() {
        // A bare LF (no CR) must still complete the line.
        let entries = parse_all(b"-rw-r--r-- 1 u g 7 Jan 29 23:32 a.txt\n").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "a.txt");
        assert_eq!(entries[0].size, 7);
    }

    #[test]
    fn unix_multiple_entries() {
        let listing = b"drwxr-xr-x 2 ftp ftp 4096 Jan 29 23:32 dir\r\n\
                        -rw-r--r-- 1 ftp ftp 100 Jan 29 23:33 a.txt\r\n\
                        -rw-r--r-- 1 ftp ftp 200 Jan 29 23:34 b.log\r\n";
        let entries = parse_all(listing).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].filename, "dir");
        assert_eq!(entries[0].filetype, FileType::Directory);
        assert_eq!(entries[1].filename, "a.txt");
        assert_eq!(entries[1].size, 100);
        assert_eq!(entries[2].filename, "b.log");
        assert_eq!(entries[2].size, 200);
    }

    #[test]
    fn unix_total_line_reproduces_curl_quirk() {
        // curl's `parse_unix_totalsize` recognizes and validates a leading
        // `total N` line, but then — via the `PL_UNIX_TOTALSIZE -> FALLTHROUGH
        // -> PL_UNIX_FILETYPE` path in `parse_unix` — feeds the line's own '\n'
        // to `unix_filetype`, which rejects it. So curl LITERALLY returns
        // CURLE_FTP_BAD_FILE_LIST on a `total` line.
        //
        // This quirk is never exercised by the regression suite: the FTP LIST
        // parser only runs for wildcard transfers (`CURLOPT_WILDCARDMATCH`),
        // and the simulated server's listing generator (`tests/directories.pm`)
        // emits no `total` line. We reproduce curl's exact behavior for
        // byte-for-byte parity rather than "fixing" it (which would be an
        // out-of-mandate behavior change). Verified against the C source with a
        // standalone harness.
        let err = parse_all(b"total 8\r\n-rw-r--r-- 1 u g 5 Jan 29 23:32 f\r\n").unwrap_err();
        assert_eq!(err, CurlError::FtpBadFileList);

        // The leading-byte detector also means a digit-led `total`-like line is
        // routed to the Windows engine instead; either way it is not a silently
        // skipped header. (Documented here so the routing decision is pinned.)
    }

    // ---- Windows / DOS engine -------------------------------------------

    #[test]
    fn dos_directory() {
        let entries = parse_all(b"11-30-21  08:39PM       <DIR>          newdir\r\n").unwrap();
        assert_eq!(entries.len(), 1);
        let fi = &entries[0];
        assert_eq!(fi.filename, "newdir");
        assert_eq!(fi.filetype, FileType::Directory);
        assert_eq!(fi.size, 0);
        assert_eq!(fi.flags, FINFOFLAG_KNOWN_SIZE);
        // The whole leading date+time becomes the time string.
        assert_eq!(fi.strings.time.as_deref(), Some("11-30-21  08:39PM"));
    }

    #[test]
    fn dos_file_with_size() {
        let entries = parse_all(b"11-30-21  08:39PM                  151 newfile.txt\r\n").unwrap();
        assert_eq!(entries.len(), 1);
        let fi = &entries[0];
        assert_eq!(fi.filename, "newfile.txt");
        assert_eq!(fi.filetype, FileType::File);
        assert_eq!(fi.size, 151);
        assert_eq!(fi.flags, FINFOFLAG_KNOWN_SIZE);
    }

    // ---- incremental feeding --------------------------------------------

    #[test]
    fn incremental_split_mid_line() {
        // A line split across two chunks, with the break in the middle of the
        // filename, must be parsed correctly once complete.
        let mut p = FtpParseListData::new();
        p.parse_chunk(b"-rw-r--r-- 1 u g 512 Jan 29 23:32 long_file")
            .unwrap();
        assert_eq!(p.entries().len(), 0, "no entry until the line completes");
        p.parse_chunk(b"name.dat\r\n").unwrap();
        let entries = p.take_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "long_filename.dat");
        assert_eq!(entries[0].size, 512);
    }

    #[test]
    fn incremental_split_across_crlf() {
        // The CR and LF of a single line arriving in separate chunks.
        let mut p = FtpParseListData::new();
        p.parse_chunk(b"drwxr-xr-x 2 u g 4096 Jan 29 23:32 d\r")
            .unwrap();
        p.parse_chunk(b"\n").unwrap();
        let entries = p.take_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "d");
        assert_eq!(entries[0].filetype, FileType::Directory);
    }

    #[test]
    fn incremental_byte_by_byte() {
        // Feeding one byte at a time must yield the same result.
        let line = b"-rw-r--r-- 1 u g 42 Jan 29 23:32 x.bin\r\n";
        let mut p = FtpParseListData::new();
        for &b in line.iter() {
            p.parse_chunk(&[b]).unwrap();
        }
        let entries = p.take_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "x.bin");
        assert_eq!(entries[0].size, 42);
    }

    // ---- error handling --------------------------------------------------

    #[test]
    fn malformed_filetype_char_is_rejected() {
        // 'z' is not a valid UNIX type char (and not the start of `total`).
        let err = parse_all(b"zrwxr-xr-x 1 u g 4 Jan 29 23:32 x\r\n").unwrap_err();
        assert_eq!(err, CurlError::FtpBadFileList);
    }

    #[test]
    fn malformed_permission_char_is_rejected() {
        // '9' is not a permission character.
        let err = parse_all(b"-rw9r--r-- 1 u g 4 Jan 29 23:32 x\r\n").unwrap_err();
        assert_eq!(err, CurlError::FtpBadFileList);
    }

    #[test]
    fn eplf_line_is_rejected_like_curl() {
        // curl 8.x ships no EPLF engine: a '+'-prefixed EPLF line is routed to
        // the UNIX engine (first byte is not a digit) and rejected there. This
        // pins the behavioral-parity decision to NOT implement EPLF.
        let err = parse_all(b"+i8388621.29609,m824255902,/,\tdev\r\n").unwrap_err();
        assert_eq!(err, CurlError::FtpBadFileList);
    }

    #[test]
    fn error_is_sticky_and_retrievable() {
        let mut p = FtpParseListData::new();
        let first = p.parse_chunk(b"zbad\r\n");
        assert_eq!(first, Err(CurlError::FtpBadFileList));
        // geterror surfaces the captured error...
        assert_eq!(p.geterror(), Some(CurlError::FtpBadFileList));
        // ...and subsequent chunks short-circuit with the same error.
        assert_eq!(p.parse_chunk(b"anything"), Err(CurlError::FtpBadFileList));
    }

    #[test]
    fn oversized_line_maps_to_out_of_memory() {
        // A single line larger than MAX_FTPLIST_BUFFER aborts with OutOfMemory,
        // bounding memory against a hostile server that never sends a newline.
        // Use a well-formed UNIX prefix followed by an unterminated, arbitrarily
        // long filename so the parser keeps accumulating (the filename state
        // accepts any byte except CR/LF) until it hits curl's dynbuf cap.
        let mut p = FtpParseListData::new();
        let mut huge = b"-rw-r--r-- 1 u g 5 Jan 29 23:32 ".to_vec();
        huge.extend(std::iter::repeat(b'a').take(MAX_FTPLIST_BUFFER));
        let err = p.parse_chunk(&huge).unwrap_err();
        assert_eq!(err, CurlError::OutOfMemory);
        assert_eq!(p.geterror(), Some(CurlError::OutOfMemory));
    }

    // ---- wildcard selection ---------------------------------------------

    #[test]
    fn wildcard_selects_matching_names() {
        let listing = b"-rw-r--r-- 1 u g 1 Jan 29 23:32 a.txt\r\n\
                        -rw-r--r-- 1 u g 2 Jan 29 23:32 b.log\r\n\
                        -rw-r--r-- 1 u g 3 Jan 29 23:32 c.txt\r\n";
        let entries = parse_all(listing).unwrap();
        assert_eq!(entries.len(), 3);

        let mut wc = WildcardData::new("/pub/", "*.txt");
        assert_eq!(wc.state, WildcardState::Init);
        wc.select_matches(entries);

        let names: Vec<&str> = wc.filelist.iter().map(|f| f.filename.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "c.txt"]);
    }

    #[test]
    fn wildcard_uses_curl_fnmatch_semantics() {
        // Sanity-check that selection delegates to curl_fnmatch (a literal
        // match here).
        let entries = parse_all(b"-rw-r--r-- 1 u g 1 Jan 29 23:32 readme\r\n").unwrap();
        let mut wc = WildcardData::new("/", "readme");
        wc.select_matches(entries);
        assert_eq!(wc.filelist.len(), 1);
        assert_eq!(curl_fnmatch(b"readme", b"readme"), FnMatch::Match);
    }

    #[test]
    fn wildcard_discards_ambiguous_symlink() {
        // A symlink whose *target* itself contains " -> " is discarded even
        // when its name matches the pattern (mirrors ftp_pl_insert_finfo).
        let mut fi = FileInfo {
            filename: "weird.txt".to_string(),
            filetype: FileType::Symlink,
            ..FileInfo::default()
        };
        fi.strings.target = Some("a -> b".to_string());
        assert!(!WildcardData::matches(b"*.txt", &fi));

        // A normal symlink with a plain target matches fine.
        let mut ok = FileInfo {
            filename: "good.txt".to_string(),
            filetype: FileType::Symlink,
            ..FileInfo::default()
        };
        ok.strings.target = Some("plain".to_string());
        assert!(WildcardData::matches(b"*.txt", &ok));
    }

    #[test]
    fn wildcard_reset_clears_state() {
        let mut wc = WildcardData::new("/p/", "*.dat");
        wc.filelist.push(FileInfo::default());
        wc.state = WildcardState::Downloading;
        wc.reset();
        assert!(wc.filelist.is_empty());
        assert!(wc.path.is_empty());
        assert!(wc.pattern.is_empty());
        assert_eq!(wc.state, WildcardState::Init);
    }
}
