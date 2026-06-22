#![forbid(unsafe_code)]
//! Operation driver — the heart of the `curl-rs` command-line tool.
//!
//! This module is the Rust re-implementation of curl's `src/tool_operate.c`
//! (the largest CLI translation unit), folding in the helpers that the C tool
//! splits across sibling files:
//!
//! * `src/tool_operate.c`  — [`operate`], the serial/parallel transfer loops,
//!   `create_transfer`/`single_transfer`, `post_per_transfer`, `retrycheck`,
//!   the share setup, and the exit-code mapping.
//! * `src/tool_operhlp.c`  — [`get_url_file_name`], [`add_file_name_to_url`],
//!   [`output_expected`], [`stdin_upload`], `urlerr_cvt`.
//! * `src/tool_progress.c` — [`max5data`], [`time2str`], the progress meter and
//!   the parallel aggregate progress bar.
//! * `src/tool_findfile.c` — [`findfile`]/`checkhome` home resolution for
//!   `.netrc`, `known_hosts`, the default CA bundle, and `.curlrc`.
//! * `src/tool_ssls.c`     — SSL-session import/export (feature-gated; skipped
//!   cleanly when the capability is unavailable).
//!
//! # Design notes (deviations from the C original, all memory-safety driven)
//!
//! * **No raw linked list.** The C `struct per_transfer` doubly-linked list
//!   (`transfers`/`transfersl`) is replaced by a safe [`VecDeque<PerTransfer>`]
//!   owned by the [`Driver`]. `add_per_transfer` is `push_back`, `del_per_transfer`
//!   is `pop_front`, and a retry simply leaves the entry at the front — the
//!   FIFO iteration and retry semantics are identical to the C list walk.
//! * **No raw file descriptors.** `per->infd`/`infdopen` and the `OutStruct`
//!   `FILE*` streams become [`Option<File>`]; "closing" is dropping the value.
//!   This keeps the module free of `libc::close`/`unsafe` while preserving the
//!   open/close lifecycle.
//! * **Memory-safe completion association.** In parallel mode the C code stores
//!   each `per` pointer in `CURLOPT_PRIVATE` and recovers it from the finished
//!   message. Here the easy handle is wrapped in a [`SharedEasy`]
//!   (`Arc<Mutex<Easy>>`) and the finished message is matched back to its
//!   [`PerTransfer`] by [`Arc::ptr_eq`] — no raw pointers cross the boundary.
//! * **Locale.** curl calls `setlocale(LC_NUMERIC, "C")` so that number parsing
//!   is locale-independent. Rust's [`str::parse`] is already locale-independent,
//!   so this is a documented no-op here.
//!
//! The single most important contract of this module is **exit-code fidelity**:
//! [`operate`] returns a [`CurlCode`] (an `i32`) whose value `main.rs` returns
//! verbatim as the process exit status — exactly like curl's `return (int)result;`.
//! Distinct errors keep distinct codes; they are never collapsed.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use curl_rs_lib::error::{codes, CurlMError, CurlShError};
use curl_rs_lib::multi::{self, CurlMInfo, SharedEasy};
use curl_rs_lib::progress::CURL_PROGRESSFUNC_CONTINUE;
use curl_rs_lib::transfer::{DebugInfoType, ReadCallback, WriteCallbacks};
use curl_rs_lib::share::{LockData, ShareSetting};
use curl_rs_lib::{
    CurlCode, CurlError, CurlInfo, CurlOption, Easy, InfoValue, Multi, OptionValue, Share,
};

use crate::callbacks::debug::CurlInfoType;
use crate::callbacks::ProgressData;
use crate::config::{FailMode, GlobalConfig, HttpReq, OperationConfig};
use crate::setopt;
use crate::urlglob;
use crate::writeout::our_write_out;
use crate::writeout_json::{HeaderField, HeaderSource};
use crate::{errorf, helpf, notef, warnf};

// ===========================================================================
// Constants (curl `src/tool_main.h` + `src/tool_cfgable.h`)
// ===========================================================================

/// Default first retry back-off in milliseconds (`RETRY_SLEEP_DEFAULT`).
const RETRY_SLEEP_DEFAULT: i64 = 1000;
/// Maximum retry back-off in milliseconds — 10 minutes (`RETRY_SLEEP_MAX`).
const RETRY_SLEEP_MAX: i64 = 600_000;
/// `global->progressmode == CURL_PROGRESS_BAR` selector value.
const CURL_PROGRESS_BAR: i32 = 1;
/// Size of the per-transfer error buffer (`CURL_ERROR_SIZE`).
const CURL_ERROR_SIZE: usize = 256;
/// `errno`/`WSAGetLastError` value for a refused connection
/// (`SOCKECONNREFUSED`), used by `--retry-connrefused`.
const SOCK_ECONNREFUSED: i64 = 111; // Linux ECONNREFUSED

// ===========================================================================
// OutStruct — output stream bookkeeping (C `struct OutStruct`, tool_cfgable.h)
// ===========================================================================

/// Tracks an output destination (the body sink, the `-D`/`--dump-header` sink,
/// or the `--etag-save` sink). The C original carries a `FILE*`; here a [`None`]
/// `stream` means "write to the process stdout", matching curl's default of
/// `outs->stream = stdout`.
#[derive(Debug, Default)]
pub struct OutStruct {
    /// The local file name this transfer writes to (`outs->filename`).
    pub filename: Option<String>,
    /// `true` when [`filename`](Self::filename) was synthesized/owned by the
    /// tool and would be freed in C (`outs->alloc_filename`). Retained for
    /// behavioral fidelity; ownership in Rust is automatic.
    pub alloc_filename: bool,
    /// `true` when the file name came from a `Content-Disposition` header
    /// (`outs->is_cd_filename`).
    pub is_cd_filename: bool,
    /// `true` when the destination is a regular file (`outs->regular_file`),
    /// which gates resume/truncate handling.
    pub regular_file: bool,
    /// `true` once the file has actually been opened by the tool
    /// (`outs->fopened`).
    pub fopened: bool,
    /// The open output file, or [`None`] to mean "not a dedicated file". With
    /// [`filename`](Self::filename) `None` and [`to_stderr`](Self::to_stderr)
    /// `false`, `None` means the process **stdout** (curl's `outs->stream =
    /// stdout`); with `filename` set it means a regular file that is opened
    /// lazily on first write (curl sets `outs->stream = NULL` for the
    /// non-resume case).
    pub stream: Option<File>,
    /// `true` when this sink targets the process **stderr** rather than a file
    /// or stdout — the `-D %` / `--dump-header %` case where curl sets
    /// `heads->stream = stderr`. Kept as a flag because [`stream`](Self::stream)
    /// (an [`Option<File>`]) cannot hold the shared stderr handle.
    pub to_stderr: bool,
    /// Bytes written to this output so far (`outs->bytes`).
    pub bytes: u64,
    /// The byte offset the output started at, for `--continue-at`
    /// (`outs->init`).
    pub init: u64,
    /// `true` when this URL's output is discarded (`outs->out_null`, i.e.
    /// `-o /dev/null` shorthand or `--remove-on-error` skip).
    pub out_null: bool,
}

// ===========================================================================
// ProgressData — custom progress-bar state (C `struct ProgressData`,
// src/tool_cb_prg.h).
//
// The canonical struct and its callback (`tool_progress_cb`/`progressbarinit`,
// the `-#` bar) are owned by `crate::callbacks::progress` (the port of
// `src/tool_cb_prg.c`); it is imported above and embedded unchanged as the
// `progressbar` field of `PerTransfer` below. The driver only reads
// `progressbar.calls` (to decide whether to close the bar with a trailing
// newline in `post_per_transfer`).
// ===========================================================================

// ===========================================================================
// HdrCbData — header callback state (C `struct HdrCbData`, src/tool_cb_hdr.h)
// ===========================================================================

/// State handed to the header-write callback (C `struct HdrCbData`). It links a
/// transfer's headers back to the operation config and the output/etag streams
/// so `Content-Disposition`-driven naming and `--etag-save` work. The driver
/// owns it; the engine reads/writes it during a transfer.
#[derive(Debug, Default)]
pub struct HdrCbData {
    /// Index of the owning [`OperationConfig`] within
    /// [`GlobalConfig::operations`] (the C `hdrcbdata.config` back-pointer,
    /// expressed safely as an index).
    pub config_idx: usize,
    /// `true` when `Content-Disposition` filenames are honored for this
    /// transfer (`--remote-header-name`; C `hdrcbdata.honor_cd_filename`).
    pub honor_cd_filename: bool,
    /// Accumulated response header lines, in receive order, as raw bytes
    /// (the C `hdrcbdata.headlist` of `struct curl_slist`). Owned here so the
    /// `--write-out` `%{header_json}` renderer can walk them.
    pub headlist: Vec<Vec<u8>>,
}

// ===========================================================================
// PerTransfer — one queued/active transfer (C `struct per_transfer`,
// src/tool_operate.h)
// ===========================================================================

/// A single transfer's complete state — the Rust analog of curl's
/// `struct per_transfer`. Instances live in the [`Driver`]'s
/// [`VecDeque`](std::collections::VecDeque); the C `next`/`prev` list pointers
/// are intentionally absent (the deque provides ordering).
///
/// It owns the [`Easy`] handle, the resolved URL and output name, the retry
/// bookkeeping, the three [`OutStruct`] sinks, the [`HdrCbData`], the progress
/// state, and the per-transfer flags. It implements
/// [`crate::writeout::PerTransfer`] and [`crate::writeout_json::HeaderSource`]
/// so `--write-out` can render against it directly.
pub struct PerTransfer {
    /// Index of the owning [`OperationConfig`] in [`GlobalConfig::operations`]
    /// (C `per->config`, expressed as a safe index rather than a pointer).
    pub config_idx: usize,
    /// The easy handle driving this transfer (C `per->curl`). Owned by value so
    /// `--write-out` can borrow it; in parallel mode it is temporarily moved
    /// into [`shared`](Self::shared) for the multi handle and restored on
    /// completion.
    pub easy: Easy,
    /// The option-application scratch state shared with [`crate::setopt`]
    /// (`config2setopts`). It owns the built `-F` MIME tree and the
    /// `CURLOPT_ERRORBUFFER` storage, whose *addresses* are programmed into
    /// [`easy`](Self::easy); it is therefore boxed so those addresses stay
    /// valid even when this `PerTransfer` is moved within the driver's
    /// [`VecDeque`]. (C keeps `mimepost` in `OperationConfig` and the error
    /// buffer in `per`; we co-locate both here for lifetime correctness.)
    pub sp: Box<setopt::PerTransfer>,
    /// While added to a [`Multi`], the shared wrapper around
    /// [`easy`](Self::easy) (`None` in serial mode or once restored). Used to
    /// match the finished multi message back to this transfer via
    /// [`Arc::ptr_eq`].
    pub shared: Option<SharedEasy>,
    /// Remaining retry attempts (C `per->retry_remaining`, seeded from
    /// `config->req_retry`).
    pub retry_remaining: i64,
    /// The base/initial retry sleep in ms (C `per->retry_sleep_default`).
    pub retry_sleep_default: i64,
    /// The current (doubling) retry sleep in ms (C `per->retry_sleep`).
    pub retry_sleep: i64,
    /// Number of retries already performed (C `per->num_retries`), surfaced as
    /// `%{num_retries}`.
    pub num_retries: i64,
    /// When this transfer started (C `per->start`); used for `--rate` pacing.
    pub start: Instant,
    /// When the current retry cycle started (C `per->retrystart`), bounding
    /// `--retry-max-time`.
    pub retrystart: Instant,
    /// The transfer's URL exactly as resolved for this iteration
    /// (C `per->url`).
    pub url: Option<String>,
    /// The 1-based ordinal within a globbed URL set (C `per->urlnum`), surfaced
    /// as `%{urlnum}`.
    pub urlnum: i64,
    /// The explicit `-o`/`--output` target, if any (C `per->outfile`).
    pub outfile: Option<String>,
    /// The open upload source, or [`None`] for stdin / no upload
    /// (replaces C `per->infd`/`per->infdopen`).
    pub infile: Option<File>,
    /// The `-T`/`--upload-file` argument for this iteration
    /// (C `per->uploadfile`).
    pub uploadfile: Option<String>,
    /// The computed upload size, or `-1` when unknown (C `per->uploadfilesize`).
    pub uploadfilesize: i64,
    /// Running count of upload-body bytes consumed so far (C
    /// `per->uploadedsofar`). The read callback (`crate::callbacks::read`) uses
    /// it to detect completion and to cap an over-growing source at the original
    /// [`uploadfilesize`](Self::uploadfilesize); libcurl's transfer engine
    /// accounts the consumed bytes into it.
    pub uploadedsofar: i64,
    /// Previous `ulnow` (uploaded-bytes-now) seen by the busy-read unpauser
    /// (`tool_readbusy_cb`). curl keeps this in a function-`static curl_off_t
    /// ulprev`; storing it per-transfer here avoids `static mut`/`unsafe` and is
    /// more correct (no cross-transfer bleed) while preserving the stall
    /// detection (a 1 ms wait only when the upload has not advanced).
    pub ulprev: i64,
    /// The libcurl error buffer (`CURLOPT_ERRORBUFFER`; C
    /// `per->errorbuffer[CURL_ERROR_SIZE]`). Empty string means "no message".
    pub errorbuffer: String,
    /// Number of response headers received (C `per->num_headers`), surfaced as
    /// `%{num_headers}`.
    pub num_headers: i64,
    /// Unix epoch second at which a delayed (retried) parallel transfer may be
    /// re-added (C `per->startat`).
    pub startat: i64,
    /// Custom progress-bar state (C `per->progressbar`).
    pub progressbar: ProgressData,
    /// The response body output sink (C `per->outs`).
    pub outs: OutStruct,
    /// The `-D`/`--dump-header` output sink (C `per->heads`).
    pub heads: OutStruct,
    /// The `--etag-save` output sink (C `per->etag_save`).
    pub etag_save: OutStruct,
    /// Header-callback linkage (C `per->hdrcbdata`).
    pub hdrcbdata: HdrCbData,
    /// Captured certificate chain for `%{certs}`/`%{num_certs}`
    /// (C `per->certinfo`), or [`None`] when unavailable.
    pub certinfo: Option<Vec<Vec<String>>>,
    /// Last-reported total download size (C `per->dltotal`), for the aggregate
    /// parallel bar.
    pub dltotal: i64,
    /// Last-reported download progress (C `per->dlnow`).
    pub dlnow: i64,
    /// Last-reported total upload size (C `per->ultotal`).
    pub ultotal: i64,
    /// Last-reported upload progress (C `per->ulnow`).
    pub ulnow: i64,
    /// Whether [`dltotal`](Self::dltotal) was already folded into the aggregate
    /// (C `per->dltotal_added`).
    pub dltotal_added: bool,
    /// Whether [`ultotal`](Self::ultotal) was already folded into the aggregate
    /// (C `per->ultotal_added`).
    pub ultotal_added: bool,
    /// Progress meter suppressed for this transfer (C `per->noprogress`).
    pub noprogress: bool,
    /// Tracks whether the last header line was empty (C
    /// `per->was_last_header_empty`), used by header processing.
    pub was_last_header_empty: bool,
    /// `true` once this transfer has been added to the multi handle
    /// (C `per->added`).
    pub added: bool,
    /// Set to request aborting this in-flight transfer (C `per->abort`), used
    /// by `--fail-early` to stop sibling transfers.
    pub abort: bool,
    /// `true` when this transfer is skipped without running (C `per->skip`),
    /// e.g. `--skip-existing` matched a local file.
    pub skip: bool,
}

impl PerTransfer {
    /// Creates an empty transfer bound to `config_idx`, mirroring the
    /// zero-initialized node `add_per_transfer` allocates in C. Timestamps are
    /// seeded with [`Instant::now`]; they are overwritten by `pre_transfer`
    /// before the transfer actually runs.
    ///
    /// `pub(crate)` so sibling modules (e.g. `crate::callbacks`) can construct a
    /// transfer record for unit tests of the callbacks they register.
    pub(crate) fn new(config_idx: usize) -> Self {
        let now = Instant::now();
        PerTransfer {
            config_idx,
            easy: Easy::new(),
            // The URL is filled in by `create_single` before `config2setopts`
            // runs; an empty placeholder keeps `new()` infallible.
            sp: Box::new(setopt::PerTransfer::new(String::new())),
            shared: None,
            retry_remaining: 0,
            retry_sleep_default: 0,
            retry_sleep: 0,
            num_retries: 0,
            start: now,
            retrystart: now,
            url: None,
            urlnum: 0,
            outfile: None,
            infile: None,
            uploadfile: None,
            uploadfilesize: -1,
            uploadedsofar: 0,
            ulprev: 0,
            errorbuffer: String::new(),
            num_headers: 0,
            startat: 0,
            progressbar: ProgressData::default(),
            outs: OutStruct::default(),
            heads: OutStruct {
                // curl defaults the header dump stream to stdout.
                stream: None,
                ..OutStruct::default()
            },
            etag_save: OutStruct::default(),
            hdrcbdata: HdrCbData {
                config_idx,
                ..HdrCbData::default()
            },
            certinfo: None,
            dltotal: 0,
            dlnow: 0,
            ultotal: 0,
            ulnow: 0,
            dltotal_added: false,
            ultotal_added: false,
            noprogress: false,
            was_last_header_empty: false,
            added: false,
            abort: false,
            skip: false,
        }
    }

    /// Returns the per-transfer error message when one is present, mirroring
    /// curl's `errorbuffer[0] ? errorbuffer : NULL` test. An empty buffer maps
    /// to [`None`] so callers fall back to [`CurlError::description`].
    fn error_message(&self) -> Option<&str> {
        // Prefer the tool-set message (e.g. the parallel `--fail-early` abort
        // notice written by `check_finished`).
        if !self.errorbuffer.is_empty() {
            return Some(self.errorbuffer.as_str());
        }
        // Then the engine's Rust-native failure latch (the safe-core analogue of
        // `CURLOPT_ERRORBUFFER`): the protocol drivers record the few `failf`
        // diagnostics whose exact text differs from the static `CURLcode`
        // description here (e.g. the decompression-bomb "more than 5 content
        // encodings" message), so the `curl: (N) <msg>` line matches curl
        // byte-for-byte. See `Easy::last_error`'s foundation-limitation note.
        if let Some(msg) = self.easy.last_error() {
            return Some(msg);
        }
        // Otherwise surface the engine-written `CURLOPT_ERRORBUFFER` storage
        // that `config2setopts` programmed into the easy handle: it lives in the
        // co-located `sp` as a NUL-terminated C buffer. Decoding it here keeps
        // `%{errormsg}` / the `curl: (N) <msg>` line accurate once the protocol
        // engine starts populating it (today it stays all-zero — see the
        // module-level "foundation limitation" note).
        let buf = &self.sp.errorbuffer;
        let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if nul == 0 {
            None
        } else {
            std::str::from_utf8(&buf[..nul])
                .ok()
                .filter(|s| !s.is_empty())
        }
    }
}

// --- writeout trait impls --------------------------------------------------

impl HeaderSource for PerTransfer {
    /// Yields the received response headers in order, reading the libcurl header
    /// store (`curl_easy_header()` / `HeaderCollector`) on the easy handle — the
    /// same source curl's `%header{}` / `%{header_json}` write-out consults
    /// (`tool_writeout.c` calls `curl_easy_header`). The store is populated by the
    /// transfer engine with the final response block's `name: value` headers (the
    /// status line is excluded), already split into name/value pairs with original
    /// case and order preserved, so no re-parsing is needed here.
    fn response_headers(&self) -> Vec<HeaderField<'_>> {
        self.easy
            .headers()
            .iter()
            .map(|(name, value)| HeaderField {
                name: name.as_bytes(),
                value: value.as_bytes(),
            })
            .collect()
    }
}

impl crate::writeout::PerTransfer for PerTransfer {
    fn easy(&self) -> &Easy {
        &self.easy
    }

    fn num_retries(&self) -> i64 {
        self.num_retries
    }

    fn num_headers(&self) -> i64 {
        self.num_headers
    }

    fn error_buffer(&self) -> Option<&str> {
        self.error_message()
    }

    fn output_filename(&self) -> Option<&str> {
        self.outs.filename.as_deref()
    }

    fn input_url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    fn urlnum(&self) -> i64 {
        self.urlnum
    }

    fn cert_chain(&self) -> Option<Vec<Vec<String>>> {
        self.certinfo.clone()
    }
}

// ===========================================================================
// Driver — owns the transfer queue and the aggregate progress accounting
// (replaces the C file-scope `transfers`/`transfersl` list and the
// `tool_progress.c` `all_*` statics)
// ===========================================================================

/// Owns the live/queued transfers and the cross-transfer accounting that the C
/// tool keeps in file-scope globals. Threading this through the transfer
/// functions (instead of using globals) is what lets the module stay
/// `#![forbid(unsafe_code)]` and free of mutable statics.
/// Number of speed samples retained for the parallel progress meter's moving
/// average (C `SPEEDCNT`).
const SPEEDCNT: usize = 10;

/// One download/upload byte-count sample taken at a point in time, used by the
/// parallel aggregate progress meter to compute a moving-average speed
/// (C `struct speedcount`, `src/tool_progress.c`).
#[derive(Clone, Copy)]
struct SpeedCount {
    /// Aggregate downloaded bytes at [`stamp`](Self::stamp) (`speedcount.dl`).
    dl: i64,
    /// Aggregate uploaded bytes at [`stamp`](Self::stamp) (`speedcount.ul`).
    ul: i64,
    /// When this sample was taken (`speedcount.stamp`).
    stamp: Instant,
}

struct Driver {
    /// The FIFO of transfers (C `transfers`/`transfersl` doubly-linked list).
    /// New work is appended at the back; the serial loop processes the front.
    transfers: VecDeque<PerTransfer>,
    /// Number of transfers currently added to the multi handle in parallel
    /// mode (C file-scope `all_added`).
    all_added: i64,
    /// Aggregate download total across all transfers (C `all_dltotal`).
    all_dltotal: i64,
    /// Aggregate upload total across all transfers (C `all_ultotal`).
    all_ultotal: i64,
    /// Download bytes already completed by finished transfers
    /// (C `all_dlalready`).
    all_dlalready: i64,
    /// Upload bytes already completed by finished transfers
    /// (C `all_ulalready`).
    all_ulalready: i64,
    /// Whether the parallel progress header line has been printed yet
    /// (C `progress_meter`'s static `header`).
    progress_header: bool,
    /// Timestamp of the last progress line, for the 500 ms throttle
    /// (C `progress_meter`'s static `stamp`).
    progress_stamp: Option<Instant>,
    /// Header-dump files already truncated this run. curl truncates the
    /// `-D`/`--dump-header` file for the first transfer of an operation and
    /// appends thereafter (`setup_headerfile`'s `per->prev->config != config`
    /// test); tracking the paths reproduces that without list back-pointers.
    opened_headerfiles: Vec<String>,
    /// Ring buffer of recent aggregate byte-count samples for the parallel
    /// progress meter's speed estimate (C file-scope `speedstore[SPEEDCNT]`).
    speedstore: [SpeedCount; SPEEDCNT],
    /// Next write index into [`speedstore`](Self::speedstore) (C `speedindex`).
    speedindex: usize,
    /// `true` once [`speedstore`](Self::speedstore) has wrapped at least once,
    /// so the oldest sample is valid (C `indexwrapped`).
    indexwrapped: bool,
}

impl Driver {
    /// Creates an empty driver — the analog of the zeroed file-scope state at
    /// program start.
    fn new() -> Self {
        Driver {
            transfers: VecDeque::new(),
            all_added: 0,
            all_dltotal: 0,
            all_ultotal: 0,
            all_dlalready: 0,
            all_ulalready: 0,
            progress_header: false,
            progress_stamp: None,
            opened_headerfiles: Vec::new(),
            speedstore: [SpeedCount {
                dl: 0,
                ul: 0,
                stamp: Instant::now(),
            }; SPEEDCNT],
            speedindex: 0,
            indexwrapped: false,
        }
    }

    /// Appends a fresh transfer bound to `config_idx` and returns the index of
    /// the back element (C `add_per_transfer`, which links a new node at the
    /// tail). The returned index is valid until the next `pop_front`.
    fn add_per_transfer(&mut self, config_idx: usize) -> usize {
        self.transfers.push_back(PerTransfer::new(config_idx));
        self.transfers.len() - 1
    }

    /// Removes the front (just-processed) transfer (C `del_per_transfer`, which
    /// unlinks the current node and returns its successor — here the successor
    /// simply becomes the new front).
    fn del_front(&mut self) {
        self.transfers.pop_front();
    }

    /// Frees the remaining globbing iteration state for the current operation
    /// (C `single_transfer_cleanup`). The URL/upload globs and the pending
    /// upload file name are cleared so a subsequent operation starts clean.
    pub fn single_transfer_cleanup(global: &mut GlobalConfig) {
        let state = &mut global.state;
        state.urlglob = None;
        state.inglob = None;
        state.uploadfile = None;
    }
}

/// Public free-function form of [`Driver::single_transfer_cleanup`], mirroring
/// curl's `void single_transfer_cleanup(void)` symbol so callers (and tests)
/// can clear the per-operation globbing state directly.
pub fn single_transfer_cleanup(global: &mut GlobalConfig) {
    Driver::single_transfer_cleanup(global);
}

// ===========================================================================
// Standalone helpers (tool_operate.c + tool_operhlp.c)
// ===========================================================================

/// Returns `true` when the TLS feature is built in, gating CA-path and
/// certificate-type discovery (C `feature_ssl`). Derived from the same feature
/// list `curl --version` reports, so the gate stays consistent with capability
/// reporting.
fn feature_ssl() -> bool {
    curl_rs_lib::version::feature_names().contains(&"SSL")
}

/// Critical errors that abort the whole run immediately rather than continuing
/// to the next transfer (C `is_fatal_error`).
fn is_fatal_error(code: CurlCode) -> bool {
    matches!(
        code,
        codes::CURLE_FAILED_INIT
            | codes::CURLE_OUT_OF_MEMORY
            | codes::CURLE_UNKNOWN_OPTION
            | codes::CURLE_BAD_FUNCTION_ARGUMENT
    )
}

/// `true` when the upload source denotes standard input (`-` or `.`), matching
/// curl's `stdin_upload` (`src/tool_operhlp.c`).
fn stdin_upload(uploadfile: &str) -> bool {
    uploadfile == "-" || uploadfile == "."
}

/// Whether a transfer is expected to produce output (C `output_expected`,
/// `src/tool_operhlp.c`): always for downloads, and for HTTP(S) uploads (the
/// response body), but not for non-HTTP uploads.
fn output_expected(url: &str, uploadfile: Option<&str>) -> bool {
    if uploadfile.is_none() {
        return true; // download
    }
    let lower = url.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Maps a URL/glob parsing error code to the `CURLcode` curl returns
/// (C `urlerr_cvt`, `src/tool_operhlp.c`). The glob layer already reports a
/// `CURLUE_*`-equivalent code; anything not specifically recognized falls
/// through to `CURLE_URL_MALFORMAT`, exactly as the C `default` arm does.
fn urlerr_cvt(ucode: i32) -> CurlCode {
    // CURLUcode integer values per include/curl/urlapi.h (the ABI oracle):
    // CURLUE_BAD_HANDLE == 1, CURLUE_UNSUPPORTED_SCHEME == 5,
    // CURLUE_OUT_OF_MEMORY == 7, CURLUE_LACKS_IDN == 30. These match the
    // `#[repr(i32)]` discriminants of `curl_rs_lib::error::CurlUError`, so a
    // `CurlUError as i32` (or `GlobError::code()`) feeds in directly. The arm
    // order and fall-through mirror curl's `urlerr_cvt` (src/tool_operhlp.c).
    match ucode {
        7 => codes::CURLE_OUT_OF_MEMORY,
        5 => codes::CURLE_UNSUPPORTED_PROTOCOL,
        30 => codes::CURLE_NOT_BUILT_IN,
        1 => codes::CURLE_BAD_FUNCTION_ARGUMENT,
        _ => codes::CURLE_URL_MALFORMAT,
    }
}

/// Extracts just the path component of a URL the way curl's URL parser does for
/// filename derivation: drop any fragment and query, skip the `scheme://`
/// prefix and the authority, and keep everything from the first `/` onward.
/// Returns an empty string when the URL has no path part.
fn url_path_component(url: &str) -> String {
    let no_frag = url.split('#').next().unwrap_or("");
    let no_query = no_frag.split('?').next().unwrap_or("");
    let after_scheme = match no_query.find("://") {
        Some(p) => &no_query[p + 3..],
        None => no_query,
    };
    match after_scheme.find('/') {
        Some(slash) => after_scheme[slash..].to_string(),
        None => String::new(),
    }
}

/// Derives the local file name from a URL (C `get_url_file_name`,
/// `src/tool_operhlp.c`). The last path segment (after the rightmost `/` or
/// `\`) is used, dropping a single trailing slash first; when no segment
/// remains the default `"curl_response"` is used and a warning is emitted —
/// byte-for-byte the curl behavior.
fn get_url_file_name(global: &GlobalConfig, url: &str) -> Result<String, CurlCode> {
    let mut path = url_path_component(url);

    // Two passes: the first may strip a single trailing slash so the directory
    // segment can be taken on the second pass (C loops `for(i = 0; i < 2; i++)`).
    let mut cut: Option<usize> = None;
    for i in 0..2 {
        let last_slash = path.rfind('/');
        let search_from = last_slash.map(|p| p + 1).unwrap_or(0);
        let last_back = path[search_from..].rfind('\\').map(|p| p + search_from);
        let pc = last_back.or(last_slash);
        if let Some(idx) = pc {
            if idx + 1 == path.len() && i == 0 {
                // Trailing separator: drop it and retry to grab the directory.
                path.truncate(idx);
                continue;
            }
        }
        cut = pc;
        break;
    }

    let filename = match cut {
        Some(idx) => path[idx + 1..].to_string(),
        None => {
            let default = "curl_response".to_string();
            warnf!(global, "No remote filename, uses \"{}\"", default);
            default
        }
    };
    Ok(filename)
}

/// Appends the upload file's base name to the URL when the URL path has no
/// filename of its own (C `add_file_name_to_url`, `src/tool_operhlp.c`). When
/// the URL already carries a query or a filename the URL is returned unchanged.
fn add_file_name_to_url(inurl: &str, filename: &str) -> Result<String, CurlCode> {
    // A query string means the path part is considered complete (C returns OK
    // without modifying the URL).
    if inurl.contains('?') {
        return Ok(inurl.to_string());
    }
    let path = url_path_component(inurl);
    let has_filename = match path.rfind('/') {
        Some(p) => p + 1 < path.len(),
        None => !path.is_empty(),
    };
    if has_filename {
        return Ok(inurl.to_string());
    }

    // Take the right-most component of the local filename (after '/' or '\\').
    let base = filename
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(filename);

    // Percent-encode the base name conservatively (RFC 3986 unreserved set is
    // left as-is; everything else is %-escaped), matching curl_easy_escape.
    let mut enc = String::with_capacity(base.len());
    for &b in base.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            enc.push(b as char);
        } else {
            enc.push('%');
            enc.push_str(&format!("{b:02X}"));
        }
    }

    let sep = if inurl.ends_with('/') { "" } else { "/" };
    Ok(format!("{inurl}{sep}{enc}"))
}

/// Sets the HTTP request method, rejecting conflicting selections
/// (C `SetHTTPrequest`, `src/tool_helpers.c`). Returns `true` on conflict (the
/// caller maps that to `CURLE_FAILED_INIT`), emitting the same warning curl
/// prints when two methods are requested.
fn set_http_request(global: &GlobalConfig, req: HttpReq, store: &mut HttpReq) -> bool {
    if *store == HttpReq::Unspec || *store == req {
        *store = req;
        return false;
    }
    let name = |r: HttpReq| match r {
        HttpReq::Unspec => "",
        HttpReq::Get => "GET (-G, --get)",
        HttpReq::Head => "HEAD (-I, --head)",
        HttpReq::MimePost => "multipart formpost (-F, --form)",
        HttpReq::SimplePost => "POST (-d, --data)",
        HttpReq::Put => "PUT (-T, --upload-file)",
    };
    warnf!(
        global,
        "You can only select one HTTP request method! You asked for both {} and {}.",
        name(req),
        name(*store)
    );
    true
}

/// Whether a string is a PKCS#11 URI (C `is_pkcs11_uri`): a case-insensitive
/// `pkcs11:` scheme prefix.
fn is_pkcs11_uri(s: &str) -> bool {
    s.len() >= 7 && s[..7].eq_ignore_ascii_case("pkcs11:")
}

/// Promotes PKCS#11 certificate/key URIs to the `"ENG"` type when the type was
/// not given explicitly (C `set_cert_types`, `src/tool_operate.c`). A no-op
/// unless TLS is built in.
fn set_cert_types(config: &mut OperationConfig) -> CurlCode {
    if !feature_ssl() {
        return codes::CURLE_OK;
    }
    if config.cert.as_deref().is_some_and(is_pkcs11_uri) && config.cert_type.is_none() {
        config.cert_type = Some("ENG".to_string());
    }
    if config.key.as_deref().is_some_and(is_pkcs11_uri) && config.key_type.is_none() {
        config.key_type = Some("ENG".to_string());
    }
    if config.proxy_cert.as_deref().is_some_and(is_pkcs11_uri) && config.proxy_cert_type.is_none() {
        config.proxy_cert_type = Some("ENG".to_string());
    }
    if config.proxy_key.as_deref().is_some_and(is_pkcs11_uri) && config.proxy_key_type.is_none() {
        config.proxy_key_type = Some("ENG".to_string());
    }
    codes::CURLE_OK
}

/// Discovers the default CA bundle/path from the environment when no explicit
/// `--cacert`/`--capath` was given and verification is on (C `cacertpaths`,
/// `src/tool_operate.c`). Honors `CURL_CA_BUNDLE`, `SSL_CERT_DIR`, and
/// `SSL_CERT_FILE` (AAP §0.8.3: `SSL_CERT_FILE` is honored). No-op unless TLS is
/// built in.
fn cacertpaths(config: &mut OperationConfig) -> CurlCode {
    if !feature_ssl()
        || config.cacert.is_some()
        || config.capath.is_some()
        || (config.insecure_ok && (config.doh_url.is_none() || config.doh_insecure_ok))
    {
        return codes::CURLE_OK;
    }

    if let Some(env) = std::env::var_os("CURL_CA_BUNDLE") {
        if !env.is_empty() {
            config.cacert = Some(env.to_string_lossy().into_owned());
            return codes::CURLE_OK;
        }
    }
    if let Some(env) = std::env::var_os("SSL_CERT_DIR") {
        if !env.is_empty() {
            config.capath = Some(env.to_string_lossy().into_owned());
        }
    }
    if let Some(env) = std::env::var_os("SSL_CERT_FILE") {
        if !env.is_empty() {
            config.cacert = Some(env.to_string_lossy().into_owned());
        }
    }
    codes::CURLE_OK
}

// ===========================================================================
// Home / config file resolution (tool_findfile.c)
// ===========================================================================

/// One entry of curl's `conf_list` finder table (`src/tool_findfile.c`).
struct Finder {
    /// The environment variable to read the base directory from.
    env: &'static str,
    /// An optional suffix appended to the directory (e.g. `/.config`).
    append: &'static str,
    /// When `true`, the leading dot of the file name is dropped before lookup
    /// (the XDG / `.config` convention).
    withoutdot: bool,
}

/// curl's `conf_list`, in priority order. The Windows-only entries are omitted
/// on non-Windows targets, exactly as the `#ifdef _WIN32` block does.
const CONF_LIST: &[Finder] = &[
    Finder {
        env: "CURL_HOME",
        append: "",
        withoutdot: false,
    },
    Finder {
        env: "XDG_CONFIG_HOME",
        append: "",
        withoutdot: true,
    },
    Finder {
        env: "HOME",
        append: "",
        withoutdot: false,
    },
    Finder {
        env: "CURL_HOME",
        append: "/.config",
        withoutdot: true,
    },
    Finder {
        env: "HOME",
        append: "/.config",
        withoutdot: true,
    },
];

/// Checks for `fname` under `home`, trying a dot-prefixed then (when `dotscore`)
/// an underscore-prefixed variant (C `checkhome`, `src/tool_findfile.c`). The
/// first byte of `fname` is the separator placeholder the C code overwrites.
fn checkhome(home: &str, fname: &str, dotscore: bool) -> Option<String> {
    let prefixes: &[char] = if dotscore { &['.', '_'] } else { &[] };
    if dotscore {
        // Replace the leading char of fname with '.' then '_'.
        let rest = &fname[1..];
        for &p in prefixes {
            let candidate = format!("{home}/{p}{rest}");
            if File::open(&candidate).is_ok() {
                return Some(candidate);
            }
        }
        None
    } else {
        let candidate = format!("{home}/{fname}");
        if File::open(&candidate).is_ok() {
            Some(candidate)
        } else {
            None
        }
    }
}

/// Resolves the full path of a per-user file (C `findfile`,
/// `src/tool_findfile.c`). Iterates the environment-variable finder table in
/// order; `dotscore == 2` additionally tries an underscore-prefixed name.
///
/// The `getpwuid` home-directory fallback of the C version is intentionally
/// omitted: it requires the C password database (and thus `unsafe`/`libc`),
/// which this crate forbids. The `HOME`/`CURL_HOME`/`XDG_CONFIG_HOME` lookups
/// cover the practical cases.
///
/// Exposed `pub(crate)` so the SSH preflight ([`crate::setopt`]) can reuse the
/// exact same finder table to default `CURLOPT_SSH_KNOWNHOSTS` to
/// `~/.ssh/known_hosts`, mirroring `config2setopts.c`'s
/// `findfile(".ssh/known_hosts", FALSE)` call.
pub(crate) fn findfile(fname: &str, dotscore: i32) -> Option<String> {
    if fname.is_empty() {
        return None;
    }
    for f in CONF_LIST {
        let home = match std::env::var_os(f.env) {
            Some(h) if !h.is_empty() => h.to_string_lossy().into_owned(),
            _ => continue,
        };
        let mut home = home;
        if !f.append.is_empty() {
            home.push_str(f.append);
        }
        let mut filename = fname;
        let mut local_dotscore = dotscore;
        if f.withoutdot {
            if dotscore == 0 {
                continue;
            }
            filename = &fname[1..]; // move past the leading dot
            local_dotscore = 0; // disable the extended check here
        }
        let ch_dotscore = if local_dotscore != 0 {
            local_dotscore - 1
        } else {
            0
        };
        if let Some(path) = checkhome(&home, filename, ch_dotscore != 0) {
            return Some(path);
        }
    }
    None
}

// ===========================================================================
// Progress meter (tool_progress.c)
// ===========================================================================

/// Formats a byte count into a fixed 5-character field with a magnitude suffix
/// (C `max5data`, `src/tool_progress.c`). Values below 100000 are shown as-is;
/// larger values use `k`/`M`/`G`/`T`/`P`/`E` units, with one decimal digit
/// while the mantissa is below 100.
fn max5data(bytes: i64) -> String {
    const UNIT: [char; 6] = ['k', 'M', 'G', 'T', 'P', 'E'];
    if bytes < 100_000 {
        return format!("{bytes:5}");
    }
    let mut b = bytes;
    let mut k = 0usize;
    loop {
        let nbytes = b / 1024;
        if nbytes < 100 {
            // one decimal digit
            return format!("{:2}.{}{}", b / 1024, (b % 1024) * 10 / 1024, UNIT[k]);
        } else if nbytes < 10000 {
            return format!("{:4}{}", nbytes, UNIT[k]);
        }
        b = nbytes;
        k += 1;
        if k >= UNIT.len() {
            // Saturate at the largest unit rather than indexing out of range.
            return format!("{:4}{}", b, UNIT[UNIT.len() - 1]);
        }
    }
}

/// Formats a duration in seconds into an 8-character time string
/// (C `time2str`, `src/tool_progress.c`): `HH:MM:SS`, then `NNNd HHh`,
/// `NNNm DDd`, `NNNNNNNy`, or ` >99999y` for ever-larger spans. Non-positive
/// input renders as eight spaces.
fn time2str(seconds: i64) -> String {
    if seconds <= 0 {
        return "        ".to_string();
    }
    let h = seconds / 3600;
    if h <= 99 {
        let m = (seconds - h * 3600) / 60;
        let s = (seconds - h * 3600) - m * 60;
        return format!("{h:02}:{m:02}:{s:02}");
    }
    let d = seconds / 86400;
    let h = (seconds - d * 86400) / 3600;
    if d <= 999 {
        format!("{d:3}d {h:02}h")
    } else {
        let m = d / 30;
        if m <= 999 {
            format!("{m:3}m {:02}d", d % 30)
        } else {
            let y = d / 365;
            if y <= 99999 {
                format!("{y:7}y")
            } else {
                " >99999y".to_string()
            }
        }
    }
}

// ===========================================================================
// Chunk 5 — the per-URL transfer builder (C `create_transfer` →
// `transfer_per_config` → `single_transfer` → `create_single`) and the
// folded-in output/etag/header helpers (`setup_outfile`, `setup_headerfile`,
// `setup_header_cb`, `etag_compare`, `etag_store`, `append2query`,
// `check_stdin_upload`). These turn one `OperationConfig` (and its globbed
// URL/upload patterns) into queued [`PerTransfer`]s on the [`Driver`].
// ===========================================================================

/// Writes a pre-formatted diagnostic line to the diagnostic stream, gated like
/// curl's glob error stream `(!global->silent || global->showerror) ?
/// tool_stderr : NULL`.
///
/// Used for the URL/upload glob parse errors and the final `curl: (N) <msg>`
/// transfer-result line, whose text already carries the `curl: (N) ` prefix (and
/// for glob errors, a caret line) that must **not** be word-wrapped — so it
/// bypasses [`crate::messages`]'s wrapping `errorf`.
///
/// The bytes are emitted through [`crate::messages::emit_raw`], so the write
/// follows any `--stderr <file>` / `--stderr -` redirection
/// (curl's `tool_stderr`) exactly as curl does, while preserving the observable
/// silent / show-error gating.
fn write_gated_err(global: &GlobalConfig, line: &str) {
    if !global.silent || global.showerror {
        crate::messages::emit_raw(line.as_bytes());
    }
}

/// Creates every parent directory of `path` (mirrors `create_dir_hierarchy`,
/// `src/tool_dirhie.c`, which the folded `--create-dirs` paths call). `path` is
/// the *output file*, so only its parent chain is created. On failure curl
/// emits an error and the transfer fails with [`codes::CURLE_WRITE_ERROR`].
fn create_dir_hierarchy(global: &GlobalConfig, path: &str) -> CurlCode {
    if let Some(dir) = Path::new(path).parent() {
        if !dir.as_os_str().is_empty() {
            if let Err(e) = fs::create_dir_all(dir) {
                errorf!(
                    global,
                    "Failed to create the path directory hierarchy: {}: {}",
                    dir.display(),
                    e
                );
                return codes::CURLE_WRITE_ERROR;
            }
        }
    }
    codes::CURLE_OK
}

impl Driver {
    /// Creates the next transfer(s) for the current operation, advancing
    /// `global.current` through the operation list (C `create_transfer`).
    ///
    /// Returns once a transfer was queued (`*added == true`) or an error
    /// occurs; a clean walk off the end of the operation list returns
    /// [`codes::CURLE_OK`] with `*added == false`.
    fn create_transfer(
        &mut self,
        global: &mut GlobalConfig,
        share: &Share,
        added: &mut bool,
        skipped: &mut bool,
    ) -> CurlCode {
        *added = false;
        let mut result = codes::CURLE_OK;
        while global.current < global.operations.len() {
            let cur = global.current;
            result = self.transfer_per_config(global, share, cur, added, skipped);
            if result == codes::CURLE_OK && !*added {
                // This operation produced no transfer (its URLs are drained):
                // move on to the next operation, exactly as curl walks
                // `global->current = global->current->next`.
                global.current += 1;
                continue;
            }
            break;
        }
        result
    }

    /// Validates and prepares one operation, then delegates to
    /// [`single_transfer`](Self::single_transfer) (C `transfer_per_config`).
    ///
    /// Emits curl's `"(2) no URL specified"` help diagnostic and returns
    /// [`codes::CURLE_FAILED_INIT`] when the operation has no URL, and clears the
    /// per-operation glob state when nothing was added or an error occurred.
    fn transfer_per_config(
        &mut self,
        global: &mut GlobalConfig,
        share: &Share,
        config_idx: usize,
        added: &mut bool,
        skipped: &mut bool,
    ) -> CurlCode {
        *added = false;

        // curl: `if(!config->url_list || !config->url_list->url)`.
        let has_url = global.operations[config_idx]
            .url_list
            .first()
            .is_some_and(|g| g.url.is_some());
        if !has_url {
            helpf!("({}) no URL specified", codes::CURLE_FAILED_INIT);
            return codes::CURLE_FAILED_INIT;
        }

        let mut result = cacertpaths(&mut global.operations[config_idx]);
        if result == codes::CURLE_OK {
            result = self.single_transfer(global, share, config_idx, added, skipped);
            if !*added || result != codes::CURLE_OK {
                single_transfer_cleanup(global);
            }
        }
        result
    }

    /// Resolves the operation's request method from `--data`/`--get`/`--head`
    /// and the `--url-query` fields, then hands off to
    /// [`create_single`](Self::create_single) (C `single_transfer`).
    fn single_transfer(
        &mut self,
        global: &mut GlobalConfig,
        share: &Share,
        config_idx: usize,
        added: &mut bool,
        skipped: &mut bool,
    ) -> CurlCode {
        *skipped = false;
        *added = false;

        if global.operations[config_idx].postfields.is_some() {
            if global.operations[config_idx].use_httpget {
                if global.state.httpgetfields.is_none() {
                    // Re-purpose the POST body as `-G` query fields and drop the
                    // body (curl moves the pointer and NULLs `config->postfields`).
                    let moved = global.operations[config_idx].postfields.take();
                    global.state.httpgetfields = moved;
                    let req = if global.operations[config_idx].no_body {
                        HttpReq::Head
                    } else {
                        HttpReq::Get
                    };
                    let mut store = global.operations[config_idx].httpreq;
                    if set_http_request(global, req, &mut store) {
                        return codes::CURLE_FAILED_INIT;
                    }
                    global.operations[config_idx].httpreq = store;
                }
            } else {
                let mut store = global.operations[config_idx].httpreq;
                if set_http_request(global, HttpReq::SimplePost, &mut store) {
                    return codes::CURLE_FAILED_INIT;
                }
                global.operations[config_idx].httpreq = store;
            }
        }
        if global.state.httpgetfields.is_none() {
            global.state.httpgetfields = global.operations[config_idx].query.clone();
        }

        let r = set_cert_types(&mut global.operations[config_idx]);
        if r != codes::CURLE_OK {
            return r;
        }

        if global.state.urlnode.is_none() {
            // First call for this operation: start at the head of its URL list.
            global.state.urlnode = Some(0);
            global.state.upnum = 1;
        }

        self.create_single(global, share, config_idx, added, skipped)
    }

    /// The core per-URL builder (C `create_single`): walks the operation's URL
    /// nodes, expands URL/upload globs, opens the output/header/etag sinks,
    /// resolves the per-iteration URL and output name, programs the [`Easy`]
    /// via [`config2setopts`](crate::setopt::config2setopts), and queues the
    /// resulting [`PerTransfer`]. Builds **one** transfer per call (then
    /// `break`s with `*added == true`), so the caller loops to drain a glob set.
    fn create_single(
        &mut self,
        global: &mut GlobalConfig,
        share: &Share,
        config_idx: usize,
        added: &mut bool,
        skipped: &mut bool,
    ) -> CurlCode {
        let orig_isatty = global.isatty;
        let orig_noprogress = global.noprogress;

        while let Some(node) = global.state.urlnode {
            // (1) No URL on this node → "end of the road".
            let node_has_url = global.operations[config_idx]
                .url_list
                .get(node)
                .and_then(|g| g.url.as_ref())
                .is_some();
            if !node_has_url {
                warnf!(global, "Got more output options than URLs");
                break;
            }

            // (2) Upload-file globbing for this node.
            if global.operations[config_idx].url_list[node]
                .infile
                .is_some()
            {
                let globoff = global.operations[config_idx].globoff;
                if !globoff && global.state.inglob.is_none() {
                    let infile = global.operations[config_idx].url_list[node]
                        .infile
                        .clone()
                        .unwrap_or_default();
                    match urlglob::glob_url(&infile) {
                        Ok((g, count)) => {
                            global.state.inglob = Some(g);
                            global.state.upnum = count;
                        }
                        Err(e) => {
                            write_gated_err(global, &e.to_stderr_string(&infile));
                            return e.code();
                        }
                    }
                }
                if global.state.uploadfile.is_none() {
                    if let Some(inglob) = global.state.inglob.as_mut() {
                        global.state.uploadfile = inglob.glob_next_url();
                    } else if global.state.upidx == 0 {
                        // No globbing: adopt the single upload file name.
                        let taken = global.operations[config_idx].url_list[node].infile.take();
                        global.state.uploadfile = taken;
                    }
                }
            }

            // (3) All uploads for this node consumed → advance to the next node.
            if global.state.upidx >= global.state.upnum {
                global.state.urlnum = 0;
                global.state.uploadfile = None;
                global.state.inglob = None;
                global.state.upidx = 0;
                let len = global.operations[config_idx].url_list.len();
                global.state.urlnode = if node + 1 < len { Some(node + 1) } else { None };
                continue;
            }

            // (4) URL globbing — establish the iteration count for this node.
            if global.state.urlnum == 0 {
                let globoff = global.operations[config_idx].globoff;
                let noglob = global.operations[config_idx].url_list[node].flags.noglob;
                if !globoff && !noglob {
                    let u_url = global.operations[config_idx].url_list[node]
                        .url
                        .clone()
                        .unwrap_or_default();
                    match urlglob::glob_url(&u_url) {
                        Ok((g, count)) => {
                            global.state.urlglob = Some(g);
                            global.state.urlnum = count;
                        }
                        Err(e) => {
                            write_gated_err(global, &e.to_stderr_string(&u_url));
                            return e.code();
                        }
                    }
                } else {
                    global.state.urlnum = 1;
                }
            }

            // (5) `--etag-save` scratch sink (defaults to stdout = `None`).
            let mut etag_first = OutStruct::default();

            // (6) `--etag-compare`: inject an `If-None-Match` header.
            if global.operations[config_idx].etag_compare_file.is_some() {
                let r = etag_compare(global, config_idx);
                if r != codes::CURLE_OK {
                    return r;
                }
            }
            // (7) `--etag-save`: open the save file (a failure skips this node).
            if global.operations[config_idx].etag_save_file.is_some() {
                let mut badetag = false;
                let r = etag_store(global, config_idx, &mut etag_first, &mut badetag);
                if r != codes::CURLE_OK || badetag {
                    return r;
                }
            }

            // (8) Build the per-transfer node.
            let mut per = PerTransfer::new(config_idx);
            per.etag_save = etag_first;

            if let Some(uf) = global.state.uploadfile.clone() {
                per.uploadfile = Some(uf);
                let mut store = global.operations[config_idx].httpreq;
                if set_http_request(global, HttpReq::Put, &mut store) {
                    return codes::CURLE_FAILED_INIT;
                }
                global.operations[config_idx].httpreq = store;
            }

            per.urlnum = global.operations[config_idx].url_list[node].num;

            // Single header dump file shared across URLs (append after truncate).
            if global.operations[config_idx].headerfile.is_some() {
                let r =
                    setup_headerfile(global, config_idx, &mut per, &mut self.opened_headerfiles);
                if r != codes::CURLE_OK {
                    return r;
                }
            }

            // Initialize the `-#` progress-bar display state for this transfer
            // (C `progressbarinit` in `single_transfer`): zero the counters,
            // thread the `--continue-at` resume offset, size the bar to the
            // terminal, and bind its output to stderr. Only meaningful in bar
            // mode; the built-in meter and the silent path do not use it.
            if global.progressmode == CURL_PROGRESS_BAR {
                crate::callbacks::progress::progressbarinit(
                    &mut per.progressbar,
                    &global.operations[config_idx],
                );
            }

            // (9) Resolve this iteration's URL (from the glob, or the literal).
            let have_url = if let Some(urlglob) = global.state.urlglob.as_mut() {
                let next = urlglob.glob_next_url();
                let some = next.is_some();
                per.url = next;
                some
            } else if global.state.urlidx == 0 {
                per.url = global.operations[config_idx].url_list[node].url.clone();
                per.url.is_some()
            } else {
                per.url = None;
                false
            };
            if !have_url {
                break;
            }

            if let Some(of) = global.operations[config_idx].url_list[node].outfile.clone() {
                per.outfile = Some(of);
            }

            // (10) Output-file setup (remote name, globbed `#N`, dirs, resume…).
            let out_null = global.operations[config_idx].url_list[node].flags.out_null;
            per.outs.out_null = out_null;
            let useremote = global.operations[config_idx].url_list[node].flags.useremote;
            let want_outfile = useremote || per.outfile.as_deref().is_some_and(|o| o != "-");
            if !out_null && want_outfile {
                let r = setup_outfile(global, config_idx, &mut per, skipped);
                if r != codes::CURLE_OK {
                    return r;
                }
            }

            // (11) Upload source: stdin vs. a named file appended to the URL.
            if let Some(uf) = per.uploadfile.clone() {
                if stdin_upload(&uf) {
                    check_stdin_upload(global, &per);
                } else {
                    let inurl = per.url.clone().unwrap_or_default();
                    match add_file_name_to_url(&inurl, &uf) {
                        Ok(newurl) => per.url = Some(newurl),
                        Err(code) => return code,
                    }
                }
                if global.operations[config_idx].resume_from_current {
                    // -1 forces libcurl to discover the resume offset itself.
                    global.operations[config_idx].resume_from = -1;
                }
            }

            // (12) Disable the progress meter when writing to a TTY stdout.
            let to_stdout =
                per.outs.filename.is_none() && per.outs.stream.is_none() && !per.outs.to_stderr;
            if !out_null
                && output_expected(per.url.as_deref().unwrap_or(""), per.uploadfile.as_deref())
                && to_stdout
                && std::io::IsTerminal::is_terminal(&std::io::stdout())
            {
                per.noprogress = true;
                global.noprogress = true;
                global.isatty = true;
            } else {
                per.noprogress = orig_noprogress;
                global.noprogress = orig_noprogress;
                global.isatty = orig_isatty;
            }

            // (13) Append `-G`/`--url-query` fields to the URL.
            if let Some(q) = global.state.httpgetfields.clone() {
                let r = append2query(global, config_idx, &mut per, &q);
                if r != codes::CURLE_OK {
                    return r;
                }
            }

            // (14) Binary stdout is a no-op in Rust; record the binary-OK flag.
            global.operations[config_idx].terminal_binary_ok = per.outfile.as_deref() == Some("-");

            // (15) Wire the header-callback linkage (Content-Disposition naming).
            let cd = global.operations[config_idx].content_disposition;
            setup_header_cb(cd, useremote, &mut per.hdrcbdata);

            // (16) Program the easy handle from the CLI configuration.
            per.sp.url = per.url.clone().unwrap_or_default();
            per.sp.uploadfile = per.uploadfile.clone();
            if let Err(e) = setopt::config2setopts(
                global,
                &global.operations[config_idx],
                per.sp.as_mut(),
                &mut per.easy,
                share,
            ) {
                return e.code();
            }

            // (17) Seed retry bookkeeping for the serial/parallel loops.
            per.retry_sleep_default = global.operations[config_idx].retry_delay_ms;
            per.retry_remaining = global.operations[config_idx].req_retry;
            per.retry_sleep = per.retry_sleep_default;
            per.retrystart = Instant::now();

            // (18) Advance the glob index; tidy up when the set drains.
            global.state.urlidx += 1;
            if global.state.urlidx >= global.state.urlnum {
                global.state.urlidx = 0;
                global.state.urlnum = 0;
                global.state.urlglob = None;
                global.state.upidx += 1;
                global.state.uploadfile = None;
            }

            self.transfers.push_back(per);
            *added = true;
            break;
        }
        codes::CURLE_OK
    }
}

/// Determines the output file name and opens it when resuming (C
/// `setup_outfile`, `src/tool_operate.c`). Handles `-O`/remote-name derivation,
/// globbed `#N` substitution, the `--output-dir` prefix, `--create-dirs`,
/// `--skip-existing`, and `--continue-at`/`-C -`. On `--skip-existing` matching
/// a local file it sets `per.skip` and `*skipped`.
fn setup_outfile(
    global: &mut GlobalConfig,
    config_idx: usize,
    per: &mut PerTransfer,
    skipped: &mut bool,
) -> CurlCode {
    // Derive (or glob-substitute) the output file name.
    if per.outfile.is_none() {
        let url = per.url.clone().unwrap_or_default();
        match get_url_file_name(global, &url) {
            Ok(name) => per.outfile = Some(name),
            Err(code) => {
                errorf!(
                    global,
                    "Failed to extract a filename from the URL to use for storage"
                );
                return code;
            }
        }
    } else if global.state.urlglob.is_some() {
        // Fill `#1`…`#9` placeholders from the active URL glob.
        let storefile = per.outfile.clone().unwrap_or_default();
        let matched = {
            let g = global.state.urlglob.as_ref().unwrap();
            g.glob_match_url(&storefile)
        };
        match matched {
            Ok(name) => {
                if name.is_empty() {
                    warnf!(global, "output glob produces empty string");
                    return codes::CURLE_WRITE_ERROR;
                }
                per.outfile = Some(name);
            }
            Err(e) => {
                warnf!(global, "bad output glob");
                return e.code();
            }
        }
    }

    // `--output-dir` prefix.
    let output_dir = global.operations[config_idx].output_dir.clone();
    if let Some(dir) = output_dir.as_deref() {
        if !dir.is_empty() {
            let of = per.outfile.clone().unwrap_or_default();
            per.outfile = Some(format!("{dir}/{of}"));
        }
    }

    // `--create-dirs`: build the parent hierarchy.
    if global.operations[config_idx].create_dirs {
        let of = per.outfile.clone().unwrap_or_default();
        let r = create_dir_hierarchy(global, &of);
        if r != codes::CURLE_OK {
            return r;
        }
    }

    // `--skip-existing`: skip the transfer when the file is already present.
    if global.operations[config_idx].skip_existing {
        let of = per.outfile.clone().unwrap_or_default();
        if Path::new(&of).exists() {
            notef!(global, "skips transfer, \"{of}\" exists locally");
            per.skip = true;
            *skipped = true;
        }
    }

    // `-C -` (`--continue-at -`): resume from the current local file size.
    if global.operations[config_idx].resume_from_current {
        let of = per.outfile.clone().unwrap_or_default();
        let size = fs::metadata(&of).map(|m| m.len() as i64).unwrap_or(0);
        global.operations[config_idx].resume_from = size;
    }

    // Open in append mode when resuming; otherwise defer the open to first write.
    if global.operations[config_idx].resume_from != 0 {
        let of = per.outfile.clone().unwrap_or_default();
        match OpenOptions::new().create(true).append(true).open(&of) {
            Ok(file) => {
                per.outs.fopened = true;
                per.outs.stream = Some(file);
                per.outs.init = global.operations[config_idx].resume_from.max(0) as u64;
            }
            Err(_) => {
                errorf!(global, "cannot open '{of}'");
                return codes::CURLE_WRITE_ERROR;
            }
        }
    } else {
        // Regular file, opened lazily on the first write (C `stream = NULL`).
        per.outs.stream = None;
    }
    per.outs.filename = per.outfile.clone();
    per.outs.regular_file = true;
    codes::CURLE_OK
}

/// Opens the shared `-D`/`--dump-header` file (C `setup_headerfile`,
/// `src/tool_operate.c`). `%` targets stderr, `-` targets stdout, otherwise the
/// file is opened in append mode — truncated once (the first transfer for this
/// operation) via the `opened` registry, which replaces curl's
/// `per->prev->config != config` first-transfer test.
fn setup_headerfile(
    global: &mut GlobalConfig,
    config_idx: usize,
    per: &mut PerTransfer,
    opened: &mut Vec<String>,
) -> CurlCode {
    let headerfile = match global.operations[config_idx].headerfile.clone() {
        Some(h) => h,
        None => return codes::CURLE_OK,
    };

    if headerfile == "%" {
        // Dump protocol headers to stderr.
        per.heads.to_stderr = true;
        per.heads.stream = None;
    } else if headerfile != "-" {
        if global.operations[config_idx].create_dirs {
            let r = create_dir_hierarchy(global, &headerfile);
            if r != codes::CURLE_OK {
                return r;
            }
        }
        // First transfer writing to this file truncates it; later transfers
        // append (transfers may finish in any order).
        if !opened.iter().any(|h| h == &headerfile) {
            let _ = File::create(&headerfile);
            opened.push(headerfile.clone());
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&headerfile)
        {
            Ok(file) => {
                per.heads.filename = Some(headerfile.clone());
                per.heads.regular_file = true;
                per.heads.fopened = true;
                per.heads.stream = Some(file);
            }
            Err(_) => {
                errorf!(global, "Failed to open {headerfile}");
                return codes::CURLE_WRITE_ERROR;
            }
        }
    }
    // headerfile == "-": headers go to stdout (`heads.stream` stays `None`).
    codes::CURLE_OK
}

/// Links the header-write callback state (C `setup_header_cb`). In the safe
/// model the output/header/etag sinks are sibling fields of the same
/// [`PerTransfer`], so only the `Content-Disposition` honor flag is recorded
/// here (the config index is already set at construction).
fn setup_header_cb(content_disposition: bool, useremote: bool, hdrcbdata: &mut HdrCbData) {
    hdrcbdata.honor_cd_filename = content_disposition && useremote;
}

/// Reads `--etag-compare`'s file and appends the corresponding `If-None-Match`
/// header to the operation's custom-header list (C `etag_compare`). A missing
/// file warns and yields an empty-quoted etag, exactly as curl does. The file
/// contents have all CR/LF stripped (curl's `file2string`/`memcrlf`).
fn etag_compare(global: &mut GlobalConfig, config_idx: usize) -> CurlCode {
    let path = match global.operations[config_idx].etag_compare_file.clone() {
        Some(p) => p,
        None => return codes::CURLE_OK,
    };

    let etag_from_file = match fs::read(&path) {
        Ok(bytes) => {
            let filtered: Vec<u8> = bytes
                .into_iter()
                .filter(|&b| b != b'\n' && b != b'\r')
                .collect();
            if filtered.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&filtered).into_owned())
            }
        }
        Err(e) => {
            warnf!(global, "Failed to open {path}: {e}");
            None
        }
    };

    let header = match etag_from_file {
        Some(etag) => format!("If-None-Match: {etag}"),
        None => "If-None-Match: \"\"".to_string(),
    };
    global.operations[config_idx].headers.push(header);
    codes::CURLE_OK
}

/// Opens `--etag-save`'s output file in append mode (C `etag_store`). `-`
/// targets stdout; a file that cannot be created warns, sets `*skip`, and
/// returns [`codes::CURLE_OK`] so the run continues with the transfer skipped.
fn etag_store(
    global: &mut GlobalConfig,
    config_idx: usize,
    etag_save: &mut OutStruct,
    skip: &mut bool,
) -> CurlCode {
    let path = match global.operations[config_idx].etag_save_file.clone() {
        Some(p) => p,
        None => return codes::CURLE_OK,
    };

    if global.operations[config_idx].create_dirs {
        let r = create_dir_hierarchy(global, &path);
        if r != codes::CURLE_OK {
            return r;
        }
    }

    if path != "-" {
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                etag_save.filename = Some(path.clone());
                etag_save.regular_file = true;
                etag_save.fopened = true;
                etag_save.stream = Some(file);
            }
            Err(_) => {
                warnf!(
                    global,
                    "Failed creating file for saving etags: \"{path}\". Skip this transfer"
                );
                *skip = true;
            }
        }
    }
    // `-`: write etags to stdout (`etag_save.stream` stays `None`).
    codes::CURLE_OK
}

/// Appends the `-G`/`--url-query` fields `q` to `per.url` using the libcurl URL
/// API with `CURLU_APPENDQUERY` (C `append2query`). A parse failure emits a
/// synthetic-error diagnostic and marks `config.synthetic_error` so the result
/// is not double-reported.
fn append2query(
    global: &mut GlobalConfig,
    config_idx: usize,
    per: &mut PerTransfer,
    q: &str,
) -> CurlCode {
    use curl_rs_lib::url::{CurlUPart, CURLU_APPENDQUERY, CURLU_GUESS_SCHEME};

    let mut uh = curl_rs_lib::Url::new();
    let url = per.url.clone().unwrap_or_default();
    match uh.set(CurlUPart::Url, Some(&url), CURLU_GUESS_SCHEME) {
        Err(e) => {
            let result = urlerr_cvt(e as i32);
            errorf!(
                global,
                "({result}) Could not parse the URL, failed to set query"
            );
            global.operations[config_idx].synthetic_error = true;
            result
        }
        Ok(()) => {
            let updated = uh
                .set(CurlUPart::Query, Some(q), CURLU_APPENDQUERY)
                .and_then(|()| uh.get(CurlUPart::Url, CURLU_GUESS_SCHEME));
            match updated {
                Ok(new_url) => {
                    per.url = Some(new_url);
                    codes::CURLE_OK
                }
                Err(e) => urlerr_cvt(e as i32),
            }
        }
    }
}

/// Warns when a stdin upload is combined with multiple auth types or
/// `--proxy-anyauth` (C `check_stdin_upload`): such combinations risk failing
/// because the body cannot be replayed. The platform-specific binary-mode and
/// non-blocking-`.`-stdin handling are no-ops here — a stdin upload reads fd 0
/// directly (`per.infile` stays `None`).
fn check_stdin_upload(global: &GlobalConfig, per: &PerTransfer) {
    let config = &global.operations[per.config_idx];
    let authbits = config.authtype.count_ones();
    if config.proxyanyauth || authbits > 1 {
        warnf!(
            global,
            "Using --anyauth or --proxy-anyauth with upload from stdin involves \
             a big risk of it not working. Use a temporary file or a fixed auth \
             type instead"
        );
    }
}

// ===========================================================================
// Transfer loops — serial & parallel drive (C `serial_transfers`,
// `parallel_transfers`, `add_parallel_transfers`, `check_finished`,
// `run_all_transfers`, `pre_transfer`)
// ===========================================================================

/// The shared state threaded through the parallel drive, mirroring C's
/// `struct parastate` (`src/tool_operate.c`). The multi handle, the global
/// config, and the share handle are passed alongside rather than stored here so
/// the borrow checker can see them as independent objects.
struct ParaState {
    /// Number of easy handles still transferring as last reported by
    /// `curl_multi_perform` (`parastate.still_running`).
    still_running: bool,
    /// `true` while there are operations not yet added to the multi handle
    /// (`parastate.more_transfers`).
    more_transfers: bool,
    /// `true` when the most recent [`add_parallel_transfers`](Driver::add_parallel_transfers)
    /// queued at least one handle (`parastate.added_transfers`).
    added_transfers: bool,
    /// Set when a critical error or `--fail-early` should wind the run down by
    /// aborting the in-flight transfers (`parastate.wrapitup`).
    wrapitup: bool,
    /// `true` once the abort flags have been propagated to the added transfers
    /// (`parastate.wrapitup_processed`).
    wrapitup_processed: bool,
    /// Coarse one-second tick used to throttle re-adding delayed transfers when
    /// nothing completed in a loop iteration (`parastate.tick`, a `time_t`).
    tick: i64,
    /// The first transfer error seen, returned as the run's result
    /// (`parastate.result`).
    result: CurlCode,
    /// The last multi-handle error, if any (`parastate.mcode`).
    mcode: CurlMError,
    /// When the parallel run began, for the progress meter (`parastate.start`).
    start: Instant,
}

/// Opens the upload source and programs the upload size before a transfer runs
/// (C `pre_transfer`, `src/tool_operate.c`).
///
/// For a real file (not stdin `-`/`.`) the file is opened read-only and, when it
/// is a regular file, its size is fed to libcurl via `CURLOPT_INFILESIZE_LARGE`
/// so chunked encoding can be avoided. Replaces curl's `per->infd`/`infdopen`
/// with an [`Option<File>`] whose [`Drop`] closes the descriptor. On open/stat
/// failure it emits curl's `cannot open '<file>'` help line and returns
/// [`codes::CURLE_READ_ERROR`].
fn pre_transfer(per: &mut PerTransfer) -> CurlCode {
    let result = codes::CURLE_OK;
    let mut uploadfilesize: i64 = -1;

    if let Some(uploadfile) = per.uploadfile.clone() {
        if !stdin_upload(&uploadfile) {
            match OpenOptions::new().read(true).open(&uploadfile) {
                Ok(file) => {
                    // We ignore the size for char/block devices, sockets, etc.;
                    // only regular files have a meaningful upload size
                    // (curl's `S_ISREG` gate).
                    if let Ok(meta) = file.metadata() {
                        if meta.is_file() {
                            uploadfilesize = meta.len() as i64;
                        }
                    }
                    per.infile = Some(file);
                }
                Err(_) => {
                    helpf!("cannot open '{uploadfile}'");
                    return codes::CURLE_READ_ERROR;
                }
            }
            if uploadfilesize != -1 {
                if let Err(e) = per.easy.setopt(
                    CurlOption::CURLOPT_INFILESIZE_LARGE,
                    OptionValue::OffT(uploadfilesize),
                ) {
                    return e.code();
                }
            }
        }
    }
    per.uploadfilesize = uploadfilesize;
    per.start = Instant::now();
    result
}

// ===========================================================================
// CLI transfer-I/O bridge — the Rust-native `WriteCallbacks` / `ReadCallback`
// adapters that route a `curl_rs_lib::Easy::perform_with` transfer through the
// CLI's `write_cb` / `tool_read_cb` handlers (`src/tool_cb_wrt.c` /
// `src/tool_cb_rea.c`), and thus to `-o` / `-T` files — and the default
// stdout / stdin — WITHOUT `unsafe`.
//
// This is the transfer-execution integration the callback layer
// (`crate::callbacks`) was authored ahead of (AAP §0.8.4 steps 11–13). Because
// this crate is `#![forbid(unsafe_code)]`, the CLI cannot register the C-ABI
// `CURLOPT_*FUNCTION` halves — storing and invoking a raw function-pointer
// address needs `unsafe`, which only the FFI crate (`curl-rs-ffi`,
// `CWriteBridge`/`CReadBridge`) is allowed to do. The CLI instead supplies
// these Rust-native sinks, which the core invokes by safe trait dispatch.
// ===========================================================================

/// Transfer state shared between the write sink and the read source for the
/// duration of one [`Easy::perform_with`](curl_rs_lib::Easy::perform_with).
///
/// Both directions need `&mut PerTransfer` (its `outs` body sink, `infile`
/// upload source, and upload counters) and `&mut GlobalConfig` (the per-operation
/// flags, the busy-read coordination flag, and warning output). The transfer
/// engine invokes the sink and the source **sequentially on the one
/// current-thread runtime** — never concurrently — so the [`Mutex`] is always
/// uncontended. It exists solely to satisfy the [`Send`] bound the callback
/// traits carry (a `RefCell` would be `!Send` and a bare split borrow cannot be
/// shared by two trait objects); it never arbitrates real contention.
struct CliIoState<'a> {
    per: &'a mut PerTransfer,
    global: &'a mut GlobalConfig,
}

/// The CLI body/header write sink — curl's `CURLOPT_WRITEFUNCTION` /
/// `CURLOPT_HEADERFUNCTION` destination, expressed as the core's
/// [`WriteCallbacks`](curl_rs_lib::transfer::WriteCallbacks) trait.
struct CliWriteSink<'a> {
    state: &'a Mutex<CliIoState<'a>>,
}

impl WriteCallbacks for CliWriteSink<'_> {
    fn write_body(&mut self, data: &[u8]) -> usize {
        // Sequential, uncontended lock (see `CliIoState`). `write_cb` is the
        // Rust port of curl's `tool_write_cb`: it lazily opens the `-o` file (or
        // writes stdout when none is set), enforces the write-size / binary-to-tty
        // guards, accounts the bytes, and returns curl's byte-count /
        // `CURL_WRITEFUNC_*` convention verbatim — which is exactly what the
        // engine's client-writer expects from `write_body`.
        let mut st = self.state.lock().expect("CLI I/O bridge mutex poisoned");
        let CliIoState { per, global } = &mut *st;
        crate::callbacks::write::write_cb(data, per, global)
    }

    fn write_header(&mut self, data: &[u8]) -> Option<usize> {
        // curl registers `tool_header_cb` as `CURLOPT_HEADERFUNCTION`
        // unconditionally (`config2setopts.c`'s `gen_cb_setopts`). It writes the
        // `-D`/`--dump-header` file, honors `-J`/`--remote-header-name` and
        // `--etag-save`, counts `%{num_headers}`, and echoes the response header
        // block onto the body stream for `-i`/`--include`. The getinfo-dependent
        // paths (`-J`/etag/`-i`) read the in-flight handle's response code and
        // scheme; during `perform_with_cli_io` the real handle is moved out, so
        // those paths read the default placeholder and gracefully no-op when
        // their flags are unset — leaving the plain `-D` dump (the common case),
        // which needs only `config.headerfile` and the pre-opened
        // `per.heads.stream`, fully functional. Returning `Some(n)` reports the
        // bytes consumed (curl's `CURLOPT_HEADERFUNCTION` byte-count contract),
        // replacing the previous NULL-callback stand-in.
        let mut st = self.state.lock().expect("CLI I/O bridge mutex poisoned");
        let CliIoState { per, global } = &mut *st;
        Some(crate::callbacks::header::tool_header_cb(data, per, global))
    }

    fn debug(&mut self, infotype: DebugInfoType, data: &[u8]) {
        // CURLOPT_DEBUGFUNCTION: route the engine's trace events to curl's
        // `tool_debug_cb`, which renders the `-v` plain trace (the `* `/`> `/`< `
        // line prefixes) or the `--trace`/`--trace-ascii` hex/ascii dump to the
        // resolved trace stream (stderr by default, stdout for `--trace -`, or the
        // named file). The core's `DebugInfoType` shares curl's `curl_infotype`
        // integer values, so the CLI enum is recovered directly from the raw id.
        let Some(it) = CurlInfoType::from_raw(infotype.as_raw()) else {
            return;
        };
        let mut st = self.state.lock().expect("CLI I/O bridge mutex poisoned");
        let CliIoState { global, .. } = &mut *st;
        // The easy handle is moved out for the duration of `perform_with_cli_io`;
        // `tool_debug_cb` consults it only for the `--trace-ids` xfer/conn ids,
        // which degrade to an empty prefix when the handle is absent — so passing
        // `None` is correct and never suppresses the trace itself.
        let _ = crate::callbacks::debug::tool_debug_cb(None, it, data, global);
    }

    fn progress(&mut self, dltotal: i64, dlnow: i64, ultotal: i64, ulnow: i64) -> i32 {
        // Progress dispatch mirrors curl's `gen_cb_setopts` gating
        // (`config2setopts.c`): the `-#` bar is installed only when
        // `progressmode == CURL_PROGRESS_BAR` and progress is not suppressed,
        // while `NOPROGRESS = noprogress || silent` hides progress entirely.
        //   * suppressed (`-s` / `--no-progress-meter`) → return `0`: draw nothing
        //     and tell the engine to suppress its built-in meter too;
        //   * `-#` bar mode → draw the bar via `tool_progress_cb` and return `0`
        //     so the engine suppresses its built-in meter;
        //   * otherwise → return `CURL_PROGRESSFUNC_CONTINUE` so the engine renders
        //     its built-in meter (curl's default `% Total …` display).
        let mut st = self.state.lock().expect("CLI I/O bridge mutex poisoned");
        let CliIoState { per, global } = &mut *st;
        if global.silent || global.noprogress {
            return 0;
        }
        if global.progressmode == CURL_PROGRESS_BAR {
            let config = &mut global.operations[per.config_idx];
            crate::callbacks::progress::tool_progress_cb(
                per, config, dltotal, dlnow, ultotal, ulnow,
            );
            return 0;
        }
        CURL_PROGRESSFUNC_CONTINUE
    }

    fn write_diag(&mut self, bytes: &[u8]) {
        // The engine renders its built-in progress meter (and the trailing
        // newline) and hands the bytes here. Route them through the diagnostic
        // sink so a `--stderr <file>` redirection is honored — curl writes the
        // meter to `tool_stderr`, which `--stderr` retargets.
        crate::messages::emit_raw(bytes);
    }
}

/// The CLI upload read source — curl's `CURLOPT_READFUNCTION`, expressed as the
/// core's [`ReadCallback`](curl_rs_lib::transfer::ReadCallback) trait.
struct CliReadSource<'a> {
    state: &'a Mutex<CliIoState<'a>>,
}

impl ReadCallback for CliReadSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        // Sequential, uncontended lock (see `CliIoState`). `tool_read_cb` is the
        // Rust port of curl's `tool_read_cb`: it pulls upload bytes from the `-T`
        // file (`per.infile`) — or stdin when none is open — honoring the timeout
        // throttle and the `CURLOPT_INFILESIZE` cap, and yields curl's byte-count
        // / `CURL_READFUNC_*` convention through `ReadResult::to_curl_return`,
        // which is the contract `read` returns to the engine.
        let mut st = self.state.lock().expect("CLI I/O bridge mutex poisoned");
        let CliIoState { per, global } = &mut *st;
        crate::callbacks::read::tool_read_cb(buf, per, global).to_curl_return()
    }
}

/// Drive one transfer through [`Easy::perform_with`](curl_rs_lib::Easy::perform_with),
/// bridging body output and upload input to the CLI callbacks so `-o` / `-T`
/// files (and the default stdout / stdin) are honored.
///
/// This replaces a bare [`Easy::perform`](curl_rs_lib::Easy::perform), whose
/// built-in sink/source are hardwired to stdout/stdin and therefore bypass the
/// CLI's `-o` output file and `-T` upload file. It is the seam curl's
/// `tool_operate.c` reaches implicitly when libcurl invokes the registered
/// `CURLOPT_WRITEFUNCTION` / `CURLOPT_READFUNCTION`.
///
/// # Handle / borrow handling
///
/// The real [`Easy`] handle is moved out of `per` (leaving a default
/// placeholder) so it can drive `perform_with` while the sink/source hold the
/// rest of `per` — and `global` — through the shared [`CliIoState`]. The
/// placeholder left in `per.easy` is touched only by `write_cb`'s busy-read
/// unpause (`Easy::pause`), which is inert here: a blocking file / stdin read
/// never reports `EAGAIN`, so the busy flag is never set and that branch never
/// runs. The real handle — carrying every `info` / `state` field the transfer
/// updated — is restored into `per.easy` before this returns, so the subsequent
/// `post_per_transfer` `getinfo` reads observe the true transfer result.
async fn perform_with_cli_io(
    per: &mut PerTransfer,
    global: &mut GlobalConfig,
) -> Result<(), CurlError> {
    // Move the real handle out (leaving `Easy::default()`) so `perform_with`
    // borrows it disjointly from the `per` the bridge holds. `Easy` has no custom
    // `Drop`, so dropping the placeholder on restore is a benign field-wise drop.
    let mut easy = std::mem::take(&mut per.easy);
    let result = {
        let state = Mutex::new(CliIoState {
            per: &mut *per,
            global: &mut *global,
        });
        let mut sink = CliWriteSink { state: &state };
        let mut source = CliReadSource { state: &state };
        easy.perform_with(&mut sink, &mut source).await
        // `sink`, `source`, and `state` drop here, releasing the `per` / `global`
        // reborrows before the handle is restored below.
    };
    // Restore the real handle for `post_per_transfer` (getinfo / cleanup).
    per.easy = easy;
    result
}

impl Driver {
    /// Runs every queued transfer one at a time (C `serial_transfers`).
    ///
    /// Each iteration runs [`pre_transfer`], drives the async
    /// [`Easy::perform`](curl_rs_lib::Easy::perform) to completion on the
    /// binary's current-thread runtime, then runs [`post_per_transfer`] — which
    /// decides retries, `--write-out`, and the final exit code. `--retry`
    /// re-runs the same front transfer after a back-off sleep; `--fail-early`
    /// and fatal errors bail out; `--rate` paces successive transfers. New
    /// transfers (e.g. the next URL of a glob set) are created just before the
    /// current one is dropped, preserving curl's iteration order.
    async fn serial_transfers(&mut self, global: &mut GlobalConfig, share: &Share) -> CurlCode {
        let mut returncode = codes::CURLE_OK;
        let mut result;
        let mut added = false;
        let mut skipped = false;

        result = self.create_transfer(global, share, &mut added, &mut skipped);
        if result != codes::CURLE_OK {
            return result;
        }
        if !added {
            crate::errorf!(global, "no transfer performed");
            return codes::CURLE_READ_ERROR;
        }

        while !self.transfers.is_empty() {
            let mut bailout = false;
            let start = Instant::now();
            result = codes::CURLE_OK;

            let skip = self.transfers.front().map(|p| p.skip).unwrap_or(true);
            if !skip {
                result = pre_transfer(self.transfers.front_mut().unwrap());
                if result != codes::CURLE_OK {
                    // curl `break`s the loop here, leaving the current transfer
                    // queued; `returncode` keeps its prior value.
                    break;
                }
                // Drive the async core to completion (curl `curl_easy_perform`),
                // routing body output and upload input through the CLI callbacks
                // (`-o` / `-T` files, default stdout / stdin) via the Rust-native
                // I/O bridge rather than the core's stdout/stdin defaults.
                let perform = {
                    let per = self.transfers.front_mut().unwrap();
                    perform_with_cli_io(per, global).await
                };
                result = match perform {
                    Ok(()) => codes::CURLE_OK,
                    Err(e) => e.code(),
                };
            }

            let (rc, retry, delay_ms) =
                post_per_transfer(global, self.transfers.front_mut().unwrap(), result);
            returncode = rc;

            if retry {
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms as u64)).await;
                }
                continue; // reprocess the same (front) transfer
            }

            // Bail out upon critical errors or --fail-early.
            if is_fatal_error(returncode) || (returncode != codes::CURLE_OK && global.fail_early) {
                bailout = true;
            } else {
                loop {
                    // Set up the next transfer just before deleting this one.
                    result = self.create_transfer(global, share, &mut added, &mut skipped);
                    if result != codes::CURLE_OK {
                        returncode = result;
                        bailout = true;
                        break;
                    }
                    if !skipped {
                        break;
                    }
                }
            }

            self.transfers.pop_front(); // del_per_transfer

            if bailout {
                break;
            }

            // --rate: pace transfers so each takes at least ms_per_transfer.
            if !self.transfers.is_empty() && global.ms_per_transfer > 0 {
                let milli = start.elapsed().as_millis() as i64;
                if milli < global.ms_per_transfer {
                    let wait = global.ms_per_transfer - milli;
                    crate::notef!(
                        global,
                        "Transfer took {milli} ms, waits {wait}ms as set by --rate"
                    );
                    tokio::time::sleep(Duration::from_millis(wait as u64)).await;
                }
            }
        }

        if returncode != codes::CURLE_OK {
            // returncode errors have priority over a late create_transfer error.
            result = returncode;
        }
        if result != codes::CURLE_OK {
            single_transfer_cleanup(global);
        }
        result
    }

    /// Drives all transfers and drains any that remain (C `run_all_transfers`).
    ///
    /// Saves and restores `global.noprogress`/`global.isatty` (which the
    /// per-URL setup may have toggled for a TTY), dispatches to the serial or
    /// parallel loop, then runs [`post_per_transfer`] over any transfers left
    /// queued (e.g. after an early bail-out) so their outputs and `--write-out`
    /// data are finalized and the original error is preserved.
    async fn run_all_transfers(
        &mut self,
        global: &mut GlobalConfig,
        share: &Share,
        mut result: CurlCode,
    ) -> CurlCode {
        let orig_noprogress = global.noprogress;
        let orig_isatty = global.isatty;

        if result == codes::CURLE_OK {
            result = if global.parallel {
                self.parallel_transfers(global, share).await
            } else {
                self.serial_transfers(global, share).await
            };
        }

        // Clean up any transfers still queued (drained without running).
        while let Some(mut per) = self.transfers.pop_front() {
            let (result2, _retry, _delay) = post_per_transfer(global, &mut per, result);
            if result == codes::CURLE_OK {
                // Do not overwrite the original error.
                result = result2;
            }
            // Free the list of URLs for this operation (C `clean_getout`).
            global.operations[per.config_idx].clean_getout();
        }

        global.noprogress = orig_noprogress;
        global.isatty = orig_isatty;
        result
    }
}

impl Driver {
    /// Runs transfers concurrently over a [`Multi`] handle (C
    /// `parallel_transfers`).
    ///
    /// Preserves curl's `curl_multi_*` drive semantics (AAP §0.7.4): the loop
    /// polls (`curl_multi_poll`), performs (`curl_multi_perform`), drains
    /// finished handles, and refreshes the aggregate progress meter until no
    /// handles are running and no operations remain to add. Instead of curl's
    /// `CURLMNOTIFY_INFO_READ` callback, finished handles are drained directly
    /// via [`check_finished`](Driver::check_finished) after each `perform` —
    /// functionally equivalent and free of callback plumbing. `--fail-early`
    /// signals the in-flight transfers to abort. A multi-level
    /// `CURLM_OUT_OF_MEMORY` maps to [`codes::CURLE_OUT_OF_MEMORY`]; any other
    /// multi error maps to [`codes::CURLE_BAD_FUNCTION_ARGUMENT`].
    async fn parallel_transfers(&mut self, global: &mut GlobalConfig, share: &Share) -> CurlCode {
        let mut multi = Multi::new();
        let mut s = ParaState {
            still_running: true,
            more_transfers: false,
            added_transfers: false,
            wrapitup: false,
            wrapitup_processed: false,
            tick: now_epoch_secs(),
            result: codes::CURLE_OK,
            mcode: CurlMError::Ok,
            start: Instant::now(),
        };

        // The C tool installs a NOTIFYFUNCTION here; we instead drain finished
        // handles inline (see check_finished), so no callback registration is
        // needed.

        let result = self.add_parallel_transfers(
            global,
            share,
            &mut multi,
            &mut s.more_transfers,
            &mut s.added_transfers,
        );
        if result != codes::CURLE_OK {
            // `multi` is dropped here (curl_multi_cleanup).
            return result;
        }

        if self.all_added > 0 {
            while s.mcode == CurlMError::Ok && (s.still_running || s.more_transfers) {
                // If stopping prematurely (e.g. a --fail-early condition) then
                // signal that any added transfers should abort.
                if s.wrapitup {
                    if !s.still_running {
                        break;
                    }
                    if !s.wrapitup_processed {
                        for per in self.transfers.iter_mut() {
                            if per.added {
                                per.abort = true;
                            }
                        }
                        s.wrapitup_processed = true;
                    }
                }

                let (pcode, _running_after_poll) = multi.poll(&mut [], 1000);
                s.mcode = pcode;
                if s.mcode == CurlMError::Ok {
                    let (pcode2, running) = multi.perform();
                    s.mcode = pcode2;
                    s.still_running = running > 0;
                }

                // Drain finished handles (replaces the mnotify callback).
                let cres = self.check_finished(global, share, &mut multi, &mut s);
                if cres != codes::CURLE_OK && s.result == codes::CURLE_OK {
                    s.result = cres;
                }

                self.progress_meter(global, &multi, s.start, false);
            }

            self.progress_meter(global, &multi, s.start, true);
        }

        // Result is the first failed transfer, if there was one.
        let mut result = s.result;

        // Surface a multi-handle problem as a generic error.
        if s.mcode != CurlMError::Ok {
            result = if s.mcode == CurlMError::OutOfMemory {
                codes::CURLE_OUT_OF_MEMORY
            } else {
                codes::CURLE_BAD_FUNCTION_ARGUMENT
            };
        }

        // `multi` drops here (curl_multi_cleanup).
        result
    }

    /// Adds queued transfers to the multi handle up to `parallel_max` (C
    /// `add_parallel_transfers`).
    ///
    /// Tops up the transfer queue (so up to `parallel_max * 2` are staged),
    /// then for each not-yet-added, non-skipped, non-sleeping transfer runs
    /// [`pre_transfer`], sets the parallel-mode easy options best-effort, and
    /// hands the easy handle to the [`Multi`] as a [`SharedEasy`] (keeping a
    /// clone for completion matching). `morep` reports whether work remains
    /// (more queued transfers or sleeping retries); `addedp` reports whether
    /// anything was added this call.
    fn add_parallel_transfers(
        &mut self,
        global: &mut GlobalConfig,
        share: &Share,
        multi: &mut Multi,
        morep: &mut bool,
        addedp: &mut bool,
    ) -> CurlCode {
        let mut sleeping = false;

        *addedp = false;
        *morep = false;

        let nxfers = match multi.get_offt(CurlMInfo::XfersCurrent) {
            Ok(n) => n,
            Err(_) => return codes::CURLE_UNKNOWN_OPTION,
        };

        if nxfers < i64::from(global.parallel_max) * 2 {
            loop {
                let mut skipped = false;
                let r = self.create_transfer(global, share, addedp, &mut skipped);
                if r != codes::CURLE_OK {
                    return r;
                }
                if !skipped {
                    break;
                }
            }
        }

        let mut i = 0;
        while i < self.transfers.len() {
            if self.all_added >= i64::from(global.parallel_max) {
                // curl's loop condition fails with `per` non-NULL: more remain.
                break;
            }
            if self.transfers[i].added || self.transfers[i].skip {
                // Already added or to be skipped.
                i += 1;
                continue;
            }
            if self.transfers[i].startat != 0 && now_epoch_secs() < self.transfers[i].startat {
                // This retry is still delaying.
                sleeping = true;
                i += 1;
                continue;
            }
            self.transfers[i].added = true;

            let r = pre_transfer(&mut self.transfers[i]);
            if r != codes::CURLE_OK {
                return r;
            }

            // Parallel connect means we do NOT set PIPEWAIT, since pipewait
            // makes libcurl prefer multiplexing. These are programmed
            // best-effort (curl casts the results to void).
            let pipewait = if global.parallel_connect { 0 } else { 1 };
            let _ = self.transfers[i]
                .easy
                .setopt(CurlOption::CURLOPT_PIPEWAIT, OptionValue::Long(pipewait));
            let _ = self.transfers[i]
                .easy
                .setopt(CurlOption::CURLOPT_NOSIGNAL, OptionValue::Long(1));
            let _ = self.transfers[i]
                .easy
                .setopt(CurlOption::CURLOPT_NOPROGRESS, OptionValue::Long(0));
            // curl also sets CURLOPT_PRIVATE (the per pointer), the
            // XFERINFOFUNCTION/DATA pair (per-transfer progress feeding the
            // aggregate bar), and CURLOPT_ERRORBUFFER here. Completion matching
            // is done via the SharedEasy `Arc` instead of PRIVATE; the error
            // buffer address was already programmed by `config2setopts`; and the
            // per-transfer progress callback is wired once the protocol engine
            // emits progress (today the stub reports none, so the aggregate bar
            // renders zero-progress lines exactly as a finished run would).

            // Hand the easy handle to the multi as a shared wrapper, keeping a
            // clone so the finished message can be matched back via Arc::ptr_eq.
            let easy = std::mem::take(&mut self.transfers[i].easy);
            let sh = multi::shared_easy(easy);
            let mcode = multi.add_handle(sh.clone());
            self.transfers[i].shared = Some(sh);
            // The only expected failure here is out-of-memory.
            let mut result = if mcode != CurlMError::Ok {
                codes::CURLE_OUT_OF_MEMORY
            } else {
                codes::CURLE_OK
            };

            if result == codes::CURLE_OK {
                loop {
                    let mut getadded = false;
                    let mut skipped = false;
                    result = self.create_transfer(global, share, &mut getadded, &mut skipped);
                    if result != codes::CURLE_OK {
                        break;
                    }
                    if !skipped {
                        break;
                    }
                }
            }
            if result != codes::CURLE_OK {
                return result;
            }

            self.transfers[i].errorbuffer.clear();
            self.transfers[i].sp.errorbuffer[0] = 0;
            self.transfers[i].added = true;
            self.all_added += 1;
            *addedp = true;
            i += 1;
        }

        // `per || sleeping`: a remaining un-added transfer or a delayed retry.
        *morep = i < self.transfers.len() || sleeping;
        codes::CURLE_OK
    }

    /// Reads finished handles from the multi and finalizes them (C
    /// `check_finished`, normally invoked from the `CURLMNOTIFY_INFO_READ`
    /// callback; here called directly after each `perform`).
    ///
    /// For each completed handle it matches the owning [`PerTransfer`] via
    /// [`Arc::ptr_eq`], removes it from the multi, restores the [`Easy`] from
    /// its [`SharedEasy`] wrapper, runs [`post_per_transfer`], folds its byte
    /// counts into the aggregate ([`progress_finalize`](Driver::progress_finalize)),
    /// and either re-queues it for retry or deletes it. After draining, it tops
    /// up the queue with [`add_parallel_transfers`](Driver::add_parallel_transfers)
    /// and sets `wrapitup` on a fatal/`--fail-early` condition. Returns the
    /// first transfer error seen during this drain.
    fn check_finished(
        &mut self,
        global: &mut GlobalConfig,
        share: &Share,
        multi: &mut Multi,
        s: &mut ParaState,
    ) -> CurlCode {
        let mut result = codes::CURLE_OK;
        let mut checkmore = false;

        while let Some(msg) = multi.info_read() {
            let result_code = msg.result_code();
            // Match the finished easy handle back to its PerTransfer.
            let idx = self.transfers.iter().position(|p| {
                p.shared
                    .as_ref()
                    .is_some_and(|sh| Arc::ptr_eq(sh, &msg.easy_handle))
            });
            multi.remove_handle(&msg.easy_handle);

            let Some(i) = idx else {
                // No matching transfer (should not happen) — discard.
                drop(msg);
                continue;
            };

            let mut tres = result_code;
            if self.transfers[i].abort && tres == codes::CURLE_ABORTED_BY_CALLBACK {
                self.transfers[i].errorbuffer =
                    "Transfer aborted due to critical error in another transfer".to_string();
            }

            // Restore the Easy from the shared wrapper so post_per_transfer can
            // read its info. Drop the message's Arc clone first so try_unwrap
            // can reclaim sole ownership.
            let shared = self.transfers[i].shared.take();
            drop(msg);
            if let Some(sh) = shared {
                if let Ok(mutex) = Arc::try_unwrap(sh) {
                    self.transfers[i].easy = mutex.into_inner();
                }
                // If other references survive (unexpected), the handle keeps its
                // default value — post_per_transfer degrades gracefully.
            }

            let (rc, retry, delay) = post_per_transfer(global, &mut self.transfers[i], tres);
            tres = rc;
            self.progress_finalize(i); // fold byte counts before it goes away
            self.all_added -= 1;
            checkmore = true;

            if retry {
                self.transfers[i].added = false; // add it again
                                                 // We delay retries in whole integer seconds only.
                self.transfers[i].startat = if delay > 0 {
                    now_epoch_secs() + delay / 1000
                } else {
                    0
                };
            } else {
                let abort = self.transfers[i].abort;
                // result receives this transfer's error unless it was aborted
                // due to a critical error in another transfer.
                if tres != codes::CURLE_OK && (!abort || result == codes::CURLE_OK) {
                    result = tres;
                }
                if is_fatal_error(result) || (result != codes::CURLE_OK && global.fail_early) {
                    s.wrapitup = true;
                }
                self.transfers.remove(i); // del_per_transfer
            }
        }

        if !s.wrapitup {
            if !checkmore {
                let tock = now_epoch_secs();
                if s.tick != tock {
                    checkmore = true;
                    s.tick = tock;
                }
            }
            if checkmore {
                // One or more transfers completed (or a second elapsed): add more.
                let tres = self.add_parallel_transfers(
                    global,
                    share,
                    multi,
                    &mut s.more_transfers,
                    &mut s.added_transfers,
                );
                if tres != codes::CURLE_OK {
                    result = tres;
                }
                if s.added_transfers {
                    // We added new ones; do not let the loop exit yet.
                    s.still_running = true;
                }
            }
            if is_fatal_error(result) || (result != codes::CURLE_OK && global.fail_early) {
                s.wrapitup = true;
            }
        }
        result
    }

    /// Folds a finished transfer's byte counts into the cross-transfer
    /// aggregate before it is removed (C `progress_finalize`,
    /// `src/tool_progress.c`). Each transfer's totals are added at most once.
    fn progress_finalize(&mut self, i: usize) {
        self.all_dlalready += self.transfers[i].dlnow;
        self.all_ulalready += self.transfers[i].ulnow;
        if !self.transfers[i].dltotal_added {
            self.all_dltotal += self.transfers[i].dltotal;
            self.transfers[i].dltotal_added = true;
        }
        if !self.transfers[i].ultotal_added {
            self.all_ultotal += self.transfers[i].ultotal;
            self.transfers[i].ultotal_added = true;
        }
    }
}

// ===========================================================================
// Aggregate progress meter (C `progress_meter`, `src/tool_progress.c`)
// ===========================================================================

impl Driver {
    /// Renders the parallel aggregate progress bar to stderr (C
    /// `progress_meter`). Returns `true` when a line was drawn.
    ///
    /// Suppressed entirely under `--silent`/`-s` or when progress is disabled.
    /// The header is printed once; thereafter a status line is redrawn at most
    /// every 500 ms (or unconditionally when `final_` is set). The line shows
    /// download/upload percentages, transferred byte counts (via
    /// [`max5data`]), the number of added/running handles, elapsed/estimated/
    /// remaining times (via [`time2str`]), and a moving-average speed computed
    /// from the [`speedstore`](Self::speedstore) ring.
    ///
    /// Note: the per-transfer byte counts this aggregates are populated by the
    /// protocol engine's progress callback; until that engine is wired the
    /// counts are zero, so the bar renders a valid all-zero line — exactly as a
    /// completed run with no progress reported would.
    fn progress_meter(
        &mut self,
        global: &GlobalConfig,
        multi: &Multi,
        start: Instant,
        final_: bool,
    ) -> bool {
        if global.noprogress || global.silent {
            return false;
        }

        let now = Instant::now();
        let diff = self
            .progress_stamp
            .map_or(i64::MAX, |st| now.duration_since(st).as_millis() as i64);

        if !self.progress_header {
            self.progress_header = true;
            eprintln!("DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed");
        }

        if !final_ && diff <= 500 {
            return false;
        }

        self.progress_stamp = Some(now);
        let spent = (now.duration_since(start).as_millis() as i64) / 1000;

        // First add the amounts of the already-completed transfers.
        let mut all_dlnow = self.all_dlalready;
        let mut all_ulnow = self.all_ulalready;
        let mut dlknown = true;
        let mut ulknown = true;

        let n = self.transfers.len();
        for i in 0..n {
            all_dlnow += self.transfers[i].dlnow;
            all_ulnow += self.transfers[i].ulnow;
            if self.transfers[i].dltotal == 0 {
                dlknown = false;
            } else if !self.transfers[i].dltotal_added {
                self.all_dltotal += self.transfers[i].dltotal;
                self.transfers[i].dltotal_added = true;
            }
            if self.transfers[i].ultotal == 0 {
                ulknown = false;
            } else if !self.transfers[i].ultotal_added {
                self.all_ultotal += self.transfers[i].ultotal;
                self.transfers[i].ultotal_added = true;
            }
        }

        let dlpercen = if dlknown && self.all_dltotal != 0 {
            let p = if all_dlnow < i64::MAX / 100 {
                all_dlnow * 100 / self.all_dltotal
            } else {
                all_dlnow / (self.all_dltotal / 100)
            };
            format!("{p}")
        } else {
            "--".to_string()
        };
        let ulpercen = if ulknown && self.all_ultotal != 0 {
            let p = if all_ulnow < i64::MAX / 100 {
                all_ulnow * 100 / self.all_ultotal
            } else {
                all_ulnow / (self.all_ultotal / 100)
            };
            format!("{p}")
        } else {
            "--".to_string()
        };

        // Record this sample and compute the higher of the two speeds.
        let idx = self.speedindex;
        self.speedstore[idx].dl = all_dlnow;
        self.speedstore[idx].ul = all_ulnow;
        self.speedstore[idx].stamp = now;
        self.speedindex += 1;
        if self.speedindex >= SPEEDCNT {
            self.indexwrapped = true;
            self.speedindex = 0;
        }

        let (mut deltams, dl, ul) = if self.indexwrapped {
            // speedindex now points at the oldest stored sample.
            let old = self.speedstore[self.speedindex];
            (
                now.duration_since(old.stamp).as_millis() as i64,
                all_dlnow - old.dl,
                all_ulnow - old.ul,
            )
        } else {
            (
                now.duration_since(start).as_millis() as i64,
                all_dlnow,
                all_ulnow,
            )
        };
        if deltams == 0 {
            deltams += 1; // no division by zero
        }
        let dls = (dl as f64 / (deltams as f64 / 1000.0)) as i64;
        let uls = (ul as f64 / (deltams as f64 / 1000.0)) as i64;
        let speed = dls.max(uls);

        let (time_left, time_total) = if dlknown && speed != 0 {
            let est = self.all_dltotal / speed;
            let left = (self.all_dltotal - all_dlnow) / speed;
            (time2str(left), time2str(est))
        } else {
            (time2str(0), time2str(0))
        };
        let time_spent = time2str(spent);

        let xfers_added = multi.get_offt(CurlMInfo::XfersAdded).unwrap_or(0);
        let xfers_running = multi.get_offt(CurlMInfo::XfersRunning).unwrap_or(0);

        let line = format!(
            "\r{:<3} {:<3} {} {} {:5} {:5}  {} {} {} {} {:>5}",
            dlpercen,
            ulpercen,
            max5data(all_dlnow),
            max5data(all_ulnow),
            xfers_added,
            xfers_running,
            time_total,
            time_spent,
            time_left,
            max5data(speed),
            if final_ { "\n" } else { "" },
        );
        eprint!("{line}");
        true
    }
}

// ===========================================================================
// Per-transfer finalization (C `post_per_transfer`, `post_check_result`,
// `post_output_handling`, `post_close_output`, `retrycheck`)
// ===========================================================================

/// The certificate-verification failure hint curl appends after a
/// `CURLE_PEER_FAILED_VERIFICATION` error (C `CURL_CA_CERT_ERRORMSG`).
const CURL_CA_CERT_ERRORMSG: &str = "More details here: https://curl.se/docs/sslcerts.html\n\n\
curl failed to verify the legitimacy of the server and therefore could not\n\
establish a secure connection to it. To learn more about this situation and\n\
how to fix it, please visit the webpage mentioned above.\n";

/// Returns the lower-cased URL scheme reported for the transfer
/// (`CURLINFO_SCHEME`), or an empty string when unavailable.
fn getinfo_scheme(per: &PerTransfer) -> String {
    match per.easy.getinfo(CurlInfo::Scheme) {
        Ok(InfoValue::Str(Some(c))) => c.to_string_lossy().to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Builds curl's exact "unsupported protocol" diagnostic for a transfer whose
/// URL scheme resolved to no compiled-in handler — the `lib/url.c`
/// `findprotocol` message `Protocol "<scheme>" not supported`.
///
/// curl emits this from the library via `failf`, so a C consumer reads it back
/// through `CURLOPT_ERRORBUFFER` and the tool prints it on both the
/// `curl: (N) ...` line and in `%{errormsg}`. The async core here is
/// `#![forbid(unsafe_code)]` and the CLI drives the library directly (not
/// through the FFI crate that owns the C error buffer), so the engine cannot
/// populate that buffer; the message is instead reconstructed at the tool layer
/// from the input URL's scheme. That scheme is curl's `protostr` — parsed from
/// the raw URL *before* the handler lookup and lower-cased exactly as the URL
/// API (and `%{url.scheme}`) reports it — so the text is byte-identical to
/// curl's. `CURLINFO_SCHEME` is deliberately **not** used: like curl, it stays
/// empty until a connection is established, so it is unavailable on this
/// pre-connection failure.
///
/// Returns [`None`] when no scheme can be recovered (e.g. no input URL or an
/// unparseable one), so the caller falls back to the static
/// [`CurlError::description`] text.
fn unsupported_protocol_message(per: &PerTransfer) -> Option<String> {
    use curl_rs_lib::url::{
        CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_GUESS_SCHEME, CURLU_NON_SUPPORT_SCHEME,
    };
    // Parse the raw input URL with the same flags curl's `%{url.scheme}` uses.
    let url = per.url.as_deref()?;
    let mut uh = CurlUrl::new();
    uh.set(
        CurlUPart::Url,
        Some(url),
        CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME,
    )
    .ok()?;
    let scheme = uh.get(CurlUPart::Scheme, CURLU_DEFAULT_PORT).ok()?;
    if scheme.is_empty() {
        return None;
    }
    Some(format!("Protocol \"{scheme}\" not supported"))
}

/// Reconstructs the host curl names in its resolver failure
/// `"Could not resolve host: <host>"` (`CURLE_COULDNT_RESOLVE_HOST`).
///
/// curl's resolver latches that exact text into `CURLOPT_ERRORBUFFER` via
/// `failf(data, "Could not resolve %s: %s", "host", conn->host.dispname)`
/// (lib/hostip.c L1586, lib/url.c L3171). The engine's errorbuffer→handle
/// bridge is the documented foundation limitation noted in
/// [`PerTransfer::error_message`] (the library's `CURLOPT_ERRORBUFFER` is a raw
/// pointer the `#![forbid(unsafe_code)]` core cannot write), so the offending
/// host is recovered here from the request URL — the same `CURLUPART_HOST` the
/// URL API (and `%{url.host}`) reports, parsed with the identical flags as
/// [`unsupported_protocol_message`] — to produce byte-identical diagnostic text.
///
/// Returns [`None`] when there is no input URL or it cannot be parsed (the
/// caller then falls back to the static [`CurlError::description`] text).
fn resolve_failure_host(per: &PerTransfer) -> Option<String> {
    use curl_rs_lib::url::{CurlUPart, CurlUrl, CURLU_GUESS_SCHEME, CURLU_NON_SUPPORT_SCHEME};
    let url = per.url.as_deref()?;
    let mut uh = CurlUrl::new();
    uh.set(
        CurlUPart::Url,
        Some(url),
        CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME,
    )
    .ok()?;
    let host = uh.get(CurlUPart::Host, 0).ok()?;
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Returns the HTTP/FTP response code reported for the transfer
/// (`CURLINFO_RESPONSE_CODE`), or `0` when unavailable.
fn getinfo_response(per: &PerTransfer) -> i64 {
    match per.easy.getinfo(CurlInfo::ResponseCode) {
        Ok(InfoValue::Long(c)) => c,
        _ => 0,
    }
}

/// Returns the effective request method (`CURLINFO_EFFECTIVE_METHOD`), or an
/// empty string when unavailable.
fn getinfo_method(per: &PerTransfer) -> String {
    match per.easy.getinfo(CurlInfo::EffectiveMethod) {
        Ok(InfoValue::Str(Some(c))) => c.to_string_lossy().into_owned(),
        _ => String::new(),
    }
}

/// Finalizes one completed transfer (C `post_per_transfer`).
///
/// Closes the upload source, runs the result/output/retry/close pipeline (when
/// the transfer was not skipped), emits `--write-out`, and closes the header and
/// etag streams. Returns the final `CURLcode` for the transfer plus whether it
/// should be retried and the back-off delay in milliseconds. No libcurl cleanup
/// is performed here — the [`PerTransfer`] is dropped by the caller, which
/// releases the easy handle, the URLs, and the header list automatically.
fn post_per_transfer(
    global: &mut GlobalConfig,
    per: &mut PerTransfer,
    mut result: CurlCode,
) -> (CurlCode, bool, i64) {
    let mut retry = false;
    let mut delay = 0i64;

    // Close the upload descriptor (drop the File; stdin uploads keep `None`).
    per.infile = None;

    if !per.skip {
        // F5-MINOR-1: reproduce curl's library `failf` text for a recognized
        // URL whose scheme has no handler. curl prints
        // `Protocol "<scheme>" not supported` (lib/url.c `findprotocol`) via
        // `CURLOPT_ERRORBUFFER`; the async core cannot write that C buffer (it
        // is `#![forbid(unsafe_code)]` and the CLI drives the library directly,
        // not through the FFI), so synthesize the identical text into the tool
        // error buffer here — before the result is reported — keeping both the
        // `curl: (N) ...` diagnostic and `%{errormsg}` in parity with curl.
        // Recognized, wired schemes never reach this branch (they no longer
        // return `CURLE_UNSUPPORTED_PROTOCOL`); only a truly-unknown scheme
        // does. The `is_empty` guard preserves any message a future engine
        // path might record, and a missing/unparseable scheme falls back to the
        // static code description.
        if result == codes::CURLE_UNSUPPORTED_PROTOCOL && per.errorbuffer.is_empty() {
            if let Some(msg) = unsupported_protocol_message(per) {
                per.errorbuffer = msg;
            }
        }
        result = post_check_result(global, per, result);
        result = post_output_handling(global, per, result);

        // Honor --retry-max-time: only retry while inside the budget.
        let within_maxtime = {
            let config = &global.operations[per.config_idx];
            config.retry_maxtime_ms == 0
                || (per.retrystart.elapsed().as_millis() as i64) < config.retry_maxtime_ms
        };
        if per.retry_remaining > 0 && within_maxtime {
            result = retrycheck(global, per, result, &mut retry, &mut delay);
            if result == codes::CURLE_OK && retry {
                return (codes::CURLE_OK, true, delay); // retry!
            }
        }

        // If the custom progress bar drew anything, close it with a newline.
        if global.progressmode == CURL_PROGRESS_BAR && per.progressbar.calls > 0 {
            eprintln!();
        }

        result = post_close_output(global, per, result);
    }

    // Write the --write-out data after the result is final but before cleanup.
    if global.operations[per.config_idx].writeout.is_some() {
        let _ = our_write_out(&global.operations[per.config_idx], &*per, result);
    }

    // Close the header-dump and etag streams (drop = close).
    per.heads.stream = None;
    per.etag_save.stream = None;
    // `hdrcbdata.headlist` is freed when the PerTransfer is dropped.

    (result, retry, delay)
}

/// Emits the `curl: (N) <message>` diagnostic for a failed transfer and applies
/// `--fail-with-body` (C `post_check_result`).
///
/// When the transfer failed and output is not suppressed, prints the error code
/// and message (preferring the engine/abort error buffer, falling back to the
/// code's static description) plus the CA-cert hint on a TLS verification
/// failure. Otherwise, for `--fail-with-body`, turns an HTTP response `>= 400`
/// into [`codes::CURLE_HTTP_RETURNED_ERROR`].
fn post_check_result(global: &GlobalConfig, per: &PerTransfer, result: CurlCode) -> CurlCode {
    let config = &global.operations[per.config_idx];
    if !config.synthetic_error && result != codes::CURLE_OK && (!global.silent || global.showerror)
    {
        let msg = per.error_message().map(str::to_string).unwrap_or_else(|| {
            if result == codes::CURLE_HTTP_RETURNED_ERROR {
                // `-f`/`--fail`: curl's library latches the message
                // `"The requested URL returned error: <code>"` into
                // `CURLOPT_ERRORBUFFER` via `failf()` on the failonerror abort
                // (lib/http.c). The engine's errorbuffer→handle bridge is a
                // documented foundation limitation, so reconstruct the identical
                // text from the recorded response code (`CURLINFO_RESPONSE_CODE`,
                // populated by the driver even on the aborted transfer) — the same
                // wording the `--fail-with-body` branch below emits, instead of the
                // generic static description "HTTP response code said error".
                format!(
                    "The requested URL returned error: {}",
                    getinfo_response(per)
                )
            } else if result == codes::CURLE_COULDNT_RESOLVE_HOST {
                // Name resolution failure: curl's resolver latches
                // `"Could not resolve host: <host>"` into `CURLOPT_ERRORBUFFER`
                // via `failf(data, "Could not resolve %s: %s", "host",
                // conn->host.dispname)` (lib/hostip.c, lib/url.c). Owing to the
                // same documented errorbuffer→handle foundation limitation,
                // reconstruct the identical text — including the offending host
                // recovered from the request URL — instead of the generic static
                // description "Could not resolve hostname". (The proxy variant
                // `CURLE_COULDNT_RESOLVE_PROXY` names the *proxy* host, not the
                // URL host, so it intentionally keeps the generic description.)
                match resolve_failure_host(per) {
                    Some(host) => format!("Could not resolve host: {host}"),
                    None => CurlError::from_code(result).description().to_string(),
                }
            } else {
                CurlError::from_code(result).description().to_string()
            }
        });
        write_gated_err(global, &format!("curl: ({result}) {msg}\n"));
        if result == codes::CURLE_PEER_FAILED_VERIFICATION {
            write_gated_err(global, CURL_CA_CERT_ERRORMSG);
        }
    } else if config.fail == FailMode::WithBody {
        // If the HTTP response was >= 400, turn it into an error.
        let code = getinfo_response(per);
        if code >= 400 {
            if !global.silent || global.showerror {
                write_gated_err(
                    global,
                    &format!(
                        "curl: ({}) The requested URL returned error: {code}\n",
                        codes::CURLE_HTTP_RETURNED_ERROR
                    ),
                );
            }
            return codes::CURLE_HTTP_RETURNED_ERROR;
        }
    }
    result
}

/// Handles post-transfer output concerns (C `post_output_handling`).
///
/// On a successful transfer that produced no bytes and never opened its named
/// output file, it forces creation of an empty file (unless a condition was
/// unmet). It then flushes buffered data on non-regular streams (stdout, stderr,
/// or an opened pipe), turning a flush failure into [`codes::CURLE_WRITE_ERROR`].
///
/// Note: `--xattr` (writing transfer metadata as extended attributes) requires
/// an OS xattr wrapper outside the allowed dependency set; the flag is accepted
/// but the attribute write is a documented no-op in this port.
fn post_output_handling(
    global: &mut GlobalConfig,
    per: &mut PerTransfer,
    result: CurlCode,
) -> CurlCode {
    // Force creation of an empty output file when a successful transfer wrote
    // nothing and the named file was never opened (curl's `!outs->stream`).
    if result == codes::CURLE_OK
        && per.outs.stream.is_none()
        && per.outs.filename.is_some()
        && per.outs.bytes == 0
        && !per.outs.out_null
    {
        let cond_unmet = match per.easy.getinfo(CurlInfo::ConditionUnmet) {
            Ok(InfoValue::Long(c)) => c,
            _ => 0,
        };
        if cond_unmet == 0 && !tool_create_output_file(&mut per.outs) {
            return codes::CURLE_WRITE_ERROR;
        }
    }

    // Flush standard / non-regular streams' buffered data.
    if !per.outs.regular_file {
        let flush_res = if let Some(f) = per.outs.stream.as_mut() {
            f.flush()
        } else if per.outs.to_stderr {
            std::io::stderr().flush()
        } else if per.outs.filename.is_none() {
            std::io::stdout().flush()
        } else {
            Ok(()) // a named file that was never opened — nothing buffered
        };
        if result == codes::CURLE_OK && flush_res.is_err() {
            errorf!(global, "Failed writing body");
            return codes::CURLE_WRITE_ERROR;
        }
    }
    result
}

/// Closes the body output file and applies `--remove-on-error`/`--remote-time`
/// (C `post_close_output`).
///
/// Flushing/closing the file can surface a write error
/// ([`codes::CURLE_WRITE_ERROR`]). On error with `--remove-on-error` the partial
/// regular file is removed. On success with `--remote-time` the remote file
/// time (`CURLINFO_FILETIME_T`) is applied to the saved file.
fn post_close_output(
    global: &mut GlobalConfig,
    per: &mut PerTransfer,
    mut result: CurlCode,
) -> CurlCode {
    if per.outs.fopened && per.outs.stream.is_some() {
        // We cannot observe a close error from `Drop`, so flush explicitly to
        // detect a failed write before dropping the handle.
        let close_err = per
            .outs
            .stream
            .as_mut()
            .map(|f| f.flush().is_err())
            .unwrap_or(false);
        per.outs.stream = None; // drop = close

        if result == codes::CURLE_OK && close_err {
            result = codes::CURLE_WRITE_ERROR;
            errorf!(global, "curl: ({result}) Failed writing body");
        }
        if result != codes::CURLE_OK && global.operations[per.config_idx].rm_partial {
            if let Some(fname) = per.outs.filename.clone() {
                match fs::metadata(&fname) {
                    Ok(md) if md.is_file() => {
                        if fs::remove_file(&fname).is_ok() {
                            notef!(global, "Removed output file: {fname}");
                        } else {
                            warnf!(global, "Failed removing: {fname}");
                        }
                    }
                    _ => warnf!(global, "Skipping removal; not a regular file: {fname}"),
                }
            }
        }
    }

    // File time can only be set after the file is closed.
    if result == codes::CURLE_OK
        && global.operations[per.config_idx].remote_time
        && per.outs.regular_file
    {
        if let Some(fname) = per.outs.filename.clone() {
            let filetime = match per.easy.getinfo(CurlInfo::FiletimeT) {
                Ok(InfoValue::OffT(t)) => t,
                _ => -1,
            };
            if filetime != -1 {
                set_file_time(filetime, &fname, global);
            }
        }
    }
    result
}

/// `true` when a retried download may keep its partially received bytes and
/// resume rather than restart (C `is_outfile_auto_resumable`). Requires
/// `--continue-at -` semantics, a regular opened output file with bytes already
/// written, a GET-like request, and a non-write/range error.
fn is_outfile_auto_resumable(global: &GlobalConfig, per: &PerTransfer, result: CurlCode) -> bool {
    let config = &global.operations[per.config_idx];
    config.use_resume
        && config.resume_from_current
        && config.resume_from >= 0
        && per.outs.init == config.resume_from as u64
        && per.outs.bytes > 0
        && per.outs.filename.is_some()
        && per.outs.regular_file
        && per.outs.fopened
        && per.outs.stream.is_some()
        && config.customrequest.is_none()
        && per.uploadfile.is_none()
        && (config.httpreq == HttpReq::Unspec || config.httpreq == HttpReq::Get)
        && result != codes::CURLE_WRITE_ERROR
        && result != codes::CURLE_RANGE_ERROR
}

/// `true` when the transfer's response carries `Accept-Ranges: bytes`
/// (used to decide auto-resume on a fresh `200`).
fn accept_ranges_is_bytes(per: &mut PerTransfer) -> bool {
    match per
        .easy
        .headers_mut()
        .header("Accept-Ranges", 0, curl_rs_lib::headers::CURLH_HEADER, -1)
    {
        Ok(h) => h.value == "bytes",
        Err(_) => false,
    }
}

/// Decides whether a finished transfer should be retried (C `retrycheck`).
///
/// Classifies the result against curl's transient-error table — connection
/// timeouts and DNS failures, refused connections (`--retry-connrefused`),
/// transient HTTP status codes (408/429/5xx/522/524), transient FTP `4xx`, and
/// `--retry-all-errors` — and, when a retry applies, computes the back-off
/// (honoring `Retry-After`, `--retry-delay`, and the doubling default), emits
/// the "Will retry…" notice, decrements the remaining count, and rewinds or
/// truncates the partial output so the next attempt starts cleanly. Sets
/// `*retryp`/`*delayms` and returns [`codes::CURLE_OK`] to signal a retry.
fn retrycheck(
    global: &mut GlobalConfig,
    per: &mut PerTransfer,
    mut result: CurlCode,
    retryp: &mut bool,
    delayms: &mut i64,
) -> CurlCode {
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum Retry {
        No,
        AllErrors,
        Timeout,
        ConnRefused,
        Http,
        Ftp,
    }
    let mut retry = Retry::No;
    let config_idx = per.config_idx;

    let fail_on_error = global.operations[config_idx].fail != FailMode::None;
    let retry_connrefused = global.operations[config_idx].retry_connrefused;
    let retry_all_errors = global.operations[config_idx].retry_all_errors;
    let retry_delay_ms = global.operations[config_idx].retry_delay_ms;
    let retry_maxtime_ms = global.operations[config_idx].retry_maxtime_ms;

    if result == codes::CURLE_OPERATION_TIMEDOUT
        || result == codes::CURLE_COULDNT_RESOLVE_HOST
        || result == codes::CURLE_COULDNT_RESOLVE_PROXY
        || result == codes::CURLE_FTP_ACCEPT_TIMEOUT
    {
        // Retry on timeout always.
        retry = Retry::Timeout;
    } else if retry_connrefused && result == codes::CURLE_COULDNT_CONNECT {
        let oserrno = match per.easy.getinfo(CurlInfo::OsErrno) {
            Ok(InfoValue::Long(e)) => e,
            _ => 0,
        };
        if oserrno == SOCK_ECONNREFUSED {
            retry = Retry::ConnRefused;
        }
    } else if result == codes::CURLE_OK
        || (fail_on_error && result == codes::CURLE_HTTP_RETURNED_ERROR)
    {
        // OK, or failonerror tripped on an HTTP error: check for transient
        // HTTP status codes worth retrying.
        let scheme = getinfo_scheme(per);
        if scheme == "http" || scheme == "https" {
            let response = getinfo_response(per);
            if matches!(response, 408 | 429 | 500 | 502 | 503 | 504 | 522 | 524) {
                retry = Retry::Http;
            }
        }
    } else if result != codes::CURLE_OK {
        let response = getinfo_response(per);
        let scheme = getinfo_scheme(per);
        if (scheme == "ftp" || scheme == "ftps") && response / 100 == 4 {
            // FTP 4xx codes are transient (e.g. server user limit).
            retry = Retry::Ftp;
        }
    }

    if result != codes::CURLE_OK && retry == Retry::No && retry_all_errors {
        retry = Retry::AllErrors;
    }

    if retry != Retry::No {
        let mut sleeptime: i64 = 0;
        let messages = [
            "",
            "(retrying all errors)",
            ": timeout",
            ": connection refused",
            ": HTTP error",
            ": FTP error",
        ];
        let msg_idx = match retry {
            Retry::No => 0,
            Retry::AllErrors => 1,
            Retry::Timeout => 2,
            Retry::ConnRefused => 3,
            Retry::Http => 4,
            Retry::Ftp => 5,
        };
        let mut truncate = true;

        if retry == Retry::Http {
            let retry_after = match per.easy.getinfo(CurlInfo::RetryAfter) {
                Ok(InfoValue::OffT(r)) => r,
                _ => 0,
            };
            if retry_after > 0 {
                if retry_after > i64::MAX / 1000 {
                    sleeptime = i64::MAX;
                } else if retry_after * 1000 > sleeptime {
                    sleeptime = retry_after * 1000;
                }
                if retry_maxtime_ms != 0 {
                    let ms = per.retrystart.elapsed().as_millis() as i64;
                    if (i64::MAX - sleeptime < ms) || (ms + sleeptime > retry_maxtime_ms) {
                        warnf!(
                            global,
                            "The Retry-After: time would make this command line \
                             exceed the maximum allowed time for retries."
                        );
                        *retryp = false;
                        return codes::CURLE_OK; // no retry
                    }
                }
            }
        }
        if sleeptime == 0 && retry_delay_ms == 0 {
            if per.retry_sleep == 0 {
                per.retry_sleep = RETRY_SLEEP_DEFAULT;
            } else {
                per.retry_sleep *= 2;
            }
            if per.retry_sleep > RETRY_SLEEP_MAX {
                per.retry_sleep = RETRY_SLEEP_MAX;
            }
        }
        if sleeptime == 0 {
            sleeptime = per.retry_sleep;
        }

        let secs = sleeptime / 1000;
        let frac = sleeptime % 1000;
        let secs_str = if frac != 0 {
            format!("{secs}.{frac:03}")
        } else {
            format!("{secs}")
        };
        let sec_plural = if sleeptime == 1000 { "" } else { "s" };
        let retr_word = if per.retry_remaining > 1 { "ies" } else { "y" };
        warnf!(
            global,
            "Problem {}. Will retry in {} second{}. {} retr{} left.",
            messages[msg_idx],
            secs_str,
            sec_plural,
            per.retry_remaining,
            retr_word
        );

        per.retry_remaining -= 1;

        // Skip truncation when auto-resume can keep the partial download.
        // (Dormant until the protocol engine writes body bytes; ported for
        // fidelity with curl's behavior.)
        if is_outfile_auto_resumable(global, per, result) {
            let method = getinfo_method(per);
            let response = getinfo_response(per);
            let scheme = getinfo_scheme(per);
            let resume_from = global.operations[config_idx].resume_from;
            let keep = (scheme == "http" || scheme == "https")
                && method == "GET"
                && ((response == 206 && resume_from != 0)
                    || (response == 200 && accept_ranges_is_bytes(per)));
            if keep {
                notef!(global, "Keeping {} bytes", per.outs.bytes);
                if let Some(f) = per.outs.stream.as_mut() {
                    if f.flush().is_err() {
                        errorf!(global, "Failed to flush output file stream");
                        return codes::CURLE_WRITE_ERROR;
                    }
                }
                if per.outs.bytes >= (i64::MAX as u64).saturating_sub(per.outs.init) {
                    errorf!(
                        global,
                        "Exceeded maximum supported file size ({} + {})",
                        per.outs.init,
                        per.outs.bytes
                    );
                    return codes::CURLE_WRITE_ERROR;
                }
                truncate = false;
                per.outs.init += per.outs.bytes;
                per.outs.bytes = 0;
                let new_resume = per.outs.init as i64;
                global.operations[config_idx].resume_from = new_resume;
                let _ = per.easy.setopt(
                    CurlOption::CURLOPT_RESUME_FROM_LARGE,
                    OptionValue::OffT(new_resume),
                );
            }
        }

        if truncate
            && per.outs.bytes > 0
            && per.outs.filename.is_some()
            && per.outs.stream.is_some()
        {
            let init = per.outs.init;
            // Only regular files can be truncated (not pipes/devices).
            if let Some(f) = per.outs.stream.as_mut() {
                let is_reg = f.metadata().map(|m| m.is_file()).unwrap_or(false);
                if is_reg {
                    let _ = f.flush();
                    notef!(global, "Throwing away {} bytes", per.outs.bytes);
                    if f.set_len(init).is_err() {
                        errorf!(global, "Failed to truncate file");
                        return codes::CURLE_WRITE_ERROR;
                    }
                    use std::io::Seek as _;
                    if f.seek(std::io::SeekFrom::End(0)).is_err() {
                        errorf!(global, "Failed seeking to end of file");
                        return codes::CURLE_WRITE_ERROR;
                    }
                    per.outs.bytes = 0;
                }
            }
        }

        *retryp = true;
        per.num_retries += 1;
        *delayms = sleeptime;
        result = codes::CURLE_OK;
    }
    result
}

/// Opens (creating/truncating) the named output file for a zero-byte successful
/// transfer (C `tool_create_output_file`). Returns `false` on failure.
fn tool_create_output_file(outs: &mut OutStruct) -> bool {
    let Some(fname) = outs.filename.clone() else {
        return false;
    };
    match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&fname)
    {
        Ok(f) => {
            outs.stream = Some(f);
            outs.fopened = true;
            true
        }
        Err(_) => false,
    }
}

/// Applies a remote file time to a saved file (C `setfiletime`,
/// `src/tool_cb_wrt.c`). Sets both the access and modification times to
/// `filetime` (seconds since the Unix epoch); a negative value predates the
/// epoch. Uses [`std::fs::File::set_times`] (stable since the 1.75 MSRV).
fn set_file_time(filetime: i64, filename: &str, global: &GlobalConfig) {
    use std::fs::FileTimes;
    use std::time::{Duration, UNIX_EPOCH};

    let when = if filetime >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(filetime as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(filetime.unsigned_abs()))
    };
    let Some(when) = when else {
        return;
    };
    if let Ok(f) = OpenOptions::new().write(true).open(filename) {
        let times = FileTimes::new().set_accessed(when).set_modified(when);
        if f.set_times(times).is_err() {
            warnf!(
                global,
                "Failed to set filetime {filetime} on outfile {filename}"
            );
        }
    }
}

/// Current wall-clock time in whole seconds since the Unix epoch (the analog of
/// C's `time(NULL)`), used to schedule delayed parallel retries and to throttle
/// the re-add tick.
fn now_epoch_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

// ===========================================================================
// operate() — the public entry point and its share-setup / get_args /
// version-and-engine reporting / SSL-session helpers.
//
// Port of `operate`, `share_setup`, and `share_setopt` from
// `src/tool_operate.c`; `get_args` from `src/tool_paramhlp.c` (the JSON-header
// portion); `tool_version_info` / `tool_list_engines` from `src/tool_help.c`;
// and `tool_ssls_load` / `tool_ssls_save` from `src/tool_ssls.c`.
// ===========================================================================

/// `true` when this build advertises SSL-session import/export.
///
/// curl exposes the capability through the `"SSLS-EXPORT"` feature string in
/// `curl_version_info()` and gates `tool_ssls_load`/`tool_ssls_save` on it
/// (`feature_ssls_export`). `curl_rs_lib` does not implement the underlying
/// `curl_easy_ssls_import`/`curl_easy_ssls_export` API, so the capability is
/// absent and this gate is always `false` — identical to a curl built without
/// SSL-session export. The check is derived from the same feature list
/// `curl --version` prints, so it stays consistent with capability reporting.
fn feature_ssls_export() -> bool {
    curl_rs_lib::version::feature_names()
        .iter()
        .any(|f| f.eq_ignore_ascii_case("SSLS-EXPORT"))
}

/// CLI product-name token printed at the start of the `--version` line — the
/// Rust analog of C `CURL_NAME` (`"curl"`, `src/tool_version.h`). Distinct from
/// the library banner's `libcurl/...` token; together they form curl's
/// canonical `curl <ver> (<os>) libcurl/<ver> ...` first line.
const CURL_NAME: &str = "curl";

/// Build target triple reported in the `--version` `(<os>)` field — the Rust
/// analog of C `CURL_OS` / the autoconf `OS` define. Emitted by
/// `curl-rs/build.rs` from Cargo's `TARGET` (e.g. `x86_64-unknown-linux-gnu`),
/// so it honestly reflects the build target. `tests/runtests.pl` only requires
/// a non-empty `(...)` token here; the value itself is not version-parsed.
const CURL_OS: &str = env!("CURL_RS_OS");

/// Prints the `--version` banner, `Release-Date:`, `Protocols:`, and
/// `Features:` lines (C `tool_version_info`, `src/tool_help.c`).
///
/// All data is sourced from [`curl_rs_lib::version`] so the CLI and the library
/// never disagree. The feature list is sorted case-insensitively, matching
/// curl's `qsort(..., struplocompare4sort)` before printing.
fn tool_version_info() {
    // C `tool_version_info` prints `CURL_ID "%s\n", curl_version()` where
    // `CURL_ID = CURL_NAME " " CURL_VERSION " (" CURL_OS ") "`
    // (`src/tool_version.h`). The library banner (`curl_version()` analog)
    // already begins `libcurl/<VERSION>`; here we prepend the `curl <VERSION>
    // (<os>) ` identity so line 1 reads
    // `curl <ver> (<os>) libcurl/<ver> <backends>` — the exact shape
    // `tests/runtests.pl` parses (its `/^curl ([^ ]*)/` capture plus the
    // required `libcurl/<ver>` substring) to extract `$CURLVERSION` /
    // `$CURLVERNUM` / `$libcurl` and drive version/backend test selection
    // (AAP §0.7.3). `CURL_VERSION` is libcurl's version (C defines
    // `CURL_VERSION` as `LIBCURL_VERSION`), sourced from the single canonical
    // `curl_rs_lib::version::VERSION`.
    println!(
        "{CURL_NAME} {} ({CURL_OS}) {}",
        curl_rs_lib::version::VERSION,
        curl_rs_lib::version::version()
    );
    // curl prints the release timestamp; an in-development (`-DEV`) build has
    // none, so curl emits `[unreleased]` (matches `main.rs::print_version`).
    println!("Release-Date: [unreleased]");

    let protocols = curl_rs_lib::version::protocols();
    if !protocols.is_empty() {
        println!("Protocols: {}", protocols.join(" "));
    }

    let mut features: Vec<&str> = curl_rs_lib::version::feature_names().to_vec();
    // Case-insensitive sort (curl's `struplocompare4sort`).
    features.sort_by_key(|f| f.to_ascii_lowercase());
    if !features.is_empty() {
        println!("Features: {}", features.join(" "));
    }
}

/// Lists the build-time SSL crypto engines (C `tool_list_engines`,
/// `src/tool_help.c`).
///
/// rustls exposes no OpenSSL-style `ENGINE` plugins, so the list is always
/// empty — exactly what curl prints when linked against a backend with no
/// engine support.
fn tool_list_engines() {
    println!("Build-time engines:");
    println!("  <none>");
}

/// Returns `true` when a header with the given field name is already present in
/// `headers` (case-insensitive on the name before the colon).
///
/// This is the analog of curl's `inlist()` check used by `get_args` to avoid
/// overriding a user-supplied `Content-Type`/`Accept` header.
fn header_in_list(headers: &[String], name: &str) -> bool {
    headers.iter().any(|h| match h.split_once(':') {
        Some((hname, _)) => hname.trim().eq_ignore_ascii_case(name),
        None => h.trim().eq_ignore_ascii_case(name),
    })
}

/// Per-operation argument finalization (C `get_args`, `src/tool_paramhlp.c`).
///
/// Reproduces the deterministic part of `get_args`: when `--json` is in effect
/// (`config->jsoned`), inject `Content-Type: application/json` and
/// `Accept: application/json` unless the user already supplied those headers
/// with `-H`.
///
/// The C `get_args` also calls `checkpasswd()` to interactively prompt for a
/// missing host/proxy password (a `-u user` with no `:password`). That prompt
/// requires a no-echo terminal read (`getpass`), which cannot be implemented
/// under this module's `#![forbid(unsafe_code)]` and the restricted dependency
/// set, and properly belongs to the paramhlp layer; the non-interactive paths
/// (a complete `user:password`, or no credentials at all) require no action
/// here, so they are fully handled.
fn get_args(global: &mut GlobalConfig, i: usize) -> CurlCode {
    let cfg = &mut global.operations[i];
    if cfg.jsoned {
        if !header_in_list(&cfg.headers, "Content-Type") {
            cfg.headers
                .push("Content-Type: application/json".to_string());
        }
        if !header_in_list(&cfg.headers, "Accept") {
            cfg.headers.push("Accept: application/json".to_string());
        }
    }
    codes::CURLE_OK
}

/// Programs one shared data type on the share handle (C `share_setopt`,
/// `src/tool_operate.c`).
///
/// Returns [`codes::CURLE_OK`] when the option is accepted, and *also* when the
/// data type is not built in ([`CurlShError::NotBuiltIn`]) — curl deliberately
/// tolerates a missing capability here. Any other share error maps to
/// [`codes::CURLE_FAILED_INIT`].
fn share_setopt(share: &Share, data: LockData) -> CurlCode {
    match share.setopt(ShareSetting::Share(data.as_i32())) {
        Ok(()) => codes::CURLE_OK,
        Err(CurlShError::NotBuiltIn) => codes::CURLE_OK,
        Err(_) => codes::CURLE_FAILED_INIT,
    }
}

/// Configures the cross-transfer share handle (C `share_setup`,
/// `src/tool_operate.c`).
///
/// The cookie jar, DNS cache, TLS session cache, PSL, and HSTS store are always
/// shared. The connection cache (`CONNECT`) is shared only in serial mode; in
/// parallel mode the multi handle owns the connection cache, so it is left
/// out — exactly matching curl's `options[5] = CURL_LOCK_DATA_CONNECT` guard.
fn share_setup(global: &GlobalConfig, share: &Share) -> CurlCode {
    // The fixed prefix, in curl's exact order.
    let mut options: Vec<LockData> = vec![
        LockData::Cookie,
        LockData::Dns,
        LockData::SslSession,
        LockData::Psl,
        LockData::Hsts,
    ];
    // Running in parallel uses the multi connection cache instead.
    if !global.parallel {
        options.push(LockData::Connect);
    }

    for data in options {
        let result = share_setopt(share, data);
        if result != codes::CURLE_OK {
            return result;
        }
    }
    codes::CURLE_OK
}

/// Imports cached TLS sessions from `filename` into the share (C
/// `tool_ssls_load`, `src/tool_ssls.c`) — capability-gated.
///
/// The C loader parses a session file and feeds each base64-encoded line to
/// `curl_easy_ssls_import`. That import entry point is not part of
/// `curl_rs_lib`'s surface, so the capability is unavailable. This function is
/// only ever reached under the [`feature_ssls_export`] gate in [`operate`],
/// which is always `false`, so the body is a documented clean skip that returns
/// success. It is retained (rather than removed) to preserve the structure and
/// call site of curl's `operate`.
fn ssls_load(_global: &GlobalConfig, _share: &Share, _filename: &str) -> CurlCode {
    codes::CURLE_OK
}

/// Exports the share's accumulated TLS sessions to `filename` (C
/// `tool_ssls_save`, `src/tool_ssls.c`) — capability-gated.
///
/// The C saver iterates the share's session cache through
/// `curl_easy_ssls_export`. As with [`ssls_load`], that entry point is absent
/// from `curl_rs_lib`, the capability is unavailable, and this is reached only
/// under the always-`false` [`feature_ssls_export`] gate, so it is a documented
/// clean skip returning success.
fn ssls_save(_global: &GlobalConfig, _share: &Share, _filename: &str) -> CurlCode {
    codes::CURLE_OK
}

/// The CLI operation driver — curl's `operate()` (`src/tool_operate.c`).
///
/// This is the single public entry point of the module, invoked by `main.rs`.
/// It performs curl's seven-step flow:
///
/// 1. **`.curlrc`** — unless the first argument is `-q`/`--disable` (or there
///    are no arguments at all), read the default config file. With no arguments
///    *and* no URL provided by `.curlrc`, print the usage hint and fail with
///    [`codes::CURLE_FAILED_INIT`].
/// 2. **Locale** — curl sets `LC_NUMERIC="C"` so number parsing is
///    locale-independent. Rust parses numerically with the C locale already, so
///    this is a documented no-op.
/// 3. **Parse arguments** — [`crate::args::parse_args`]. Informational requests
///    (help/manual/version/engines/CA-embed) render and reset the result to
///    [`codes::CURLE_OK`]; the error variants map to the exact `CURLcode` curl
///    uses (`PARAM_LIBCURL_UNSUPPORTED_PROTOCOL` →
///    [`codes::CURLE_UNSUPPORTED_PROTOCOL`], `PARAM_READ_ERROR` →
///    [`codes::CURLE_READ_ERROR`], everything else →
///    [`codes::CURLE_FAILED_INIT`]). If `.curlrc` was read, a `notef` is emitted
///    *after* `parse_args` so it honors the parsed verbosity.
/// 4. **Share** — create the share handle and run [`share_setup`].
/// 5. **`get_args`** — per-operation finalization (JSON headers).
/// 6. **Run** — point `global.current` at the first operation and drive
///    [`Driver::run_all_transfers`]. Optional SSL-session import/export bracket
///    the run when the capability is present (it is not, today).
/// 7. **Cleanup** — release the share and the `--variable` store.
///
/// The returned [`CurlCode`] is the process exit status, returned verbatim by
/// `main.rs` — curl's `return (int)result;`.
pub async fn operate(global: &mut GlobalConfig, args: Vec<OsString>) -> CurlCode {
    let mut result = codes::CURLE_OK;

    // curl treats argv as C strings. A lossy `OsString` → `String` conversion
    // never fails and keeps non-UTF-8 bytes printable, matching curl's
    // tolerance of arbitrary argv bytes for the purpose of option parsing.
    let argv: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let argc = argv.len();

    // first_arg = argv[1] (C `convert_tchar_to_UTF8(argv[1])`).
    let first_arg: Option<&str> = if argc > 1 {
        Some(argv[1].as_str())
    } else {
        None
    };

    // --- Step 2 (locale): documented no-op (see the doc comment above). ---

    // --- Step 1: parse `.curlrc` unless suppressed. ---
    // curl reads `.curlrc` when there are no arguments, or when the first
    // argument neither begins with `-q` nor equals `--disable`.
    let mut curlrc_path: Option<String> = None;
    let mut found_curlrc = false;
    let read_curlrc =
        argc == 1 || first_arg.is_some_and(|a| !a.starts_with("-q") && a != "--disable");
    if read_curlrc {
        // A failure here is ignored: it simply means there is no `.curlrc`.
        if let Ok(path) =
            crate::parsecfg::parseconfig(global, None, crate::parsecfg::CONFIG_MAX_LEVELS)
        {
            found_curlrc = true;
            curlrc_path = path;
        }
        // With no command-line arguments, a URL must come from `.curlrc`.
        if argc < 2 && global.first().url_list.is_empty() {
            helpf!();
            result = codes::CURLE_FAILED_INIT;
        }
    }

    if result == codes::CURLE_OK {
        // --- Step 3: parse the command line. ---
        let parsed = crate::args::parse_args(global, &argv);

        // Emit the `.curlrc` notice now — after `parse_args`, so it respects the
        // verbosity the arguments just established (C ordering).
        if found_curlrc {
            if let Some(ref path) = curlrc_path {
                notef!(global, "Read config file from '{path}'");
            }
        }

        match parsed {
            Err(err) => {
                use crate::args::ParameterError as Pe;
                // Informational requests render output and succeed; the genuine
                // errors map to their exact `CURLcode`.
                result = codes::CURLE_OK;
                match err {
                    // Render the categorized option help (C `tool_help`),
                    // honoring the optional category captured during parsing
                    // (`--help`, `-h`, `--help all`, `--help category`,
                    // `--help <category>`).
                    Pe::HelpRequested => {
                        crate::help::tool_help(global.help_category.as_deref());
                    }
                    // The built-in manual is not bundled in this build.
                    Pe::ManualRequested => {
                        warnf!(global, "built-in manual was disabled at build-time");
                    }
                    Pe::VersionInfoRequested => tool_version_info(),
                    Pe::EnginesRequested => tool_list_engines(),
                    // No CA bundle is embedded, so there is nothing to dump.
                    Pe::CaEmbedRequested => {}
                    Pe::LibcurlUnsupportedProtocol => {
                        result = codes::CURLE_UNSUPPORTED_PROTOCOL;
                    }
                    Pe::ReadError => result = codes::CURLE_READ_ERROR,
                    _ => result = codes::CURLE_FAILED_INIT,
                }
            }
            Ok(()) => {
                // --- Step 4: share init + setup. ---
                let share = Share::new();
                result = share_setup(global, &share);

                // --- Step 5a: optional SSL-session import (capability-gated). ---
                if result == codes::CURLE_OK
                    && global.ssl_sessions.is_some()
                    && feature_ssls_export()
                {
                    let filename = global
                        .ssl_sessions
                        .clone()
                        .expect("ssl_sessions is Some in this branch");
                    result = ssls_load(global, &share, &filename);
                }

                if result == codes::CURLE_OK {
                    // --- Step 5b: per-operation get_args over the whole list. ---
                    let count = global.operations.len();
                    let mut i = 0;
                    while i < count && result == codes::CURLE_OK {
                        result = get_args(global, i);
                        i += 1;
                    }

                    if result == codes::CURLE_OK {
                        // --- Step 6: run all transfers. ---
                        global.current = 0;
                        let mut driver = Driver::new();
                        result = driver.run_all_transfers(global, &share, result).await;

                        // SSL-session export on the way out (capability-gated).
                        if global.ssl_sessions.is_some() && feature_ssls_export() {
                            let filename = global
                                .ssl_sessions
                                .clone()
                                .expect("ssl_sessions is Some in this branch");
                            let r2 = ssls_save(global, &share, &filename);
                            if r2 != codes::CURLE_OK && result == codes::CURLE_OK {
                                result = r2;
                            }
                        }
                    }
                }

                // --- Step 7: release the share handle. ---
                // A cleanup failure (e.g. still-in-use) does not override the
                // transfer result, matching curl's `curl_share_cleanup(share)`
                // which discards its return value here.
                let _ = share.cleanup();
            }
        }
    }

    // varcleanup() — release the `--variable` store.
    global.var_cleanup();

    result
}

// ===========================================================================
// Unit tests — the deterministic, dependency-free helpers folded in from
// tool_operhlp.c, tool_progress.c, and tool_operate.c. These pin curl's exact
// byte-for-byte formatting and exit-code mappings so a regression is caught at
// `cargo test` time rather than against the full suite.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GlobalConfig;

    /// `is_fatal_error` selects exactly curl's immediately-fatal set
    /// (`src/tool_operate.c`): FAILED_INIT, OUT_OF_MEMORY, UNKNOWN_OPTION,
    /// BAD_FUNCTION_ARGUMENT. Everything else continues to the next transfer.
    #[test]
    fn fatal_error_set_matches_curl() {
        assert!(is_fatal_error(codes::CURLE_FAILED_INIT));
        assert!(is_fatal_error(codes::CURLE_OUT_OF_MEMORY));
        assert!(is_fatal_error(codes::CURLE_UNKNOWN_OPTION));
        assert!(is_fatal_error(codes::CURLE_BAD_FUNCTION_ARGUMENT));
        // Non-fatal: the run continues to the next transfer for these.
        assert!(!is_fatal_error(codes::CURLE_OK));
        assert!(!is_fatal_error(codes::CURLE_READ_ERROR));
        assert!(!is_fatal_error(codes::CURLE_HTTP_RETURNED_ERROR));
        assert!(!is_fatal_error(codes::CURLE_OPERATION_TIMEDOUT));
    }

    /// `stdin_upload` recognizes only `-` and `.` as standard-input sources
    /// (`src/tool_operhlp.c`).
    #[test]
    fn stdin_upload_recognizes_dash_and_dot() {
        assert!(stdin_upload("-"));
        assert!(stdin_upload("."));
        assert!(!stdin_upload("file.txt"));
        assert!(!stdin_upload(""));
        assert!(!stdin_upload("./file"));
    }

    /// `output_expected` is `true` for every download (no upload file) and for
    /// HTTP(S) uploads (which still return a response body), but `false` for a
    /// non-HTTP upload (`src/tool_operhlp.c`). The scheme test is
    /// case-insensitive.
    #[test]
    fn output_expected_matches_curl() {
        // Downloads always produce output.
        assert!(output_expected("ftp://host/file", None));
        assert!(output_expected("http://host/file", None));
        // HTTP(S) uploads still yield a response body.
        assert!(output_expected("http://host/file", Some("up.bin")));
        assert!(output_expected("https://host/file", Some("up.bin")));
        assert!(output_expected("HTTPS://HOST/FILE", Some("up.bin")));
        // Non-HTTP uploads produce no expected output.
        assert!(!output_expected("ftp://host/file", Some("up.bin")));
        assert!(!output_expected("scp://host/file", Some("up.bin")));
    }

    /// `urlerr_cvt` maps the URL-API/glob error integers to the exact
    /// `CURLcode` curl returns, with the `default` arm falling through to
    /// `CURLE_URL_MALFORMAT` (`src/tool_operhlp.c`). The integers are the ABI
    /// `CURLUcode` discriminants from `include/curl/urlapi.h`.
    #[test]
    fn urlerr_cvt_matches_curl() {
        assert_eq!(urlerr_cvt(7), codes::CURLE_OUT_OF_MEMORY); // CURLUE_OUT_OF_MEMORY
        assert_eq!(urlerr_cvt(5), codes::CURLE_UNSUPPORTED_PROTOCOL); // CURLUE_UNSUPPORTED_SCHEME
        assert_eq!(urlerr_cvt(30), codes::CURLE_NOT_BUILT_IN); // CURLUE_LACKS_IDN
        assert_eq!(urlerr_cvt(1), codes::CURLE_BAD_FUNCTION_ARGUMENT); // CURLUE_BAD_HANDLE
                                                                       // Anything unrecognized is a malformed URL.
        assert_eq!(urlerr_cvt(99), codes::CURLE_URL_MALFORMAT);
        assert_eq!(urlerr_cvt(0), codes::CURLE_URL_MALFORMAT);
    }

    /// `is_pkcs11_uri` matches a case-insensitive `pkcs11:` scheme prefix and
    /// nothing shorter (`src/tool_operate.c`).
    #[test]
    fn pkcs11_uri_detection() {
        assert!(is_pkcs11_uri("pkcs11:object=foo"));
        assert!(is_pkcs11_uri("PKCS11:object=foo"));
        assert!(is_pkcs11_uri("Pkcs11:"));
        assert!(!is_pkcs11_uri("pkcs11")); // 6 chars, no colon
        assert!(!is_pkcs11_uri("file:///etc/key.pem"));
        assert!(!is_pkcs11_uri(""));
    }

    /// `header_in_list` finds a header by field name case-insensitively, the
    /// analog of curl's `inlist` guard in `get_args`.
    #[test]
    fn header_in_list_is_case_insensitive() {
        let headers = vec![
            "Content-Type: text/plain".to_string(),
            "X-Foo:bar".to_string(),
        ];
        assert!(header_in_list(&headers, "content-type"));
        assert!(header_in_list(&headers, "Content-Type"));
        assert!(header_in_list(&headers, "x-foo"));
        assert!(!header_in_list(&headers, "Accept"));
        assert!(!header_in_list(&[], "Accept"));
    }

    /// `get_args` injects the two JSON headers when `--json` is set, but never
    /// overrides a user-supplied `Content-Type`/`Accept`.
    #[test]
    fn get_args_injects_json_headers() {
        let mut g = GlobalConfig::new();
        g.current_mut().jsoned = true;
        assert_eq!(get_args(&mut g, 0), codes::CURLE_OK);
        let h = &g.operations[0].headers;
        assert!(h.iter().any(|x| x == "Content-Type: application/json"));
        assert!(h.iter().any(|x| x == "Accept: application/json"));

        // A user-supplied Content-Type is preserved; only Accept is added.
        let mut g2 = GlobalConfig::new();
        g2.current_mut().jsoned = true;
        g2.current_mut()
            .headers
            .push("Content-Type: application/xml".to_string());
        assert_eq!(get_args(&mut g2, 0), codes::CURLE_OK);
        let h2 = &g2.operations[0].headers;
        assert_eq!(
            h2.iter().filter(|x| x.starts_with("Content-Type:")).count(),
            1
        );
        assert!(h2.iter().any(|x| x == "Content-Type: application/xml"));
        assert!(h2.iter().any(|x| x == "Accept: application/json"));

        // Without --json nothing is injected.
        let mut g3 = GlobalConfig::new();
        assert_eq!(get_args(&mut g3, 0), codes::CURLE_OK);
        assert!(g3.operations[0].headers.is_empty());
    }

    /// `max5data` reproduces curl's fixed 5-character byte formatting
    /// (`src/tool_progress.c`) — plain integers below 100000, then a
    /// one-decimal mantissa or a 4-digit value with a unit suffix.
    #[test]
    fn max5data_matches_curl() {
        assert_eq!(max5data(0), "    0");
        assert_eq!(max5data(999), "  999");
        assert_eq!(max5data(99999), "99999");
        // 100000 → 97.6k (97 KiB + decimal).
        assert_eq!(max5data(100_000), "97.6k");
        // 1 MiB → "1024k" (no decimal, 4-digit).
        assert_eq!(max5data(1_048_576), "1024k");
        // 10 MiB → "10.0M" (carry into the next unit, decimal mantissa).
        assert_eq!(max5data(10_485_760), "10.0M");
    }

    /// `time2str` reproduces curl's 8-character duration formatting
    /// (`src/tool_progress.c`): `HH:MM:SS`, then `NNNd HHh` for longer spans;
    /// non-positive input is eight spaces.
    #[test]
    fn time2str_matches_curl() {
        assert_eq!(time2str(0), "        "); // 8 spaces
        assert_eq!(time2str(-5), "        ");
        assert_eq!(time2str(59), "00:00:59");
        assert_eq!(time2str(3661), "01:01:01");
        assert_eq!(time2str(3600), "01:00:00");
        assert_eq!(time2str(359_999), "99:59:59"); // last HH:MM:SS value
        assert_eq!(time2str(360_000), "  4d 04h"); // first day form
    }

    /// `get_url_file_name` takes the last path segment as the local file name
    /// (`src/tool_operhlp.c`), dropping query and fragment.
    #[test]
    fn url_file_name_basic_segments() {
        let g = GlobalConfig::new();
        assert_eq!(
            get_url_file_name(&g, "http://example.com/path/to/file.tar.gz").unwrap(),
            "file.tar.gz"
        );
        assert_eq!(
            get_url_file_name(&g, "ftp://host/dir/data.bin").unwrap(),
            "data.bin"
        );
        // Query and fragment are stripped before taking the segment.
        assert_eq!(
            get_url_file_name(&g, "http://h/a/b/page.html?x=1#frag").unwrap(),
            "page.html"
        );
    }

    /// With no usable path segment, `get_url_file_name` falls back to curl's
    /// default `"curl_response"` name.
    #[test]
    fn url_file_name_defaults_when_empty() {
        // `silent` suppresses the "No remote filename" warning during the test.
        let mut g = GlobalConfig::new();
        g.silent = true;
        assert_eq!(
            get_url_file_name(&g, "http://example.com/").unwrap(),
            "curl_response"
        );
    }

    /// `add_file_name_to_url` leaves a URL that already carries a query string
    /// unchanged (`src/tool_operhlp.c`).
    #[test]
    fn add_file_name_leaves_query_urls_unchanged() {
        let url = "http://host/path?a=b";
        assert_eq!(add_file_name_to_url(url, "local.bin").unwrap(), url);
    }

    /// SSL-session export is not a capability of this build, so the gate is
    /// always `false` and the `tool_ssls_*` paths are never taken — matching a
    /// curl built without SSL-session export.
    #[test]
    fn ssls_export_capability_absent() {
        assert!(!feature_ssls_export());
    }

    /// `share_setup` succeeds for the default (serial) configuration and for the
    /// parallel configuration (where the connection cache is intentionally not
    /// shared). The share handle accepts every data type curl programs.
    #[test]
    fn share_setup_succeeds_serial_and_parallel() {
        let mut g = GlobalConfig::new();
        let share = Share::new();
        assert_eq!(share_setup(&g, &share), codes::CURLE_OK);

        g.parallel = true;
        let share2 = Share::new();
        assert_eq!(share_setup(&g, &share2), codes::CURLE_OK);
    }
}
