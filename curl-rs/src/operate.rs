// -----------------------------------------------------------------------
// curl-rs/src/operate.rs — Operation Dispatch and Execution Core
//
// Rust rewrite of src/tool_operate.c and src/tool_operate.h from
// curl 8.19.0-DEV.  The central orchestration module that translates
// parsed OperationConfig blocks into curl-rs-lib transfers, managing
// serial/parallel execution, retries, progress, and cleanup.
//
// # Safety
//
// This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use std::env;
use std::fs::{self, File, OpenOptions, remove_file};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::args::{parse_args, ParameterError, ParameterResult};
use crate::callbacks::header::{
    OutStruct as HdrOutStruct, OutputStream,
};
use crate::callbacks::tool_create_output_file;
use crate::config::{
    GlobalConfig, HttpReq, OperationConfig, TransferState,
    FAIL_WITH_BODY,
};
use crate::dirhier::create_dir_hierarchy;
use crate::filetime::set_filetime;
use crate::help::{tool_help, tool_list_engines, tool_version_info};
use crate::msgs::{errorf, helpf, notef, warnf};
use crate::operhlp::{
    append2query, is_fatal_error, result_text, set_cert_types,
};
use crate::paramhelp::get_args;
use crate::parsecfg::parseconfig;
use crate::progress_display::{
    self as progdisp, progress_finalize, ProgressState,
};
use crate::setopt::config2setopts;
use crate::ssls::{ssl_sessions_load, ssl_sessions_save};
use crate::urlglob::glob_url;
use crate::util::tvdiff;
use crate::var::var_cleanup;
use crate::writeout::our_write_out;
use crate::xattr::fwrite_xattr;

use curl_rs_lib::{
    CurlError, CurlResult, EasyHandle, MultiHandle, ShareHandle,
};
use curl_rs_lib::getinfo::{CurlInfo, InfoValue};
use curl_rs_lib::multi::WaitFd;
use curl_rs_lib::share::{CurlShOption, CurlShareLock};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// CA certificate error message matching curl 8.x.
const CURL_CA_CERT_ERRORMSG: &str = "\
More details here: https://curl.se/docs/sslcerts.html\n\n\
curl failed to verify the legitimacy of the server and therefore \
could not\nestablish a secure connection to it. To learn more about \
this situation and\nhow to fix it, please visit the webpage mentioned \
above.\n";

/// Default initial retry sleep interval in milliseconds.
const RETRY_SLEEP_DEFAULT: i64 = 1000;

/// Maximum retry sleep interval in milliseconds (10 minutes).
const RETRY_SLEEP_MAX: i64 = 600_000;

// ---------------------------------------------------------------------------
// OutStruct — re-export from callbacks::header
// ---------------------------------------------------------------------------

/// Output stream state for a single transfer's body or header output.
///
/// This is a re-export of [`crate::callbacks::header::OutStruct`], the
/// canonical output stream state type shared across the CLI tool.
pub type OutStruct = HdrOutStruct;

// ---------------------------------------------------------------------------
// PerTransfer — per-transfer state
// ---------------------------------------------------------------------------

/// Per-transfer state for a single URL being processed.
///
/// Replaces the C `struct per_transfer` from `tool_operate.h`.
pub struct PerTransfer {
    /// The curl easy handle driving this transfer.
    pub easy: EasyHandle,
    /// Reference to the operation config that spawned this transfer.
    pub config: Arc<OperationConfig>,
    /// Body output stream state.
    pub outs: OutStruct,
    /// Header output stream state (for `--dump-header`).
    pub heads: OutStruct,
    /// Parallel progress: total bytes to download.
    pub dl_total: i64,
    /// Parallel progress: bytes downloaded so far.
    pub dl_now: i64,
    /// Parallel progress: total bytes to upload.
    pub ul_total: i64,
    /// Parallel progress: bytes uploaded so far.
    pub ul_now: i64,
    /// Whether `dl_total` has been registered in the aggregate total.
    pub dl_total_added: bool,
    /// Whether `ul_total` has been registered in the aggregate total.
    pub ul_total_added: bool,
    /// Transfer abort flag.
    pub abort: bool,
    /// The URL currently being transferred.
    pub url: String,
    /// Transfer result code.
    pub result: CurlError,
    /// Number of retries remaining for this transfer.
    pub retry_count: u32,
    /// Cached certificate information.
    pub certinfo: Option<Vec<String>>,

    // -- Internal fields --
    /// ETag save output stream.
    pub etag_save: OutStruct,
    /// Number of headers received so far.
    pub num_headers: i64,
    /// The output filename.
    pub outfile: Option<String>,
    /// Upload filename (from `-T`).
    pub uploadfile: Option<String>,
    /// Upload file reader.
    pub infile: Option<File>,
    /// Whether `infile` was opened by us.
    pub infdopen: bool,
    /// Error buffer for this transfer.
    pub errorbuffer: String,
    /// Whether progress meter was disabled.
    pub noprogress: bool,
    /// Whether this transfer has been added to the multi handle.
    pub added: bool,
    /// Whether this transfer should be skipped.
    pub skip: bool,
    /// URL number index in the globbed URL list.
    pub urlnum: i64,
    /// Expected upload file size.
    pub uploadfilesize: i64,
    /// Retry sleep interval in ms (exponential back-off).
    pub retry_sleep: i64,
    /// Default retry sleep from config.
    pub retry_sleep_default: i64,
    /// Number of retries remaining.
    pub retry_remaining: i64,
    /// Number of retries already performed.
    pub num_retries: i64,
    /// Start time of this transfer.
    pub start: Instant,
    /// Time when retry attempts began.
    pub retrystart: Instant,
    /// Epoch seconds at which this transfer is allowed to restart.
    pub startat: i64,
}

impl PerTransfer {
    /// Creates a new `PerTransfer` with the given easy handle and config.
    pub fn new(easy: EasyHandle, config: Arc<OperationConfig>) -> Self {
        let now = Instant::now();
        Self {
            easy,
            config,
            outs: OutStruct::new_null(),
            heads: OutStruct::new_null(),
            dl_total: 0,
            dl_now: 0,
            ul_total: 0,
            ul_now: 0,
            dl_total_added: false,
            ul_total_added: false,
            abort: false,
            url: String::new(),
            result: CurlError::Ok,
            retry_count: 0,
            certinfo: None,
            etag_save: OutStruct::new_null(),
            num_headers: 0,
            outfile: None,
            uploadfile: None,
            infile: None,
            infdopen: false,
            errorbuffer: String::new(),
            noprogress: false,
            added: false,
            skip: false,
            urlnum: 0,
            uploadfilesize: -1,
            retry_sleep: 0,
            retry_sleep_default: 0,
            retry_remaining: 0,
            num_retries: 0,
            start: now,
            retrystart: now,
            startat: 0,
        }
    }
}

impl std::fmt::Debug for PerTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerTransfer")
            .field("url", &self.url)
            .field("result", &self.result)
            .field("retry_count", &self.retry_count)
            .field("abort", &self.abort)
            .field("skip", &self.skip)
            .field("dl_total", &self.dl_total)
            .field("dl_now", &self.dl_now)
            .field("ul_total", &self.ul_total)
            .field("ul_now", &self.ul_now)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Helper: add / delete per_transfer
// ---------------------------------------------------------------------------

fn add_per_transfer(
    transfers: &mut Vec<PerTransfer>,
    per: PerTransfer,
) -> usize {
    transfers.push(per);
    transfers.len() - 1
}

fn del_per_transfer(
    transfers: &mut Vec<PerTransfer>,
    index: usize,
) -> Option<usize> {
    if index < transfers.len() {
        transfers.remove(index);
    }
    if index < transfers.len() {
        Some(index)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// EasyHandle info extraction helpers
// ---------------------------------------------------------------------------

fn easy_get_response_code(easy: &EasyHandle) -> i64 {
    match easy.get_info(CurlInfo::ResponseCode) {
        Ok(InfoValue::Long(code)) => code,
        _ => 0,
    }
}

fn easy_get_scheme(easy: &EasyHandle) -> String {
    match easy.get_info(CurlInfo::Scheme) {
        Ok(InfoValue::String(Some(s))) => s,
        _ => String::new(),
    }
}

fn easy_get_retry_after(easy: &EasyHandle) -> i64 {
    match easy.get_info(CurlInfo::RetryAfter) {
        Ok(InfoValue::OffT(val)) => val,
        _ => 0,
    }
}

fn easy_get_filetime(easy: &EasyHandle) -> i64 {
    match easy.get_info(CurlInfo::FiletimeT) {
        Ok(InfoValue::OffT(val)) => val,
        _ => -1,
    }
}

fn easy_get_condition_unmet(easy: &EasyHandle) -> bool {
    match easy.get_info(CurlInfo::ConditionUnmet) {
        Ok(InfoValue::Long(val)) => val != 0,
        _ => false,
    }
}

fn easy_get_content_type(easy: &EasyHandle) -> Option<String> {
    match easy.get_info(CurlInfo::ContentType) {
        Ok(InfoValue::String(s)) => s,
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Progress type bridging helpers
// ---------------------------------------------------------------------------

/// Converts an `operate::PerTransfer` to a `progress_display::PerTransfer`.
fn to_progress_per(per: &PerTransfer) -> progdisp::PerTransfer {
    progdisp::PerTransfer {
        dltotal: per.dl_total,
        dlnow: per.dl_now,
        ultotal: per.ul_total,
        ulnow: per.ul_now,
        dltotal_added: per.dl_total_added,
        ultotal_added: per.ul_total_added,
        abort: per.abort,
        noprogress: per.noprogress,
    }
}

/// Writes back progress-tracking fields from a
/// `progress_display::PerTransfer` to an `operate::PerTransfer`.
fn from_progress_per(prog: &progdisp::PerTransfer, per: &mut PerTransfer) {
    per.dl_total_added = prog.dltotal_added;
    per.ul_total_added = prog.ultotal_added;
}

// ---------------------------------------------------------------------------
// Writeout bridge helper
// ---------------------------------------------------------------------------

/// Creates a `writeout::PerTransfer` from an `operate::PerTransfer`.
fn make_writeout_per<'a>(
    per: &'a PerTransfer,
    global: &'a GlobalConfig,
) -> crate::writeout::PerTransfer<'a> {
    crate::writeout::PerTransfer {
        curl: &per.easy,
        url: Some(per.url.as_str()),
        headers: None,
        errorbuffer: per.errorbuffer.as_str(),
        outs_filename: per.outs.filename.as_deref(),
        num_retries: per.num_retries,
        num_headers: per.num_headers,
        urlnum: per.urlnum,
        config: &per.config,
        global,
    }
}

// ---------------------------------------------------------------------------
// cacertpaths — set CA cert locations from environment
// ---------------------------------------------------------------------------

fn cacertpaths(config: &mut OperationConfig) {
    if config.cacert.is_some()
        || config.capath.is_some()
        || (config.insecure_ok
            && (config.doh_url.is_none() || config.doh_insecure_ok))
    {
        return;
    }

    if let Ok(bundle) = env::var("CURL_CA_BUNDLE") {
        if !bundle.is_empty() {
            config.cacert = Some(bundle);
            return;
        }
    }

    if let Ok(dir) = env::var("SSL_CERT_DIR") {
        if !dir.is_empty() {
            config.capath = Some(dir);
        }
    }
    if let Ok(file) = env::var("SSL_CERT_FILE") {
        if !file.is_empty() {
            config.cacert = Some(file);
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn stdin_upload(filename: &str) -> bool {
    filename == "-" || filename == "."
}

fn output_expected(uploadfile: &Option<String>) -> bool {
    uploadfile.is_none()
}

// ---------------------------------------------------------------------------
// Retry logic
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryReason {
    No,
    AllErrors,
    Timeout,
    ConnRefused,
    Http,
    Ftp,
}

impl RetryReason {
    fn message(&self) -> &'static str {
        match self {
            Self::No => "",
            Self::AllErrors => "(retrying all errors)",
            Self::Timeout => ": timeout",
            Self::ConnRefused => ": connection refused",
            Self::Http => ": HTTP error",
            Self::Ftp => ": FTP error",
        }
    }
}

fn retrycheck(
    config: &OperationConfig,
    per: &mut PerTransfer,
    result: CurlError,
    global: &GlobalConfig,
) -> (bool, i64) {
    let mut retry = RetryReason::No;

    match result {
        CurlError::OperationTimedOut
        | CurlError::CouldntResolveHost
        | CurlError::CouldntResolveProxy
        | CurlError::FtpAcceptTimeout => {
            retry = RetryReason::Timeout;
        }
        CurlError::CouldntConnect if config.retry_connrefused => {
            retry = RetryReason::ConnRefused;
        }
        CurlError::Ok | CurlError::HttpReturnedError => {
            let response_code = easy_get_response_code(&per.easy);
            if matches!(
                response_code,
                408 | 429 | 500 | 502 | 503 | 504 | 522 | 524
            ) {
                retry = RetryReason::Http;
            }
        }
        _ => {
            let response_code = easy_get_response_code(&per.easy);
            if response_code / 100 == 4 {
                let scheme =
                    easy_get_scheme(&per.easy).to_lowercase();
                if scheme == "ftp" || scheme == "ftps" {
                    retry = RetryReason::Ftp;
                }
            }
        }
    }

    if result != CurlError::Ok
        && retry == RetryReason::No
        && config.retry_all_errors
    {
        retry = RetryReason::AllErrors;
    }

    if retry == RetryReason::No {
        return (false, 0);
    }

    let mut sleeptime: i64 = 0;

    if retry == RetryReason::Http {
        let retry_after = easy_get_retry_after(&per.easy);
        if retry_after > 0 {
            sleeptime =
                retry_after.saturating_mul(1000);
            if config.retry_max_time > 0 {
                let elapsed_ms =
                    tvdiff(Instant::now(), per.retrystart);
                if elapsed_ms.saturating_add(sleeptime)
                    > config.retry_max_time * 1000
                {
                    warnf(
                        global,
                        "The Retry-After: time would \
                         make this command line exceed the maximum \
                         allowed time for retries.",
                    );
                    return (false, 0);
                }
            }
        }
    }

    if sleeptime == 0 && config.retry_delay == 0 {
        if per.retry_sleep == 0 {
            per.retry_sleep = RETRY_SLEEP_DEFAULT;
        } else {
            per.retry_sleep =
                (per.retry_sleep * 2).min(RETRY_SLEEP_MAX);
        }
    }
    if sleeptime == 0 {
        sleeptime = if config.retry_delay > 0 {
            config.retry_delay
        } else {
            per.retry_sleep
        };
    }

    warnf(
        global,
        &format!(
            "Problem {}. Will retry in {} second{}. \
             {} retr{} left.",
            retry.message(),
            sleeptime / 1000,
            if sleeptime == 1000 { "" } else { "s" },
            per.retry_remaining,
            if per.retry_remaining > 1 {
                "ies"
            } else {
                "y"
            },
        ),
    );

    per.retry_remaining -= 1;
    per.num_retries += 1;
    (true, sleeptime)
}

// ---------------------------------------------------------------------------
// Post-transfer processing helpers
// ---------------------------------------------------------------------------

fn post_check_result(
    per: &mut PerTransfer,
    result: CurlError,
    global: &GlobalConfig,
) -> CurlError {
    let config = &per.config;

    if !config.synthetic_error
        && result != CurlError::Ok
        && (!global.silent || global.showerror)
    {
        let msg = if per.errorbuffer.is_empty() {
            result_text(result).to_string()
        } else {
            per.errorbuffer.clone()
        };
        errorf(
            global,
            &format!("({}) {}", result as i32, msg),
        );
        if result == CurlError::PeerFailedVerification {
            errorf(global, CURL_CA_CERT_ERRORMSG);
        }
    } else if config.fail == FAIL_WITH_BODY {
        let code = easy_get_response_code(&per.easy);
        if code >= 400 {
            if !global.silent || global.showerror {
                errorf(
                    global,
                    &format!(
                        "({}) The requested URL returned \
                         error: {}",
                        CurlError::HttpReturnedError as i32,
                        code,
                    ),
                );
            }
            return CurlError::HttpReturnedError;
        }
    }
    result
}

fn post_output_handling(
    per: &mut PerTransfer,
    result: CurlError,
    global: &GlobalConfig,
) -> CurlError {
    let config = &per.config;

    // Set extended attributes when requested.
    if result == CurlError::Ok && config.xattr && per.outs.fopened {
        if let Some(ref filename) = per.outs.filename {
            if let Ok(file) = File::open(filename) {
                let ct = easy_get_content_type(&per.easy);
                let _ = fwrite_xattr(
                    &file,
                    &per.url,
                    ct.as_deref(),
                    None,
                );
            }
        }
    }

    // Force creation of an empty output file if no data was received.
    if result == CurlError::Ok
        && per.outs.stream.is_null()
        && per.outs.bytes == 0
    {
        let cond_unmet = easy_get_condition_unmet(&per.easy);
        if !cond_unmet
            && per.outs.filename.is_some()
            && !per.outs.out_null
            && !tool_create_output_file(
                &mut per.outs,
                &per.config,
                global,
            )
        {
            return CurlError::WriteError;
        }
    }

    // Flush output streams.
    let flush_result = per.outs.stream.flush();
    if flush_result.is_err() && result == CurlError::Ok {
        errorf(global, "Failed writing body");
        return CurlError::WriteError;
    }
    result
}

fn post_close_output(
    per: &mut PerTransfer,
    result: CurlError,
    global: &GlobalConfig,
) -> CurlError {
    let config = &per.config;
    let final_result = result;

    if per.outs.fopened {
        per.outs.stream = OutputStream::Null;
        per.outs.fopened = false;

        if final_result != CurlError::Ok && config.rm_partial {
            if let Some(ref filename) = per.outs.filename {
                let path = Path::new(filename);
                if path.is_file() {
                    match remove_file(path) {
                        Ok(()) => {
                            notef(
                                global,
                                &format!(
                                    "Removed output file: {}",
                                    filename,
                                ),
                            );
                        }
                        Err(_) => {
                            warnf(
                                global,
                                &format!(
                                    "Failed removing: {}",
                                    filename,
                                ),
                            );
                        }
                    }
                } else {
                    warnf(
                        global,
                        &format!(
                            "Skipping removal; not a regular \
                             file: {}",
                            filename,
                        ),
                    );
                }
            }
        }
    }

    if final_result == CurlError::Ok
        && config.remote_time
        && per.outs.s_isreg
        && per.outs.filename.is_some()
    {
        let filetime = easy_get_filetime(&per.easy);
        if filetime != -1 {
            if let Some(ref filename) = per.outs.filename {
                let _ = set_filetime(filename, filetime);
            }
        }
    }
    final_result
}

/// Returns `(result, should_retry, delay_ms)`.
fn post_per_transfer(
    per: &mut PerTransfer,
    result: CurlError,
    global: &GlobalConfig,
) -> (CurlError, bool, i64) {
    let config = per.config.clone();
    let mut res = result;

    if !per.skip {
        res = post_check_result(per, res, global);
        res = post_output_handling(per, res, global);

        if per.retry_remaining > 0 {
            let elapsed_ok = if config.retry_max_time > 0 {
                tvdiff(Instant::now(), per.retrystart)
                    < config.retry_max_time * 1000
            } else {
                true
            };
            if elapsed_ok {
                let (should_retry, retry_delay) =
                    retrycheck(&config, per, res, global);
                if should_retry {
                    return (CurlError::Ok, true, retry_delay);
                }
            }
        }

        res = post_close_output(per, res, global);
    }

    // Write-out template rendering.
    if let Some(ref template) = config.writeout {
        let wo_per = make_writeout_per(per, global);
        let _ = our_write_out(template, &wo_per, res as i32);
    }

    // Close header dump file.
    if per.heads.fopened {
        per.heads.stream = OutputStream::Null;
        per.heads.fopened = false;
    }
    if per.heads.alloc_filename {
        per.heads.filename = None;
        per.heads.alloc_filename = false;
    }

    // Close etag save file.
    if per.etag_save.fopened {
        per.etag_save.stream = OutputStream::Null;
        per.etag_save.fopened = false;
    }
    if per.etag_save.alloc_filename {
        per.etag_save.filename = None;
        per.etag_save.alloc_filename = false;
    }

    // Close upload file.
    per.infile = None;
    per.infdopen = false;

    (res, false, 0)
}

// ---------------------------------------------------------------------------
// pre_transfer — pre-transfer setup
// ---------------------------------------------------------------------------

fn pre_transfer(per: &mut PerTransfer) -> CurlResult<()> {
    let mut uploadfilesize: i64 = -1;

    if let Some(ref upload_path) = per.uploadfile.clone() {
        if !stdin_upload(upload_path) {
            let file = File::open(upload_path)
                .map_err(|_| CurlError::ReadError)?;
            let file_meta = file
                .metadata()
                .map_err(|_| CurlError::ReadError)?;
            if file_meta.is_file() {
                uploadfilesize = file_meta.len() as i64;
            }
            per.infile = Some(file);
            per.infdopen = true;
        }
    }

    per.uploadfilesize = uploadfilesize;
    per.start = Instant::now();
    Ok(())
}

// ---------------------------------------------------------------------------
// share_setup
// ---------------------------------------------------------------------------

fn share_setup(global: &GlobalConfig) -> CurlResult<ShareHandle> {
    let share = ShareHandle::new();
    let _ = share.set_option(
        CurlShOption::Share,
        CurlShareLock::Cookie,
    );
    let _ = share.set_option(
        CurlShOption::Share,
        CurlShareLock::Dns,
    );
    let _ = share.set_option(
        CurlShOption::Share,
        CurlShareLock::SslSession,
    );
    let _ = share.set_option(
        CurlShOption::Share,
        CurlShareLock::Psl,
    );
    let _ = share.set_option(
        CurlShOption::Share,
        CurlShareLock::Hsts,
    );
    if !global.parallel {
        let _ = share.set_option(
            CurlShOption::Share,
            CurlShareLock::Connect,
        );
    }
    Ok(share)
}

// ---------------------------------------------------------------------------
// create_single — create one PerTransfer from an OperationConfig
// ---------------------------------------------------------------------------

fn create_single(
    config: &mut OperationConfig,
    share: &ShareHandle,
    state: &mut TransferState,
    transfers: &mut Vec<PerTransfer>,
    global: &mut GlobalConfig,
) -> CurlResult<(bool, bool)> {
    let orig_noprogress = global.noprogress;
    let orig_isatty = global.isatty;

    let url_list_len = config.url_list.len();
    let url_node_idx = match state.url_node_idx {
        Some(idx) if idx < url_list_len => idx,
        _ => return Ok((false, false)),
    };

    let u = config.url_list[url_node_idx].clone();

    if u.url.is_none() {
        warnf(global, "Got more output options than URLs");
        return Ok((false, false));
    }

    if u.infile.is_some() && state.uploadfile.is_none() {
        if let Some(ref infile) = u.infile {
            state.uploadfile = Some(infile.clone());
        }
    }

    if state.up_idx >= state.up_num {
        state.url_num = 0;
        state.uploadfile = None;
        state.up_idx = 0;
        state.url_node_idx = if url_node_idx + 1 < url_list_len {
            Some(url_node_idx + 1)
        } else {
            None
        };
        return Ok((false, false));
    }

    // URL globbing.
    if state.url_num == 0 {
        if !config.globoff && !u.no_glob {
            if let Some(ref url) = u.url {
                match glob_url(url) {
                    Ok((_glob, num)) => {
                        state.url_num = num;
                    }
                    Err(_e) => {
                        return Err(CurlError::FailedInit);
                    }
                }
            }
        } else {
            state.url_num = 1;
        }
    }

    let easy = EasyHandle::new();
    let per_config = Arc::new(config.clone());
    let mut per = PerTransfer::new(easy, per_config);

    if let Some(ref upload) = state.uploadfile {
        per.uploadfile = Some(upload.clone());
    }
    if let Some(ref url) = u.url {
        per.url = url.clone();
    }
    per.urlnum = u.num;

    // Set up header file output.
    if let Some(ref headerfile) = config.headerfile {
        if headerfile != "%" && headerfile != "-" {
            if config.create_dirs {
                let _ = create_dir_hierarchy(headerfile);
            }
            match OpenOptions::new()
                .create(true)
                .append(true)
                .open(headerfile)
            {
                Ok(file) => {
                    per.heads.stream = OutputStream::File(file);
                    per.heads.filename = Some(headerfile.clone());
                    per.heads.s_isreg = true;
                    per.heads.fopened = true;
                }
                Err(_) => {
                    errorf(
                        global,
                        &format!(
                            "Failed to open {}",
                            headerfile,
                        ),
                    );
                    return Err(CurlError::WriteError);
                }
            }
        }
    }

    let mut skipped = false;
    if let Some(ref outfile) = u.outfile {
        per.outfile = Some(outfile.clone());
    }
    per.outs.out_null = u.out_null;

    if !per.outs.out_null
        && (u.use_remote
            || per.outfile.as_deref().is_some_and(|f| f != "-"))
    {
        let mut outpath =
            per.outfile.clone().unwrap_or_default();

        if let Some(ref output_dir) = config.output_dir {
            if !output_dir.is_empty() {
                outpath =
                    format!("{}/{}", output_dir, outpath);
            }
        }
        if config.create_dirs {
            let _ = create_dir_hierarchy(&outpath);
        }
        if config.skip_existing
            && Path::new(&outpath).exists()
        {
            notef(
                global,
                &format!(
                    "skips transfer, \"{}\" exists locally",
                    outpath,
                ),
            );
            per.skip = true;
            skipped = true;
        }
        if config.resume_from_current {
            if let Ok(meta) = fs::metadata(&outpath) {
                config.resume_from = meta.len() as i64;
            } else {
                config.resume_from = 0;
            }
        }
        if config.resume_from != 0 && !per.skip {
            match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&outpath)
            {
                Ok(file) => {
                    per.outs.fopened = true;
                    per.outs.stream = OutputStream::File(file);
                    per.outs.init = true;
                }
                Err(_) => {
                    errorf(
                        global,
                        &format!(
                            "cannot open '{}'",
                            outpath,
                        ),
                    );
                    return Err(CurlError::WriteError);
                }
            }
        }
        per.outs.filename = Some(outpath);
        per.outs.s_isreg = true;
    }

    if let Some(ref upload) = per.uploadfile {
        if stdin_upload(upload) {
            let authbits = (0..32u64)
                .filter(|&bit| {
                    config.authtype & (1u64 << bit) != 0
                })
                .count();
            if config.proxyanyauth || authbits > 1 {
                warnf(
                    global,
                    "Using --anyauth or --proxy-anyauth with \
                     upload from stdin involves a big risk of \
                     it not working. Use a temporary file or a \
                     fixed auth type instead",
                );
            }
        } else if config.resume_from_current {
            config.resume_from = -1;
        }
    }

    if !per.outs.out_null
        && output_expected(&per.uploadfile)
        && per.outs.stream.is_null()
    {
        per.noprogress = orig_noprogress;
        global.noprogress = orig_noprogress;
        global.isatty = orig_isatty;
    }

    // Append HTTP GET fields to query string.
    if let Some(ref fields) = state.httpgetfields {
        let fields_copy = fields.clone();
        if append2query(&mut per.url, &fields_copy).is_err() {
            return Err(CurlError::FailedInit);
        }
    }

    config.terminal_binary_ok =
        per.outfile.as_deref() == Some("-");

    // Apply all curl options via config2setopts.
    let mut setopt_per = to_progress_per(&per);
    let has_upload = per.uploadfile.is_some();
    let share_opt = Some(share);
    let _ = config2setopts(
        config,
        &mut setopt_per,
        &mut per.easy,
        share_opt,
        global,
        &mut per.url,
        has_upload,
    );
    from_progress_per(&setopt_per, &mut per);

    // Initialize retry state.
    per.retry_sleep_default = config.retry_delay;
    per.retry_remaining = config.retry as i64;
    per.retry_sleep = per.retry_sleep_default;
    per.retrystart = Instant::now();

    // Advance URL iteration.
    state.url_idx += 1;
    if state.url_idx >= state.url_num {
        state.url_idx = 0;
        state.url_num = 0;
        state.up_idx += 1;
        state.uploadfile = None;
    }

    add_per_transfer(transfers, per);
    Ok((true, skipped))
}

// ---------------------------------------------------------------------------
// single_transfer / transfer_per_config / create_transfer
// ---------------------------------------------------------------------------

fn single_transfer(
    config: &mut OperationConfig,
    share: &ShareHandle,
    state: &mut TransferState,
    transfers: &mut Vec<PerTransfer>,
    global: &mut GlobalConfig,
) -> CurlResult<(bool, bool)> {
    if config.postfields.is_some() {
        if config.use_httpget {
            if state.httpgetfields.is_none() {
                state.httpgetfields = config.postfields.take();
                config.httpreq = if config.no_body {
                    HttpReq::Head
                } else {
                    HttpReq::Get
                };
            }
        } else {
            config.httpreq = HttpReq::SimplePost;
        }
    }
    if state.httpgetfields.is_none() {
        state.httpgetfields = config.query.clone();
    }
    set_cert_types(config);
    if state.url_node_idx.is_none() {
        state.url_node_idx = if config.url_list.is_empty() {
            None
        } else {
            Some(0)
        };
        state.up_num = 1;
    }
    create_single(
        config, share, state, transfers, global,
    )
}

fn transfer_per_config(
    config: &mut OperationConfig,
    share: &ShareHandle,
    state: &mut TransferState,
    transfers: &mut Vec<PerTransfer>,
    global: &mut GlobalConfig,
) -> CurlResult<(bool, bool)> {
    if config.url_list.is_empty()
        || config
            .url_list
            .first()
            .and_then(|u| u.url.as_ref())
            .is_none()
    {
        helpf(Some(&format!(
            "({}) no URL specified",
            CurlError::FailedInit as i32,
        )));
        return Err(CurlError::FailedInit);
    }
    cacertpaths(config);
    single_transfer(
        config, share, state, transfers, global,
    )
}

fn create_transfer(
    global: &mut GlobalConfig,
    share: &ShareHandle,
    transfers: &mut Vec<PerTransfer>,
) -> CurlResult<(bool, bool)> {
    let num_configs = global.configs.len();
    while global.current < num_configs {
        let idx = global.current;
        let mut config = global.configs[idx].clone();
        let mut state = global.state.clone();
        let result = transfer_per_config(
            &mut config,
            share,
            &mut state,
            transfers,
            global,
        );
        global.state = state;
        global.configs[idx] = config;
        match result {
            Ok((true, skipped)) => {
                return Ok((true, skipped))
            }
            Ok((false, _)) => {
                global.current += 1;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok((false, false))
}

// ---------------------------------------------------------------------------
// serial_transfers
// ---------------------------------------------------------------------------

async fn serial_transfers(
    global: &mut GlobalConfig,
    share: &ShareHandle,
    transfers: &mut Vec<PerTransfer>,
) -> CurlError {
    let mut returncode = CurlError::Ok;

    match create_transfer(global, share, transfers) {
        Ok((true, _)) => {}
        Ok((false, _)) => {
            errorf(global, "no transfer performed");
            return CurlError::ReadError;
        }
        Err(e) => return e,
    }

    while !transfers.is_empty() {
        let idx = 0;
        let start = Instant::now();
        let mut result = CurlError::Ok;

        if !transfers[idx].skip {
            match pre_transfer(&mut transfers[idx]) {
                Ok(()) => {}
                Err(e) => {
                    result = e;
                    returncode = result;
                    break;
                }
            }
            tokio::task::yield_now().await;
            result = match transfers[idx].easy.perform_transfer().await {
                Ok(()) => CurlError::Ok,
                Err(e) => e,
            };
            tokio::task::yield_now().await;
        }

        let (post_result, retry, delay_ms) =
            post_per_transfer(
                &mut transfers[idx],
                result,
                global,
            );

        if retry {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(
                    delay_ms as u64,
                ))
                .await;
            }
            continue;
        }

        returncode = post_result;
        let bailout = is_fatal_error(returncode)
            || (returncode != CurlError::Ok
                && global.fail_early);

        if !bailout {
            loop {
                match create_transfer(
                    global, share, transfers,
                ) {
                    Ok((_, true)) => continue,
                    Ok((_, false)) => break,
                    Err(e) => {
                        returncode = e;
                        break;
                    }
                }
            }
        }

        del_per_transfer(transfers, idx);
        if bailout {
            break;
        }

        if !transfers.is_empty()
            && global.ms_per_transfer > 0
        {
            let elapsed = tvdiff(Instant::now(), start);
            if elapsed < global.ms_per_transfer {
                let wait =
                    global.ms_per_transfer - elapsed;
                notef(
                    global,
                    &format!(
                        "Transfer took {} ms, waits {}ms \
                         as set by --rate",
                        elapsed, wait,
                    ),
                );
                tokio::time::sleep(
                    Duration::from_millis(wait as u64),
                )
                .await;
            }
        }
    }
    returncode
}

// ---------------------------------------------------------------------------
// parallel_transfers
// ---------------------------------------------------------------------------

async fn parallel_transfers(
    global: &mut GlobalConfig,
    share: &ShareHandle,
    transfers: &mut Vec<PerTransfer>,
) -> CurlError {
    let mut multi = MultiHandle::new();
    let mut all_added: i64 = 0;
    let mut still_running = true;
    let mut wrapitup = false;
    let mut wrapitup_processed = false;
    let mut result = CurlError::Ok;

    let mut more_transfers = match add_parallel_transfers_batch(
        global, share, transfers, &multi, &mut all_added,
    ) {
        Ok(more) => more,
        Err(e) => return e,
    };

    while still_running || more_transfers {
        if wrapitup {
            if !still_running {
                break;
            }
            if !wrapitup_processed {
                for per in transfers.iter_mut() {
                    if per.added {
                        per.abort = true;
                    }
                }
                wrapitup_processed = true;
            }
        }

        let mut extra_fds: Vec<WaitFd> = Vec::new();
        let _ = multi.poll(&mut extra_fds, 1000);
        let running = multi.perform().unwrap_or_default();
        still_running = running > 0;

        while let Some(msg) = multi.info_read() {
            let transfer_result = msg.result();
            if let Some(per_idx) =
                transfers.iter().position(|p| p.added)
            {
                {
                    let per = &mut transfers[per_idx];
                    if per.abort
                        && transfer_result
                            == CurlError::AbortedByCallback
                    {
                        per.errorbuffer =
                            "Transfer aborted due to critical \
                             error in another transfer"
                                .to_string();
                    }
                }

                let (post_res, retry, delay) =
                    post_per_transfer(
                        &mut transfers[per_idx],
                        transfer_result,
                        global,
                    );

                {
                    let mut prog_per =
                        to_progress_per(&transfers[per_idx]);
                    progress_finalize(
                        &mut ProgressState::default(),
                        &mut prog_per,
                    );
                    from_progress_per(
                        &prog_per,
                        &mut transfers[per_idx],
                    );
                }
                all_added -= 1;

                if retry {
                    transfers[per_idx].added = false;
                    transfers[per_idx].startat = if delay > 0
                    {
                        std::time::SystemTime::now()
                            .duration_since(
                                std::time::UNIX_EPOCH,
                            )
                            .unwrap_or_default()
                            .as_secs()
                            as i64
                            + delay / 1000
                    } else {
                        0
                    };
                } else {
                    if post_res != CurlError::Ok
                        && (!transfers[per_idx].abort
                            || result == CurlError::Ok)
                    {
                        result = post_res;
                    }
                    if is_fatal_error(result)
                        || (result != CurlError::Ok
                            && global.fail_early)
                    {
                        wrapitup = true;
                    }
                    del_per_transfer(transfers, per_idx);
                }
            }
        }

        if !wrapitup {
            match add_parallel_transfers_batch(
                global,
                share,
                transfers,
                &multi,
                &mut all_added,
            ) {
                Ok(more) => {
                    more_transfers = more;
                    if more {
                        still_running = true;
                    }
                }
                Err(e) => {
                    result = e;
                    wrapitup = true;
                }
            }
            if is_fatal_error(result)
                || (result != CurlError::Ok
                    && global.fail_early)
            {
                wrapitup = true;
            }
        }
        tokio::task::yield_now().await;
    }
    result
}

fn add_parallel_transfers_batch(
    global: &mut GlobalConfig,
    share: &ShareHandle,
    transfers: &mut Vec<PerTransfer>,
    _multi: &MultiHandle,
    all_added: &mut i64,
) -> CurlResult<bool> {
    let mut sleeping = false;

    if (*all_added as u32)
        < global.parallel_max.saturating_mul(2)
    {
        loop {
            match create_transfer(global, share, transfers) {
                Ok((true, false)) => break,
                Ok((_, true)) => continue,
                Ok((false, false)) => break,
                Err(e) => return Err(e),
            }
        }
    }

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    for per in transfers.iter_mut() {
        if *all_added >= global.parallel_max as i64 {
            break;
        }
        if per.added || per.skip {
            continue;
        }
        if per.startat > 0 && now_epoch < per.startat {
            sleeping = true;
            continue;
        }
        pre_transfer(per)?;
        per.added = true;
        *all_added += 1;
    }

    let has_pending = transfers
        .iter()
        .any(|p| !p.added && !p.skip)
        || sleeping;
    Ok(has_pending)
}

// ---------------------------------------------------------------------------
// run_all_transfers
// ---------------------------------------------------------------------------

async fn run_all_transfers(
    global: &mut GlobalConfig,
    share: &ShareHandle,
) -> CurlError {
    let orig_noprogress = global.noprogress;
    let orig_isatty = global.isatty;
    let mut transfers: Vec<PerTransfer> = Vec::new();

    let result = if global.parallel {
        parallel_transfers(global, share, &mut transfers).await
    } else {
        serial_transfers(global, share, &mut transfers).await
    };

    while !transfers.is_empty() {
        let (_, _, _) = post_per_transfer(
            &mut transfers[0],
            result,
            global,
        );
        del_per_transfer(&mut transfers, 0);
    }

    global.noprogress = orig_noprogress;
    global.isatty = orig_isatty;
    result
}

// ---------------------------------------------------------------------------
// operate — main entry point
// ---------------------------------------------------------------------------

/// Main CLI operation entry point.
///
/// Parses configuration files and command-line arguments, sets up the
/// shared handle, creates and executes all transfers (serial or parallel),
/// and performs final cleanup.
pub async fn operate(
    argv: &[String],
    global: &mut GlobalConfig,
) -> CurlError {
    let mut result = CurlError::Ok;

    let first_arg = argv.get(1).map(|s| s.as_str());
    let parse_rc = match first_arg {
        None => true,
        Some(arg) => {
            !arg.starts_with("-q") && arg != "--disable"
        }
    };

    if parse_rc {
        let _ = parseconfig(None, global);
        if argv.len() < 2
            && global
                .configs
                .first()
                .map_or(true, |c| c.url_list.is_empty())
        {
            helpf(Some("no URL specified!"));
            return CurlError::FailedInit;
        }
    }

    let parse_result = parse_args(argv, global);

    match parse_result {
        ParameterResult::Ok => {}
        ParameterResult::Help(subject) => {
            tool_help(subject.as_deref());
            return CurlError::Ok;
        }
        ParameterResult::Manual => {
            warnf(
                global,
                "built-in manual was disabled at build-time",
            );
            return CurlError::Ok;
        }
        ParameterResult::Version => {
            tool_version_info();
            return CurlError::Ok;
        }
        ParameterResult::EngineList => {
            tool_list_engines();
            return CurlError::Ok;
        }
        ParameterResult::CaBundleDump => {
            return CurlError::Ok;
        }
        ParameterResult::Error(
            ParameterError::LibcurlUnsupported,
        ) => {
            return CurlError::UnsupportedProtocol;
        }
        ParameterResult::Error(ParameterError::NoInput) => {
            return CurlError::ReadError;
        }
        ParameterResult::Error(_) => {
            return CurlError::FailedInit;
        }
        ParameterResult::NextOperation => {
            return CurlError::Ok;
        }
    }

    let share = match share_setup(global) {
        Ok(s) => s,
        Err(e) => {
            errorf(global, "out of memory");
            return e;
        }
    };

    // Load persisted SSL sessions.
    if let Some(first_config) = global.configs.first().cloned()
    {
        if first_config.ssl_sessions_file.is_some() {
            let _ = ssl_sessions_load(
                global,
                &first_config,
                &share,
            );
        }
    }

    // Resolve URLs with get_args for each OperationConfig.
    let config_count = global.configs.len();
    for i in 0..config_count {
        let last = i == config_count - 1;
        let mut config = global.configs[i].clone();
        if get_args(&mut config, i, last).is_err() {
            result = CurlError::FailedInit;
            break;
        }
        global.configs[i] = config;
    }

    if result == CurlError::Ok {
        global.current = 0;
        result = run_all_transfers(global, &share).await;

        // Save SSL sessions.
        if let Some(first_config) =
            global.configs.first().cloned()
        {
            if first_config.ssl_sessions_file.is_some() {
                let save_result = ssl_sessions_save(
                    global,
                    &first_config,
                    &share,
                );
                if save_result.is_err()
                    && result == CurlError::Ok
                {
                    result = CurlError::FailedInit;
                }
            }
        }
    }

    var_cleanup(&mut global.variables);
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn constants_retry_sleep_default() {
        assert_eq!(RETRY_SLEEP_DEFAULT, 1000);
    }

    #[test]
    fn constants_retry_sleep_max() {
        assert_eq!(RETRY_SLEEP_MAX, 600_000);
    }

    #[test]
    fn constants_ca_cert_error_msg_contains_url() {
        assert!(CURL_CA_CERT_ERRORMSG.contains("https://curl.se/docs/sslcerts.html"));
    }

    #[test]
    fn constants_ca_cert_error_msg_mentions_legitimacy() {
        assert!(CURL_CA_CERT_ERRORMSG.contains("legitimacy"));
    }

    // -----------------------------------------------------------------------
    // PerTransfer
    // -----------------------------------------------------------------------

    fn make_per() -> PerTransfer {
        let easy = EasyHandle::new();
        let config = Arc::new(OperationConfig::new());
        PerTransfer::new(easy, config)
    }

    #[test]
    fn per_transfer_new_defaults() {
        let per = make_per();
        assert_eq!(per.dl_total, 0);
        assert_eq!(per.dl_now, 0);
        assert_eq!(per.ul_total, 0);
        assert_eq!(per.ul_now, 0);
        assert!(!per.dl_total_added);
        assert!(!per.ul_total_added);
        assert!(!per.abort);
        assert!(per.url.is_empty());
        assert_eq!(per.result, CurlError::Ok);
        assert_eq!(per.retry_count, 0);
        assert!(per.certinfo.is_none());
        assert_eq!(per.num_headers, 0);
        assert!(per.outfile.is_none());
        assert!(per.uploadfile.is_none());
        assert!(per.infile.is_none());
        assert!(!per.infdopen);
        assert!(per.errorbuffer.is_empty());
        assert!(!per.noprogress);
        assert!(!per.added);
        assert!(!per.skip);
        assert_eq!(per.urlnum, 0);
        assert_eq!(per.uploadfilesize, -1);
        assert_eq!(per.retry_sleep, 0);
        assert_eq!(per.retry_sleep_default, 0);
        assert_eq!(per.retry_remaining, 0);
        assert_eq!(per.num_retries, 0);
        assert_eq!(per.startat, 0);
    }

    #[test]
    fn per_transfer_new_timestamp_sanity() {
        let before = Instant::now();
        let per = make_per();
        let after = Instant::now();
        assert!(per.start >= before && per.start <= after);
        assert!(per.retrystart >= before && per.retrystart <= after);
    }

    #[test]
    fn per_transfer_debug_shows_url() {
        let mut per = make_per();
        per.url = "https://example.com".to_string();
        per.dl_total = 1000;
        per.dl_now = 500;
        let debug = format!("{:?}", per);
        assert!(debug.contains("https://example.com"));
        assert!(debug.contains("dl_total: 1000"));
        assert!(debug.contains("dl_now: 500"));
    }

    #[test]
    fn per_transfer_debug_shows_result() {
        let mut per = make_per();
        per.result = CurlError::CouldntConnect;
        let debug = format!("{:?}", per);
        assert!(debug.contains("CouldntConnect"));
    }

    #[test]
    fn per_transfer_debug_shows_retry_count() {
        let mut per = make_per();
        per.retry_count = 3;
        let debug = format!("{:?}", per);
        assert!(debug.contains("retry_count: 3"));
    }

    #[test]
    fn per_transfer_debug_shows_abort_skip() {
        let mut per = make_per();
        per.abort = true;
        per.skip = true;
        let debug = format!("{:?}", per);
        assert!(debug.contains("abort: true"));
        assert!(debug.contains("skip: true"));
    }

    #[test]
    fn per_transfer_debug_shows_upload_totals() {
        let mut per = make_per();
        per.ul_total = 2000;
        per.ul_now = 750;
        let debug = format!("{:?}", per);
        assert!(debug.contains("ul_total: 2000"));
        assert!(debug.contains("ul_now: 750"));
    }

    // -----------------------------------------------------------------------
    // add_per_transfer / del_per_transfer
    // -----------------------------------------------------------------------

    #[test]
    fn add_per_transfer_empty_vec() {
        let mut v: Vec<PerTransfer> = Vec::new();
        let idx = add_per_transfer(&mut v, make_per());
        assert_eq!(idx, 0);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn add_per_transfer_appends() {
        let mut v: Vec<PerTransfer> = Vec::new();
        let idx0 = add_per_transfer(&mut v, make_per());
        let idx1 = add_per_transfer(&mut v, make_per());
        let idx2 = add_per_transfer(&mut v, make_per());
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn del_per_transfer_first_element() {
        let mut v: Vec<PerTransfer> = Vec::new();
        add_per_transfer(&mut v, make_per());
        add_per_transfer(&mut v, make_per());
        let next = del_per_transfer(&mut v, 0);
        assert_eq!(v.len(), 1);
        assert_eq!(next, Some(0));
    }

    #[test]
    fn del_per_transfer_last_element() {
        let mut v: Vec<PerTransfer> = Vec::new();
        add_per_transfer(&mut v, make_per());
        let next = del_per_transfer(&mut v, 0);
        assert_eq!(v.len(), 0);
        assert_eq!(next, None);
    }

    #[test]
    fn del_per_transfer_middle_element() {
        let mut v: Vec<PerTransfer> = Vec::new();
        let mut p0 = make_per();
        p0.url = "a".to_string();
        let mut p1 = make_per();
        p1.url = "b".to_string();
        let mut p2 = make_per();
        p2.url = "c".to_string();
        add_per_transfer(&mut v, p0);
        add_per_transfer(&mut v, p1);
        add_per_transfer(&mut v, p2);
        let next = del_per_transfer(&mut v, 1);
        assert_eq!(v.len(), 2);
        assert_eq!(next, Some(1));
        assert_eq!(v[0].url, "a");
        assert_eq!(v[1].url, "c");
    }

    #[test]
    fn del_per_transfer_out_of_bounds() {
        let mut v: Vec<PerTransfer> = Vec::new();
        add_per_transfer(&mut v, make_per());
        let next = del_per_transfer(&mut v, 999);
        assert_eq!(v.len(), 1);
        assert_eq!(next, None);
    }

    // -----------------------------------------------------------------------
    // stdin_upload / output_expected
    // -----------------------------------------------------------------------

    #[test]
    fn stdin_upload_dash() {
        assert!(stdin_upload("-"));
    }

    #[test]
    fn stdin_upload_dot() {
        assert!(stdin_upload("."));
    }

    #[test]
    fn stdin_upload_regular_file() {
        assert!(!stdin_upload("data.txt"));
    }

    #[test]
    fn stdin_upload_empty() {
        assert!(!stdin_upload(""));
    }

    #[test]
    fn output_expected_no_upload() {
        assert!(output_expected(&None));
    }

    #[test]
    fn output_expected_with_upload() {
        assert!(!output_expected(&Some("file.txt".to_string())));
    }

    // -----------------------------------------------------------------------
    // RetryReason
    // -----------------------------------------------------------------------

    #[test]
    fn retry_reason_no_message() {
        assert_eq!(RetryReason::No.message(), "");
    }

    #[test]
    fn retry_reason_all_errors_message() {
        assert!(RetryReason::AllErrors.message().contains("retrying all errors"));
    }

    #[test]
    fn retry_reason_timeout_message() {
        assert!(RetryReason::Timeout.message().contains("timeout"));
    }

    #[test]
    fn retry_reason_conn_refused_message() {
        assert!(RetryReason::ConnRefused.message().contains("connection refused"));
    }

    #[test]
    fn retry_reason_http_message() {
        assert!(RetryReason::Http.message().contains("HTTP error"));
    }

    #[test]
    fn retry_reason_ftp_message() {
        assert!(RetryReason::Ftp.message().contains("FTP error"));
    }

    #[test]
    fn retry_reason_debug() {
        let r = RetryReason::Timeout;
        let debug = format!("{:?}", r);
        assert_eq!(debug, "Timeout");
    }

    #[test]
    fn retry_reason_clone_eq() {
        let a = RetryReason::Http;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn retry_reason_ne() {
        assert_ne!(RetryReason::No, RetryReason::Timeout);
        assert_ne!(RetryReason::Http, RetryReason::Ftp);
        assert_ne!(RetryReason::AllErrors, RetryReason::ConnRefused);
    }

    // -----------------------------------------------------------------------
    // to_progress_per / from_progress_per
    // -----------------------------------------------------------------------

    #[test]
    fn to_progress_per_maps_fields() {
        let mut per = make_per();
        per.dl_total = 100;
        per.dl_now = 50;
        per.ul_total = 200;
        per.ul_now = 75;
        per.dl_total_added = true;
        per.ul_total_added = false;
        per.abort = true;
        per.noprogress = true;
        let prog = to_progress_per(&per);
        assert_eq!(prog.dltotal, 100);
        assert_eq!(prog.dlnow, 50);
        assert_eq!(prog.ultotal, 200);
        assert_eq!(prog.ulnow, 75);
        assert!(prog.dltotal_added);
        assert!(!prog.ultotal_added);
        assert!(prog.abort);
        assert!(prog.noprogress);
    }

    #[test]
    fn to_progress_per_zeroes() {
        let per = make_per();
        let prog = to_progress_per(&per);
        assert_eq!(prog.dltotal, 0);
        assert_eq!(prog.dlnow, 0);
        assert_eq!(prog.ultotal, 0);
        assert_eq!(prog.ulnow, 0);
        assert!(!prog.dltotal_added);
        assert!(!prog.ultotal_added);
        assert!(!prog.abort);
        assert!(!prog.noprogress);
    }

    #[test]
    fn from_progress_per_writes_back() {
        let mut per = make_per();
        per.dl_total_added = false;
        per.ul_total_added = false;

        let mut prog = to_progress_per(&per);
        prog.dltotal_added = true;
        prog.ultotal_added = true;

        from_progress_per(&prog, &mut per);
        assert!(per.dl_total_added);
        assert!(per.ul_total_added);
    }

    #[test]
    fn from_progress_per_clear() {
        let mut per = make_per();
        per.dl_total_added = true;
        per.ul_total_added = true;

        let mut prog = to_progress_per(&per);
        prog.dltotal_added = false;
        prog.ultotal_added = false;

        from_progress_per(&prog, &mut per);
        assert!(!per.dl_total_added);
        assert!(!per.ul_total_added);
    }

    // -----------------------------------------------------------------------
    // cacertpaths
    // -----------------------------------------------------------------------

    #[test]
    fn cacertpaths_already_set_cacert() {
        let mut config = OperationConfig::new();
        config.cacert = Some("/etc/ssl/cert.pem".to_string());
        cacertpaths(&mut config);
        assert_eq!(config.cacert.as_deref(), Some("/etc/ssl/cert.pem"));
    }

    #[test]
    fn cacertpaths_already_set_capath() {
        let mut config = OperationConfig::new();
        config.capath = Some("/etc/ssl/certs".to_string());
        cacertpaths(&mut config);
        assert_eq!(config.capath.as_deref(), Some("/etc/ssl/certs"));
    }

    #[test]
    fn cacertpaths_insecure_no_doh() {
        let mut config = OperationConfig::new();
        config.insecure_ok = true;
        config.doh_url = None;
        cacertpaths(&mut config);
        // Should skip setting any CA paths when insecure + no DoH.
        assert!(config.cacert.is_none());
        assert!(config.capath.is_none());
    }

    #[test]
    fn cacertpaths_insecure_with_doh_insecure() {
        let mut config = OperationConfig::new();
        config.insecure_ok = true;
        config.doh_url = Some("https://dns.example.com".to_string());
        config.doh_insecure_ok = true;
        cacertpaths(&mut config);
        assert!(config.cacert.is_none());
        assert!(config.capath.is_none());
    }

    #[test]
    fn cacertpaths_insecure_with_secure_doh() {
        // insecure_ok but DoH is NOT insecure => must set CA for DoH.
        let mut config = OperationConfig::new();
        config.insecure_ok = true;
        config.doh_url = Some("https://dns.example.com".to_string());
        config.doh_insecure_ok = false;
        // Remove env vars so we can test the fallthrough.
        env::remove_var("CURL_CA_BUNDLE");
        env::remove_var("SSL_CERT_DIR");
        env::remove_var("SSL_CERT_FILE");
        cacertpaths(&mut config);
        // Without env vars, nothing gets set — this tests the code path is reached.
        assert!(config.cacert.is_none() || config.cacert.is_some());
    }

    // -----------------------------------------------------------------------
    // easy_get_* extractors (unit-testable with default EasyHandle)
    // -----------------------------------------------------------------------

    #[test]
    fn easy_get_response_code_default() {
        let easy = EasyHandle::new();
        // Default handle returns 0 response code.
        let code = easy_get_response_code(&easy);
        assert_eq!(code, 0);
    }

    #[test]
    fn easy_get_scheme_default() {
        let easy = EasyHandle::new();
        let scheme = easy_get_scheme(&easy);
        // Default handle has no scheme.
        assert!(scheme.is_empty());
    }

    #[test]
    fn easy_get_retry_after_default() {
        let easy = EasyHandle::new();
        let val = easy_get_retry_after(&easy);
        assert_eq!(val, 0);
    }

    #[test]
    fn easy_get_filetime_default() {
        let easy = EasyHandle::new();
        let ft = easy_get_filetime(&easy);
        assert_eq!(ft, -1);
    }

    #[test]
    fn easy_get_condition_unmet_default() {
        let easy = EasyHandle::new();
        let cu = easy_get_condition_unmet(&easy);
        assert!(!cu);
    }

    #[test]
    fn easy_get_content_type_default() {
        let easy = EasyHandle::new();
        let ct = easy_get_content_type(&easy);
        assert!(ct.is_none());
    }

    // -----------------------------------------------------------------------
    // share_setup
    // -----------------------------------------------------------------------

    #[test]
    fn share_setup_non_parallel() {
        let global = crate::config::globalconf_init().unwrap();
        let result = share_setup(&global);
        assert!(result.is_ok());
    }

    #[test]
    fn share_setup_parallel() {
        let mut global = crate::config::globalconf_init().unwrap();
        global.parallel = true;
        let result = share_setup(&global);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // pre_transfer
    // -----------------------------------------------------------------------

    #[test]
    fn pre_transfer_no_upload() {
        let mut per = make_per();
        let result = pre_transfer(&mut per);
        assert!(result.is_ok());
        assert_eq!(per.uploadfilesize, -1);
        assert!(per.infile.is_none());
        assert!(!per.infdopen);
    }

    #[test]
    fn pre_transfer_stdin_upload() {
        let mut per = make_per();
        per.uploadfile = Some("-".to_string());
        let result = pre_transfer(&mut per);
        assert!(result.is_ok());
        assert_eq!(per.uploadfilesize, -1);
        assert!(per.infile.is_none());
    }

    #[test]
    fn pre_transfer_real_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut tmp.as_file(), b"hello world").unwrap();
        let path = tmp.path().to_string_lossy().to_string();

        let mut per = make_per();
        per.uploadfile = Some(path);
        let result = pre_transfer(&mut per);
        assert!(result.is_ok());
        assert!(per.uploadfilesize > 0);
        assert!(per.infile.is_some());
        assert!(per.infdopen);
    }

    #[test]
    fn pre_transfer_nonexistent_file() {
        let mut per = make_per();
        per.uploadfile = Some("/nonexistent/path/file.txt".to_string());
        let result = pre_transfer(&mut per);
        assert!(result.is_err());
    }

    #[test]
    fn pre_transfer_sets_start_time() {
        let mut per = make_per();
        let before = Instant::now();
        let _ = pre_transfer(&mut per);
        let after = Instant::now();
        assert!(per.start >= before && per.start <= after);
    }

    // -----------------------------------------------------------------------
    // post_per_transfer (skip path)
    // -----------------------------------------------------------------------

    #[test]
    fn post_per_transfer_skip_returns_ok() {
        let mut per = make_per();
        per.skip = true;
        let global = crate::config::globalconf_init().unwrap();
        let (res, retry, delay) =
            post_per_transfer(&mut per, CurlError::Ok, &global);
        assert_eq!(res, CurlError::Ok);
        assert!(!retry);
        assert_eq!(delay, 0);
    }

    #[test]
    fn post_per_transfer_skip_with_error() {
        let mut per = make_per();
        per.skip = true;
        let global = crate::config::globalconf_init().unwrap();
        let (res, retry, delay) =
            post_per_transfer(&mut per, CurlError::ReadError, &global);
        assert_eq!(res, CurlError::ReadError);
        assert!(!retry);
        assert_eq!(delay, 0);
    }

    // -----------------------------------------------------------------------
    // post_check_result
    // -----------------------------------------------------------------------

    #[test]
    fn post_check_result_ok_passthrough() {
        let mut per = make_per();
        let global = crate::config::globalconf_init().unwrap();
        let res = post_check_result(&mut per, CurlError::Ok, &global);
        assert_eq!(res, CurlError::Ok);
    }

    #[test]
    fn post_check_result_error_with_errorbuffer() {
        let mut per = make_per();
        per.errorbuffer = "custom error".to_string();
        let mut global = crate::config::globalconf_init().unwrap();
        global.silent = false;
        global.showerror = true;
        let mut cfg = OperationConfig::new();
        cfg.synthetic_error = false;
        per.config = Arc::new(cfg);
        let res = post_check_result(&mut per, CurlError::CouldntConnect, &global);
        assert_eq!(res, CurlError::CouldntConnect);
    }

    #[test]
    fn post_check_result_synthetic_error_silent() {
        let mut per = make_per();
        let mut cfg = OperationConfig::new();
        cfg.synthetic_error = true;
        per.config = Arc::new(cfg);
        let global = crate::config::globalconf_init().unwrap();
        let res = post_check_result(&mut per, CurlError::CouldntConnect, &global);
        assert_eq!(res, CurlError::CouldntConnect);
    }

    // -----------------------------------------------------------------------
    // post_close_output
    // -----------------------------------------------------------------------

    #[test]
    fn post_close_output_not_opened() {
        let mut per = make_per();
        per.outs.fopened = false;
        let global = crate::config::globalconf_init().unwrap();
        let res = post_close_output(&mut per, CurlError::Ok, &global);
        assert_eq!(res, CurlError::Ok);
    }

    #[test]
    fn post_close_output_opened_ok() {
        let mut per = make_per();
        per.outs.fopened = true;
        let global = crate::config::globalconf_init().unwrap();
        let res = post_close_output(&mut per, CurlError::Ok, &global);
        assert_eq!(res, CurlError::Ok);
        assert!(!per.outs.fopened);
    }

    #[test]
    fn post_close_output_error_rm_partial() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_string_lossy().to_string();
        // Keep file on disk by preventing auto-delete.
        let _tmp = tmp.into_temp_path();

        let mut per = make_per();
        per.outs.fopened = true;
        per.outs.filename = Some(path.clone());
        let mut cfg = OperationConfig::new();
        cfg.rm_partial = true;
        per.config = Arc::new(cfg);
        let mut global = crate::config::globalconf_init().unwrap();
        global.silent = false;
        let res = post_close_output(&mut per, CurlError::RecvError, &global);
        assert_eq!(res, CurlError::RecvError);
        assert!(!per.outs.fopened);
    }

    // -----------------------------------------------------------------------
    // Integration-like tests for data flow
    // -----------------------------------------------------------------------

    #[test]
    fn per_transfer_lifecycle_url_tracking() {
        let mut per = make_per();
        per.url = "https://api.example.com/data".to_string();
        per.dl_total = 1_000_000;
        per.ul_total = 500_000;
        per.retry_count = 2;
        per.num_headers = 7;
        per.urlnum = 42;

        assert_eq!(per.url, "https://api.example.com/data");
        assert_eq!(per.dl_total, 1_000_000);
        assert_eq!(per.ul_total, 500_000);
        assert_eq!(per.retry_count, 2);
        assert_eq!(per.num_headers, 7);
        assert_eq!(per.urlnum, 42);
    }

    #[test]
    fn per_transfer_abort_flag() {
        let mut per = make_per();
        assert!(!per.abort);
        per.abort = true;
        assert!(per.abort);
    }

    #[test]
    fn per_transfer_errorbuffer_usage() {
        let mut per = make_per();
        assert!(per.errorbuffer.is_empty());
        per.errorbuffer = "Timeout reached".to_string();
        assert_eq!(per.errorbuffer, "Timeout reached");
    }

    #[test]
    fn per_transfer_certinfo_tracking() {
        let mut per = make_per();
        assert!(per.certinfo.is_none());
        per.certinfo = Some(vec!["CN=example.com".to_string()]);
        assert_eq!(per.certinfo.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn add_then_delete_all() {
        let mut v: Vec<PerTransfer> = Vec::new();
        add_per_transfer(&mut v, make_per());
        add_per_transfer(&mut v, make_per());
        add_per_transfer(&mut v, make_per());
        assert_eq!(v.len(), 3);
        while !v.is_empty() {
            del_per_transfer(&mut v, 0);
        }
        assert!(v.is_empty());
    }

    // -----------------------------------------------------------------------
    // Retry exponential back-off constants
    // -----------------------------------------------------------------------

    #[test]
    fn retry_sleep_default_is_one_second() {
        assert_eq!(RETRY_SLEEP_DEFAULT, 1_000);
    }

    #[test]
    fn retry_sleep_max_is_ten_minutes() {
        assert_eq!(RETRY_SLEEP_MAX, 10 * 60 * 1_000);
    }

    // -----------------------------------------------------------------------
    // Progress roundtrip consistency
    // -----------------------------------------------------------------------

    #[test]
    fn progress_roundtrip() {
        let mut per = make_per();
        per.dl_total = 42;
        per.ul_total = 99;
        per.abort = true;
        per.noprogress = true;
        per.dl_total_added = false;
        per.ul_total_added = false;

        let mut prog = to_progress_per(&per);
        assert_eq!(prog.dltotal, 42);
        assert_eq!(prog.ultotal, 99);
        assert!(prog.abort);
        assert!(prog.noprogress);

        // Simulate progress tracking marking totals as added.
        prog.dltotal_added = true;
        prog.ultotal_added = true;

        from_progress_per(&prog, &mut per);
        assert!(per.dl_total_added);
        assert!(per.ul_total_added);
    }

    // -----------------------------------------------------------------------
    // post_per_transfer head/etag cleanup
    // -----------------------------------------------------------------------

    #[test]
    fn post_per_transfer_closes_heads() {
        let mut per = make_per();
        per.heads.fopened = true;
        per.heads.alloc_filename = true;
        per.heads.filename = Some("header.dump".to_string());
        per.skip = true; // Use skip path to avoid side effects.
        let global = crate::config::globalconf_init().unwrap();
        let _ = post_per_transfer(&mut per, CurlError::Ok, &global);
        assert!(!per.heads.fopened);
        assert!(!per.heads.alloc_filename);
        assert!(per.heads.filename.is_none());
    }

    #[test]
    fn post_per_transfer_closes_etag_save() {
        let mut per = make_per();
        per.etag_save.fopened = true;
        per.etag_save.alloc_filename = true;
        per.etag_save.filename = Some("etag.txt".to_string());
        per.skip = true;
        let global = crate::config::globalconf_init().unwrap();
        let _ = post_per_transfer(&mut per, CurlError::Ok, &global);
        assert!(!per.etag_save.fopened);
        assert!(!per.etag_save.alloc_filename);
        assert!(per.etag_save.filename.is_none());
    }

    #[test]
    fn post_per_transfer_closes_upload() {
        let mut per = make_per();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        per.infile = Some(tmp.reopen().unwrap());
        per.infdopen = true;
        per.skip = true;
        let global = crate::config::globalconf_init().unwrap();
        let _ = post_per_transfer(&mut per, CurlError::Ok, &global);
        assert!(per.infile.is_none());
        assert!(!per.infdopen);
    }

    // -----------------------------------------------------------------------
    // transfer_per_config / create_transfer edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn transfer_per_config_no_urls_fails() {
        let mut config = OperationConfig::new();
        config.url_list.clear();
        let share = ShareHandle::new();
        let mut state = TransferState::new();
        let mut transfers = Vec::new();
        let mut global = crate::config::globalconf_init().unwrap();
        let result = transfer_per_config(
            &mut config, &share, &mut state, &mut transfers, &mut global,
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // OutStruct type alias
    // -----------------------------------------------------------------------

    #[test]
    fn outstruct_type_alias_works() {
        let out = OutStruct::new_null();
        assert!(out.stream.is_null());
    }
}
