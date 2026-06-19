#![forbid(unsafe_code)]
//! `CURLOPT_SEEKFUNCTION` seek callback — the memory-safe Rust port of curl's
//! `src/tool_cb_see.c`.
//!
//! # Role
//!
//! libcurl invokes a transfer's seek callback whenever it must **rewind or
//! reposition the upload input** before (re)sending body data — for example on
//! an HTTP redirect that replays the request, on an authentication retry, or
//! when resuming a ranged upload (`--continue-at`). The CLI registers
//! [`tool_seek_cb`] for this purpose (curl's `CURLOPT_SEEKFUNCTION`), with the
//! per-transfer record ([`crate::operate::PerTransfer`]) as the callback's
//! user data.
//!
//! # Return contract
//!
//! This callback **never returns the resulting file offset**; it returns *only*
//! a `CURL_SEEKFUNC_*` status code, exactly as the C original documents
//! (`src/tool_cb_see.c:31-35`):
//!
//! * [`CURL_SEEKFUNC_OK`] — the seek succeeded.
//! * [`CURL_SEEKFUNC_FAIL`] — fail the whole transfer.
//! * [`CURL_SEEKFUNC_CANTSEEK`] — this input cannot be sought; libcurl is free
//!   to work around it by other means (e.g. by re-reading from the start).
//!
//! # Design notes (deviations from the C original, all memory-safety driven)
//!
//! * **No raw file descriptor.** The C callback seeks `per->infd` with
//!   `curl_lseek` (a thin `lseek` wrapper). Here the upload source is the typed,
//!   owned [`Option<File>`](std::fs::File) held in
//!   [`PerTransfer::infile`](crate::operate::PerTransfer::infile); the seek goes
//!   through the safe [`Seek`] trait. When there is no seekable source — stdin
//!   or a pipe, where C had an `infd` that `lseek` would reject — the field is
//!   [`None`] and the callback returns [`CURL_SEEKFUNC_CANTSEEK`], so libcurl
//!   falls back exactly as curl 8.x does for a non-seekable input.
//!
//! * **Error maps to `CANTSEEK`, not `FAIL`.** A failed seek returns
//!   [`CURL_SEEKFUNC_CANTSEEK`] rather than [`CURL_SEEKFUNC_FAIL`]. This is
//!   deliberate and matches the C comment (`src/tool_cb_see.c:80-83`): the exact
//!   `errno` is not portable and not interesting, so the tool lets libcurl
//!   attempt other recovery strategies instead of hard-failing the transfer.
//!
//! * **The 32-bit `off_t` workaround is omitted.** The bulk of the C file
//!   (`src/tool_cb_see.c:41-77`) is a legacy guard for platforms where
//!   `curl_off_t` is 64-bit but the system `off_t` is only 32-bit: it rewinds
//!   and then seeks forward in `≤ 2 GiB - 2` byte steps. Rust's [`Seek`] is
//!   natively 64-bit (`i64`/`u64`), so a single [`Seek::seek`] spans the full
//!   range and the workaround is unnecessary. That block is also the only place
//!   the C code ever returns [`CURL_SEEKFUNC_FAIL`]; the constant is preserved
//!   here for ABI/contract completeness even though this port never returns it.
//!
//! # Integration
//!
//! [`tool_seek_cb`] is registered by the operation driver
//! ([`crate::operate`]) against `curl_rs_lib`'s `Easy` seek-function setter
//! (curl's `gen_cb_setopts` programs `CURLOPT_SEEKDATA`/`CURLOPT_SEEKFUNCTION`).
//! Until that wiring lands, the surrounding `callbacks` module is staged behind
//! `#![allow(dead_code)]` — see `callbacks/mod.rs`.

use std::io::{Seek, SeekFrom};

use crate::operate::PerTransfer;

// ===========================================================================
// CURL_SEEKFUNC_* return codes
// ===========================================================================
//
// These mirror the libcurl public constants of the same name (see
// `include/curl/curl.h`). `curl_rs_lib` does not currently re-export them, so
// they are defined here exactly as curl defines them; the integer values are
// part of the observable contract a seek callback must honor.

/// Seek succeeded — libcurl may proceed with the (re)send. curl's
/// `CURL_SEEKFUNC_OK`.
pub const CURL_SEEKFUNC_OK: i32 = 0;

/// Fail the entire transfer. curl's `CURL_SEEKFUNC_FAIL`.
///
/// In the C tool this is returned only from the legacy 32-bit `off_t`
/// workaround (`src/tool_cb_see.c:62,66,72`), which this port omits because
/// Rust's [`Seek`] is natively 64-bit. It is defined here for contract
/// completeness; [`tool_seek_cb`] never returns it.
pub const CURL_SEEKFUNC_FAIL: i32 = 1;

/// The input cannot be sought; libcurl may work around it by other means (for
/// instance by re-reading from the beginning). curl's `CURL_SEEKFUNC_CANTSEEK`.
pub const CURL_SEEKFUNC_CANTSEEK: i32 = 2;

// ===========================================================================
// `whence` origin selectors (the libc `SEEK_*` constants)
// ===========================================================================
//
// libcurl passes the standard C `whence` values straight through to the seek
// callback. They are the universal POSIX/libc constants (verified against
// `/usr/include/fcntl.h`): SEEK_SET = 0, SEEK_CUR = 1, SEEK_END = 2.

/// Seek relative to the start of the input (libc `SEEK_SET`).
const SEEK_SET: i32 = 0;
/// Seek relative to the current position (libc `SEEK_CUR`).
const SEEK_CUR: i32 = 1;
/// Seek relative to the end of the input (libc `SEEK_END`).
const SEEK_END: i32 = 2;

/// `CURLOPT_SEEKFUNCTION` callback — reposition the upload input for this
/// transfer.
///
/// Port of `tool_seek_cb` (`src/tool_cb_see.c:37-85`). The C signature is
/// `int tool_seek_cb(void *userdata, curl_off_t offset, int whence)`; in this
/// safe crate the opaque `userdata` is the typed [`PerTransfer`] record and the
/// `curl_off_t` offset is a plain [`i64`].
///
/// # Parameters
///
/// * `per` — the per-transfer record (curl's `per`); its
///   [`infile`](PerTransfer::infile) is the seekable upload source.
/// * `offset` — the byte offset to seek to, interpreted relative to `whence`.
/// * `whence` — the origin: `SEEK_SET` (0), `SEEK_CUR` (1), or `SEEK_END` (2).
///
/// # Returns
///
/// One of [`CURL_SEEKFUNC_OK`] or [`CURL_SEEKFUNC_CANTSEEK`] — never the
/// resulting offset (the seek-callback contract). A missing/non-seekable input,
/// an unrecognized `whence`, or a failed seek all yield
/// [`CURL_SEEKFUNC_CANTSEEK`] so libcurl can fall back to other means.
pub fn tool_seek_cb(per: &mut PerTransfer, offset: i64, whence: i32) -> i32 {
    // NOTE: C 32-bit off_t large-seek workaround is unnecessary in Rust (Seek
    // is 64-bit). The single `seek` below covers the full `i64`/`u64` range.
    seek_input(per.infile.as_mut(), offset, whence)
}

/// Performs the actual seek on an optional seekable upload source.
///
/// This is the safe analog of the C tool's `curl_lseek(per->infd, offset,
/// whence)`. It is factored out of [`tool_seek_cb`] — and made generic over any
/// [`Seek`] source — so the seek logic can be exercised directly by unit tests
/// (a full [`PerTransfer`] is not constructible outside its owning module),
/// while production code instantiates it for [`std::fs::File`].
///
/// Returns [`CURL_SEEKFUNC_CANTSEEK`] when there is no input, when `whence` is
/// not one of `SEEK_SET`/`SEEK_CUR`/`SEEK_END`, or when the seek fails;
/// otherwise [`CURL_SEEKFUNC_OK`].
fn seek_input<S: Seek>(input: Option<&mut S>, offset: i64, whence: i32) -> i32 {
    // No seekable source (stdin / a pipe / no upload): C would have an `infd`
    // that `lseek` rejects; we report CANTSEEK so libcurl works around it.
    let Some(input) = input else {
        return CURL_SEEKFUNC_CANTSEEK;
    };

    // Translate curl's libc `whence` into the typed `SeekFrom`. SEEK_SET takes
    // an absolute (non-negative) position, hence the `u64`; SEEK_CUR/SEEK_END
    // accept signed relative offsets. An unrecognized `whence` is treated like
    // an `lseek` EINVAL → CANTSEEK.
    let seek_from = match whence {
        SEEK_SET => SeekFrom::Start(offset as u64),
        SEEK_CUR => SeekFrom::Current(offset),
        SEEK_END => SeekFrom::End(offset),
        _ => return CURL_SEEKFUNC_CANTSEEK,
    };

    match input.seek(seek_from) {
        Ok(_) => CURL_SEEKFUNC_OK,
        // The reason lives in `errno`, but it is neither portable nor important
        // here (mirrors `src/tool_cb_see.c:80-83`): let libcurl try other means.
        Err(_) => CURL_SEEKFUNC_CANTSEEK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    /// The `CURL_SEEKFUNC_*` values are an observable contract and must equal
    /// curl's: OK = 0, FAIL = 1, CANTSEEK = 2.
    #[test]
    fn seekfunc_constants_match_libcurl() {
        assert_eq!(CURL_SEEKFUNC_OK, 0);
        assert_eq!(CURL_SEEKFUNC_FAIL, 1);
        assert_eq!(CURL_SEEKFUNC_CANTSEEK, 2);
    }

    /// `SEEK_SET` rewinds a regular, seekable input — the redirect/resume case.
    #[test]
    fn seek_set_rewinds_to_start() {
        let mut cur = Cursor::new(b"hello world".to_vec());
        // Advance to the end so the rewind is observable.
        cur.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(seek_input(Some(&mut cur), 0, SEEK_SET), CURL_SEEKFUNC_OK);
        assert_eq!(cur.position(), 0);
    }

    /// `SEEK_SET` can also seek to a non-zero absolute resume position.
    #[test]
    fn seek_set_to_absolute_offset() {
        let mut cur = Cursor::new(b"hello world".to_vec());
        assert_eq!(seek_input(Some(&mut cur), 6, SEEK_SET), CURL_SEEKFUNC_OK);
        assert_eq!(cur.position(), 6);
    }

    /// `SEEK_CUR` moves relative to the current position with a signed offset.
    #[test]
    fn seek_cur_moves_relative() {
        let mut cur = Cursor::new(b"hello world".to_vec());
        cur.seek(SeekFrom::Start(4)).unwrap();
        assert_eq!(seek_input(Some(&mut cur), 3, SEEK_CUR), CURL_SEEKFUNC_OK);
        assert_eq!(cur.position(), 7);
    }

    /// `SEEK_END` with a negative offset positions relative to the end.
    #[test]
    fn seek_end_from_end() {
        let data = b"hello world".to_vec();
        let len = data.len() as u64;
        let mut cur = Cursor::new(data);
        assert_eq!(seek_input(Some(&mut cur), -2, SEEK_END), CURL_SEEKFUNC_OK);
        assert_eq!(cur.position(), len - 2);
    }

    /// No seekable input (stdin / pipe / no upload) yields `CANTSEEK`, so
    /// libcurl falls back — matching curl 8.x.
    #[test]
    fn missing_input_yields_cantseek() {
        let none: Option<&mut Cursor<Vec<u8>>> = None;
        assert_eq!(seek_input(none, 0, SEEK_SET), CURL_SEEKFUNC_CANTSEEK);
    }

    /// An unrecognized `whence` is treated like an `lseek` EINVAL → `CANTSEEK`.
    #[test]
    fn unknown_whence_yields_cantseek() {
        let mut cur = Cursor::new(b"hello world".to_vec());
        assert_eq!(seek_input(Some(&mut cur), 0, 99), CURL_SEEKFUNC_CANTSEEK);
    }

    /// A seek that fails (here, to a negative resulting position) yields
    /// `CANTSEEK`, never `FAIL`.
    #[test]
    fn failed_seek_yields_cantseek() {
        // Cursor at position 0; seeking back 100 bytes is an invalid (negative)
        // position and returns an error from `Seek::seek`.
        let mut cur = Cursor::new(b"short".to_vec());
        assert_eq!(
            seek_input(Some(&mut cur), -100, SEEK_CUR),
            CURL_SEEKFUNC_CANTSEEK
        );
    }

    /// The production path uses a real [`std::fs::File`]; verify a rewind on an
    /// actual on-disk upload source works end-to-end and the next read sees the
    /// rewound bytes.
    #[test]
    fn seek_set_rewinds_real_file() {
        let mut file = tempfile::tempfile().expect("create temp file");
        file.write_all(b"upload body").expect("write");
        // Writing left the cursor at EOF; rewinding to the start must succeed.
        assert_eq!(seek_input(Some(&mut file), 0, SEEK_SET), CURL_SEEKFUNC_OK);
        let mut buf = [0u8; 6];
        file.read_exact(&mut buf).expect("read after rewind");
        assert_eq!(&buf, b"upload");
    }

    /// Every code this callback can return is one of the three legal
    /// `CURL_SEEKFUNC_*` values — never a resulting offset.
    #[test]
    fn only_returns_seekfunc_codes() {
        let legal = [CURL_SEEKFUNC_OK, CURL_SEEKFUNC_FAIL, CURL_SEEKFUNC_CANTSEEK];

        let mut ok_cur = Cursor::new(b"hello world".to_vec());
        let ok = seek_input(Some(&mut ok_cur), 0, SEEK_SET);

        let none: Option<&mut Cursor<Vec<u8>>> = None;
        let cantseek = seek_input(none, 0, SEEK_SET);

        let mut bad_cur = Cursor::new(b"x".to_vec());
        let bad_whence = seek_input(Some(&mut bad_cur), 0, 42);

        for code in [ok, cantseek, bad_whence] {
            assert!(legal.contains(&code), "unexpected return code {code}");
        }
    }
}
