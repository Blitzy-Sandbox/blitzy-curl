//! Growable dynamic byte buffer — the Rust rewrite of libcurl's
//! `lib/curlx/dynbuf.c` / `lib/curlx/dynbuf.h`.
//!
//! [`DynBuf`] is curl's ubiquitous append-only growable buffer (`struct dynbuf`
//! in C). It accumulates bytes — request/response headers, request bodies, DoH
//! responses, proxy `CONNECT` headers, trailers, command pipelines, and so on —
//! while enforcing a per-buffer maximum size (`toobig`). Any append that would
//! grow the buffer past that ceiling fails with [`CurlError::TooLarge`]
//! (`CURLE_TOO_LARGE`), exactly as the C implementation does, and — matching the
//! C behavior — the buffer is *freed* on that failure.
//!
//! # Relationship to the C oracle
//!
//! This is a *behavioral* re-implementation, not a line-by-line transliteration.
//! The externally observable contract is preserved precisely:
//!
//! * The current length ([`DynBuf::curlx_dyn_len`]) **excludes** the trailing
//!   NUL. C keeps the underlying allocation NUL-terminated so that
//!   [`curlx_dyn_ptr`](DynBuf::curlx_dyn_ptr) can be handed to C string APIs;
//!   we store only the data bytes in a [`Vec<u8>`] and expose
//!   [`to_nul_terminated`](DynBuf::to_nul_terminated) for the rare consumer that
//!   genuinely needs a C string. The capacity-check arithmetic still reserves
//!   the one extra NUL byte (`new + old + 1`) so the size at which an append is
//!   rejected is identical to curl.
//! * On a cap breach the buffer is freed and `CURLE_TOO_LARGE` is returned (C's
//!   `dyn_nappend` calls `curlx_dyn_free` before returning the error).
//! * [`curlx_dyn_free`](DynBuf::curlx_dyn_free) releases the allocation but keeps
//!   the `toobig` limit so the same buffer can be reused.
//! * [`curlx_dyn_reset`](DynBuf::curlx_dyn_reset) sets the length to zero while
//!   retaining the existing allocation.
//! * [`curlx_dyn_take`](DynBuf::curlx_dyn_take) detaches the owned bytes and
//!   leaves the buffer empty — the Rust equivalent of C handing ownership of the
//!   `malloc`'d pointer to the caller.
//!
//! # Memory safety (AAP §0.7.1)
//!
//! The buffer is backed by a [`Vec<u8>`]; there is **no** manual `realloc` or
//! pointer arithmetic and the module contains **zero** `unsafe`. It compiles
//! cleanly under the crate-root `#![forbid(unsafe_code)]`. Growth is delegated
//! to `Vec`, and overflow of the size computation is handled with checked
//! arithmetic (an overflowing request is, by definition, larger than any legal
//! `toobig` and is rejected with `CURLE_TOO_LARGE`).
//!
//! # Dependency direction (no cycle with `mprintf`)
//!
//! The formatted-append helpers ([`curlx_dyn_addf`](DynBuf::curlx_dyn_addf) /
//! [`curlx_dyn_vaddf`](DynBuf::curlx_dyn_vaddf)) render through
//! [`crate::util::mprintf`] and then append the result. The edge therefore runs
//! `dynbuf -> mprintf`; `mprintf` never depends on `dynbuf`, keeping `mprintf` a
//! leaf and avoiding a dependency cycle.

use crate::error::{CurlError, Result};
use crate::util::mprintf::{maprintf, FmtArg};

// ===========================================================================
// Size ceilings
// ===========================================================================

/// Absolute ceiling for any dynamic buffer (`#define MAX_DYNBUF_SIZE
/// (SIZE_MAX / 2)` in `dynbuf.h`).
///
/// Every `toobig` passed to [`DynBuf::new`] is expected to be `<=` this value;
/// the value is also enforced at append time so the buffer can never be asked
/// to grow past it regardless of the configured `toobig`.
pub const MAX_DYNBUF_SIZE: usize = usize::MAX / 2;

// ---------------------------------------------------------------------------
// Named per-use caps (verbatim values from `dynbuf.h`).
//
// These are the exact size limits curl assigns to each distinct use of a
// dynbuf. They are reproduced here with identical names (including the upstream
// `DYN_PINGPPONG_CMD` spelling) and identical values so that the ported
// subsystems request the same ceilings as curl 8.x.
// ---------------------------------------------------------------------------

/// Maximum size of a buffered DoH (DNS-over-HTTPS) response.
pub const DYN_DOH_RESPONSE: usize = 3000;
/// Maximum size of a CNAME accumulated while following a DoH chain.
pub const DYN_DOH_CNAME: usize = 256;
/// Maximum size of the transfer pause buffer (64 MiB).
pub const DYN_PAUSE_BUFFER: usize = 64 * 1024 * 1024;
/// Maximum size of a buffered HAProxy PROXY protocol header.
pub const DYN_HAXPROXY: usize = 2048;
/// Maximum size of an assembled HTTP request (1 MiB).
pub const DYN_HTTP_REQUEST: usize = 1024 * 1024;
/// Maximum size produced by the allocating printf family (`curl_maprintf`).
pub const DYN_APRINTF: usize = 8_000_000;
/// Maximum size of an assembled RTSP request header block (64 KiB).
pub const DYN_RTSP_REQ_HEADER: usize = 64 * 1024;
/// Maximum size of accumulated HTTP trailers (64 KiB).
pub const DYN_TRAILERS: usize = 64 * 1024;
/// Maximum size of buffered proxy `CONNECT` response headers.
pub const DYN_PROXY_CONNECT_HEADERS: usize = 16384;
/// Maximum length of a generated qlog file name.
pub const DYN_QLOG_NAME: usize = 1024;
/// Maximum size of a single HTTP/1 trailer line.
pub const DYN_H1_TRAILER: usize = 4096;
/// Maximum size of a pingpong (FTP/IMAP/POP3/SMTP) command line (64 KiB).
///
/// The `PINGPPONG` spelling is preserved verbatim from upstream curl's header.
pub const DYN_PINGPPONG_CMD: usize = 64 * 1024;
/// Maximum size of an assembled IMAP command (64 KiB).
pub const DYN_IMAP_CMD: usize = 64 * 1024;
/// Maximum size of a buffered MQTT receive payload (64 KiB).
pub const DYN_MQTT_RECV: usize = 64 * 1024;
/// Maximum size of an assembled MQTT send payload.
pub const DYN_MQTT_SEND: usize = 0xFFFFFFF;
/// Maximum size of a loaded CRL file (400 MiB).
pub const DYN_CRLFILE_SIZE: usize = 400 * 1024 * 1024;
/// Maximum size of a loaded client certificate file (100 KiB).
pub const DYN_CERTFILE_SIZE: usize = 100 * 1024;
/// Maximum size of a loaded private key file (100 KiB).
pub const DYN_KEYFILE_SIZE: usize = 100 * 1024;

// ===========================================================================
// DynBuf
// ===========================================================================

/// A growable, length-bounded byte buffer (curl's `struct dynbuf`).
///
/// The buffer grows on demand as bytes are appended, up to the `toobig` ceiling
/// fixed at construction. The stored length never counts a NUL terminator (see
/// the module documentation); the bytes are held in a plain [`Vec<u8>`].
///
/// `DynBuf` deliberately does **not** implement [`Clone`] or [`Copy`]: the C
/// type owns a heap allocation and is moved, not silently duplicated. Use
/// [`curlx_dyn_take`](DynBuf::curlx_dyn_take) to detach the bytes when ownership
/// must be transferred.
///
/// # Examples
///
/// ```ignore
/// use crate::util::dynbuf::{DynBuf, DYN_HTTP_REQUEST};
/// use crate::util::mprintf::FmtArg;
///
/// let mut buf = DynBuf::new(DYN_HTTP_REQUEST);
/// buf.curlx_dyn_add("GET / HTTP/1.1\r\n").unwrap();
/// buf.curlx_dyn_addf(b"Host: %s\r\n", &[FmtArg::string("example.com")]).unwrap();
/// assert_eq!(buf.curlx_dyn_ptr(), b"GET / HTTP/1.1\r\nHost: example.com\r\n");
/// ```
#[derive(Debug)]
pub struct DynBuf {
    /// The accumulated data bytes (never includes a NUL terminator).
    buf: Vec<u8>,
    /// The maximum number of bytes (plus one reserved NUL slot) the buffer may
    /// grow to before an append is rejected with `CURLE_TOO_LARGE`.
    toobig: usize,
}

impl DynBuf {
    /// Create an empty buffer with the given maximum size (`curlx_dyn_init`).
    ///
    /// `toobig` is the inclusive ceiling on the allocation; an append is
    /// rejected once it would push `len + 1` (data plus the reserved NUL slot)
    /// past `toobig`. The contract mirrors curl's `curlx_dyn_init`, which
    /// requires a non-zero `toobig` that does not exceed [`MAX_DYNBUF_SIZE`];
    /// these expectations are checked with `debug_assert!` (the upstream
    /// `DEBUGASSERT`s) and so are active in debug/test builds only.
    #[must_use]
    pub fn new(toobig: usize) -> Self {
        debug_assert!(toobig != 0, "dynbuf `toobig` must be non-zero");
        debug_assert!(
            toobig <= MAX_DYNBUF_SIZE,
            "dynbuf `toobig` must not exceed MAX_DYNBUF_SIZE"
        );
        DynBuf {
            buf: Vec::new(),
            toobig,
        }
    }

    /// Alias for [`new`](DynBuf::new) using curl's C function name
    /// (`curlx_dyn_init`).
    #[must_use]
    pub fn curlx_dyn_init(toobig: usize) -> Self {
        Self::new(toobig)
    }

    /// Core append routine — curl's `dyn_nappend`.
    ///
    /// Computes the prospective allocation as `new + old + 1` (the trailing `+1`
    /// reserves the NUL slot, exactly as C does) and rejects the append when it
    /// would exceed either `toobig` or the absolute [`MAX_DYNBUF_SIZE`] ceiling.
    /// On rejection the buffer is freed and `CURLE_TOO_LARGE` is returned, again
    /// matching curl. Checked arithmetic guarantees the size computation can
    /// never overflow `usize`; an overflowing request is treated as a cap
    /// breach.
    fn nappend(&mut self, mem: &[u8]) -> Result<()> {
        let idx = self.buf.len();
        // fit = len + idx + 1  (new bytes + existing bytes + NUL slot)
        let fit = mem
            .len()
            .checked_add(idx)
            .and_then(|sum| sum.checked_add(1));

        match fit {
            Some(fit) if fit <= self.toobig && fit <= MAX_DYNBUF_SIZE => {
                self.buf.extend_from_slice(mem);
                Ok(())
            }
            _ => {
                // Parity with C `dyn_nappend`: free the buffer on a cap breach
                // (or arithmetic overflow) and report the failure.
                self.curlx_dyn_free();
                Err(CurlError::TooLarge)
            }
        }
    }

    /// Append a chunk of bytes (`curlx_dyn_addn`).
    ///
    /// Fails with [`CurlError::TooLarge`] (and frees the buffer) if the append
    /// would exceed the configured `toobig`.
    pub fn curlx_dyn_addn(&mut self, mem: &[u8]) -> Result<()> {
        self.nappend(mem)
    }

    /// Append the bytes of a string (`curlx_dyn_add`).
    ///
    /// The C API takes a NUL-terminated `char *`; the Rust signature takes a
    /// [`&str`] and appends its bytes. No NUL is stored — the length grows by
    /// `s.len()`. Fails with [`CurlError::TooLarge`] on a cap breach.
    pub fn curlx_dyn_add(&mut self, s: &str) -> Result<()> {
        self.nappend(s.as_bytes())
    }

    /// Append a string rendered `vprintf`-style (`curlx_dyn_vaddf`).
    ///
    /// The format is rendered through [`crate::util::mprintf::maprintf`] using
    /// the typed [`FmtArg`] argument model, then the result is appended (subject
    /// to the `toobig` cap). When the rendered output would exceed the printf
    /// ceiling (`maprintf` returns [`None`], mirroring curl's `curl_mvaprintf`
    /// returning `NULL`), the buffer is freed and [`CurlError::OutOfMemory`] is
    /// returned, exactly as curl's `curlx_dyn_vaddf` reports the failure.
    pub fn curlx_dyn_vaddf(&mut self, fmt: &[u8], args: &[FmtArg]) -> Result<()> {
        match maprintf(fmt, args) {
            Some(rendered) => self.nappend(&rendered),
            None => {
                self.curlx_dyn_free();
                Err(CurlError::OutOfMemory)
            }
        }
    }

    /// Append a string rendered `printf`-style (`curlx_dyn_addf`).
    ///
    /// Identical to [`curlx_dyn_vaddf`](DynBuf::curlx_dyn_vaddf); the C variadic
    /// (`...`) versus `va_list` distinction collapses to a single typed-argument
    /// entry point in Rust.
    pub fn curlx_dyn_addf(&mut self, fmt: &[u8], args: &[FmtArg]) -> Result<()> {
        self.curlx_dyn_vaddf(fmt, args)
    }

    /// Clear the contents, keeping the allocation (`curlx_dyn_reset`).
    ///
    /// The length becomes zero but the underlying capacity is retained so the
    /// buffer can be refilled without re-allocating — matching curl, which only
    /// resets `leng`.
    pub fn curlx_dyn_reset(&mut self) {
        self.buf.clear();
    }

    /// Keep only the last `trail` bytes, dropping the prefix (`curlx_dyn_tail`).
    ///
    /// * `trail > len` → [`CurlError::BadFunctionArgument`].
    /// * `trail == len` → no-op success.
    /// * `trail == 0` → equivalent to [`curlx_dyn_reset`](DynBuf::curlx_dyn_reset).
    /// * otherwise the first `len - trail` bytes are removed.
    pub fn curlx_dyn_tail(&mut self, trail: usize) -> Result<()> {
        let leng = self.buf.len();
        if trail > leng {
            Err(CurlError::BadFunctionArgument)
        } else if trail == leng {
            Ok(())
        } else if trail == 0 {
            self.curlx_dyn_reset();
            Ok(())
        } else {
            // Drop the leading `leng - trail` bytes, keeping the tail.
            self.buf.drain(..leng - trail);
            Ok(())
        }
    }

    /// Set a new, smaller length (`curlx_dyn_setlen`).
    ///
    /// Only shrinking is permitted: `set > len` yields
    /// [`CurlError::BadFunctionArgument`] (matching curl). Otherwise the buffer
    /// is truncated to `set` bytes.
    pub fn curlx_dyn_setlen(&mut self, set: usize) -> Result<()> {
        if set > self.buf.len() {
            return Err(CurlError::BadFunctionArgument);
        }
        self.buf.truncate(set);
        Ok(())
    }

    /// Free the buffer, releasing its allocation (`curlx_dyn_free`).
    ///
    /// The length and allocation are dropped, but the `toobig` limit is kept so
    /// the buffer may be reused (just like curl, which leaves the size limit in
    /// place and only frees `bufr`). The owned [`Vec`] is also released
    /// automatically when the `DynBuf` itself is dropped; this method exists for
    /// explicit, early release and for parity with the C API.
    pub fn curlx_dyn_free(&mut self) {
        self.buf = Vec::new();
    }

    /// Return a borrowed view of the buffer contents (`curlx_dyn_ptr`).
    ///
    /// The returned slice covers exactly the [`curlx_dyn_len`](DynBuf::curlx_dyn_len)
    /// data bytes and never includes a NUL terminator. (C's `curlx_dyn_ptr`
    /// returns a `char *` into a NUL-terminated allocation; in Rust the byte
    /// view carries its own length, so the terminator is unnecessary.)
    #[must_use]
    pub fn curlx_dyn_ptr(&self) -> &[u8] {
        &self.buf
    }

    /// Return a borrowed view of the buffer contents (`curlx_dyn_uptr`).
    ///
    /// Identical to [`curlx_dyn_ptr`](DynBuf::curlx_dyn_ptr): the C `char *`
    /// versus `unsigned char *` distinction is moot in Rust, where both are a
    /// `&[u8]` byte view. Provided for one-to-one API parity.
    #[must_use]
    pub fn curlx_dyn_uptr(&self) -> &[u8] {
        &self.buf
    }

    /// Return the contents as an owned, NUL-terminated byte vector.
    ///
    /// This is the explicit accessor for the rare consumer that needs the
    /// C-string form that `curlx_dyn_ptr` implies (a buffer with a trailing
    /// `\0`). The returned vector is `len + 1` bytes: the data followed by a
    /// single `0`. Interior NUL bytes, if any, are preserved.
    #[must_use]
    pub fn to_nul_terminated(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.buf.len() + 1);
        out.extend_from_slice(&self.buf);
        out.push(0);
        out
    }

    /// Return the current length in bytes (`curlx_dyn_len`).
    ///
    /// Excludes any NUL terminator, matching curl's `leng` field.
    #[must_use]
    pub fn curlx_dyn_len(&self) -> usize {
        self.buf.len()
    }

    /// Idiomatic alias for [`curlx_dyn_len`](DynBuf::curlx_dyn_len).
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Return `true` when the buffer holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Detach and return the owned buffer, leaving `self` empty
    /// (`curlx_dyn_take`).
    ///
    /// This mirrors curl handing ownership of the `malloc`'d buffer to the
    /// caller: after the call the `DynBuf` is reset to its initial empty state
    /// (length zero, no allocation) while the `toobig` limit is retained, so it
    /// can be reused for further appends.
    #[must_use = "the detached buffer is returned by value; ignoring it drops the data"]
    pub fn curlx_dyn_take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CurlError;
    use crate::util::mprintf::FmtArg;

    /// A generous cap used by tests that are not exercising the limit itself.
    const BIG: usize = 1024 * 1024;

    #[test]
    fn new_buffer_is_empty() {
        let buf = DynBuf::new(BIG);
        assert_eq!(buf.curlx_dyn_len(), 0);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.curlx_dyn_ptr(), b"");
    }

    #[test]
    fn init_alias_matches_new() {
        let buf = DynBuf::curlx_dyn_init(BIG);
        assert!(buf.is_empty());
    }

    #[test]
    fn addn_accumulates_bytes() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_addn(b"hello").unwrap();
        buf.curlx_dyn_addn(b" ").unwrap();
        buf.curlx_dyn_addn(b"world").unwrap();
        assert_eq!(buf.curlx_dyn_len(), 11);
        assert_eq!(buf.curlx_dyn_ptr(), b"hello world");
    }

    #[test]
    fn add_appends_string_bytes() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("foo").unwrap();
        buf.curlx_dyn_add("bar").unwrap();
        assert_eq!(buf.curlx_dyn_ptr(), b"foobar");
        // `len` excludes any NUL terminator.
        assert_eq!(buf.curlx_dyn_len(), 6);
    }

    #[test]
    fn len_excludes_nul_but_nul_view_has_it() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("hi").unwrap();
        assert_eq!(buf.curlx_dyn_len(), 2);
        // The data view has no terminator...
        assert_eq!(buf.curlx_dyn_ptr(), b"hi");
        // ...while the explicit C-string view appends exactly one NUL.
        assert_eq!(buf.to_nul_terminated(), b"hi\0");
    }

    #[test]
    fn ptr_and_uptr_are_identical_views() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_addn(&[0x01, 0x00, 0x02, 0xff]).unwrap();
        // Interior NUL bytes are preserved verbatim (binary safe).
        assert_eq!(buf.curlx_dyn_len(), 4);
        assert_eq!(buf.curlx_dyn_ptr(), &[0x01, 0x00, 0x02, 0xff]);
        assert_eq!(buf.curlx_dyn_uptr(), buf.curlx_dyn_ptr());
    }

    #[test]
    fn exceeding_toobig_returns_too_large_and_frees() {
        // With toobig = 8, the reserved NUL slot means at most 7 data bytes fit
        // from empty (fit = 7 + 0 + 1 = 8 <= 8).
        let mut buf = DynBuf::new(8);
        buf.curlx_dyn_addn(b"1234567").unwrap();
        assert_eq!(buf.curlx_dyn_len(), 7);

        // One more byte (fit = 1 + 7 + 1 = 9 > 8) is rejected...
        let err = buf.curlx_dyn_addn(b"8").unwrap_err();
        assert_eq!(err, CurlError::TooLarge);
        assert_eq!(err.code(), 100);
        // ...and on failure the buffer is freed, matching curl.
        assert_eq!(buf.curlx_dyn_len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn exact_boundary_payload() {
        // From empty with toobig = 8: a 7-byte payload is the largest that fits
        // (the 8th slot is the reserved NUL); an 8-byte payload is rejected.
        let mut ok = DynBuf::new(8);
        assert!(ok.curlx_dyn_addn(b"7777777").is_ok());
        assert_eq!(ok.curlx_dyn_len(), 7);

        let mut too = DynBuf::new(8);
        assert_eq!(
            too.curlx_dyn_addn(b"88888888").unwrap_err(),
            CurlError::TooLarge
        );
    }

    #[test]
    fn reusable_after_too_large() {
        // The cap breach frees the buffer but retains `toobig`, so the buffer
        // can be used again.
        let mut buf = DynBuf::new(8);
        assert!(buf.curlx_dyn_addn(b"88888888").is_err());
        assert_eq!(buf.curlx_dyn_len(), 0);
        buf.curlx_dyn_addn(b"abc").unwrap();
        assert_eq!(buf.curlx_dyn_ptr(), b"abc");
    }

    #[test]
    fn reset_zeroes_length_and_allows_reuse() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("hello").unwrap();
        buf.curlx_dyn_reset();
        assert_eq!(buf.curlx_dyn_len(), 0);
        assert!(buf.is_empty());
        // Reusable after reset.
        buf.curlx_dyn_add("again").unwrap();
        assert_eq!(buf.curlx_dyn_ptr(), b"again");
    }

    #[test]
    fn free_releases_but_keeps_limit() {
        let mut buf = DynBuf::new(8);
        buf.curlx_dyn_addn(b"123").unwrap();
        buf.curlx_dyn_free();
        assert_eq!(buf.curlx_dyn_len(), 0);
        // `toobig` is retained: a too-large append still fails after free.
        assert_eq!(
            buf.curlx_dyn_addn(b"88888888").unwrap_err(),
            CurlError::TooLarge
        );
    }

    #[test]
    fn take_detaches_and_empties() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("hello").unwrap();
        let taken = buf.curlx_dyn_take();
        assert_eq!(taken, b"hello");
        // After take the buffer is empty but reusable (toobig retained).
        assert_eq!(buf.curlx_dyn_len(), 0);
        assert!(buf.is_empty());
        buf.curlx_dyn_add("more").unwrap();
        assert_eq!(buf.curlx_dyn_ptr(), b"more");
    }

    #[test]
    fn tail_keeps_last_bytes() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("abcdef").unwrap();
        buf.curlx_dyn_tail(2).unwrap();
        assert_eq!(buf.curlx_dyn_ptr(), b"ef");
        assert_eq!(buf.curlx_dyn_len(), 2);
    }

    #[test]
    fn tail_zero_resets() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("abcdef").unwrap();
        buf.curlx_dyn_tail(0).unwrap();
        assert_eq!(buf.curlx_dyn_len(), 0);
    }

    #[test]
    fn tail_equal_len_is_noop() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("abcdef").unwrap();
        buf.curlx_dyn_tail(6).unwrap();
        assert_eq!(buf.curlx_dyn_ptr(), b"abcdef");
    }

    #[test]
    fn tail_too_long_is_bad_argument() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("abc").unwrap();
        assert_eq!(
            buf.curlx_dyn_tail(4).unwrap_err(),
            CurlError::BadFunctionArgument
        );
        // The buffer is unchanged after the rejected call.
        assert_eq!(buf.curlx_dyn_ptr(), b"abc");
    }

    #[test]
    fn setlen_shrinks() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("abcdef").unwrap();
        buf.curlx_dyn_setlen(3).unwrap();
        assert_eq!(buf.curlx_dyn_ptr(), b"abc");
        assert_eq!(buf.curlx_dyn_len(), 3);
    }

    #[test]
    fn setlen_grow_is_bad_argument() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("abc").unwrap();
        assert_eq!(
            buf.curlx_dyn_setlen(4).unwrap_err(),
            CurlError::BadFunctionArgument
        );
        assert_eq!(buf.curlx_dyn_ptr(), b"abc");
    }

    #[test]
    fn addf_formats_integer() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_addf(b"%d", &[FmtArg::Int(42)]).unwrap();
        assert_eq!(buf.curlx_dyn_ptr(), b"42");
    }

    #[test]
    fn addf_formats_mixed_and_accumulates() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_add("[").unwrap();
        buf.curlx_dyn_addf(b"%s=%d", &[FmtArg::string("x"), FmtArg::Int(5)])
            .unwrap();
        buf.curlx_dyn_add("]").unwrap();
        assert_eq!(buf.curlx_dyn_ptr(), b"[x=5]");
    }

    #[test]
    fn vaddf_behaves_like_addf() {
        let mut buf = DynBuf::new(BIG);
        buf.curlx_dyn_vaddf(b"%05d", &[FmtArg::Int(42)]).unwrap();
        assert_eq!(buf.curlx_dyn_ptr(), b"00042");
    }

    #[test]
    fn addf_respects_cap() {
        // toobig = 4 → at most 3 data bytes; rendering "9999" (4 bytes) is too big.
        let mut buf = DynBuf::new(4);
        assert_eq!(
            buf.curlx_dyn_addf(b"%d", &[FmtArg::Int(9999)]).unwrap_err(),
            CurlError::TooLarge
        );
        // On failure the buffer was freed.
        assert_eq!(buf.curlx_dyn_len(), 0);
    }

    #[test]
    fn constants_match_curl_header() {
        assert_eq!(MAX_DYNBUF_SIZE, usize::MAX / 2);
        assert_eq!(DYN_DOH_RESPONSE, 3000);
        assert_eq!(DYN_DOH_CNAME, 256);
        assert_eq!(DYN_PAUSE_BUFFER, 64 * 1024 * 1024);
        assert_eq!(DYN_HAXPROXY, 2048);
        assert_eq!(DYN_HTTP_REQUEST, 1024 * 1024);
        assert_eq!(DYN_APRINTF, 8_000_000);
        assert_eq!(DYN_RTSP_REQ_HEADER, 64 * 1024);
        assert_eq!(DYN_TRAILERS, 64 * 1024);
        assert_eq!(DYN_PROXY_CONNECT_HEADERS, 16384);
        assert_eq!(DYN_QLOG_NAME, 1024);
        assert_eq!(DYN_H1_TRAILER, 4096);
        assert_eq!(DYN_PINGPPONG_CMD, 64 * 1024);
        assert_eq!(DYN_IMAP_CMD, 64 * 1024);
        assert_eq!(DYN_MQTT_RECV, 64 * 1024);
        assert_eq!(DYN_MQTT_SEND, 0xFFFFFFF);
        assert_eq!(DYN_CRLFILE_SIZE, 400 * 1024 * 1024);
        assert_eq!(DYN_CERTFILE_SIZE, 100 * 1024);
        assert_eq!(DYN_KEYFILE_SIZE, 100 * 1024);
    }
}

