//! Alternative Services (RFC 7838) cache.
//!
//! This module is the memory-safe Rust reimplementation of libcurl's Alt-Svc
//! subsystem (the behavioral / file-format oracle is `lib/altsvc.c` and
//! `lib/altsvc.h`). It is responsible for three things and three things only:
//!
//! 1. **Parsing** the `Alt-Svc:` HTTP response header into cache entries
//!    ([`AltSvcCache::parse`]).
//! 2. **Storing** those entries in an in-memory cache with optional on-disk
//!    persistence in curl's documented text format
//!    ([`AltSvcCache::load`] / [`AltSvcCache::save`]).
//! 3. **Answering lookups** for a request origin, returning a non-expired
//!    alternate `(host, port, ALPN)` triple ([`AltSvcCache::lookup`]).
//!
//! Actually *redirecting* a connection to the discovered alternate is the job
//! of the connection layer (`crate::conn`) and the HTTP protocol engine
//! (`crate::protocols::http`) — Alt-Svc is, in particular, the mechanism by
//! which curl discovers HTTP/3 (`h3`) endpoints. This module merely parses,
//! stores, persists, and answers.
//!
//! # Parity contract
//!
//! Alt-Svc behavior is part of curl's externally observable surface and is
//! exercised by the (immutable) regression suite — notably `tests/unit/unit1654`
//! (header-parsing behavior) and `tests/data/test1654` (the byte-exact file
//! dump). Three things therefore MUST match curl 8.x exactly:
//!
//! * **ALPN-id mapping.** The numeric values of [`AlpnId`] mirror curl's
//!   `enum alpnid` (`lib/hostip.h`), which deliberately equals the
//!   `CURLALTSVC_*` control bits so that the lookup version filter is a single
//!   bitwise-AND. Getting these wrong silently breaks HTTP/3 discovery.
//! * **Header parsing.** `ma=`, `persist=`, the magic `clear` token, the
//!   per-origin replacement rule, and unknown-token skipping all follow
//!   `Curl_altsvc_parse` precisely.
//! * **File format.** The text layout written by [`AltSvcCache::save`] is
//!   byte-for-byte identical to `altsvc_out` in `lib/altsvc.c`, because the test
//!   suite diffs the dumped file.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and is compiled under the
//! module-level `#![forbid(unsafe_code)]` below (in addition to whatever the
//! crate root enforces). C dynamic buffers and the hand-rolled linked list of
//! `lib/altsvc.c` become a plain [`Vec`] of owned [`AltSvc`] values; manual
//! `free()` is replaced by ownership and `Drop`. Date handling is delegated to
//! the safe `chrono` crate rather than to C `gmtime`/`getdate`.
//!
//! # Feature gating
//!
//! Alt-Svc is gated behind the `alt-svc` Cargo feature (default on); the crate
//! root is expected to declare this module as
//! `#[cfg(feature = "alt-svc")] pub mod altsvc;`. When the feature is off the
//! module is simply not compiled and `version.rs` omits the
//! `CURL_VERSION_ALTSVC` (`1 << 24`) capability bit. The module itself carries
//! no inner feature `cfg`, so it compiles cleanly in either configuration.

#![forbid(unsafe_code)]

use crate::error::{CurlError, Result};
use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};

// ---------------------------------------------------------------------------
// Internal limits — mirrored verbatim from `lib/altsvc.c` so that the accept /
// reject decisions on malformed input match curl exactly.
// ---------------------------------------------------------------------------

/// Maximum length of one alternative being parsed / one persisted line
/// (`MAX_ALTSVC_LINE`).
const MAX_ALTSVC_LINE: usize = 4095;
/// Maximum length of the quoted date field (`MAX_ALTSVC_DATELEN`); exactly the
/// width of `"YYYYMMDD HH:MM:SS"`.
const MAX_ALTSVC_DATELEN: usize = 17;
/// Maximum host length accepted in a persisted line / parsed header
/// (`MAX_ALTSVC_HOSTLEN`).
const MAX_ALTSVC_HOSTLEN: usize = 2048;
/// Maximum ALPN-id token length (`MAX_ALTSVC_ALPNLEN`).
const MAX_ALTSVC_ALPNLEN: usize = 10;
/// Maximum textual length of an IP address, used when reading a bracketed IPv6
/// alternate host (`MAX_IPADR_LEN` == `sizeof("ffff:…:255.255.255.255")`).
const MAX_IPADR_LEN: usize = 46;
/// Maximum representable `time_t` on a 64-bit signed platform
/// (`TIME_T_MAX == 0x7FFFFFFFFFFFFFFF`). Used to cap `ma=` expiry arithmetic.
const TIME_T_MAX: i64 = i64::MAX;

/// Maximum length of a flag *name* inside the `; name=value` tail of an
/// alternative (curl uses a literal `20` in `Curl_altsvc_parse`).
const MAX_ALTSVC_FLAGNAME: usize = 20;

// ---------------------------------------------------------------------------
// Public control bits — these are the `CURLALTSVC_*` values from
// `include/curl/curl.h` (bits for the `CURLOPT_ALTSVC_CTRL` option). They are
// part of the public ABI; the FFI crate re-exposes the same integers.
// ---------------------------------------------------------------------------

/// `CURLALTSVC_READONLYFILE` (`1 << 2`): the cache file is read-only and must
/// never be written back by [`AltSvcCache::save`].
pub const CURLALTSVC_READONLYFILE: i64 = 1 << 2;
/// `CURLALTSVC_H1` (`1 << 3`): allow HTTP/1.1 alternatives.
pub const CURLALTSVC_H1: i64 = 1 << 3;
/// `CURLALTSVC_H2` (`1 << 4`): allow HTTP/2 alternatives.
pub const CURLALTSVC_H2: i64 = 1 << 4;
/// `CURLALTSVC_H3` (`1 << 5`): allow HTTP/3 alternatives.
pub const CURLALTSVC_H3: i64 = 1 << 5;

/// The default control bitmask of a freshly initialized cache: all three HTTP
/// version families enabled (`CURLALTSVC_H1 | CURLALTSVC_H2 | CURLALTSVC_H3`).
///
/// curl makes the H2/H3 bits conditional on `USE_HTTP2` / `USE_HTTP3` at build
/// time; the Rust workspace always builds with HTTP/2 (`h2`) and HTTP/3
/// (`quinn`/`h3`) support, so all three are enabled by default — matching the
/// default capability set reported by `curl --version`.
const ALTSVC_DEFAULT_FLAGS: i64 = CURLALTSVC_H1 | CURLALTSVC_H2 | CURLALTSVC_H3;

// ---------------------------------------------------------------------------
// ALPN identifiers
// ---------------------------------------------------------------------------

/// An ALPN protocol identifier, as used by the Alt-Svc machinery.
///
/// The numeric discriminants are **not** arbitrary: they reproduce curl's
/// `enum alpnid` (`lib/hostip.h`), where `ALPN_h1 = CURLALTSVC_H1`,
/// `ALPN_h2 = CURLALTSVC_H2` and `ALPN_h3 = CURLALTSVC_H3`. Because the values
/// coincide with the [`CURLALTSVC_H1`]/[`CURLALTSVC_H2`]/[`CURLALTSVC_H3`]
/// control bits, [`AltSvcCache::lookup`] can filter allowed alternates with a
/// single bitwise-AND (`versions & entry.dst.alpnid.bits()`), exactly as
/// `Curl_altsvc_lookup` does. `#[repr(i32)]` pins the layout for the C `int`
/// the FFI boundary expects.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlpnId {
    /// No / unknown protocol (`ALPN_none`, value `0`).
    None = 0,
    /// HTTP/1.1 (`ALPN_h1`, value `CURLALTSVC_H1` == `8`).
    H1 = 1 << 3,
    /// HTTP/2 (`ALPN_h2`, value `CURLALTSVC_H2` == `16`).
    H2 = 1 << 4,
    /// HTTP/3 (`ALPN_h3`, value `CURLALTSVC_H3` == `32`).
    H3 = 1 << 5,
}

impl AlpnId {
    /// Map an ALPN token (as it appears on the wire / in the header) to an
    /// [`AlpnId`].
    ///
    /// This is a byte-exact reproduction of `Curl_alpn2alpnid` (`lib/connect.c`):
    /// only the two-byte tokens `h1`, `h2`, `h3` and the eight-byte token
    /// `http/1.1` are recognized; everything else (including draft tokens such
    /// as `h3-29`, which curl 8.19 does *not* recognize) maps to
    /// [`AlpnId::None`].
    #[must_use]
    pub fn from_bytes(name: &[u8]) -> AlpnId {
        match name {
            b"h1" => AlpnId::H1,
            b"h2" => AlpnId::H2,
            b"h3" => AlpnId::H3,
            b"http/1.1" => AlpnId::H1,
            _ => AlpnId::None,
        }
    }

    /// Convenience wrapper around [`AlpnId::from_bytes`] for `&str` tokens.
    #[must_use]
    pub fn from_token(name: &str) -> AlpnId {
        AlpnId::from_bytes(name.as_bytes())
    }

    /// Return the canonical wire name for this id.
    ///
    /// Reproduces `Curl_alpnid2str` (`lib/altsvc.c`): `h1`/`h2`/`h3`, and the
    /// empty string for [`AlpnId::None`] (curl's "bad" sentinel). This is the
    /// exact spelling written to the persisted cache file.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AlpnId::H1 => "h1",
            AlpnId::H2 => "h2",
            AlpnId::H3 => "h3",
            AlpnId::None => "",
        }
    }

    /// Return the numeric bit value (equal to the matching `CURLALTSVC_*` bit
    /// for `h1`/`h2`/`h3`, and `0` for [`AlpnId::None`]).
    ///
    /// Used by [`AltSvcCache::lookup`] for the `versions & alpnid` filter.
    #[must_use]
    pub fn bits(self) -> i64 {
        self as i64
    }

    /// True for any recognized protocol (i.e. not [`AlpnId::None`]).
    #[must_use]
    pub fn is_valid(self) -> bool {
        self != AlpnId::None
    }
}

// ---------------------------------------------------------------------------
// Cache entry types
// ---------------------------------------------------------------------------

/// One end of an Alt-Svc mapping: a `(host, port, alpn)` triple.
///
/// Mirrors curl's `struct althost`. The `host` is stored **without** any
/// surrounding IPv6 brackets and without a trailing dot — exactly as
/// `altsvc_createid` normalizes it — so that comparisons and the persisted
/// representation are canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltHost {
    /// The hostname or (bracket-stripped) IP literal.
    pub host: String,
    /// The TCP/UDP port.
    pub port: u16,
    /// The ALPN protocol id spoken to this endpoint.
    pub alpnid: AlpnId,
}

/// A single cached alternative service: the origin (`src`) and the alternate
/// endpoint (`dst`) it maps to, plus expiry and the `persist` flag.
///
/// Mirrors curl's `struct altsvc`. `prio` is retained for file-format parity
/// (curl always writes `0`) but is otherwise unused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvc {
    /// The request origin this alternative applies to.
    pub src: AltHost,
    /// The alternate endpoint to use instead.
    pub dst: AltHost,
    /// Absolute expiry time as a Unix timestamp (seconds since the epoch),
    /// equivalent to curl's `time_t expires`.
    pub expires: i64,
    /// Whether the alternative should persist across network changes
    /// (RFC 7838 `persist=1`).
    pub persist: bool,
    /// Priority. Always `0`; preserved only for byte-exact file output.
    pub prio: u32,
}

impl AltSvc {
    /// Whether this alternative points at the *same* destination as the given
    /// request origin (only the protocol/ALPN differs).
    ///
    /// Reproduces curl's `psame_destination` computation in
    /// `Curl_altsvc_lookup`: `(req_port == dst.port) && hostcompare(req_host,
    /// dst.host)`. When this is true the caller need not actually reconnect to
    /// a different host:port — it only gains additional HTTP-version options.
    #[must_use]
    pub fn is_same_destination(&self, req_host: &str, req_port: u16) -> bool {
        req_port == self.dst.port && host_compare(req_host, &self.dst.host)
    }
}

// ---------------------------------------------------------------------------
// The cache
// ---------------------------------------------------------------------------

/// An in-memory Alternative-Services cache with optional file backing.
///
/// This is the Rust counterpart of curl's `struct altsvcinfo`. Entries are held
/// in a [`Vec`] in insertion order (matching the head-to-tail iteration order
/// of curl's linked list, on which lookup precedence depends). The optional
/// `filename` records the backing file so that [`AltSvcCache::save`] can be
/// called with no argument after a [`AltSvcCache::load`], surviving an
/// easy-handle reset exactly as curl's private filename copy does.
///
/// The struct is `Send + Sync` (it owns only `String`, `Vec`, integers and
/// plain enums), so it can be shared across the multi runtime via
/// `Arc<Mutex<…>>` in `crate::share`.
#[derive(Debug, Clone)]
pub struct AltSvcCache {
    /// Cached alternatives, in insertion order.
    list: Vec<AltSvc>,
    /// The backing file path, if a cache file is in use.
    filename: Option<String>,
    /// The publicly set `CURLALTSVC_*` control bitmask.
    flags: i64,
}

impl Default for AltSvcCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AltSvcCache {
    /// Create a new, empty cache with curl's default control flags
    /// (`H1 | H2 | H3`).
    ///
    /// Equivalent to `Curl_altsvc_init`.
    #[must_use]
    pub fn new() -> Self {
        AltSvcCache {
            list: Vec::new(),
            filename: None,
            flags: ALTSVC_DEFAULT_FLAGS,
        }
    }

    /// Create a cache and immediately load entries from `file`.
    ///
    /// Convenience for `let mut c = AltSvcCache::new(); c.load(file)?;`. Loading
    /// errors are surfaced, though — like curl — individual malformed lines are
    /// silently ignored.
    pub fn with_file(file: &str) -> Result<Self> {
        let mut cache = Self::new();
        cache.load(file)?;
        Ok(cache)
    }

    /// The current `CURLALTSVC_*` control bitmask.
    #[must_use]
    pub fn flags(&self) -> i64 {
        self.flags
    }

    /// Set the control bitmask, validating it like `Curl_altsvc_ctrl`.
    ///
    /// A zero bitmask is rejected with [`CurlError::BadFunctionArgument`]
    /// (curl returns `CURLE_BAD_FUNCTION_ARGUMENT` for `ctrl == 0`).
    pub fn ctrl(&mut self, ctrl: i64) -> Result<()> {
        if ctrl == 0 {
            return Err(CurlError::BadFunctionArgument);
        }
        self.flags = ctrl;
        Ok(())
    }

    /// The configured backing-file path, if any.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Number of entries currently cached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Iterate over the cached entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &AltSvc> {
        self.list.iter()
    }
}

// ---------------------------------------------------------------------------
// Header parsing, lookup and the per-origin flush — the behavioral heart of the
// module. These reproduce `Curl_altsvc_parse`, `Curl_altsvc_lookup` and
// `altsvc_flush` from `lib/altsvc.c` exactly (the regression suite — in
// particular `tests/unit/unit1654` — verifies the entry counts produced by a
// fixed sequence of header values, so the accept/reject and replacement rules
// must match to the byte).
// ---------------------------------------------------------------------------

impl AltSvcCache {
    /// Parse an incoming `Alt-Svc:` response-header *value* and fold its
    /// alternatives into the cache.
    ///
    /// This is the faithful port of `Curl_altsvc_parse`. `value` is the text to
    /// the right of the `Alt-Svc:` header name; `src_alpn`/`src_host`/`src_port`
    /// identify the origin the header was received from; `now` is the current
    /// time as a Unix timestamp (injected so tests are deterministic — curl
    /// reads it from `time(NULL)`, overridable via `CURL_TIME` in debug builds).
    ///
    /// Behavior reproduced exactly:
    ///
    /// * The magic **`clear`** token (optionally followed by `;`/newline) flushes
    ///   every cached alternative for the origin and returns.
    /// * Each alternative is `protocol-id="[host][:port]"` with optional
    ///   `; ma=<seconds>` (max-age, default 24h) and `; persist=1` parameters.
    ///   A missing host reuses `src_host`; a bracketed `[…]` host is an IPv6
    ///   literal.
    /// * Unknown protocol-ids are skipped (no entry, no flush); the first *valid*
    ///   alternative on a line first flushes the origin's previous entries, so a
    ///   fresh header replaces rather than accumulates.
    /// * Malformed input (bad host, bad/again-missing port, missing quote)
    ///   stops parsing of the remainder without error, exactly as curl.
    ///
    /// Returns `Err(CurlError::OutOfMemory)` only on the same path curl returns
    /// `CURLE_OUT_OF_MEMORY` — a degenerate empty host after normalization;
    /// genuine allocation failure cannot occur in safe Rust.
    pub fn parse(
        &mut self,
        src_alpn: AlpnId,
        src_host: &str,
        src_port: u16,
        value: &str,
        now: i64,
    ) -> Result<()> {
        let bytes = value.as_bytes();

        // --- initial check for the magic "clear" keyword -------------------
        // curl: str_cspn(&p, &alpn, ";\n\r"); trimblanks; if casecompare "clear".
        {
            let mut sc = Scan::new(bytes);
            if let Some(seg) = sc.cspn(b";\n\r") {
                if case_eq(trim_blanks(seg), b"clear") {
                    self.flush(src_alpn, src_host, src_port);
                    return Ok(());
                }
            }
        }

        // --- read the first protocol-id (up to '=') ------------------------
        let mut sc = Scan::new(bytes);
        let mut alpn_tok: &[u8] = match sc.until(MAX_ALTSVC_LINE, b'=') {
            Some(t) => trim_blanks(t),
            None => return Ok(()), // strange line — nothing to do
        };

        let mut entries: usize = 0;

        // --- do { … } while(1) over the comma-separated alternatives -------
        loop {
            if sc.single(b'=') {
                let mut maxage: i64 = 24 * 3600; // default is 24 hours
                let mut persist = false;
                let dst_alpn = AlpnId::from_bytes(alpn_tok);

                if sc.single(b'"') {
                    // Destination host: owned so the `src_host` fallback and the
                    // header-derived slice share one type without lifetime
                    // gymnastics (one short alloc per alternative).
                    let dst_host_bytes: Vec<u8>;

                    // curl: `if(str_single(&p, ':'))` is true when ':' is ABSENT
                    // (str_single returns non-zero on no-match), i.e. a host is
                    // present. `!single(':')` mirrors that.
                    if !sc.single(b':') {
                        let parsed: &[u8];
                        // `!single('[')` true when '[' absent → regular host;
                        // the else branch (consumed '[') is the IPv6 literal.
                        if !sc.single(b'[') {
                            match sc.until(MAX_ALTSVC_HOSTLEN, b':') {
                                Some(h) => parsed = h,
                                None => break, // bad alt-svc hostname
                            }
                        } else {
                            match sc.until(MAX_IPADR_LEN, b']') {
                                Some(h) => parsed = h,
                                None => break, // bad alt-svc IPv6 hostname
                            }
                            if !sc.single(b']') {
                                break; // bad alt-svc IPv6 hostname
                            }
                        }
                        if !sc.single(b':') {
                            break; // missing ':' before the port
                        }
                        dst_host_bytes = parsed.to_vec();
                    } else {
                        // ':' consumed → no destination name → use source host.
                        dst_host_bytes = src_host.as_bytes().to_vec();
                    }

                    let dstport = match sc.number(0xffff) {
                        Some(p) => p as u16,
                        None => break, // unknown alt-svc port number
                    };

                    if !sc.single(b'"') {
                        break; // missing closing quote
                    }

                    // --- optional "; ma=… ; persist=…" parameter list ------
                    sc.pass_blanks();
                    if sc.single(b';') {
                        // Each `; name=value` flag; the loop ends when no further
                        // `name=` prefix is present (curl breaks on the same
                        // `str_until` failure).
                        while let Some(name) = sc.until(MAX_ALTSVC_FLAGNAME, b'=') {
                            if !sc.single(b'=') {
                                break;
                            }
                            let val_start = sc.pos;
                            if sc.cspn(b",;").is_none() {
                                break;
                            }
                            let val_end = sc.pos;
                            let name_t = trim_blanks(name);
                            // Trim the value range; a leading '"' makes it quoted.
                            let (ts, te) = trim_range(bytes, val_start, val_end);
                            let quoted = ts < te && bytes[ts] == b'"';
                            let num_start = if quoted { ts + 1 } else { ts };
                            // Reposition to the (post-quote) number and parse it;
                            // curl sets `p = vp` to the byte ending the value.
                            sc.pos = num_start;
                            let num = match sc.number(TIME_T_MAX) {
                                Some(n) => n,
                                None => break,
                            };
                            if case_eq(name_t, b"ma") {
                                maxage = num;
                            } else if case_eq(name_t, b"persist") && num == 1 {
                                persist = true;
                            }
                            sc.pass_blanks();
                            if quoted && !sc.single(b'"') {
                                break;
                            }
                            sc.pass_blanks();
                            if !sc.single(b';') {
                                break;
                            }
                        }
                    }

                    // --- commit the entry when the protocol-id is known ----
                    if dst_alpn.is_valid() {
                        if entries == 0 {
                            // First valid alternative of this header replaces any
                            // previously cached alternatives for the origin.
                            self.flush(src_alpn, src_host, src_port);
                        }
                        entries += 1;
                        match create_id(
                            src_host.as_bytes(),
                            &dst_host_bytes,
                            src_alpn,
                            dst_alpn,
                            src_port,
                            dstport,
                        ) {
                            Some(mut entry) => {
                                // expires = now + maxage, saturating at TIME_T_MAX
                                // (RFC 7838 §3.1), matching curl's overflow guard.
                                entry.expires = if maxage > TIME_T_MAX - now {
                                    TIME_T_MAX
                                } else {
                                    maxage + now
                                };
                                entry.persist = persist;
                                self.list.push(entry);
                            }
                            None => return Err(CurlError::OutOfMemory),
                        }
                    }
                } else {
                    break; // no opening quote
                }

                // A comma introduces another alternative; anything else ends it.
                if !sc.single(b',') {
                    break;
                }
                match sc.until(MAX_ALTSVC_LINE, b'=') {
                    Some(t) => alpn_tok = trim_blanks(t),
                    None => break,
                }
            } else {
                break; // no '=' after the protocol-id
            }
        }

        Ok(())
    }

    /// Convenience wrapper around [`AltSvcCache::parse`] that reads the current
    /// wall-clock time itself (the common caller path; tests use [`parse`] with
    /// an explicit timestamp).
    ///
    /// [`parse`]: AltSvcCache::parse
    pub fn parse_now(
        &mut self,
        src_alpn: AlpnId,
        src_host: &str,
        src_port: u16,
        value: &str,
    ) -> Result<()> {
        self.parse(src_alpn, src_host, src_port, value, system_now())
    }

    /// Remove every cached alternative whose **source origin** matches
    /// `(src_alpn, src_host, src_port)`.
    ///
    /// Reproduces `altsvc_flush`: the host match uses [`host_compare`], which
    /// ignores a single trailing dot on `src_host`.
    fn flush(&mut self, src_alpn: AlpnId, src_host: &str, src_port: u16) {
        self.list.retain(|entry| {
            !(entry.src.alpnid == src_alpn
                && entry.src.port == src_port
                && host_compare(src_host, &entry.src.host))
        });
    }

    /// Look up a cached alternative for the request origin
    /// `(src_alpn, src_host, src_port)`, restricted to the ALPN families set in
    /// `versions` (a bitwise-OR of [`CURLALTSVC_H1`]/[`CURLALTSVC_H2`]/
    /// [`CURLALTSVC_H3`]). `now` is the current Unix timestamp.
    ///
    /// Returns the first non-expired matching entry (a clone), in insertion
    /// order — exactly the precedence of `Curl_altsvc_lookup`. Callers typically
    /// pass `allowed_versions & cache.flags()` for `versions`, mirroring curl's
    /// `url.c`, which masks the request's permitted ALPNs with the cache flags.
    ///
    /// Use [`AltSvc::is_same_destination`] on the result to reproduce curl's
    /// `psame_destination` out-parameter. Unlike curl — which removes expired
    /// entries as a side effect of lookup — this method does not mutate the
    /// cache; call [`AltSvcCache::prune_expired`] for that, keeping `&self`
    /// lookups cheap and lock-friendly.
    #[must_use]
    pub fn lookup(
        &self,
        src_alpn: AlpnId,
        src_host: &str,
        src_port: u16,
        versions: i64,
        now: i64,
    ) -> Option<AltSvc> {
        for entry in &self.list {
            if entry.expires < now {
                continue; // expired — curl removes; we simply skip
            }
            if entry.src.alpnid == src_alpn
                && host_compare(src_host, &entry.src.host)
                && entry.src.port == src_port
                && (versions & entry.dst.alpnid.bits()) != 0
            {
                return Some(entry.clone());
            }
        }
        None
    }

    /// Convenience wrapper around [`AltSvcCache::lookup`] using the current
    /// wall-clock time.
    #[must_use]
    pub fn lookup_now(
        &self,
        src_alpn: AlpnId,
        src_host: &str,
        src_port: u16,
        versions: i64,
    ) -> Option<AltSvc> {
        self.lookup(src_alpn, src_host, src_port, versions, system_now())
    }

    /// Drop every entry that has expired as of `now`.
    ///
    /// curl performs this pruning lazily inside `Curl_altsvc_lookup`; exposing
    /// it explicitly lets callers keep [`AltSvcCache::lookup`] non-mutating
    /// while still reclaiming stale entries (e.g. before a [`save`]).
    ///
    /// [`save`]: AltSvcCache::save
    pub fn prune_expired(&mut self, now: i64) {
        self.list.retain(|entry| entry.expires >= now);
    }
}

// ---------------------------------------------------------------------------
// File persistence — load/save in curl's documented Alt-Svc text format. The
// regression suite (`tests/data/test1654`) diffs the dumped file byte-for-byte,
// so the line layout, the two-line header, the quoted `"YYYYMMDD HH:MM:SS"`
// date, and the IPv6 bracketing must all match `altsvc_load` / `altsvc_out`
// from `lib/altsvc.c` exactly.
// ---------------------------------------------------------------------------

/// The two-line banner curl writes at the top of every saved cache file.
/// Reproduced verbatim from `Curl_altsvc_save` (`lib/altsvc.c`).
const ALTSVC_FILE_HEADER: &str = "# Your alt-svc cache. https://curl.se/docs/alt-svc.html\n\
     # This file was generated by libcurl! Edit at your own risk.\n";

impl AltSvcCache {
    /// Load alt-svc entries from `file`, appending them to the cache and
    /// recording `file` as the backing path (so a later [`AltSvcCache::save`]
    /// with no argument writes back to the same place).
    ///
    /// Faithful port of `altsvc_load`. The text format is one entry per line:
    ///
    /// ```text
    /// <srcalpn> <srchost> <srcport> <dstalpn> <dsthost> <dstport> "<date>" <persist> <prio>
    /// ```
    ///
    /// Lines whose first non-blank character is `#` are comments; blank,
    /// malformed, or unknown-ALPN lines are silently skipped (curl discards the
    /// per-line result). A missing/unreadable file is **not** an error — the
    /// filename is still recorded and the cache is left unchanged, exactly as
    /// curl treats a failed `fopen`.
    pub fn load(&mut self, file: &str) -> Result<()> {
        // Record a private copy of the filename first — like curl, this must
        // survive even when the file does not exist or cannot be opened.
        self.filename = Some(file.to_string());

        let data = match std::fs::read(file) {
            Ok(d) => d,
            Err(_) => return Ok(()), // no readable file → no entries, still OK
        };

        // `Curl_get_line` yields lines terminated by '\n'; `split_inclusive`
        // keeps that terminator so the per-line `newline()` check matches.
        for line in data.split_inclusive(|&b| b == b'\n') {
            if let Some(entry) = parse_load_line(line) {
                self.list.push(entry);
            }
        }
        Ok(())
    }

    /// Write the cache to a file in curl's Alt-Svc text format.
    ///
    /// Faithful port of `Curl_altsvc_save`:
    ///
    /// * If `file` is `None`, the path recorded by a prior [`AltSvcCache::load`]
    ///   is used.
    /// * If the [`CURLALTSVC_READONLYFILE`] flag is set, or there is no
    ///   (non-empty) target path, this is a successful no-op.
    /// * Every entry is written regardless of expiry (curl does not prune on
    ///   save); the write is atomic (a sibling temp file is written then
    ///   renamed over the target).
    ///
    /// Returns [`CurlError::WriteError`] on an I/O failure or if an entry's
    /// expiry cannot be represented as a calendar date (the analogue of curl's
    /// `gmtime` failure).
    pub fn save(&self, file: Option<&str>) -> Result<()> {
        let target = match file.or(self.filename.as_deref()) {
            Some(t) => t,
            None => return Ok(()), // no cache file configured
        };
        if (self.flags & CURLALTSVC_READONLYFILE) != 0 || target.is_empty() {
            // Marked read-only, or no/zero-length filename → nothing to do.
            return Ok(());
        }

        // Build the full output in memory first; this makes the write atomic in
        // spirit and means a date-formatting failure aborts before touching the
        // target file (curl unlinks its temp file on the same failure).
        let mut out = String::with_capacity(ALTSVC_FILE_HEADER.len() + self.list.len() * 64);
        out.push_str(ALTSVC_FILE_HEADER);
        for entry in &self.list {
            out.push_str(&altsvc_line(entry)?);
        }

        // Atomic replace: write a sibling temp file, then rename over target.
        let tmp = format!("{target}.tmp.{}", std::process::id());
        std::fs::write(&tmp, out.as_bytes()).map_err(|_| CurlError::WriteError)?;
        if std::fs::rename(&tmp, target).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(CurlError::WriteError);
        }
        Ok(())
    }
}

/// Format one cache entry as a single persisted line (including the trailing
/// `'\n'`), byte-for-byte equivalent to `altsvc_out`.
///
/// The date is emitted as `"YYYYMMDD HH:MM:SS"` with the year unpadded (`%d`)
/// and every other component zero-padded to two digits (`%02d`), matching curl's
/// `curl_mfprintf` format string. IPv6 hosts are wrapped in `[ ]`.
fn altsvc_line(entry: &AltSvc) -> Result<String> {
    let (year, month, day, hour, minute, second) =
        gmtime_components(entry.expires).ok_or(CurlError::WriteError)?;
    Ok(format!(
        "{} {} {} {} {} {} \"{}{:02}{:02} {:02}:{:02}:{:02}\" {} {}\n",
        entry.src.alpnid.as_str(),
        host_for_file(&entry.src.host),
        entry.src.port,
        entry.dst.alpnid.as_str(),
        host_for_file(&entry.dst.host),
        entry.dst.port,
        year,
        month,
        day,
        hour,
        minute,
        second,
        u32::from(entry.persist),
        entry.prio,
    ))
}

/// Parse a single persisted line into an [`AltSvc`], or return `None` if the
/// line is a comment, blank, syntactically invalid, or names an unknown ALPN.
///
/// Faithful port of `altsvc_add` (plus the comment/blank handling that
/// `altsvc_load` performs before calling it): leading blanks are skipped, a
/// leading `#` marks a comment, and the nine space-separated fields are read
/// with the same width limits and the trailing newline requirement as curl. A
/// `getdate` failure on the quoted date yields `expires = 0` (matching
/// `Curl_getdate_capped`), and an unrecognized ALPN drops the line (curl's
/// `altsvc_create` returns NULL, whose error `altsvc_load` discards).
fn parse_load_line(line: &[u8]) -> Option<AltSvc> {
    let mut sc = Scan::new(line);
    sc.pass_blanks();
    // curl: `if(str_single(&lineptr, '#')) altsvc_add(...)` — process the line
    // only when '#' is ABSENT (a present '#' is consumed and the line skipped).
    if sc.single(b'#') {
        return None;
    }

    let src_alpn = AlpnId::from_bytes(sc.word(MAX_ALTSVC_ALPNLEN)?);
    if !sc.single(b' ') {
        return None;
    }
    let src_host = sc.word(MAX_ALTSVC_HOSTLEN)?.to_vec();
    if !sc.single(b' ') {
        return None;
    }
    let src_port = sc.number(0xffff)? as u16;
    if !sc.single(b' ') {
        return None;
    }
    let dst_alpn = AlpnId::from_bytes(sc.word(MAX_ALTSVC_ALPNLEN)?);
    if !sc.single(b' ') {
        return None;
    }
    let dst_host = sc.word(MAX_ALTSVC_HOSTLEN)?.to_vec();
    if !sc.single(b' ') {
        return None;
    }
    let dst_port = sc.number(0xffff)? as u16;
    if !sc.single(b' ') {
        return None;
    }
    // The date is a quoted word (it contains an embedded space); a parse failure
    // leaves expires at 0, exactly as `Curl_getdate_capped` does.
    let expires = parse_date(sc.quoted_word(MAX_ALTSVC_DATELEN)?).unwrap_or(0);
    if !sc.single(b' ') {
        return None;
    }
    let persist = sc.number(1)?;
    if !sc.single(b' ') {
        return None;
    }
    // prio: curl parses it with max 0 (so only "0" is accepted) and always
    // stores 0. We honor the same constraint for byte-format parity.
    let _prio = sc.number(0)?;
    if !sc.newline() {
        return None;
    }

    // `altsvc_create` rejects unknown ALPNs (returns NULL → line discarded).
    if !src_alpn.is_valid() || !dst_alpn.is_valid() {
        return None;
    }
    let mut entry = create_id(&src_host, &dst_host, src_alpn, dst_alpn, src_port, dst_port)?;
    entry.expires = expires;
    entry.persist = persist == 1;
    entry.prio = 0;
    Some(entry)
}

// ---------------------------------------------------------------------------
// Byte-oriented scanner — a faithful, allocation-free port of the subset of
// `lib/curlx/strparse.c` that `lib/altsvc.c` relies on. Working in bytes (Alt-Svc
// data is ASCII) keeps the accept/reject behavior identical to C and sidesteps
// UTF-8 boundary concerns. All primitives mirror their curl counterparts:
//
//   * the `*_until` / `word` / `quoted_word` / `number` / `cspn` parsers return
//     `None` on the errors where curl returns non-zero, and crucially DO NOT
//     advance the cursor on failure (curl leaves `*linep` untouched on error);
//   * `single` returns `true` only when the byte matched and was consumed
//     (curl's function returns `0` == "ok" in that case);
//   * `number` enforces the same `max` overflow semantics, including the
//     `max < base` special case used for the `persist`/`prio` fields.
// ---------------------------------------------------------------------------

/// A cursor over an input byte slice, mirroring curl's `const char **linep`.
struct Scan<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Scan<'a> {
    /// Create a scanner at the start of `bytes`.
    fn new(bytes: &'a [u8]) -> Self {
        Scan { bytes, pos: 0 }
    }

    /// Peek at the current byte without consuming, or `None` at end of input.
    ///
    /// A NUL byte is treated as end-of-input, matching C string semantics.
    fn peek(&self) -> Option<u8> {
        match self.bytes.get(self.pos) {
            Some(&0) | None => None,
            Some(&b) => Some(b),
        }
    }

    /// `curlx_str_single`: consume `byte` if it is next. Returns `true` on a
    /// match (cursor advanced), `false` otherwise (cursor unchanged).
    fn single(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// `curlx_str_until`: read until `delim` (or NUL / end of input). Requires
    /// at least one byte and at most `max` bytes; returns `None` (cursor
    /// unchanged) on either violation.
    fn until(&mut self, max: usize, delim: u8) -> Option<&'a [u8]> {
        // Copy the buffer reference so the returned slice carries the buffer
        // lifetime `'a`, decoupled from the `&mut self` borrow.
        let bytes = self.bytes;
        let start = self.pos;
        let mut j = start;
        while let Some(&c) = bytes.get(j) {
            if c == 0 || c == delim {
                break;
            }
            j += 1;
            if j - start > max {
                return None; // STRE_BIG — do not advance
            }
        }
        if j == start {
            return None; // STRE_SHORT — at least one byte required
        }
        self.pos = j;
        Some(&bytes[start..j])
    }

    /// `curlx_str_word`: read until the first space (or NUL / end of input).
    fn word(&mut self, max: usize) -> Option<&'a [u8]> {
        self.until(max, b' ')
    }

    /// `curlx_str_quotedword`: read a `"`-delimited word. Backslash escapes are
    /// honored (the escaped byte is taken verbatim and both bytes count toward
    /// `max`). The returned slice excludes the surrounding quotes; the cursor is
    /// left just past the closing quote. Returns `None` on a missing opening
    /// quote, a missing closing quote, or an over-length body.
    fn quoted_word(&mut self, max: usize) -> Option<&'a [u8]> {
        let bytes = self.bytes;
        let start = self.pos;
        if bytes.get(start) != Some(&b'"') {
            return None; // STRE_BEGQUOTE
        }
        let content_start = start + 1;
        let mut j = content_start;
        let mut len = 0usize;
        while let Some(&c) = bytes.get(j) {
            if c == 0 || c == b'"' {
                break;
            }
            if c == b'\\' {
                // Escaped byte: only treated as an escape if a byte follows.
                if let Some(&n) = bytes.get(j + 1) {
                    if n != 0 {
                        j += 1;
                        len += 1;
                        if len > max {
                            return None; // STRE_BIG
                        }
                    }
                }
            }
            j += 1;
            len += 1;
            if len > max {
                return None; // STRE_BIG
            }
        }
        if bytes.get(j) != Some(&b'"') {
            return None; // STRE_ENDQUOTE
        }
        self.pos = j + 1;
        Some(&bytes[content_start..j])
    }

    /// `curlx_str_number` (base 10): parse an unsigned decimal with no leading
    /// sign/space and no `0x` prefix, bounded by `max`. Leading zeroes are
    /// accepted. Stops at the first non-digit. Returns `None` if the first byte
    /// is not a digit or if the value would exceed `max` (cursor unchanged in
    /// both error cases, exactly as curl).
    fn number(&mut self, max: i64) -> Option<i64> {
        let start = self.pos;
        let first = *self.bytes.get(start)?;
        if !first.is_ascii_digit() {
            return None; // STRE_NO_NUM
        }
        let mut num: i64 = 0;
        let mut j = start;
        loop {
            let digit = i64::from(self.bytes[j] - b'0');
            j += 1;
            if max < 10 {
                // Low-max special case (used for the persist/prio fields):
                // build first, then range-check, matching curl's branch.
                num = num * 10 + digit;
                if num > max {
                    return None; // STRE_OVERFLOW
                }
            } else {
                if num > (max - digit) / 10 {
                    return None; // STRE_OVERFLOW
                }
                num = num * 10 + digit;
            }
            match self.bytes.get(j) {
                Some(&c) if c.is_ascii_digit() => continue,
                _ => break,
            }
        }
        self.pos = j;
        Some(num)
    }

    /// `curlx_str_newline`: consume a single CR or LF. Returns `true` on success.
    fn newline(&mut self) -> bool {
        match self.bytes.get(self.pos) {
            Some(&b'\r') | Some(&b'\n') => {
                self.pos += 1;
                true
            }
            _ => false,
        }
    }

    /// `curlx_str_cspn`: read the run of bytes that are **not** in `reject`
    /// (also stopping at NUL / end of input). Requires at least one byte;
    /// returns `None` (cursor unchanged) if the first byte is rejected.
    fn cspn(&mut self, reject: &[u8]) -> Option<&'a [u8]> {
        let bytes = self.bytes;
        let start = self.pos;
        let mut j = start;
        while let Some(&c) = bytes.get(j) {
            if c == 0 || reject.contains(&c) {
                break;
            }
            j += 1;
        }
        if j == start {
            return None; // STRE_SHORT
        }
        self.pos = j;
        Some(&bytes[start..j])
    }

    /// `curlx_str_passblanks`: advance over any leading spaces/tabs.
    fn pass_blanks(&mut self) {
        while let Some(&c) = self.bytes.get(self.pos) {
            if c == b' ' || c == b'\t' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }
}

/// `curlx_str_trimblanks`: return `s` with leading and trailing spaces/tabs
/// removed (`ISBLANK` == space or tab).
fn trim_blanks(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

/// `curlx_str_casecompare`: case-insensitive (ASCII) equality of a parsed token
/// against a fixed literal. Returns `true` only on an exact, length-equal match.
fn case_eq(s: &[u8], literal: &[u8]) -> bool {
    s.eq_ignore_ascii_case(literal)
}

/// `hostcompare` (`lib/altsvc.c`): case-insensitive host equality where a single
/// trailing dot on the *first* argument is ignored.
fn host_compare(host: &str, check: &str) -> bool {
    let hb = host.as_bytes();
    let hlen = if !hb.is_empty() && hb[hb.len() - 1] == b'.' {
        hb.len() - 1
    } else {
        hb.len()
    };
    hb[..hlen].eq_ignore_ascii_case(check.as_bytes())
}

/// Trim leading/trailing spaces and tabs from the half-open byte range
/// `[start, end)` of `buf`, returning the trimmed absolute range. This is the
/// in-place analogue of [`trim_blanks`] used while parsing the `; name=value`
/// parameter list, where curl trims the value `Curl_str` before inspecting its
/// first byte for a leading quote.
fn trim_range(buf: &[u8], start: usize, end: usize) -> (usize, usize) {
    let mut s = start;
    let mut e = end;
    while s < e && (buf[s] == b' ' || buf[s] == b'\t') {
        s += 1;
    }
    while e > s && (buf[e - 1] == b' ' || buf[e - 1] == b'\t') {
        e -= 1;
    }
    (s, e)
}

/// The current wall-clock time as a Unix timestamp (seconds since the epoch),
/// the analogue of curl's `time(NULL)`. Used by the `*_now` convenience
/// wrappers; the core [`AltSvcCache::parse`] / [`AltSvcCache::lookup`] take an
/// explicit timestamp so tests stay deterministic.
fn system_now() -> i64 {
    Utc::now().timestamp()
}

// ---------------------------------------------------------------------------
// Host / date helpers
// ---------------------------------------------------------------------------

/// Convert raw host bytes (always ASCII for hostnames / IP literals in practice)
/// into an owned `String`. Invalid UTF-8 is replaced rather than rejected, which
/// keeps the safe-Rust guarantee while never panicking; well-formed Alt-Svc
/// hosts are unaffected.
fn host_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Whether `host` is a textual IPv6 address literal (so it must be written
/// inside `[ ]` in the persisted file).
///
/// Mirrors curl's `curlx_inet_pton(AF_INET6, host, …) == 1` check. The stored
/// host never carries brackets (they are stripped on the way in), so this tests
/// the bare literal, e.g. `::1` or `2001:db8::1`.
fn is_ipv6_literal(host: &str) -> bool {
    host.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Build the file representation of a host: bracketed if it is an IPv6 literal,
/// bare otherwise. Reproduces the `%s%s%s` (pre/host/post) formatting in
/// `altsvc_out`.
fn host_for_file(host: &str) -> String {
    if is_ipv6_literal(host) {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Parse the quoted date field from a persisted line into a Unix timestamp.
///
/// curl writes the field as `"YYYYMMDD HH:MM:SS"` (UTC) and reads it back with
/// its general `Curl_getdate_capped`. The field is capped at
/// [`MAX_ALTSVC_DATELEN`] (17) bytes, so only this fixed-width form can occur;
/// we parse it explicitly (avoiding `chrono`'s ambiguous separator-less
/// `%Y%m%d`) so that the load → save round-trip is byte-exact. On any malformed
/// input we return `None`, and the caller stores `expires = 0` — matching curl,
/// where a `getdate` failure leaves `expires` at its `0` initial value.
fn parse_date(date: &[u8]) -> Option<i64> {
    // Fixed layout: positions 0-3 year, 4-5 month, 6-7 day, 8 space,
    // 9-10 hour, 11 ':', 12-13 minute, 14 ':', 15-16 second.
    if date.len() != MAX_ALTSVC_DATELEN {
        return None;
    }
    let s = std::str::from_utf8(date).ok()?;
    let b = s.as_bytes();
    if b[8] != b' ' || b[11] != b':' || b[14] != b':' {
        return None;
    }
    let year: i32 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(4..6)?.parse().ok()?;
    let day: u32 = s.get(6..8)?.parse().ok()?;
    let hour: u32 = s.get(9..11)?.parse().ok()?;
    let minute: u32 = s.get(12..14)?.parse().ok()?;
    let second: u32 = s.get(15..17)?.parse().ok()?;
    let dt = Utc
        .with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()?;
    Some(dt.timestamp())
}

/// Break a Unix timestamp into UTC `(year, month, day, hour, minute, second)`
/// components for the persisted-file writer. Returns `None` if the timestamp is
/// outside the representable calendar range (the analogue of a `gmtime`
/// failure, which curl surfaces as a write error).
fn gmtime_components(secs: i64) -> Option<(i32, u32, u32, u32, u32, u32)> {
    let dt: DateTime<Utc> = DateTime::<Utc>::from_timestamp(secs, 0)?;
    Some((
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    ))
}

/// Build an [`AltSvc`] from raw source/destination hosts, normalizing them the
/// way `altsvc_createid` does:
///
/// * a bracketed IPv6 source host (`[…]`) has its brackets stripped, otherwise a
///   single trailing dot is stripped;
/// * a bracketed IPv6 destination host has its brackets stripped;
/// * an empty source or destination host is rejected (`None`), matching curl's
///   "bad input" guard.
///
/// The caller is responsible for setting `expires`/`persist` afterwards.
fn create_id(
    src_host: &[u8],
    dst_host: &[u8],
    src_alpn: AlpnId,
    dst_alpn: AlpnId,
    src_port: u16,
    dst_port: u16,
) -> Option<AltSvc> {
    let mut sh = src_host;
    let mut dh = dst_host;

    if sh.len() > 2 && sh[0] == b'[' {
        // IPv6 literal: drop the leading '[' and the trailing ']'.
        sh = &sh[1..sh.len() - 1];
    } else if !sh.is_empty() && sh[sh.len() - 1] == b'.' {
        // Strip a single trailing dot from the source host.
        sh = &sh[..sh.len() - 1];
    }
    if dh.len() > 2 && dh[0] == b'[' {
        dh = &dh[1..dh.len() - 1];
    }

    if sh.is_empty() || dh.is_empty() {
        return None;
    }

    Some(AltSvc {
        src: AltHost {
            host: host_string(sh),
            port: src_port,
            alpnid: src_alpn,
        },
        dst: AltHost {
            host: host_string(dh),
            port: dst_port,
            alpnid: dst_alpn,
        },
        expires: 0,
        persist: false,
        prio: 0,
    })
}

// ===========================================================================
// Tests
//
// These reproduce the curl 8.x regression oracle for Alt-Svc:
//   * `tests/unit/unit1654.c` — the exact load + 14-call parse sequence and the
//     entry counts it asserts after each call;
//   * `tests/data/test1654`   — the byte-exact dumped-file comparison, using the
//     suite's fixed clock `CURL_TIME=1548369261` (2019-01-24 22:34:21 UTC).
// Passing these is the binary parity condition for this module.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The fixed clock used by curl's Alt-Svc tests (`CURL_TIME=1548369261`,
    /// i.e. 2019-01-24 22:34:21 UTC). Injecting it as `now` makes the generated
    /// expiry dates deterministic so the saved file can be diffed byte-for-byte.
    const T: i64 = 1_548_369_261;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A unique, collision-free temporary path (cargo runs tests in parallel).
    fn temp_path(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "blitzy_altsvc_{tag}_{}_{n}.txt",
            std::process::id()
        ));
        p
    }

    // ---- ALPN id mapping (Curl_alpn2alpnid / Curl_alpnid2str) -----------

    #[test]
    fn alpn_from_bytes_matches_curl() {
        assert_eq!(AlpnId::from_bytes(b"h1"), AlpnId::H1);
        assert_eq!(AlpnId::from_bytes(b"h2"), AlpnId::H2);
        assert_eq!(AlpnId::from_bytes(b"h3"), AlpnId::H3);
        assert_eq!(AlpnId::from_bytes(b"http/1.1"), AlpnId::H1);
        // Everything else is None — including draft tokens and wrong case
        // (curl uses a case-sensitive memcmp).
        assert_eq!(AlpnId::from_bytes(b"h6"), AlpnId::None);
        assert_eq!(AlpnId::from_bytes(b"h3-29"), AlpnId::None);
        assert_eq!(AlpnId::from_bytes(b"H1"), AlpnId::None);
        assert_eq!(AlpnId::from_bytes(b"bad"), AlpnId::None);
        assert_eq!(AlpnId::from_bytes(b""), AlpnId::None);
        assert_eq!(AlpnId::from_token("h2"), AlpnId::H2);
    }

    #[test]
    fn alpn_numeric_values_equal_control_bits() {
        // The discriminants MUST equal the CURLALTSVC_* bits so lookup can
        // filter with a single bitwise-AND.
        assert_eq!(AlpnId::None.bits(), 0);
        assert_eq!(AlpnId::H1.bits(), CURLALTSVC_H1);
        assert_eq!(AlpnId::H2.bits(), CURLALTSVC_H2);
        assert_eq!(AlpnId::H3.bits(), CURLALTSVC_H3);
        assert_eq!(CURLALTSVC_READONLYFILE, 4);
        assert_eq!(CURLALTSVC_H1, 8);
        assert_eq!(CURLALTSVC_H2, 16);
        assert_eq!(CURLALTSVC_H3, 32);
    }

    #[test]
    fn alpn_as_str_matches_curl() {
        assert_eq!(AlpnId::H1.as_str(), "h1");
        assert_eq!(AlpnId::H2.as_str(), "h2");
        assert_eq!(AlpnId::H3.as_str(), "h3");
        assert_eq!(AlpnId::None.as_str(), "");
    }

    // ---- ctrl (Curl_altsvc_ctrl) ----------------------------------------

    #[test]
    fn ctrl_rejects_zero_and_sets_flags() {
        let mut c = AltSvcCache::new();
        assert_eq!(c.flags(), CURLALTSVC_H1 | CURLALTSVC_H2 | CURLALTSVC_H3);
        assert_eq!(c.ctrl(0), Err(CurlError::BadFunctionArgument));
        assert!(c.ctrl(CURLALTSVC_H1).is_ok());
        assert_eq!(c.flags(), CURLALTSVC_H1);
    }

    // ---- load fixture (mirrors tests/data/test1654 <file>) --------------

    const LOAD_INPUT: &str = concat!(
        "h2 example.com 443 h3 shiny.example.com 8443 \"20191231 00:00:00\" 0 0\n",
        "# a comment\n",
        "h2 foo.example.com 443 h3 shiny.example.com 8443 \"20291231 23:30:00\" 0 0\n",
        "  h1 example.com 443 h3 shiny.example.com 8443 \"20121231 00:00:01\" 0 0\n",
        "\th3 example.com 443 h3 shiny.example.com 8443 \"20131231 00:00:00\" 0 0\n",
        "    # also a comment\n",
        "bad example.com 443 h3 shiny.example.com 8443 \"20191231 00:00:00\" 0 0\n",
        "rubbish\n",
    );

    fn load_fixture() -> (AltSvcCache, PathBuf) {
        let path = temp_path("load");
        std::fs::write(&path, LOAD_INPUT).unwrap();
        let mut cache = AltSvcCache::new();
        cache.load(path.to_str().unwrap()).unwrap();
        (cache, path)
    }

    #[test]
    fn load_skips_comments_blanks_bad_alpn_and_garbage() {
        let (cache, path) = load_fixture();
        // 4 valid lines; the comment, leading-blank/tab handling, the "bad"
        // ALPN line and the "rubbish" line are all handled exactly as curl.
        assert_eq!(cache.len(), 4);
        assert_eq!(cache.filename(), path.to_str());
        let _ = std::fs::remove_file(path);
    }

    /// Replay the full unit1654 parse sequence onto a freshly loaded cache.
    fn replay_unit1654(c: &mut AltSvcCache) {
        c.parse(
            AlpnId::H1,
            "example.org",
            8080,
            "h2=\"example.com:8080\"\r\n",
            T,
        )
        .unwrap();
        c.parse(AlpnId::H1, "2.example.org", 8080, "h3=\":8080\"\r\n", T)
            .unwrap();
        c.parse(
            AlpnId::H1,
            "3.example.org",
            8080,
            "h2=\"example.com:8080\", h3=\"yesyes.com:8080\"\r\n",
            T,
        )
        .unwrap();
        c.parse(
            AlpnId::H2,
            "example.org",
            80,
            "h2=\"example.com:443\"; ma = 120;\r\n",
            T,
        )
        .unwrap();
        c.parse(
            AlpnId::H2,
            "example.net",
            80,
            "h2=\"example.net:443\"; ma=\"180\";\r\n",
            T,
        )
        .unwrap();
        c.parse(
            AlpnId::H1,
            "curl.se",
            80,
            "h2=\":443\"; ma=180, h3=\":443\"; persist = \"1\"; ma = 120;\r\n",
            T,
        )
        .unwrap();
        c.parse(AlpnId::H1, "curl.se", 80, "clear;\r\n", T).unwrap();
        c.parse(
            AlpnId::H1,
            "curl.se",
            80,
            "h2=\":443\", h3=\":443\"; persist = \"1\"; ma = 120;\r\n",
            T,
        )
        .unwrap();
        c.parse(AlpnId::H1, "curl.se", 80, "clear\r\n", T).unwrap();
        c.parse(
            AlpnId::H2,
            "5.example.net",
            80,
            "h6=\"example.net:443\"; ma=\"180\";\r\n",
            T,
        )
        .unwrap();
        c.parse(
            AlpnId::H2,
            "6.example.net",
            80,
            "h2=\"example.net:443,; ma=\"180\";\r\n",
            T,
        )
        .unwrap();
        c.parse(
            AlpnId::H2,
            "7.example.net",
            80,
            "h2=\"example.net\"; ma=\"180\";\r\n",
            T,
        )
        .unwrap();
        c.parse(
            AlpnId::H2,
            "8.example.net",
            80,
            "h2=\"example.net:70000\"; ma=\"180\";\r\n",
            T,
        )
        .unwrap();
        c.parse(
            AlpnId::H2,
            "test.se",
            443,
            "h2=\"test2.se:443\"; ma=\"180 \" ; unknown=2, h2=\"test3.se:443\"; ma = 120;\r\n",
            T,
        )
        .unwrap();
    }

    #[test]
    fn unit1654_entry_counts() {
        let (mut c, path) = load_fixture();
        assert_eq!(c.len(), 4);

        // Each step mirrors a fail_unless(Curl_llist_count(...) == N) in unit1654.
        let expected = [5, 6, 8, 9, 10, 12, 10, 12, 10, 10, 10, 10, 10, 12];
        let calls: [(AlpnId, &str, u16, &str); 14] = [
            (
                AlpnId::H1,
                "example.org",
                8080,
                "h2=\"example.com:8080\"\r\n",
            ),
            (AlpnId::H1, "2.example.org", 8080, "h3=\":8080\"\r\n"),
            (
                AlpnId::H1,
                "3.example.org",
                8080,
                "h2=\"example.com:8080\", h3=\"yesyes.com:8080\"\r\n",
            ),
            (
                AlpnId::H2,
                "example.org",
                80,
                "h2=\"example.com:443\"; ma = 120;\r\n",
            ),
            (
                AlpnId::H2,
                "example.net",
                80,
                "h2=\"example.net:443\"; ma=\"180\";\r\n",
            ),
            (
                AlpnId::H1,
                "curl.se",
                80,
                "h2=\":443\"; ma=180, h3=\":443\"; persist = \"1\"; ma = 120;\r\n",
            ),
            (AlpnId::H1, "curl.se", 80, "clear;\r\n"),
            (
                AlpnId::H1,
                "curl.se",
                80,
                "h2=\":443\", h3=\":443\"; persist = \"1\"; ma = 120;\r\n",
            ),
            (AlpnId::H1, "curl.se", 80, "clear\r\n"),
            (
                AlpnId::H2,
                "5.example.net",
                80,
                "h6=\"example.net:443\"; ma=\"180\";\r\n",
            ),
            (
                AlpnId::H2,
                "6.example.net",
                80,
                "h2=\"example.net:443,; ma=\"180\";\r\n",
            ),
            (
                AlpnId::H2,
                "7.example.net",
                80,
                "h2=\"example.net\"; ma=\"180\";\r\n",
            ),
            (
                AlpnId::H2,
                "8.example.net",
                80,
                "h2=\"example.net:70000\"; ma=\"180\";\r\n",
            ),
            (
                AlpnId::H2,
                "test.se",
                443,
                "h2=\"test2.se:443\"; ma=\"180 \" ; unknown=2, h2=\"test3.se:443\"; ma = 120;\r\n",
            ),
        ];
        for (i, (alpn, host, port, header)) in calls.iter().enumerate() {
            c.parse(*alpn, host, *port, header, T).unwrap();
            assert_eq!(
                c.len(),
                expected[i],
                "after parse call {} ({header:?})",
                i + 1
            );
        }
        let _ = std::fs::remove_file(path);
    }

    /// The exact bytes curl writes for this scenario (header + 12 entries).
    const EXPECTED_SAVE: &str = concat!(
        "# Your alt-svc cache. https://curl.se/docs/alt-svc.html\n",
        "# This file was generated by libcurl! Edit at your own risk.\n",
        "h2 example.com 443 h3 shiny.example.com 8443 \"20191231 00:00:00\" 0 0\n",
        "h2 foo.example.com 443 h3 shiny.example.com 8443 \"20291231 23:30:00\" 0 0\n",
        "h1 example.com 443 h3 shiny.example.com 8443 \"20121231 00:00:01\" 0 0\n",
        "h3 example.com 443 h3 shiny.example.com 8443 \"20131231 00:00:00\" 0 0\n",
        "h1 example.org 8080 h2 example.com 8080 \"20190125 22:34:21\" 0 0\n",
        "h1 2.example.org 8080 h3 2.example.org 8080 \"20190125 22:34:21\" 0 0\n",
        "h1 3.example.org 8080 h2 example.com 8080 \"20190125 22:34:21\" 0 0\n",
        "h1 3.example.org 8080 h3 yesyes.com 8080 \"20190125 22:34:21\" 0 0\n",
        "h2 example.org 80 h2 example.com 443 \"20190124 22:36:21\" 0 0\n",
        "h2 example.net 80 h2 example.net 443 \"20190124 22:37:21\" 0 0\n",
        "h2 test.se 443 h2 test2.se 443 \"20190124 22:37:21\" 0 0\n",
        "h2 test.se 443 h2 test3.se 443 \"20190124 22:36:21\" 0 0\n",
    );

    #[test]
    fn unit1654_save_is_byte_exact() {
        let (mut c, in_path) = load_fixture();
        replay_unit1654(&mut c);
        assert_eq!(c.len(), 12);

        let out_path = temp_path("save");
        c.save(Some(out_path.to_str().unwrap())).unwrap();
        let dumped = std::fs::read_to_string(&out_path).unwrap();
        assert_eq!(dumped, EXPECTED_SAVE);

        let _ = std::fs::remove_file(in_path);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn save_then_load_roundtrips() {
        let (mut c, in_path) = load_fixture();
        replay_unit1654(&mut c);
        let out_path = temp_path("rt");
        c.save(Some(out_path.to_str().unwrap())).unwrap();

        let mut c2 = AltSvcCache::new();
        c2.load(out_path.to_str().unwrap()).unwrap();
        assert_eq!(c2.len(), c.len());
        // Saving the reloaded cache yields identical bytes.
        let out_path2 = temp_path("rt2");
        c2.save(Some(out_path2.to_str().unwrap())).unwrap();
        assert_eq!(
            std::fs::read_to_string(&out_path).unwrap(),
            std::fs::read_to_string(&out_path2).unwrap()
        );

        let _ = std::fs::remove_file(in_path);
        let _ = std::fs::remove_file(out_path);
        let _ = std::fs::remove_file(out_path2);
    }

    // ---- lookup (Curl_altsvc_lookup) ------------------------------------

    #[test]
    fn lookup_filters_by_alpn_origin_and_expiry() {
        let mut c = AltSvcCache::new();
        c.parse(
            AlpnId::H1,
            "example.org",
            80,
            "h3=\"alt.example:443\"; ma=3600\r\n",
            T,
        )
        .unwrap();
        assert_eq!(c.len(), 1);
        let now = T + 10;

        let hit = c
            .lookup(AlpnId::H1, "example.org", 80, CURLALTSVC_H3, now)
            .expect("h3 alternate should be found");
        assert_eq!(hit.dst.alpnid, AlpnId::H3);
        assert_eq!(hit.dst.host, "alt.example");
        assert_eq!(hit.dst.port, 443);
        assert!(!hit.is_same_destination("example.org", 80));

        // Disallowing h3 → no match.
        assert!(c
            .lookup(
                AlpnId::H1,
                "example.org",
                80,
                CURLALTSVC_H1 | CURLALTSVC_H2,
                now
            )
            .is_none());
        // Wrong source ALPN / host / port → no match.
        assert!(c
            .lookup(AlpnId::H2, "example.org", 80, CURLALTSVC_H3, now)
            .is_none());
        assert!(c
            .lookup(AlpnId::H1, "other.org", 80, CURLALTSVC_H3, now)
            .is_none());
        assert!(c
            .lookup(AlpnId::H1, "example.org", 81, CURLALTSVC_H3, now)
            .is_none());
        // Past expiry → skipped.
        assert!(c
            .lookup(AlpnId::H1, "example.org", 80, CURLALTSVC_H3, T + 4000)
            .is_none());
    }

    #[test]
    fn lookup_ignores_trailing_dot_on_request_host() {
        let mut c = AltSvcCache::new();
        c.parse(
            AlpnId::H1,
            "example.org",
            80,
            "h2=\"alt:443\"; ma=3600\r\n",
            T,
        )
        .unwrap();
        assert!(c
            .lookup(AlpnId::H1, "example.org.", 80, CURLALTSVC_H2, T + 1)
            .is_some());
    }

    #[test]
    fn same_destination_when_only_protocol_differs() {
        let mut c = AltSvcCache::new();
        // No host given → destination host == source host, same port.
        c.parse(
            AlpnId::H1,
            "example.org",
            443,
            "h3=\":443\"; ma=3600\r\n",
            T,
        )
        .unwrap();
        let hit = c
            .lookup(AlpnId::H1, "example.org", 443, CURLALTSVC_H3, T + 1)
            .unwrap();
        assert!(hit.is_same_destination("example.org", 443));
    }

    #[test]
    fn prune_expired_drops_only_stale_entries() {
        let mut c = AltSvcCache::new();
        c.parse(AlpnId::H1, "a.example", 80, "h2=\"x:443\"; ma=10\r\n", T)
            .unwrap();
        c.parse(AlpnId::H1, "b.example", 80, "h2=\"y:443\"; ma=10000\r\n", T)
            .unwrap();
        assert_eq!(c.len(), 2);
        c.prune_expired(T + 100); // first entry (ma=10) is now stale
        assert_eq!(c.len(), 1);
        assert_eq!(c.iter().next().unwrap().src.host, "b.example");
    }

    // ---- clear (the magic keyword) --------------------------------------

    #[test]
    fn clear_removes_only_the_matching_origin() {
        let mut c = AltSvcCache::new();
        c.parse(AlpnId::H1, "a.example", 80, "h2=\"x:443\"\r\n", T)
            .unwrap();
        c.parse(AlpnId::H1, "b.example", 80, "h2=\"y:443\"\r\n", T)
            .unwrap();
        assert_eq!(c.len(), 2);
        c.parse(AlpnId::H1, "a.example", 80, "clear\r\n", T)
            .unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c.iter().next().unwrap().src.host, "b.example");
    }

    #[test]
    fn clear_on_empty_cache_is_ok() {
        let mut c = AltSvcCache::new();
        c.parse(AlpnId::H1, "example.org", 80, "clear\r\n", T)
            .unwrap();
        assert_eq!(c.len(), 0);
    }

    // ---- IPv6 bracketing round-trip -------------------------------------

    #[test]
    fn ipv6_destination_brackets_roundtrip() {
        let mut c = AltSvcCache::new();
        c.parse(
            AlpnId::H1,
            "example.org",
            443,
            "h2=\"[2001:db8::1]:8443\"; ma=3600\r\n",
            T,
        )
        .unwrap();
        let stored = c.iter().next().unwrap();
        assert_eq!(stored.dst.host, "2001:db8::1"); // brackets stripped on store
        assert_eq!(stored.dst.port, 8443);

        let out = temp_path("ipv6");
        c.save(Some(out.to_str().unwrap())).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(
            text.contains("h2 [2001:db8::1] 8443"),
            "IPv6 destination must be bracketed on disk; got:\n{text}"
        );

        let mut c2 = AltSvcCache::new();
        c2.load(out.to_str().unwrap()).unwrap();
        assert_eq!(c2.len(), 1);
        let reloaded = c2.iter().next().unwrap();
        assert_eq!(reloaded.dst.host, "2001:db8::1");
        assert_eq!(reloaded.dst.port, 8443);
        let _ = std::fs::remove_file(out);
    }

    // ---- persist flag ---------------------------------------------------

    #[test]
    fn persist_flag_is_parsed_and_persisted() {
        let mut c = AltSvcCache::new();
        c.parse(
            AlpnId::H1,
            "example.org",
            443,
            "h3=\":443\"; persist=1; ma=3600\r\n",
            T,
        )
        .unwrap();
        assert!(c.iter().next().unwrap().persist);

        let out = temp_path("persist");
        c.save(Some(out.to_str().unwrap())).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        // The persist column (second-to-last) is 1.
        let line = text.lines().nth(2).unwrap();
        assert!(
            line.ends_with(" 1 0"),
            "persist should serialize as 1: {line}"
        );
        let _ = std::fs::remove_file(out);
    }

    // ---- save guards ----------------------------------------------------

    #[test]
    fn save_is_noop_when_readonly() {
        let mut c = AltSvcCache::new();
        c.parse(AlpnId::H1, "example.org", 443, "h2=\"x:443\"\r\n", T)
            .unwrap();
        c.ctrl(CURLALTSVC_READONLYFILE | CURLALTSVC_H1).unwrap();
        let out = temp_path("ro");
        c.save(Some(out.to_str().unwrap())).unwrap();
        assert!(!out.exists(), "READONLYFILE must suppress the write");
    }

    #[test]
    fn save_without_any_file_is_ok() {
        let c = AltSvcCache::new();
        assert!(c.save(None).is_ok());
    }

    #[test]
    fn load_missing_file_is_ok_and_records_name() {
        let mut c = AltSvcCache::new();
        let missing = temp_path("missing");
        assert!(c.load(missing.to_str().unwrap()).is_ok());
        assert_eq!(c.len(), 0);
        assert_eq!(c.filename(), missing.to_str());
    }

    #[test]
    fn expires_saturates_at_time_t_max() {
        let mut c = AltSvcCache::new();
        // A huge ma must saturate rather than overflow (RFC 7838 §3.1).
        let header = format!("h2=\"x:443\"; ma={}\r\n", i64::MAX);
        c.parse(AlpnId::H1, "example.org", 443, &header, T).unwrap();
        assert_eq!(c.iter().next().unwrap().expires, TIME_T_MAX);
    }
}
