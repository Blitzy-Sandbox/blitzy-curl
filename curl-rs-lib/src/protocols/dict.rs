// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! DICT protocol handler (RFC 2229) — the memory-safe Rust port of curl's
//! `lib/dict.c` for the byte-for-byte functional-parity rewrite of
//! curl / libcurl **8.19.0-DEV**.
//!
//! DICT is a minimal, line-oriented TCP text protocol for querying network
//! dictionary servers. A curl DICT URL encodes the *operation* in its path, and
//! the handler translates that path into one of two RFC 2229 commands —
//! `MATCH` or `DEFINE` — or, when the path uses no recognized command prefix,
//! into a raw command line. The whole exchange is a single, one-shot
//! conversation: the client sends a `CLIENT` identification banner, then the
//! `MATCH`/`DEFINE`/raw command, then `QUIT`, and streams whatever the server
//! replies straight through to the download sink with no further processing.
//!
//! # What this module reproduces (source-of-truth `lib/dict.c`)
//!
//! * **Command detection** (`dict_do`). The decoded URL path is matched, *case
//!   insensitively*, against the six command prefixes curl recognizes:
//!   `/MATCH:`, `/M:`, `/FIND:` (all three select `MATCH`) and `/DEFINE:`,
//!   `/D:`, `/LOOKUP:` (all three select `DEFINE`). curl performs this test with
//!   `curl_strnequal`, which is a locale-independent **ASCII case-insensitive**
//!   comparison (`lib/strcase.c`, `Curl_raw_toupper`), so `/d:word` and
//!   `/D:word` behave identically — exactly as exercised by `tests/data/test1450`
//!   (`dict://…/d:basic`).
//! * **Field extraction.** The fields following the prefix are split on `':'`
//!   exactly as curl's `strchr`-walking does: the URL carries them in the order
//!   `word[:database[:strategy]]`, while the wire command orders them
//!   `MATCH <database> <strategy> <word>` / `DEFINE <database> <word>`. A missing
//!   or empty database defaults to `"!"`, a missing or empty strategy to `"."`,
//!   and a missing or empty word to `"default"` — the same fallbacks `dict_do`
//!   applies. Any field beyond the ones a command uses (curl's `nthdef`) is
//!   discarded.
//! * **Word escaping** (`unescape_word`). Per RFC 2229 §2.2 each byte that is a
//!   space or control (`<= 0x20`), `DEL` (`0x7F`), `'`, `"`, or `\` is prefixed
//!   with a backslash. The word is **not** wrapped in quotes — the backslash
//!   escaping is the whole of the "quoting".
//! * **URL decoding.** The path is percent-decoded first, rejecting decoded
//!   control bytes (`< 0x20`) — curl's `Curl_urldecode(..., REJECT_CTRL)`
//!   (`lib/escape.c`) — which maps a bad path to
//!   [`CURLE_URL_MALFORMAT`](crate::error::CurlCode::UrlMalformat).
//! * **Request framing** (`sendf`). The request is a single buffer,
//!   `CLIENT <version>\r\n<command>\r\nQUIT\r\n`, with CRLF line endings, sent in
//!   one shot; the response is read to end-of-stream and passed through byte for
//!   byte.
//!
//! # Fidelity notes
//!
//! * **Version banner.** curl emits `CLIENT libcurl <LIBCURL_VERSION>`; this
//!   rewrite emits `CLIENT ` followed by the workspace-wide version string from
//!   [`crate::version`] (`curl-rs/8.19.0-DEV rustls …`), so the identification
//!   line matches the form every other component of this rewrite reports. No
//!   version literal is hard-coded here.
//! * **Fallback command.** When the path matches no `MATCH`/`DEFINE` prefix,
//!   `dict_do` takes everything after the first `'/'`, turns every `':'` into a
//!   space, and sends it as a raw command line (it does **not** synthesize a
//!   `DEFINE`); if the path has no `'/'` at all, curl sends nothing. This module
//!   reproduces that exact fallback.
//! * **Signed-`char` corner.** curl's `unescape_word` reads each byte into a
//!   `char`; on platforms where `char` is signed, bytes `>= 0x80` compare as
//!   negative and are incidentally escaped. That is a platform artifact, not the
//!   RFC 2229 intent; this port uses the unsigned byte value, so only
//!   space/control, `DEL`, `'`, `"`, and `\` are escaped. No DICT test exercises
//!   high bytes, so behavioral parity is unaffected.
//!
//! # Transport
//!
//! DICT is a single plaintext TCP connection with no authentication and no TLS
//! ([`SCHEME_DICT`](crate::protocols::SCHEME_DICT): scheme `dict`,
//! `PROTOPT_NOURLQUERY`, default port 2628). The conversation is driven over the
//! byte stream provided by the [`crate::conn`] connection-filter chain; the
//! engine here ([`DictHandler::transfer`]) is written against the Tokio
//! [`AsyncRead`]/[`AsyncWrite`] byte-stream contract that chain exposes.
//!
//! The memory-safety cornerstone is inherited from the crate root
//! (`#![forbid(unsafe_code)]`): there is no `unsafe`, no raw pointer, and no FFI
//! anywhere in this module.

use crate::error::{Error, Result};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ===========================================================================
// Command prefixes (← `lib/dict.c` `#define DICT_*`).
//
// Matched case-insensitively against the decoded path, reproducing curl's
// `curl_strnequal(path, PREFIX, strlen(PREFIX))` test. The three MATCH aliases
// and the three DEFINE aliases each select the same operation.
// ===========================================================================

/// `DICT_MATCH` — the canonical `MATCH` command prefix.
const DICT_MATCH: &[u8] = b"/MATCH:";
/// `DICT_MATCH2` — the short `MATCH` alias.
const DICT_MATCH2: &[u8] = b"/M:";
/// `DICT_MATCH3` — the `FIND` `MATCH` alias.
const DICT_MATCH3: &[u8] = b"/FIND:";
/// `DICT_DEFINE` — the canonical `DEFINE` command prefix.
const DICT_DEFINE: &[u8] = b"/DEFINE:";
/// `DICT_DEFINE2` — the short `DEFINE` alias.
const DICT_DEFINE2: &[u8] = b"/D:";
/// `DICT_DEFINE3` — the `LOOKUP` `DEFINE` alias.
const DICT_DEFINE3: &[u8] = b"/LOOKUP:";

/// Default database when the URL omits one (`"!"` = "search all databases").
const DEFAULT_DATABASE: &[u8] = b"!";
/// Default match strategy when the URL omits one (`"."` = server default).
const DEFAULT_STRATEGY: &[u8] = b".";
/// Word substituted when the lookup word is missing/empty (curl's `"default"`).
const DEFAULT_WORD: &[u8] = b"default";

// ===========================================================================
// DictHandler — the protocol behavior singleton (← `Curl_protocol_dict`).
// ===========================================================================

/// The DICT protocol handler (← curl's `Curl_protocol_dict`).
///
/// A zero-sized, stateless handler: like every curl protocol vtable it holds no
/// per-transfer state, so it is shared as the `'static` [`HANDLER`] singleton
/// that [`SCHEME_DICT`](crate::protocols::SCHEME_DICT) points at. All
/// per-transfer state (URL path, connection stream, download sink) is supplied
/// to [`DictHandler::transfer`] by the caller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DictHandler;

/// The DICT handler singleton referenced by
/// [`SCHEME_DICT`](crate::protocols::SCHEME_DICT) (← `Curl_protocol_dict`).
pub static HANDLER: DictHandler = DictHandler;

impl DictHandler {
    /// Perform a complete DICT conversation over `stream`, appending the
    /// server's response bytes to `output` unchanged.
    ///
    /// This is the whole of curl's `dict_do` plus the ensuing response read: the
    /// URL `path` (the `dict://…` path component, still percent-encoded) is
    /// turned into the request buffer, the buffer is written in one shot, and
    /// every byte the server sends back — banner, response, and all — is streamed
    /// straight into `output` exactly as curl writes the DICT response to the
    /// download with no interpretation.
    ///
    /// When `path` uses no recognized command prefix and contains no `'/'`,
    /// curl sends nothing and reads nothing; this method then leaves `output`
    /// untouched and returns `Ok(())`, matching `dict_do`'s empty fall-through.
    ///
    /// `stream` is any Tokio byte stream, which is precisely what the
    /// [`crate::conn`] filter chain yields once a DICT connection is
    /// established.
    ///
    /// # Errors
    ///
    /// Returns [`CURLE_URL_MALFORMAT`](crate::error::CurlCode::UrlMalformat) when
    /// the path fails `REJECT_CTRL` percent-decoding, and the send/receive I/O
    /// errors ([`CURLE_SEND_ERROR`](crate::error::CurlCode::SendError) /
    /// [`CURLE_RECV_ERROR`](crate::error::CurlCode::RecvError)) surfaced by the
    /// underlying stream, exactly as curl reports them.
    pub async fn transfer<S>(&self, path: &str, stream: &mut S, output: &mut Vec<u8>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // `dict_do` builds the request first; only if there is one to send does
        // it set up the receive side. `None` reproduces the fall-through where
        // the path has no '/' and curl issues no request at all.
        if let Some(request) = build_request(path)? {
            let response = converse(stream, &request).await?;
            output.extend_from_slice(&response);
        }
        Ok(())
    }
}

impl Protocol for DictHandler {
    /// The DICT "DO" phase (← `dict_do`).
    ///
    /// `dict_do` sets `*done = TRUE` unconditionally and issues the entire
    /// request in one shot, after which the generic transfer loop reads the
    /// response body. The DO phase is therefore always complete in a single
    /// step, which this returns as `Ok(true)`.
    ///
    /// The concrete send/receive work lives in [`DictHandler::transfer`], which
    /// is driven over the connection's byte stream. It binds here once
    /// [`TransferCtx`] carries the easy-handle's URL path, the owning
    /// [`crate::conn::Connection`] stream, and the download sink; that context
    /// is a documented placeholder in [`crate::protocols`] today, finalized by
    /// [`crate::transfer`]/[`crate::multi`]. DICT needs no protocol-specific
    /// connect, `do_more`, or `doing` step, so every other [`Protocol`] hook
    /// keeps its faithful no-op default — mirroring the `ZERO_NULL` entries of
    /// curl's `Curl_protocol_dict`.
    fn do_it<'a>(&'a self, _ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    /// The DICT "DONE" phase (← `Curl_protocol_dict.done`, which is `ZERO_NULL`).
    ///
    /// curl registers no `done` callback for DICT: there is no protocol-level
    /// teardown beyond the generic connection close. The [`Protocol`] trait
    /// requires the method, so this is the faithful no-op equivalent of the
    /// `NULL` pointer.
    fn done<'a>(
        &'a self,
        _ctx: &'a mut TransferCtx,
        _status: Result<()>,
        _premature: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

// ===========================================================================
// Request construction (← the body of `dict_do`).
// ===========================================================================

/// Build the DICT request buffer for a URL `path` (← the body of `dict_do`).
///
/// `path` is the raw `dict://…` path component (still percent-encoded). The
/// return is the exact bytes to send —
/// `CLIENT <version>\r\n<command>\r\nQUIT\r\n` — or `None` when the path selects
/// no command *and* contains no `'/'`, the case in which `dict_do` sends
/// nothing at all.
///
/// # Errors
///
/// Returns [`CURLE_URL_MALFORMAT`](crate::error::CurlCode::UrlMalformat) if the
/// path fails `REJECT_CTRL` percent-decoding.
fn build_request(path: &str) -> Result<Option<Vec<u8>>> {
    // curl url-decodes the path (REJECT_CTRL) before any command detection.
    let decoded = urldecode_reject_ctrl(path.as_bytes())?;

    if ascii_prefix_ci(&decoded, DICT_MATCH)
        || ascii_prefix_ci(&decoded, DICT_MATCH2)
        || ascii_prefix_ci(&decoded, DICT_MATCH3)
    {
        // The URL carries the fields in word:database:strategy order; the wire
        // command orders them MATCH <database> <strategy> <word>.
        let (word, database, strategy) = parse_match_fields(&decoded);
        let db = default_if_empty(database, DEFAULT_DATABASE);
        let strat = default_if_empty(strategy, DEFAULT_STRATEGY);
        let eword = unescape_word(word_or_default(word));
        Ok(Some(build_command_match(db, strat, &eword)))
    } else if ascii_prefix_ci(&decoded, DICT_DEFINE)
        || ascii_prefix_ci(&decoded, DICT_DEFINE2)
        || ascii_prefix_ci(&decoded, DICT_DEFINE3)
    {
        // The URL carries word:database; the wire command is DEFINE <database>
        // <word>.
        let (word, database) = parse_define_fields(&decoded);
        let db = default_if_empty(database, DEFAULT_DATABASE);
        let eword = unescape_word(word_or_default(word));
        Ok(Some(build_command_define(db, &eword)))
    } else {
        // Fallback: everything after the first '/', with every ':' turned into a
        // space, is sent verbatim as the command line. With no '/', send nothing.
        match decoded.iter().position(|&b| b == b'/') {
            Some(slash) => {
                let mut ppath = decoded[slash + 1..].to_vec();
                for byte in &mut ppath {
                    if *byte == b':' {
                        *byte = b' ';
                    }
                }
                Ok(Some(build_command_raw(&ppath)))
            }
            None => Ok(None),
        }
    }
}

// ===========================================================================
// Conversation driver (← `sendf` + `Curl_xfer_setup_recv`).
// ===========================================================================

/// Drive the DICT conversation over `stream`: send `request` in full, then read
/// the response to end-of-stream and return it verbatim.
///
/// curl issues the `CLIENT`/command/`QUIT` buffer in a single `sendf` and then
/// streams the entire server reply straight through to the download;
/// `read_to_end` mirrors that "read until the server closes" behavior and keeps
/// every byte exactly as received (curl does no DICT-level response parsing).
///
/// # Errors
///
/// Maps a write failure to [`CURLE_SEND_ERROR`](crate::error::CurlCode::SendError)
/// and a read failure to [`CURLE_RECV_ERROR`](crate::error::CurlCode::RecvError),
/// the codes curl's send/receive path surfaces.
async fn converse<S>(stream: &mut S, request: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await.map_err(|_| Error::Send)?;
    stream.flush().await.map_err(|_| Error::Send)?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|_| Error::Recv)?;
    Ok(response)
}

// ===========================================================================
// Field parsing, escaping, and command framing helpers.
// ===========================================================================

/// Case-insensitive ASCII prefix test (← `curl_strnequal(path, prefix, len)`).
///
/// `curl_strnequal` folds only ASCII letters (`lib/strcase.c`,
/// `Curl_raw_toupper`), which is exactly what [`slice::eq_ignore_ascii_case`]
/// does, so this is a faithful, locale-independent match.
fn ascii_prefix_ci(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack.len() >= prefix.len() && haystack[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// The optional `(word, database, strategy)` fields parsed from a `MATCH` path,
/// each borrowing from the decoded path (`None` = the field was absent, curl's
/// `NULL`). A named alias keeps the parser signature readable (and satisfies
/// `clippy::type_complexity`).
type MatchFields<'a> = (Option<&'a [u8]>, Option<&'a [u8]>, Option<&'a [u8]>);

/// The optional `(word, database)` fields parsed from a `DEFINE` path, each
/// borrowing from the decoded path (`None` = the field was absent).
type DefineFields<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);

/// Split the decoded path into `(word, database, strategy)` for a `MATCH`
/// request (← the `strchr` walk in `dict_do`'s MATCH branch).
///
/// The fields follow the first `':'` in `word:database:strategy` order; any
/// fourth field (curl's `nthdef`) is dropped, and `strategy` is truncated at it.
/// `None` marks an absent field (curl's `NULL`), which the caller resolves to a
/// default.
fn parse_match_fields(decoded: &[u8]) -> MatchFields<'_> {
    let rest = match decoded.iter().position(|&b| b == b':') {
        Some(i) => &decoded[i + 1..],
        None => return (None, None, None),
    };
    let (word, rest) = match rest.iter().position(|&b| b == b':') {
        Some(j) => (&rest[..j], &rest[j + 1..]),
        None => return (Some(rest), None, None),
    };
    let (database, rest) = match rest.iter().position(|&b| b == b':') {
        Some(k) => (&rest[..k], &rest[k + 1..]),
        None => return (Some(word), Some(rest), None),
    };
    // curl truncates the strategy at the next ':' (its `nthdef`).
    let strategy = match rest.iter().position(|&b| b == b':') {
        Some(m) => &rest[..m],
        None => rest,
    };
    (Some(word), Some(database), Some(strategy))
}

/// Split the decoded path into `(word, database)` for a `DEFINE` request (← the
/// `strchr` walk in `dict_do`'s DEFINE branch).
///
/// The fields follow the first `':'` in `word:database` order; any third field
/// (curl's `nthdef`) is dropped, and `database` is truncated at it.
fn parse_define_fields(decoded: &[u8]) -> DefineFields<'_> {
    let rest = match decoded.iter().position(|&b| b == b':') {
        Some(i) => &decoded[i + 1..],
        None => return (None, None),
    };
    let (word, rest) = match rest.iter().position(|&b| b == b':') {
        Some(j) => (&rest[..j], &rest[j + 1..]),
        None => return (Some(rest), None),
    };
    // curl truncates the database at the next ':' (its `nthdef`).
    let database = match rest.iter().position(|&b| b == b':') {
        Some(k) => &rest[..k],
        None => rest,
    };
    (Some(word), Some(database))
}

/// The word to look up, or curl's `"default"` when it is missing or empty
/// (← `(!word || (*word == 0)) ? "default" : word`).
fn word_or_default(word: Option<&[u8]>) -> &[u8] {
    match word {
        Some(w) if !w.is_empty() => w,
        _ => DEFAULT_WORD,
    }
}

/// A field value, or `default` when the field is missing or empty (← curl's
/// `(!field || (*field == 0)) ? default : field`).
fn default_if_empty<'a>(field: Option<&'a [u8]>, default: &'a [u8]) -> &'a [u8] {
    match field {
        Some(f) if !f.is_empty() => f,
        _ => default,
    }
}

/// Backslash-escape a lookup word per RFC 2229 §2.2 (← `unescape_word`).
///
/// Every byte that is space-or-below (`<= 0x20`), `DEL` (`0x7F`), `'`, `"`, or
/// `\` is emitted preceded by a `\`; the word is not otherwise quoted. Operates
/// on raw bytes (see the module-level signed-`char` note): a percent-decoded
/// byte `>= 0x80` passes through unescaped.
fn unescape_word(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        if b <= 0x20 || b == 0x7F || b == b'\'' || b == b'"' || b == b'\\' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out
}

/// Percent-decode `input`, rejecting decoded control bytes (← `Curl_urldecode`
/// in `REJECT_CTRL` mode, `lib/escape.c`).
///
/// A `%` is decoded only when at least two hex digits follow it (curl's
/// `alloc > 2 && ISXDIGIT && ISXDIGIT`); otherwise it is passed through
/// literally. Any resulting byte `< 0x20` aborts the decode; `DEL` (`0x7F`) is
/// deliberately *not* rejected, matching curl.
///
/// # Errors
///
/// [`CURLE_URL_MALFORMAT`](crate::error::CurlCode::UrlMalformat) if a decoded
/// byte is a control character.
fn urldecode_reject_ctrl(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let (byte, step) = decode_one(input, i);
        if byte < 0x20 {
            return Err(Error::url("DICT URL path contains a control character"));
        }
        out.push(byte);
        i += step;
    }
    Ok(out)
}

/// Decode the byte at `input[i]`, returning the decoded value and how many input
/// bytes it consumed (`3` for a `%XX` escape, `1` otherwise). Mirrors the single
/// step of curl's `Curl_urldecode` loop.
fn decode_one(input: &[u8], i: usize) -> (u8, usize) {
    if input[i] == b'%' && i + 2 < input.len() {
        if let (Some(hi), Some(lo)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
            return ((hi << 4) | lo, 3);
        }
    }
    (input[i], 1)
}

/// Value of a single ASCII hex digit, or `None` for a non-hex byte (← the
/// `ISXDIGIT`-guarded `curlx_hexval`).
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Assemble `CLIENT <version>\r\nMATCH <database> <strategy> <word>\r\nQUIT\r\n`
/// (← the MATCH `sendf` format string).
fn build_command_match(database: &[u8], strategy: &[u8], eword: &[u8]) -> Vec<u8> {
    let mut req = Vec::new();
    push_client_line(&mut req);
    req.extend_from_slice(b"MATCH ");
    req.extend_from_slice(database);
    req.push(b' ');
    req.extend_from_slice(strategy);
    req.push(b' ');
    req.extend_from_slice(eword);
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(b"QUIT\r\n");
    req
}

/// Assemble `CLIENT <version>\r\nDEFINE <database> <word>\r\nQUIT\r\n`
/// (← the DEFINE `sendf` format string).
fn build_command_define(database: &[u8], eword: &[u8]) -> Vec<u8> {
    let mut req = Vec::new();
    push_client_line(&mut req);
    req.extend_from_slice(b"DEFINE ");
    req.extend_from_slice(database);
    req.push(b' ');
    req.extend_from_slice(eword);
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(b"QUIT\r\n");
    req
}

/// Assemble `CLIENT <version>\r\n<command>\r\nQUIT\r\n` for the raw fallback
/// (← the else-branch `sendf` format string).
fn build_command_raw(command: &[u8]) -> Vec<u8> {
    let mut req = Vec::new();
    push_client_line(&mut req);
    req.extend_from_slice(command);
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(b"QUIT\r\n");
    req
}

/// Push the `CLIENT <version>\r\n` identification line (← `"CLIENT " LIBCURL_NAME
/// " " LIBCURL_VERSION "\r\n"`), using the workspace-wide [`crate::version`]
/// string so no version literal is hard-coded here.
fn push_client_line(req: &mut Vec<u8>) {
    req.extend_from_slice(b"CLIENT ");
    req.extend_from_slice(crate::version().as_bytes());
    req.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    // `Error`, `Result`, `Protocol`, `ProtoFuture`, and the Tokio traits are
    // private `use` aliases of the parent module, so `use super::*` does not
    // re-export them; import what the tests reference directly.
    use crate::error::CurlCode;
    use crate::protocols::{Protocol, TransferCtx};
    use std::io::{Error as IoError, ErrorKind};
    use tokio_test::io::Builder;

    // -- helpers ------------------------------------------------------------

    /// The full request frame the handler emits for a given command body,
    /// computed from [`crate::version`] so the expectation tracks the
    /// workspace-wide version string rather than a hard-coded literal.
    fn framed(command: &str) -> Vec<u8> {
        let mut v = format!("CLIENT {}\r\n", crate::version()).into_bytes();
        v.extend_from_slice(command.as_bytes());
        v.extend_from_slice(b"\r\nQUIT\r\n");
        v
    }

    /// `build_request` for a path that is expected to decode and to yield a
    /// request (panics otherwise), returning the request bytes.
    fn built(path: &str) -> Vec<u8> {
        build_request(path)
            .expect("path decodes without a control byte")
            .expect("path yields a request")
    }

    // -- command detection: MATCH / DEFINE aliases --------------------------

    #[test]
    fn every_match_alias_builds_a_match_command() {
        // URL order word:database:strategy → wire order MATCH <db> <strat> <word>.
        for path in [
            "/MATCH:cat:web:prefix",
            "/M:cat:web:prefix",
            "/FIND:cat:web:prefix",
        ] {
            assert_eq!(built(path), framed("MATCH web prefix cat"), "path {path}");
        }
    }

    #[test]
    fn every_define_alias_builds_a_define_command() {
        // URL order word:database → wire order DEFINE <db> <word>.
        for path in ["/DEFINE:cat:web", "/D:cat:web", "/LOOKUP:cat:web"] {
            assert_eq!(built(path), framed("DEFINE web cat"), "path {path}");
        }
    }

    #[test]
    fn prefixes_are_case_insensitive() {
        // curl uses `curl_strnequal` (ASCII case-insensitive), so mixed-case
        // prefixes select the same command as the canonical spellings.
        assert_eq!(
            built("/match:cat:web:prefix"),
            framed("MATCH web prefix cat")
        );
        assert_eq!(
            built("/FiNd:cat:web:prefix"),
            framed("MATCH web prefix cat")
        );
        assert_eq!(built("/m:cat:web:prefix"), framed("MATCH web prefix cat"));
        assert_eq!(built("/Define:cat:web"), framed("DEFINE web cat"));
        assert_eq!(built("/lOoKuP:cat:web"), framed("DEFINE web cat"));
    }

    #[test]
    fn test1450_basic_lookup_matches_curl() {
        // `tests/data/test1450`: `dict://…/d:basic`. Lowercase `/d:` must select
        // DEFINE (case-insensitive), with the default database `!` and the word
        // `basic` — i.e. the exact bytes `DEFINE ! basic`.
        assert_eq!(built("/d:basic"), framed("DEFINE ! basic"));
    }

    // -- default field substitution -----------------------------------------

    #[test]
    fn match_fills_missing_database_and_strategy() {
        assert_eq!(built("/MATCH:cat"), framed("MATCH ! . cat"));
        assert_eq!(built("/MATCH:cat:web"), framed("MATCH web . cat"));
    }

    #[test]
    fn define_fills_missing_database() {
        assert_eq!(built("/DEFINE:cat"), framed("DEFINE ! cat"));
    }

    #[test]
    fn empty_word_becomes_the_literal_default() {
        // curl substitutes "default" when the word is missing or empty.
        assert_eq!(built("/DEFINE:"), framed("DEFINE ! default"));
        assert_eq!(built("/MATCH:"), framed("MATCH ! . default"));
        assert_eq!(
            built("/MATCH::web:prefix"),
            framed("MATCH web prefix default")
        );
    }

    #[test]
    fn trailing_nthdef_field_is_discarded() {
        // The field beyond what a command uses (curl's `nthdef`) is dropped and
        // truncates the last used field at its ':'.
        assert_eq!(
            built("/MATCH:cat:web:prefix:extra"),
            framed("MATCH web prefix cat")
        );
        assert_eq!(built("/DEFINE:cat:web:extra"), framed("DEFINE web cat"));
    }

    // -- fallback (no recognized prefix) ------------------------------------

    #[test]
    fn fallback_sends_path_after_first_slash_with_colons_spaced() {
        // No MATCH/DEFINE prefix: everything after the first '/' is sent
        // verbatim, with each ':' turned into a space.
        assert_eq!(built("/show:db"), framed("show db"));
        assert_eq!(built("/spanish"), framed("spanish"));
        assert_eq!(built("/show:info:server"), framed("show info server"));
    }

    #[test]
    fn fallback_without_a_slash_sends_nothing() {
        // curl's else-branch does nothing when the path has no '/'.
        assert!(build_request("noslash").unwrap().is_none());
        assert!(build_request("").unwrap().is_none());
        assert!(build_request("word:only").unwrap().is_none());
    }

    // -- word escaping (RFC 2229 §2.2) --------------------------------------

    #[test]
    fn unescape_word_escapes_only_the_rfc2229_specials() {
        assert_eq!(unescape_word(b"word"), b"word");
        assert_eq!(unescape_word(b"a b"), b"a\\ b"); // space (<= 0x20)
        assert_eq!(unescape_word(b"a'b"), b"a\\'b");
        assert_eq!(unescape_word(b"a\"b"), b"a\\\"b");
        assert_eq!(unescape_word(b"a\\b"), b"a\\\\b");
        assert_eq!(unescape_word(b"a\tb"), b"a\\\tb"); // TAB (0x09 <= 0x20)
        assert_eq!(
            unescape_word(&[b'a', 0x01, b'b']),
            &[b'a', b'\\', 0x01, b'b']
        );
        assert_eq!(unescape_word(&[0x7f]), &[b'\\', 0x7f]); // DEL
    }

    #[test]
    fn unescape_word_leaves_high_bytes_unescaped() {
        // Unsigned-byte interpretation: bytes >= 0x80 are not escaped (see the
        // module-level signed-`char` note).
        assert_eq!(unescape_word(&[0x80, 0xff]), &[0x80, 0xff]);
    }

    #[test]
    fn escaping_flows_into_the_built_request() {
        // `%20` decodes to a space, which is then backslash-escaped in the word.
        assert_eq!(built("/DEFINE:a%20b"), framed("DEFINE ! a\\ b"));
    }

    // -- percent-decoding (Curl_urldecode, REJECT_CTRL) ---------------------

    #[test]
    fn urldecode_handles_escapes_and_literals() {
        assert_eq!(urldecode_reject_ctrl(b"hello").unwrap(), b"hello");
        assert_eq!(urldecode_reject_ctrl(b"%41%42").unwrap(), b"AB");
        assert_eq!(urldecode_reject_ctrl(b"a%20b").unwrap(), b"a b");
        assert_eq!(urldecode_reject_ctrl(b"a%25b").unwrap(), b"a%b");
        assert_eq!(urldecode_reject_ctrl(b"%2f").unwrap(), b"/"); // lowercase hex
        assert_eq!(
            urldecode_reject_ctrl(b"a%7fb").unwrap(),
            &[b'a', 0x7f, b'b']
        ); // DEL allowed
    }

    #[test]
    fn urldecode_passes_through_incomplete_or_nonhex_escapes() {
        assert_eq!(urldecode_reject_ctrl(b"%2").unwrap(), b"%2"); // too short
        assert_eq!(urldecode_reject_ctrl(b"%").unwrap(), b"%");
        assert_eq!(urldecode_reject_ctrl(b"%zz").unwrap(), b"%zz"); // non-hex
        assert_eq!(urldecode_reject_ctrl(b"%2x").unwrap(), b"%2x"); // second non-hex
        assert_eq!(urldecode_reject_ctrl(b"100%25").unwrap(), b"100%");
    }

    #[test]
    fn urldecode_rejects_control_bytes() {
        assert!(urldecode_reject_ctrl(b"a%00b").is_err()); // NUL
        assert!(urldecode_reject_ctrl(b"a%1fb").is_err()); // US
        assert!(urldecode_reject_ctrl(b"a%0ab").is_err()); // LF
        assert!(urldecode_reject_ctrl(&[b'a', 0x01, b'b']).is_err()); // literal control
    }

    #[test]
    fn build_request_maps_bad_url_to_url_malformat() {
        let err = build_request("/DEFINE:%00").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
        assert_eq!(err.code_i32(), 3);
    }

    // -- small helpers -------------------------------------------------------

    #[test]
    fn ascii_prefix_ci_folds_ascii_case_and_checks_length() {
        assert!(ascii_prefix_ci(b"/MATCH:x", DICT_MATCH));
        assert!(ascii_prefix_ci(b"/match:x", DICT_MATCH));
        assert!(ascii_prefix_ci(b"/mAtCh:x", DICT_MATCH));
        assert!(!ascii_prefix_ci(b"/MATC", DICT_MATCH)); // shorter than prefix
        assert!(!ascii_prefix_ci(b"/DEFINE:", DICT_MATCH)); // different prefix
    }

    #[test]
    fn hex_val_decodes_only_hex_digits() {
        assert_eq!(hex_val(b'0'), Some(0));
        assert_eq!(hex_val(b'9'), Some(9));
        assert_eq!(hex_val(b'a'), Some(10));
        assert_eq!(hex_val(b'f'), Some(15));
        assert_eq!(hex_val(b'A'), Some(10));
        assert_eq!(hex_val(b'F'), Some(15));
        assert_eq!(hex_val(b'g'), None);
        assert_eq!(hex_val(b'/'), None);
    }

    // -- CLIENT banner form --------------------------------------------------

    #[test]
    fn client_banner_uses_the_workspace_version_not_libcurl() {
        let req = String::from_utf8(built("/d:basic")).expect("ASCII request");
        assert!(
            req.starts_with("CLIENT curl-rs/8.19.0-DEV"),
            "banner: {req:?}"
        );
        assert!(!req.contains("libcurl"));
        assert!(req.contains("\r\nDEFINE ! basic\r\n"));
        assert!(req.ends_with("QUIT\r\n"));
    }

    // -- conversation driver (converse) -------------------------------------

    #[tokio::test]
    async fn converse_passes_the_response_through_unchanged() {
        let request = b"CLIENT x\r\nDEFINE ! basic\r\nQUIT\r\n";
        // A dictserver-style reply (banner + status line); every byte must be
        // returned verbatim.
        let response: &[u8] = b"220 dictd <auth.mime> <1@server>\n552 no match\n.\n250 ok\n";
        let mut mock = Builder::new().write(request).read(response).build();

        let got = converse(&mut mock, request).await.unwrap();
        assert_eq!(got, response);
    }

    #[tokio::test]
    async fn converse_reads_to_end_of_stream() {
        // An empty reply followed by EOF yields an empty body, not an error.
        let request = b"CLIENT x\r\nQUIT\r\n";
        let mut mock = Builder::new().write(request).build();
        let got = converse(&mut mock, request).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn converse_maps_write_failure_to_send_error() {
        let mut mock = Builder::new()
            .write_error(IoError::new(ErrorKind::BrokenPipe, "boom"))
            .build();
        let err = converse(&mut mock, b"data").await.unwrap_err();
        assert_eq!(err.code(), CurlCode::SendError);
        assert_eq!(err.code_i32(), 55);
    }

    #[tokio::test]
    async fn converse_maps_read_failure_to_recv_error() {
        let request = b"req";
        let mut mock = Builder::new()
            .write(request)
            .read_error(IoError::new(ErrorKind::ConnectionReset, "boom"))
            .build();
        let err = converse(&mut mock, request).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::RecvError);
        assert_eq!(err.code_i32(), 56);
    }

    // -- end-to-end handler transfer ----------------------------------------

    #[tokio::test]
    async fn transfer_writes_request_and_appends_response() {
        let expected = built("/d:basic");
        let response: &[u8] = b"552 no match\n";
        let mut mock = Builder::new().write(&expected).read(response).build();

        let mut out = Vec::new();
        HANDLER
            .transfer("/d:basic", &mut mock, &mut out)
            .await
            .unwrap();
        assert_eq!(out, response);
    }

    #[tokio::test]
    async fn transfer_without_a_slash_touches_no_stream() {
        // No request is built, so the stream (with no expectations) is untouched
        // and the output stays empty.
        let mut mock = Builder::new().build();
        let mut out = Vec::new();
        HANDLER
            .transfer("noslash", &mut mock, &mut out)
            .await
            .unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn transfer_propagates_url_malformat_before_any_io() {
        let mut mock = Builder::new().build();
        let mut out = Vec::new();
        let err = HANDLER
            .transfer("/DEFINE:%00", &mut mock, &mut out)
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
        assert!(out.is_empty());
    }

    // -- Protocol trait wiring ----------------------------------------------

    #[tokio::test]
    async fn handler_do_it_completes_and_done_is_noop() {
        // Reproduces `dict_do` setting `*done = TRUE` (DO completes in one step)
        // and the `ZERO_NULL` `done` pointer (a faithful no-op).
        let dynref: &dyn Protocol = &HANDLER;
        let mut ctx = TransferCtx::new();
        assert!(dynref.do_it(&mut ctx).await.unwrap());
        assert!(dynref.done(&mut ctx, Ok(()), false).await.is_ok());
        assert!(dynref.done(&mut ctx, Ok(()), true).await.is_ok());
    }
}
