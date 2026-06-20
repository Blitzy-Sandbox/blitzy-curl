//! The DICT protocol engine — the `dict://` scheme handler.
//!
//! This is the idiomatic, async Rust analog of curl's C `lib/dict.c` (consumed
//! strictly as a behavioral oracle, never transliterated). DICT (RFC 2229) is a
//! deliberately tiny TCP query protocol for dictionary look-ups: there is no
//! authentication, no TLS, and no persistent login state machine. A single
//! request is issued over a plain TCP connection and the server's response body
//! is streamed back to the client unchanged.
//!
//! # What `do_it` does (mirrors C `dict_do`)
//!
//! DICT has no `connect`/`done`/`disconnect` work — the C `Curl_protocol_dict`
//! vtable wires up *only* `do_it`. The handler therefore implements just
//! [`Protocol::scheme`] and [`Protocol::do_it`], inheriting every other
//! [`Protocol`] method's default.
//!
//! `do_it`:
//!
//! 1. reads the configured request URL and extracts its URL-decoded path
//!    (curl's `Curl_urldecode(data->state.up.path, …, REJECT_CTRL)`),
//! 2. maps that path to one DICT command — `DEFINE`, `MATCH`, or a raw command
//!    — exactly reproducing curl's path grammar and word escaping,
//! 3. sends a single `CLIENT … / <command> / QUIT` request over the
//!    already-established [`crate::conn::Connection`] (the standard plain-TCP
//!    filter chain), and
//! 4. returns a [`ProtocolTransfer`] describing a download so the transfer
//!    engine reads the response body and writes it to the client — the analog of
//!    curl's `Curl_xfer_setup_recv(data, FIRSTSOCKET, -1)`. (The engine, not the
//!    handler, owns the client-writer chain, exactly as in C where `dict_do`
//!    only *sets up* the receive and the generic transfer loop performs it.)
//!
//! # URL → command grammar (parity-critical, reproduced byte-for-byte)
//!
//! The URL-decoded path selects the command by a case-insensitive prefix:
//!
//! * `/MATCH:`, `/M:`, `/FIND:`  → `MATCH <database> <strategy> <word>`
//! * `/DEFINE:`, `/D:`, `/LOOKUP:` → `DEFINE <database> <word>`
//! * anything else                → a raw command (the path after the first
//!   `/`, with every `:` turned into a space)
//!
//! For the `MATCH`/`DEFINE` forms the remainder is split on `:` into
//! `word:database[:strategy]`; a missing database defaults to `!` (curl's
//! "first/any database" sentinel), a missing strategy to `.` (the server's
//! default strategy), and a missing word to `default` (with an info trace, as in
//! curl). The word is escaped per RFC 2229 §2.2 (see [`escape_word`]).
//!
//! # Memory safety
//!
//! This module inherits `#![forbid(unsafe_code)]` from [`crate::protocols`]; it
//! contains zero `unsafe` and does not re-declare the attribute (re-forbidding an
//! already-forbidden lint is itself a lint). All I/O flows through the safe
//! [`crate::conn`] filter-chain API.

use crate::conn::{BoxFuture, Connection, Curl_conn_send, FIRSTSOCKET};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{
    connect_network_scheme, stream_body_to_sink, Protocol, ProtocolTransfer, Scheme,
    TransferDirection, SCHEME_DICT,
};
use crate::transfer::{ReadCallback, WriteCallbacks};
use crate::url::{CurlUPart, CurlUrl, CURLU_URLDECODE};
use crate::version;

// ===========================================================================
// Command-prefix tokens (C `dict.c` `DICT_MATCH*` / `DICT_DEFINE*` `#define`s).
//
// Matched case-insensitively against the URL-decoded path, exactly like curl's
// `curl_strnequal(path, DICT_*, sizeof(DICT_*) - 1)`.
// ===========================================================================

/// `MATCH` alias `/MATCH:` (C `DICT_MATCH`).
const DICT_MATCH: &str = "/MATCH:";
/// `MATCH` alias `/M:` (C `DICT_MATCH2`).
const DICT_MATCH2: &str = "/M:";
/// `MATCH` alias `/FIND:` (C `DICT_MATCH3`).
const DICT_MATCH3: &str = "/FIND:";
/// `DEFINE` alias `/DEFINE:` (C `DICT_DEFINE`).
const DICT_DEFINE: &str = "/DEFINE:";
/// `DEFINE` alias `/D:` (C `DICT_DEFINE2`).
const DICT_DEFINE2: &str = "/D:";
/// `DEFINE` alias `/LOOKUP:` (C `DICT_DEFINE3`).
const DICT_DEFINE3: &str = "/LOOKUP:";

/// The sentinel curl sends for "any/first database" when none is supplied.
const DEFAULT_DATABASE: &str = "!";
/// The sentinel curl sends for "server default strategy" when none is supplied.
const DEFAULT_STRATEGY: &str = ".";
/// The placeholder word curl substitutes when the look-up word is empty.
const DEFAULT_WORD: &str = "default";

// ===========================================================================
// Pure helpers — URL-path grammar and word escaping.
// ===========================================================================

/// Case-insensitive ASCII prefix test — the analog of curl's
/// `curl_strnequal(path, prefix, strlen(prefix))`.
///
/// Compares raw bytes (the prefixes are pure ASCII), so it never panics on a
/// non-char-boundary slice.
fn ci_starts_with(s: &str, prefix: &str) -> bool {
    let (s, p) = (s.as_bytes(), prefix.as_bytes());
    s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p)
}

/// Escape a DICT look-up word per RFC 2229 §2.2 — the analog of curl's
/// `unescape_word` (which, despite its name, *adds* the protective backslashes).
///
/// Every space/control character, `DEL`, single quote, double quote, and
/// backslash is prefixed with a `\`. Non-ASCII (multi-byte) characters are
/// passed through unchanged, which both preserves valid UTF-8 and matches the
/// behavior of curl built with an unsigned `char` (e.g. on aarch64); the DICT
/// test corpus uses ASCII words, so the distinction is unobservable in practice.
fn escape_word(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        // `c <= ' '` covers U+0000..=U+0020 (all controls plus space), matching
        // curl's `ch <= 32`.
        if c <= ' ' || c == '\u{7f}' || c == '\'' || c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A parsed DICT request: the single command line to place between the `CLIENT`
/// and `QUIT` lines, plus whether the look-up word was missing (so the caller can
/// emit curl's "lookup word is missing" info trace).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DictRequest {
    /// The command line, e.g. `"DEFINE foldoc curl"`, `"MATCH ! . curl"`, or a
    /// raw `"<command>"`.
    command: String,
    /// `true` when a `DEFINE`/`MATCH` look-up word was empty and the
    /// [`DEFAULT_WORD`] placeholder was substituted.
    word_missing: bool,
}

/// Map a URL-decoded DICT path to its command line, reproducing curl's
/// `dict_do` grammar exactly.
///
/// Returns `None` only for the raw form when the path contains no `/` (curl
/// sends nothing in that case and the transfer completes with no body).
fn parse_dict_path(path: &str) -> Option<DictRequest> {
    if ci_starts_with(path, DICT_MATCH)
        || ci_starts_with(path, DICT_MATCH2)
        || ci_starts_with(path, DICT_MATCH3)
    {
        // `word:database:strategy[:nthdef]` — curl splits on ':' and ignores
        // any field beyond the strategy.
        let mut fields = path.split(':');
        let _prefix = fields.next(); // the "/M" / "/MATCH" / "/FIND" token
        let word = fields.next().unwrap_or("");
        let database = fields.next().unwrap_or("");
        let strategy = fields.next().unwrap_or("");

        let word_missing = word.is_empty();
        let eword = escape_word(if word.is_empty() { DEFAULT_WORD } else { word });
        let database = if database.is_empty() {
            DEFAULT_DATABASE
        } else {
            database
        };
        let strategy = if strategy.is_empty() {
            DEFAULT_STRATEGY
        } else {
            strategy
        };

        Some(DictRequest {
            command: format!("MATCH {database} {strategy} {eword}"),
            word_missing,
        })
    } else if ci_starts_with(path, DICT_DEFINE)
        || ci_starts_with(path, DICT_DEFINE2)
        || ci_starts_with(path, DICT_DEFINE3)
    {
        // `word:database[:nthdef]` — curl splits on ':' and ignores any field
        // beyond the database.
        let mut fields = path.split(':');
        let _prefix = fields.next(); // the "/D" / "/DEFINE" / "/LOOKUP" token
        let word = fields.next().unwrap_or("");
        let database = fields.next().unwrap_or("");

        let word_missing = word.is_empty();
        let eword = escape_word(if word.is_empty() { DEFAULT_WORD } else { word });
        let database = if database.is_empty() {
            DEFAULT_DATABASE
        } else {
            database
        };

        Some(DictRequest {
            command: format!("DEFINE {database} {eword}"),
            word_missing,
        })
    } else {
        // Raw form: take everything after the first '/' and turn every ':' into
        // a space (curl's in-place `ppath[i] == ':' -> ' '`). With no '/' curl
        // sends nothing.
        path.find('/').map(|idx| DictRequest {
            command: path[idx + 1..].replace(':', " "),
            word_missing: false,
        })
    }
}

/// Wrap a DICT command line into the full request curl sends: an identifying
/// `CLIENT` line, the command, and a trailing `QUIT`, each CRLF-terminated
/// (C `dict_do`'s `"CLIENT " LIBCURL_NAME " " LIBCURL_VERSION "\r\n…QUIT\r\n"`).
fn wrap_request(command: &str) -> String {
    // The `CLIENT` line is sent verbatim to the DICT server, so it must match
    // curl's wire bytes exactly (AAP G6): C emits the wire product name
    // `LIBCURL_NAME` ("libcurl"), NOT the rewrite's consumer-facing identity
    // `version::NAME` ("curl-rs"). See `version::LIBCURL_NAME`.
    let (name, ver) = (version::LIBCURL_NAME, version::VERSION);
    format!("CLIENT {name} {ver}\r\n{command}\r\nQUIT\r\n")
}

/// Send an entire buffer over `FIRSTSOCKET`, looping until every byte is
/// accepted — the analog of curl's `sendf` write loop.
///
/// `eos` is `false`: the request is complete but the connection stays open for
/// the response, exactly as curl passes `FALSE` to `Curl_xfer_send`.
async fn send_all(conn: &mut Connection, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        let written = Curl_conn_send(conn, FIRSTSOCKET, buf, false).await?;
        if written == 0 {
            // No forward progress on an open stream: treat as a send failure
            // rather than spin forever (curl's blocking loop cannot observe a
            // zero-length non-error write).
            return Err(CurlError::SendError);
        }
        buf = &buf[written..];
    }
    Ok(())
}

// ===========================================================================
// The protocol handler.
// ===========================================================================

/// The `dict://` protocol handler — the Rust analog of curl's
/// `Curl_protocol_dict` (`lib/dict.c`).
///
/// It is a zero-sized, stateless singleton: all per-transfer state lives on the
/// [`Easy`] handle and the [`Connection`], so one value can serve every DICT
/// transfer. Construct it with [`DictHandler::new`].
#[derive(Debug, Clone, Copy, Default)]
pub struct DictHandler;

impl DictHandler {
    /// Create a DICT handler.
    #[must_use]
    pub const fn new() -> Self {
        DictHandler
    }
}

impl Protocol for DictHandler {
    /// The static `dict` scheme descriptor (`Curl_scheme_dict`): default port
    /// 2628, flags `PROTOPT_NONE | PROTOPT_NOURLQUERY`.
    fn scheme(&self) -> &'static Scheme {
        &SCHEME_DICT
    }

    /// Issue the DICT request and set up reception of the response body
    /// (C `dict_do`).
    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            // The configured URL must be present by the time a transfer starts;
            // defensively map its absence to a malformed-URL error.
            let url = match data.url() {
                Some(url) => url.to_owned(),
                None => return Err(CurlError::UrlMalformat),
            };

            // Extract the URL-decoded path (curl decodes `state.up.path` with
            // REJECT_CTRL; `CURLU_URLDECODE` applies the same control rejection).
            let path = {
                let mut parsed = CurlUrl::new();
                parsed
                    .set(CurlUPart::Url, Some(&url), 0)
                    .map_err(|_| CurlError::UrlMalformat)?;
                parsed
                    .get(CurlUPart::Path, CURLU_URLDECODE)
                    .map_err(|_| CurlError::UrlMalformat)?
            };

            // Map the path to a DICT command. `None` is curl's "raw path with no
            // '/'" case: nothing is sent and the transfer carries no body.
            let Some(request) = parse_dict_path(&path) else {
                return Ok(ProtocolTransfer::new(TransferDirection::None));
            };

            if request.word_missing {
                crate::infof!(data.set.verbose, "lookup word is missing");
            }

            let payload = wrap_request(&request.command);
            if let Err(err) = send_all(conn, payload.as_bytes()).await {
                crate::infof!(data.set.verbose, "Failed sending DICT request");
                return Err(err);
            }

            // The server now streams the look-up response; the transfer engine
            // reads it over this connection and writes it to the client
            // (C `Curl_xfer_setup_recv(data, FIRSTSOCKET, -1)`).
            Ok(ProtocolTransfer::new(TransferDirection::Download))
        })
    }
}

// ===========================================================================
// Transfer-engine driver (C `Curl_do` → `Curl_done` for a `dict://` transfer).
// ===========================================================================

/// Drive a `dict://` transfer end-to-end, the DICT analog of
/// [`pop3::perform_pop3`](crate::protocols::pop3::perform_pop3) and the seam
/// [`perform_transfer`](crate::protocols::perform_transfer) dispatches every
/// `dict` scheme to. DICT has a single (plain-TCP, default port 2628) scheme
/// with no TLS variant and no login phase, so the drive is the minimal
/// connect → DO → stream → done shape:
///
/// 1. Open the connection-filter chain (plain TCP) with
///    [`connect_network_scheme`].
/// 2. [`DictHandler::do_it`](Protocol::do_it) issues the `DEFINE`/`MATCH`/raw
///    command (C `dict_do`) and reports a [`TransferDirection::Download`] (or
///    [`TransferDirection::None`] for the raw-path-without-`/` case, where curl
///    sends nothing and the transfer carries no body).
/// 3. For a download, [`stream_body_to_sink`] reads the look-up response off the
///    socket and writes it to the client `sink` until the server closes the
///    connection (DICT has no length framing; C
///    `Curl_xfer_setup_recv(data, FIRSTSOCKET, -1)` reads to EOF).
/// 4. [`done`](Protocol::done) and [`disconnect`](Protocol::disconnect) finalize
///    the transfer (both no-ops for DICT — there is no `QUIT` chatter).
///
/// This is the wiring whose absence produced QA finding **F5-CRIT-5** (every
/// `dict://` transfer returned `UnsupportedProtocol` before a socket opened).
///
/// # Errors
///
/// Propagates any connection-setup, request-send, body-streaming, or finalize
/// error as the corresponding [`CurlError`].
pub(crate) async fn perform_dict(
    data: &mut Easy,
    sink: &mut dyn WriteCallbacks,
    _source: &mut dyn ReadCallback,
) -> Result<()> {
    // DICT has exactly one scheme descriptor (no implicit-TLS variant).
    let scheme: &'static Scheme = &SCHEME_DICT;

    // (1) Establish the plain-TCP connection over the filter chain.
    let mut conn = connect_network_scheme(data, scheme).await?;

    // (2) DICT has no greeting/login phase (`connect` defaults to a no-op);
    //     call it for parity with the other protocol drivers.
    let handler = DictHandler::new();
    handler.connect(data, &mut conn).await?;

    // (3) DO phase: issue the request and stream the response body to the
    //     client. Body movement is fenced so a failure still runs `done`.
    let result: Result<()> = async {
        let xfer = handler.do_it(data, &mut conn).await?;
        if xfer.direction == TransferDirection::Download {
            // DICT responses have no length framing — read until the server
            // closes (`expected = None`); there is no engine-buffered prefix.
            stream_body_to_sink(data, &mut conn, sink, &[], xfer.expected_size).await?;
        }
        Ok(())
    }
    .await;

    // (4) Finalize then best-effort tear-down. A transfer-phase error takes
    //     precedence over the `done` result (curl: `result = done(); if(!result)
    //     result = status;`), so the driver returns `result.and(done)` — the
    //     transfer error when `result` failed, otherwise the `done` outcome.
    //     `CurlError` is `Copy`, so `result` is still readable after the move
    //     into `done`. This matters because DICT uses the default no-op `done`,
    //     which would otherwise mask a `do_it`/stream error as success.
    let premature = result.is_err();
    let done = handler.done(data, &mut conn, result, premature).await;
    let _ = handler.disconnect(data, &mut conn, done.is_err()).await;
    result.and(done)
}

// ===========================================================================
// Tests — the URL→command grammar and word escaping are the parity-critical
// surface, so they are exercised exhaustively against curl's `dict_do` behavior
// (`lib/dict.c`). The async `do_it` path is driven end-to-end over a captured
// in-memory filter to assert the exact bytes placed on the wire.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{CfState, ConnectionFilter};
    use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};
    use crate::options::CurlOption;
    use crate::setopt::OptionValue;
    use std::sync::{Arc, Mutex};

    // -- helpers ------------------------------------------------------------

    /// Convenience: the command line a successfully-parsed path yields.
    fn command_of(path: &str) -> String {
        parse_dict_path(path)
            .unwrap_or_else(|| panic!("path {path:?} should parse to a command"))
            .command
    }

    // -- ci_starts_with -----------------------------------------------------

    #[test]
    fn ci_starts_with_is_case_insensitive_and_length_checked() {
        assert!(ci_starts_with("/D:word", "/d:"));
        assert!(ci_starts_with("/define:word", DICT_DEFINE));
        assert!(ci_starts_with("/MaTcH:w", DICT_MATCH));
        // Not a prefix.
        assert!(!ci_starts_with("/x:word", "/d:"));
        // Shorter than the prefix can never match.
        assert!(!ci_starts_with("/d", "/d:"));
        assert!(!ci_starts_with("", "/d:"));
    }

    // -- escape_word (RFC 2229 §2.2) ---------------------------------------

    #[test]
    fn escape_word_leaves_plain_ascii_untouched() {
        assert_eq!(escape_word("curl"), "curl");
        assert_eq!(escape_word("foldoc"), "foldoc");
        // Printable punctuation outside the protected set is passed through.
        assert_eq!(escape_word("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(escape_word(""), "");
    }

    #[test]
    fn escape_word_escapes_spaces_and_controls() {
        // A space (0x20) is `<= ' '`, so it is backslash-protected.
        assert_eq!(escape_word("two words"), "two\\ words");
        assert_eq!(escape_word(" lead"), "\\ lead");
        // Control characters (tab, newline) are escaped.
        assert_eq!(escape_word("a\tb"), "a\\\tb");
        assert_eq!(escape_word("a\nb"), "a\\\nb");
        // DEL (0x7f) is explicitly escaped.
        assert_eq!(escape_word("a\u{7f}b"), "a\\\u{7f}b");
    }

    #[test]
    fn escape_word_escapes_quotes_and_backslash() {
        assert_eq!(escape_word("a'b"), "a\\'b");
        assert_eq!(escape_word("a\"b"), "a\\\"b");
        assert_eq!(escape_word("a\\b"), "a\\\\b");
        // All three together.
        assert_eq!(escape_word("'\"\\"), "\\'\\\"\\\\");
    }

    #[test]
    fn escape_word_passes_non_ascii_through() {
        // Multi-byte UTF-8 is not in the protected set and is emitted verbatim,
        // matching curl built with an unsigned `char`.
        assert_eq!(escape_word("café"), "café");
        assert_eq!(escape_word("naïve"), "naïve");
    }

    // -- parse_dict_path: DEFINE -------------------------------------------

    #[test]
    fn define_maps_word_and_database() {
        // The agent-prompt's canonical example: `/d:curl:foldoc` → DEFINE.
        let req = parse_dict_path("/d:curl:foldoc").expect("define parses");
        assert_eq!(req.command, "DEFINE foldoc curl");
        assert!(!req.word_missing);
    }

    #[test]
    fn define_recognizes_all_aliases_case_insensitively() {
        for path in [
            "/d:curl:foldoc",
            "/D:curl:foldoc",
            "/define:curl:foldoc",
            "/DEFINE:curl:foldoc",
            "/lookup:curl:foldoc",
            "/LOOKUP:curl:foldoc",
        ] {
            assert_eq!(command_of(path), "DEFINE foldoc curl", "alias {path:?}");
        }
    }

    #[test]
    fn define_defaults_missing_database_to_bang() {
        // No database field → curl's `!` sentinel.
        assert_eq!(command_of("/d:curl"), "DEFINE ! curl");
    }

    #[test]
    fn define_missing_word_substitutes_default_and_flags_it() {
        // Empty word → "default" placeholder and the missing-word flag.
        let req = parse_dict_path("/d::foldoc").expect("define parses");
        assert_eq!(req.command, "DEFINE foldoc default");
        assert!(req.word_missing);

        // Bare "/d:" → empty word, empty database.
        let req = parse_dict_path("/d:").expect("define parses");
        assert_eq!(req.command, "DEFINE ! default");
        assert!(req.word_missing);
    }

    #[test]
    fn define_escapes_word_with_spaces() {
        // `word:database` where the word contains a space.
        assert_eq!(
            command_of("/d:two words:foldoc"),
            "DEFINE foldoc two\\ words"
        );
    }

    #[test]
    fn define_ignores_trailing_nthdef_field() {
        // curl keeps only word:database; any 3rd field (nthdef) is discarded.
        assert_eq!(command_of("/d:curl:foldoc:3"), "DEFINE foldoc curl");
    }

    // -- parse_dict_path: MATCH --------------------------------------------

    #[test]
    fn match_defaults_database_and_strategy() {
        // The agent-prompt's canonical example: `/m:curl::` → MATCH defaults.
        let req = parse_dict_path("/m:curl::").expect("match parses");
        assert_eq!(req.command, "MATCH ! . curl");
        assert!(!req.word_missing);
    }

    #[test]
    fn match_recognizes_all_aliases_case_insensitively() {
        for path in [
            "/m:curl::",
            "/M:curl::",
            "/match:curl::",
            "/MATCH:curl::",
            "/find:curl::",
            "/FIND:curl::",
        ] {
            assert_eq!(command_of(path), "MATCH ! . curl", "alias {path:?}");
        }
    }

    #[test]
    fn match_maps_word_database_and_strategy() {
        // Full `word:database:strategy`.
        assert_eq!(
            command_of("/m:dog:wordnet:exact"),
            "MATCH wordnet exact dog"
        );
    }

    #[test]
    fn match_missing_word_substitutes_default_and_flags_it() {
        let req = parse_dict_path("/m:").expect("match parses");
        assert_eq!(req.command, "MATCH ! . default");
        assert!(req.word_missing);
    }

    #[test]
    fn match_ignores_trailing_nthdef_field() {
        // A 4th field beyond strategy is discarded.
        assert_eq!(
            command_of("/match:dog:wordnet:exact:2"),
            "MATCH wordnet exact dog"
        );
    }

    #[test]
    fn match_escapes_word_with_spaces() {
        assert_eq!(
            command_of("/m:two words:db:exact"),
            "MATCH db exact two\\ words"
        );
    }

    // -- parse_dict_path: raw ----------------------------------------------

    #[test]
    fn raw_command_replaces_colons_with_spaces() {
        // No DEFINE/MATCH prefix → raw: everything after the first '/' with
        // every ':' turned into a space.
        let req = parse_dict_path("/show:db").expect("raw parses");
        assert_eq!(req.command, "show db");
        assert!(!req.word_missing);

        assert_eq!(command_of("/show:info:server"), "show info server");
        assert_eq!(command_of("/help"), "help");
    }

    #[test]
    fn raw_root_path_yields_empty_command() {
        // "/" → after the leading '/' nothing remains; curl still sends an
        // (empty) command line, so this parses to an empty command rather than
        // `None`.
        let req = parse_dict_path("/").expect("root parses");
        assert_eq!(req.command, "");
        assert!(!req.word_missing);
    }

    #[test]
    fn raw_without_slash_yields_none() {
        // curl's raw branch sends nothing when the path holds no '/'. URL paths
        // always start with '/', so this is the defensive no-op case.
        assert!(parse_dict_path("noslash").is_none());
        assert!(parse_dict_path("").is_none());
    }

    // -- wrap_request -------------------------------------------------------

    #[test]
    fn wrap_request_frames_with_client_and_quit() {
        let framed = wrap_request("DEFINE foldoc curl");
        // The wire `CLIENT` line carries the on-the-wire product name
        // `LIBCURL_NAME` ("libcurl") — NOT the consumer-facing `version::NAME`
        // ("curl-rs") — so it byte-matches C `dict_do` (AAP G6).
        let expected = format!(
            "CLIENT {} {}\r\nDEFINE foldoc curl\r\nQUIT\r\n",
            version::LIBCURL_NAME,
            version::VERSION
        );
        assert_eq!(framed, expected);
        // Pin the exact oracle bytes so a regression in either constant is
        // caught here, not only at runtime against a live server.
        assert_eq!(
            framed,
            "CLIENT libcurl 8.19.0-DEV\r\nDEFINE foldoc curl\r\nQUIT\r\n"
        );
        // Structural invariants regardless of the version string.
        assert!(framed.starts_with("CLIENT "));
        assert!(framed.ends_with("\r\nQUIT\r\n"));
    }

    // -- scheme descriptor --------------------------------------------------

    #[test]
    fn scheme_matches_the_dict_oracle() {
        let handler = DictHandler::new();
        let scheme = handler.scheme();
        // The handler hands back the canonical `dict` descriptor (compared by
        // value: `SCHEME_DICT` is a `const`, so it is inlined per use-site and
        // pointer identity is not guaranteed).
        assert_eq!(*scheme, SCHEME_DICT);
        // The oracle values from `const struct Curl_scheme Curl_scheme_dict`.
        assert_eq!(scheme.name, "dict");
        assert_eq!(scheme.default_port, 2628);
    }

    #[test]
    fn handler_is_zero_sized_and_default_matches_new() {
        assert_eq!(std::mem::size_of::<DictHandler>(), 0);
        // Exercise the derived `Default` impl via a generic so clippy does not
        // (rightly) flag a direct unit-struct `::default()` construction; this
        // still proves `DictHandler: Default` produces a working handler.
        fn defaulted<T: Default>() -> T {
            T::default()
        }
        assert_eq!(defaulted::<DictHandler>().scheme().name, "dict");
        // `new` is a const fn usable in const context.
        const H: DictHandler = DictHandler::new();
        assert_eq!(H.scheme().name, "dict");
    }

    // -- do_it: end-to-end I/O over a captured filter ----------------------

    /// A minimal connected filter that records every byte `send` receives, so
    /// the test can assert the exact request `do_it` puts on the wire.
    struct CapturingFilter {
        state: CfState,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturingFilter {
        fn new(sent: Arc<Mutex<Vec<u8>>>) -> Self {
            let mut state = CfState::new();
            // Mark connected so `FilterChain::send` routes to this filter
            // (it walks to the first connected node, mirroring `Curl_cf_send`).
            state.connected = true;
            Self { state, sent }
        }
    }

    impl ConnectionFilter for CapturingFilter {
        fn name(&self) -> &'static str {
            "capturing"
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
        fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
            let sink = self.sent.clone();
            let n = buf.len();
            Box::pin(async move {
                sink.lock().expect("sent lock").extend_from_slice(buf);
                Ok(n)
            })
        }
    }

    /// Drive `do_it` for `url` and return `(bytes-sent, result)`.
    async fn run_do_it(url: &str) -> (Vec<u8>, Result<ProtocolTransfer>) {
        let mut data = Easy::new();
        data.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(url.to_string())),
        )
        .expect("set CURLOPT_URL");

        let desc = SchemeDescriptor::new(
            SCHEME_DICT.name,
            SCHEME_DICT.default_port,
            SCHEME_DICT.flags,
            SCHEME_DICT.protocol,
        );
        let mut conn = Connection::new(
            format!("host:{}", SCHEME_DICT.default_port),
            TRNSPRT_TCP,
            desc,
        );

        let sent = Arc::new(Mutex::new(Vec::new()));
        conn.cfilter[FIRSTSOCKET].add_filter(Box::new(CapturingFilter::new(sent.clone())));

        let handler = DictHandler::new();
        let result = handler.do_it(&mut data, &mut conn).await;
        let captured = sent.lock().expect("sent lock").clone();
        (captured, result)
    }

    #[tokio::test]
    async fn do_it_define_sends_request_and_sets_up_download() {
        let (sent, result) = run_do_it("dict://host/d:curl:foldoc").await;
        let xfer = result.expect("do_it ok");
        assert_eq!(xfer.direction, TransferDirection::Download);
        assert_eq!(sent, wrap_request("DEFINE foldoc curl").into_bytes());
    }

    #[tokio::test]
    async fn do_it_match_uses_defaults() {
        let (sent, result) = run_do_it("dict://host/m:curl::").await;
        let xfer = result.expect("do_it ok");
        assert_eq!(xfer.direction, TransferDirection::Download);
        assert_eq!(sent, wrap_request("MATCH ! . curl").into_bytes());
    }

    #[tokio::test]
    async fn do_it_raw_command_replaces_colons() {
        let (sent, result) = run_do_it("dict://host/show:db").await;
        let xfer = result.expect("do_it ok");
        assert_eq!(xfer.direction, TransferDirection::Download);
        assert_eq!(sent, wrap_request("show db").into_bytes());
    }

    #[tokio::test]
    async fn do_it_missing_url_is_url_malformat() {
        // No CURLOPT_URL set → defensive malformed-URL error.
        let mut data = Easy::new();
        let desc = SchemeDescriptor::new(
            SCHEME_DICT.name,
            SCHEME_DICT.default_port,
            SCHEME_DICT.flags,
            SCHEME_DICT.protocol,
        );
        let mut conn = Connection::new("host:2628", TRNSPRT_TCP, desc);
        let handler = DictHandler::new();
        let result = handler.do_it(&mut data, &mut conn).await;
        assert!(matches!(result, Err(CurlError::UrlMalformat)));
    }
}
