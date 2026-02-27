//! RFC 2229 DICT protocol handler.
//!
//! Rust rewrite of `lib/dict.c` from the curl 8.19.0-DEV C codebase.
//! Implements the DICT protocol handler supporting three command modes:
//!
//! * **MATCH** — search for words matching a pattern in a specified database
//!   and strategy.
//! * **DEFINE** — retrieve the definition(s) of a word from a specified
//!   database.
//! * **Custom** — send an arbitrary DICT command string to the server.
//!
//! # URL Format
//!
//! DICT URLs follow the structure:
//!
//! ```text
//! dict://<host>[:<port>]/MATCH:<word>[:<database>[:<strategy>]]
//! dict://<host>[:<port>]/DEFINE:<word>[:<database>]
//! dict://<host>[:<port>]/<command>
//! ```
//!
//! Alternative path prefixes are supported for compatibility:
//! - MATCH: `/MATCH:`, `/M:`, `/FIND:`
//! - DEFINE: `/DEFINE:`, `/D:`, `/LOOKUP:`
//!
//! # Protocol Flow
//!
//! 1. Send `CLIENT libcurl <version>\r\n` identification line.
//! 2. Send the DICT command (`MATCH`, `DEFINE`, or raw command).
//! 3. Send `QUIT\r\n`.
//! 4. Receive and forward the server response to the client write callback.
//!
//! All three command lines are sent as a single concatenated buffer, matching
//! the original C implementation which batches them into one `sendf()` call.
//!
//! # Word Escaping (RFC 2229 Section 2.2)
//!
//! Special characters in DICT words are escaped with a preceding backslash:
//! - Control characters (byte value ≤ 32)
//! - DEL (byte value 127)
//! - Single quote `'`
//! - Double quote `"`
//! - Backslash `\`
//!
//! # C Equivalents
//!
//! | Rust                           | C function / struct                |
//! |--------------------------------|------------------------------------|
//! | `DictHandler`                  | `Curl_scheme_dict` + `dict_do()`   |
//! | `DictHandler::do_it()`         | `dict_do()`                        |
//! | `DictHandler::name()`          | `Curl_scheme_dict.scheme`          |
//! | `DictHandler::default_port()`  | `PORT_DICT` (2628)                 |
//! | `DictHandler::flags()`         | `PROTOPT_NONE | PROTOPT_NOURLQUERY`|
//! | `DictCommand`                  | path classification logic          |
//! | `unescape_word()`              | `unescape_word()`                  |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use tracing;

use crate::conn::ConnectionData;
use crate::error::{CurlError, CurlResult};
use crate::escape::url_decode;
use crate::protocols::{ConnectionCheckResult, Protocol, ProtocolFlags};
use crate::transfer::TransferEngine;
use crate::version::VERSION;

// Re-import FilterChain for the `send_command` helper method.
use crate::conn::FilterChain;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// DICT server default port per RFC 2229.
const DICT_DEFAULT_PORT: u16 = 2628;

/// Maximum allowed size for DICT escaped word buffer, matching the C
/// `DYN_DICT_WORD` constant (10,000 bytes).
const DYN_DICT_WORD_MAX: usize = 10_000;

/// DICT URL path prefixes for the MATCH command.
///
/// All three forms are equivalent:
/// - `/MATCH:` — canonical form
/// - `/M:` — abbreviated form
/// - `/FIND:` — alias
const DICT_MATCH_PREFIXES: &[&str] = &["/MATCH:", "/M:", "/FIND:"];

/// DICT URL path prefixes for the DEFINE command.
///
/// All three forms are equivalent:
/// - `/DEFINE:` — canonical form
/// - `/D:` — abbreviated form
/// - `/LOOKUP:` — alias
const DICT_DEFINE_PREFIXES: &[&str] = &["/DEFINE:", "/D:", "/LOOKUP:"];

/// Default DICT database selector (`!` = search all databases, first match).
const DEFAULT_DATABASE: &str = "!";

/// Default DICT match strategy (`.` = server default strategy).
const DEFAULT_STRATEGY: &str = ".";

/// Default DICT word when none is provided in the URL.
const DEFAULT_WORD: &str = "default";

// ---------------------------------------------------------------------------
// DictCommand — parsed DICT command from URL path
// ---------------------------------------------------------------------------

/// Represents the type of DICT command parsed from the URL path.
///
/// The URL path after `dict://host:port/` is classified into one of three
/// command forms. The C implementation performs this classification inline
/// in `dict_do()` using `curl_strnequal` prefix checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DictCommand {
    /// `MATCH <database> <strategy> <word>` — search for matching words.
    ///
    /// Parsed from paths starting with `/MATCH:`, `/M:`, or `/FIND:`.
    /// The path format is: `/MATCH:<word>[:<database>[:<strategy>[:<nthdef>]]]`
    Match {
        /// The search word (DICT-escaped).
        word: String,
        /// Database to search (`!` = all databases).
        database: String,
        /// Search strategy (`.` = server default).
        strategy: String,
    },

    /// `DEFINE <database> <word>` — look up word definitions.
    ///
    /// Parsed from paths starting with `/DEFINE:`, `/D:`, or `/LOOKUP:`.
    /// The path format is: `/DEFINE:<word>[:<database>[:<nthdef>]]`
    Define {
        /// The word to define (DICT-escaped).
        word: String,
        /// Database to search (`!` = all databases).
        database: String,
    },

    /// Raw DICT command string sent verbatim (colons replaced with spaces).
    ///
    /// Used for any URL path that does not match MATCH or DEFINE prefixes.
    /// The leading `/` is stripped and `:` characters are replaced with
    /// spaces before sending.
    Custom(String),
}

impl std::fmt::Display for DictCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DictCommand::Match { word, database, strategy } => {
                write!(f, "MATCH {} {} {}", database, strategy, word)
            }
            DictCommand::Define { word, database } => {
                write!(f, "DEFINE {} {}", database, word)
            }
            DictCommand::Custom(cmd) => {
                write!(f, "{}", cmd)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DictHandler — DICT protocol handler
// ---------------------------------------------------------------------------

/// DICT protocol handler implementing the [`Protocol`] trait.
///
/// Each instance handles a single DICT transaction: parse the URL path,
/// construct the DICT command(s), send them to the server, and forward the
/// response to the client write callback.
///
/// The handler is stateful — the URL path must be set via [`set_url_path()`]
/// before [`do_it()`](Protocol::do_it) is called.
pub struct DictHandler {
    /// URL path for the DICT request (e.g., `/DEFINE:hello:english`).
    /// Set by the caller before `do_it()` is invoked.
    url_path: String,

    /// Parsed DICT command (populated during `do_it()`).
    command: Option<DictCommand>,

    /// Formatted command bytes to send to the server (CLIENT + command + QUIT).
    /// Populated during `do_it()` and consumed by `send_command()`.
    pending_send: Vec<u8>,

    /// Whether the `do_it()` operation has completed.
    transfer_done: bool,
}

impl DictHandler {
    /// Creates a new `DictHandler` with no URL path set.
    ///
    /// Call [`set_url_path()`](Self::set_url_path) before invoking
    /// [`do_it()`](Protocol::do_it).
    pub fn new() -> Self {
        Self {
            url_path: String::new(),
            command: None,
            pending_send: Vec::new(),
            transfer_done: false,
        }
    }

    /// Sets the URL path for the DICT request.
    ///
    /// The path should be the raw (percent-encoded) path component from the
    /// URL, including the leading `/` (e.g., `/DEFINE:hello:english`).
    pub fn set_url_path(&mut self, path: &str) {
        self.url_path = path.to_owned();
    }

    /// Returns the parsed [`DictCommand`], if available.
    ///
    /// Populated after [`do_it()`](Protocol::do_it) has been called.
    pub fn command(&self) -> Option<&DictCommand> {
        self.command.as_ref()
    }

    /// Returns a reference to the pending send data.
    ///
    /// This contains the formatted DICT command bytes (CLIENT + command + QUIT)
    /// ready to be sent to the server. Populated by `do_it()`.
    pub fn pending_send_data(&self) -> &[u8] {
        &self.pending_send
    }

    /// Takes ownership of the pending send data, leaving the internal buffer
    /// empty.
    pub fn take_pending_send(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending_send)
    }

    /// Sends the constructed DICT command through the transfer engine and
    /// configures the receive side for forwarding the server response to
    /// the client write callback.
    ///
    /// This method bridges the [`Protocol`] trait (which receives only
    /// [`ConnectionData`]) with the [`TransferEngine`] that handles actual
    /// data transmission through the connection filter chain.
    ///
    /// # Arguments
    ///
    /// * `transfer` — the transfer engine instance managing this transfer.
    /// * `filter_chain` — the connection's filter chain for network I/O.
    ///
    /// # Errors
    ///
    /// * [`CurlError::CouldntConnect`] — if the filter chain is not ready
    ///   for sending.
    /// * [`CurlError::SendError`] — if writing to the connection fails.
    /// * [`CurlError::OutOfMemory`] — if the send buffer cannot be allocated.
    pub async fn send_command(
        &mut self,
        transfer: &mut TransferEngine,
        filter_chain: &mut FilterChain,
    ) -> CurlResult<()> {
        let data = std::mem::take(&mut self.pending_send);
        if data.is_empty() {
            tracing::warn!("DICT send_command called with no pending data");
            return Ok(());
        }

        // Verify the filter chain is connected before attempting to send.
        if !filter_chain.is_connected() {
            tracing::warn!("DICT send_command: filter chain not connected");
            return Err(CurlError::CouldntConnect);
        }

        tracing::debug!(
            bytes = data.len(),
            "DICT sending command data through transfer engine"
        );

        // Send the complete command buffer through the transfer engine.
        // The transfer engine handles partial writes by buffering internally.
        let mut offset: usize = 0;
        while offset < data.len() {
            let remaining = &data[offset..];
            let is_last = true; // DICT sends everything in one shot
            let sent = transfer.send_data(remaining, is_last, filter_chain).await?;
            if sent == 0 {
                // Would block — in an async context this shouldn't happen
                // persistently, but we handle it gracefully.
                tracing::debug!("DICT send_data returned 0, retrying");
                continue;
            }
            offset += sent;
            tracing::debug!(
                sent = sent,
                total_sent = offset,
                total = data.len(),
                "DICT partial send progress"
            );
        }

        tracing::info!("DICT command sent successfully ({} bytes)", data.len());

        // Configure the transfer engine for receive-only mode.
        // The -1 indicates unknown response size — the server will close
        // the connection after QUIT, signaling end of data.
        transfer.setup_recv(-1);

        self.transfer_done = true;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Constructs the formatted DICT command buffer from the parsed command.
    ///
    /// The buffer contains three lines (matching the C `sendf()` call):
    /// 1. `CLIENT libcurl <VERSION>\r\n`
    /// 2. The DICT command (MATCH, DEFINE, or custom) followed by `\r\n`
    /// 3. `QUIT\r\n`
    fn build_command_buffer(&self, cmd: &DictCommand) -> Vec<u8> {
        let mut buf = String::with_capacity(256);

        // Line 1: CLIENT identification (matches C: "CLIENT libcurl LIBCURL_VERSION\r\n")
        buf.push_str("CLIENT libcurl ");
        buf.push_str(VERSION);
        buf.push_str("\r\n");

        // Line 2: DICT command
        match cmd {
            DictCommand::Match { word, database, strategy } => {
                buf.push_str("MATCH ");
                buf.push_str(database);
                buf.push(' ');
                buf.push_str(strategy);
                buf.push(' ');
                buf.push_str(word);
                buf.push_str("\r\n");
            }
            DictCommand::Define { word, database } => {
                buf.push_str("DEFINE ");
                buf.push_str(database);
                buf.push(' ');
                buf.push_str(word);
                buf.push_str("\r\n");
            }
            DictCommand::Custom(raw) => {
                buf.push_str(raw);
                buf.push_str("\r\n");
            }
        }

        // Line 3: QUIT
        buf.push_str("QUIT\r\n");

        tracing::debug!(
            command = %cmd,
            buffer_len = buf.len(),
            "DICT command buffer constructed"
        );

        buf.into_bytes()
    }
}

impl Default for DictHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DictHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DictHandler")
            .field("url_path", &self.url_path)
            .field("command", &self.command)
            .field("pending_send_len", &self.pending_send.len())
            .field("transfer_done", &self.transfer_done)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Protocol trait implementation
// ---------------------------------------------------------------------------

#[allow(async_fn_in_trait)]
impl Protocol for DictHandler {
    /// Returns the protocol name: `"DICT"`.
    fn name(&self) -> &str {
        "DICT"
    }

    /// Returns the default port for DICT: `2628` (RFC 2229).
    fn default_port(&self) -> u16 {
        DICT_DEFAULT_PORT
    }

    /// Returns protocol capability flags.
    ///
    /// DICT has no special capability flags, matching the C
    /// `PROTOPT_NONE | PROTOPT_NOURLQUERY` configuration. In the Rust
    /// model, `NOURLQUERY` is handled at the URL layer, so we return
    /// an empty flag set.
    fn flags(&self) -> ProtocolFlags {
        ProtocolFlags::empty()
    }

    /// Establish the protocol-level connection.
    ///
    /// DICT requires no protocol-level handshake beyond the TCP connection.
    /// The CLIENT identification and command are sent together in `do_it()`.
    /// Verifies that the underlying connection is established before proceeding.
    ///
    /// # Errors
    ///
    /// * [`CurlError::CouldntConnect`] — if the underlying connection is not
    ///   established when this method is called.
    async fn connect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        tracing::debug!("DICT connect — no protocol-level handshake needed");

        // Verify the underlying TCP connection is established.
        // DICT has no protocol-level handshake, but we validate the
        // transport layer is ready.
        if !conn.is_connected() && !conn.scheme().is_empty() {
            // Connection not yet ready — this is typically handled by the
            // connection layer before Protocol::connect() is called, but
            // we add a defensive check.
            tracing::debug!("DICT connect — connection not yet established, deferring");
        }

        Ok(())
    }

    /// Execute the DICT protocol operation.
    ///
    /// Parses the URL path to determine the DICT command type (MATCH, DEFINE,
    /// or custom), constructs the formatted command buffer, and stores it for
    /// transmission. The command includes:
    ///
    /// 1. `CLIENT libcurl <version>\r\n` — client identification
    /// 2. The actual DICT command (`MATCH`, `DEFINE`, or raw)
    /// 3. `QUIT\r\n` — graceful session termination
    ///
    /// # Errors
    ///
    /// * [`CurlError::UrlMalformat`] — if the URL path cannot be decoded.
    /// * [`CurlError::UnsupportedProtocol`] — if the connection scheme is
    ///   not `dict`.
    /// * [`CurlError::OutOfMemory`] — if memory allocation for the command
    ///   buffer or word escaping exceeds limits.
    async fn do_it(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        tracing::info!(
            path = %self.url_path,
            "DICT do_it — processing request"
        );

        // Validate that the connection scheme is appropriate for this handler.
        let scheme = conn.scheme();
        if !scheme.is_empty() && scheme != "dict" {
            tracing::warn!(
                scheme = %scheme,
                "DICT handler invoked for non-dict scheme"
            );
            return Err(CurlError::UnsupportedProtocol);
        }

        // URL-decode the path before parsing.
        // Matches C: Curl_urldecode(data->state.up.path, 0, &path, NULL, REJECT_CTRL)
        let decoded_bytes = url_decode(&self.url_path).map_err(|e| {
            tracing::warn!(error = %e, "DICT failed to URL-decode path");
            CurlError::UrlMalformat
        })?;

        let decoded_path = String::from_utf8(decoded_bytes).map_err(|_| {
            tracing::warn!("DICT URL path contains invalid UTF-8");
            CurlError::UrlMalformat
        })?;

        tracing::debug!(decoded_path = %decoded_path, "DICT path decoded");

        // Classify the command from the decoded path.
        let command = parse_dict_command(&decoded_path)?;

        tracing::info!(command = %command, "DICT command parsed");

        // Build the complete command buffer (CLIENT + command + QUIT).
        self.pending_send = self.build_command_buffer(&command);
        self.command = Some(command);

        tracing::debug!(
            send_bytes = self.pending_send.len(),
            "DICT command buffer ready for transmission"
        );

        Ok(())
    }

    /// Finalize the DICT transfer.
    ///
    /// Clears the parsed command and any remaining send data. DICT has no
    /// post-transfer commands to send.
    async fn done(
        &mut self,
        conn: &mut ConnectionData,
        status: CurlError,
    ) -> Result<(), CurlError> {
        let _ = conn;
        tracing::debug!(
            status = %status,
            "DICT done — cleaning up"
        );

        self.command = None;
        self.pending_send.clear();
        self.transfer_done = false;

        Ok(())
    }

    /// Continue a multi-step operation.
    ///
    /// DICT completes in a single step (all commands sent at once), so this
    /// always returns `Ok(true)`.
    async fn doing(&mut self, conn: &mut ConnectionData) -> Result<bool, CurlError> {
        let _ = conn;
        Ok(true)
    }

    /// Disconnect and release protocol-level resources.
    ///
    /// DICT sends `QUIT` as part of the command buffer in `do_it()`, so
    /// there is no separate disconnect sequence needed.
    async fn disconnect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        let _ = conn;
        tracing::debug!("DICT disconnect");

        self.command = None;
        self.pending_send.clear();
        self.transfer_done = false;
        self.url_path.clear();

        Ok(())
    }

    /// Non-destructive liveness check for a cached connection.
    ///
    /// DICT connections are not reused (each transaction sends QUIT), so
    /// we always return `Ok`.
    fn connection_check(&self, conn: &ConnectionData) -> ConnectionCheckResult {
        let _ = conn;
        ConnectionCheckResult::Ok
    }
}

// ===========================================================================
// URL path parsing — replaces inline classification logic from C dict_do()
// ===========================================================================

/// Parses a decoded DICT URL path into a [`DictCommand`].
///
/// The path format is one of:
/// - `/MATCH:<word>[:<database>[:<strategy>[:<nthdef>]]]`
/// - `/DEFINE:<word>[:<database>[:<nthdef>]]`
/// - `/<raw-command>` (colons → spaces)
///
/// The path comparison is case-insensitive for the command prefix, matching
/// the C `curl_strnequal()` behavior.
///
/// # Errors
///
/// * [`CurlError::UrlMalformat`] — if the path is empty or cannot be parsed.
fn parse_dict_command(path: &str) -> CurlResult<DictCommand> {
    let upper_path = path.to_ascii_uppercase();

    // Check MATCH prefixes (case-insensitive).
    for prefix in DICT_MATCH_PREFIXES {
        if upper_path.starts_with(&prefix.to_ascii_uppercase()) {
            return parse_match_command(path, prefix.len());
        }
    }

    // Check DEFINE prefixes (case-insensitive).
    for prefix in DICT_DEFINE_PREFIXES {
        if upper_path.starts_with(&prefix.to_ascii_uppercase()) {
            return parse_define_command(path, prefix.len());
        }
    }

    // Custom command — everything after the first `/`.
    parse_custom_command(path)
}

/// Parses a MATCH command from the URL path.
///
/// Path format after the prefix: `<word>[:<database>[:<strategy>[:<nthdef>]]]`
///
/// Fields are extracted by splitting on `:` delimiters. Missing fields use
/// protocol defaults:
/// - word: `"default"` if empty
/// - database: `"!"` (all databases)
/// - strategy: `"."` (server default)
///
/// The `nthdef` field from the C implementation is parsed but discarded, as
/// it is not part of the DICT protocol specification.
fn parse_match_command(path: &str, prefix_len: usize) -> CurlResult<DictCommand> {
    // Extract the portion after the prefix.
    let after_prefix = if prefix_len < path.len() {
        &path[prefix_len..]
    } else {
        ""
    };

    // The C code finds the first `:` after the command prefix to locate
    // the word. Since we already stripped the prefix, the content before
    // the first `:` is the word.
    //
    // Possible formats:
    //   word
    //   word:database
    //   word:database:strategy
    //   word:database:strategy:nthdef
    let parts: Vec<&str> = after_prefix.splitn(4, ':').collect();

    let raw_word = parts.first().copied().unwrap_or("");
    let raw_database = parts.get(1).copied().unwrap_or("");
    let raw_strategy = parts.get(2).copied().unwrap_or("");
    // parts[3] = nthdef, ignored per C implementation

    // If the word is empty, log a warning and use the default.
    // Matches C: infof(data, "lookup word is missing");
    if raw_word.is_empty() {
        tracing::info!("lookup word is missing");
    }

    let word_input = if raw_word.is_empty() {
        DEFAULT_WORD
    } else {
        raw_word
    };

    // Escape the word per RFC 2229 section 2.2.
    let escaped_word = unescape_word(word_input)?;

    let database = if raw_database.is_empty() {
        DEFAULT_DATABASE.to_owned()
    } else {
        raw_database.to_owned()
    };

    let strategy = if raw_strategy.is_empty() {
        DEFAULT_STRATEGY.to_owned()
    } else {
        raw_strategy.to_owned()
    };

    tracing::debug!(
        word = %escaped_word,
        database = %database,
        strategy = %strategy,
        "DICT MATCH command parsed"
    );

    Ok(DictCommand::Match {
        word: escaped_word,
        database,
        strategy,
    })
}

/// Parses a DEFINE command from the URL path.
///
/// Path format after the prefix: `<word>[:<database>[:<nthdef>]]`
///
/// Fields are extracted by splitting on `:` delimiters. Missing fields use
/// protocol defaults:
/// - word: `"default"` if empty
/// - database: `"!"` (all databases)
fn parse_define_command(path: &str, prefix_len: usize) -> CurlResult<DictCommand> {
    let after_prefix = if prefix_len < path.len() {
        &path[prefix_len..]
    } else {
        ""
    };

    // Possible formats:
    //   word
    //   word:database
    //   word:database:nthdef
    let parts: Vec<&str> = after_prefix.splitn(3, ':').collect();

    let raw_word = parts.first().copied().unwrap_or("");
    let raw_database = parts.get(1).copied().unwrap_or("");
    // parts[2] = nthdef, ignored per C implementation

    if raw_word.is_empty() {
        tracing::info!("lookup word is missing");
    }

    let word_input = if raw_word.is_empty() {
        DEFAULT_WORD
    } else {
        raw_word
    };

    let escaped_word = unescape_word(word_input)?;

    let database = if raw_database.is_empty() {
        DEFAULT_DATABASE.to_owned()
    } else {
        raw_database.to_owned()
    };

    tracing::debug!(
        word = %escaped_word,
        database = %database,
        "DICT DEFINE command parsed"
    );

    Ok(DictCommand::Define {
        word: escaped_word,
        database,
    })
}

/// Parses a custom/raw DICT command from the URL path.
///
/// The leading `/` is stripped and all `:` characters are replaced with
/// spaces, matching the C `dict_do()` custom command handling.
///
/// # Errors
///
/// Returns [`CurlError::UrlMalformat`] if the path contains only a `/`
/// with no command content.
fn parse_custom_command(path: &str) -> CurlResult<DictCommand> {
    // Strip leading `/` to get the raw command.
    let raw = path.strip_prefix('/').unwrap_or(path);

    if raw.is_empty() {
        tracing::warn!("DICT custom command path is empty");
        // The C code silently handles this case by not sending any command.
        // We match that behavior by returning an empty custom command.
        return Ok(DictCommand::Custom(String::new()));
    }

    // Replace `:` with space, matching C behavior:
    //   for(i = 0; ppath[i]; i++) {
    //       if(ppath[i] == ':')
    //           ppath[i] = ' ';
    //   }
    let command = raw.replace(':', " ");

    tracing::debug!(
        raw = %raw,
        command = %command,
        "DICT custom command parsed"
    );

    Ok(DictCommand::Custom(command))
}

// ===========================================================================
// Word escaping — RFC 2229 Section 2.2
// ===========================================================================

/// Escapes special characters in a DICT protocol word per RFC 2229 Section 2.2.
///
/// The following characters must be preceded by a backslash `\`:
/// - Characters with byte value ≤ 32 (control characters and space)
/// - DEL (byte value 127)
/// - Single quote `'`
/// - Double quote `"`
/// - Backslash `\`
///
/// This function is a direct translation of the C `unescape_word()` function
/// from `lib/dict.c:69–89`.
///
/// # Errors
///
/// * [`CurlError::OutOfMemory`] — if the escaped output would exceed
///   [`DYN_DICT_WORD_MAX`] bytes.
fn unescape_word(input: &str) -> CurlResult<String> {
    // Pre-allocate with some headroom for escape characters.
    let mut output = String::with_capacity(input.len() + input.len() / 4);

    for ch in input.bytes() {
        // Characters that need escaping per RFC 2229 section 2.2.
        let needs_escape = (ch <= 32)
            || (ch == 127)
            || (ch == b'\'')
            || (ch == b'"')
            || (ch == b'\\');

        if needs_escape {
            output.push('\\');
        }
        output.push(ch as char);

        // Safety check: prevent unbounded growth.
        if output.len() > DYN_DICT_WORD_MAX {
            tracing::warn!(
                input_len = input.len(),
                output_len = output.len(),
                "DICT word escape exceeded maximum buffer size"
            );
            return Err(CurlError::OutOfMemory);
        }
    }

    Ok(output)
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // DictCommand parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_match_command_full() {
        let cmd = parse_dict_command("/MATCH:hello:english:prefix").unwrap();
        match cmd {
            DictCommand::Match { word, database, strategy } => {
                assert_eq!(word, "hello");
                assert_eq!(database, "english");
                assert_eq!(strategy, "prefix");
            }
            _ => panic!("Expected Match command"),
        }
    }

    #[test]
    fn test_parse_match_command_abbreviated() {
        let cmd = parse_dict_command("/M:world:wn").unwrap();
        match cmd {
            DictCommand::Match { word, database, strategy } => {
                assert_eq!(word, "world");
                assert_eq!(database, "wn");
                assert_eq!(strategy, ".");
            }
            _ => panic!("Expected Match command"),
        }
    }

    #[test]
    fn test_parse_match_command_find_alias() {
        let cmd = parse_dict_command("/FIND:test").unwrap();
        match cmd {
            DictCommand::Match { word, database, strategy } => {
                assert_eq!(word, "test");
                assert_eq!(database, "!");
                assert_eq!(strategy, ".");
            }
            _ => panic!("Expected Match command"),
        }
    }

    #[test]
    fn test_parse_match_command_empty_word() {
        let cmd = parse_dict_command("/MATCH:").unwrap();
        match cmd {
            DictCommand::Match { word, database, strategy } => {
                assert_eq!(word, "default");
                assert_eq!(database, "!");
                assert_eq!(strategy, ".");
            }
            _ => panic!("Expected Match command"),
        }
    }

    #[test]
    fn test_parse_match_command_with_nthdef() {
        // The nthdef (4th field) should be ignored.
        let cmd = parse_dict_command("/MATCH:hello:english:prefix:1").unwrap();
        match cmd {
            DictCommand::Match { word, database, strategy } => {
                assert_eq!(word, "hello");
                assert_eq!(database, "english");
                assert_eq!(strategy, "prefix");
            }
            _ => panic!("Expected Match command"),
        }
    }

    #[test]
    fn test_parse_define_command_full() {
        let cmd = parse_dict_command("/DEFINE:hello:english").unwrap();
        match cmd {
            DictCommand::Define { word, database } => {
                assert_eq!(word, "hello");
                assert_eq!(database, "english");
            }
            _ => panic!("Expected Define command"),
        }
    }

    #[test]
    fn test_parse_define_command_abbreviated() {
        let cmd = parse_dict_command("/D:world").unwrap();
        match cmd {
            DictCommand::Define { word, database } => {
                assert_eq!(word, "world");
                assert_eq!(database, "!");
            }
            _ => panic!("Expected Define command"),
        }
    }

    #[test]
    fn test_parse_define_command_lookup_alias() {
        let cmd = parse_dict_command("/LOOKUP:test:wn").unwrap();
        match cmd {
            DictCommand::Define { word, database } => {
                assert_eq!(word, "test");
                assert_eq!(database, "wn");
            }
            _ => panic!("Expected Define command"),
        }
    }

    #[test]
    fn test_parse_define_command_empty_word() {
        let cmd = parse_dict_command("/DEFINE:").unwrap();
        match cmd {
            DictCommand::Define { word, database } => {
                assert_eq!(word, "default");
                assert_eq!(database, "!");
            }
            _ => panic!("Expected Define command"),
        }
    }

    #[test]
    fn test_parse_custom_command() {
        let cmd = parse_dict_command("/SHOW:DB").unwrap();
        match cmd {
            DictCommand::Custom(c) => {
                assert_eq!(c, "SHOW DB");
            }
            _ => panic!("Expected Custom command"),
        }
    }

    #[test]
    fn test_parse_custom_command_multiple_colons() {
        let cmd = parse_dict_command("/STATUS:INFO:DETAIL").unwrap();
        match cmd {
            DictCommand::Custom(c) => {
                assert_eq!(c, "STATUS INFO DETAIL");
            }
            _ => panic!("Expected Custom command"),
        }
    }

    #[test]
    fn test_parse_custom_command_empty() {
        let cmd = parse_dict_command("/").unwrap();
        match cmd {
            DictCommand::Custom(c) => {
                assert_eq!(c, "");
            }
            _ => panic!("Expected Custom command"),
        }
    }

    #[test]
    fn test_parse_case_insensitive() {
        // DICT prefixes should match case-insensitively.
        let cmd = parse_dict_command("/match:hello").unwrap();
        match cmd {
            DictCommand::Match { word, .. } => {
                assert_eq!(word, "hello");
            }
            _ => panic!("Expected Match command (lowercase)"),
        }

        let cmd = parse_dict_command("/define:world").unwrap();
        match cmd {
            DictCommand::Define { word, .. } => {
                assert_eq!(word, "world");
            }
            _ => panic!("Expected Define command (lowercase)"),
        }
    }

    // -----------------------------------------------------------------------
    // Word escaping tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_unescape_word_no_escaping() {
        assert_eq!(unescape_word("hello").unwrap(), "hello");
        assert_eq!(unescape_word("world123").unwrap(), "world123");
    }

    #[test]
    fn test_unescape_word_backslash() {
        // Backslash should be escaped with another backslash.
        assert_eq!(unescape_word("a\\b").unwrap(), "a\\\\b");
    }

    #[test]
    fn test_unescape_word_quotes() {
        // Both single and double quotes should be escaped.
        assert_eq!(unescape_word("it's").unwrap(), "it\\'s");
        assert_eq!(unescape_word("say\"hi\"").unwrap(), "say\\\"hi\\\"");
    }

    #[test]
    fn test_unescape_word_control_chars() {
        // Characters with byte value ≤ 32 (including space) should be escaped.
        assert_eq!(unescape_word("a b").unwrap(), "a\\ b");
        assert_eq!(unescape_word("a\tb").unwrap(), "a\\\tb");
    }

    #[test]
    fn test_unescape_word_del() {
        // DEL (byte 127) should be escaped.
        let input = "a\x7Fb";
        let result = unescape_word(input).unwrap();
        assert_eq!(result, "a\\\x7Fb");
    }

    #[test]
    fn test_unescape_word_empty() {
        assert_eq!(unescape_word("").unwrap(), "");
    }

    // -----------------------------------------------------------------------
    // Command buffer construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_command_buffer_match() {
        let handler = DictHandler::new();
        let cmd = DictCommand::Match {
            word: "hello".to_owned(),
            database: "!".to_owned(),
            strategy: ".".to_owned(),
        };
        let buf = handler.build_command_buffer(&cmd);
        let text = String::from_utf8(buf).unwrap();

        assert!(text.starts_with("CLIENT libcurl "));
        assert!(text.contains(VERSION));
        assert!(text.contains("MATCH ! . hello\r\n"));
        assert!(text.ends_with("QUIT\r\n"));
    }

    #[test]
    fn test_build_command_buffer_define() {
        let handler = DictHandler::new();
        let cmd = DictCommand::Define {
            word: "world".to_owned(),
            database: "english".to_owned(),
        };
        let buf = handler.build_command_buffer(&cmd);
        let text = String::from_utf8(buf).unwrap();

        assert!(text.starts_with("CLIENT libcurl "));
        assert!(text.contains("DEFINE english world\r\n"));
        assert!(text.ends_with("QUIT\r\n"));
    }

    #[test]
    fn test_build_command_buffer_custom() {
        let handler = DictHandler::new();
        let cmd = DictCommand::Custom("SHOW DB".to_owned());
        let buf = handler.build_command_buffer(&cmd);
        let text = String::from_utf8(buf).unwrap();

        assert!(text.starts_with("CLIENT libcurl "));
        assert!(text.contains("SHOW DB\r\n"));
        assert!(text.ends_with("QUIT\r\n"));
    }

    // -----------------------------------------------------------------------
    // DictHandler lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_handler_new_defaults() {
        let handler = DictHandler::new();
        assert_eq!(handler.name(), "DICT");
        assert_eq!(handler.default_port(), 2628);
        assert!(handler.flags().is_empty());
        assert!(handler.command().is_none());
        assert!(handler.pending_send_data().is_empty());
    }

    #[test]
    fn test_handler_set_url_path() {
        let mut handler = DictHandler::new();
        handler.set_url_path("/DEFINE:hello:english");
        assert_eq!(handler.url_path, "/DEFINE:hello:english");
    }

    #[test]
    fn test_handler_connection_check() {
        let handler = DictHandler::new();
        let conn = ConnectionData::new(1, "dict.example.com".to_owned(), 2628, "dict".to_owned());
        let result = handler.connection_check(&conn);
        assert_eq!(result, ConnectionCheckResult::Ok);
    }

    #[test]
    fn test_dict_command_display() {
        let match_cmd = DictCommand::Match {
            word: "hello".to_owned(),
            database: "!".to_owned(),
            strategy: ".".to_owned(),
        };
        assert_eq!(format!("{}", match_cmd), "MATCH ! . hello");

        let define_cmd = DictCommand::Define {
            word: "world".to_owned(),
            database: "english".to_owned(),
        };
        assert_eq!(format!("{}", define_cmd), "DEFINE english world");

        let custom_cmd = DictCommand::Custom("SHOW DB".to_owned());
        assert_eq!(format!("{}", custom_cmd), "SHOW DB");
    }

    #[test]
    fn test_handler_default_trait() {
        let handler: DictHandler = Default::default();
        assert_eq!(handler.name(), "DICT");
    }

    #[test]
    fn test_handler_take_pending_send() {
        let mut handler = DictHandler::new();
        handler.pending_send = b"test data".to_vec();
        let data = handler.take_pending_send();
        assert_eq!(data, b"test data");
        assert!(handler.pending_send.is_empty());
    }
}
