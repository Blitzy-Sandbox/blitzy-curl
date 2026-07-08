//! TELNET protocol handler (RFC 854 + option negotiation).
//!
//! This is the idiomatic-Rust rewrite of curl's `lib/telnet.c` (~1608 lines),
//! together with the IAC / command / option byte constants from
//! `lib/arpa_telnet.h`. It preserves curl 8.19.0-DEV behavior byte-for-byte:
//!
//! * the full set of TELNET command and option constants
//!   (`lib/arpa_telnet.h`), reproduced verbatim;
//! * the RFC 1143 "Q Method" option-negotiation state machine
//!   (`set_local_option` / `set_remote_option` / `rec_will` / `rec_wont` /
//!   `rec_do` / `rec_dont`), including curl's exact agree/refuse policy per
//!   option;
//! * `SB ... SE` sub-negotiation for `TTYPE`, `XDISPLOC`, `NEW-ENVIRON` and
//!   `NAWS`, with byte-identical framing (`suboption` / `sendsuboption`);
//! * the `CURLOPT_TELNETOPTIONS` parser (`check_telnet_options`), matching
//!   curl's `TTYPE=` / `XDISPLOC=` / `NEW_ENV=` / `WS=` / `BINARY=` handling and
//!   the exact `CURLcode` values it returns;
//! * the `telrcv` receive decoder, whose state names (`CURL_TS_*`) are
//!   preserved for `--trace` parity;
//! * the bidirectional, interactive data pump (`telnet_do`), re-expressed with
//!   Tokio [`tokio::select!`] duplex I/O instead of C `select`/`poll`. curl's
//!   Windows-specific stdin-thread path is intentionally **not** ported
//!   (Windows is out of scope for this rewrite).
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` code, satisfying the workspace-wide
//! containment policy (`grep -rn 'unsafe' curl-rs-lib/src/` must return
//! nothing). All buffer handling uses safe indexing.
//!
//! # Wiring note
//!
//! The [`Protocol`] trait's [`do_it`](Protocol::do_it) / [`done`](Protocol::done)
//! entry points are necessarily thin while [`TransferCtx`] is still an empty
//! placeholder (owned by `transfer.rs` / `multi.rs`). The complete TELNET
//! behavior lives in the fully-implemented, unit-tested public methods of
//! [`Telnet`] — chiefly [`Telnet::run`], the duplex pump — which the transfer
//! layer invokes once the context carries the live connection and its
//! socket/input/output streams.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep_until, Instant};

use crate::error::{CurlCode, Error, Result};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx};

// ===========================================================================
// PHASE 1 — TELNET command & option constants (← `lib/arpa_telnet.h`).
//
// Reproduced verbatim. Every value is `pub const` so it is both part of the
// module's frozen public surface (asserted by the unit tests below) and always
// reachable, exactly mirroring the C `#define`s.
// ===========================================================================

// --- Telnet commands (the trailing bytes 236..=255, `telnetcmds[]` order) ---

/// `CURL_xEOF` — End Of File (command byte `236`).
pub const XEOF: u8 = 236;
/// Suspend process (command byte `237`).
pub const SUSP: u8 = 237;
/// Abort process (command byte `238`).
pub const ABORT: u8 = 238;
/// End Of Record (command byte `239`).
pub const EOR: u8 = 239;
/// `CURL_SE` — Sub-negotiation End (command byte `240`).
pub const SE: u8 = 240;
/// `CURL_NOP` — No OPeration (command byte `241`).
pub const NOP: u8 = 241;
/// `CURL_DM` — Data Mark (command byte `242`).
pub const DM: u8 = 242;
/// Break (command byte `243`).
pub const BREAK: u8 = 243;
/// Interrupt Process (command byte `244`).
pub const IP: u8 = 244;
/// Abort Output (command byte `245`).
pub const AO: u8 = 245;
/// Are You There (command byte `246`).
pub const AYT: u8 = 246;
/// Erase Character (command byte `247`).
pub const EC: u8 = 247;
/// Erase Line (command byte `248`).
pub const EL: u8 = 248;
/// `CURL_GA` — Go Ahead (command byte `249`).
pub const GA: u8 = 249;
/// `CURL_SB` — SuBnegotiation start (command byte `250`).
pub const SB: u8 = 250;
/// `CURL_WILL` — our side WILL use this option (command byte `251`).
pub const WILL: u8 = 251;
/// `CURL_WONT` — our side will NOT use this option (command byte `252`).
pub const WONT: u8 = 252;
/// `CURL_DO` — DO use this option! (command byte `253`).
pub const DO: u8 = 253;
/// `CURL_DONT` — DO NOT use this option! (command byte `254`).
pub const DONT: u8 = 254;
/// `CURL_IAC` — Interpret As Command (command byte `255`).
pub const IAC: u8 = 255;

/// `CURL_TELCMD_MINIMUM` — first command byte ([`XEOF`]).
pub const TELCMD_MINIMUM: u8 = XEOF;
/// `CURL_TELCMD_MAXIMUM` — last command byte ([`IAC`], `255`).
pub const TELCMD_MAXIMUM: u8 = IAC;

// --- Telnet options (`telnetoptions[]` indices 0..=39, plus EXOPL) ---

/// `CURL_TELOPT_BINARY` — binary 8-bit data (option `0`).
pub const TELOPT_BINARY: u8 = 0;
/// `CURL_TELOPT_ECHO` — echo (option `1`).
pub const TELOPT_ECHO: u8 = 1;
/// `CURL_TELOPT_SGA` — Suppress Go Ahead (option `3`).
pub const TELOPT_SGA: u8 = 3;
/// `CURL_TELOPT_TTYPE` — Terminal TYPE (option `24`).
pub const TELOPT_TTYPE: u8 = 24;
/// `CURL_TELOPT_NAWS` — Negotiate About Window Size (option `31`).
pub const TELOPT_NAWS: u8 = 31;
/// `CURL_TELOPT_XDISPLOC` — X DISPlay LOCation (option `35`).
pub const TELOPT_XDISPLOC: u8 = 35;
/// `CURL_TELOPT_NEW_ENVIRON` — NEW ENVIRONment variables (option `39`).
pub const TELOPT_NEW_ENVIRON: u8 = 39;
/// `CURL_TELOPT_EXOPL` — EXtended OPtions List (option `255`).
pub const TELOPT_EXOPL: u8 = 255;

/// `CURL_TELOPT_MAXIMUM` — highest named option ([`TELOPT_NEW_ENVIRON`], `39`).
pub const TELOPT_MAXIMUM: u8 = TELOPT_NEW_ENVIRON;
/// `CURL_NTELOPTS` — number of entries in the option name table (`40`).
pub const NTELOPTS: usize = 40;

// --- NEW-ENVIRON sub-negotiation markers (`lib/arpa_telnet.h`) ---

/// `CURL_NEW_ENV_VAR` — introduces an environment variable name (`0`).
pub const NEW_ENV_VAR: u8 = 0;
/// `CURL_NEW_ENV_VALUE` — introduces an environment variable value (`1`).
pub const NEW_ENV_VALUE: u8 = 1;

// --- Sub-negotiation qualifiers (`lib/arpa_telnet.h`) ---

/// `CURL_TELQUAL_IS` — "here is" qualifier (`0`).
pub const TELQUAL_IS: u8 = 0;
/// `CURL_TELQUAL_SEND` — "send me" qualifier (`1`).
pub const TELQUAL_SEND: u8 = 1;
/// `CURL_TELQUAL_INFO` — "informational" qualifier (`2`).
pub const TELQUAL_INFO: u8 = 2;
/// `CURL_TELQUAL_NAME` — "name" qualifier (`3`).
pub const TELQUAL_NAME: u8 = 3;

// --- RFC 1143 negotiation states (`lib/telnet.c`) ---

/// `CURL_NO` — option is disabled (`0`).
pub const NO: u8 = 0;
/// `CURL_YES` — option is enabled (`1`).
pub const YES: u8 = 1;
/// `CURL_WANTYES` — enable requested, awaiting confirmation (`2`).
pub const WANTYES: u8 = 2;
/// `CURL_WANTNO` — disable requested, awaiting confirmation (`3`).
pub const WANTNO: u8 = 3;

/// `CURL_EMPTY` — no queued opposite request (`0`).
pub const EMPTY: u8 = 0;
/// `CURL_OPPOSITE` — an opposite request is queued (`1`).
pub const OPPOSITE: u8 = 1;

/// `SUBBUFSIZE` — capacity of the sub-option collection buffer (`512`).
pub const SUBBUFSIZE: usize = 512;

/// The telnet options represented as strings (← `telnetoptions[]`,
/// `lib/arpa_telnet.h`). Indexed directly by option value (`0..=39`); used by
/// [`telopt_name`] for `--trace` parity.
static TELNETOPTIONS: [&str; NTELOPTS] = [
    "BINARY",
    "ECHO",
    "RCP",
    "SUPPRESS GO AHEAD",
    "NAME",
    "STATUS",
    "TIMING MARK",
    "RCTE",
    "NAOL",
    "NAOP",
    "NAOCRD",
    "NAOHTS",
    "NAOHTD",
    "NAOFFD",
    "NAOVTS",
    "NAOVTD",
    "NAOLFD",
    "EXTEND ASCII",
    "LOGOUT",
    "BYTE MACRO",
    "DE TERMINAL",
    "SUPDUP",
    "SUPDUP OUTPUT",
    "SEND LOCATION",
    "TERM TYPE",
    "END OF RECORD",
    "TACACS UID",
    "OUTPUT MARKING",
    "TTYLOC",
    "3270 REGIME",
    "X3 PAD",
    "NAWS",
    "TERM SPEED",
    "LFLOW",
    "LINEMODE",
    "XDISPLOC",
    "OLD-ENVIRON",
    "AUTHENTICATION",
    "ENCRYPT",
    "NEW-ENVIRON",
];

/// Telnet command bytes represented as strings (← `telnetcmds[]`,
/// `lib/arpa_telnet.h`). Indexed by `byte - CURL_TELCMD_MINIMUM`; used by
/// [`telcmd_name`] for `--trace` parity.
static TELNETCMDS: [&str; 20] = [
    "EOF", "SUSP", "ABORT", "EOR", "SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC", "EL",
    "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC",
];

/// `CURL_TELOPT_OK(x)` — is `x` a known telnet option? (`x <= TELOPT_MAXIMUM`).
#[must_use]
pub fn telopt_ok(x: u8) -> bool {
    x <= TELOPT_MAXIMUM
}

/// `CURL_TELCMD_OK(x)` — is `x` a telnet command byte?
/// (`TELCMD_MINIMUM <= x <= TELCMD_MAXIMUM`; the upper bound is `255`, so for a
/// `u8` this reduces to `x >= TELCMD_MINIMUM`).
#[must_use]
pub fn telcmd_ok(x: u8) -> bool {
    x >= TELCMD_MINIMUM
}

/// `CURL_TELOPT(x)` — the name of option `x` for trace output, or `""` when the
/// option is unknown ([`TELOPT_EXOPL`] renders as `"EXOPL"`, matching curl's
/// `printoption`).
#[must_use]
pub fn telopt_name(x: u8) -> &'static str {
    if telopt_ok(x) {
        TELNETOPTIONS[x as usize]
    } else if x == TELOPT_EXOPL {
        "EXOPL"
    } else {
        ""
    }
}

/// `CURL_TELCMD(x)` — the name of command byte `x` for trace output, or `""`
/// when `x` is not a command byte.
#[must_use]
pub fn telcmd_name(x: u8) -> &'static str {
    if telcmd_ok(x) {
        TELNETCMDS[(x - TELCMD_MINIMUM) as usize]
    } else {
        ""
    }
}

/// The `telrcv` receive-decoder state (← `TelnetReceive`, `lib/telnet.c`).
///
/// The variant identifiers are preserved verbatim (`CURL_TS_*`) for `--trace`
/// parity with curl; the `#[allow]`s keep `clippy -D warnings` clean while
/// honoring that naming contract.
#[allow(non_camel_case_types, clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum TelnetReceive {
    /// Normal data byte processing.
    #[default]
    CURL_TS_DATA,
    /// An `IAC` byte was seen; the next byte is a command.
    CURL_TS_IAC,
    /// Awaiting the option byte for a received `WILL`.
    CURL_TS_WILL,
    /// Awaiting the option byte for a received `WONT`.
    CURL_TS_WONT,
    /// Awaiting the option byte for a received `DO`.
    CURL_TS_DO,
    /// Awaiting the option byte for a received `DONT`.
    CURL_TS_DONT,
    /// A carriage return was seen; peek the following byte.
    CURL_TS_CR,
    /// Collecting sub-option bytes (`SB` seen).
    CURL_TS_SB,
    /// Looking for the sub-option end (`IAC SE`).
    CURL_TS_SE,
}

// ===========================================================================
// The per-transfer TELNET state (← `struct TELNET`, `lib/telnet.c`).
// ===========================================================================

/// Per-transfer TELNET protocol state and negotiation engine.
///
/// This is the rewrite of curl's `struct TELNET`. It owns the RFC 1143
/// negotiation tables, the sub-option collection buffer, the receive-decoder
/// state, and the parsed `CURLOPT_TELNETOPTIONS` inputs.
///
/// Outbound protocol bytes (negotiation replies, sub-option responses) are
/// accumulated into [`Telnet::outgoing`] rather than written inline as curl's
/// C does with `swrite`; the [`run`](Telnet::run) pump flushes that buffer to
/// the socket. Because the decoder processes the input stream strictly in
/// order and appends in that same order, the on-wire byte sequence is
/// identical to curl's.
pub struct Telnet {
    /// The peer has begun negotiating (← `please_negotiate`).
    please_negotiate: bool,
    /// We have already emitted our proactive negotiation (← `already_negotiated`).
    already_negotiated: bool,
    /// Current state of each *local* option (← `us[256]`).
    us: [u8; 256],
    /// Queued opposite request for each local option (← `usq[256]`).
    usq: [u8; 256],
    /// Whether we prefer each local option enabled (← `us_preferred[256]`).
    us_preferred: [u8; 256],
    /// Current state of each *remote* option (← `him[256]`).
    him: [u8; 256],
    /// Queued opposite request for each remote option (← `himq[256]`).
    himq: [u8; 256],
    /// Whether we prefer each remote option enabled (← `him_preferred[256]`).
    him_preferred: [u8; 256],
    /// Whether an option carries sub-negotiation data (← `subnegotiation[256]`).
    subnegotiation: [u8; 256],
    /// Terminal type set via the `TTYPE=` telnet option (← `subopt_ttype`).
    subopt_ttype: Option<String>,
    /// X display location set via `XDISPLOC=` (← `subopt_xdisploc`).
    subopt_xdisploc: Option<String>,
    /// Window width set via `WS=` (← `subopt_wsx`).
    subopt_wsx: u16,
    /// Window height set via `WS=` (← `subopt_wsy`).
    subopt_wsy: u16,
    /// Receive-decoder state (← `telrcv_state`).
    telrcv_state: TelnetReceive,
    /// `NEW-ENVIRON` variables, each formatted `"name,value"` (← `telnet_vars`).
    telnet_vars: Vec<String>,
    /// Sub-option collection buffer (← `subbuffer[SUBBUFSIZE]`).
    subbuffer: [u8; SUBBUFSIZE],
    /// Write/read cursor into [`Telnet::subbuffer`] (← `subpointer`).
    subpointer: usize,
    /// End-of-data cursor into [`Telnet::subbuffer`] (← `subend`).
    subend: usize,
    /// Accumulated outbound protocol bytes awaiting a socket flush.
    outgoing: Vec<u8>,
}

impl Default for Telnet {
    /// Build the initial TELNET state (← `init_telnet`).
    ///
    /// Reproduces curl's default option preferences exactly:
    /// * `SGA` preferred both locally and remotely;
    /// * `BINARY` preferred both ways (enabled by default for backward
    ///   compatibility; can be disabled via the `BINARY` telnet option);
    /// * `ECHO` preferred remotely (we allow the server to echo but never
    ///   request it — `ECHO` is skipped in [`telnet_negotiate`]);
    /// * `NAWS` flagged as carrying sub-negotiation data.
    fn default() -> Self {
        let mut tn = Telnet {
            please_negotiate: false,
            already_negotiated: false,
            us: [NO; 256],
            usq: [EMPTY; 256],
            us_preferred: [NO; 256],
            him: [NO; 256],
            himq: [EMPTY; 256],
            him_preferred: [NO; 256],
            subnegotiation: [NO; 256],
            subopt_ttype: None,
            subopt_xdisploc: None,
            subopt_wsx: 0,
            subopt_wsy: 0,
            telrcv_state: TelnetReceive::CURL_TS_DATA,
            telnet_vars: Vec::new(),
            subbuffer: [0; SUBBUFSIZE],
            subpointer: 0,
            subend: 0,
            outgoing: Vec::new(),
        };

        // Set the options we want by default (← `init_telnet`).
        tn.us_preferred[TELOPT_SGA as usize] = YES;
        tn.him_preferred[TELOPT_SGA as usize] = YES;

        // Enabled by default to be compatible with previous libcurl releases;
        // changeable via the "BINARY" option in CURLOPT_TELNETOPTIONS.
        tn.us_preferred[TELOPT_BINARY as usize] = YES;
        tn.him_preferred[TELOPT_BINARY as usize] = YES;

        // Allow the server to echo what we send, but do not request it (that
        // might force the server to close the connection); ECHO is therefore
        // ignored by telnet_negotiate.
        tn.him_preferred[TELOPT_ECHO as usize] = YES;

        // Send NAWS sub-negotiation data right after negotiation passes.
        tn.subnegotiation[TELOPT_NAWS as usize] = YES;

        tn
    }
}

impl Telnet {
    /// Create a freshly-initialized TELNET state (← `init_telnet`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // -----------------------------------------------------------------------
    // Sub-option buffer helpers (← the `CURL_SB_*` macros, `lib/telnet.c`).
    //
    // Re-expressed as index arithmetic over `subbuffer`/`subpointer`/`subend`
    // so there is no pointer manipulation and thus no `unsafe`.
    // -----------------------------------------------------------------------

    /// `CURL_SB_CLEAR` — reset the write cursor to the start of the buffer.
    fn sb_clear(&mut self) {
        self.subpointer = 0;
    }

    /// `CURL_SB_TERM` — mark the current cursor as the end of data, then clear.
    fn sb_term(&mut self) {
        self.subend = self.subpointer;
        self.sb_clear();
    }

    /// `CURL_SB_ACCUM` — append one byte if the buffer is not full (extra bytes
    /// are silently dropped, exactly like curl's bounds-checked macro).
    fn sb_accum(&mut self, c: u8) {
        if self.subpointer < SUBBUFSIZE {
            self.subbuffer[self.subpointer] = c;
            self.subpointer += 1;
        }
    }

    /// `CURL_SB_GET` — read the byte at the cursor and advance it.
    fn sb_get(&mut self) -> u8 {
        let v = self.subbuffer.get(self.subpointer).copied().unwrap_or(0);
        self.subpointer += 1;
        v
    }

    /// `CURL_SB_LEN` — number of bytes remaining between the cursor and the end.
    fn sb_len(&self) -> usize {
        self.subend.saturating_sub(self.subpointer)
    }

    // -----------------------------------------------------------------------
    // Trace helpers (← `printoption` / `printsub`, gated on `--verbose` in C).
    //
    // Emitted through `tracing`, which is this workspace's `--trace`/`--verbose`
    // mechanism. The command/option name tables above feed these, preserving
    // curl's diagnostic vocabulary.
    // -----------------------------------------------------------------------

    /// `printoption` — trace a single negotiation command (`IAC`, `WILL`,
    /// `WONT`, `DO`, `DONT`) in curl's exact textual form.
    fn printoption(&self, direction: &str, cmd: u8, option: u8) {
        if cmd == IAC {
            if telcmd_ok(option) {
                tracing::trace!("{} IAC {}", direction, telcmd_name(option));
            } else {
                tracing::trace!("{} IAC {}", direction, option);
            }
        } else {
            let fmt = match cmd {
                WILL => "WILL",
                WONT => "WONT",
                DO => "DO",
                DONT => "DONT",
                _ => "",
            };
            if fmt.is_empty() {
                tracing::trace!("{} {} {}", direction, cmd, option);
            } else {
                let name = telopt_name(option);
                if name.is_empty() {
                    tracing::trace!("{} {} {}", direction, fmt, option);
                } else {
                    tracing::trace!("{} {} {}", direction, fmt, name);
                }
            }
        }
    }

    /// `printsub` — trace a sub-option block (`direction` is `'<'` for received,
    /// `'>'` for sent). `pointer` includes the trailing `IAC SE`, matching the
    /// way curl passes the buffer.
    fn printsub(&self, direction: char, pointer: &[u8]) {
        let mut length = pointer.len();
        let mut msg = String::new();
        msg.push_str(if direction == '<' {
            "RCVD IAC SB "
        } else {
            "SENT IAC SB "
        });

        if length >= 3 {
            let i = pointer[length - 2];
            let j = pointer[length - 1];
            if i != IAC || j != SE {
                msg.push_str("(terminated by ");
                msg.push_str(term_name(i).as_str());
                msg.push(' ');
                msg.push_str(term_name(j).as_str());
                msg.push_str(", not IAC SE) ");
            }
        }
        if length >= 2 {
            length -= 2;
        } else {
            tracing::trace!("{}", msg);
            return;
        }

        if length <= 1 {
            msg.push_str("(Empty suboption?)");
            tracing::trace!("{}", msg);
            return;
        }

        if telopt_ok(pointer[0]) {
            match pointer[0] {
                TELOPT_TTYPE | TELOPT_XDISPLOC | TELOPT_NEW_ENVIRON | TELOPT_NAWS => {
                    msg.push_str(telopt_name(pointer[0]));
                }
                _ => {
                    msg.push_str(telopt_name(pointer[0]));
                    msg.push_str(" (unsupported)");
                }
            }
        } else {
            msg.push_str(&format!("{} (unknown)", pointer[0]));
        }

        if pointer[0] == TELOPT_NAWS {
            if length > 4 {
                let w = (usize::from(pointer[1]) << 8) | usize::from(pointer[2]);
                let h = (usize::from(pointer[3]) << 8) | usize::from(pointer[4]);
                msg.push_str(&format!("Width: {w} ; Height: {h}"));
            }
        } else {
            match pointer[1] {
                TELQUAL_IS => msg.push_str(" IS"),
                TELQUAL_SEND => msg.push_str(" SEND"),
                TELQUAL_INFO => msg.push_str(" INFO/REPLY"),
                TELQUAL_NAME => msg.push_str(" NAME"),
                _ => {}
            }

            match pointer[0] {
                TELOPT_TTYPE | TELOPT_XDISPLOC => {
                    let value = if length > 2 {
                        &pointer[2..length]
                    } else {
                        &[][..]
                    };
                    msg.push_str(&format!(" \"{}\"", String::from_utf8_lossy(value)));
                }
                TELOPT_NEW_ENVIRON => {
                    if pointer[1] == TELQUAL_IS {
                        msg.push(' ');
                        for &b in &pointer[3..length] {
                            match b {
                                NEW_ENV_VAR => msg.push_str(", "),
                                NEW_ENV_VALUE => msg.push_str(" = "),
                                other => msg.push(char::from(other)),
                            }
                        }
                    }
                }
                _ => {
                    for &b in &pointer[2..length] {
                        msg.push_str(&format!(" {b:02x}"));
                    }
                }
            }
        }

        tracing::trace!("{}", msg);
    }

    /// `send_negotiation` — queue a 3-byte `IAC <cmd> <option>` command and
    /// trace it. (In C this is an immediate `swrite`; here it is appended to
    /// [`Telnet::outgoing`] and flushed by the pump, preserving byte order.)
    fn send_negotiation(&mut self, cmd: u8, option: u8) {
        self.outgoing.extend_from_slice(&[IAC, cmd, option]);
        self.printoption("SENT", cmd, option);
    }
}

/// Name of a byte appearing in a `printsub` "terminated by" clause: an option
/// name, else a command name, else its decimal value (← `printsub`).
fn term_name(b: u8) -> String {
    if telopt_ok(b) {
        telopt_name(b).to_string()
    } else if telcmd_ok(b) {
        telcmd_name(b).to_string()
    } else {
        b.to_string()
    }
}

// ===========================================================================
// PHASE 2 — Option negotiation (RFC 1143 "Q Method"; ← `set_remote_option` /
// `set_local_option` / `telnet_negotiate` / `rec_will` / `rec_wont` /
// `rec_do` / `rec_dont`, `lib/telnet.c`).
//
// Each state transition is reproduced branch-for-branch. `us[]`/`usq[]` track
// *our* (local) options; `him[]`/`himq[]` track the *peer's* (remote) options.
// ===========================================================================

impl Telnet {
    /// `set_remote_option` — drive the peer's option toward `newstate`
    /// (`YES`/`NO`) via `DO`/`DONT`, honoring any queued opposite request.
    fn set_remote_option(&mut self, option: u8, newstate: u8) {
        let o = option as usize;
        if newstate == YES {
            match self.him[o] {
                NO => {
                    self.him[o] = WANTYES;
                    self.send_negotiation(DO, option);
                }
                YES => { /* Already enabled */ }
                WANTNO => {
                    // EMPTY: already negotiating for YES, queue the request.
                    // OPPOSITE (else): already queued an enable request — no-op.
                    if self.himq[o] == EMPTY {
                        self.himq[o] = OPPOSITE;
                    }
                }
                WANTYES => match self.himq[o] {
                    // Error: already negotiating for enable.
                    EMPTY => {}
                    OPPOSITE => self.himq[o] = EMPTY,
                    _ => {}
                },
                _ => {}
            }
        } else {
            match self.him[o] {
                NO => { /* Already disabled */ }
                YES => {
                    self.him[o] = WANTNO;
                    self.send_negotiation(DONT, option);
                }
                WANTNO => match self.himq[o] {
                    // Already negotiating for NO.
                    EMPTY => {}
                    OPPOSITE => self.himq[o] = EMPTY,
                    _ => {}
                },
                WANTYES => {
                    // Mid-enable but now want it disabled: queue the opposite
                    // (disable) request unless one is already queued.
                    if self.himq[o] == EMPTY {
                        self.himq[o] = OPPOSITE;
                    }
                }
                _ => {}
            }
        }
    }

    /// `set_local_option` — drive our own option toward `newstate` (`YES`/`NO`)
    /// via `WILL`/`WONT`, honoring any queued opposite request.
    fn set_local_option(&mut self, option: u8, newstate: u8) {
        let o = option as usize;
        if newstate == YES {
            match self.us[o] {
                NO => {
                    self.us[o] = WANTYES;
                    self.send_negotiation(WILL, option);
                }
                YES => { /* Already enabled */ }
                WANTNO => {
                    // EMPTY: already negotiating for YES, queue the request.
                    // OPPOSITE (else): already queued an enable request — no-op.
                    if self.usq[o] == EMPTY {
                        self.usq[o] = OPPOSITE;
                    }
                }
                WANTYES => match self.usq[o] {
                    // Error: already negotiating for enable.
                    EMPTY => {}
                    OPPOSITE => self.usq[o] = EMPTY,
                    _ => {}
                },
                _ => {}
            }
        } else {
            match self.us[o] {
                NO => { /* Already disabled */ }
                YES => {
                    self.us[o] = WANTNO;
                    self.send_negotiation(WONT, option);
                }
                WANTNO => match self.usq[o] {
                    // Already negotiating for NO.
                    EMPTY => {}
                    OPPOSITE => self.usq[o] = EMPTY,
                    _ => {}
                },
                WANTYES => {
                    // Mid-enable but now want it disabled: queue the opposite
                    // (disable) request unless one is already queued.
                    if self.usq[o] == EMPTY {
                        self.usq[o] = OPPOSITE;
                    }
                }
                _ => {}
            }
        }
    }

    /// `telnet_negotiate` — send our proactive `WILL`/`DO` for every preferred
    /// option once the peer has started negotiating. `ECHO` is deliberately
    /// skipped: we allow the server to echo but never request it.
    pub fn telnet_negotiate(&mut self) {
        for i in 0..NTELOPTS {
            let opt = i as u8;
            if opt == TELOPT_ECHO {
                continue;
            }
            if self.us_preferred[i] == YES {
                self.set_local_option(opt, YES);
            }
            if self.him_preferred[i] == YES {
                self.set_remote_option(opt, YES);
            }
        }
    }

    /// `rec_will` — react to a received `WILL <option>` from the peer.
    fn rec_will(&mut self, option: u8) {
        let o = option as usize;
        match self.him[o] {
            NO => {
                if self.him_preferred[o] == YES {
                    self.him[o] = YES;
                    self.send_negotiation(DO, option);
                } else {
                    self.send_negotiation(DONT, option);
                }
            }
            YES => { /* Already enabled */ }
            WANTNO => match self.himq[o] {
                // Error: DONT answered by WILL.
                EMPTY => self.him[o] = NO,
                OPPOSITE => {
                    // Error: DONT answered by WILL.
                    self.him[o] = YES;
                    self.himq[o] = EMPTY;
                }
                _ => {}
            },
            WANTYES => match self.himq[o] {
                EMPTY => self.him[o] = YES,
                OPPOSITE => {
                    self.him[o] = WANTNO;
                    self.himq[o] = EMPTY;
                    self.send_negotiation(DONT, option);
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// `rec_wont` — react to a received `WONT <option>` from the peer.
    fn rec_wont(&mut self, option: u8) {
        let o = option as usize;
        match self.him[o] {
            NO => { /* Already disabled */ }
            YES => {
                self.him[o] = NO;
                self.send_negotiation(DONT, option);
            }
            WANTNO => match self.himq[o] {
                EMPTY => self.him[o] = NO,
                OPPOSITE => {
                    self.him[o] = WANTYES;
                    self.himq[o] = EMPTY;
                    self.send_negotiation(DO, option);
                }
                _ => {}
            },
            WANTYES => match self.himq[o] {
                EMPTY => self.him[o] = NO,
                OPPOSITE => {
                    self.him[o] = NO;
                    self.himq[o] = EMPTY;
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// `rec_do` — react to a received `DO <option>` from the peer.
    fn rec_do(&mut self, option: u8) {
        let o = option as usize;
        match self.us[o] {
            NO => {
                if self.us_preferred[o] == YES {
                    self.us[o] = YES;
                    self.send_negotiation(WILL, option);
                    if self.subnegotiation[o] == YES {
                        // Transmission of data option.
                        self.sendsuboption(option);
                    }
                } else if self.subnegotiation[o] == YES {
                    // Send information to achieve this option.
                    self.us[o] = YES;
                    self.send_negotiation(WILL, option);
                    self.sendsuboption(option);
                } else {
                    self.send_negotiation(WONT, option);
                }
            }
            YES => { /* Already enabled */ }
            WANTNO => match self.usq[o] {
                // Error: DONT answered by WILL.
                EMPTY => self.us[o] = NO,
                OPPOSITE => {
                    // Error: DONT answered by WILL.
                    self.us[o] = YES;
                    self.usq[o] = EMPTY;
                }
                _ => {}
            },
            WANTYES => match self.usq[o] {
                EMPTY => {
                    self.us[o] = YES;
                    if self.subnegotiation[o] == YES {
                        // Transmission of data option.
                        self.sendsuboption(option);
                    }
                }
                OPPOSITE => {
                    self.us[o] = WANTNO;
                    // NOTE: curl assigns `himq` here (not `usq`); reproduced
                    // verbatim for byte-for-byte parity.
                    self.himq[o] = EMPTY;
                    self.send_negotiation(WONT, option);
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// `rec_dont` — react to a received `DONT <option>` from the peer.
    fn rec_dont(&mut self, option: u8) {
        let o = option as usize;
        match self.us[o] {
            NO => { /* Already disabled */ }
            YES => {
                self.us[o] = NO;
                self.send_negotiation(WONT, option);
            }
            WANTNO => match self.usq[o] {
                EMPTY => self.us[o] = NO,
                OPPOSITE => {
                    self.us[o] = WANTYES;
                    self.usq[o] = EMPTY;
                    self.send_negotiation(WILL, option);
                }
                _ => {}
            },
            WANTYES => match self.usq[o] {
                EMPTY => self.us[o] = NO,
                OPPOSITE => {
                    self.us[o] = NO;
                    self.usq[o] = EMPTY;
                }
                _ => {}
            },
            _ => {}
        }
    }
}

/// Capacity of curl's on-stack `temp[2048]` sub-option assembly buffer, used to
/// reproduce the exact `NEW-ENVIRON` fit guard (`len + tmplen < 2048 - 6`).
const SUBOPT_TEMP_SIZE: usize = 2048;

/// Escape a data block for the wire by doubling every `IAC` (`0xFF`) byte
/// (← the escaping half of `send_telnet_data`). This is the only transformation
/// applied to outbound application data.
fn escape_iac(input: &[u8], out: &mut Vec<u8>) {
    for &b in input {
        out.push(b);
        if b == IAC {
            // IAC in the data stream must be sent doubled (`IAC IAC`).
            out.push(IAC);
        }
    }
}

/// `str_is_nonascii` — does any byte have its high bit set? (← `str_is_nonascii`).
fn str_is_nonascii(s: &str) -> bool {
    s.bytes().any(|b| b & 0x80 != 0)
}

/// `bad_option` — reject option data that embeds an `IAC` byte, since there is
/// no legitimate way to carry it in a sub-option value (← `bad_option`). A
/// Rust `&str` is UTF-8 and thus can never contain `0xFF`, so this is normally
/// vacuously `false`; it is retained to preserve curl's guarantee exactly.
fn bad_option(s: &str) -> bool {
    s.as_bytes().contains(&IAC)
}

impl Telnet {
    /// `sendsuboption` — emit sub-option data the server has agreed to receive.
    /// Only `NAWS` (window size) is transmitted here, matching curl.
    ///
    /// The framing is byte-identical to curl's: the `IAC SB NAWS` header and
    /// the `IAC SE` footer are sent verbatim, while the four window-size bytes
    /// pass through [`escape_iac`] so an `0xFF` dimension is doubled.
    fn sendsuboption(&mut self, option: u8) {
        if option == TELOPT_NAWS {
            // Assemble the full block in the sub-option buffer (as curl does),
            // primarily so the trace matches; the wire bytes are produced
            // below with the correct per-segment escaping.
            self.sb_clear();
            self.sb_accum(IAC);
            self.sb_accum(SB);
            self.sb_accum(TELOPT_NAWS);
            // Window size travels in network byte order (big-endian) — the
            // Rust `to_be_bytes` is exactly curl's `htons`.
            let x = self.subopt_wsx.to_be_bytes();
            let y = self.subopt_wsy.to_be_bytes();
            self.sb_accum(x[0]);
            self.sb_accum(x[1]);
            self.sb_accum(y[0]);
            self.sb_accum(y[1]);
            self.sb_accum(IAC);
            self.sb_accum(SE);
            self.sb_term();

            // Header (3 bytes, raw) ... window (4 bytes, IAC-escaped) ...
            // footer (2 bytes, raw).
            self.outgoing.extend_from_slice(&[IAC, SB, TELOPT_NAWS]);
            let mut esc = Vec::with_capacity(6);
            escape_iac(&[x[0], x[1], y[0], y[1]], &mut esc);
            self.outgoing.extend_from_slice(&esc);
            self.outgoing.extend_from_slice(&[IAC, SE]);

            // Trace over subbuffer[2..subend] (== NAWS w w w w IAC SE), matching
            // curl's `printsub(data, '>', subbuffer + 2, CURL_SB_LEN - 2)`.
            let end = self.subend.min(SUBBUFSIZE);
            let trace = self.subbuffer[2..end].to_vec();
            self.printsub('>', &trace);
        }
    }

    /// `suboption` — respond to a completed received sub-option, being helpful
    /// to the peer. Handles `TTYPE`, `XDISPLOC` and `NEW-ENVIRON` `SEND`
    /// requests, emitting the corresponding `IS` reply. Response bytes are
    /// appended to [`Telnet::outgoing`].
    fn suboption(&mut self) -> Result<()> {
        if self.sb_len() == 0 {
            // Ignore an empty suboption.
            return Ok(());
        }

        // Trace the received block: pointer includes the trailing IAC SE that
        // is still physically present in the buffer past `subend`.
        let rcvd_end = (self.subpointer + self.sb_len() + 2).min(SUBBUFSIZE);
        let rcvd = self.subbuffer[self.subpointer..rcvd_end].to_vec();
        self.printsub('<', &rcvd);

        match self.sb_get() {
            TELOPT_TTYPE => {
                let ttype = self.subopt_ttype.clone();
                let Some(s) = ttype else {
                    return Err(Error::from(CurlCode::BadFunctionArgument));
                };
                if bad_option(&s) {
                    return Err(Error::from(CurlCode::BadFunctionArgument));
                }
                if s.len() > 1000 {
                    // NB: curl's message text is reproduced verbatim, typo and
                    // all, for stderr parity.
                    return Err(Error::with_context(
                        CurlCode::SendError,
                        "Tool long telnet TTYPE",
                    ));
                }
                let mut temp = vec![IAC, SB, TELOPT_TTYPE, TELQUAL_IS];
                temp.extend_from_slice(s.as_bytes());
                temp.extend_from_slice(&[IAC, SE]);
                self.outgoing.extend_from_slice(&temp);
                self.printsub('>', &temp[2..]);
            }
            TELOPT_XDISPLOC => {
                let xdisploc = self.subopt_xdisploc.clone();
                let Some(s) = xdisploc else {
                    return Err(Error::from(CurlCode::BadFunctionArgument));
                };
                if bad_option(&s) {
                    return Err(Error::from(CurlCode::BadFunctionArgument));
                }
                if s.len() > 1000 {
                    return Err(Error::with_context(
                        CurlCode::SendError,
                        "Tool long telnet XDISPLOC",
                    ));
                }
                let mut temp = vec![IAC, SB, TELOPT_XDISPLOC, TELQUAL_IS];
                temp.extend_from_slice(s.as_bytes());
                temp.extend_from_slice(&[IAC, SE]);
                self.outgoing.extend_from_slice(&temp);
                self.printsub('>', &temp[2..]);
            }
            TELOPT_NEW_ENVIRON => {
                let vars = self.telnet_vars.clone();
                let mut temp = vec![IAC, SB, TELOPT_NEW_ENVIRON, TELQUAL_IS];
                for v in &vars {
                    let tmplen = v.len() + 1;
                    if bad_option(v) {
                        return Err(Error::from(CurlCode::BadFunctionArgument));
                    }
                    // Add the variable only if it fits (exact curl guard).
                    if temp.len() + tmplen < SUBOPT_TEMP_SIZE - 6 {
                        match v.find(',') {
                            None => {
                                temp.push(NEW_ENV_VAR);
                                temp.extend_from_slice(v.as_bytes());
                            }
                            Some(idx) => {
                                temp.push(NEW_ENV_VAR);
                                temp.extend_from_slice(v[..idx].as_bytes());
                                temp.push(NEW_ENV_VALUE);
                                temp.extend_from_slice(v[idx + 1..].as_bytes());
                            }
                        }
                    }
                }
                temp.extend_from_slice(&[IAC, SE]);
                self.outgoing.extend_from_slice(&temp);
                self.printsub('>', &temp[2..]);
            }
            _ => {}
        }

        Ok(())
    }
}

/// Parse a run of ASCII decimal digits into a value bounded by `max`
/// (← `curlx_str_number`). Returns `None` if there is no digit or the value
/// would exceed `max`; on success `i` is advanced past the digits.
fn parse_number(bytes: &[u8], i: &mut usize, max: u64) -> Option<u64> {
    let start = *i;
    let mut val: u64 = 0;
    while *i < bytes.len() && bytes[*i].is_ascii_digit() {
        val = val * 10 + u64::from(bytes[*i] - b'0');
        if val > max {
            return None;
        }
        *i += 1;
    }
    if *i == start {
        return None;
    }
    Some(val)
}

/// Parse a `WS=` argument of the form `<width>x<height>`, each dimension in
/// `0..=0xffff` (← the `curlx_str_number` / `curlx_str_single(&p, 'x')`
/// sequence). The `x` separator is lowercase and case-sensitive, as in curl.
fn parse_window_size(arg: &str) -> Option<(u16, u16)> {
    let bytes = arg.as_bytes();
    let mut i = 0usize;
    let x = parse_number(bytes, &mut i, 0xffff)?;
    if i >= bytes.len() || bytes[i] != b'x' {
        return None;
    }
    i += 1;
    let y = parse_number(bytes, &mut i, 0xffff)?;
    Some((x as u16, y as u16))
}

/// Parse a `BINARY=` argument, a number in `0..=1` (← `curlx_str_number(&p,
/// &binary_option, 1)`). `None` on parse failure, which curl treats as "leave
/// BINARY enabled" rather than an error.
fn parse_binary(arg: &str) -> Option<u64> {
    let bytes = arg.as_bytes();
    let mut i = 0usize;
    parse_number(bytes, &mut i, 1)
}

impl Telnet {
    /// `check_telnet_options` — parse the `CURLOPT_TELNETOPTIONS` list into the
    /// negotiation preferences (← `check_telnet_options`).
    ///
    /// `options` are the raw `name=value` strings (curl's `telnet_options`
    /// slist). `user` is the command-line username, if one was set (curl's
    /// `data->conn->user`, gated on `data->state.aptr.user`); when present it is
    /// injected as a `NEW-ENVIRON` `USER` variable. On any error the accumulated
    /// environment variables are discarded, exactly as curl does.
    ///
    /// # Errors
    ///
    /// * [`CurlCode::BadFunctionArgument`] — a non-ASCII username.
    /// * [`CurlCode::SetoptOptionSyntax`] — an option without `=`, or a
    ///   malformed `WS=` value.
    /// * [`CurlCode::UnknownOption`] — an unrecognized option name.
    pub fn check_telnet_options(&mut self, options: &[String], user: Option<&str>) -> Result<()> {
        let result = self.check_telnet_options_inner(options, user);
        if result.is_err() {
            self.telnet_vars.clear();
        }
        result
    }

    fn check_telnet_options_inner(&mut self, options: &[String], user: Option<&str>) -> Result<()> {
        // Add the username as an environment variable if it was given on the
        // command line.
        if let Some(u) = user {
            if str_is_nonascii(u) {
                return Err(Error::from(CurlCode::BadFunctionArgument));
            }
            self.telnet_vars.push(format!("USER,{u}"));
            self.us_preferred[TELOPT_NEW_ENVIRON as usize] = YES;
        }

        for option in options {
            let Some(idx) = option.find('=') else {
                return Err(Error::with_context(
                    CurlCode::SetoptOptionSyntax,
                    format!("Syntax error in telnet option: {option}"),
                ));
            };
            let name = &option[..idx];
            let arg = &option[idx + 1..];
            if str_is_nonascii(arg) {
                continue;
            }

            match name.len() {
                // Terminal type.
                5 => {
                    if name.eq_ignore_ascii_case("TTYPE") {
                        self.subopt_ttype = Some(arg.to_string());
                        self.us_preferred[TELOPT_TTYPE as usize] = YES;
                    } else {
                        return Err(Error::from(CurlCode::UnknownOption));
                    }
                }
                // Display variable.
                8 => {
                    if name.eq_ignore_ascii_case("XDISPLOC") {
                        self.subopt_xdisploc = Some(arg.to_string());
                        self.us_preferred[TELOPT_XDISPLOC as usize] = YES;
                    } else {
                        return Err(Error::from(CurlCode::UnknownOption));
                    }
                }
                // Environment variable.
                7 => {
                    if name.eq_ignore_ascii_case("NEW_ENV") {
                        self.telnet_vars.push(arg.to_string());
                        self.us_preferred[TELOPT_NEW_ENVIRON as usize] = YES;
                    } else {
                        return Err(Error::from(CurlCode::UnknownOption));
                    }
                }
                // Window size.
                2 => {
                    if name.eq_ignore_ascii_case("WS") {
                        match parse_window_size(arg) {
                            Some((w, h)) => {
                                self.subopt_wsx = w;
                                self.subopt_wsy = h;
                                self.us_preferred[TELOPT_NAWS as usize] = YES;
                            }
                            None => {
                                return Err(Error::with_context(
                                    CurlCode::SetoptOptionSyntax,
                                    format!("Syntax error in telnet option: {option}"),
                                ));
                            }
                        }
                    } else {
                        return Err(Error::from(CurlCode::UnknownOption));
                    }
                }
                // Whether to take care of the 8th bit in data exchange.
                6 => {
                    if name.eq_ignore_ascii_case("BINARY") {
                        if let Some(v) = parse_binary(arg) {
                            if v != 1 {
                                self.us_preferred[TELOPT_BINARY as usize] = NO;
                                self.him_preferred[TELOPT_BINARY as usize] = NO;
                            }
                        }
                        // A parse failure leaves BINARY enabled and is not an
                        // error, matching curl.
                    } else {
                        return Err(Error::from(CurlCode::UnknownOption));
                    }
                }
                _ => {
                    return Err(Error::with_context(
                        CurlCode::UnknownOption,
                        format!("Unknown telnet option {option}"),
                    ));
                }
            }
        }

        Ok(())
    }
}

// ===========================================================================
// PHASE 3 (decode half) — the receive decoder (← `telrcv`, `lib/telnet.c`).
// ===========================================================================

impl Telnet {
    /// `telrcv` — decode a chunk of bytes received from the socket.
    ///
    /// "Clean" application bytes (with `IAC IAC` un-escaped to a single `0xFF`
    /// and telnet's `CR NUL` collapsed to `CR`) are appended to `out_data` —
    /// the equivalent of curl's `Curl_client_write(CLIENTWRITE_BODY, ...)`.
    /// Negotiation commands mutate the option state and enqueue replies into
    /// [`Telnet::outgoing`]; completed sub-options are dispatched to
    /// [`suboption`](Telnet::suboption).
    ///
    /// The decoder state (`telrcv_state`) persists across calls, so a command
    /// or sub-option split across chunk boundaries is handled correctly.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::RecvError`] on a malformed sub-option terminator
    /// (anything other than `IAC IAC` or `IAC SE` after an in-sub-option
    /// `IAC`), exactly as curl's `telrcv`.
    pub fn telrcv(&mut self, inbuf: &[u8], out_data: &mut Vec<u8>) -> Result<()> {
        for &c in inbuf {
            match self.telrcv_state {
                TelnetReceive::CURL_TS_CR => {
                    self.telrcv_state = TelnetReceive::CURL_TS_DATA;
                    if c == b'\0' {
                        // Ignore \0 after CR.
                        continue;
                    }
                    out_data.push(c);
                }

                TelnetReceive::CURL_TS_DATA => {
                    if c == IAC {
                        self.telrcv_state = TelnetReceive::CURL_TS_IAC;
                        continue;
                    } else if c == b'\r' {
                        self.telrcv_state = TelnetReceive::CURL_TS_CR;
                    }
                    out_data.push(c);
                }

                TelnetReceive::CURL_TS_IAC => match c {
                    WILL => self.telrcv_state = TelnetReceive::CURL_TS_WILL,
                    WONT => self.telrcv_state = TelnetReceive::CURL_TS_WONT,
                    DO => self.telrcv_state = TelnetReceive::CURL_TS_DO,
                    DONT => self.telrcv_state = TelnetReceive::CURL_TS_DONT,
                    SB => {
                        self.sb_clear();
                        self.telrcv_state = TelnetReceive::CURL_TS_SB;
                    }
                    IAC => {
                        // Doubled IAC — emit a single 0xFF data byte.
                        self.telrcv_state = TelnetReceive::CURL_TS_DATA;
                        out_data.push(c);
                    }
                    // DM, NOP, GA and any other command byte: consumed, traced.
                    _ => {
                        self.telrcv_state = TelnetReceive::CURL_TS_DATA;
                        self.printoption("RCVD", IAC, c);
                    }
                },

                TelnetReceive::CURL_TS_WILL => {
                    self.printoption("RCVD", WILL, c);
                    self.please_negotiate = true;
                    self.rec_will(c);
                    self.telrcv_state = TelnetReceive::CURL_TS_DATA;
                }

                TelnetReceive::CURL_TS_WONT => {
                    self.printoption("RCVD", WONT, c);
                    self.please_negotiate = true;
                    self.rec_wont(c);
                    self.telrcv_state = TelnetReceive::CURL_TS_DATA;
                }

                TelnetReceive::CURL_TS_DO => {
                    self.printoption("RCVD", DO, c);
                    self.please_negotiate = true;
                    self.rec_do(c);
                    self.telrcv_state = TelnetReceive::CURL_TS_DATA;
                }

                TelnetReceive::CURL_TS_DONT => {
                    self.printoption("RCVD", DONT, c);
                    self.please_negotiate = true;
                    self.rec_dont(c);
                    self.telrcv_state = TelnetReceive::CURL_TS_DATA;
                }

                TelnetReceive::CURL_TS_SB => {
                    if c == IAC {
                        self.telrcv_state = TelnetReceive::CURL_TS_SE;
                    } else {
                        self.sb_accum(c);
                    }
                }

                TelnetReceive::CURL_TS_SE => {
                    if c != SE {
                        if c != IAC {
                            // We only expect "IAC IAC" or "IAC SE" here. An IAC
                            // was not doubled, the IAC SE was left off, or
                            // another option was inserted into the sub-option.
                            return Err(Error::with_context(
                                CurlCode::RecvError,
                                "telnet: suboption error",
                            ));
                        }
                        // Escaped IAC within the sub-option data.
                        self.sb_accum(c);
                        self.telrcv_state = TelnetReceive::CURL_TS_SB;
                    } else {
                        self.sb_accum(IAC);
                        self.sb_accum(SE);
                        self.subpointer = self.subpointer.saturating_sub(2);
                        self.sb_term();
                        self.suboption()?;
                        self.telrcv_state = TelnetReceive::CURL_TS_DATA;
                    }
                }
            }
        }

        Ok(())
    }

    /// Take the bytes accumulated in [`Telnet::outgoing`], leaving it empty.
    /// Exposed so the pump (or a future transfer driver) can flush protocol
    /// replies to the socket.
    fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outgoing)
    }
}

/// Await an absolute `deadline`, or never resolve when there is no timeout.
/// Used as the timeout arm of the pump's [`tokio::select!`].
async fn wait_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(dl) => sleep_until(dl).await,
        None => std::future::pending::<()>().await,
    }
}

impl Telnet {
    /// `telnet_do` (non-Windows path) — the interactive, bidirectional data
    /// pump, expressed with Tokio duplex I/O.
    ///
    /// Concurrently, and until the transfer ends, this:
    ///
    /// * reads from `socket`, decodes it through [`telrcv`](Telnet::telrcv)
    ///   (writing clean application bytes to `output` and enqueuing negotiation
    ///   replies), performs the reactive [`telnet_negotiate`](Telnet::telnet_negotiate)
    ///   once the peer starts negotiating, and flushes any queued protocol
    ///   bytes back to `socket`;
    /// * reads from `input` (stdin / the upload source) and forwards it to
    ///   `socket` with outbound `0xFF` bytes escaped as `IAC IAC`.
    ///
    /// Termination matches curl:
    /// * the server closing the connection (a 0-byte read) ends the transfer
    ///   cleanly;
    /// * a socket receive error is reported as [`CurlCode::RecvError`];
    /// * an `input` read error ends the loop cleanly (curl leaves the result
    ///   `OK`);
    /// * reaching `timeout` (measured from entry) yields
    ///   [`CurlCode::OperationTimedout`].
    ///
    /// Reaching end-of-input does **not** end the transfer: curl keeps servicing
    /// the network after stdin closes, so this stops polling `input` while
    /// continuing to read `socket` until the server closes (or a timeout/error
    /// occurs). This avoids a busy-loop on an EOF'd input while preserving the
    /// observable behavior — no further client data is sent.
    ///
    /// Negotiation is reactive only: like curl, we never speak telnet first, so
    /// that non-telnet servers (POP, SMTP) are not disturbed.
    ///
    /// # Errors
    ///
    /// See the termination rules above; sub-option decode errors from
    /// [`telrcv`](Telnet::telrcv) also propagate.
    pub async fn run<S, I, O>(
        &mut self,
        socket: &mut S,
        input: &mut I,
        output: &mut O,
        timeout: Option<Duration>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        I: AsyncRead + Unpin,
        O: AsyncWrite + Unpin,
    {
        let deadline = timeout.map(|d| Instant::now() + d);
        let mut input_eof = false;
        // curl uses a single 4 KiB buffer; two independent buffers are used
        // here so the two concurrent reads never alias.
        let mut sockbuf = [0u8; 4096];
        let mut inbuf = [0u8; 4096];

        loop {
            tokio::select! {
                // Prefer the timeout, then the network, then the input source —
                // mirroring curl's per-iteration "network before input" order.
                biased;

                () = wait_deadline(deadline) => {
                    return Err(Error::with_context(CurlCode::OperationTimedout, "Time-out"));
                }

                res = socket.read(&mut sockbuf) => {
                    let n = res.map_err(|_| Error::Recv)?;
                    if n == 0 {
                        // The server closed the connection; bail out cleanly.
                        break;
                    }
                    let mut out_data = Vec::new();
                    self.telrcv(&sockbuf[..n], &mut out_data)?;
                    if !out_data.is_empty() {
                        output.write_all(&out_data).await.map_err(|_| Error::Write)?;
                    }
                    // Negotiate if the peer has started negotiating, otherwise
                    // stay silent.
                    if self.please_negotiate && !self.already_negotiated {
                        self.telnet_negotiate();
                        self.already_negotiated = true;
                    }
                    let outbytes = self.take_outgoing();
                    if !outbytes.is_empty() {
                        socket.write_all(&outbytes).await.map_err(|_| Error::Send)?;
                    }
                }

                res = input.read(&mut inbuf), if !input_eof => {
                    match res {
                        // An input read error ends the loop cleanly.
                        Err(_) => break,
                        // End-of-input: stop polling input, keep reading network.
                        Ok(0) => input_eof = true,
                        Ok(n) => {
                            let mut esc = Vec::new();
                            escape_iac(&inbuf[..n], &mut esc);
                            socket.write_all(&esc).await.map_err(|_| Error::Send)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

// ===========================================================================
// PHASE 4 — `Protocol` trait implementation (← `Curl_protocol_telnet` /
// `Curl_scheme_telnet`, `lib/telnet.c`).
// ===========================================================================

/// The TELNET protocol handler singleton (← `Curl_protocol_telnet`).
///
/// A zero-sized type; the parent module's `SCHEME_TELNET` scheme record refers
/// to the shared [`HANDLER`] instance as `&telnet::HANDLER`.
#[derive(Debug, Clone, Copy)]
pub struct TelnetHandler;

/// The shared TELNET handler instance referenced by `SCHEME_TELNET`.
pub static HANDLER: TelnetHandler = TelnetHandler;

impl Protocol for TelnetHandler {
    /// The "DO" phase (← `telnet_do`). curl sets `*done = TRUE` unconditionally
    /// and then runs the interactive pump; here we signal DO-complete. The
    /// duplex pump itself, [`Telnet::run`], is driven by the transfer layer
    /// once [`TransferCtx`] carries the live connection and its
    /// socket/input/output streams (see the module docs).
    fn do_it<'a>(&'a self, _ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    /// The teardown phase (← `telnet_done`). curl ignores `status`/`premature`
    /// and returns `CURLE_OK`.
    fn done<'a>(
        &'a self,
        _ctx: &'a mut TransferCtx,
        _status: Result<()>,
        _premature: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // -- PHASE 1: constants & name tables -----------------------------------

    #[test]
    fn command_constants_are_frozen() {
        assert_eq!(XEOF, 236);
        assert_eq!(SUSP, 237);
        assert_eq!(ABORT, 238);
        assert_eq!(EOR, 239);
        assert_eq!(SE, 240);
        assert_eq!(NOP, 241);
        assert_eq!(DM, 242);
        assert_eq!(BREAK, 243);
        assert_eq!(IP, 244);
        assert_eq!(AO, 245);
        assert_eq!(AYT, 246);
        assert_eq!(EC, 247);
        assert_eq!(EL, 248);
        assert_eq!(GA, 249);
        assert_eq!(SB, 250);
        assert_eq!(WILL, 251);
        assert_eq!(WONT, 252);
        assert_eq!(DO, 253);
        assert_eq!(DONT, 254);
        assert_eq!(IAC, 255);
        assert_eq!(TELCMD_MINIMUM, 236);
        assert_eq!(TELCMD_MAXIMUM, 255);
    }

    #[test]
    fn option_constants_are_frozen() {
        assert_eq!(TELOPT_BINARY, 0);
        assert_eq!(TELOPT_ECHO, 1);
        assert_eq!(TELOPT_SGA, 3);
        assert_eq!(TELOPT_TTYPE, 24);
        assert_eq!(TELOPT_NAWS, 31);
        assert_eq!(TELOPT_XDISPLOC, 35);
        assert_eq!(TELOPT_NEW_ENVIRON, 39);
        assert_eq!(TELOPT_EXOPL, 255);
        assert_eq!(TELOPT_MAXIMUM, 39);
        assert_eq!(NTELOPTS, 40);
        assert_eq!(SUBBUFSIZE, 512);
    }

    #[test]
    fn qualifier_env_and_state_constants_are_frozen() {
        assert_eq!(NEW_ENV_VAR, 0);
        assert_eq!(NEW_ENV_VALUE, 1);
        assert_eq!(TELQUAL_IS, 0);
        assert_eq!(TELQUAL_SEND, 1);
        assert_eq!(TELQUAL_INFO, 2);
        assert_eq!(TELQUAL_NAME, 3);
        assert_eq!(NO, 0);
        assert_eq!(YES, 1);
        assert_eq!(WANTYES, 2);
        assert_eq!(WANTNO, 3);
        assert_eq!(EMPTY, 0);
        assert_eq!(OPPOSITE, 1);
    }

    #[test]
    fn name_tables_match_arpa_telnet() {
        assert_eq!(telopt_name(TELOPT_BINARY), "BINARY");
        assert_eq!(telopt_name(TELOPT_ECHO), "ECHO");
        assert_eq!(telopt_name(TELOPT_SGA), "SUPPRESS GO AHEAD");
        assert_eq!(telopt_name(TELOPT_NAWS), "NAWS");
        assert_eq!(telopt_name(TELOPT_NEW_ENVIRON), "NEW-ENVIRON");
        assert_eq!(telopt_name(TELOPT_EXOPL), "EXOPL");
        assert_eq!(telopt_name(100), "");

        assert_eq!(telcmd_name(XEOF), "EOF");
        assert_eq!(telcmd_name(DM), "DMARK");
        assert_eq!(telcmd_name(BREAK), "BRK");
        assert_eq!(telcmd_name(IAC), "IAC");
        assert_eq!(telcmd_name(WILL), "WILL");
        assert_eq!(telcmd_name(10), "");

        assert!(telopt_ok(TELOPT_NEW_ENVIRON));
        assert!(!telopt_ok(40));
        assert!(telcmd_ok(IAC));
        assert!(!telcmd_ok(235));
    }

    #[test]
    fn escape_iac_doubles_only_ff() {
        let mut out = Vec::new();
        escape_iac(&[0x41, 0xFF, 0x42, 0xFF], &mut out);
        assert_eq!(out, vec![0x41, 0xFF, 0xFF, 0x42, 0xFF, 0xFF]);

        let mut clean = Vec::new();
        escape_iac(b"hello", &mut clean);
        assert_eq!(clean, b"hello");
    }

    // -- init_telnet defaults -----------------------------------------------

    #[test]
    fn new_applies_init_telnet_defaults() {
        let tn = Telnet::new();
        assert_eq!(tn.us_preferred[TELOPT_SGA as usize], YES);
        assert_eq!(tn.him_preferred[TELOPT_SGA as usize], YES);
        assert_eq!(tn.us_preferred[TELOPT_BINARY as usize], YES);
        assert_eq!(tn.him_preferred[TELOPT_BINARY as usize], YES);
        assert_eq!(tn.him_preferred[TELOPT_ECHO as usize], YES);
        assert_eq!(tn.us_preferred[TELOPT_ECHO as usize], NO);
        assert_eq!(tn.subnegotiation[TELOPT_NAWS as usize], YES);
        assert_eq!(tn.telrcv_state, TelnetReceive::CURL_TS_DATA);
        assert!(tn.outgoing.is_empty());
        assert!(!tn.please_negotiate);
        assert!(!tn.already_negotiated);
    }

    // -- PHASE 3: telrcv decoder --------------------------------------------

    #[test]
    fn telrcv_passes_plain_data() {
        let mut tn = Telnet::new();
        let mut out = Vec::new();
        tn.telrcv(b"hello world", &mut out).unwrap();
        assert_eq!(out, b"hello world");
        assert!(tn.outgoing.is_empty());
    }

    #[test]
    fn telrcv_handles_cr_nul_and_cr_lf() {
        let mut tn = Telnet::new();
        let mut out = Vec::new();
        // CR NUL collapses to CR; CR LF is preserved.
        tn.telrcv(&[b'\r', 0, b'X', b'\r', b'\n'], &mut out)
            .unwrap();
        assert_eq!(out, vec![b'\r', b'X', b'\r', b'\n']);
    }

    #[test]
    fn telrcv_unescapes_doubled_iac() {
        let mut tn = Telnet::new();
        let mut out = Vec::new();
        tn.telrcv(&[b'a', IAC, IAC, b'b'], &mut out).unwrap();
        assert_eq!(out, vec![b'a', 0xFF, b'b']);
    }

    #[test]
    fn telrcv_rejects_bad_suboption_terminator() {
        let mut tn = Telnet::new();
        let mut out = Vec::new();
        // IAC SB TTYPE IAC 'X' — 'X' is neither IAC nor SE => error.
        let err = tn
            .telrcv(&[IAC, SB, TELOPT_TTYPE, IAC, b'X'], &mut out)
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::RecvError);
    }

    // -- PHASE 2: negotiation policy ----------------------------------------

    #[test]
    fn rec_do_agrees_for_preferred_option() {
        let mut tn = Telnet::new();
        tn.rec_do(TELOPT_SGA);
        assert_eq!(tn.us[TELOPT_SGA as usize], YES);
        assert_eq!(tn.outgoing, vec![IAC, WILL, TELOPT_SGA]);
    }

    #[test]
    fn rec_do_refuses_unpreferred_option() {
        let mut tn = Telnet::new();
        // Option 5 (STATUS) is neither preferred nor a sub-negotiation option.
        tn.rec_do(5);
        assert_eq!(tn.us[5], NO);
        assert_eq!(tn.outgoing, vec![IAC, WONT, 5]);
    }

    #[test]
    fn rec_will_agrees_for_preferred_option() {
        let mut tn = Telnet::new();
        tn.rec_will(TELOPT_BINARY);
        assert_eq!(tn.him[TELOPT_BINARY as usize], YES);
        assert_eq!(tn.outgoing, vec![IAC, DO, TELOPT_BINARY]);
    }

    #[test]
    fn rec_will_refuses_unpreferred_option() {
        let mut tn = Telnet::new();
        tn.rec_will(5);
        assert_eq!(tn.him[5], NO);
        assert_eq!(tn.outgoing, vec![IAC, DONT, 5]);
    }

    #[test]
    fn telnet_negotiate_emits_default_burst() {
        let mut tn = Telnet::new();
        tn.telnet_negotiate();
        // BINARY (0) then SGA (3); ECHO (1) is skipped entirely.
        assert_eq!(
            tn.outgoing,
            vec![
                IAC,
                WILL,
                TELOPT_BINARY,
                IAC,
                DO,
                TELOPT_BINARY,
                IAC,
                WILL,
                TELOPT_SGA,
                IAC,
                DO,
                TELOPT_SGA,
            ]
        );
    }

    // -- PHASE 2: CURLOPT_TELNETOPTIONS parsing -----------------------------

    #[test]
    fn check_options_parses_all_known_forms() {
        let mut tn = Telnet::new();
        tn.check_telnet_options(&["TTYPE=vt100".to_string()], None)
            .unwrap();
        assert_eq!(tn.subopt_ttype.as_deref(), Some("vt100"));
        assert_eq!(tn.us_preferred[TELOPT_TTYPE as usize], YES);

        let mut tn = Telnet::new();
        tn.check_telnet_options(&["WS=80x24".to_string()], None)
            .unwrap();
        assert_eq!(tn.subopt_wsx, 80);
        assert_eq!(tn.subopt_wsy, 24);
        assert_eq!(tn.us_preferred[TELOPT_NAWS as usize], YES);

        let mut tn = Telnet::new();
        tn.check_telnet_options(&["XDISPLOC=host:0".to_string()], None)
            .unwrap();
        assert_eq!(tn.subopt_xdisploc.as_deref(), Some("host:0"));
        assert_eq!(tn.us_preferred[TELOPT_XDISPLOC as usize], YES);

        let mut tn = Telnet::new();
        tn.check_telnet_options(&["NEW_ENV=FOO,bar".to_string()], None)
            .unwrap();
        assert_eq!(tn.telnet_vars, vec!["FOO,bar".to_string()]);
        assert_eq!(tn.us_preferred[TELOPT_NEW_ENVIRON as usize], YES);

        // BINARY=0 disables both directions; BINARY=1 leaves the default on.
        let mut tn = Telnet::new();
        tn.check_telnet_options(&["BINARY=0".to_string()], None)
            .unwrap();
        assert_eq!(tn.us_preferred[TELOPT_BINARY as usize], NO);
        assert_eq!(tn.him_preferred[TELOPT_BINARY as usize], NO);

        let mut tn = Telnet::new();
        tn.check_telnet_options(&["BINARY=1".to_string()], None)
            .unwrap();
        assert_eq!(tn.us_preferred[TELOPT_BINARY as usize], YES);
    }

    #[test]
    fn check_options_reports_exact_error_codes() {
        let mut tn = Telnet::new();
        assert_eq!(
            tn.check_telnet_options(&["BOGUS=x".to_string()], None)
                .unwrap_err()
                .code(),
            CurlCode::UnknownOption
        );

        let mut tn = Telnet::new();
        assert_eq!(
            tn.check_telnet_options(&["noequalsign".to_string()], None)
                .unwrap_err()
                .code(),
            CurlCode::SetoptOptionSyntax
        );

        let mut tn = Telnet::new();
        assert_eq!(
            tn.check_telnet_options(&["WS=abc".to_string()], None)
                .unwrap_err()
                .code(),
            CurlCode::SetoptOptionSyntax
        );

        let mut tn = Telnet::new();
        assert_eq!(
            tn.check_telnet_options(&["WS=80y24".to_string()], None)
                .unwrap_err()
                .code(),
            CurlCode::SetoptOptionSyntax
        );

        // A non-ASCII username is rejected.
        let mut tn = Telnet::new();
        assert_eq!(
            tn.check_telnet_options(&[], Some("na\u{ef}ve"))
                .unwrap_err()
                .code(),
            CurlCode::BadFunctionArgument
        );
    }

    #[test]
    fn check_options_clears_vars_on_error() {
        let mut tn = Telnet::new();
        let opts = vec!["NEW_ENV=A,b".to_string(), "BOGUS=x".to_string()];
        assert!(tn.check_telnet_options(&opts, None).is_err());
        assert!(tn.telnet_vars.is_empty());
    }

    #[test]
    fn check_options_injects_user_env() {
        let mut tn = Telnet::new();
        tn.check_telnet_options(&[], Some("alice")).unwrap();
        assert_eq!(tn.telnet_vars, vec!["USER,alice".to_string()]);
        assert_eq!(tn.us_preferred[TELOPT_NEW_ENVIRON as usize], YES);
    }

    // -- PHASE 2: sub-negotiation byte layouts ------------------------------

    #[test]
    fn suboption_ttype_response_layout() {
        let mut tn = Telnet::new();
        tn.check_telnet_options(&["TTYPE=xterm".to_string()], None)
            .unwrap();
        tn.outgoing.clear();
        let mut out = Vec::new();
        // Server: IAC SB TTYPE SEND IAC SE.
        tn.telrcv(&[IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE], &mut out)
            .unwrap();
        assert!(out.is_empty());
        let mut expected = vec![IAC, SB, TELOPT_TTYPE, TELQUAL_IS];
        expected.extend_from_slice(b"xterm");
        expected.extend_from_slice(&[IAC, SE]);
        assert_eq!(tn.outgoing, expected);
    }

    #[test]
    fn suboption_new_environ_response_layout() {
        let mut tn = Telnet::new();
        tn.check_telnet_options(&["NEW_ENV=USER,me".to_string()], None)
            .unwrap();
        tn.outgoing.clear();
        let mut out = Vec::new();
        tn.telrcv(
            &[IAC, SB, TELOPT_NEW_ENVIRON, TELQUAL_SEND, IAC, SE],
            &mut out,
        )
        .unwrap();
        let mut expected = vec![IAC, SB, TELOPT_NEW_ENVIRON, TELQUAL_IS, NEW_ENV_VAR];
        expected.extend_from_slice(b"USER");
        expected.push(NEW_ENV_VALUE);
        expected.extend_from_slice(b"me");
        expected.extend_from_slice(&[IAC, SE]);
        assert_eq!(tn.outgoing, expected);
    }

    #[test]
    fn sendsuboption_naws_layout_and_escaping() {
        let mut tn = Telnet::new();
        tn.subopt_wsx = 80;
        tn.subopt_wsy = 24;
        tn.sendsuboption(TELOPT_NAWS);
        assert_eq!(
            tn.outgoing,
            vec![IAC, SB, TELOPT_NAWS, 0, 80, 0, 24, IAC, SE]
        );

        // A window dimension of 0xFF must be escaped as IAC IAC on the wire.
        let mut tn = Telnet::new();
        tn.subopt_wsx = 255;
        tn.subopt_wsy = 24;
        tn.sendsuboption(TELOPT_NAWS);
        assert_eq!(
            tn.outgoing,
            vec![IAC, SB, TELOPT_NAWS, 0, 0xFF, 0xFF, 0, 24, IAC, SE]
        );
    }

    // -- PHASE 3: the async duplex pump -------------------------------------

    #[tokio::test]
    async fn pump_performs_reactive_negotiation() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        // The server asks us to enable TTYPE, then closes its write half.
        server.write_all(&[IAC, DO, TELOPT_TTYPE]).await.unwrap();
        server.shutdown().await.unwrap();

        let mut input = tokio::io::empty();
        let mut output = tokio::io::sink();
        let mut tn = Telnet::new();
        tn.run(&mut client, &mut input, &mut output, None)
            .await
            .unwrap();

        drop(client);
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();

        // WONT TTYPE (refused: not preferred) followed by the default burst.
        let mut expected = vec![IAC, WONT, TELOPT_TTYPE];
        expected.extend_from_slice(&[
            IAC,
            WILL,
            TELOPT_BINARY,
            IAC,
            DO,
            TELOPT_BINARY,
            IAC,
            WILL,
            TELOPT_SGA,
            IAC,
            DO,
            TELOPT_SGA,
        ]);
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn pump_escapes_outbound_iac() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let mut input: &[u8] = &[0x41, 0xFF, 0x42];
        let mut output = tokio::io::sink();
        let mut tn = Telnet::new();

        let pump = tn.run(&mut client, &mut input, &mut output, None);
        let server_side = async {
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).await.unwrap();
            // Close our write half so the pump observes EOF and returns.
            server.shutdown().await.unwrap();
            buf
        };
        let (pump_res, buf) = tokio::join!(pump, server_side);
        pump_res.unwrap();
        // 'A', escaped 0xFF (doubled), 'B'.
        assert_eq!(buf, [0x41, 0xFF, 0xFF, 0x42]);
    }

    #[tokio::test]
    async fn pump_stops_cleanly_when_server_closes() {
        let (mut client, mut server) = tokio::io::duplex(64);
        server.shutdown().await.unwrap();
        drop(server);
        let mut input = tokio::io::empty();
        let mut output = tokio::io::sink();
        let mut tn = Telnet::new();
        assert!(tn
            .run(&mut client, &mut input, &mut output, None)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn pump_times_out_when_idle() {
        // Server stays open but never sends; input is immediately at EOF, so
        // only the timeout can end the pump.
        let (mut client, _server) = tokio::io::duplex(64);
        let mut input = tokio::io::empty();
        let mut output = tokio::io::sink();
        let mut tn = Telnet::new();
        let err = tn
            .run(
                &mut client,
                &mut input,
                &mut output,
                Some(Duration::from_millis(30)),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::OperationTimedout);
    }

    // -- PHASE 4: Protocol trait wiring -------------------------------------

    #[test]
    fn handler_do_it_and_done_are_object_safe() {
        // Exercise the handler through `&dyn Protocol`, matching how the scheme
        // table stores it, and drive the two required phases to completion.
        fn block_on<F: std::future::Future>(fut: F) -> F::Output {
            use std::sync::Arc;
            use std::task::{Context, Poll, Wake, Waker};

            struct NoopWake;
            impl Wake for NoopWake {
                fn wake(self: Arc<Self>) {}
            }
            let waker = Waker::from(Arc::new(NoopWake));
            let mut cx = Context::from_waker(&waker);
            let mut fut = Box::pin(fut);
            loop {
                if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                    return v;
                }
            }
        }

        let handler: &dyn Protocol = &HANDLER;
        let mut ctx = TransferCtx::new();
        assert!(block_on(handler.do_it(&mut ctx)).unwrap());
        block_on(handler.done(&mut ctx, Ok(()), false)).unwrap();
    }
}
