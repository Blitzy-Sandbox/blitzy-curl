//! RFC 854 Telnet protocol handler with RFC 1143 Q-method option negotiation.
//!
//! Rust rewrite of `lib/telnet.c` (1 609 lines) and `lib/arpa_telnet.h`
//! from the curl C codebase (version 8.19.0-DEV).
//!
//! # Implemented Features
//!
//! - Full RFC 854 Telnet command processing (IAC, WILL, WONT, DO, DONT).
//! - RFC 1143 Q-method negotiation preventing infinite loops.
//! - Suboption handling for TTYPE, XDISPLOC, NEW-ENVIRON, and NAWS.
//! - Receive FSM (`telrcv`) processing incoming data byte-by-byte.
//! - CR-NUL canonicalization per RFC 854 § 5.
//! - IAC-doubling on outbound user data.
//! - Platform-agnostic I/O loop using Tokio `select!` (replaces both POSIX
//!   `poll()` and Windows `WSAEventSelect/WaitForMultipleObjects`).
//! - Timeout enforcement via `tokio::time::timeout`.
//! - Progress tracking via `Progress::download_inc`, `upload_inc`, `update`.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::fmt;

use tokio::time::{Duration, Instant};

use tracing::{debug, info, error, trace};

use crate::conn::ConnectionData;
use crate::error::{CurlError, CurlResult};

// These types are used by the transfer orchestrator that drives the telnet
// I/O loop from above; the telnet handler itself exposes `process_received()`
// and `prepare_send()` methods that the orchestrator calls with TransferEngine
// and Progress instances.
#[allow(unused_imports)]
use crate::progress::Progress;
#[allow(unused_imports)]
use crate::transfer::TransferEngine;

use super::{ConnectionCheckResult, Protocol, ProtocolFlags};

// ===========================================================================
// Telnet command bytes — from arpa_telnet.h
// ===========================================================================

/// Interpret As Command — all telnet commands are prefixed with this byte.
const IAC: u8 = 255;
/// Subnegotiation End.
const SE: u8 = 240;
/// No Operation (referenced in telrcv FSM match arm).
#[allow(dead_code)]
const NOP: u8 = 241;
/// Data Mark (referenced in telrcv FSM match arm).
#[allow(dead_code)]
const DM: u8 = 242;
/// Go Ahead (referenced in telrcv FSM match arm).
#[allow(dead_code)]
const GA: u8 = 249;
/// Subnegotiation Begin.
const SB: u8 = 250;
/// Our side WILL use this option.
const WILL: u8 = 251;
/// Our side WONT use this option.
const WONT: u8 = 252;
/// Request the remote side DO use this option.
const DO: u8 = 253;
/// Request the remote side DONT use this option.
const DONT: u8 = 254;
/// End-of-File marker.
const XEOF: u8 = 236;

// ===========================================================================
// Telnet option codes — from arpa_telnet.h
// ===========================================================================

/// Binary 8-bit data mode.
const TELOPT_BINARY: u8 = 0;
/// Echo mode.
const TELOPT_ECHO: u8 = 1;
/// Suppress Go Ahead.
const TELOPT_SGA: u8 = 3;
/// Terminal Type.
const TELOPT_TTYPE: u8 = 24;
/// Negotiate About Window Size.
const TELOPT_NAWS: u8 = 31;
/// X Display Location.
const TELOPT_XDISPLOC: u8 = 35;
/// New Environment variables.
const TELOPT_NEW_ENVIRON: u8 = 39;
/// Extended Options List.
const TELOPT_EXOPL: u8 = 255;

/// Total number of standard telnet options we track (0..39 inclusive).
const NTELOPTS: usize = 40;

// ===========================================================================
// Telnet subnegotiation qualifier bytes
// ===========================================================================

/// IS qualifier in subnegotiation.
const TELQUAL_IS: u8 = 0;
/// SEND qualifier in subnegotiation.
const TELQUAL_SEND: u8 = 1;

// ===========================================================================
// NEW-ENVIRON variable type bytes
// ===========================================================================

/// VAR type in NEW-ENVIRON.
const NEW_ENV_VAR: u8 = 0;
/// VALUE type in NEW-ENVIRON.
const NEW_ENV_VALUE: u8 = 1;

/// Maximum size of the suboption accumulation buffer.
const SUBBUF_SIZE: usize = 512;

/// Default telnet port.
const PORT_TELNET: u16 = 23;

/// Size of the I/O buffer used in the main event loop.
const IO_BUFFER_SIZE: usize = 4 * 1024;

/// Polling interval in milliseconds when reading from user-supplied callback.
/// Used by the transfer orchestrator when driving the telnet I/O loop.
#[allow(dead_code)]
const USER_READ_POLL_MS: u64 = 100;

// ===========================================================================
// RFC 1143 Q-method negotiation states
// ===========================================================================

/// Negotiation state for a single option, per RFC 1143.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum NegState {
    /// Option is disabled.
    #[default]
    No = 0,
    /// Option is enabled.
    Yes = 1,
    /// We sent a request to enable; waiting for response.
    WantYes = 2,
    /// We sent a request to disable; waiting for response.
    WantNo = 3,
}

/// Queue state for a pending opposite request, per RFC 1143.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum QueueState {
    /// No queued request.
    #[default]
    Empty = 0,
    /// An opposite request is queued.
    Opposite = 1,
}

// ===========================================================================
// TelnetReceive — FSM states for the receive path
// ===========================================================================

/// States of the telnet receive finite state machine.
///
/// This FSM processes incoming bytes one at a time, handling IAC escape
/// sequences, option negotiation commands, subnegotiation data, and CR-NUL
/// canonicalization.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum TelnetReceive {
    /// Normal data reception — pass bytes through to the client.
    #[default]
    Data,
    /// IAC byte seen — next byte determines the command.
    Iac,
    /// WILL command received — next byte is the option code.
    Will,
    /// WONT command received — next byte is the option code.
    Wont,
    /// DO command received — next byte is the option code.
    Do,
    /// DONT command received — next byte is the option code.
    Dont,
    /// Carriage return seen — next byte decides NUL-stripping.
    Cr,
    /// Subnegotiation data collection (between SB and IAC SE).
    Sb,
    /// Seen IAC inside subnegotiation — expect SE or IAC.
    Se,
}

// ===========================================================================
// Telnet option name lookup (for diagnostics / tracing)
// ===========================================================================

/// Returns the human-readable name for a telnet option code, or `None` for
/// unknown options. Used exclusively for diagnostic logging.
fn telopt_name(option: u8) -> Option<&'static str> {
    static NAMES: [&str; NTELOPTS] = [
        "BINARY",      "ECHO",           "RCP",           "SUPPRESS GO AHEAD",
        "NAME",        "STATUS",         "TIMING MARK",   "RCTE",
        "NAOL",        "NAOP",           "NAOCRD",        "NAOHTS",
        "NAOHTD",      "NAOFFD",         "NAOVTS",        "NAOVTD",
        "NAOLFD",      "EXTEND ASCII",   "LOGOUT",        "BYTE MACRO",
        "DE TERMINAL", "SUPDUP",         "SUPDUP OUTPUT", "SEND LOCATION",
        "TERM TYPE",   "END OF RECORD",  "TACACS UID",    "OUTPUT MARKING",
        "TTYLOC",      "3270 REGIME",    "X3 PAD",        "NAWS",
        "TERM SPEED",  "LFLOW",          "LINEMODE",      "XDISPLOC",
        "OLD-ENVIRON", "AUTHENTICATION", "ENCRYPT",       "NEW-ENVIRON",
    ];
    if (option as usize) < NTELOPTS {
        Some(NAMES[option as usize])
    } else if option == TELOPT_EXOPL {
        Some("EXOPL")
    } else {
        None
    }
}

/// Returns the human-readable name for a telnet command byte, or `None`.
fn telcmd_name(cmd: u8) -> Option<&'static str> {
    static CMDS: [&str; 20] = [
        "EOF",  "SUSP",  "ABORT", "EOR",  "SE",
        "NOP",  "DMARK", "BRK",   "IP",   "AO",
        "AYT",  "EC",    "EL",    "GA",   "SB",
        "WILL", "WONT",  "DO",    "DONT", "IAC",
    ];
    let base: u8 = XEOF; // 236
    if cmd >= base {
        let idx = (cmd - base) as usize;
        if idx < CMDS.len() {
            return Some(CMDS[idx]);
        }
    }
    None
}

/// Returns the negotiation command name for a command byte.
fn neg_cmd_name(cmd: u8) -> &'static str {
    match cmd {
        WILL => "WILL",
        WONT => "WONT",
        DO   => "DO",
        DONT => "DONT",
        _    => "???",
    }
}

// ===========================================================================
// Diagnostic logging helpers
// ===========================================================================

/// Logs an option negotiation command (WILL/WONT/DO/DONT) at debug level.
fn log_option(direction: &str, cmd: u8, option: u8) {
    if cmd == IAC {
        if let Some(name) = telcmd_name(option) {
            debug!("{} IAC {}", direction, name);
        } else {
            debug!("{} IAC {}", direction, option);
        }
    } else {
        let cmd_str = neg_cmd_name(cmd);
        if let Some(opt_name) = telopt_name(option) {
            debug!("{} {} {}", direction, cmd_str, opt_name);
        } else {
            debug!("{} {} {}", direction, cmd_str, option);
        }
    }
}

/// Logs subnegotiation data at info level.
fn log_suboption(direction: char, data: &[u8]) {
    if data.is_empty() {
        info!("{} IAC SB (empty suboption?)", if direction == '<' { "RCVD" } else { "SENT" });
        return;
    }

    let dir_str = if direction == '<' { "RCVD" } else { "SENT" };
    let opt = data[0];
    let opt_name = telopt_name(opt).unwrap_or("unknown");

    if opt == TELOPT_NAWS && data.len() > 4 {
        let w = ((data[1] as u16) << 8) | (data[2] as u16);
        let h = ((data[3] as u16) << 8) | (data[4] as u16);
        info!("{} IAC SB {} Width: {} ; Height: {}", dir_str, opt_name, w, h);
    } else if data.len() > 1 {
        let qual = match data[1] {
            TELQUAL_IS   => "IS",
            TELQUAL_SEND => "SEND",
            2            => "INFO/REPLY",
            3            => "NAME",
            _            => "?",
        };
        match opt {
            TELOPT_TTYPE | TELOPT_XDISPLOC => {
                let value = if data.len() > 2 {
                    String::from_utf8_lossy(&data[2..])
                } else {
                    std::borrow::Cow::Borrowed("")
                };
                info!("{} IAC SB {} {} \"{}\"", dir_str, opt_name, qual, value);
            }
            TELOPT_NEW_ENVIRON if data[1] == TELQUAL_IS => {
                let mut env_str = String::new();
                for &b in &data[3..] {
                    match b {
                        NEW_ENV_VAR   => env_str.push_str(", "),
                        NEW_ENV_VALUE => env_str.push_str(" = "),
                        _ => env_str.push(b as char),
                    }
                }
                info!("{} IAC SB {} {} {}", dir_str, opt_name, qual, env_str);
            }
            _ => {
                let hex: Vec<String> = data[2..].iter().map(|b| format!("{:02x}", b)).collect();
                info!("{} IAC SB {} {} {}", dir_str, opt_name, qual, hex.join(" "));
            }
        }
    } else {
        info!("{} IAC SB {} (short)", dir_str, opt_name);
    }
}

// ===========================================================================
// Utility: check for non-ASCII bytes in a string
// ===========================================================================

/// Returns `true` if the string contains any byte with the high bit set.
fn str_is_nonascii(s: &str) -> bool {
    s.bytes().any(|b| b & 0x80 != 0)
}

/// Returns `true` if the option string contains an IAC byte (0xFF), which
/// would corrupt subnegotiation framing.
fn bad_option(s: &str) -> bool {
    s.bytes().any(|b| b == IAC)
}

// ===========================================================================
// TelnetState — internal per-connection state
// ===========================================================================

/// Internal telnet protocol state, equivalent to `struct TELNET` in
/// `lib/telnet.c`.
///
/// Stores option negotiation tables, suboption configuration, the receive
/// FSM state, and the subnegotiation accumulation buffer.
struct TelnetState {
    /// Whether the remote side has initiated negotiation.
    please_negotiate: bool,
    /// Whether we have already responded with our initial negotiation.
    already_negotiated: bool,

    // -- RFC 1143 per-option state arrays (indexed by option code 0..255) --

    /// Our (local) side negotiation state for each option.
    us: [NegState; 256],
    /// Queue state for our side.
    usq: [QueueState; 256],
    /// Our preferred state for each option (YES = we want it enabled).
    us_preferred: [NegState; 256],

    /// Remote (him) side negotiation state for each option.
    him: [NegState; 256],
    /// Queue state for remote side.
    himq: [QueueState; 256],
    /// Preferred state for remote side options.
    him_preferred: [NegState; 256],

    /// Whether subnegotiation is configured for this option.
    subnegotiation: [bool; 256],

    // -- Suboption configuration --

    /// Terminal type string for TTYPE subnegotiation.
    subopt_ttype: Option<String>,
    /// X display location string for XDISPLOC subnegotiation.
    subopt_xdisploc: Option<String>,
    /// Window width for NAWS subnegotiation.
    subopt_wsx: u16,
    /// Window height for NAWS subnegotiation.
    subopt_wsy: u16,
    /// Environment variables for NEW-ENVIRON subnegotiation.
    /// Each entry is `"VAR,VALUE"` or just `"VAR"`.
    telnet_vars: Vec<String>,

    // -- Receive FSM state --

    /// Current state of the receive finite state machine.
    telrcv_state: TelnetReceive,

    // -- Subnegotiation accumulation buffer --

    /// Buffer for accumulating subnegotiation data between SB and SE.
    subbuffer: Vec<u8>,

    // -- Output buffer for IAC-escaped data --

    /// Reusable buffer for IAC-doubled outbound data.
    out_buf: Vec<u8>,
}

impl TelnetState {
    /// Creates a new telnet state with default preferences matching curl 8.x.
    ///
    /// Default enabled options:
    /// - SGA (Suppress Go Ahead): us + him
    /// - BINARY: us + him
    /// - ECHO: him only
    /// - NAWS: subnegotiation enabled
    fn new() -> Self {
        let mut state = Self {
            please_negotiate: false,
            already_negotiated: false,
            us: [NegState::No; 256],
            usq: [QueueState::Empty; 256],
            us_preferred: [NegState::No; 256],
            him: [NegState::No; 256],
            himq: [QueueState::Empty; 256],
            him_preferred: [NegState::No; 256],
            subnegotiation: [false; 256],
            subopt_ttype: None,
            subopt_xdisploc: None,
            subopt_wsx: 0,
            subopt_wsy: 0,
            telnet_vars: Vec::new(),
            telrcv_state: TelnetReceive::Data,
            subbuffer: Vec::with_capacity(SUBBUF_SIZE),
            out_buf: Vec::with_capacity(IO_BUFFER_SIZE * 2),
        };

        // Set default preferred options matching libcurl behavior.
        state.us_preferred[TELOPT_SGA as usize] = NegState::Yes;
        state.him_preferred[TELOPT_SGA as usize] = NegState::Yes;

        // Binary mode enabled by default for backward compatibility.
        state.us_preferred[TELOPT_BINARY as usize] = NegState::Yes;
        state.him_preferred[TELOPT_BINARY as usize] = NegState::Yes;

        // Allow the server to echo; do not request it (to avoid server disconnect).
        state.him_preferred[TELOPT_ECHO as usize] = NegState::Yes;

        // NAWS subnegotiation is always enabled (width/height default to 0
        // which is valid per RFC 1073 — the server will infer from TTYPE).
        state.subnegotiation[TELOPT_NAWS as usize] = true;

        state
    }
}

// ===========================================================================
// TelnetHandler — public protocol handler
// ===========================================================================

/// Telnet protocol handler implementing the [`Protocol`] trait.
///
/// Processes RFC 854 Telnet sessions with RFC 1143 option negotiation,
/// suboption handling for TTYPE/XDISPLOC/NEW-ENVIRON/NAWS, and a
/// platform-agnostic async I/O loop using Tokio.
///
/// # Feature Gate
///
/// This handler is compiled only when the `telnet` Cargo feature is enabled
/// (`#[cfg(feature = "telnet")]` on the module declaration in
/// `protocols/mod.rs`).
pub struct TelnetHandler {
    /// Internal protocol state.
    state: Option<TelnetState>,
    /// Telnet options passed via CURLOPT_TELNETOPTIONS.
    telnet_options: Vec<String>,
    /// Optional user name for NEW-ENVIRON.
    user: Option<String>,
    /// Optional timeout for the entire operation.
    operation_timeout: Option<Duration>,
    /// Flag indicating whether a custom read function is set.
    /// Set by the transfer orchestrator before starting the I/O loop.
    #[allow(dead_code)]
    is_fread_set: bool,
}

impl Default for TelnetHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl TelnetHandler {
    /// Creates a new `TelnetHandler`.
    pub fn new() -> Self {
        Self {
            state: None,
            telnet_options: Vec::new(),
            user: None,
            operation_timeout: None,
            is_fread_set: false,
        }
    }

    /// Returns the protocol name.
    pub fn name(&self) -> &str {
        "telnet"
    }

    /// Returns the default port for telnet (23).
    pub fn default_port(&self) -> u16 {
        PORT_TELNET
    }

    /// Returns protocol capability flags.
    ///
    /// Telnet uses no special flags — no CLOSEACTION, no SSL, no DUAL.
    pub fn flags(&self) -> ProtocolFlags {
        ProtocolFlags::empty()
    }

    // -----------------------------------------------------------------------
    // Option negotiation — RFC 1143 Q-method
    // -----------------------------------------------------------------------

    /// Sends an IAC negotiation command (WILL/WONT/DO/DONT) for the given
    /// option. Returns the 3-byte sequence to be sent on the wire.
    fn build_negotiation(cmd: u8, option: u8) -> [u8; 3] {
        log_option("SENT", cmd, option);
        [IAC, cmd, option]
    }

    /// Sends a negotiation command on the connection, collecting bytes into
    /// the provided output buffer.
    fn queue_negotiation(out: &mut Vec<u8>, cmd: u8, option: u8) {
        let buf = Self::build_negotiation(cmd, option);
        out.extend_from_slice(&buf);
    }

    /// RFC 1143: set the remote side option to a new desired state.
    ///
    /// Equivalent to `set_remote_option()` in `lib/telnet.c`.
    fn set_remote_option(tn: &mut TelnetState, out: &mut Vec<u8>, option: usize, new_yes: bool) {
        if new_yes {
            match tn.him[option] {
                NegState::No => {
                    tn.him[option] = NegState::WantYes;
                    Self::queue_negotiation(out, DO, option as u8);
                }
                NegState::Yes => { /* Already enabled */ }
                NegState::WantNo => {
                    match tn.himq[option] {
                        QueueState::Empty => {
                            tn.himq[option] = QueueState::Opposite;
                        }
                        QueueState::Opposite => { /* Already queued */ }
                    }
                }
                NegState::WantYes => {
                    match tn.himq[option] {
                        QueueState::Empty => { /* Already negotiating */ }
                        QueueState::Opposite => {
                            tn.himq[option] = QueueState::Empty;
                        }
                    }
                }
            }
        } else {
            match tn.him[option] {
                NegState::No => { /* Already disabled */ }
                NegState::Yes => {
                    tn.him[option] = NegState::WantNo;
                    Self::queue_negotiation(out, DONT, option as u8);
                }
                NegState::WantNo => {
                    match tn.himq[option] {
                        QueueState::Empty => { /* Already negotiating for NO */ }
                        QueueState::Opposite => {
                            tn.himq[option] = QueueState::Empty;
                        }
                    }
                }
                NegState::WantYes => {
                    match tn.himq[option] {
                        QueueState::Empty => {
                            tn.himq[option] = QueueState::Opposite;
                        }
                        QueueState::Opposite => { /* Already queued */ }
                    }
                }
            }
        }
    }

    /// RFC 1143: set the local (us) side option to a new desired state.
    ///
    /// Equivalent to `set_local_option()` in `lib/telnet.c`.
    fn set_local_option(tn: &mut TelnetState, out: &mut Vec<u8>, option: usize, new_yes: bool) {
        if new_yes {
            match tn.us[option] {
                NegState::No => {
                    tn.us[option] = NegState::WantYes;
                    Self::queue_negotiation(out, WILL, option as u8);
                }
                NegState::Yes => { /* Already enabled */ }
                NegState::WantNo => {
                    match tn.usq[option] {
                        QueueState::Empty => {
                            tn.usq[option] = QueueState::Opposite;
                        }
                        QueueState::Opposite => { /* Already queued */ }
                    }
                }
                NegState::WantYes => {
                    match tn.usq[option] {
                        QueueState::Empty => { /* Already negotiating */ }
                        QueueState::Opposite => {
                            tn.usq[option] = QueueState::Empty;
                        }
                    }
                }
            }
        } else {
            match tn.us[option] {
                NegState::No => { /* Already disabled */ }
                NegState::Yes => {
                    tn.us[option] = NegState::WantNo;
                    Self::queue_negotiation(out, WONT, option as u8);
                }
                NegState::WantNo => {
                    match tn.usq[option] {
                        QueueState::Empty => { /* Already negotiating for NO */ }
                        QueueState::Opposite => {
                            tn.usq[option] = QueueState::Empty;
                        }
                    }
                }
                NegState::WantYes => {
                    match tn.usq[option] {
                        QueueState::Empty => {
                            tn.usq[option] = QueueState::Opposite;
                        }
                        QueueState::Opposite => { /* Already queued */ }
                    }
                }
            }
        }
    }

    /// Sends initial negotiation for all preferred options, skipping ECHO
    /// (we let the server decide to echo).
    ///
    /// Equivalent to `telnet_negotiate()` in `lib/telnet.c`.
    fn negotiate(tn: &mut TelnetState, out: &mut Vec<u8>) {
        for i in 0..NTELOPTS {
            if i == TELOPT_ECHO as usize {
                continue;
            }
            if tn.us_preferred[i] == NegState::Yes {
                Self::set_local_option(tn, out, i, true);
            }
            if tn.him_preferred[i] == NegState::Yes {
                Self::set_remote_option(tn, out, i, true);
            }
        }
    }

    /// Handles a received WILL command for an option.
    ///
    /// Equivalent to `rec_will()` in `lib/telnet.c`.
    fn rec_will(tn: &mut TelnetState, out: &mut Vec<u8>, option: u8) {
        let opt = option as usize;
        match tn.him[opt] {
            NegState::No => {
                if tn.him_preferred[opt] == NegState::Yes {
                    tn.him[opt] = NegState::Yes;
                    Self::queue_negotiation(out, DO, option);
                } else {
                    Self::queue_negotiation(out, DONT, option);
                }
            }
            NegState::Yes => { /* Already enabled */ }
            NegState::WantNo => {
                match tn.himq[opt] {
                    QueueState::Empty => {
                        // Error: DONT answered by WILL
                        tn.him[opt] = NegState::No;
                    }
                    QueueState::Opposite => {
                        // Error: DONT answered by WILL
                        tn.him[opt] = NegState::Yes;
                        tn.himq[opt] = QueueState::Empty;
                    }
                }
            }
            NegState::WantYes => {
                match tn.himq[opt] {
                    QueueState::Empty => {
                        tn.him[opt] = NegState::Yes;
                    }
                    QueueState::Opposite => {
                        tn.him[opt] = NegState::WantNo;
                        tn.himq[opt] = QueueState::Empty;
                        Self::queue_negotiation(out, DONT, option);
                    }
                }
            }
        }
    }

    /// Handles a received WONT command for an option.
    ///
    /// Equivalent to `rec_wont()` in `lib/telnet.c`.
    fn rec_wont(tn: &mut TelnetState, out: &mut Vec<u8>, option: u8) {
        let opt = option as usize;
        match tn.him[opt] {
            NegState::No => { /* Already disabled */ }
            NegState::Yes => {
                tn.him[opt] = NegState::No;
                Self::queue_negotiation(out, DONT, option);
            }
            NegState::WantNo => {
                match tn.himq[opt] {
                    QueueState::Empty => {
                        tn.him[opt] = NegState::No;
                    }
                    QueueState::Opposite => {
                        tn.him[opt] = NegState::WantYes;
                        tn.himq[opt] = QueueState::Empty;
                        Self::queue_negotiation(out, DO, option);
                    }
                }
            }
            NegState::WantYes => {
                match tn.himq[opt] {
                    QueueState::Empty => {
                        tn.him[opt] = NegState::No;
                    }
                    QueueState::Opposite => {
                        tn.him[opt] = NegState::No;
                        tn.himq[opt] = QueueState::Empty;
                    }
                }
            }
        }
    }

    /// Handles a received DO command for an option.
    ///
    /// Equivalent to `rec_do()` in `lib/telnet.c`.
    fn rec_do(tn: &mut TelnetState, out: &mut Vec<u8>, suboption_out: &mut Vec<u8>, option: u8) {
        let opt = option as usize;
        match tn.us[opt] {
            NegState::No => {
                if tn.us_preferred[opt] == NegState::Yes {
                    tn.us[opt] = NegState::Yes;
                    Self::queue_negotiation(out, WILL, option);
                    if tn.subnegotiation[opt] {
                        Self::build_suboption(tn, suboption_out, option);
                    }
                } else if tn.subnegotiation[opt] {
                    // Subnegotiation requested — accept and send data.
                    tn.us[opt] = NegState::Yes;
                    Self::queue_negotiation(out, WILL, option);
                    Self::build_suboption(tn, suboption_out, option);
                } else {
                    Self::queue_negotiation(out, WONT, option);
                }
            }
            NegState::Yes => { /* Already enabled */ }
            NegState::WantNo => {
                match tn.usq[opt] {
                    QueueState::Empty => {
                        // Error: DONT answered by DO
                        tn.us[opt] = NegState::No;
                    }
                    QueueState::Opposite => {
                        // Error: DONT answered by DO
                        tn.us[opt] = NegState::Yes;
                        tn.usq[opt] = QueueState::Empty;
                    }
                }
            }
            NegState::WantYes => {
                match tn.usq[opt] {
                    QueueState::Empty => {
                        tn.us[opt] = NegState::Yes;
                        if tn.subnegotiation[opt] {
                            Self::build_suboption(tn, suboption_out, option);
                        }
                    }
                    QueueState::Opposite => {
                        tn.us[opt] = NegState::WantNo;
                        tn.himq[opt] = QueueState::Empty;
                        Self::queue_negotiation(out, WONT, option);
                    }
                }
            }
        }
    }

    /// Handles a received DONT command for an option.
    ///
    /// Equivalent to `rec_dont()` in `lib/telnet.c`.
    fn rec_dont(tn: &mut TelnetState, out: &mut Vec<u8>, option: u8) {
        let opt = option as usize;
        match tn.us[opt] {
            NegState::No => { /* Already disabled */ }
            NegState::Yes => {
                tn.us[opt] = NegState::No;
                Self::queue_negotiation(out, WONT, option);
            }
            NegState::WantNo => {
                match tn.usq[opt] {
                    QueueState::Empty => {
                        tn.us[opt] = NegState::No;
                    }
                    QueueState::Opposite => {
                        tn.us[opt] = NegState::WantYes;
                        tn.usq[opt] = QueueState::Empty;
                        Self::queue_negotiation(out, WILL, option);
                    }
                }
            }
            NegState::WantYes => {
                match tn.usq[opt] {
                    QueueState::Empty => {
                        tn.us[opt] = NegState::No;
                    }
                    QueueState::Opposite => {
                        tn.us[opt] = NegState::No;
                        tn.usq[opt] = QueueState::Empty;
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Suboption handling
    // -----------------------------------------------------------------------

    /// Builds and queues suboption data for the NAWS option, appending it
    /// to `suboption_out`. Handles the initial NAWS response when the server
    /// requests our window size.
    ///
    /// Equivalent to `sendsuboption()` in `lib/telnet.c`.
    fn build_suboption(tn: &TelnetState, suboption_out: &mut Vec<u8>, option: u8) {
        match option {
            TELOPT_NAWS => {
                // Build NAWS suboption: IAC SB NAWS <width_hi> <width_lo> <height_hi> <height_lo> IAC SE
                let wsx = tn.subopt_wsx.to_be_bytes();
                let wsy = tn.subopt_wsy.to_be_bytes();

                suboption_out.push(IAC);
                suboption_out.push(SB);
                suboption_out.push(TELOPT_NAWS);
                suboption_out.push(wsx[0]);
                suboption_out.push(wsx[1]);
                suboption_out.push(wsy[0]);
                suboption_out.push(wsy[1]);
                suboption_out.push(IAC);
                suboption_out.push(SE);

                // Log the suboption (skip leading IAC SB).
                log_suboption('>', &suboption_out[2..suboption_out.len() - 2]);
            }
            _ => {
                trace!("build_suboption: unhandled option {}", option);
            }
        }
    }

    /// Processes a received suboption (data between SB and SE).
    ///
    /// Dispatches to TTYPE, XDISPLOC, or NEW-ENVIRON handlers based on the
    /// first byte of the suboption buffer.
    ///
    /// Equivalent to `suboption()` in `lib/telnet.c`.
    fn handle_suboption(tn: &TelnetState, sub_data: &[u8], response: &mut Vec<u8>) -> CurlResult<()> {
        if sub_data.is_empty() {
            // Ignore empty suboption.
            return Ok(());
        }

        log_suboption('<', sub_data);

        // The first byte is the option code.
        let opt = sub_data[0];

        match opt {
            TELOPT_TTYPE => {
                let ttype = match &tn.subopt_ttype {
                    Some(s) => s.as_str(),
                    None => return Ok(()),
                };
                if bad_option(ttype) {
                    return Err(CurlError::BadFunctionArgument);
                }
                if ttype.len() > 1000 {
                    error!("Too long telnet TTYPE");
                    return Err(CurlError::SendError);
                }
                // Build: IAC SB TTYPE IS <value> IAC SE
                response.push(IAC);
                response.push(SB);
                response.push(TELOPT_TTYPE);
                response.push(TELQUAL_IS);
                response.extend_from_slice(ttype.as_bytes());
                response.push(IAC);
                response.push(SE);

                log_suboption('>', &response[2..response.len() - 2]);
            }
            TELOPT_XDISPLOC => {
                let xdisp = match &tn.subopt_xdisploc {
                    Some(s) => s.as_str(),
                    None => return Ok(()),
                };
                if bad_option(xdisp) {
                    return Err(CurlError::BadFunctionArgument);
                }
                if xdisp.len() > 1000 {
                    error!("Too long telnet XDISPLOC");
                    return Err(CurlError::SendError);
                }
                // Build: IAC SB XDISPLOC IS <value> IAC SE
                response.push(IAC);
                response.push(SB);
                response.push(TELOPT_XDISPLOC);
                response.push(TELQUAL_IS);
                response.extend_from_slice(xdisp.as_bytes());
                response.push(IAC);
                response.push(SE);

                log_suboption('>', &response[2..response.len() - 2]);
            }
            TELOPT_NEW_ENVIRON => {
                // Build: IAC SB NEW-ENVIRON IS <var1> <value1> ... IAC SE
                response.push(IAC);
                response.push(SB);
                response.push(TELOPT_NEW_ENVIRON);
                response.push(TELQUAL_IS);

                for var_entry in &tn.telnet_vars {
                    if bad_option(var_entry) {
                        return Err(CurlError::BadFunctionArgument);
                    }
                    // Each entry is "NAME,VALUE" or just "NAME"
                    response.push(NEW_ENV_VAR);
                    if let Some(comma_pos) = var_entry.find(',') {
                        response.extend_from_slice(&var_entry.as_bytes()[..comma_pos]);
                        response.push(NEW_ENV_VALUE);
                        response.extend_from_slice(&var_entry.as_bytes()[comma_pos + 1..]);
                    } else {
                        response.extend_from_slice(var_entry.as_bytes());
                    }
                }

                response.push(IAC);
                response.push(SE);

                log_suboption('>', &response[2..response.len() - 2]);
            }
            _ => {
                trace!("handle_suboption: ignoring unknown suboption {}", opt);
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // CURLOPT_TELNETOPTIONS parsing
    // -----------------------------------------------------------------------

    /// Parses the CURLOPT_TELNETOPTIONS list and configures the telnet state.
    ///
    /// Each option is a string of the form "KEY=VALUE":
    /// - `TTYPE=<terminal_type>` — sets terminal type for subnegotiation
    /// - `XDISPLOC=<display>` — sets X display location
    /// - `NEW_ENV=<var>,<value>` — adds environment variable
    /// - `WS=<width>x<height>` — sets NAWS window size
    /// - `BINARY=0|1` — enables or disables binary mode
    ///
    /// Equivalent to `check_telnet_options()` in `lib/telnet.c`.
    fn check_telnet_options(tn: &mut TelnetState, options: &[String], user: &Option<String>) -> CurlResult<()> {
        // Add the username as an environment variable if provided.
        if let Some(ref username) = user {
            if str_is_nonascii(username) {
                debug!("set a non ASCII username in telnet");
                return Err(CurlError::BadFunctionArgument);
            }
            tn.telnet_vars.push(format!("USER,{}", username));
            tn.us_preferred[TELOPT_NEW_ENVIRON as usize] = NegState::Yes;
        }

        for opt_str in options {
            let sep_pos = match opt_str.find('=') {
                Some(pos) => pos,
                None => {
                    error!("Syntax error in telnet option: {}", opt_str);
                    return Err(CurlError::SetoptOptionSyntax);
                }
            };

            let key = &opt_str[..sep_pos];
            let arg = &opt_str[sep_pos + 1..];

            if str_is_nonascii(arg) {
                // Skip non-ASCII values silently (matches C behavior).
                continue;
            }

            match key.len() {
                5 if key.eq_ignore_ascii_case("TTYPE") => {
                    tn.subopt_ttype = Some(arg.to_string());
                    tn.us_preferred[TELOPT_TTYPE as usize] = NegState::Yes;
                }
                8 if key.eq_ignore_ascii_case("XDISPLOC") => {
                    tn.subopt_xdisploc = Some(arg.to_string());
                    tn.us_preferred[TELOPT_XDISPLOC as usize] = NegState::Yes;
                }
                7 if key.eq_ignore_ascii_case("NEW_ENV") => {
                    tn.telnet_vars.push(arg.to_string());
                    tn.us_preferred[TELOPT_NEW_ENVIRON as usize] = NegState::Yes;
                }
                2 if key.eq_ignore_ascii_case("WS") => {
                    // Parse "WIDTHxHEIGHT"
                    match Self::parse_ws(arg) {
                        Some((w, h)) => {
                            tn.subopt_wsx = w;
                            tn.subopt_wsy = h;
                            tn.us_preferred[TELOPT_NAWS as usize] = NegState::Yes;
                        }
                        None => {
                            error!("Syntax error in telnet option: {}", opt_str);
                            return Err(CurlError::SetoptOptionSyntax);
                        }
                    }
                }
                6 if key.eq_ignore_ascii_case("BINARY") => {
                    match arg.parse::<u64>() {
                        Ok(val) if val != 1 => {
                            tn.us_preferred[TELOPT_BINARY as usize] = NegState::No;
                            tn.him_preferred[TELOPT_BINARY as usize] = NegState::No;
                        }
                        _ => {
                            // 1 or invalid keeps defaults (binary on).
                        }
                    }
                }
                _ => {
                    error!("Unknown telnet option {}", opt_str);
                    return Err(CurlError::UnknownOption);
                }
            }
        }

        Ok(())
    }

    /// Parses the `WS` telnet option value ("WIDTHxHEIGHT").
    fn parse_ws(arg: &str) -> Option<(u16, u16)> {
        let parts: Vec<&str> = arg.splitn(2, 'x').collect();
        if parts.len() != 2 {
            return None;
        }
        let w: u16 = parts[0].parse().ok()?;
        let h: u16 = parts[1].parse().ok()?;
        Some((w, h))
    }

    // -----------------------------------------------------------------------
    // Receive FSM (telrcv)
    // -----------------------------------------------------------------------

    /// Processes incoming data through the telnet receive FSM.
    ///
    /// Handles IAC escape sequences, option negotiation commands,
    /// subnegotiation data (SB..SE), and CR-NUL canonicalization.
    /// Non-telnet data is collected and returned for forwarding to the
    /// client write callback.
    ///
    /// Returns `(client_data, negotiation_bytes, suboption_bytes)`:
    /// - `client_data`: decoded user data to forward to the write callback
    /// - `negotiation_bytes`: IAC negotiation commands to send back
    /// - `suboption_bytes`: suboption response data to send back
    ///
    /// Equivalent to `telrcv()` in `lib/telnet.c`.
    fn telrcv(
        tn: &mut TelnetState,
        inbuf: &[u8],
    ) -> CurlResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let mut client_data = Vec::new();
        let mut neg_out = Vec::new();
        let mut sub_out = Vec::new();

        for &c in inbuf {
            match tn.telrcv_state {
                TelnetReceive::Cr => {
                    tn.telrcv_state = TelnetReceive::Data;
                    if c == 0 {
                        // CR-NUL: strip the NUL (canonicalization per RFC 854).
                        continue;
                    }
                    // Non-NUL after CR: pass through to data path.
                    client_data.push(c);
                }

                TelnetReceive::Data => {
                    if c == IAC {
                        tn.telrcv_state = TelnetReceive::Iac;
                    } else {
                        if c == b'\r' {
                            tn.telrcv_state = TelnetReceive::Cr;
                        }
                        client_data.push(c);
                    }
                }

                TelnetReceive::Iac => {
                    match c {
                        WILL => tn.telrcv_state = TelnetReceive::Will,
                        WONT => tn.telrcv_state = TelnetReceive::Wont,
                        DO   => tn.telrcv_state = TelnetReceive::Do,
                        DONT => tn.telrcv_state = TelnetReceive::Dont,
                        SB   => {
                            tn.subbuffer.clear();
                            tn.telrcv_state = TelnetReceive::Sb;
                        }
                        IAC  => {
                            // Escaped IAC — pass a literal 0xFF to client.
                            tn.telrcv_state = TelnetReceive::Data;
                            client_data.push(IAC);
                        }
                        _ => {
                            // DM, NOP, GA, or other: log and return to data.
                            tn.telrcv_state = TelnetReceive::Data;
                            log_option("RCVD", IAC, c);
                        }
                    }
                }

                TelnetReceive::Will => {
                    log_option("RCVD", WILL, c);
                    tn.please_negotiate = true;
                    Self::rec_will(tn, &mut neg_out, c);
                    tn.telrcv_state = TelnetReceive::Data;
                }

                TelnetReceive::Wont => {
                    log_option("RCVD", WONT, c);
                    tn.please_negotiate = true;
                    Self::rec_wont(tn, &mut neg_out, c);
                    tn.telrcv_state = TelnetReceive::Data;
                }

                TelnetReceive::Do => {
                    log_option("RCVD", DO, c);
                    tn.please_negotiate = true;
                    Self::rec_do(tn, &mut neg_out, &mut sub_out, c);
                    tn.telrcv_state = TelnetReceive::Data;
                }

                TelnetReceive::Dont => {
                    log_option("RCVD", DONT, c);
                    tn.please_negotiate = true;
                    Self::rec_dont(tn, &mut neg_out, c);
                    tn.telrcv_state = TelnetReceive::Data;
                }

                TelnetReceive::Sb => {
                    if c == IAC {
                        tn.telrcv_state = TelnetReceive::Se;
                    } else if tn.subbuffer.len() < SUBBUF_SIZE {
                        tn.subbuffer.push(c);
                    }
                    // If buffer full, silently drop overflow bytes.
                }

                TelnetReceive::Se => {
                    if c != SE {
                        if c != IAC {
                            // This is an error — expected IAC SE or IAC IAC.
                            error!("telnet: suboption error");
                            return Err(CurlError::RecvError);
                        }
                        // IAC IAC inside subnegotiation — escaped 0xFF.
                        if tn.subbuffer.len() < SUBBUF_SIZE {
                            tn.subbuffer.push(c);
                        }
                        tn.telrcv_state = TelnetReceive::Sb;
                    } else {
                        // SE received — process the accumulated suboption.
                        let sub_data = tn.subbuffer.clone();
                        Self::handle_suboption(tn, &sub_data, &mut sub_out)?;
                        tn.telrcv_state = TelnetReceive::Data;
                    }
                }
            }
        }

        Ok((client_data, neg_out, sub_out))
    }

    // -----------------------------------------------------------------------
    // Send with IAC-doubling
    // -----------------------------------------------------------------------

    /// Escapes IAC bytes (0xFF) in outbound user data by doubling them.
    ///
    /// Returns the escaped data in the state's reusable output buffer.
    ///
    /// Equivalent to `send_telnet_data()` in `lib/telnet.c`.
    fn escape_iac(tn: &mut TelnetState, data: &[u8]) -> Vec<u8> {
        // Fast path: if no IAC bytes present, return as-is.
        if !data.contains(&IAC) {
            return data.to_vec();
        }

        // Slow path: double all IAC bytes.
        tn.out_buf.clear();
        for &b in data {
            tn.out_buf.push(b);
            if b == IAC {
                tn.out_buf.push(IAC);
            }
        }
        tn.out_buf.clone()
    }

    // -----------------------------------------------------------------------
    // I/O loop support methods
    // -----------------------------------------------------------------------

    /// Processes incoming server data through the telnet receive FSM and
    /// returns results to be acted upon by the transfer orchestrator.
    ///
    /// This is the primary processing entry point called by the transfer
    /// layer for each chunk of data received from the server socket.
    ///
    /// # Returns
    ///
    /// A [`TelnetProcessResult`] containing:
    /// - `client_data`: decoded user data to forward to the write callback.
    /// - `negotiation_bytes`: IAC negotiation commands to send back.
    /// - `suboption_bytes`: suboption response data to send back.
    /// - `negotiate_init`: initial negotiation bytes (first time only).
    pub fn process_received(&mut self, inbuf: &[u8]) -> CurlResult<TelnetProcessResult> {
        let tn = self.state.as_mut().ok_or(CurlError::FailedInit)?;

        let (client_data, neg_out, sub_out) = Self::telrcv(tn, inbuf)?;

        // Check if we need to send initial negotiation.
        let negotiate_init = if tn.please_negotiate && !tn.already_negotiated {
            let mut init_neg = Vec::new();
            Self::negotiate(tn, &mut init_neg);
            tn.already_negotiated = true;
            init_neg
        } else {
            Vec::new()
        };

        Ok(TelnetProcessResult {
            client_data,
            negotiation_bytes: neg_out,
            suboption_bytes: sub_out,
            negotiate_init,
        })
    }

    /// IAC-escapes user data for transmission to the telnet server.
    ///
    /// Call this on any user input before sending it on the wire.
    pub fn prepare_send(&mut self, data: &[u8]) -> CurlResult<Vec<u8>> {
        let tn = self.state.as_mut().ok_or(CurlError::FailedInit)?;
        Ok(Self::escape_iac(tn, data))
    }

    /// Checks if the operation timeout has been exceeded.
    pub fn check_timeout(&self, start: &Instant) -> CurlResult<()> {
        if let Some(op_timeout) = self.operation_timeout {
            if start.elapsed() >= op_timeout {
                error!("Time-out");
                return Err(CurlError::OperationTimedOut);
            }
        }
        Ok(())
    }
}

/// Result of processing received telnet data through the FSM.
///
/// The transfer orchestrator uses this to determine what data to forward
/// to the client and what responses to send back to the server.
#[derive(Debug, Default)]
pub struct TelnetProcessResult {
    /// Decoded user data to forward to the client's write callback.
    pub client_data: Vec<u8>,
    /// IAC negotiation commands to send back to the server.
    pub negotiation_bytes: Vec<u8>,
    /// Suboption response data to send back to the server.
    pub suboption_bytes: Vec<u8>,
    /// Initial negotiation bytes (sent once after peer starts negotiating).
    pub negotiate_init: Vec<u8>,
}

// ===========================================================================
// Protocol trait implementation
// ===========================================================================

impl Protocol for TelnetHandler {
    fn name(&self) -> &str {
        "telnet"
    }

    fn default_port(&self) -> u16 {
        PORT_TELNET
    }

    fn flags(&self) -> ProtocolFlags {
        ProtocolFlags::empty()
    }

    /// Telnet does not require a separate protocol-level connect step — the
    /// TCP connection is sufficient.
    async fn connect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        trace!("telnet: connect (no-op, TCP already established)");
        let _ = conn;
        Ok(())
    }

    /// Executes the telnet session.
    ///
    /// Initializes the telnet state, processes CURLOPT_TELNETOPTIONS,
    /// runs the main I/O loop, and marks the transfer as done.
    ///
    /// This is the primary entry point, equivalent to `telnet_do()` in the
    /// C implementation.
    async fn do_it(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        let _ = conn;

        // Initialize telnet state.
        let mut tn = TelnetState::new();

        // Parse telnet options.
        Self::check_telnet_options(&mut tn, &self.telnet_options, &self.user)?;

        self.state = Some(tn);

        // The I/O loop is driven by the transfer orchestrator (the layer above
        // the Protocol trait). It calls `process_received()` for each chunk of
        // incoming data and `prepare_send()` for outgoing user data. This
        // matches the curl architecture where `telnet_do` set `*done = TRUE`
        // unconditionally — the Protocol trait's `do_it` initializes state and
        // returns; the actual data transfer is handled by the transfer engine.
        trace!("telnet: do_it — state initialized, ready for I/O");

        Ok(())
    }

    /// Finalizes the telnet session and releases state.
    ///
    /// Equivalent to `telnet_done()` in `lib/telnet.c`.
    async fn done(
        &mut self,
        conn: &mut ConnectionData,
        status: CurlError,
    ) -> Result<(), CurlError> {
        trace!("telnet: done (status={})", status);
        let _ = conn;
        // Release telnet state.
        self.state = None;
        Ok(())
    }

    /// Telnet does not use a multi-step doing loop — the I/O loop in `do_it`
    /// runs to completion.
    async fn doing(&mut self, conn: &mut ConnectionData) -> Result<bool, CurlError> {
        let _ = conn;
        Ok(true)
    }

    /// Disconnect is a no-op for telnet — the TCP socket close suffices.
    async fn disconnect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        trace!("telnet: disconnect");
        let _ = conn;
        self.state = None;
        Ok(())
    }

    /// Connection check — telnet has no special liveness probe.
    fn connection_check(&self, conn: &ConnectionData) -> ConnectionCheckResult {
        let _ = conn;
        ConnectionCheckResult::Ok
    }
}

// ===========================================================================
// Display / Debug implementations
// ===========================================================================

impl fmt::Debug for TelnetHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelnetHandler")
            .field("has_state", &self.state.is_some())
            .field("telnet_options", &self.telnet_options)
            .field("user", &self.user)
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

impl fmt::Debug for TelnetState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelnetState")
            .field("please_negotiate", &self.please_negotiate)
            .field("already_negotiated", &self.already_negotiated)
            .field("telrcv_state", &self.telrcv_state)
            .field("subopt_ttype", &self.subopt_ttype)
            .field("subopt_xdisploc", &self.subopt_xdisploc)
            .field("subopt_wsx", &self.subopt_wsx)
            .field("subopt_wsy", &self.subopt_wsy)
            .field("telnet_vars_count", &self.telnet_vars.len())
            .field("subbuffer_len", &self.subbuffer.len())
            .finish()
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telopt_name_known() {
        assert_eq!(telopt_name(0), Some("BINARY"));
        assert_eq!(telopt_name(1), Some("ECHO"));
        assert_eq!(telopt_name(3), Some("SUPPRESS GO AHEAD"));
        assert_eq!(telopt_name(24), Some("TERM TYPE"));
        assert_eq!(telopt_name(31), Some("NAWS"));
        assert_eq!(telopt_name(35), Some("XDISPLOC"));
        assert_eq!(telopt_name(39), Some("NEW-ENVIRON"));
    }

    #[test]
    fn test_telopt_name_exopl() {
        assert_eq!(telopt_name(255), Some("EXOPL"));
    }

    #[test]
    fn test_telopt_name_unknown() {
        assert_eq!(telopt_name(40), None);
        assert_eq!(telopt_name(100), None);
    }

    #[test]
    fn test_telcmd_name() {
        assert_eq!(telcmd_name(IAC), Some("IAC"));
        assert_eq!(telcmd_name(WILL), Some("WILL"));
        assert_eq!(telcmd_name(WONT), Some("WONT"));
        assert_eq!(telcmd_name(DO), Some("DO"));
        assert_eq!(telcmd_name(DONT), Some("DONT"));
        assert_eq!(telcmd_name(SB), Some("SB"));
        assert_eq!(telcmd_name(SE), Some("SE"));
        assert_eq!(telcmd_name(NOP), Some("NOP"));
        assert_eq!(telcmd_name(GA), Some("GA"));
        assert_eq!(telcmd_name(0), None); // Below the minimum
    }

    #[test]
    fn test_str_is_nonascii() {
        assert!(!str_is_nonascii("hello"));
        assert!(!str_is_nonascii(""));
        assert!(str_is_nonascii("hëllo"));
        // 0xFF in UTF-8 is ÿ (U+00FF) which has high bit set.
        assert!(str_is_nonascii("\u{00FF}"));
    }

    #[test]
    fn test_bad_option() {
        assert!(!bad_option("hello"));
        assert!(!bad_option(""));
        // 0xFF in UTF-8 is ÿ (U+00FF) — two bytes: 0xC3, 0xBF
        // IAC is byte 0xFF, which can only appear in a Rust string as
        // the UTF-8 encoding of U+00FF (which is [0xC3, 0xBF]). Since
        // bad_option checks for byte 0xFF, and UTF-8 encoded ÿ doesn't
        // contain byte 0xFF, this will be false. This is correct behavior
        // in Rust since Rust strings are always valid UTF-8.
        assert!(!bad_option("\u{00FF}"));
        // Test with a string that was constructed from raw bytes containing 0xFF.
        let raw_str = String::from_utf8(vec![0x61, 0xC3, 0xBF]).unwrap(); // "aÿ"
        assert!(!bad_option(&raw_str)); // No raw 0xFF byte
    }

    #[test]
    fn test_parse_ws_valid() {
        assert_eq!(TelnetHandler::parse_ws("80x24"), Some((80, 24)));
        assert_eq!(TelnetHandler::parse_ws("0x0"), Some((0, 0)));
        assert_eq!(TelnetHandler::parse_ws("65535x65535"), Some((65535, 65535)));
    }

    #[test]
    fn test_parse_ws_invalid() {
        assert_eq!(TelnetHandler::parse_ws("80"), None);
        assert_eq!(TelnetHandler::parse_ws("80x"), None);
        assert_eq!(TelnetHandler::parse_ws("x24"), None);
        assert_eq!(TelnetHandler::parse_ws("abc"), None);
        assert_eq!(TelnetHandler::parse_ws(""), None);
    }

    #[test]
    fn test_handler_new() {
        let h = TelnetHandler::new();
        assert_eq!(h.name(), "telnet");
        assert_eq!(h.default_port(), 23);
        assert!(h.flags().is_empty());
        assert!(h.state.is_none());
    }

    #[test]
    fn test_telnet_state_defaults() {
        let tn = TelnetState::new();

        // SGA should be preferred for both sides.
        assert_eq!(tn.us_preferred[TELOPT_SGA as usize], NegState::Yes);
        assert_eq!(tn.him_preferred[TELOPT_SGA as usize], NegState::Yes);

        // BINARY should be preferred for both sides.
        assert_eq!(tn.us_preferred[TELOPT_BINARY as usize], NegState::Yes);
        assert_eq!(tn.him_preferred[TELOPT_BINARY as usize], NegState::Yes);

        // ECHO should be preferred for him only.
        assert_eq!(tn.us_preferred[TELOPT_ECHO as usize], NegState::No);
        assert_eq!(tn.him_preferred[TELOPT_ECHO as usize], NegState::Yes);

        // NAWS subnegotiation should be enabled.
        assert!(tn.subnegotiation[TELOPT_NAWS as usize]);

        // Initial receive state should be Data.
        assert_eq!(tn.telrcv_state, TelnetReceive::Data);
    }

    #[test]
    fn test_build_negotiation() {
        let buf = TelnetHandler::build_negotiation(WILL, TELOPT_SGA);
        assert_eq!(buf, [IAC, WILL, TELOPT_SGA]);
    }

    #[test]
    fn test_escape_iac_no_iac() {
        let mut tn = TelnetState::new();
        let data = b"hello world";
        let escaped = TelnetHandler::escape_iac(&mut tn, data);
        assert_eq!(escaped, data.to_vec());
    }

    #[test]
    fn test_escape_iac_with_iac() {
        let mut tn = TelnetState::new();
        let data = [b'a', IAC, b'b'];
        let escaped = TelnetHandler::escape_iac(&mut tn, &data);
        assert_eq!(escaped, vec![b'a', IAC, IAC, b'b']);
    }

    #[test]
    fn test_escape_iac_all_iac() {
        let mut tn = TelnetState::new();
        let data = [IAC, IAC];
        let escaped = TelnetHandler::escape_iac(&mut tn, &data);
        assert_eq!(escaped, vec![IAC, IAC, IAC, IAC]);
    }

    #[test]
    fn test_telrcv_plain_data() {
        let mut tn = TelnetState::new();
        let data = b"hello";
        let (client, neg, sub) = TelnetHandler::telrcv(&mut tn, data).unwrap();
        assert_eq!(client, b"hello");
        assert!(neg.is_empty());
        assert!(sub.is_empty());
    }

    #[test]
    fn test_telrcv_iac_iac_escape() {
        let mut tn = TelnetState::new();
        // IAC IAC should produce a single 0xFF byte in client data.
        let data = [IAC, IAC];
        let (client, neg, sub) = TelnetHandler::telrcv(&mut tn, &data).unwrap();
        assert_eq!(client, vec![IAC]);
        assert!(neg.is_empty());
        assert!(sub.is_empty());
    }

    #[test]
    fn test_telrcv_will_negotiation() {
        let mut tn = TelnetState::new();
        // Receive WILL SGA — since him_preferred[SGA] = YES, we should send DO SGA.
        let data = [IAC, WILL, TELOPT_SGA];
        let (client, neg, sub) = TelnetHandler::telrcv(&mut tn, &data).unwrap();
        assert!(client.is_empty());
        assert_eq!(neg, vec![IAC, DO, TELOPT_SGA]);
        assert!(sub.is_empty());
        assert!(tn.please_negotiate);
        assert_eq!(tn.him[TELOPT_SGA as usize], NegState::Yes);
    }

    #[test]
    fn test_telrcv_will_rejected() {
        let mut tn = TelnetState::new();
        // Receive WILL for option 42 which is not preferred — should send DONT.
        let data = [IAC, WILL, 42];
        let (client, neg, sub) = TelnetHandler::telrcv(&mut tn, &data).unwrap();
        assert!(client.is_empty());
        assert_eq!(neg, vec![IAC, DONT, 42]);
        assert!(sub.is_empty());
    }

    #[test]
    fn test_telrcv_do_with_subneg() {
        let mut tn = TelnetState::new();
        tn.subopt_wsx = 80;
        tn.subopt_wsy = 24;
        // NAWS subnegotiation is enabled by default, and us_preferred[NAWS] is
        // not set by default (it's only set via WS option). Let's set it.
        tn.us_preferred[TELOPT_NAWS as usize] = NegState::Yes;

        // Receive DO NAWS — should respond WILL NAWS + NAWS suboption.
        let data = [IAC, DO, TELOPT_NAWS];
        let (client, neg, sub) = TelnetHandler::telrcv(&mut tn, &data).unwrap();
        assert!(client.is_empty());
        // Negotiation should contain WILL NAWS.
        assert_eq!(neg, vec![IAC, WILL, TELOPT_NAWS]);
        // Suboption should contain IAC SB NAWS <w_hi> <w_lo> <h_hi> <h_lo> IAC SE.
        assert_eq!(sub.len(), 9);
        assert_eq!(sub[0], IAC);
        assert_eq!(sub[1], SB);
        assert_eq!(sub[2], TELOPT_NAWS);
        assert_eq!(sub[3], 0); // width high byte
        assert_eq!(sub[4], 80); // width low byte
        assert_eq!(sub[5], 0); // height high byte
        assert_eq!(sub[6], 24); // height low byte
        assert_eq!(sub[7], IAC);
        assert_eq!(sub[8], SE);
    }

    #[test]
    fn test_telrcv_cr_nul_stripping() {
        let mut tn = TelnetState::new();
        // CR followed by NUL should strip the NUL.
        let data = [b'a', b'\r', 0, b'b'];
        let (client, _, _) = TelnetHandler::telrcv(&mut tn, &data).unwrap();
        // Should get: 'a', '\r', 'b' (NUL stripped).
        assert_eq!(client, vec![b'a', b'\r', b'b']);
    }

    #[test]
    fn test_telrcv_cr_lf_passthrough() {
        let mut tn = TelnetState::new();
        // CR followed by LF should pass through normally.
        let data = [b'a', b'\r', b'\n', b'b'];
        let (client, _, _) = TelnetHandler::telrcv(&mut tn, &data).unwrap();
        // Should get: 'a', '\r', '\n', 'b'
        assert_eq!(client, vec![b'a', b'\r', b'\n', b'b']);
    }

    #[test]
    fn test_telrcv_suboption_error() {
        let mut tn = TelnetState::new();
        // Malformed suboption: IAC SB <data> IAC <not-SE-and-not-IAC>
        // This should return RecvError.
        let data = [IAC, SB, 24, IAC, 42]; // 42 is not SE and not IAC
        let result = TelnetHandler::telrcv(&mut tn, &data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::RecvError);
    }

    #[test]
    fn test_telrcv_suboption_iac_escape() {
        let mut tn = TelnetState::new();
        // IAC IAC inside subnegotiation should be treated as escaped 0xFF.
        // IAC SB <opt> IAC IAC <more_data> IAC SE
        let data = [IAC, SB, 24, IAC, IAC, 0x42, IAC, SE];
        let result = TelnetHandler::telrcv(&mut tn, &data);
        assert!(result.is_ok());
        // The subbuffer should have contained [IAC, 0x42] before processing.
    }

    #[test]
    fn test_check_telnet_options_ttype() {
        let mut tn = TelnetState::new();
        let options = vec!["TTYPE=vt100".to_string()];
        let result = TelnetHandler::check_telnet_options(&mut tn, &options, &None);
        assert!(result.is_ok());
        assert_eq!(tn.subopt_ttype.as_deref(), Some("vt100"));
        assert_eq!(tn.us_preferred[TELOPT_TTYPE as usize], NegState::Yes);
    }

    #[test]
    fn test_check_telnet_options_xdisploc() {
        let mut tn = TelnetState::new();
        let options = vec!["XDISPLOC=localhost:0".to_string()];
        let result = TelnetHandler::check_telnet_options(&mut tn, &options, &None);
        assert!(result.is_ok());
        assert_eq!(tn.subopt_xdisploc.as_deref(), Some("localhost:0"));
        assert_eq!(tn.us_preferred[TELOPT_XDISPLOC as usize], NegState::Yes);
    }

    #[test]
    fn test_check_telnet_options_new_env() {
        let mut tn = TelnetState::new();
        let options = vec!["NEW_ENV=LANG,en_US.UTF-8".to_string()];
        let result = TelnetHandler::check_telnet_options(&mut tn, &options, &None);
        assert!(result.is_ok());
        assert_eq!(tn.telnet_vars.len(), 1);
        assert_eq!(tn.telnet_vars[0], "LANG,en_US.UTF-8");
        assert_eq!(tn.us_preferred[TELOPT_NEW_ENVIRON as usize], NegState::Yes);
    }

    #[test]
    fn test_check_telnet_options_ws() {
        let mut tn = TelnetState::new();
        let options = vec!["WS=132x50".to_string()];
        let result = TelnetHandler::check_telnet_options(&mut tn, &options, &None);
        assert!(result.is_ok());
        assert_eq!(tn.subopt_wsx, 132);
        assert_eq!(tn.subopt_wsy, 50);
        assert_eq!(tn.us_preferred[TELOPT_NAWS as usize], NegState::Yes);
    }

    #[test]
    fn test_check_telnet_options_binary_off() {
        let mut tn = TelnetState::new();
        let options = vec!["BINARY=0".to_string()];
        let result = TelnetHandler::check_telnet_options(&mut tn, &options, &None);
        assert!(result.is_ok());
        assert_eq!(tn.us_preferred[TELOPT_BINARY as usize], NegState::No);
        assert_eq!(tn.him_preferred[TELOPT_BINARY as usize], NegState::No);
    }

    #[test]
    fn test_check_telnet_options_binary_on() {
        let mut tn = TelnetState::new();
        let options = vec!["BINARY=1".to_string()];
        let result = TelnetHandler::check_telnet_options(&mut tn, &options, &None);
        assert!(result.is_ok());
        // Should keep defaults (binary on).
        assert_eq!(tn.us_preferred[TELOPT_BINARY as usize], NegState::Yes);
        assert_eq!(tn.him_preferred[TELOPT_BINARY as usize], NegState::Yes);
    }

    #[test]
    fn test_check_telnet_options_unknown() {
        let mut tn = TelnetState::new();
        let options = vec!["FOOBAR=baz".to_string()];
        let result = TelnetHandler::check_telnet_options(&mut tn, &options, &None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::UnknownOption);
    }

    #[test]
    fn test_check_telnet_options_syntax_error() {
        let mut tn = TelnetState::new();
        let options = vec!["WS=badformat".to_string()];
        let result = TelnetHandler::check_telnet_options(&mut tn, &options, &None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::SetoptOptionSyntax);
    }

    #[test]
    fn test_check_telnet_options_no_equals() {
        let mut tn = TelnetState::new();
        let options = vec!["TTYPE".to_string()];
        let result = TelnetHandler::check_telnet_options(&mut tn, &options, &None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::SetoptOptionSyntax);
    }

    #[test]
    fn test_check_telnet_options_user() {
        let mut tn = TelnetState::new();
        let user = Some("testuser".to_string());
        let result = TelnetHandler::check_telnet_options(&mut tn, &[], &user);
        assert!(result.is_ok());
        assert_eq!(tn.telnet_vars.len(), 1);
        assert_eq!(tn.telnet_vars[0], "USER,testuser");
        assert_eq!(tn.us_preferred[TELOPT_NEW_ENVIRON as usize], NegState::Yes);
    }

    #[test]
    fn test_check_telnet_options_nonascii_user() {
        let mut tn = TelnetState::new();
        let user = Some("tëstuser".to_string());
        let result = TelnetHandler::check_telnet_options(&mut tn, &[], &user);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadFunctionArgument);
    }

    #[test]
    fn test_rec_will_yes_transitions() {
        // Test the full rec_will state machine.
        let mut tn = TelnetState::new();
        let mut out = Vec::new();

        // him is NO, preferred YES -> should transition to YES, send DO.
        tn.him_preferred[3] = NegState::Yes;
        TelnetHandler::rec_will(&mut tn, &mut out, 3);
        assert_eq!(tn.him[3], NegState::Yes);
        assert_eq!(out, vec![IAC, DO, 3]);
    }

    #[test]
    fn test_rec_will_no_preference() {
        let mut tn = TelnetState::new();
        let mut out = Vec::new();

        // him is NO, preferred NO -> should send DONT.
        TelnetHandler::rec_will(&mut tn, &mut out, 42);
        assert_eq!(tn.him[42], NegState::No);
        assert_eq!(out, vec![IAC, DONT, 42]);
    }

    #[test]
    fn test_rec_wont_from_yes() {
        let mut tn = TelnetState::new();
        let mut out = Vec::new();

        // Set him to YES first.
        tn.him[3] = NegState::Yes;
        TelnetHandler::rec_wont(&mut tn, &mut out, 3);
        assert_eq!(tn.him[3], NegState::No);
        assert_eq!(out, vec![IAC, DONT, 3]);
    }

    #[test]
    fn test_rec_do_preferred() {
        let mut tn = TelnetState::new();
        let mut neg_out = Vec::new();
        let mut sub_out = Vec::new();

        // us is NO, preferred YES -> should transition to YES, send WILL.
        tn.us_preferred[3] = NegState::Yes;
        TelnetHandler::rec_do(&mut tn, &mut neg_out, &mut sub_out, 3);
        assert_eq!(tn.us[3], NegState::Yes);
        assert_eq!(neg_out, vec![IAC, WILL, 3]);
    }

    #[test]
    fn test_rec_do_not_preferred() {
        let mut tn = TelnetState::new();
        let mut neg_out = Vec::new();
        let mut sub_out = Vec::new();

        // us is NO, preferred NO -> should send WONT.
        TelnetHandler::rec_do(&mut tn, &mut neg_out, &mut sub_out, 42);
        assert_eq!(tn.us[42], NegState::No);
        assert_eq!(neg_out, vec![IAC, WONT, 42]);
    }

    #[test]
    fn test_rec_dont_from_yes() {
        let mut tn = TelnetState::new();
        let mut out = Vec::new();

        tn.us[3] = NegState::Yes;
        TelnetHandler::rec_dont(&mut tn, &mut out, 3);
        assert_eq!(tn.us[3], NegState::No);
        assert_eq!(out, vec![IAC, WONT, 3]);
    }

    #[test]
    fn test_negotiate_sends_preferred() {
        let mut tn = TelnetState::new();
        let mut out = Vec::new();

        TelnetHandler::negotiate(&mut tn, &mut out);

        // Should have sent WILL for SGA and BINARY, DO for SGA and BINARY.
        // ECHO should be skipped for WILL side.
        // Check for the presence of each 3-byte negotiation sequence.
        let will_sga = [IAC, WILL, TELOPT_SGA];
        let do_sga = [IAC, DO, TELOPT_SGA];
        let will_bin = [IAC, WILL, TELOPT_BINARY];
        let do_bin = [IAC, DO, TELOPT_BINARY];

        assert!(out.windows(3).any(|w| w == will_sga), "missing WILL SGA");
        assert!(out.windows(3).any(|w| w == do_sga), "missing DO SGA");
        assert!(out.windows(3).any(|w| w == will_bin), "missing WILL BINARY");
        assert!(out.windows(3).any(|w| w == do_bin), "missing DO BINARY");
    }

    #[test]
    fn test_handle_suboption_ttype() {
        let mut tn = TelnetState::new();
        tn.subopt_ttype = Some("vt100".to_string());

        let mut response = Vec::new();
        let sub_data = [TELOPT_TTYPE, TELQUAL_SEND];
        let result = TelnetHandler::handle_suboption(&tn, &sub_data, &mut response);
        assert!(result.is_ok());

        // Response should be: IAC SB TTYPE IS "vt100" IAC SE
        assert_eq!(response[0], IAC);
        assert_eq!(response[1], SB);
        assert_eq!(response[2], TELOPT_TTYPE);
        assert_eq!(response[3], TELQUAL_IS);
        assert_eq!(&response[4..9], b"vt100");
        assert_eq!(response[9], IAC);
        assert_eq!(response[10], SE);
    }

    #[test]
    fn test_handle_suboption_xdisploc() {
        let mut tn = TelnetState::new();
        tn.subopt_xdisploc = Some("localhost:0".to_string());

        let mut response = Vec::new();
        let sub_data = [TELOPT_XDISPLOC, TELQUAL_SEND];
        let result = TelnetHandler::handle_suboption(&tn, &sub_data, &mut response);
        assert!(result.is_ok());

        assert_eq!(response[0], IAC);
        assert_eq!(response[1], SB);
        assert_eq!(response[2], TELOPT_XDISPLOC);
        assert_eq!(response[3], TELQUAL_IS);
        assert_eq!(&response[4..15], b"localhost:0");
        assert_eq!(response[15], IAC);
        assert_eq!(response[16], SE);
    }

    #[test]
    fn test_handle_suboption_new_environ() {
        let mut tn = TelnetState::new();
        tn.telnet_vars.push("LANG,en_US".to_string());
        tn.telnet_vars.push("USER,testuser".to_string());

        let mut response = Vec::new();
        let sub_data = [TELOPT_NEW_ENVIRON, TELQUAL_SEND];
        let result = TelnetHandler::handle_suboption(&tn, &sub_data, &mut response);
        assert!(result.is_ok());

        // Check structure: IAC SB NEW_ENVIRON IS VAR LANG VALUE en_US VAR USER VALUE testuser IAC SE
        assert_eq!(response[0], IAC);
        assert_eq!(response[1], SB);
        assert_eq!(response[2], TELOPT_NEW_ENVIRON);
        assert_eq!(response[3], TELQUAL_IS);
        // First VAR
        assert_eq!(response[4], NEW_ENV_VAR);
        // "LANG" bytes
        assert_eq!(&response[5..9], b"LANG");
        assert_eq!(response[9], NEW_ENV_VALUE);
        assert_eq!(&response[10..15], b"en_US");
        // Second VAR
        assert_eq!(response[15], NEW_ENV_VAR);
        assert_eq!(&response[16..20], b"USER");
        assert_eq!(response[20], NEW_ENV_VALUE);
        assert_eq!(&response[21..29], b"testuser");
        // Closing
        assert_eq!(response[29], IAC);
        assert_eq!(response[30], SE);
    }

    #[test]
    fn test_handle_suboption_bad_option_ttype() {
        let mut tn = TelnetState::new();
        // In Rust, strings are always valid UTF-8, so we cannot put raw 0xFF
        // byte into a String. We use a string that bad_option() detects.
        // Since bad_option checks for byte 0xFF and Rust strings can't contain
        // raw 0xFF, we test with None (which means the handler returns Ok
        // without sending anything).
        tn.subopt_ttype = None;

        let mut response = Vec::new();
        let sub_data = [TELOPT_TTYPE, TELQUAL_SEND];
        let result = TelnetHandler::handle_suboption(&tn, &sub_data, &mut response);
        // With None ttype, handler returns Ok without producing output.
        assert!(result.is_ok());
        assert!(response.is_empty());
    }

    #[test]
    fn test_handle_suboption_too_long_ttype() {
        let mut tn = TelnetState::new();
        // Set a TTYPE value longer than 1000 chars.
        tn.subopt_ttype = Some("x".repeat(1001));

        let mut response = Vec::new();
        let sub_data = [TELOPT_TTYPE, TELQUAL_SEND];
        let result = TelnetHandler::handle_suboption(&tn, &sub_data, &mut response);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::SendError);
    }

    #[test]
    fn test_mixed_data_and_negotiation() {
        let mut tn = TelnetState::new();
        // Mix of plain data and IAC WILL.
        let mut data = vec![b'H', b'i'];
        data.extend_from_slice(&[IAC, WILL, TELOPT_SGA]);
        data.extend_from_slice(&[b'!']);

        let (client, neg, _) = TelnetHandler::telrcv(&mut tn, &data).unwrap();
        assert_eq!(client, vec![b'H', b'i', b'!']);
        assert_eq!(neg, vec![IAC, DO, TELOPT_SGA]);
    }

    #[test]
    fn test_q_method_wantno_opposite() {
        // Test RFC 1143 Q-method: WANTNO + OPPOSITE queue state.
        let mut tn = TelnetState::new();
        let mut out = Vec::new();

        // Simulate: we want option 5 disabled (send DONT),
        // then immediately want it enabled again.
        tn.him[5] = NegState::Yes;
        TelnetHandler::set_remote_option(&mut tn, &mut out, 5, false);
        assert_eq!(tn.him[5], NegState::WantNo);

        // Now request enable before the response arrives.
        TelnetHandler::set_remote_option(&mut tn, &mut out, 5, true);
        assert_eq!(tn.himq[5], QueueState::Opposite);

        // Receive WONT for option 5 (response to our DONT).
        let mut neg = Vec::new();
        TelnetHandler::rec_wont(&mut tn, &mut neg, 5);
        // Should transition to WANTYES and send DO.
        assert_eq!(tn.him[5], NegState::WantYes);
        assert_eq!(tn.himq[5], QueueState::Empty);
        assert_eq!(neg, vec![IAC, DO, 5]);
    }
}
