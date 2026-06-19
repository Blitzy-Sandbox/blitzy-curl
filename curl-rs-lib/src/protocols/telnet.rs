//! TELNET (RFC 854) protocol engine — the Rust analog of `lib/telnet.c`
//! (≈1.6 k lines) plus the `lib/arpa_telnet.h` command/option constants.
//!
//! TELNET is an interactive, bidirectional byte-stream protocol. Its entire
//! "structure" is the **IAC (Interpret As Command, byte 255) framing** layered
//! over an otherwise transparent 8-bit stream:
//!
//! * In-band commands are introduced by `IAC`. A literal `0xFF` data byte is
//!   therefore transmitted as `IAC IAC` (doubled) and de-escaped back to a
//!   single `0xFF` on receipt.
//! * Capability negotiation uses the four option commands `WILL` / `WONT`
//!   (sender's local state) and `DO` / `DONT` (request about the peer), each
//!   followed by an option code. Negotiation runs the RFC 1143 "Q-method"
//!   state machine to avoid negotiation loops.
//! * Richer option data uses sub-negotiation framed as `IAC SB <opt> … IAC SE`
//!   (terminal type, X display location, environment variables, window size).
//!
//! # Design
//!
//! [`TelnetState`] is a self-contained, fully unit-tested engine that owns all
//! of `telnet.c`'s substance: the RFC 1143 negotiation tables, IAC escaping,
//! sub-option request/response handling, and `--telnet-option` parsing. It is
//! deliberately free of any I/O so it can be exercised in isolation:
//!
//! * Inbound bytes are fed to [`TelnetState::telrcv`], which runs the receiver
//!   FSM, delivers decoded application bytes through a caller-supplied sink, and
//!   queues any protocol responses (negotiation / sub-option replies) into an
//!   internal `out` buffer.
//! * That `out` buffer is then drained to the wire by the [`Protocol::do_it`]
//!   driver, which also bridges the interactive stream: local input → server
//!   and server → local output, exactly as curl's `telnet_do` does.
//!
//! # C oracle (read-only references)
//!
//! * `lib/telnet.c`   — negotiation policy, `telrcv`, `suboption`,
//!   `check_telnet_options`, `telnet_do`.
//! * `lib/arpa_telnet.h` — the IAC command bytes and option codes, ported
//!   verbatim into the [`tel`] module below.
//!
//! # Safety
//!
//! This module contains **zero `unsafe`**. The crate root declares
//! `#![forbid(unsafe_code)]`; that guarantee is inherited here and is
//! intentionally **not** re-declared.

use crate::conn::{BoxFuture, Connection, Curl_conn_recv, Curl_conn_send, FIRSTSOCKET};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{Protocol, ProtocolTransfer, Scheme, TransferDirection, SCHEME_TELNET};
use crate::util::sendf;

/// TELNET command bytes, option codes and sub-option qualifiers, ported
/// verbatim from `lib/arpa_telnet.h`.
///
/// The complete arpa_telnet.h set is defined here for fidelity to the C header
/// (and so tests can reference the symbolic names); the engine does not branch
/// on every command byte (`DM`/`NOP`/`GA`/… are accepted and ignored exactly as
/// curl does), so the module opts out of dead-code warnings as a group.
mod tel {
    #![allow(dead_code)]

    // --- Command bytes (telnet.c `telnetcmds[]`, values 236..=255) -----------
    /// End Of File.
    pub const CURL_XEOF: u8 = 236;
    /// Suspend process.
    pub const CURL_SUSP: u8 = 237;
    /// Abort process.
    pub const CURL_ABORT: u8 = 238;
    /// End Of Record.
    pub const CURL_EOR: u8 = 239;
    /// Sub-negotiation End.
    pub const CURL_SE: u8 = 240;
    /// No OPeration.
    pub const CURL_NOP: u8 = 241;
    /// Data Mark.
    pub const CURL_DM: u8 = 242;
    /// Break.
    pub const CURL_BREAK: u8 = 243;
    /// Interrupt Process.
    pub const CURL_IP: u8 = 244;
    /// Abort Output.
    pub const CURL_AO: u8 = 245;
    /// Are You There.
    pub const CURL_AYT: u8 = 246;
    /// Erase Character.
    pub const CURL_EC: u8 = 247;
    /// Erase Line.
    pub const CURL_EL: u8 = 248;
    /// Go Ahead.
    pub const CURL_GA: u8 = 249;
    /// SuBnegotiation begins.
    pub const CURL_SB: u8 = 250;
    /// Our side WILL use the option.
    pub const CURL_WILL: u8 = 251;
    /// Our side WON'T use the option.
    pub const CURL_WONT: u8 = 252;
    /// Please DO use the option.
    pub const CURL_DO: u8 = 253;
    /// Please DON'T use the option.
    pub const CURL_DONT: u8 = 254;
    /// Interpret As Command (the escape / framing byte).
    pub const CURL_IAC: u8 = 255;

    /// First valid command byte (`CURL_XEOF`).
    pub const CURL_TELCMD_MINIMUM: u8 = CURL_XEOF;
    /// Last valid command byte (`CURL_IAC`).
    pub const CURL_TELCMD_MAXIMUM: u8 = CURL_IAC;

    // --- Option codes (telnet.c `telnetoptions[]`) ---------------------------
    /// Binary 8-bit data transmission (RFC 856).
    pub const CURL_TELOPT_BINARY: u8 = 0;
    /// Echo (RFC 857).
    pub const CURL_TELOPT_ECHO: u8 = 1;
    /// Suppress Go Ahead (RFC 858).
    pub const CURL_TELOPT_SGA: u8 = 3;
    /// Terminal TYPE (RFC 1091).
    pub const CURL_TELOPT_TTYPE: u8 = 24;
    /// Negotiate About Window Size (RFC 1073).
    pub const CURL_TELOPT_NAWS: u8 = 31;
    /// X DISPlay LOCation (RFC 1096).
    pub const CURL_TELOPT_XDISPLOC: u8 = 35;
    /// NEW ENVIRONment variables (RFC 1572).
    pub const CURL_TELOPT_NEW_ENVIRON: u8 = 39;
    /// Extended Options List.
    pub const CURL_TELOPT_EXOPL: u8 = 255;

    /// Highest option code curl tracks by preference (`NEW_ENVIRON`).
    pub const CURL_TELOPT_MAXIMUM: u8 = CURL_TELOPT_NEW_ENVIRON;
    /// Number of option slots curl iterates during negotiation (0..=39 → 40).
    pub const CURL_NTELOPTS: usize = 40;

    // --- Sub-negotiation qualifiers (RFC 1091 / 1096 / 1572) -----------------
    /// `IS` — the value follows.
    pub const CURL_TELQUAL_IS: u8 = 0;
    /// `SEND` — please send your value.
    pub const CURL_TELQUAL_SEND: u8 = 1;
    /// `INFO` — informational value (NEW-ENVIRON).
    pub const CURL_TELQUAL_INFO: u8 = 2;
    /// `NAME` — variable name (NEW-ENVIRON).
    pub const CURL_TELQUAL_NAME: u8 = 3;

    /// NEW-ENVIRON: introduces a variable name.
    pub const CURL_NEW_ENV_VAR: u8 = 0;
    /// NEW-ENVIRON: introduces a variable value.
    pub const CURL_NEW_ENV_VALUE: u8 = 1;

    /// Maximum sub-negotiation buffer size curl accumulates (telnet.c).
    pub const SUBBUFSIZE: usize = 512;
}

use tel::*;

/// RFC 1143 "Q-method" per-option negotiation state.
///
/// Mirrors telnet.c's `CURL_NO` / `CURL_YES` / `CURL_WANTYES` / `CURL_WANTNO`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NegState {
    /// Option is off and not being negotiated.
    No,
    /// Option is on.
    Yes,
    /// We requested "on" and are awaiting confirmation.
    WantYes,
    /// We requested "off" and are awaiting confirmation.
    WantNo,
}

/// RFC 1143 pending-opposite queue bit (telnet.c `CURL_EMPTY` / `CURL_OPPOSITE`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NegQueue {
    /// No queued opposite request.
    Empty,
    /// An opposite request is queued.
    Opposite,
}

/// Receiver FSM state (telnet.c `CURL_TS_*`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TelnetReceive {
    /// Ordinary data.
    Data,
    /// Saw `IAC`.
    Iac,
    /// Saw `IAC WILL`, awaiting the option byte.
    Will,
    /// Saw `IAC WONT`, awaiting the option byte.
    Wont,
    /// Saw `IAC DO`, awaiting the option byte.
    Do,
    /// Saw `IAC DONT`, awaiting the option byte.
    Dont,
    /// Saw a bare `CR`, awaiting the byte that follows (to drop a trailing NUL).
    Cr,
    /// Inside a sub-negotiation, accumulating bytes.
    Sb,
    /// Inside a sub-negotiation and saw `IAC`, awaiting `SE` (or escaped `IAC`).
    Se,
}

/// The complete, I/O-free TELNET engine.
///
/// One instance lives for the duration of a single TELNET transfer. It owns the
/// RFC 1143 negotiation tables, the preferred-option policy, sub-option state,
/// the receiver FSM cursor, and an `out` buffer into which all protocol
/// responses are queued for the [`Protocol::do_it`] driver to flush.
///
/// The negotiation tables are sized `256` so that *any* option byte received
/// from the peer indexes safely; curl only actively offers the first
/// [`CURL_NTELOPTS`] (40) options.
struct TelnetState {
    /// Set by `telrcv` when the peer sends any negotiation command, signalling
    /// that we should kick off our own preferred-option negotiation once.
    please_negotiate: bool,
    /// Guards the one-shot initial negotiation (telnet.c `already_negotiated`).
    already_negotiated: bool,

    /// Negotiation state for *our* side of each option (`WILL`/`WONT`).
    us: [NegState; 256],
    /// Pending-opposite queue for our side.
    usq: [NegQueue; 256],
    /// Options we prefer to enable on our side.
    us_preferred: [bool; 256],

    /// Negotiation state for the *peer's* side of each option (`DO`/`DONT`).
    him: [NegState; 256],
    /// Pending-opposite queue for the peer's side.
    himq: [NegQueue; 256],
    /// Options we prefer the peer to enable.
    him_preferred: [bool; 256],

    /// Options for which we must emit a sub-negotiation once enabled (NAWS).
    subnegotiation: [bool; 256],

    /// `--telnet-option TTYPE=…` value (terminal type), if configured.
    subopt_ttype: Option<String>,
    /// `--telnet-option XDISPLOC=…` value (X display location), if configured.
    subopt_xdisploc: Option<String>,
    /// NAWS window width (columns).
    subopt_wsx: u16,
    /// NAWS window height (rows).
    subopt_wsy: u16,

    /// NEW-ENVIRON variables, each stored as `"NAME,VALUE"` or just `"NAME"`.
    telnet_vars: Vec<String>,

    /// Receiver FSM cursor.
    telrcv_state: TelnetReceive,
    /// Accumulator for the bytes of an in-progress sub-negotiation
    /// (capped at [`SUBBUFSIZE`], matching telnet.c).
    subbuffer: Vec<u8>,

    /// Outbound protocol bytes (negotiation + sub-option replies), queued by the
    /// engine and drained to the socket by the driver. These are written
    /// **raw** — command framing is never IAC-escaped; only the NAWS window
    /// payload escapes embedded `IAC` bytes (see [`TelnetState::sendsuboption`]).
    out: Vec<u8>,
}

impl TelnetState {
    /// Build a fresh engine with curl's default option preferences
    /// (telnet.c `init_telnet`):
    ///
    /// * `SGA`    — preferred on both sides (suppress go-ahead).
    /// * `BINARY` — preferred on both sides (8-bit clean).
    /// * `ECHO`   — preferred from the peer (server echoes).
    /// * `NAWS`   — flagged for sub-negotiation once our side is enabled.
    fn new() -> Self {
        let mut s = TelnetState {
            please_negotiate: false,
            already_negotiated: false,
            us: [NegState::No; 256],
            usq: [NegQueue::Empty; 256],
            us_preferred: [false; 256],
            him: [NegState::No; 256],
            himq: [NegQueue::Empty; 256],
            him_preferred: [false; 256],
            subnegotiation: [false; 256],
            subopt_ttype: None,
            subopt_xdisploc: None,
            subopt_wsx: 0,
            subopt_wsy: 0,
            telnet_vars: Vec::new(),
            telrcv_state: TelnetReceive::Data,
            subbuffer: Vec::new(),
            out: Vec::new(),
        };

        s.us_preferred[CURL_TELOPT_SGA as usize] = true;
        s.him_preferred[CURL_TELOPT_SGA as usize] = true;

        s.us_preferred[CURL_TELOPT_BINARY as usize] = true;
        s.him_preferred[CURL_TELOPT_BINARY as usize] = true;

        s.him_preferred[CURL_TELOPT_ECHO as usize] = true;

        s.subnegotiation[CURL_TELOPT_NAWS as usize] = true;

        s
    }

    /// Queue a 3-byte `IAC <cmd> <option>` negotiation command (telnet.c
    /// `send_negotiation`). Command framing is written **raw / unescaped**.
    fn send_negotiation(&mut self, cmd: u8, option: u8) {
        self.out.push(CURL_IAC);
        self.out.push(cmd);
        self.out.push(option);
    }

    /// Drive *our* side of `option` toward `enable`d, emitting `WILL`/`WONT`
    /// as the RFC 1143 Q-method dictates (telnet.c `set_local_option`).
    fn set_local_option(&mut self, option: u8, enable: bool) {
        let o = option as usize;
        if enable {
            match self.us[o] {
                NegState::No => {
                    self.us[o] = NegState::WantYes;
                    self.send_negotiation(CURL_WILL, option);
                }
                NegState::Yes => {}
                NegState::WantNo => match self.usq[o] {
                    NegQueue::Empty => self.usq[o] = NegQueue::Opposite,
                    NegQueue::Opposite => {}
                },
                NegState::WantYes => match self.usq[o] {
                    NegQueue::Empty => {}
                    NegQueue::Opposite => self.usq[o] = NegQueue::Empty,
                },
            }
        } else {
            match self.us[o] {
                NegState::No => {}
                NegState::Yes => {
                    self.us[o] = NegState::WantNo;
                    self.send_negotiation(CURL_WONT, option);
                }
                NegState::WantNo => match self.usq[o] {
                    NegQueue::Empty => {}
                    NegQueue::Opposite => self.usq[o] = NegQueue::Empty,
                },
                NegState::WantYes => match self.usq[o] {
                    NegQueue::Empty => self.usq[o] = NegQueue::Opposite,
                    NegQueue::Opposite => {}
                },
            }
        }
    }

    /// Drive the *peer's* side of `option` toward `enable`d, emitting
    /// `DO`/`DONT` per RFC 1143 (telnet.c `set_remote_option`).
    fn set_remote_option(&mut self, option: u8, enable: bool) {
        let o = option as usize;
        if enable {
            match self.him[o] {
                NegState::No => {
                    self.him[o] = NegState::WantYes;
                    self.send_negotiation(CURL_DO, option);
                }
                NegState::Yes => {}
                NegState::WantNo => match self.himq[o] {
                    NegQueue::Empty => self.himq[o] = NegQueue::Opposite,
                    NegQueue::Opposite => {}
                },
                NegState::WantYes => match self.himq[o] {
                    NegQueue::Empty => {}
                    NegQueue::Opposite => self.himq[o] = NegQueue::Empty,
                },
            }
        } else {
            match self.him[o] {
                NegState::No => {}
                NegState::Yes => {
                    self.him[o] = NegState::WantNo;
                    self.send_negotiation(CURL_DONT, option);
                }
                NegState::WantNo => match self.himq[o] {
                    NegQueue::Empty => {}
                    NegQueue::Opposite => self.himq[o] = NegQueue::Empty,
                },
                NegState::WantYes => match self.himq[o] {
                    NegQueue::Empty => self.himq[o] = NegQueue::Opposite,
                    NegQueue::Opposite => {}
                },
            }
        }
    }

    /// Kick off negotiation of every preferred option (telnet.c
    /// `telnet_negotiate`): for each option slot `0..CURL_NTELOPTS`, skipping
    /// `ECHO`, request our preferred local options (`WILL`) and the peer's
    /// preferred remote options (`DO`).
    fn negotiate(&mut self) {
        for i in 0..CURL_NTELOPTS {
            // ECHO is intentionally skipped here, exactly as curl does: the
            // server drives echo, so we only ever respond to its `WILL ECHO`.
            if i == CURL_TELOPT_ECHO as usize {
                continue;
            }
            if self.us_preferred[i] {
                self.set_local_option(i as u8, true);
            }
            if self.him_preferred[i] {
                self.set_remote_option(i as u8, true);
            }
        }
    }
}

impl TelnetState {
    /// Handle an inbound `IAC WILL <option>` (telnet.c `rec_will`): the peer
    /// offers to enable its side of the option. Respond per RFC 1143.
    fn rec_will(&mut self, option: u8) {
        let o = option as usize;
        match self.him[o] {
            NegState::No => {
                if self.him_preferred[o] {
                    self.him[o] = NegState::Yes;
                    self.send_negotiation(CURL_DO, option);
                } else {
                    self.send_negotiation(CURL_DONT, option);
                }
            }
            NegState::Yes => {}
            NegState::WantNo => match self.himq[o] {
                // DONT answered by WILL — abandon the request.
                NegQueue::Empty => self.him[o] = NegState::No,
                NegQueue::Opposite => {
                    self.him[o] = NegState::Yes;
                    self.himq[o] = NegQueue::Empty;
                }
            },
            NegState::WantYes => match self.himq[o] {
                NegQueue::Empty => self.him[o] = NegState::Yes,
                NegQueue::Opposite => {
                    self.him[o] = NegState::WantNo;
                    self.himq[o] = NegQueue::Empty;
                    self.send_negotiation(CURL_DONT, option);
                }
            },
        }
    }

    /// Handle an inbound `IAC WONT <option>` (telnet.c `rec_wont`): the peer
    /// refuses or disables its side of the option.
    fn rec_wont(&mut self, option: u8) {
        let o = option as usize;
        match self.him[o] {
            NegState::No => {}
            NegState::Yes => {
                self.him[o] = NegState::No;
                self.send_negotiation(CURL_DONT, option);
            }
            NegState::WantNo => match self.himq[o] {
                NegQueue::Empty => self.him[o] = NegState::No,
                NegQueue::Opposite => {
                    self.him[o] = NegState::WantYes;
                    self.himq[o] = NegQueue::Empty;
                    self.send_negotiation(CURL_DO, option);
                }
            },
            NegState::WantYes => match self.himq[o] {
                NegQueue::Empty => self.him[o] = NegState::No,
                NegQueue::Opposite => {
                    self.him[o] = NegState::No;
                    self.himq[o] = NegQueue::Empty;
                }
            },
        }
    }

    /// Handle an inbound `IAC DO <option>` (telnet.c `rec_do`): the peer asks us
    /// to enable our side. May trigger a sub-negotiation (e.g. NAWS) once we
    /// agree.
    fn rec_do(&mut self, option: u8) {
        let o = option as usize;
        match self.us[o] {
            NegState::No => {
                if self.us_preferred[o] {
                    self.us[o] = NegState::Yes;
                    self.send_negotiation(CURL_WILL, option);
                    if self.subnegotiation[o] {
                        self.sendsuboption(option);
                    }
                } else if self.subnegotiation[o] {
                    // Enable purely to deliver the sub-option payload.
                    self.us[o] = NegState::Yes;
                    self.send_negotiation(CURL_WILL, option);
                    self.sendsuboption(option);
                } else {
                    self.send_negotiation(CURL_WONT, option);
                }
            }
            NegState::Yes => {}
            NegState::WantNo => match self.usq[o] {
                // DONT answered by DO — treat as enabled per RFC 1143.
                NegQueue::Empty => self.us[o] = NegState::No,
                NegQueue::Opposite => {
                    self.us[o] = NegState::Yes;
                    self.usq[o] = NegQueue::Empty;
                }
            },
            NegState::WantYes => match self.usq[o] {
                NegQueue::Empty => {
                    self.us[o] = NegState::Yes;
                    if self.subnegotiation[o] {
                        self.sendsuboption(option);
                    }
                }
                NegQueue::Opposite => {
                    self.us[o] = NegState::WantNo;
                    // NOTE: curl clears `himq` here (not `usq`); reproduced
                    // verbatim from telnet.c's `rec_do` for behavioral parity.
                    self.himq[o] = NegQueue::Empty;
                    self.send_negotiation(CURL_WONT, option);
                }
            },
        }
    }

    /// Handle an inbound `IAC DONT <option>` (telnet.c `rec_dont`): the peer
    /// asks us to disable our side.
    fn rec_dont(&mut self, option: u8) {
        let o = option as usize;
        match self.us[o] {
            NegState::No => {}
            NegState::Yes => {
                self.us[o] = NegState::No;
                self.send_negotiation(CURL_WONT, option);
            }
            NegState::WantNo => match self.usq[o] {
                NegQueue::Empty => self.us[o] = NegState::No,
                NegQueue::Opposite => {
                    self.us[o] = NegState::WantYes;
                    self.usq[o] = NegQueue::Empty;
                    self.send_negotiation(CURL_WILL, option);
                }
            },
            NegState::WantYes => match self.usq[o] {
                NegQueue::Empty => self.us[o] = NegState::No,
                NegQueue::Opposite => {
                    self.us[o] = NegState::No;
                    self.usq[o] = NegQueue::Empty;
                }
            },
        }
    }
}

impl TelnetState {
    /// Clear the sub-negotiation accumulator (telnet.c `CURL_SB_CLEAR`).
    fn sb_clear(&mut self) {
        self.subbuffer.clear();
    }

    /// Append a byte to the sub-negotiation accumulator, capped at
    /// [`SUBBUFSIZE`] exactly like telnet.c's `CURL_SB_ACCUM`.
    fn sb_accum(&mut self, c: u8) {
        if self.subbuffer.len() < SUBBUFSIZE {
            self.subbuffer.push(c);
        }
    }

    /// `true` if `s` is unusable as sub-option content: empty or containing an
    /// `IAC` byte (telnet.c `bad_option`, which rejects `NULL` or embedded
    /// `0xFF`). An embedded `IAC` would corrupt the raw, unescaped command
    /// framing, so such values are refused outright.
    fn bad_option(s: Option<&str>) -> bool {
        match s {
            None => true,
            Some(v) => v.as_bytes().contains(&CURL_IAC),
        }
    }

    /// Respond to a completed inbound sub-negotiation (telnet.c `suboption`).
    ///
    /// The accumulated [`Self::subbuffer`] holds `[option, request-payload…]`.
    /// We dispatch on the option byte and queue our reply. For TTYPE / XDISPLOC
    /// we send the configured value; for NEW-ENVIRON we send every configured
    /// variable. The reply framing is queued **raw** (never IAC-escaped) — any
    /// value carrying an embedded `IAC` is rejected by [`Self::bad_option`]
    /// before it can reach the wire.
    fn suboption(&mut self) -> Result<()> {
        // Ignore an empty sub-option (telnet.c `if(!CURL_SB_LEN(tn))`).
        if self.subbuffer.is_empty() {
            return Ok(());
        }
        let option = self.subbuffer[0];
        match option {
            CURL_TELOPT_TTYPE => {
                let t = match self.subopt_ttype.as_deref() {
                    Some(t) => t,
                    None => return Err(CurlError::BadFunctionArgument),
                };
                if Self::bad_option(Some(t)) {
                    return Err(CurlError::BadFunctionArgument);
                }
                if t.len() > 1000 {
                    return Err(CurlError::SendError);
                }
                let mut buf = vec![CURL_IAC, CURL_SB, CURL_TELOPT_TTYPE, CURL_TELQUAL_IS];
                buf.extend_from_slice(t.as_bytes());
                buf.push(CURL_IAC);
                buf.push(CURL_SE);
                self.out.extend_from_slice(&buf);
            }
            CURL_TELOPT_XDISPLOC => {
                let x = match self.subopt_xdisploc.as_deref() {
                    Some(x) => x,
                    None => return Err(CurlError::BadFunctionArgument),
                };
                if Self::bad_option(Some(x)) {
                    return Err(CurlError::BadFunctionArgument);
                }
                if x.len() > 1000 {
                    return Err(CurlError::SendError);
                }
                let mut buf = vec![CURL_IAC, CURL_SB, CURL_TELOPT_XDISPLOC, CURL_TELQUAL_IS];
                buf.extend_from_slice(x.as_bytes());
                buf.push(CURL_IAC);
                buf.push(CURL_SE);
                self.out.extend_from_slice(&buf);
            }
            CURL_TELOPT_NEW_ENVIRON => {
                let mut buf = vec![CURL_IAC, CURL_SB, CURL_TELOPT_NEW_ENVIRON, CURL_TELQUAL_IS];
                // NOTE: telnet.c bounds each var against a fixed 2 KiB stack
                // buffer (`temp[2048]`). That cap is a C buffer-overflow guard,
                // not a protocol limit; the growable `Vec` removes the hazard by
                // construction (AAP §0.7.1, G1), so every well-formed variable
                // is emitted.
                for v in &self.telnet_vars {
                    if Self::bad_option(Some(v)) {
                        return Err(CurlError::BadFunctionArgument);
                    }
                    match v.split_once(',') {
                        // No comma: a bare variable name with no value.
                        None => {
                            buf.push(CURL_NEW_ENV_VAR);
                            buf.extend_from_slice(v.as_bytes());
                        }
                        // "NAME,VALUE": split on the first comma.
                        Some((name, value)) => {
                            buf.push(CURL_NEW_ENV_VAR);
                            buf.extend_from_slice(name.as_bytes());
                            buf.push(CURL_NEW_ENV_VALUE);
                            buf.extend_from_slice(value.as_bytes());
                        }
                    }
                }
                buf.push(CURL_IAC);
                buf.push(CURL_SE);
                self.out.extend_from_slice(&buf);
            }
            // Any other option: nothing to send (telnet.c has no other arm).
            _ => {}
        }
        Ok(())
    }

    /// Emit the sub-negotiation payload for a freshly enabled local option
    /// (telnet.c `sendsuboption`). Only `NAWS` is handled, matching curl.
    ///
    /// The frame is `IAC SB NAWS <w_hi> <w_lo> <h_hi> <h_lo> IAC SE`. The header
    /// (`IAC SB NAWS`) and footer (`IAC SE`) are written **raw**, but the four
    /// window-size bytes are IAC-escaped (a `0xFF` octet is doubled) because
    /// they are payload data, exactly as telnet.c routes them through
    /// `send_telnet_data`.
    fn sendsuboption(&mut self, option: u8) {
        if option == CURL_TELOPT_NAWS {
            // Raw header.
            self.out.push(CURL_IAC);
            self.out.push(CURL_SB);
            self.out.push(CURL_TELOPT_NAWS);

            // Window size in network byte order, IAC-escaped as data.
            let wsx = self.subopt_wsx.to_be_bytes();
            let wsy = self.subopt_wsy.to_be_bytes();
            for &b in &[wsx[0], wsx[1], wsy[0], wsy[1]] {
                self.out.push(b);
                if b == CURL_IAC {
                    self.out.push(CURL_IAC);
                }
            }

            // Raw footer.
            self.out.push(CURL_IAC);
            self.out.push(CURL_SE);
        }
    }
}

/// Escape outbound application data for the TELNET stream (telnet.c
/// `send_telnet_data`): every literal `IAC` (`0xFF`) byte is doubled so the peer
/// does not interpret it as the start of a command. As an allocation
/// optimisation — and to mirror curl's `memchr` fast path — buffers with no
/// `IAC` byte are returned unchanged.
fn escape_iac(input: &[u8]) -> Vec<u8> {
    if !input.contains(&CURL_IAC) {
        return input.to_vec();
    }
    let mut out = Vec::with_capacity(input.len() + 8);
    for &b in input {
        out.push(b);
        if b == CURL_IAC {
            out.push(CURL_IAC);
        }
    }
    out
}

impl TelnetState {
    /// Run the inbound byte stream through the receiver FSM (telnet.c `telrcv`).
    ///
    /// Decoded application bytes are delivered to `sink` in contiguous runs
    /// (curl's `Curl_client_write(CLIENTWRITE_BODY, …)` seam). Protocol bytes —
    /// negotiation commands and sub-option replies — are consumed here and any
    /// responses are queued into [`Self::out`] for the driver to flush.
    ///
    /// De-escaping rules reproduced verbatim from curl:
    /// * `IAC IAC` collapses to a single `0xFF` data byte.
    /// * A `CR` is emitted, and a `NUL` immediately following it is dropped
    ///   (the `CR NUL` → bare-`CR` convention).
    /// * Inside a sub-negotiation, `IAC IAC` collapses to one `0xFF`, while
    ///   `IAC SE` terminates it; any other byte after a lone `IAC` is a
    ///   suboption framing error ([`CurlError::RecvError`]).
    fn telrcv(&mut self, inbuf: &[u8], sink: &mut dyn FnMut(&[u8])) -> Result<()> {
        // `startwrite` marks the start index of the current run of data bytes
        // awaiting delivery; `None` means "no run open" (curl's `startwrite<0`).
        let mut startwrite: Option<usize> = None;
        let mut in_idx = 0usize;

        while in_idx < inbuf.len() {
            let c = inbuf[in_idx];
            match self.telrcv_state {
                TelnetReceive::Cr => {
                    self.telrcv_state = TelnetReceive::Data;
                    if c == b'\0' {
                        // Flush the run (which includes the preceding CR) and
                        // drop the NUL.
                        if let Some(s) = startwrite.take() {
                            sink(&inbuf[s..in_idx]);
                        }
                    } else if startwrite.is_none() {
                        startwrite = Some(in_idx);
                    }
                }
                TelnetReceive::Data => {
                    if c == CURL_IAC {
                        self.telrcv_state = TelnetReceive::Iac;
                        // The IAC byte is a command introducer, not data: close
                        // the current run before it.
                        if let Some(s) = startwrite.take() {
                            sink(&inbuf[s..in_idx]);
                        }
                    } else {
                        if c == b'\r' {
                            self.telrcv_state = TelnetReceive::Cr;
                        }
                        if startwrite.is_none() {
                            startwrite = Some(in_idx);
                        }
                    }
                }
                TelnetReceive::Iac => match c {
                    CURL_WILL => self.telrcv_state = TelnetReceive::Will,
                    CURL_WONT => self.telrcv_state = TelnetReceive::Wont,
                    CURL_DO => self.telrcv_state = TelnetReceive::Do,
                    CURL_DONT => self.telrcv_state = TelnetReceive::Dont,
                    CURL_SB => {
                        self.sb_clear();
                        self.telrcv_state = TelnetReceive::Sb;
                    }
                    CURL_IAC => {
                        // `IAC IAC` → one literal 0xFF data byte: begin (or
                        // continue) a run at this second IAC's index.
                        self.telrcv_state = TelnetReceive::Data;
                        if startwrite.is_none() {
                            startwrite = Some(in_idx);
                        }
                    }
                    // DM / NOP / GA and any other command: accepted and ignored.
                    _ => self.telrcv_state = TelnetReceive::Data,
                },
                TelnetReceive::Will => {
                    self.please_negotiate = true;
                    self.rec_will(c);
                    self.telrcv_state = TelnetReceive::Data;
                }
                TelnetReceive::Wont => {
                    self.please_negotiate = true;
                    self.rec_wont(c);
                    self.telrcv_state = TelnetReceive::Data;
                }
                TelnetReceive::Do => {
                    self.please_negotiate = true;
                    self.rec_do(c);
                    self.telrcv_state = TelnetReceive::Data;
                }
                TelnetReceive::Dont => {
                    self.please_negotiate = true;
                    self.rec_dont(c);
                    self.telrcv_state = TelnetReceive::Data;
                }
                TelnetReceive::Sb => {
                    if c == CURL_IAC {
                        self.telrcv_state = TelnetReceive::Se;
                    } else {
                        self.sb_accum(c);
                    }
                }
                TelnetReceive::Se => {
                    if c != CURL_SE {
                        if c != CURL_IAC {
                            // We only expect "IAC IAC" or "IAC SE" here.
                            return Err(CurlError::RecvError);
                        }
                        // Escaped IAC inside sub-option data → one 0xFF.
                        self.sb_accum(c);
                        self.telrcv_state = TelnetReceive::Sb;
                    } else {
                        // Complete sub-negotiation: dispatch and reset.
                        self.suboption()?;
                        self.sb_clear();
                        self.telrcv_state = TelnetReceive::Data;
                    }
                }
            }
            in_idx += 1;
        }

        // Flush any trailing run of data bytes (curl's `bufferflush()`).
        if let Some(s) = startwrite.take() {
            sink(&inbuf[s..]);
        }
        Ok(())
    }
}

/// Parse a leading run of ASCII decimal digits as curl's `curlx_str_number`
/// does: at least one digit is required, and the value must not exceed `max`
/// (otherwise the parse fails). Trailing non-digit bytes are left unconsumed and
/// ignored by the caller, matching the C helper's pointer-advance behaviour.
fn leading_number(s: &str, max: u64) -> Option<u64> {
    let digits = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let n: u64 = s[..digits].parse().ok()?;
    if n > max {
        None
    } else {
        Some(n)
    }
}

/// Parse a `--telnet-option WS=…` window-size argument of the form
/// `WIDTHxHEIGHT` (telnet.c: `str_number(0xffff)` / `str_single('x')` /
/// `str_number(0xffff)`). Both fields must be present decimal numbers no greater
/// than `0xffff`; any trailing text after the height is ignored, exactly as the
/// C parser leaves it unconsumed. Returns `None` on any syntax error.
fn parse_naws(arg: &str) -> Option<(u16, u16)> {
    let bytes = arg.as_bytes();
    let mut i = 0usize;

    // Width: one or more digits, value <= 0xffff.
    let w_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == w_start {
        return None;
    }
    let x: u64 = arg[w_start..i].parse().ok()?;
    if x > 0xffff {
        return None;
    }

    // Separator: a single 'x'.
    if bytes.get(i) != Some(&b'x') {
        return None;
    }
    i += 1;

    // Height: one or more digits, value <= 0xffff.
    let h_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == h_start {
        return None;
    }
    let y: u64 = arg[h_start..i].parse().ok()?;
    if y > 0xffff {
        return None;
    }

    Some((x as u16, y as u16))
}

impl TelnetState {
    /// Apply the `--telnet-option` / `CURLOPT_TELNETOPTIONS` list and the
    /// command-line username (telnet.c `check_telnet_options`).
    ///
    /// `user` is the configured username (curl's `conn->user`), or `None` when
    /// no credential was supplied. A non-`None` username is exported as the
    /// NEW-ENVIRON variable `USER` and forces `us_preferred[NEW_ENVIRON]`; a
    /// non-ASCII username is rejected with [`CurlError::BadFunctionArgument`].
    ///
    /// Each option in `options` is `NAME=VALUE`:
    /// * `TTYPE=…`    — terminal type (sub-option reply value).
    /// * `XDISPLOC=…` — X display location.
    /// * `NEW_ENV=…`  — an additional NEW-ENVIRON variable (`NAME` or
    ///   `NAME,VALUE`).
    /// * `WS=W x H`   — NAWS window size (each field `<= 0xffff`).
    /// * `BINARY=0`   — disable the otherwise-default binary mode.
    ///
    /// A missing `=` yields [`CurlError::SetoptOptionSyntax`]; a malformed `WS`
    /// value yields the same; any unrecognised name yields
    /// [`CurlError::UnknownOption`]. Processing stops at the first error
    /// (first-error-wins, as in curl). An option whose value contains a
    /// non-ASCII byte is silently skipped.
    fn check_telnet_options<'a, I>(&mut self, options: I, user: Option<&str>) -> Result<()>
    where
        I: IntoIterator<Item = &'a str>,
    {
        // The command-line username becomes the NEW-ENVIRON `USER` variable.
        if let Some(u) = user {
            if u.bytes().any(|b| b & 0x80 != 0) {
                // A non-ASCII username cannot be represented here.
                return Err(CurlError::BadFunctionArgument);
            }
            self.telnet_vars.push(format!("USER,{u}"));
            self.us_preferred[CURL_TELOPT_NEW_ENVIRON as usize] = true;
        }

        for option in options {
            // Split on the first '='; its absence is a syntax error.
            let (name, arg) = match option.split_once('=') {
                Some(pair) => pair,
                None => return Err(CurlError::SetoptOptionSyntax),
            };

            // Silently skip options whose value carries non-ASCII bytes.
            if arg.bytes().any(|b| b & 0x80 != 0) {
                continue;
            }

            match name.len() {
                5 if name.eq_ignore_ascii_case("TTYPE") => {
                    self.subopt_ttype = Some(arg.to_string());
                    self.us_preferred[CURL_TELOPT_TTYPE as usize] = true;
                }
                8 if name.eq_ignore_ascii_case("XDISPLOC") => {
                    self.subopt_xdisploc = Some(arg.to_string());
                    self.us_preferred[CURL_TELOPT_XDISPLOC as usize] = true;
                }
                7 if name.eq_ignore_ascii_case("NEW_ENV") => {
                    self.telnet_vars.push(arg.to_string());
                    self.us_preferred[CURL_TELOPT_NEW_ENVIRON as usize] = true;
                }
                2 if name.eq_ignore_ascii_case("WS") => match parse_naws(arg) {
                    Some((x, y)) => {
                        self.subopt_wsx = x;
                        self.subopt_wsy = y;
                        self.us_preferred[CURL_TELOPT_NAWS as usize] = true;
                    }
                    None => return Err(CurlError::SetoptOptionSyntax),
                },
                6 if name.eq_ignore_ascii_case("BINARY") => {
                    // Only an explicit leading `0` (within the [0,1] range curl
                    // accepts) disables binary; anything else leaves the
                    // on-by-default preference untouched.
                    if leading_number(arg, 1) == Some(0) {
                        self.us_preferred[CURL_TELOPT_BINARY as usize] = false;
                        self.him_preferred[CURL_TELOPT_BINARY as usize] = false;
                    }
                }
                // Right length but wrong name, or any other length: unknown.
                _ => return Err(CurlError::UnknownOption),
            }
        }

        Ok(())
    }
}

/// Send the whole of `buf` through the first socket of `conn`, looping until
/// every byte is accepted. Transient [`CurlError::Again`] yields the task and
/// retries (the filter chain registers writability); a zero-length accept is
/// treated as a send failure to avoid spinning.
async fn conn_send_all(conn: &mut Connection, buf: &[u8]) -> Result<()> {
    let mut sent = 0usize;
    while sent < buf.len() {
        match Curl_conn_send(conn, FIRSTSOCKET, &buf[sent..], false).await {
            Ok(0) => return Err(CurlError::SendError),
            Ok(n) => sent += n,
            Err(CurlError::Again) => tokio::task::yield_now().await,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// The interactive TELNET driver (telnet.c `telnet_do`).
///
/// Builds a fresh [`TelnetState`], applies the configured `--telnet-option`s,
/// then bridges the interactive byte stream until the server closes the
/// connection or an error occurs:
///
/// * **server → local:** received bytes are decoded by [`TelnetState::telrcv`];
///   negotiation/sub-option replies it queues are flushed back to the socket,
///   and the one-shot preferred-option negotiation is kicked off the moment the
///   peer starts negotiating (curl's "don't speak telnet to non-telnet
///   servers" guard).
/// * **local → server:** standard input is read on a blocking helper thread
///   (Tokio's `io-std` feature is intentionally not enabled in this workspace)
///   and forwarded with outbound `IAC` bytes escaped via [`escape_iac`].
///
/// On completion the transfer is reported as [`TransferDirection::None`],
/// mirroring telnet.c's terminal `Curl_xfer_setup_nop` — the bridge above *is*
/// the whole transfer, so the engine performs no further body transfer.
async fn telnet_do(data: &mut Easy, conn: &mut Connection) -> Result<ProtocolTransfer> {
    let verbose = data.set.verbose;
    // Local error-message sink. The bridge to the C `CURLOPT_ERRORBUFFER` slot
    // (`data.set.errorbuffer`, a raw C pointer) belongs to the FFI layer and is
    // not yet plumbed; until then failures are surfaced via `infof` below.
    let mut errbuf: Option<String> = None;

    let mut tn = TelnetState::new();

    // Collect the `--telnet-option` / `CURLOPT_TELNETOPTIONS` strings.
    let options: Vec<String> = data
        .set
        .telnet_options
        .as_ref()
        .map(|list| {
            list.iter()
                .filter_map(|c| c.to_str().ok().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    // NOTE: the username → NEW-ENVIRON `USER` bridge needs the connection
    // credential, which lives behind the setopt/connection surface that is
    // outside this file's dependency whitelist. We pass `None`; the equivalent
    // `--telnet-option NEW_ENV=USER,<name>` form is fully supported above.
    if let Err(e) = tn.check_telnet_options(options.iter().map(String::as_str), None) {
        sendf::failf(&mut errbuf, "Syntax error in telnet option");
        if let Some(msg) = &errbuf {
            sendf::infof(verbose, msg);
        }
        return Err(e);
    }

    sendf::infof(verbose, "TELNET: interactive session started");

    // Stdin reader → bounded channel, on a blocking thread.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    let _stdin_task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break, // local EOF
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break; // driver finished; receiver dropped
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut netbuf = [0u8; 4096];
    // Once stdin reaches EOF the channel closes; disable that select branch so
    // we keep servicing the socket without spinning on a closed receiver.
    let mut stdin_open = true;

    let outcome: Result<()> = loop {
        tokio::select! {
            recv = Curl_conn_recv(conn, FIRSTSOCKET, &mut netbuf) => {
                match recv {
                    // Server closed the connection: clean end of session.
                    Ok(0) => break Ok(()),
                    Ok(n) => {
                        // Decode the chunk, collecting application bytes for
                        // local output.
                        let mut app: Vec<u8> = Vec::new();
                        let telrcv_res = {
                            let mut sink = |bytes: &[u8]| app.extend_from_slice(bytes);
                            tn.telrcv(&netbuf[..n], &mut sink)
                        };
                        if let Err(e) = telrcv_res {
                            sendf::failf(&mut errbuf, "telnet: suboption error");
                            break Err(e);
                        }
                        if !app.is_empty() {
                            use std::io::Write;
                            let mut out = std::io::stdout();
                            if out.write_all(&app).is_err() {
                                break Err(CurlError::WriteError);
                            }
                            let _ = out.flush();
                        }
                        // Begin negotiation only after the peer does, so we do
                        // not "speak telnet" to non-telnet servers.
                        if tn.please_negotiate && !tn.already_negotiated {
                            tn.negotiate();
                            tn.already_negotiated = true;
                        }
                        // Flush queued negotiation / sub-option responses.
                        if !tn.out.is_empty() {
                            let pending = std::mem::take(&mut tn.out);
                            if let Err(e) = conn_send_all(conn, &pending).await {
                                break Err(e);
                            }
                        }
                    }
                    // Not ready yet: poll again.
                    Err(CurlError::Again) => {}
                    Err(e) => break Err(e),
                }
            }
            chunk = rx.recv(), if stdin_open => {
                match chunk {
                    Some(bytes) => {
                        let escaped = escape_iac(&bytes);
                        if let Err(e) = conn_send_all(conn, &escaped).await {
                            break Err(e);
                        }
                    }
                    // Local input drained: stop selecting on stdin.
                    None => stdin_open = false,
                }
            }
        }
    };

    // In verbose mode, surface any buffered failure message (FFI error-buffer
    // bridge pending, as noted above).
    if outcome.is_err() {
        if let Some(msg) = &errbuf {
            sendf::infof(verbose, msg);
        }
    }

    outcome.map(|()| ProtocolTransfer::new(TransferDirection::None))
}

/// The TELNET protocol handler (telnet.c `Curl_protocol_telnet`).
///
/// A zero-sized dispatcher: per-transfer state lives entirely inside
/// [`telnet_do`], so the handler itself carries no fields.
pub struct Telnet;

impl Telnet {
    /// Construct the handler.
    #[must_use]
    pub const fn new() -> Self {
        Telnet
    }
}

impl Default for Telnet {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for Telnet {
    fn scheme(&self) -> &'static Scheme {
        &SCHEME_TELNET
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move { telnet_do(data, conn).await })
    }

    fn done<'a>(
        &'a self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
        _status: Result<()>,
        _premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        // telnet.c `telnet_done` only removes the per-handle meta entry; our
        // engine state is local to `do_it`, so there is nothing to tear down.
        Box::pin(async move { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `input` through the receiver FSM and return the decoded application
    /// bytes the sink received.
    fn feed(tn: &mut TelnetState, input: &[u8]) -> Vec<u8> {
        let mut app = Vec::new();
        {
            let mut sink = |b: &[u8]| app.extend_from_slice(b);
            tn.telrcv(input, &mut sink).expect("telrcv should succeed");
        }
        app
    }

    // -----------------------------------------------------------------------
    // Initial option preferences (telnet.c `init_telnet`).
    // -----------------------------------------------------------------------
    #[test]
    fn new_sets_curl_default_preferences() {
        let tn = TelnetState::new();
        assert!(tn.us_preferred[CURL_TELOPT_SGA as usize]);
        assert!(tn.him_preferred[CURL_TELOPT_SGA as usize]);
        assert!(tn.us_preferred[CURL_TELOPT_BINARY as usize]);
        assert!(tn.him_preferred[CURL_TELOPT_BINARY as usize]);
        assert!(tn.him_preferred[CURL_TELOPT_ECHO as usize]);
        assert!(!tn.us_preferred[CURL_TELOPT_ECHO as usize]);
        assert!(tn.subnegotiation[CURL_TELOPT_NAWS as usize]);
        // Window defaults to 0x0 (RFC 1073 "unspecified").
        assert_eq!(tn.subopt_wsx, 0);
        assert_eq!(tn.subopt_wsy, 0);
        assert_eq!(tn.telrcv_state, TelnetReceive::Data);
    }

    // -----------------------------------------------------------------------
    // IAC negotiation responses (DO/WILL → policy-driven reply).
    // -----------------------------------------------------------------------

    #[test]
    fn do_echo_is_refused_with_wont() {
        // ECHO is not a preferred local option, so `DO ECHO` → `WONT ECHO`.
        let mut tn = TelnetState::new();
        let app = feed(&mut tn, &[CURL_IAC, CURL_DO, CURL_TELOPT_ECHO]);
        assert!(app.is_empty(), "negotiation carries no application data");
        assert_eq!(tn.out, vec![CURL_IAC, CURL_WONT, CURL_TELOPT_ECHO]);
        assert_eq!(tn.us[CURL_TELOPT_ECHO as usize], NegState::No);
        assert!(tn.please_negotiate);
    }

    #[test]
    fn do_sga_is_accepted_with_will() {
        // SGA is a preferred local option, so `DO SGA` → `WILL SGA`.
        let mut tn = TelnetState::new();
        feed(&mut tn, &[CURL_IAC, CURL_DO, CURL_TELOPT_SGA]);
        assert_eq!(tn.out, vec![CURL_IAC, CURL_WILL, CURL_TELOPT_SGA]);
        assert_eq!(tn.us[CURL_TELOPT_SGA as usize], NegState::Yes);
    }

    #[test]
    fn will_echo_is_accepted_with_do() {
        // ECHO is preferred on the peer's side, so `WILL ECHO` → `DO ECHO`.
        let mut tn = TelnetState::new();
        feed(&mut tn, &[CURL_IAC, CURL_WILL, CURL_TELOPT_ECHO]);
        assert_eq!(tn.out, vec![CURL_IAC, CURL_DO, CURL_TELOPT_ECHO]);
        assert_eq!(tn.him[CURL_TELOPT_ECHO as usize], NegState::Yes);
    }

    #[test]
    fn will_unpreferred_option_is_refused_with_dont() {
        // We do not prefer the peer to enable TTYPE on *its* side → `DONT`.
        let mut tn = TelnetState::new();
        feed(&mut tn, &[CURL_IAC, CURL_WILL, CURL_TELOPT_TTYPE]);
        assert_eq!(tn.out, vec![CURL_IAC, CURL_DONT, CURL_TELOPT_TTYPE]);
    }

    #[test]
    fn do_naws_enables_and_emits_subnegotiation() {
        // NAWS is flagged for sub-negotiation: `DO NAWS` → `WILL NAWS` followed
        // by the window-size sub-option (default 0x0).
        let mut tn = TelnetState::new();
        feed(&mut tn, &[CURL_IAC, CURL_DO, CURL_TELOPT_NAWS]);
        assert_eq!(
            tn.out,
            vec![
                CURL_IAC,
                CURL_WILL,
                CURL_TELOPT_NAWS, // accept
                CURL_IAC,
                CURL_SB,
                CURL_TELOPT_NAWS, // sub-option header
                0,
                0,
                0,
                0, // width=0, height=0
                CURL_IAC,
                CURL_SE, // sub-option footer
            ]
        );
        assert_eq!(tn.us[CURL_TELOPT_NAWS as usize], NegState::Yes);
    }

    #[test]
    fn rfc1143_completes_local_handshake_without_looping() {
        // We initiate WILL SGA (No → WantYes), the peer answers DO SGA, which
        // finalizes us[SGA] = Yes with no further output.
        let mut tn = TelnetState::new();
        tn.set_local_option(CURL_TELOPT_SGA, true);
        assert_eq!(tn.out, vec![CURL_IAC, CURL_WILL, CURL_TELOPT_SGA]);
        assert_eq!(tn.us[CURL_TELOPT_SGA as usize], NegState::WantYes);

        tn.out.clear();
        feed(&mut tn, &[CURL_IAC, CURL_DO, CURL_TELOPT_SGA]);
        assert_eq!(tn.us[CURL_TELOPT_SGA as usize], NegState::Yes);
        assert!(
            tn.out.is_empty(),
            "a completed handshake emits nothing more"
        );
    }

    #[test]
    fn repeated_will_does_not_re_emit_once_enabled() {
        // First WILL ECHO → DO ECHO (him = Yes); a second WILL ECHO is a no-op.
        let mut tn = TelnetState::new();
        feed(&mut tn, &[CURL_IAC, CURL_WILL, CURL_TELOPT_ECHO]);
        tn.out.clear();
        feed(&mut tn, &[CURL_IAC, CURL_WILL, CURL_TELOPT_ECHO]);
        assert!(
            tn.out.is_empty(),
            "already-enabled option must not re-negotiate"
        );
    }

    #[test]
    fn negotiate_emits_all_preferred_options() {
        // The initial negotiation burst offers our preferred local options
        // (WILL) and requests the peer's preferred remote options (DO), in
        // option-index order, skipping ECHO.
        let mut tn = TelnetState::new();
        tn.negotiate();
        assert_eq!(
            tn.out,
            vec![
                CURL_IAC,
                CURL_WILL,
                CURL_TELOPT_BINARY, // i=0 local
                CURL_IAC,
                CURL_DO,
                CURL_TELOPT_BINARY, // i=0 remote
                CURL_IAC,
                CURL_WILL,
                CURL_TELOPT_SGA, // i=3 local
                CURL_IAC,
                CURL_DO,
                CURL_TELOPT_SGA, // i=3 remote
            ]
        );
        // ECHO is skipped on our side but its remote preference is *not* offered
        // here either (curl only ever responds to the server's WILL ECHO).
        assert_eq!(tn.us[CURL_TELOPT_ECHO as usize], NegState::No);
        assert_eq!(tn.him[CURL_TELOPT_ECHO as usize], NegState::No);
    }

    // -----------------------------------------------------------------------
    // Sub-negotiation parse + reply (telnet.c `telrcv` SB/SE + `suboption`).
    // -----------------------------------------------------------------------

    #[test]
    fn ttype_send_subnegotiation_replies_with_is() {
        // `IAC SB TTYPE SEND IAC SE` → `IAC SB TTYPE IS "xterm" IAC SE`.
        let mut tn = TelnetState::new();
        tn.subopt_ttype = Some("xterm".to_string());
        feed(
            &mut tn,
            &[
                CURL_IAC,
                CURL_SB,
                CURL_TELOPT_TTYPE,
                CURL_TELQUAL_SEND,
                CURL_IAC,
                CURL_SE,
            ],
        );
        let mut expected = vec![CURL_IAC, CURL_SB, CURL_TELOPT_TTYPE, CURL_TELQUAL_IS];
        expected.extend_from_slice(b"xterm");
        expected.extend_from_slice(&[CURL_IAC, CURL_SE]);
        assert_eq!(tn.out, expected);
    }

    #[test]
    fn xdisploc_subnegotiation_replies_with_is() {
        let mut tn = TelnetState::new();
        tn.subopt_xdisploc = Some(":0.0".to_string());
        feed(
            &mut tn,
            &[
                CURL_IAC,
                CURL_SB,
                CURL_TELOPT_XDISPLOC,
                CURL_TELQUAL_SEND,
                CURL_IAC,
                CURL_SE,
            ],
        );
        let mut expected = vec![CURL_IAC, CURL_SB, CURL_TELOPT_XDISPLOC, CURL_TELQUAL_IS];
        expected.extend_from_slice(b":0.0");
        expected.extend_from_slice(&[CURL_IAC, CURL_SE]);
        assert_eq!(tn.out, expected);
    }

    #[test]
    fn new_environ_subnegotiation_emits_var_value_pairs() {
        let mut tn = TelnetState::new();
        tn.telnet_vars.push("USER,alice".to_string());
        tn.telnet_vars.push("TERM".to_string()); // bare name, no value
        feed(
            &mut tn,
            &[
                CURL_IAC,
                CURL_SB,
                CURL_TELOPT_NEW_ENVIRON,
                CURL_TELQUAL_SEND,
                CURL_IAC,
                CURL_SE,
            ],
        );
        let mut expected = vec![CURL_IAC, CURL_SB, CURL_TELOPT_NEW_ENVIRON, CURL_TELQUAL_IS];
        expected.push(CURL_NEW_ENV_VAR);
        expected.extend_from_slice(b"USER");
        expected.push(CURL_NEW_ENV_VALUE);
        expected.extend_from_slice(b"alice");
        expected.push(CURL_NEW_ENV_VAR);
        expected.extend_from_slice(b"TERM");
        expected.extend_from_slice(&[CURL_IAC, CURL_SE]);
        assert_eq!(tn.out, expected);
    }

    #[test]
    fn ttype_subnegotiation_without_value_is_rejected() {
        // A server requesting TTYPE when none was configured hits
        // `bad_option(None)` → BadFunctionArgument. (The other `bad_option`
        // trigger — an embedded IAC in the value — is structurally impossible
        // here: values are stored as UTF-8 `String`s and 0xFF never appears in
        // valid UTF-8, so the type system enforces what C checked at runtime.)
        let mut tn = TelnetState::new();
        assert!(tn.subopt_ttype.is_none());
        let mut sink = |_: &[u8]| {};
        let res = tn.telrcv(
            &[
                CURL_IAC,
                CURL_SB,
                CURL_TELOPT_TTYPE,
                CURL_TELQUAL_SEND,
                CURL_IAC,
                CURL_SE,
            ],
            &mut sink,
        );
        assert!(matches!(res, Err(CurlError::BadFunctionArgument)));
    }

    #[test]
    fn subnegotiation_framing_error_is_recv_error() {
        // Inside SB, a lone IAC must be followed by IAC or SE; anything else is
        // a sub-option framing error.
        let mut tn = TelnetState::new();
        let mut sink = |_: &[u8]| {};
        let res = tn.telrcv(
            &[
                CURL_IAC,
                CURL_SB,
                CURL_TELOPT_TTYPE,
                CURL_IAC,
                CURL_TELOPT_BINARY,
            ],
            &mut sink,
        );
        assert!(matches!(res, Err(CurlError::RecvError)));
    }

    #[test]
    fn subnegotiation_escaped_iac_is_accepted() {
        // `IAC IAC` inside a sub-option is a literal 0xFF data byte, not a
        // terminator; the sub-option then completes normally.
        let mut tn = TelnetState::new();
        // SB for an option with no reply arm (BINARY) carrying an escaped IAC.
        let res = {
            let mut sink = |_: &[u8]| {};
            tn.telrcv(
                &[
                    CURL_IAC,
                    CURL_SB,
                    CURL_TELOPT_BINARY,
                    CURL_IAC,
                    CURL_IAC,
                    CURL_IAC,
                    CURL_SE,
                ],
                &mut sink,
            )
        };
        assert!(res.is_ok());
        assert_eq!(tn.telrcv_state, TelnetReceive::Data);
        assert!(tn.out.is_empty(), "BINARY sub-option has no reply");
    }

    // -----------------------------------------------------------------------
    // Outbound IAC escaping (telnet.c `send_telnet_data`).
    // -----------------------------------------------------------------------

    #[test]
    fn escape_iac_doubles_single_ff() {
        assert_eq!(escape_iac(&[0xFF]), vec![0xFF, 0xFF]);
    }

    #[test]
    fn escape_iac_doubles_embedded_ff_only() {
        assert_eq!(
            escape_iac(&[0x01, 0xFF, 0x02]),
            vec![0x01, 0xFF, 0xFF, 0x02]
        );
        assert_eq!(escape_iac(&[0xFF, 0xFF]), vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn escape_iac_passes_clean_data_through() {
        assert_eq!(escape_iac(b"hello"), b"hello".to_vec());
        assert_eq!(escape_iac(&[]), Vec::<u8>::new());
    }

    // -----------------------------------------------------------------------
    // Receiver de-escaping and CR handling (telnet.c `telrcv`).
    // -----------------------------------------------------------------------

    #[test]
    fn telrcv_delivers_plain_data() {
        let mut tn = TelnetState::new();
        assert_eq!(feed(&mut tn, b"hello world"), b"hello world".to_vec());
    }

    #[test]
    fn telrcv_de_escapes_iac_iac_to_single_ff() {
        let mut tn = TelnetState::new();
        let app = feed(&mut tn, &[b'A', CURL_IAC, CURL_IAC, b'B']);
        assert_eq!(app, vec![b'A', 0xFF, b'B']);
    }

    #[test]
    fn telrcv_drops_nul_after_cr() {
        // CR NUL → bare CR (the trailing NUL is stripped).
        let mut tn = TelnetState::new();
        let app = feed(&mut tn, &[b'a', b'\r', 0x00, b'b']);
        assert_eq!(app, b"a\rb".to_vec());
    }

    #[test]
    fn telrcv_preserves_cr_lf() {
        let mut tn = TelnetState::new();
        let app = feed(&mut tn, b"a\r\n");
        assert_eq!(app, b"a\r\n".to_vec());
    }

    #[test]
    fn telrcv_data_split_across_calls_keeps_state() {
        // An IAC at the end of one chunk and the command in the next must still
        // be interpreted as a command, not data.
        let mut tn = TelnetState::new();
        let a = feed(&mut tn, &[b'x', CURL_IAC]);
        assert_eq!(a, b"x".to_vec());
        let b = feed(&mut tn, &[CURL_WILL, CURL_TELOPT_ECHO]);
        assert!(b.is_empty());
        assert_eq!(tn.out, vec![CURL_IAC, CURL_DO, CURL_TELOPT_ECHO]);
    }

    // -----------------------------------------------------------------------
    // `--telnet-option` parsing (telnet.c `check_telnet_options`).
    // -----------------------------------------------------------------------

    #[test]
    fn option_ttype_is_parsed() {
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["TTYPE=vt100"], None).unwrap();
        assert_eq!(tn.subopt_ttype.as_deref(), Some("vt100"));
        assert!(tn.us_preferred[CURL_TELOPT_TTYPE as usize]);
    }

    #[test]
    fn option_xdisploc_is_parsed() {
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["XDISPLOC=host:0"], None).unwrap();
        assert_eq!(tn.subopt_xdisploc.as_deref(), Some("host:0"));
        assert!(tn.us_preferred[CURL_TELOPT_XDISPLOC as usize]);
    }

    #[test]
    fn option_new_env_is_appended() {
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["NEW_ENV=FOO,bar"], None).unwrap();
        assert_eq!(tn.telnet_vars, vec!["FOO,bar".to_string()]);
        assert!(tn.us_preferred[CURL_TELOPT_NEW_ENVIRON as usize]);
    }

    #[test]
    fn option_ws_is_parsed() {
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["WS=132x43"], None).unwrap();
        assert_eq!(tn.subopt_wsx, 132);
        assert_eq!(tn.subopt_wsy, 43);
        assert!(tn.us_preferred[CURL_TELOPT_NAWS as usize]);
    }

    #[test]
    fn option_ws_max_dimensions() {
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["WS=65535x65535"], None).unwrap();
        assert_eq!(tn.subopt_wsx, 0xffff);
        assert_eq!(tn.subopt_wsy, 0xffff);
    }

    #[test]
    fn option_ws_syntax_errors() {
        for bad in ["WS=80", "WS=x24", "WS=80x", "WS=axb", "WS=99999x1"] {
            let mut tn = TelnetState::new();
            let res = tn.check_telnet_options([bad], None);
            assert!(
                matches!(res, Err(CurlError::SetoptOptionSyntax)),
                "{bad:?} must be a WS syntax error"
            );
        }
    }

    #[test]
    fn option_binary_zero_disables_binary() {
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["BINARY=0"], None).unwrap();
        assert!(!tn.us_preferred[CURL_TELOPT_BINARY as usize]);
        assert!(!tn.him_preferred[CURL_TELOPT_BINARY as usize]);
    }

    #[test]
    fn option_binary_one_keeps_default() {
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["BINARY=1"], None).unwrap();
        assert!(tn.us_preferred[CURL_TELOPT_BINARY as usize]);
        assert!(tn.him_preferred[CURL_TELOPT_BINARY as usize]);
    }

    #[test]
    fn option_binary_out_of_range_keeps_default() {
        // Values curl's `str_number(max=1)` rejects (e.g. 2) leave binary on.
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["BINARY=2"], None).unwrap();
        assert!(tn.us_preferred[CURL_TELOPT_BINARY as usize]);
    }

    #[test]
    fn option_missing_equals_is_syntax_error() {
        let mut tn = TelnetState::new();
        let res = tn.check_telnet_options(["TTYPE"], None);
        assert!(matches!(res, Err(CurlError::SetoptOptionSyntax)));
    }

    #[test]
    fn option_unknown_name_is_unknown_option() {
        let mut tn = TelnetState::new();
        let res = tn.check_telnet_options(["BOGUS=1"], None);
        assert!(matches!(res, Err(CurlError::UnknownOption)));
        // Right length but wrong name is also unknown (len 5 != "TTYPE").
        let mut tn2 = TelnetState::new();
        assert!(matches!(
            tn2.check_telnet_options(["ABCDE=1"], None),
            Err(CurlError::UnknownOption)
        ));
    }

    #[test]
    fn option_name_is_case_insensitive() {
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["ttype=xterm"], None).unwrap();
        assert_eq!(tn.subopt_ttype.as_deref(), Some("xterm"));
    }

    #[test]
    fn option_non_ascii_value_is_skipped() {
        // A non-ASCII value is silently ignored (no error, no effect).
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["TTYPE=xter\u{00e9}m"], None)
            .unwrap();
        assert!(tn.subopt_ttype.is_none());
        assert!(!tn.us_preferred[CURL_TELOPT_TTYPE as usize]);
    }

    #[test]
    fn option_processing_stops_at_first_error() {
        // First-error-wins: the bad WS aborts before the trailing TTYPE.
        let mut tn = TelnetState::new();
        let res = tn.check_telnet_options(["WS=bad", "TTYPE=vt100"], None);
        assert!(matches!(res, Err(CurlError::SetoptOptionSyntax)));
        assert!(tn.subopt_ttype.is_none());
    }

    // -----------------------------------------------------------------------
    // Username → NEW-ENVIRON `USER` variable.
    // -----------------------------------------------------------------------

    #[test]
    fn username_becomes_user_env_var() {
        let mut tn = TelnetState::new();
        tn.check_telnet_options(std::iter::empty(), Some("alice"))
            .unwrap();
        assert_eq!(tn.telnet_vars, vec!["USER,alice".to_string()]);
        assert!(tn.us_preferred[CURL_TELOPT_NEW_ENVIRON as usize]);
    }

    #[test]
    fn username_precedes_new_env_options() {
        let mut tn = TelnetState::new();
        tn.check_telnet_options(["NEW_ENV=TERM,xterm"], Some("bob"))
            .unwrap();
        assert_eq!(
            tn.telnet_vars,
            vec!["USER,bob".to_string(), "TERM,xterm".to_string()]
        );
    }

    #[test]
    fn non_ascii_username_is_rejected() {
        let mut tn = TelnetState::new();
        let res = tn.check_telnet_options(std::iter::empty(), Some("ali\u{00e7}e"));
        assert!(matches!(res, Err(CurlError::BadFunctionArgument)));
    }

    // -----------------------------------------------------------------------
    // NAWS sub-option emission (telnet.c `sendsuboption`).
    // -----------------------------------------------------------------------

    #[test]
    fn sendsuboption_naws_encodes_window_big_endian() {
        let mut tn = TelnetState::new();
        tn.subopt_wsx = 0x0050; // 80
        tn.subopt_wsy = 0x0018; // 24
        tn.sendsuboption(CURL_TELOPT_NAWS);
        assert_eq!(
            tn.out,
            vec![
                CURL_IAC,
                CURL_SB,
                CURL_TELOPT_NAWS,
                0x00,
                0x50,
                0x00,
                0x18,
                CURL_IAC,
                CURL_SE,
            ]
        );
    }

    #[test]
    fn sendsuboption_naws_escapes_ff_window_byte() {
        // A window dimension whose low byte is 0xFF must be IAC-escaped.
        let mut tn = TelnetState::new();
        tn.subopt_wsx = 0x00FF; // low byte 0xFF → doubled
        tn.subopt_wsy = 0x0018;
        tn.sendsuboption(CURL_TELOPT_NAWS);
        assert_eq!(
            tn.out,
            vec![
                CURL_IAC,
                CURL_SB,
                CURL_TELOPT_NAWS,
                0x00,
                0xFF,
                0xFF, // width: 0x00 0xFF(escaped)
                0x00,
                0x18, // height
                CURL_IAC,
                CURL_SE,
            ]
        );
    }

    #[test]
    fn sendsuboption_ignores_non_naws() {
        let mut tn = TelnetState::new();
        tn.sendsuboption(CURL_TELOPT_TTYPE);
        assert!(tn.out.is_empty());
    }

    // -----------------------------------------------------------------------
    // Handler descriptor.
    // -----------------------------------------------------------------------

    #[test]
    fn handler_reports_telnet_scheme() {
        let h = Telnet::new();
        assert_eq!(h.scheme().name, "telnet");
        assert_eq!(h.scheme().default_port, 23);
    }
}
