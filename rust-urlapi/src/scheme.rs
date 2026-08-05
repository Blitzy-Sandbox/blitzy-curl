// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Scheme resolution: default ports, the URL-options capability bit and the
//! protocol-enabled marker.
//!
//! `lib/urlapi.c` does not own this data. It calls `Curl_get_scheme()`, which
//! is defined in `lib/url.c` L1469-L1472 and delegates to `Curl_getn_scheme()`
//! at L1477-L1541, a perfect-hash lookup over 33 per-protocol descriptors that
//! live one per protocol module. That is the module's one genuine
//! cross-translation-unit dependency for *data* rather than for a utility, and
//! an object file standing in for `lib/urlapi.o` has to resolve it somehow.
//! This module is where it is resolved, in one of two ways selected at compile
//! time.
//!
//! # The two modes
//!
//! | Feature `scheme-table` | Source of truth        | `unsafe` |
//! |------------------------|------------------------|----------|
//! | off, the drop-in mode  | the real `Curl_get_scheme()`, imported | three blocks |
//! | on, standalone default | a table compiled into this file        | none |
//!
//! This is the "capability provider selected at compile time" pattern, and it
//! is the Rust expression of what the C achieves through link-time symbol
//! resolution. The two backends present *exactly* the same interface, which is
//! the point: `src/getset.rs`, `src/parse/scheme.rs` and
//! `src/parse/authority.rs` contain no `#[cfg]` at all, because every
//! conditional in the port's scheme handling lives here.
//!
//! Drop-in mode is the authoritative one. It links beside a real libcurl, so
//! the real and complete table is consulted and this crate contributes none of
//! its own -- which also means it must not *define* `Curl_get_scheme`, only
//! import it, or the link acquires a duplicate symbol. Standalone mode exists
//! for the demo program and the lib1560 harness when no libcurl takes part in
//! the link at all.
//!
//! # What the URL API actually reads
//!
//! `struct Curl_scheme` at `lib/urldata.h` L515-L524 has six fields.
//! `lib/urlapi.c` calls the lookup at six sites and performs ten field
//! accesses across them, and between them they touch exactly three fields:
//!
//! - **L284**, read at L290: existence, then
//!   `flags & PROTOPT_URLOPTIONS`, deciding whether to split an options part
//!   out of the userinfo field.
//! - **L951**: existence only, rejecting an unknown scheme with
//!   `CURLUE_UNSUPPORTED_SCHEME`.
//! - **L1460**, read at L1465, L1472 and L1477: existence, `defport` twice
//!   and `flags & PROTOPT_URLOPTIONS`, while serialising the whole URL.
//! - **L1589**, read at L1591: `defport`, supplying `CURLU_DEFAULT_PORT` for
//!   `CURLUPART_PORT`.
//! - **L1598**, read at L1599: `defport`, honouring
//!   `CURLU_NO_DEFAULT_PORT`.
//! - **L1645**, read at L1646: existence and `!h->run`, rejecting a disabled
//!   protocol.
//!
//! `name` is never read -- the lookup is *by* name -- and neither `protocol`
//! nor `family` is read at all. [`SchemeInfo`] therefore carries three values
//! and no more. Keeping the interface that narrow is what lets the standalone
//! table stay small and lets the drop-in mirror be audited in one sitting.
//!
//! # The matching rule is case-insensitive, and that had to be established
//!
//! Reproducing the lookup means reproducing its comparison, and the comparison
//! is not obvious from `Curl_getn_scheme`'s three-line tail. Following it
//! through:
//!
//! ```text
//! lib/url.c:1524     if(len && (len <= 7)) {
//! lib/url.c:1531       c += (unsigned int)Curl_raw_tolower(*s);   /* hash */
//! lib/url.c:1537       if(h && curl_strnequal(scheme, h->name, len) && !h->name[len])
//! ```
//!
//! The hash folds with `Curl_raw_tolower`, so it is case-insensitive.
//! `curl_strnequal` at `lib/strequal.c` L87-L94 delegates to `ncasecompare` at
//! L52-L64, which folds both sides with `Curl_raw_toupper`, so the comparison
//! is case-insensitive too. And `!h->name[len]` pins the table name's length to
//! exactly `len`. With `len` coming from `strlen(scheme)` the net rule is
//! plain **case-insensitive equality of the whole name**, which is what
//! [`crate::ctype::eq_ignore_case`] computes, length check included.
//!
//! This matters because the two call paths do not guarantee the same case. On
//! the parse path the scheme has already been lower-cased by
//! `Curl_is_absolute_url` at `lib/urlapi.c` L214, but
//! `curl_url_set(CURLUPART_SCHEME, ...)` hands the caller's string straight to
//! the lookup at L1645. A case-sensitive port would quietly reject
//! `curl_url_set(u, CURLUPART_SCHEME, "HTTPS", 0)`, which the C accepts.
//!
//! The `len <= 7` guard is reproduced as well. It changes no outcome today,
//! because the longest name in the table is `gophers` at seven bytes, but it is
//! the C's own bound and a table that grew a longer name would silently stop
//! finding it -- in the C as much as here.
//!
//! # Two transcription findings, reproduced rather than corrected
//!
//! Transformation rule T6, faithful over correct, governs both.
//!
//! First, four descriptors spell their name in upper case -- `"SCP"` at
//! `lib/vssh/vssh.c` L353, `"SFTP"` at L339, `"WS"` at `lib/ws.c` L1985 and
//! `"WSS"` at L2000 -- although `lib/urldata.h` L516 describes the field as
//! "URL scheme name in lowercase". It is harmless precisely because the
//! comparison is case-insensitive, and the standalone table transcribes all
//! four verbatim. A transcription that silently corrects its source is not a
//! transcription, and the four are a standing reminder that the case-folding
//! above is load-bearing rather than defensive.
//!
//! Second, the authoritative name list at `scripts/schemetable.c` L33-L65 holds
//! **33** names, not the 32 an off-by-one count of it suggests, and `lib/`
//! contains exactly 33 `const struct Curl_scheme Curl_scheme_*` definitions to
//! match. The count is pinned at compile time by the table's array type.
//! Neither `ipfs` nor `ipns` is among them: those are command-line tool schemes
//! and appear nowhere in `lib/`.
//!
//! # See also
//!
//! `src/abi.rs` owns `PROTOPT_URLOPTIONS`, the one capability bit the URL API
//! tests, so that it has a single definition in the crate. The remaining
//! `PROTOPT_*` bits are needed only to write the standalone table's `flags`
//! words out the way the C descriptors write them, and are therefore defined
//! inside that backend and nowhere else.

// Reachability here is decided by the feature set and by the consumers, not by
// this file. `getn_scheme` is the length-delimited entry point that mirrors
// `Curl_getn_scheme`, and a build whose parser only ever holds NUL-terminated
// schemes reaches `get_scheme` alone; the drop-in mirror deliberately
// describes all six fields of `struct Curl_scheme` while reading three, since
// the three that are read sit *after* the three that are not and cannot be
// located without them. Warnings are errors for this crate, so rather than let
// the feature matrix or a sibling module decide whether the build is clean,
// the allowance is stated once here with its reason. It is scoped to this
// module and to this lint alone.
#![allow(dead_code)]

use crate::abi::PROTOPT_URLOPTIONS;
use core::ffi::CStr;

/// The three fields of `struct Curl_scheme` that `lib/urlapi.c` reads.
///
/// An owned copy rather than a borrow of the descriptor, which is what keeps
/// the raw pointer of drop-in mode from escaping this module: in either mode a
/// caller receives plain values it can copy freely, and in standalone mode the
/// same values are produced with no `unsafe` at all. Eight bytes, so copying
/// is cheaper than borrowing would be.
///
/// The C reads the descriptor through a `const struct Curl_scheme *` that
/// points into libcurl's `.rodata` and lives for the whole program, so nothing
/// is lost by snapshotting it. Nothing writes to a descriptor, in libcurl or
/// here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SchemeInfo {
    /// `flags` at `lib/urldata.h` L522, a `uint32_t` of `PROTOPT_*` bits.
    ///
    /// The whole word, not just the one bit the URL API tests. Drop-in mode
    /// reads the real field, so narrowing it here would make the two modes
    /// disagree for any future reader of another bit, and it would make the
    /// standalone table impossible to diff against the C descriptors it was
    /// transcribed from.
    flags: u32,
    /// `defport` at `lib/urldata.h` L523, a `uint16_t`.
    ///
    /// Compared against `struct Curl_URL::portnum` at `lib/urlapi.c` L79,
    /// which is an `unsigned short`, so the widths already agree and no cast
    /// is needed at the comparison sites.
    defport: u16,
    /// Whether `run` at `lib/urldata.h` L517 is non-null.
    ///
    /// The C tests the pointer itself at `lib/urlapi.c` L1646, and the comment
    /// at `lib/url.c` L1474-L1476 says why: the field is what distinguishes a
    /// scheme libcurl knows the name of from one it can actually drive. A
    /// disabled protocol is still in the table, with `run` set to `ZERO_NULL`
    /// by its module's `#ifdef`, as `lib/file.c` L628-L632 shows.
    ///
    /// Reduced to a boolean because the pointer is never dereferenced, only
    /// tested, and because a raw pointer must not leave this module.
    implemented: bool,
}

impl SchemeInfo {
    /// The whole `PROTOPT_*` word.
    ///
    /// Prefer [`SchemeInfo::has_url_options`] for the one bit the URL API
    /// actually consults. This accessor exists so that the field is reachable
    /// at all: it is the third of the three values the C reads, and hiding it
    /// behind a single predicate would make the snapshot narrower than the
    /// descriptor it stands for.
    pub(crate) const fn flags(self) -> u32 {
        self.flags
    }

    /// The scheme's default port, or zero when it has none.
    ///
    /// Zero is a real answer and not a sentinel for "unknown": `file` is
    /// initialised with `0` at `lib/file.c` L636 because a file URL has no
    /// port to default to. The C makes no special case of it -- it formats
    /// whatever it finds with `"%u"` at `lib/urlapi.c` L1465 -- and neither
    /// does this port, because the `file://` branch at L1440-L1447 serialises
    /// such URLs without ever consulting a port.
    pub(crate) const fn defport(self) -> u16 {
        self.defport
    }

    /// Whether libcurl can actually drive this scheme, that is `h->run != 0`.
    ///
    /// `lib/urlapi.c` L1646 rejects the scheme with
    /// `CURLUE_UNSUPPORTED_SCHEME` when this is false and the caller did not
    /// pass `CURLU_NON_SUPPORT_SCHEME`.
    pub(crate) const fn implemented(self) -> bool {
        self.implemented
    }

    /// Whether the scheme permits an options part in the userinfo field.
    ///
    /// `flags & PROTOPT_URLOPTIONS`, the only bit test the URL API performs on
    /// this word. It is read at `lib/urlapi.c` L290, choosing whether to hand
    /// `Curl_parse_login_details` somewhere to put an options string, and
    /// again at L1477, where a scheme without the bit has its options
    /// suppressed while the whole URL is serialised.
    ///
    /// Exactly six schemes carry it: `imap`, `imaps`, `pop3`, `pop3s`, `smtp`
    /// and `smtps`.
    pub(crate) const fn has_url_options(self) -> bool {
        self.flags & PROTOPT_URLOPTIONS != 0
    }
}

/// Looks up a NUL-terminated scheme name. Mirrors `Curl_get_scheme`.
///
/// `lib/url.c` L1469-L1472 is a one-line forward:
/// `Curl_getn_scheme(scheme, strlen(scheme))`. This function is the same
/// forward, and it is the entry point every one of the six call sites in
/// `lib/urlapi.c` uses.
///
/// A `&CStr` rather than a `&[u8]`, because in drop-in mode the pointer really
/// is handed to C and the terminator is a precondition of that call rather
/// than a detail of this one. Taking the terminated type makes the guarantee
/// the caller's, and makes it impossible to forget: there is no code path here
/// that could append a terminator, since doing so would need an allocation.
/// `src/abi.rs` carries `DEFAULT_SCHEME_CSTR` for the one caller,
/// `lib/urlapi.c` L1456 followed by L1460, that has a literal rather than a
/// handle field to look up.
///
/// # Returns
///
/// `None` for a name the table does not hold, which is the C's null return.
/// Note that "found" and "usable" are different questions: a disabled protocol
/// is found, and reports [`SchemeInfo::implemented`] as false.
pub(crate) fn get_scheme(scheme: &CStr) -> Option<SchemeInfo> {
    backend::get_scheme(scheme)
}

/// Looks up a scheme name given as a byte slice. Mirrors `Curl_getn_scheme`.
///
/// `lib/url.c` L1477-L1541, declared alongside `Curl_get_scheme` at
/// `lib/url.h` L76-L77 and exported by the same object file, so drop-in mode
/// can forward to it directly. It is offered here so that a caller holding a
/// scheme without a terminator -- a slice of the URL being parsed, say -- can
/// look it up without building a C string, which would cost an allocation that
/// the C never pays.
///
/// # Returns
///
/// `None` for an empty slice, for a slice longer than the C's seven-byte
/// bound, and for a name the table does not hold.
pub(crate) fn getn_scheme(name: &[u8]) -> Option<SchemeInfo> {
    backend::getn_scheme(name)
}

/// The standalone backend: a scheme table compiled into this crate.
///
/// Selected by the `scheme-table` feature, which is on by default. Nothing in
/// here is `unsafe`, and no C structure is described, because none is read.
#[cfg(feature = "scheme-table")]
mod backend {
    use super::SchemeInfo;
    use crate::ctype::eq_ignore_case;
    use core::ffi::CStr;

    /// Default ports, transcribed from `lib/urldata.h` L29-L53.
    ///
    /// All 25 macros are reproduced, under their C names, so that the table
    /// below reads the way the protocol descriptors read and a reviewer can
    /// diff the two texts rather than compare numbers. Three of them are
    /// aliases in the C and are aliases here for the same reason: `PORT_RTMPT`
    /// is `PORT_HTTP` at L49, `PORT_RTMPS` is `PORT_HTTPS` at L50, and
    /// `PORT_SMBS` happens to equal `PORT_SMB` at L43-L44 while being written
    /// out separately, which this file preserves.
    ///
    /// There is no `PORT_GOPHERS` and no port macro for `file`. `gophers`
    /// shares `PORT_GOPHER`, per `lib/gopher.c` L242, and `file` is
    /// initialised with a literal `0` at `lib/file.c` L636.
    mod port {
        pub(super) const FTP: u16 = 21;
        pub(super) const FTPS: u16 = 990;
        pub(super) const TELNET: u16 = 23;
        pub(super) const HTTP: u16 = 80;
        pub(super) const HTTPS: u16 = 443;
        pub(super) const DICT: u16 = 2628;
        pub(super) const LDAP: u16 = 389;
        pub(super) const LDAPS: u16 = 636;
        pub(super) const TFTP: u16 = 69;
        pub(super) const SSH: u16 = 22;
        pub(super) const IMAP: u16 = 143;
        pub(super) const IMAPS: u16 = 993;
        pub(super) const POP3: u16 = 110;
        pub(super) const POP3S: u16 = 995;
        pub(super) const SMB: u16 = 445;
        pub(super) const SMBS: u16 = 445;
        pub(super) const SMTP: u16 = 25;
        /// L46 notes this one is "sometimes called SSMTP".
        pub(super) const SMTPS: u16 = 465;
        pub(super) const RTSP: u16 = 554;
        pub(super) const RTMP: u16 = 1935;
        pub(super) const RTMPT: u16 = HTTP;
        pub(super) const RTMPS: u16 = HTTPS;
        pub(super) const GOPHER: u16 = 70;
        pub(super) const MQTT: u16 = 1883;
        pub(super) const MQTTS: u16 = 8883;
        /// `file` has no default port. Not a sentinel: see
        /// [`super::super::SchemeInfo::defport`].
        pub(super) const NONE: u16 = 0;
    }

    /// Capability bits, transcribed from `lib/urldata.h` L526-L558.
    ///
    /// Only the bits the 33 descriptors actually set are reproduced, again
    /// under their C names so the `flags` words below can be diffed against
    /// the descriptors they came from. Note the hole: bit 9 was
    /// `PROTOPT_STREAM` and is retired, which `lib/urldata.h` L544 records, so
    /// `PROTOPT_URLOPTIONS` at bit 10 is not an off-by-one.
    ///
    /// `PROTOPT_URLOPTIONS` is deliberately absent from this list. It lives in
    /// `src/abi.rs`, because it is the one bit the URL API tests and it must
    /// have a single definition in the crate; it is re-exported here under its
    /// C name so the table's text stays uniform.
    mod protopt {
        pub(super) use crate::abi::PROTOPT_URLOPTIONS as URLOPTIONS;

        /// L526, "nothing extra".
        pub(super) const NONE: u32 = 0;
        /// L527, uses TLS.
        pub(super) const SSL: u32 = 1 << 0;
        /// L528, two connections.
        pub(super) const DUAL: u32 = 1 << 1;
        /// L529, needs action before the socket closes.
        pub(super) const CLOSEACTION: u32 = 1 << 2;
        /// L534, call the transfer functions regardless of socket state.
        pub(super) const DIRLOCK: u32 = 1 << 3;
        /// L535, does not use the network at all.
        pub(super) const NONETWORK: u32 = 1 << 4;
        /// L536, gets a default password when none is set.
        pub(super) const NEEDSPWD: u32 = 1 << 5;
        /// L538, cannot carry a URL query string.
        pub(super) const NOURLQUERY: u32 = 1 << 6;
        /// L540, credentials per request rather than per connection.
        pub(super) const CREDSPERREQUEST: u32 = 1 << 7;
        /// L543, set ALPN.
        pub(super) const ALPN: u32 = 1 << 8;
        /// L547, may go over an HTTP proxy as HTTP.
        pub(super) const PROXY_AS_HTTP: u32 = 1 << 11;
        /// L551, supports wildcard matching.
        pub(super) const WILDCARD: u32 = 1 << 12;
        /// L552, allows control bytes in the credentials.
        pub(super) const USERPWDCTRL: u32 = 1 << 13;
        /// L554, cannot proxy over TCP.
        pub(super) const NOTCPPROXY: u32 = 1 << 14;
        /// L555, may reuse a TLS connection in the same family.
        pub(super) const SSL_REUSE: u32 = 1 << 15;
        /// L558, can reuse connections.
        pub(super) const CONN_REUSE: u32 = 1 << 16;
    }

    /// One row of the built-in table: the three values a lookup can yield,
    /// plus the name it is found by.
    struct SchemeEntry {
        /// Transcribed verbatim from the descriptor, upper case included. See
        /// the module documentation: four of the 33 are spelled in upper case
        /// in the C and are left that way here on purpose.
        name: &'static [u8],
        /// The descriptor's `defport` initialiser.
        defport: u16,
        /// The descriptor's `flags` initialiser, in full.
        flags: u32,
    }

    /// How many schemes the table holds.
    ///
    /// 33, from the authoritative list at `scripts/schemetable.c` L33-L65,
    /// corroborated by there being exactly 33 `Curl_scheme_*` definitions in
    /// `lib/`. Naming it and using it as the array's length pins the count at
    /// compile time: adding or losing a row without updating this constant
    /// fails the build rather than the parity diff.
    const SCHEME_COUNT: usize = 33;

    /// The longest name any table row may have, from `lib/url.c` L1524.
    ///
    /// The C guards its hash with `len && (len <= 7)`, so a name longer than
    /// seven bytes could never be found no matter what the table held. Seven
    /// is exactly `gophers`. A test walks the table and fails if any row
    /// exceeds this, which is the drift check the guard itself cannot perform.
    const MAX_TABLE_NAME_LEN: usize = 7;

    /// What this backend reports for `h->run != NULL`.
    ///
    /// In the C, `run` is `ZERO_NULL` when the protocol was compiled out --
    /// `lib/file.c` L628-L632 is the pattern, an `#ifdef CURL_DISABLE_FILE`
    /// around the initialiser -- and `lib/urlapi.c` L1646 turns that into
    /// `CURLUE_UNSUPPORTED_SCHEME`.
    ///
    /// Standalone mode has no libcurl, so there is no protocol implementation
    /// to be present or absent and nothing for a `#ifdef` to have removed. The
    /// honest answer is therefore "yes" for every row, and the
    /// disabled-protocol path is simply unreachable in this mode rather than
    /// missing from it. Drop-in mode, which is the authoritative
    /// configuration, reads the real pointer and reaches that path exactly
    /// when the linked libcurl does.
    ///
    /// The consequence is worth stating plainly: in standalone mode
    /// `curl_url_set(u, CURLUPART_SCHEME, "rtmp", 0)` succeeds, where a
    /// libcurl built without librtmp would return
    /// `CURLUE_UNSUPPORTED_SCHEME`. No assertion in
    /// `tests/libtest/lib1560.c` depends on that difference: the only scheme
    /// it sets is `imaps`, at L1085, and the only ones it rejects are names no
    /// table holds at all.
    const IMPLEMENTED: bool = true;

    /// The 33 schemes, in the order of `scripts/schemetable.c` L33-L65.
    ///
    /// Each row's `defport` and `flags` are transcribed from that protocol
    /// module's own `const struct Curl_scheme` literal, with the file and line
    /// on the row, rather than inferred from the scheme's name or from its
    /// TLS-free sibling. That distinction is not pedantry: `imaps` sets
    /// `PROTOPT_SSL` and drops `PROTOPT_SSL_REUSE` relative to `imap`,
    /// `gophers` shares `gopher`'s port rather than having one of its own, and
    /// `rtmpe` takes `PORT_RTMP` while `rtmpt` takes `PORT_HTTP`. Every one of
    /// those would have been guessed wrong.
    static TABLE: [SchemeEntry; SCHEME_COUNT] = [
        // lib/dict.c L303-L314
        SchemeEntry {
            name: b"dict",
            defport: port::DICT,
            flags: protopt::NONE | protopt::NOURLQUERY,
        },
        // lib/file.c L626-L637. The only row with no default port.
        SchemeEntry {
            name: b"file",
            defport: port::NONE,
            flags: protopt::NONETWORK | protopt::NOURLQUERY,
        },
        // lib/ftp.c L4348-L4362
        SchemeEntry {
            name: b"ftp",
            defport: port::FTP,
            flags: protopt::DUAL
                | protopt::CLOSEACTION
                | protopt::NEEDSPWD
                | protopt::NOURLQUERY
                | protopt::PROXY_AS_HTTP
                | protopt::WILDCARD
                | protopt::SSL_REUSE
                | protopt::CONN_REUSE,
        },
        // lib/ftp.c L4367-L4380
        SchemeEntry {
            name: b"ftps",
            defport: port::FTPS,
            flags: protopt::SSL
                | protopt::DUAL
                | protopt::CLOSEACTION
                | protopt::NEEDSPWD
                | protopt::NOURLQUERY
                | protopt::WILDCARD
                | protopt::CONN_REUSE,
        },
        // lib/gopher.c L219-L230
        SchemeEntry {
            name: b"gopher",
            defport: port::GOPHER,
            flags: protopt::NONE,
        },
        // lib/gopher.c L232-L243. Shares gopher's port.
        SchemeEntry {
            name: b"gophers",
            defport: port::GOPHER,
            flags: protopt::SSL,
        },
        // lib/http.c L5011-L5023
        SchemeEntry {
            name: b"http",
            defport: port::HTTP,
            flags: protopt::CREDSPERREQUEST | protopt::USERPWDCTRL | protopt::CONN_REUSE,
        },
        // lib/http.c L5028-L5040
        SchemeEntry {
            name: b"https",
            defport: port::HTTPS,
            flags: protopt::SSL
                | protopt::CREDSPERREQUEST
                | protopt::ALPN
                | protopt::USERPWDCTRL
                | protopt::CONN_REUSE,
        },
        // lib/imap.c L2331-L2344
        SchemeEntry {
            name: b"imap",
            defport: port::IMAP,
            flags: protopt::CLOSEACTION
                | protopt::URLOPTIONS
                | protopt::SSL_REUSE
                | protopt::CONN_REUSE,
        },
        // lib/imap.c L2349-L2361
        SchemeEntry {
            name: b"imaps",
            defport: port::IMAPS,
            flags: protopt::CLOSEACTION | protopt::SSL | protopt::URLOPTIONS | protopt::CONN_REUSE,
        },
        // lib/ldap.c L1008-L1018
        SchemeEntry {
            name: b"ldap",
            defport: port::LDAP,
            flags: protopt::SSL_REUSE,
        },
        // lib/ldap.c L1024-L1034
        SchemeEntry {
            name: b"ldaps",
            defport: port::LDAPS,
            flags: protopt::SSL,
        },
        // lib/mqtt.c L1032-L1043
        SchemeEntry {
            name: b"mqtt",
            defport: port::MQTT,
            flags: protopt::NONE,
        },
        // lib/mqtt.c L1015-L1026
        SchemeEntry {
            name: b"mqtts",
            defport: port::MQTTS,
            flags: protopt::SSL,
        },
        // lib/pop3.c L1720-L1732
        SchemeEntry {
            name: b"pop3",
            defport: port::POP3,
            flags: protopt::CLOSEACTION
                | protopt::NOURLQUERY
                | protopt::URLOPTIONS
                | protopt::SSL_REUSE
                | protopt::CONN_REUSE,
        },
        // lib/pop3.c L1737-L1749
        SchemeEntry {
            name: b"pop3s",
            defport: port::POP3S,
            flags: protopt::CLOSEACTION
                | protopt::SSL
                | protopt::NOURLQUERY
                | protopt::URLOPTIONS
                | protopt::CONN_REUSE,
        },
        // lib/curl_rtmp.c L250-L261
        SchemeEntry {
            name: b"rtmp",
            defport: port::RTMP,
            flags: protopt::NONE,
        },
        // lib/curl_rtmp.c L263-L274
        SchemeEntry {
            name: b"rtmpt",
            defport: port::RTMPT,
            flags: protopt::NONE,
        },
        // lib/curl_rtmp.c L276-L287. Takes PORT_RTMP, not PORT_RTMPT.
        SchemeEntry {
            name: b"rtmpe",
            defport: port::RTMP,
            flags: protopt::NONE,
        },
        // lib/curl_rtmp.c L289-L300
        SchemeEntry {
            name: b"rtmpte",
            defport: port::RTMPT,
            flags: protopt::NONE,
        },
        // lib/curl_rtmp.c L302-L313
        SchemeEntry {
            name: b"rtmps",
            defport: port::RTMPS,
            flags: protopt::NONE,
        },
        // lib/curl_rtmp.c L315-L326
        SchemeEntry {
            name: b"rtmpts",
            defport: port::RTMPS,
            flags: protopt::NONE,
        },
        // lib/rtsp.c L1073-L1084
        SchemeEntry {
            name: b"rtsp",
            defport: port::RTSP,
            flags: protopt::CONN_REUSE,
        },
        // lib/vssh/vssh.c L352-L364. Upper case in the C.
        SchemeEntry {
            name: b"SCP",
            defport: port::SSH,
            flags: protopt::DIRLOCK
                | protopt::CLOSEACTION
                | protopt::NOURLQUERY
                | protopt::CONN_REUSE,
        },
        // lib/vssh/vssh.c L338-L350. Upper case in the C.
        SchemeEntry {
            name: b"SFTP",
            defport: port::SSH,
            flags: protopt::DIRLOCK
                | protopt::CLOSEACTION
                | protopt::NOURLQUERY
                | protopt::CONN_REUSE,
        },
        // lib/smb.c L1234-L1245
        SchemeEntry {
            name: b"smb",
            defport: port::SMB,
            flags: protopt::CONN_REUSE,
        },
        // lib/smb.c L1250-L1262
        SchemeEntry {
            name: b"smbs",
            defport: port::SMBS,
            flags: protopt::SSL | protopt::CONN_REUSE,
        },
        // lib/smtp.c L2012-L2024
        SchemeEntry {
            name: b"smtp",
            defport: port::SMTP,
            flags: protopt::CLOSEACTION
                | protopt::NOURLQUERY
                | protopt::URLOPTIONS
                | protopt::SSL_REUSE
                | protopt::CONN_REUSE,
        },
        // lib/smtp.c L2029-L2041
        SchemeEntry {
            name: b"smtps",
            defport: port::SMTPS,
            flags: protopt::CLOSEACTION
                | protopt::SSL
                | protopt::NOURLQUERY
                | protopt::URLOPTIONS
                | protopt::CONN_REUSE,
        },
        // lib/telnet.c L1597-L1608
        SchemeEntry {
            name: b"telnet",
            defport: port::TELNET,
            flags: protopt::NONE | protopt::NOURLQUERY,
        },
        // lib/tftp.c L1360-L1371
        SchemeEntry {
            name: b"tftp",
            defport: port::TFTP,
            flags: protopt::NOTCPPROXY | protopt::NOURLQUERY,
        },
        // lib/ws.c L1984-L1996. Upper case in the C, and it borrows
        // PORT_HTTP rather than declaring a port of its own.
        SchemeEntry {
            name: b"WS",
            defport: port::HTTP,
            flags: protopt::CREDSPERREQUEST | protopt::USERPWDCTRL,
        },
        // lib/ws.c L1999-L2011. Upper case in the C.
        SchemeEntry {
            name: b"WSS",
            defport: port::HTTPS,
            flags: protopt::SSL | protopt::CREDSPERREQUEST | protopt::USERPWDCTRL,
        },
    ];

    /// `Curl_get_scheme`, standalone: forward to the length-delimited form
    /// exactly as `lib/url.c` L1469-L1472 does.
    pub(super) fn get_scheme(scheme: &CStr) -> Option<SchemeInfo> {
        // `CStr::to_bytes` excludes the terminator, so its length is the
        // `strlen(scheme)` the C passes.
        getn_scheme(scheme.to_bytes())
    }

    /// `Curl_getn_scheme`, standalone.
    ///
    /// A linear scan rather than the C's perfect hash. The hash exists to keep
    /// the C's 67-slot table small and its lookup branch-free; it is not part
    /// of the contract, and reproducing it would mean reproducing a table
    /// generated by `scripts/schemetable.c` that has to be regenerated by hand
    /// whenever a scheme is added. What has to be reproduced is the *matching
    /// rule*, and that is the guard and the comparison below.
    pub(super) fn getn_scheme(name: &[u8]) -> Option<SchemeInfo> {
        // `if(len && (len <= 7))` at lib/url.c L1524. Both halves matter: an
        // empty name is rejected, and so is one longer than the longest name
        // the table can hold.
        if name.is_empty() || name.len() > MAX_TABLE_NAME_LEN {
            return None;
        }
        // `curl_strnequal(scheme, h->name, len) && !h->name[len]` at L1537.
        // `eq_ignore_case` requires equal lengths, which is what the second
        // half of that condition establishes, and folds ASCII case, which is
        // what the first half does.
        //
        // A slice with an interior NUL matches nothing here, because no table
        // name contains one. The C would stop its comparison at that NUL and
        // then read `h->name[len]` past the literal's terminator; the path is
        // unreachable through `get_scheme`, whose length comes from `strlen`,
        // so the two agree wherever the URL API can actually get to.
        TABLE
            .iter()
            .find(|entry| eq_ignore_case(name, entry.name))
            .map(|entry| SchemeInfo {
                flags: entry.flags,
                defport: entry.defport,
                implemented: IMPLEMENTED,
            })
    }

    #[cfg(test)]
    mod tests {
        use super::{MAX_TABLE_NAME_LEN, SCHEME_COUNT, TABLE};
        use crate::abi::{MAX_SCHEME_LEN, PROTOPT_URLOPTIONS};
        use crate::ctype::eq_ignore_case;
        use crate::scheme::{get_scheme, getn_scheme, SchemeInfo};
        use core::ffi::CStr;

        /// Every scheme name and its default port, derived from
        /// `lib/urldata.h` L29-L53 rather than from the table above.
        ///
        /// The point of restating them is that the expectation must not share
        /// a derivation with the thing it checks. These are the numbers the
        /// `PORT_*` macros expand to, written as decimal literals against
        /// lower-case names, where the table is written as macro names against
        /// verbatim -- sometimes upper-case -- names. A transcription slip has
        /// to be made twice, in two different notations, to survive.
        const NAMES_AND_PORTS: [(&[u8], u16); SCHEME_COUNT] = [
            (b"dict", 2628),
            (b"file", 0),
            (b"ftp", 21),
            (b"ftps", 990),
            (b"gopher", 70),
            (b"gophers", 70),
            (b"http", 80),
            (b"https", 443),
            (b"imap", 143),
            (b"imaps", 993),
            (b"ldap", 389),
            (b"ldaps", 636),
            (b"mqtt", 1883),
            (b"mqtts", 8883),
            (b"pop3", 110),
            (b"pop3s", 995),
            (b"rtmp", 1935),
            (b"rtmpt", 80),
            (b"rtmpe", 1935),
            (b"rtmpte", 80),
            (b"rtmps", 443),
            (b"rtmpts", 443),
            (b"rtsp", 554),
            (b"scp", 22),
            (b"sftp", 22),
            (b"smb", 445),
            (b"smbs", 445),
            (b"smtp", 25),
            (b"smtps", 465),
            (b"telnet", 23),
            (b"tftp", 69),
            (b"ws", 80),
            (b"wss", 443),
        ];

        /// The nine features `tests/data/test1560` declares. Below this
        /// coverage, scheme-dependent assertions in
        /// `tests/libtest/lib1560.c` diverge for reasons that have nothing to
        /// do with the port.
        const REQUIRED_BY_TEST1560: [&[u8]; 9] = [
            b"file", b"https", b"http", b"pop3", b"smtp", b"imap", b"ldap", b"dict", b"ftp",
        ];

        /// The six schemes whose descriptors set `PROTOPT_URLOPTIONS`, from
        /// `lib/imap.c` L2340 and L2358, `lib/pop3.c` L1729 and L1746, and
        /// `lib/smtp.c` L2021 and L2038. Each TLS variant was read separately
        /// rather than assumed to match its plain sibling.
        const WITH_URL_OPTIONS: [&[u8]; 6] =
            [b"imap", b"imaps", b"pop3", b"pop3s", b"smtp", b"smtps"];

        /// Builds a `&CStr` from a byte literal that ends in NUL.
        ///
        /// `CStr::from_bytes_with_nul` returns a `Result`, and the crate root
        /// denies both `unwrap` and `expect`, so the assertion below stands in
        /// for them: it is the checked constructor's own test, reported as a
        /// test failure rather than swallowed.
        fn cstr(terminated: &[u8]) -> &CStr {
            assert!(
                CStr::from_bytes_with_nul(terminated).is_ok(),
                "test literal must end in exactly one NUL and hold no other"
            );
            // SAFETY: the assertion above is precisely
            // `from_bytes_with_nul`'s precondition -- one terminating NUL and
            // no interior one -- so reaching this line means it holds.
            unsafe { CStr::from_bytes_with_nul_unchecked(terminated) }
        }

        /// Renders a scheme name for an assertion message.
        ///
        /// Written against `core` rather than reaching for `alloc`, so that
        /// this module stays as portable as the code it tests. Every name below
        /// is ASCII, so the fallback never appears; it exists so the helper
        /// cannot fail and needs no panicking construct.
        fn shown(name: &[u8]) -> &str {
            core::str::from_utf8(name).unwrap_or("(not UTF-8)")
        }

        /// The guard in `getn_scheme` is only correct while no row exceeds it,
        /// and the C's own `len <= 7` has the same precondition. Checked here
        /// because a `const` proof would need to index the table, which the
        /// crate's lint policy forbids.
        #[test]
        fn no_table_name_exceeds_the_c_length_bound() {
            for entry in &TABLE {
                assert!(
                    !entry.name.is_empty(),
                    "a table row has an empty name, which no lookup could ever find"
                );
                assert!(
                    entry.name.len() <= MAX_TABLE_NAME_LEN,
                    "a table name is longer than the {MAX_TABLE_NAME_LEN} bytes \
                     lib/url.c:1524 allows, so no lookup could ever find it"
                );
            }
            // And the bound is tight: dropping it below seven would lose
            // `gophers`, so this pins it from the other side too.
            assert!(
                TABLE
                    .iter()
                    .any(|entry| entry.name.len() == MAX_TABLE_NAME_LEN),
                "no table name is exactly {MAX_TABLE_NAME_LEN} bytes, so the bound is too loose"
            );
        }

        /// Two rows with the same name would make the linear scan's result
        /// depend on row order, where the C's perfect hash has one slot per
        /// name and cannot express a duplicate at all.
        #[test]
        fn every_table_name_is_distinct_ignoring_case() {
            for (position, entry) in TABLE.iter().enumerate() {
                let duplicates = TABLE
                    .iter()
                    .filter(|other| eq_ignore_case(entry.name, other.name))
                    .count();
                assert_eq!(
                    duplicates, 1,
                    "row {position} shares its name with another row, ignoring case"
                );
            }
            assert_eq!(TABLE.len(), SCHEME_COUNT);
        }

        /// All 33 names resolve, through both entry points, and report the
        /// default port `lib/urldata.h` gives them.
        #[test]
        fn every_scheme_resolves_with_its_documented_default_port() {
            for (name, port) in NAMES_AND_PORTS {
                let found = getn_scheme(name);
                assert!(
                    found.is_some(),
                    "{} is in scripts/schemetable.c but not in this table",
                    shown(name)
                );
                assert_eq!(
                    found.map(SchemeInfo::defport),
                    Some(port),
                    "wrong default port for {}",
                    shown(name)
                );
            }
            // The expectation list must cover the table rather than a subset
            // of it, or a row could be wrong without any of this noticing.
            assert_eq!(NAMES_AND_PORTS.len(), TABLE.len());
        }

        /// The nine schemes `tests/data/test1560` requires, called out
        /// separately so a failure names the gate that would break.
        #[test]
        fn the_nine_schemes_test1560_requires_are_all_present() {
            for name in REQUIRED_BY_TEST1560 {
                let expected = NAMES_AND_PORTS
                    .iter()
                    .find(|(candidate, _)| eq_ignore_case(name, candidate))
                    .map(|(_, port)| *port);
                assert!(
                    expected.is_some(),
                    "{} is required by tests/data/test1560 and is not even in \
                     the expectation list",
                    shown(name)
                );
                assert_eq!(
                    getn_scheme(name).map(SchemeInfo::defport),
                    expected,
                    "tests/data/test1560 requires {}",
                    shown(name)
                );
            }
        }

        /// `file` is the one row with no default port, and the zero is
        /// load-bearing: `lib/urlapi.c` L1440-L1447 serialises a file URL
        /// through a branch of its own, and the port logic must not inject a
        /// default underneath it.
        #[test]
        fn file_has_no_default_port_and_carries_its_two_flags() {
            let found = getn_scheme(b"file");
            assert_eq!(found.map(SchemeInfo::defport), Some(0), "lib/file.c:636");
            // PROTOPT_NONETWORK is bit 4 and PROTOPT_NOURLQUERY is bit 6, so
            // the word is 0x50. Spelled as a mask rather than as the two names
            // the table uses, so the two derivations stay independent.
            assert_eq!(found.map(SchemeInfo::flags), Some(0x0050), "lib/file.c:635");
            assert_eq!(found.map(SchemeInfo::has_url_options), Some(false));
        }

        /// `PROTOPT_URLOPTIONS` belongs to exactly six schemes. Checked over
        /// the whole table, not just over the six, because a stray bit
        /// elsewhere would change how `lib/urlapi.c` L290 splits credentials
        /// for that scheme.
        #[test]
        fn url_options_belongs_to_exactly_the_six_mail_schemes() {
            for (name, _) in NAMES_AND_PORTS {
                let expected = WITH_URL_OPTIONS
                    .iter()
                    .any(|mail| eq_ignore_case(name, mail));
                assert_eq!(
                    getn_scheme(name).map(SchemeInfo::has_url_options),
                    Some(expected),
                    "PROTOPT_URLOPTIONS is wrong for {}",
                    shown(name)
                );
            }
            // Three non-mail schemes named explicitly, so that a regression
            // that set the bit everywhere could not pass by making
            // `expected` true everywhere as well.
            for name in [b"http".as_slice(), b"https".as_slice(), b"ftp".as_slice()] {
                assert_eq!(
                    getn_scheme(name).map(SchemeInfo::has_url_options),
                    Some(false),
                    "{} must not carry PROTOPT_URLOPTIONS",
                    shown(name)
                );
            }
        }

        /// Spot checks on the whole `flags` word, against hexadecimal masks
        /// worked out from the bit positions rather than from the constant
        /// names the table uses.
        #[test]
        fn representative_flag_words_match_their_descriptors() {
            // SSL 0x1, CREDSPERREQUEST 0x80, ALPN 0x100, USERPWDCTRL 0x2000,
            // CONN_REUSE 0x10000. lib/http.c:5037-5038.
            assert_eq!(
                getn_scheme(b"https").map(SchemeInfo::flags),
                Some(0x0001_2181)
            );
            // CREDSPERREQUEST, USERPWDCTRL, CONN_REUSE. lib/http.c:5020-5021.
            assert_eq!(
                getn_scheme(b"http").map(SchemeInfo::flags),
                Some(0x0001_2080)
            );
            // The same two as http, without CONN_REUSE. lib/ws.c:1993-1994.
            assert_eq!(getn_scheme(b"ws").map(SchemeInfo::flags), Some(0x0000_2080));
            // DUAL 0x2, CLOSEACTION 0x4, NEEDSPWD 0x20, NOURLQUERY 0x40,
            // PROXY_AS_HTTP 0x800, WILDCARD 0x1000, SSL_REUSE 0x8000,
            // CONN_REUSE 0x10000. lib/ftp.c:4357-4360.
            assert_eq!(
                getn_scheme(b"ftp").map(SchemeInfo::flags),
                Some(0x0001_9866)
            );
            // CLOSEACTION, URLOPTIONS 0x400, SSL_REUSE, CONN_REUSE.
            // lib/imap.c:2339-2341.
            assert_eq!(
                getn_scheme(b"imap").map(SchemeInfo::flags),
                Some(0x0001_8404)
            );
            // PROTOPT_NONE, and nothing else at all. lib/gopher.c:227.
            assert_eq!(getn_scheme(b"gopher").map(SchemeInfo::flags), Some(0));
            // SSL_REUSE alone. lib/ldap.c:1015.
            assert_eq!(
                getn_scheme(b"ldap").map(SchemeInfo::flags),
                Some(0x0000_8000)
            );
            // The one bit the URL API reads has to be where abi.rs says.
            assert_eq!(PROTOPT_URLOPTIONS, 0x0400);
        }

        /// The matching rule established from `lib/url.c` L1531 and L1537 is
        /// case-insensitive, and both call paths depend on it: the parse path
        /// arrives lower-cased from `lib/urlapi.c` L214, while
        /// `curl_url_set(CURLUPART_SCHEME, ...)` at L1645 arrives as the
        /// caller typed it.
        #[test]
        fn lookup_folds_ascii_case_in_both_directions() {
            // A row stored lower case, asked for in upper and mixed case.
            let lower = getn_scheme(b"https");
            assert_eq!(getn_scheme(b"HTTPS"), lower);
            assert_eq!(getn_scheme(b"HtTpS"), lower);
            // And a row stored upper case in the C -- see the module
            // documentation -- asked for the way a URL would spell it. This is
            // the direction a case-sensitive port would fail, and it is not
            // hypothetical: `ws://` appears in tests/libtest/lib1560.c:296.
            let ws = getn_scheme(b"WS");
            assert!(ws.is_some());
            assert_eq!(getn_scheme(b"ws"), ws);
            assert_eq!(getn_scheme(b"Ws"), ws);
            assert_eq!(getn_scheme(b"scp"), getn_scheme(b"SCP"));
            assert_eq!(getn_scheme(b"sFtP"), getn_scheme(b"SFTP"));
        }

        /// Names no table row holds. `data`, `about` and `mailto` are the ones
        /// `tests/libtest/lib1560.c` L635-L640 expects
        /// `CURLUE_UNSUPPORTED_SCHEME` for, and `tp` is L789-L790.
        #[test]
        fn unknown_names_are_not_found() {
            for name in [
                b"tp".as_slice(),
                b"foo".as_slice(),
                b"data".as_slice(),
                b"d".as_slice(),
                b"about".as_slice(),
                b"mailto".as_slice(),
                b"example".as_slice(),
                // Neither is a scheme-table entry, although both appear in
                // curl's runtime protocol list.
                b"ipfs".as_slice(),
                b"ipns".as_slice(),
                // Prefixes and extensions of real names must not match, which
                // is what the length half of the comparison guarantees.
                b"http ".as_slice(),
                b"htt".as_slice(),
                b"httpss".as_slice(),
            ] {
                assert_eq!(
                    getn_scheme(name),
                    None,
                    "{} is not a scheme and must not resolve",
                    shown(name)
                );
            }
        }

        /// `if(len && ...)` at `lib/url.c` L1524: an empty name is rejected
        /// before the hash is computed.
        #[test]
        fn an_empty_name_is_not_found() {
            assert_eq!(getn_scheme(b""), None);
            assert_eq!(get_scheme(cstr(b"\0")), None);
        }

        /// Two length bounds, and they are different numbers.
        ///
        /// `lib/url.c` L1524 stops at seven bytes, which is the lookup's own
        /// bound and the one this module enforces. `MAX_SCHEME_LEN` is 40, from
        /// `lib/urlapi.c` L55, and is enforced by the caller instead:
        /// `set_url_scheme` rejects a longer scheme at L1641-L1643 *before*
        /// reaching the lookup. Both are checked, because a reader who knows
        /// only the 40 would expect a 39-byte name to reach the table.
        #[test]
        fn names_beyond_either_length_bound_are_not_found() {
            // Eight bytes: one past the lookup's own bound, and long enough
            // that no row could match it anyway.
            assert_eq!(getn_scheme(b"gopherss"), None);
            // Exactly one past MAX_SCHEME_LEN, which the lookup rejects for
            // the same reason it rejects eight.
            let overlong = [b'a'; 41];
            assert!(overlong.len() > MAX_SCHEME_LEN);
            assert_eq!(getn_scheme(&overlong), None);
            // And a name inside MAX_SCHEME_LEN but past the lookup's bound is
            // still not found, which is the point the two numbers make.
            let middling = [b'a'; 20];
            assert!(middling.len() < MAX_SCHEME_LEN);
            assert!(middling.len() > MAX_TABLE_NAME_LEN);
            assert_eq!(getn_scheme(&middling), None);
        }

        /// Standalone mode has no libcurl to have compiled a protocol out, so
        /// every row reports an implementation. `lib/urlapi.c` L1646 is
        /// therefore unreachable in this mode; drop-in mode reaches it exactly
        /// when the linked libcurl does.
        #[test]
        fn every_scheme_reports_an_implementation() {
            for (name, _) in NAMES_AND_PORTS {
                assert_eq!(
                    getn_scheme(name).map(SchemeInfo::implemented),
                    Some(true),
                    "{} must report an implementation in standalone mode",
                    shown(name)
                );
            }
        }

        /// `Curl_get_scheme` is `Curl_getn_scheme(scheme, strlen(scheme))` and
        /// nothing else, so the two entry points must never disagree.
        #[test]
        fn the_two_entry_points_agree() {
            for (terminated, name) in [
                (b"https\0".as_slice(), b"https".as_slice()),
                (b"file\0".as_slice(), b"file".as_slice()),
                (b"gophers\0".as_slice(), b"gophers".as_slice()),
                (b"WS\0".as_slice(), b"WS".as_slice()),
                (b"nope\0".as_slice(), b"nope".as_slice()),
            ] {
                assert_eq!(
                    get_scheme(cstr(terminated)),
                    getn_scheme(name),
                    "the two entry points disagree about {}",
                    shown(name)
                );
            }
        }
    }
}

/// The drop-in backend: libcurl's own `Curl_get_scheme` is imported.
///
/// Selected when the `scheme-table` feature is off, which is the drop-in and
/// authoritative configuration. This is the only module in the crate outside
/// `src/ffi.rs`, `src/alloc.rs`, `src/inet.rs` and `src/idn.rs` that contains
/// `unsafe`, and every block carries a safety comment.
///
/// Note what is *not* here: no definition of `Curl_get_scheme`. The crate
/// imports it, so the archive must show the symbol as undefined rather than
/// defined, or the drop-in link acquires a duplicate of a symbol `lib/url.c`
/// already provides and `scripts/check-abi.sh` reports an export the C object
/// file does not have.
#[cfg(not(feature = "scheme-table"))]
mod backend {
    use super::SchemeInfo;
    use core::ffi::CStr;
    use core::mem;
    use libc::{c_char, c_void, size_t};

    /// Mirror of `struct Curl_scheme` at `lib/urldata.h` L515-L524.
    ///
    /// The field order is the C's, and it is not negotiable: this structure is
    /// never constructed here, only read through a pointer libcurl handed
    /// back, so the offsets are the whole contract. `name`, `protocol` and
    /// `family` are described even though nothing reads them, because the
    /// three fields that *are* read sit after them and cannot be located
    /// otherwise.
    ///
    /// # THE LAYOUT HAZARD
    ///
    /// `protocol` and `family` are `curl_prot_t`, and `curl_prot_t` is
    /// **conditional**:
    ///
    /// ```text
    /// lib/urldata.h:81   /* This should be undefined once we need bit 32 or higher */
    /// lib/urldata.h:82   #define PROTO_TYPE_SMALL
    /// lib/urldata.h:84   #ifndef PROTO_TYPE_SMALL
    /// lib/urldata.h:85   typedef curl_off_t curl_prot_t;
    /// lib/urldata.h:87   typedef uint32_t curl_prot_t;
    /// ```
    ///
    /// So `u32` above is correct only while `PROTO_TYPE_SMALL` is defined in
    /// the libcurl being linked against. If it is ever undefined the two
    /// fields become 64-bit and **every field after them shifts**, which is
    /// exactly the pair of fields this module reads. A reviewer who notices
    /// that `protocol` and `family` are never read may conclude their width
    /// does not matter. It matters more than any other line in this file:
    /// `flags` and `defport` are located by it, and getting it wrong does not
    /// fail to compile, it silently returns another field's bytes as a default
    /// port.
    ///
    /// This is not a hypothetical. `lib/urldata.h` L71 already defines
    /// `CURLPROTO_WSS` as `((curl_prot_t)1 << 31)`, so bit 31 is taken and the
    /// header is one protocol away from the condition its own comment
    /// describes.
    ///
    /// Two things guard the assumption, and it is worth being precise about
    /// what each one can do.
    ///
    /// [`LAYOUT_PROOF`] pins *this* structure to the shape the port assumes,
    /// at compile time. It catches an edit here -- a reordered field, a
    /// widened integer, a `#[repr(C)]` accidentally dropped. It cannot observe
    /// the C side at all: no assertion written in Rust can read
    /// `lib/urldata.h`. The 32-bit `curl_prot_t` is therefore a documented
    /// *precondition* of drop-in mode rather than a checked one, and belongs
    /// with the other documented limitations of that mode in
    /// `docs/KNOWN-DIVERGENCES.md`.
    ///
    /// The live cross-check is the parity run. `tests/libtest/lib1560.c`
    /// asserts default ports directly -- `https://127.0.0.1` with
    /// `CURLU_DEFAULT_PORT` must yield `443` at L592-L594, and
    /// `http://example.com:80` with `CURLU_NO_DEFAULT_PORT` must serialise
    /// without the port at L786-L788 -- and both readings come through
    /// `defport`. A shifted mirror fails them on the first sub-test rather
    /// than subtly, which is the outcome to want.
    #[repr(C)]
    struct CurlScheme {
        /// L516, "URL scheme name in lowercase" -- which four descriptors
        /// disregard, as the module documentation records. Never read: the
        /// lookup is by name and libcurl has already done the comparing.
        name: *const c_char,
        /// L517, `const struct Curl_protocol *`, the implementation.
        ///
        /// Modelled as an opaque pointer because it is only ever tested for
        /// null. `struct Curl_protocol` is a 30-odd member function table at
        /// `lib/urldata.h` L400-L513 and describing it would add a large
        /// second ABI contract for no gain.
        run: *const c_void,
        /// L518-L519, `curl_prot_t`. Never read. See the layout hazard above:
        /// its width is load-bearing regardless.
        protocol: u32,
        /// L520-L521, `curl_prot_t`. Never read, same caveat.
        family: u32,
        /// L522, `uint32_t` of `PROTOPT_*` bits. Read, for
        /// `PROTOPT_URLOPTIONS`.
        flags: u32,
        /// L523, `uint16_t`. Read, as the scheme's default port.
        defport: u16,
    }

    // The names below are C identifiers and must stay exactly as libcurl
    // spells them, so the Rust naming convention cannot apply. Scoped to the
    // extern block, so nothing else in the module inherits the allowance.
    #[allow(non_snake_case)]
    extern "C" {
        /// `lib/url.c` L1469-L1472, declared at `lib/url.h` L76.
        ///
        /// Returns null for a name the table does not hold.
        fn Curl_get_scheme(scheme: *const c_char) -> *const CurlScheme;

        /// `lib/url.c` L1477-L1541, declared at `lib/url.h` L77.
        ///
        /// The length-delimited form `Curl_get_scheme` forwards to. `size_t`
        /// is `usize` on every platform this crate targets, which is what
        /// `libc::size_t` states.
        fn Curl_getn_scheme(scheme: *const c_char, len: size_t) -> *const CurlScheme;
    }

    /// The size [`CurlScheme`] must have, given a 32-bit `curl_prot_t`.
    ///
    /// Written as a table rather than as arithmetic, so that the padding
    /// reasoning is visible instead of encoded, and so that no arithmetic
    /// operator appears in a file the crate's lint policy holds to checked
    /// arithmetic.
    ///
    /// - 64-bit pointers: `name` 8 at 0, `run` 8 at 8, `protocol` 4 at 16,
    ///   `family` 4 at 20, `flags` 4 at 24, `defport` 2 at 28, then 2 bytes of
    ///   tail padding to the 8-byte alignment. 32 in total. A 64-bit
    ///   `curl_prot_t` would make it 40, so the check discriminates.
    /// - 32-bit pointers: `name` 4 at 0, `run` 4 at 4, `protocol` 4 at 8,
    ///   `family` 4 at 12, `flags` 4 at 16, `defport` 2 at 20, then 2 bytes of
    ///   tail padding to the 4-byte alignment. 24 in total, against 32 for the
    ///   wide variant.
    ///
    /// Any other pointer width is a platform this port has not reasoned about.
    /// Returning zero for it fails [`LAYOUT_PROOF`] outright, because no
    /// structure containing a pointer can be zero bytes, which is the intended
    /// outcome: refuse rather than guess.
    const fn expected_mirror_size() -> usize {
        match mem::size_of::<*const c_void>() {
            8 => 32,
            4 => 24,
            _ => 0,
        }
    }

    /// Compile-time proof that the mirror still has the layout the port
    /// assumes. See the hazard note on [`CurlScheme`] for what this does and
    /// does not establish.
    const LAYOUT_PROOF: () = {
        assert!(
            mem::size_of::<CurlScheme>() == expected_mirror_size(),
            "src/scheme.rs: the struct Curl_scheme mirror is not the size \
             lib/urldata.h:515-524 implies with a 32-bit curl_prot_t. Either \
             a field here was reordered, widened or narrowed, or the target \
             has an unexpected pointer width."
        );
        assert!(
            mem::align_of::<CurlScheme>() == mem::align_of::<*const c_void>(),
            "src/scheme.rs: the struct Curl_scheme mirror is not \
             pointer-aligned, so its first member is no longer a pointer and \
             every offset after it has moved."
        );
        assert!(
            mem::size_of::<u32>() == 4 && mem::size_of::<u16>() == 2,
            "src/scheme.rs: uint32_t and uint16_t are not 4 and 2 bytes, so \
             the flags and defport fields cannot be where lib/urldata.h puts \
             them."
        );
    };

    /// `Curl_get_scheme`, drop-in.
    pub(super) fn get_scheme(scheme: &CStr) -> Option<SchemeInfo> {
        // SAFETY: `Curl_get_scheme` reads its argument as a NUL-terminated C
        // string and does not retain it. `CStr::as_ptr` yields a non-null,
        // readable pointer to bytes that are NUL terminated by the type's own
        // invariant, and the borrow keeps them alive for the whole call, which
        // is longer than libcurl needs them: `lib/url.c` L1471 passes the
        // pointer to `strlen` and to `Curl_getn_scheme`, which compares it and
        // returns. Nothing is written through the pointer, matching the C's
        // `const char *`.
        let descriptor = unsafe { Curl_get_scheme(scheme.as_ptr()) };
        describe(descriptor)
    }

    /// `Curl_getn_scheme`, drop-in.
    pub(super) fn getn_scheme(name: &[u8]) -> Option<SchemeInfo> {
        // Reproduces the `len &&` half of the guard at `lib/url.c` L1524
        // before the call rather than after it, for a reason that is about
        // Rust and not about C: `<[u8]>::as_ptr` on an empty slice yields a
        // dangling pointer, which the C would never dereference -- it tests
        // `len` first -- but which has no business crossing the boundary at
        // all. The outcome is identical either way.
        if name.is_empty() {
            return None;
        }
        // SAFETY: the slice is non-empty, so `as_ptr` yields a pointer to
        // `name.len()` readable, initialised bytes, and the borrow keeps them
        // alive for the whole call. `len` is that same count, so libcurl reads
        // exactly the slice and never past it: `lib/url.c` L1529-L1534 walks
        // `len` bytes and L1537 compares `len` bytes. No terminator is needed
        // or assumed on this path, which is why the length-delimited entry
        // point exists. `u8` and `c_char` have the same size and alignment, so
        // the cast changes only the sign the compiler ascribes to the bytes,
        // and libcurl folds them through a 256-entry table that is total over
        // all byte values.
        let descriptor = unsafe { Curl_getn_scheme(name.as_ptr().cast::<c_char>(), name.len()) };
        describe(descriptor)
    }

    /// Turns the descriptor pointer libcurl returned into the safe, owned
    /// answer, so no raw pointer leaves this module.
    fn describe(descriptor: *const CurlScheme) -> Option<SchemeInfo> {
        // Forces the layout proof to be evaluated in every build. It emits no
        // code, and `describe` is on every path out of this backend, so the
        // proof cannot be compiled out of a configuration that uses the
        // mirror.
        let () = LAYOUT_PROOF;
        // The C's own test, at `lib/urlapi.c` L284 followed by L290, L951,
        // L1460 followed by L1465, L1589, L1598 and L1645: every one of the
        // six call sites checks the pointer before reading through it.
        if descriptor.is_null() {
            return None;
        }
        // SAFETY: the pointer is non-null, checked immediately above. libcurl
        // only ever returns `&Curl_scheme_<name>`, one of the 33 `const struct
        // Curl_scheme` objects with static storage duration listed in
        // `lib/url.c` L1488-L1522, so the referent outlives this call by the
        // whole program and is never written to by libcurl or by this crate --
        // which makes a shared reference sound and rules out any aliasing
        // conflict. The referent's layout matches `CurlScheme` under the
        // precondition documented on that type and pinned as far as Rust can
        // pin it by `LAYOUT_PROOF`. The reference is dropped before this
        // function returns; only copies of three scalar fields escape.
        let scheme = unsafe { &*descriptor };
        Some(SchemeInfo {
            flags: scheme.flags,
            defport: scheme.defport,
            // `!h->run` at `lib/urlapi.c` L1646, inverted: the C tests for
            // absence, this records presence.
            implemented: !scheme.run.is_null(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::{expected_mirror_size, CurlScheme, LAYOUT_PROOF};
        use crate::abi::PROTOPT_URLOPTIONS;
        use crate::scheme::{get_scheme, getn_scheme, SchemeInfo};
        use core::ffi::CStr;
        use core::mem;
        use core::ptr;
        use libc::{c_char, c_void, size_t};

        /// A `static const struct Curl_scheme` stand-in for libcurl's table.
        ///
        /// Drop-in mode imports `Curl_get_scheme` rather than defining it, so a
        /// test binary in this configuration has no libcurl to link against and
        /// the symbol would be undefined. The double below supplies it, which
        /// buys more than a working link: it exercises the real code path --
        /// the call, the null check and the dereference through the mirror --
        /// including the disabled-protocol case, which a real libcurl only
        /// produces for a protocol its build switched off.
        ///
        /// It is defined under `cfg(test)` and can therefore never reach the
        /// shipped archive, so `scripts/check-abi.sh` still sees
        /// `Curl_get_scheme` as an undefined symbol there.
        struct Descriptors([CurlScheme; 4]);

        // SAFETY: the array is immutable for the whole program and the only
        // pointers it holds are into `static` byte literals, so no thread can
        // observe it changing and none of its contents can be freed. That is
        // the same posture as libcurl's own table, whose entries are
        // `const struct Curl_scheme` objects with static storage duration.
        unsafe impl Sync for Descriptors {}

        /// One byte with static storage, used as a non-null `run` that is never
        /// dereferenced. `lib/urlapi.c` L1646 only tests the pointer, so any
        /// non-null value models an implemented protocol faithfully.
        static RUN_MARKER: u8 = 0;

        /// Four rows: two ordinary schemes, one with `PROTOPT_URLOPTIONS`, and
        /// one whose `run` is null the way `ZERO_NULL` leaves it at
        /// `lib/file.c` L629.
        static DESCRIPTORS: Descriptors = Descriptors([
            CurlScheme {
                name: b"https\0".as_ptr().cast::<c_char>(),
                run: (&RUN_MARKER as *const u8).cast::<c_void>(),
                protocol: 1 << 1,
                family: 1 << 0,
                // PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN |
                // PROTOPT_USERPWDCTRL | PROTOPT_CONN_REUSE, lib/http.c:5037.
                flags: 0x0001_2181,
                defport: 443,
            },
            CurlScheme {
                name: b"imap\0".as_ptr().cast::<c_char>(),
                run: (&RUN_MARKER as *const u8).cast::<c_void>(),
                protocol: 1 << 10,
                family: 1 << 10,
                // PROTOPT_CLOSEACTION | PROTOPT_URLOPTIONS |
                // PROTOPT_SSL_REUSE | PROTOPT_CONN_REUSE, lib/imap.c:2339.
                flags: 0x0001_8404,
                defport: 143,
            },
            CurlScheme {
                name: b"file\0".as_ptr().cast::<c_char>(),
                run: (&RUN_MARKER as *const u8).cast::<c_void>(),
                protocol: 1 << 9,
                family: 1 << 9,
                // PROTOPT_NONETWORK | PROTOPT_NOURLQUERY, lib/file.c:635.
                flags: 0x0050,
                defport: 0,
            },
            CurlScheme {
                // A protocol whose module compiled its implementation out.
                name: b"rtmp\0".as_ptr().cast::<c_char>(),
                run: ptr::null(),
                protocol: 1 << 19,
                family: 1 << 19,
                flags: 0,
                defport: 1935,
            },
        ]);

        /// Case-insensitive lookup over the double, matching `Curl_getn_scheme`
        /// at `lib/url.c` L1524-L1540 in rule if not in mechanism.
        fn find(name: &[u8]) -> *const CurlScheme {
            if name.is_empty() || name.len() > 7 {
                return ptr::null();
            }
            for descriptor in &DESCRIPTORS.0 {
                // SAFETY: every `name` above is a byte literal ending in
                // exactly one NUL, so the pointer stored in the row is a valid
                // NUL-terminated C string with static lifetime.
                let stored = unsafe { CStr::from_ptr(descriptor.name) };
                if crate::ctype::eq_ignore_case(name, stored.to_bytes()) {
                    return descriptor;
                }
            }
            ptr::null()
        }

        /// Stands in for `lib/url.c` L1469-L1472 while the crate's own tests
        /// run.
        #[no_mangle]
        extern "C" fn Curl_get_scheme(scheme: *const c_char) -> *const CurlScheme {
            if scheme.is_null() {
                return ptr::null();
            }
            // SAFETY: the only caller is `super::get_scheme`, which passes
            // `CStr::as_ptr`, so the pointer is non-null -- rechecked above in
            // any case -- and NUL terminated for the duration of the call.
            let name = unsafe { CStr::from_ptr(scheme) };
            find(name.to_bytes())
        }

        /// Stands in for `lib/url.c` L1477-L1541.
        #[no_mangle]
        extern "C" fn Curl_getn_scheme(scheme: *const c_char, len: size_t) -> *const CurlScheme {
            if scheme.is_null() || len == 0 {
                return ptr::null();
            }
            // SAFETY: the only caller is `super::getn_scheme`, which rejects an
            // empty slice and then passes that slice's pointer together with
            // its own length, so exactly `len` initialised bytes are readable
            // and they stay borrowed for the whole call. `c_char` and `u8`
            // share size and alignment.
            let name = unsafe { core::slice::from_raw_parts(scheme.cast::<u8>(), len) };
            find(name)
        }

        /// The compile-time proof has to actually be evaluated, and a test that
        /// references it says so out loud rather than relying on a reader
        /// spotting the binding inside `describe`.
        #[test]
        fn the_layout_proof_is_evaluated() {
            let () = LAYOUT_PROOF;
            assert_eq!(mem::size_of::<CurlScheme>(), expected_mirror_size());
            assert_eq!(
                mem::align_of::<CurlScheme>(),
                mem::align_of::<*const c_void>()
            );
        }

        /// The offsets the compile-time proof cannot express at this crate's
        /// minimum supported Rust version, `mem::offset_of!` having arrived in
        /// 1.77. Measured on a live value instead, which is exactly as
        /// authoritative and costs one stack slot in a test.
        ///
        /// These four numbers are the ABI contract. If `curl_prot_t` ever
        /// widens, `flags` and `defport` move and this test still passes --
        /// because it measures the Rust mirror, not the C original -- which is
        /// why the hazard is documented on [`CurlScheme`] as a precondition and
        /// cross-checked by the parity run rather than pretended to be checked
        /// here.
        #[test]
        fn mirror_field_offsets_are_where_the_c_layout_puts_them() {
            let probe = CurlScheme {
                name: ptr::null(),
                run: ptr::null(),
                protocol: 0,
                family: 0,
                flags: 0,
                defport: 0,
            };
            let base = (&probe as *const CurlScheme).cast::<u8>() as usize;
            let offset_of = |field: usize| field.wrapping_sub(base);
            let pointer = mem::size_of::<*const c_void>();

            assert_eq!(offset_of((&probe.name as *const *const c_char) as usize), 0);
            assert_eq!(
                offset_of((&probe.run as *const *const c_void) as usize),
                pointer,
                "run must follow name immediately"
            );
            assert_eq!(
                offset_of((&probe.protocol as *const u32) as usize),
                pointer.saturating_mul(2),
                "protocol must follow the two pointers"
            );
            assert_eq!(
                offset_of((&probe.family as *const u32) as usize),
                pointer.saturating_mul(2).saturating_add(4)
            );
            assert_eq!(
                offset_of((&probe.flags as *const u32) as usize),
                pointer.saturating_mul(2).saturating_add(8),
                "flags is read, so its offset is part of the ABI contract"
            );
            assert_eq!(
                offset_of((&probe.defport as *const u16) as usize),
                pointer.saturating_mul(2).saturating_add(12),
                "defport is read, so its offset is part of the ABI contract"
            );
        }

        /// The whole drop-in path: call, null check, dereference, and the three
        /// fields arriving in the right places rather than merely arriving.
        #[test]
        fn the_three_fields_are_read_through_the_mirror() {
            let https = getn_scheme(b"https");
            assert_eq!(https.map(SchemeInfo::defport), Some(443));
            assert_eq!(https.map(SchemeInfo::flags), Some(0x0001_2181));
            assert_eq!(https.map(SchemeInfo::implemented), Some(true));
            assert_eq!(https.map(SchemeInfo::has_url_options), Some(false));

            let imap = getn_scheme(b"imap");
            assert_eq!(imap.map(SchemeInfo::defport), Some(143));
            assert_eq!(imap.map(SchemeInfo::has_url_options), Some(true));
            assert_eq!(
                imap.map(|info| info.flags() & PROTOPT_URLOPTIONS),
                Some(PROTOPT_URLOPTIONS)
            );

            // The zero default port has to survive the trip as a zero and not
            // be confused with "not found".
            let file = getn_scheme(b"file");
            assert_eq!(file.map(SchemeInfo::defport), Some(0));
            assert!(file.is_some());
        }

        /// `!h->run` at `lib/urlapi.c` L1646. A protocol whose module compiled
        /// its implementation out is still found, and still reports that it
        /// cannot be driven.
        #[test]
        fn a_null_run_pointer_reports_a_disabled_protocol() {
            let rtmp = getn_scheme(b"rtmp");
            assert!(rtmp.is_some(), "a disabled protocol is still in the table");
            assert_eq!(rtmp.map(SchemeInfo::implemented), Some(false));
            assert_eq!(rtmp.map(SchemeInfo::defport), Some(1935));
        }

        /// A null descriptor is the C's "not a known scheme", and must never be
        /// dereferenced.
        #[test]
        fn a_null_descriptor_is_reported_as_not_found() {
            assert_eq!(getn_scheme(b"nope"), None);
            assert_eq!(super::describe(ptr::null()), None);
        }

        /// The empty slice is turned away before its pointer can cross the
        /// boundary, and the terminated entry point agrees.
        #[test]
        fn an_empty_name_never_reaches_the_c_lookup() {
            assert_eq!(getn_scheme(b""), None);
            // SAFETY: the literal is a single NUL byte, so it is a valid empty
            // C string with no interior NUL.
            let empty = unsafe { CStr::from_bytes_with_nul_unchecked(b"\0") };
            assert_eq!(get_scheme(empty), None);
        }

        /// Both entry points reach the same descriptor, as `Curl_get_scheme`
        /// forwarding to `Curl_getn_scheme` guarantees on the C side.
        #[test]
        fn the_two_entry_points_agree() {
            for (terminated, name) in [
                (b"https\0".as_slice(), b"https".as_slice()),
                (b"file\0".as_slice(), b"file".as_slice()),
                (b"rtmp\0".as_slice(), b"rtmp".as_slice()),
                (b"nope\0".as_slice(), b"nope".as_slice()),
            ] {
                // SAFETY: each literal above ends in exactly one NUL and holds
                // no interior NUL, by inspection.
                let scheme = unsafe { CStr::from_bytes_with_nul_unchecked(terminated) };
                assert_eq!(get_scheme(scheme), getn_scheme(name));
            }
        }
    }
}

/// Tests of the mode-independent surface, which needs no backend at all.
#[cfg(test)]
mod tests {
    use super::SchemeInfo;
    use crate::abi::PROTOPT_URLOPTIONS;

    /// The accessors return the three fields, and nothing reorders them. Worth
    /// its own test because both backends build this value by field name and a
    /// swap of two same-typed fields would otherwise go unnoticed in whichever
    /// backend the build did not select.
    #[test]
    fn the_accessors_return_the_three_fields() {
        let info = SchemeInfo {
            flags: 0x0001_8404,
            defport: 143,
            implemented: true,
        };
        assert_eq!(info.flags(), 0x0001_8404);
        assert_eq!(info.defport(), 143);
        assert!(info.implemented());

        let disabled = SchemeInfo {
            flags: 0,
            defport: 0,
            implemented: false,
        };
        assert_eq!(disabled.flags(), 0);
        assert_eq!(disabled.defport(), 0);
        assert!(!disabled.implemented());
    }

    /// `flags & PROTOPT_URLOPTIONS`, the one bit test `lib/urlapi.c` performs,
    /// at L290 and L1477.
    #[test]
    fn has_url_options_tests_bit_ten_and_no_other() {
        let info = |flags| SchemeInfo {
            flags,
            defport: 0,
            implemented: true,
        };
        assert!(info(PROTOPT_URLOPTIONS).has_url_options());
        assert!(info(0x0001_8404).has_url_options());
        assert!(!info(0).has_url_options());
        // Bit 9 is retired, per lib/urldata.h:544, and bit 11 is
        // PROTOPT_PROXY_AS_HTTP. Neither may be mistaken for bit 10.
        assert!(!info(1 << 9).has_url_options());
        assert!(!info(1 << 11).has_url_options());
        // Every other bit of the word set, and bit 10 clear.
        assert!(!info(!PROTOPT_URLOPTIONS).has_url_options());
        // And bit 10 set inside an otherwise full word.
        assert!(info(u32::MAX).has_url_options());
    }

    /// The value is small enough that copying it is the right choice, which is
    /// the reason the backends hand out an owned snapshot instead of a borrow
    /// of libcurl's descriptor.
    #[test]
    fn the_snapshot_stays_small_and_copyable() {
        let info = SchemeInfo {
            flags: 0,
            defport: 0,
            implemented: false,
        };
        let copy = info;
        assert_eq!(info, copy);
        assert!(core::mem::size_of::<SchemeInfo>() <= 8);
    }
}
