// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The owned handle that sits behind every `CURLU *`.
//!
//! This module is the port of `struct Curl_URL` at `lib/urlapi.c:L67-L82`,
//! of `free_urlhandle()` at `L86-L98`, of the `DUP` macro at `L1301-L1308`
//! and of `curl_url_dup()` at `L1310-L1332`. It also owns the store step at
//! `L1994-L1995`, where `curl_url_set()` releases a field's previous value
//! before overwriting it; getting that order wrong leaks on every repeated
//! set, so the operation lives here once rather than at each call site.
//!
//! # Layout freedom, which is what makes this port tractable
//!
//! `include/curl/urlapi.h:L107` declares
//!
//! ```c
//! typedef struct Curl_URL CURLU;
//! ```
//!
//! and never defines `struct Curl_URL`; the definition is private to
//! `lib/urlapi.c`. The type is therefore *incomplete* to every consumer:
//! nothing outside that one translation unit can take its size, read a
//! field, or copy it by value. Every caller holds only a `CURLU *`.
//!
//! The consequence is the single property that makes this port feasible:
//! the Rust structure below chooses **its own field order, its own field
//! types and its own padding**. There is deliberately no `#[repr(C)]`, no
//! size assertion and no attempt to mimic the C layout, because there is
//! nothing to mimic it for. Had the structure been public, the port would
//! have had to reproduce a C layout field for field before a single line of
//! behavior could be ported.
//!
//! The exception proves the rule, and it is worth naming because it is the
//! one place layout *would* have mattered. `tests/unit/unit1653.c:L37`
//! calls `Curl_parse_port()` directly, handing it a `CURLU *` together with
//! a `struct dynbuf *` the test constructed itself. Satisfying that test
//! from Rust would require bit-compatible interoperation with C's dynamic
//! buffer structure, a materially harder contract than anything the public
//! API demands. That test is out of scope, and `docs/PORTING-NOTES.md`
//! records it as a documented limitation of the drop-in, which is precisely
//! why no layout constraint reaches this file.
//!
//! # Fourteen fields, not ten
//!
//! A reader who knows the API expects ten heap strings. The structure has
//! four more members, at `lib/urlapi.c:L78-L81`: `portnum`, and the three
//! one-bit fields `query_present`, `fragment_present` and `guessed_scheme`.
//! They are not incidental: without them `CURLU_GET_EMPTY`,
//! `CURLU_NO_GUESS_SCHEME` and `CURLU_NO_DEFAULT_PORT` cannot behave
//! correctly. Each field below records which flag depends on it.
//!
//! # Ownership, stated once here and again at every field
//!
//! Every one of the ten strings is a buffer from the **C allocator**, held
//! by [`CBuf`], whose `Drop` releases it. That is what makes the teardown
//! below correct by construction rather than by a reader checking every
//! path, and it removes the failure-path leak class that `FB2` and `FB3` in
//! `docs/KNOWN-DIVERGENCES.md` record in the original.
//!
//! The boundary of that ownership is exactly where the header puts it.
//! `include/curl/urlapi.h:L116-L118` says `curl_url_cleanup()` frees the
//! handle and the resources it used, and that it "will not free strings
//! previously returned with the URL API". This type releases only what it
//! still owns, and the strings `curl_url_get()` hands back are not among
//! them: each one is a **separate buffer**, formatted or copied for that
//! one call, whose `curl_free()` obligation is the caller's from the moment
//! `CBuf::into_raw` returns the pointer. A handle field is never given
//! away, so cleanup here cannot reach a returned buffer -- not because it
//! carefully avoids one, but because it never held it.
//!
//! [`CurlUrl::take`] is the one operation that does move a field's buffer
//! out. It is used where the C module hands a field's block onward instead
//! of copying it, and it leaves the field absent, so the handle has
//! nothing left to release either way.
//!
//! # No raw pointers and no `unsafe`
//!
//! Raw-pointer operations are confined to `src/ffi.rs`, and
//! `#![forbid(unsafe_code)]` below makes that mechanical for this module.
//! Every ownership transition here is expressed in the type system --
//! `Option<CBuf>` fields, moves, and `Drop` -- so the borrow checker
//! enforces them rather than a convention.
//!
//! That split leaves `src/ffi.rs` one obligation this module cannot
//! discharge for it. `curl_url()` at `lib/urlapi.c:L1288-L1291` returns a
//! block from the C allocator, and `curl_url_cleanup()` at `L1293-L1299`
//! releases it with the C allocator, so the handle block itself has to come
//! from the C allocator rather than from a Rust `Box`. `src/ffi.rs`
//! therefore allocates `core::mem::size_of::<CurlUrl>()` bytes with its own
//! `c_calloc`, mirroring the `curlx_calloc()` the C uses, and writes a
//! [`CurlUrl::new`] value into the block; the allocation, the null check and
//! the write all live there, next to the `unsafe` the write needs and the
//! safety comment that justifies it.
//!
//! One trap in that arrangement deserves spelling out here, because it is
//! invisible from the facade side and it would corrupt the first handle a
//! caller ever obtains. Zeroing the block is not the same as initialising
//! it, so the write is not redundant with the `c_calloc`. The ten fields are
//! `Option<CBuf>`, and [`CBuf`] wraps a plain `*mut c_char` rather than a
//! `NonNull`, so `Option<CBuf>` has no null niche and the language
//! guarantees nothing about the bit pattern of its `None`. An all-zero block
//! is therefore not necessarily ten `None`s. [`CurlUrl::new`] is the only way
//! to obtain a valid empty handle, and it must be written into the block.
//!
//! # Two behaviors here are faithful reproductions, not mistakes
//!
//! [`CurlUrl::dup`] does not copy `guessed_scheme`, because
//! `curl_url_dup()` does not copy it. That is `FB1`, and the omission
//! carries the longest comment in this file so that nobody removes it by
//! accident. This module's own test module asserts that the divergence
//! survives, and `src/ffi.rs` asserts the same thing through the exported
//! `curl_url_dup` signature.
//!
//! `FB2` is not reproduced here but is visible from here.
//! `parse_hostname_login()` at `lib/urlapi.c:L328-L330` sets the handle's
//! user, password and options to null without releasing what they held.
//! That is harmless on the ordinary parse path *precisely because*
//! `parseurl_and_replace()` at `L1197-L1209` parses into a zeroed temporary
//! whose three fields are already null, and it is observable only on the
//! authority-setter path at `L658-L675`, which runs against a live handle
//! and which `lib/http2.c:L739` calls with one. `src/parse/authority.rs`
//! owns the finding; [`CurlUrl::replace`] carries the note from the
//! handle's side, because the temporary is this type. [`CurlUrl::clear`]
//! records which half of it this port reproduces.
//!
//! # A note on what this module does not import
//!
//! `crate::alloc` is the only module of this crate that this one imports
//! from; the sole other import is `core::fmt`, for [`StringField`]'s
//! `Display`. `src/abi.rs` is available and is deliberately unused: the
//! handle stores no ABI constant, and `DEFAULT_SCHEME` from
//! `lib/urlapi.c:L84`, which the module map in `docs/PORTING-NOTES.md`
//! lists under this file, is already defined in `src/abi.rs` alongside the
//! rest of the numeric contract. Duplicating it here would create a second
//! place for it to drift.
//!
//! # Thread safety
//!
//! [`CurlUrl`] contains [`CBuf`], which holds a raw pointer and is neither
//! `Send` nor `Sync`, so neither is this type. That matches the C original
//! exactly: a `CURLU` handle and its strings are not safe to share across
//! threads either.
//!
//! # See also
//!
//! `docs/MEMORY-OWNERSHIP.md` records the whole ownership chain, including
//! how `curl_free()` resolves and every allocation site in the C module.
//! `docs/KNOWN-DIVERGENCES.md` records `FB1` through `FB6`.
//! `docs/PORTING-NOTES.md` maps every C function to its Rust module.

// The handle is a foundation type whose consumers are `src/ffi.rs`,
// `src/getset.rs` and the modules under `src/parse/`, all of which exist.
// Which of the accessors below any one build reaches still depends on the
// selected feature set.
//
// Dead-code diagnostics are answered at the items. Where an item below has no
// production caller, it carries its own `#[allow(dead_code)]` with the reason
// it is kept immediately above it, and there is no crate-wide allowance to
// fall back on; see "DEAD-CODE POLICY" in `src/lib.rs` for the four outcomes
// that policy permits.

// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1).
// `forbid` rather than `deny` because an inner `allow` here would be a
// design change and should have to be argued for, not slipped in.
#![forbid(unsafe_code)]

use core::fmt;

use crate::alloc::CBuf;

/// Selects one of the handle's ten heap strings.
///
/// This is the port of the `char **storep` local in `curl_url_set()` at
/// `lib/urlapi.c:L1808`. The C dispatch at `L1828-L1875` points that
/// pointer at one of ten members and then, at `L1994-L1995`, releases the
/// old value and stores the new one through it. A pointer to a struct
/// member has no safe Rust equivalent, so the field is named by value here
/// and [`CurlUrl::field_mut`] resolves it. The result is the same
/// mechanism with none of the aliasing.
///
/// The variants are in the declaration order of `lib/urlapi.c:L68-L77`,
/// which is also the order `free_urlhandle()` releases them in at
/// `L88-L97`. It is *not* the order `curl_url_dup()` copies them in; see
/// [`CurlUrl::DUP_ORDER`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) enum StringField {
    /// `u->scheme`, `lib/urlapi.c:L68`.
    Scheme,
    /// `u->user`, `lib/urlapi.c:L69`.
    User,
    /// `u->password`, `lib/urlapi.c:L70`.
    Password,
    /// `u->options`, `lib/urlapi.c:L71`.
    Options,
    /// `u->host`, `lib/urlapi.c:L72`.
    Host,
    /// `u->zoneid`, `lib/urlapi.c:L73`.
    ZoneId,
    /// `u->port`, `lib/urlapi.c:L74`.
    Port,
    /// `u->path`, `lib/urlapi.c:L75`.
    Path,
    /// `u->query`, `lib/urlapi.c:L76`.
    Query,
    /// `u->fragment`, `lib/urlapi.c:L77`.
    Fragment,
}

impl StringField {
    /// Every variant, in the declaration order of `lib/urlapi.c:L68-L77`.
    ///
    /// [`CurlUrl::release_strings`] walks this to reproduce
    /// `free_urlhandle()` at `L86-L98`, and the test module walks it to
    /// assert that no field is left out of an operation that should cover
    /// all ten. Adding a field to the structure without adding it here is
    /// caught by the exhaustiveness of the matches in
    /// [`CurlUrl::field_mut`], which the compiler checks.
    // Never read outside the tests: `release_strings` spells the ten fields
    // out, one assignment per `Curl_safefree` at L86-L98, so that the
    // correspondence with the C is line for line. Retained because the tests
    // walk it to prove that no field is left out of an operation that should
    // cover all ten.
    #[allow(dead_code)]
    pub(crate) const ALL: [Self; 10] = [
        Self::Scheme,
        Self::User,
        Self::Password,
        Self::Options,
        Self::Host,
        Self::ZoneId,
        Self::Port,
        Self::Path,
        Self::Query,
        Self::Fragment,
    ];

    /// The C member name, for diagnostics and test failure messages.
    ///
    /// Spelled exactly as `lib/urlapi.c` spells it, so a message can be
    /// grepped for in the reference implementation.
    #[must_use]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Scheme => "scheme",
            Self::User => "user",
            Self::Password => "password",
            Self::Options => "options",
            Self::Host => "host",
            Self::ZoneId => "zoneid",
            Self::Port => "port",
            Self::Path => "path",
            Self::Query => "query",
            Self::Fragment => "fragment",
        }
    }
}

/// The internal representation of a `CURLU`, owning every string it holds.
///
/// The port of `struct Curl_URL` at `lib/urlapi.c:L67-L82`. Fourteen
/// members: ten C-allocator strings, one port number and three flags. The
/// C comment above the structure records that the strings point to
/// URL-encoded content, and that remains true here; nothing in this type
/// decodes or encodes anything.
///
/// # Not `Copy`, not `Clone`
///
/// Neither is derivable, because [`CBuf`] owns heap memory and a bitwise
/// copy would produce two owners of one allocation and then a double free.
/// [`CurlUrl::dup`] is the deliberate, fallible copy, and it is the port of
/// `curl_url_dup()` rather than a general-purpose clone: it reproduces that
/// function's behavior, including the member it does not copy.
///
/// The absence also matters at the boundary. The type is only ever handed
/// to C behind a pointer, and `src/ffi.rs` keeps it that way; making it
/// `Copy` would invite passing it by value across an FFI signature, which
/// would expose a layout this crate is free to change.
pub(crate) struct CurlUrl {
    /// `u->scheme` at `lib/urlapi.c:L68`.
    ///
    /// Owned C-allocator buffer, released by this type's `Drop`. Set from
    /// the parsed input at `L977`, from the literal `"file"` at `L838`, and
    /// from a guess at `L1004`.
    scheme: Option<CBuf>,
    /// `u->user` at `lib/urlapi.c:L69`.
    ///
    /// Owned C-allocator buffer, released by this type's `Drop`. Stored at
    /// `L306` after the previous value is released at `L305`.
    user: Option<CBuf>,
    /// `u->password` at `lib/urlapi.c:L70`.
    ///
    /// Owned C-allocator buffer, released by this type's `Drop`.
    password: Option<CBuf>,
    /// `u->options` at `lib/urlapi.c:L71`, whose C comment reads
    /// "IMAP only?".
    ///
    /// Owned C-allocator buffer, released by this type's `Drop`. Only ever
    /// populated for a scheme whose handler sets `PROTOPT_URLOPTIONS`,
    /// tested at `L290`, and suppressed on output at `L1477` otherwise.
    options: Option<CBuf>,
    /// `u->host` at `lib/urlapi.c:L72`.
    ///
    /// Owned C-allocator buffer, released by this type's `Drop`. The parse
    /// path hands over the dynamic buffer's block at `L1185`, and the
    /// authority setter replaces it at `L671-L672`.
    host: Option<CBuf>,
    /// `u->zoneid` at `lib/urlapi.c:L73`, "for numerical IPv6 addresses".
    ///
    /// Owned C-allocator buffer, released by this type's `Drop`. Assigned
    /// at `L418` when a bracketed address carries a `%`-delimited zone.
    /// `FB3` in `docs/KNOWN-DIVERGENCES.md` records that the C code neither
    /// releases a previous value there nor clears the field when a later
    /// host has no zone; the one path that clears it is the host setter at
    /// `L1848`.
    zoneid: Option<CBuf>,
    /// `u->port` at `lib/urlapi.c:L74`, the textual port.
    ///
    /// Owned C-allocator buffer, released by this type's `Drop`.
    /// Regenerated numerically at `L381` rather than copied, which is how
    /// leading zeroes are dropped, so it is always the decimal rendering of
    /// [`CurlUrl::portnum`] when both are set.
    port: Option<CBuf>,
    /// `u->path` at `lib/urlapi.c:L75`.
    ///
    /// Owned C-allocator buffer, released by this type's `Drop`. A handle
    /// with no path reads back as `"/"` at `L1606-L1607`, which is a
    /// property of the getter and not of this field: `None` here means
    /// absent, never `"/"`.
    path: Option<CBuf>,
    /// `u->query` at `lib/urlapi.c:L76`.
    ///
    /// Owned C-allocator buffer, released by this type's `Drop`. May hold a
    /// zero-length string, which is why [`CurlUrl::query_present`] exists
    /// as well; `L1059` stores exactly that for a bare `?`.
    query: Option<CBuf>,
    /// `u->fragment` at `lib/urlapi.c:L77`.
    ///
    /// Owned C-allocator buffer, released by this type's `Drop`. As with
    /// the query, absence and emptiness are different states and
    /// [`CurlUrl::fragment_present`] distinguishes them.
    fragment: Option<CBuf>,
    /// `u->portnum` at `lib/urlapi.c:L78`, "the numerical version".
    ///
    /// `unsigned short` in C, so `u16` here, and the width mirrors the
    /// domain the C validates rather than being an arbitrary choice. The
    /// value is range-checked to `0xffff` at `L375` before being assigned
    /// from a `curl_off_t` through an explicit `(unsigned short)` cast at
    /// `L378` and `L1681`, and it is compared against a scheme's `defport`,
    /// itself 16 bits wide, at `L1472` and `L1599`. `u16` is therefore the
    /// exact type of the values that can arrive here.
    portnum: u16,
    /// `u->query_present` at `lib/urlapi.c:L79`, "to support blank".
    ///
    /// `BIT(x)` expands to `curl_bit x:1` at `lib/curl_setup.h:L1039`, a
    /// one-bit bitfield in an `unsigned int`. A plain `bool` is the correct
    /// equivalent here precisely because layout is free: `CURLU` is an
    /// incomplete type at `include/curl/urlapi.h:L107`, so no C caller can
    /// take this structure's size or read a field, and whether the three
    /// flags occupy three bytes or three bits is invisible across the ABI.
    /// Packing them into a bit-flags type would add a dependency for no
    /// observable difference.
    ///
    /// Set at `L1039` when a `?` was seen and at `L1865` when the query is
    /// assigned, cleared at `L1767` when the query is cleared. Read at
    /// exactly one place, `L1435`, inside the `show_query` computation that
    /// spans `L1434-L1435`, and only under `CURLU_GET_EMPTY`. Note that the
    /// query getter's own blank-query suppression at `L1613-L1615` does
    /// *not* consult this bit; it tests the stored string's first byte.
    query_present: bool,
    /// `u->fragment_present` at `lib/urlapi.c:L80`, "to support blank".
    ///
    /// Set at `L1016` when a `#` was seen and at `L1869` when the fragment
    /// is assigned, cleared at `L1771`. Read at `L1433`, inside the
    /// `show_fragment` computation that spans `L1432-L1433`, and at `L1620`,
    /// where an absent-but-present fragment is reported as `""`. Both reads
    /// are under `CURLU_GET_EMPTY`.
    fragment_present: bool,
    /// `u->guessed_scheme` at `lib/urlapi.c:L81`, "when a URL without
    /// scheme is parsed".
    ///
    /// Set at `L1008`, the last statement of `guess_scheme()`, and cleared
    /// at `L1662` when a scheme is assigned explicitly and at `L1741` when
    /// the scheme is cleared. Read at `L1512` to decide whether the whole
    /// URL carries a `scheme://` prefix and at `L1559` to decide whether
    /// reading the scheme answers `CURLUE_NO_SCHEME`; both are gated on
    /// `CURLU_NO_GUESS_SCHEME`.
    ///
    /// This is the member `curl_url_dup()` fails to copy. See
    /// [`CurlUrl::dup`], which reproduces the omission on purpose.
    guessed_scheme: bool,
}

impl CurlUrl {
    /// The order `curl_url_dup()` copies the ten strings in.
    ///
    /// `lib/urlapi.c:L1314-L1323`, one `DUP()` invocation per line. It is
    /// **not** the declaration order in [`StringField::ALL`]: `port`
    /// precedes `path`, and `zoneid` comes last rather than sixth.
    ///
    /// The difference is invisible in a successful duplication and is
    /// exactly what is visible in a failing one. Each copy is an
    /// allocation, and the first that fails abandons the whole operation,
    /// so under memory pressure *which* fields the abandoned copy had
    /// already populated is determined by this order. Reproducing it costs
    /// one array and keeps the failure behavior identical.
    const DUP_ORDER: [StringField; 10] = [
        StringField::Scheme,
        StringField::User,
        StringField::Password,
        StringField::Options,
        StringField::Host,
        StringField::Port,
        StringField::Path,
        StringField::Query,
        StringField::Fragment,
        StringField::ZoneId,
    ];

    /// An empty handle: ten absent strings, port number zero, flags clear.
    ///
    /// The port of `curl_url()` at `lib/urlapi.c:L1288-L1291`, whose whole
    /// body is `curlx_calloc(1, sizeof(struct Curl_URL))`. The zeroing is
    /// the contract, not an implementation detail: every parse stage and
    /// every getter is written on the assumption that an untouched field
    /// reads as absent.
    ///
    /// This is infallible and allocates nothing, which is the difference
    /// between it and the C function. `curl_url()` can fail because it
    /// allocates the block that holds the structure; obtaining the value
    /// that goes *into* that block cannot fail. `src/ffi.rs` owns the
    /// allocation and reports its failure with a null return, as the module
    /// documentation above sets out.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            scheme: None,
            user: None,
            password: None,
            options: None,
            host: None,
            zoneid: None,
            port: None,
            path: None,
            query: None,
            fragment: None,
            portnum: 0,
            query_present: false,
            fragment_present: false,
            guessed_scheme: false,
        }
    }

    /// Releases all ten strings and leaves each field absent.
    ///
    /// The port of `free_urlhandle()` at `lib/urlapi.c:L86-L98`, in that
    /// function's own order, `L88` through `L97`. Assigning `None` runs
    /// [`CBuf`]'s `Drop`, which is the `curlx_free()` each of those ten
    /// lines performs.
    ///
    /// It releases only what the handle still owns. A string returned by
    /// `curl_url_get()` is a separate buffer built for that call, never a
    /// field of this structure, so this cannot reach one: that is the
    /// header's promise at `include/curl/urlapi.h:L116-L118` that cleanup
    /// does not free strings previously returned with the URL API, and it
    /// holds because the handle never owned them.
    ///
    /// Private because the two callers are the only two in C as well:
    /// `curl_url_cleanup()` at `L1296`, which is this type's `Drop`, and
    /// `urlset_clear(CURLUPART_URL)` at `L1736`, which is
    /// [`CurlUrl::reset`].
    fn release_strings(&mut self) {
        self.scheme = None;
        self.user = None;
        self.password = None;
        self.options = None;
        self.host = None;
        self.zoneid = None;
        self.port = None;
        self.path = None;
        self.query = None;
        self.fragment = None;
    }

    /// Returns a populated handle to its freshly constructed state.
    ///
    /// The port of the `CURLUPART_URL` arm of `urlset_clear()` at
    /// `lib/urlapi.c:L1735-L1738`, which calls `free_urlhandle(u)` and then
    /// `memset(u, 0, sizeof(struct Curl_URL))`. Both halves are here: the
    /// call releases the ten strings, the `memset` clears the four
    /// remaining members, and this method does the two in that order.
    ///
    /// This is a reset **in place**, and it is deliberately distinct from
    /// `Drop`. The handle survives; only its contents go. `curl_url_set(u,
    /// CURLUPART_URL, NULL, 0)` reaches it through the null-part rule at
    /// `L1819-L1821`, and the caller still holds a usable handle
    /// afterwards, which is exactly what `clear_url()` at
    /// `tests/libtest/lib1560.c` relies on.
    pub(crate) fn reset(&mut self) {
        // free_urlhandle(u) at L1736.
        self.release_strings();
        // memset(u, 0, sizeof(struct Curl_URL)) at L1737, which clears the
        // four members `release_strings` does not touch. Spelled out member
        // by member rather than as `*self = Self::new()` because that
        // assignment would drop the displaced value and run `Drop`, and so
        // `release_strings`, a second time; harmless, but it would obscure
        // the one-to-one correspondence with the two C lines above. The
        // safety net against a member being added and forgotten is
        // elsewhere and is mechanical: `Self::new()` is a struct literal,
        // so a new member cannot compile without being named there, and
        // `field_mut` matches every variant exhaustively.
        self.portnum = 0;
        self.query_present = false;
        self.fragment_present = false;
        self.guessed_scheme = false;
    }

    /// Replaces the whole handle with a freshly parsed one, atomically.
    ///
    /// The port of the successful branch of `parseurl_and_replace()` at
    /// `lib/urlapi.c:L1197-L1209`. That function declares a local `CURLU`
    /// at `L1201`, zeroes it at `L1202`, parses into it at `L1203`, and
    /// only if the parse succeeded releases the live handle at `L1205` and
    /// copies the temporary over it at `L1206`. A failed parse frees the
    /// temporary at `L1188-L1191` and leaves the live handle untouched, so
    /// no partial mutation is ever observable.
    ///
    /// In Rust the whole pattern is one assignment. `*self = fresh` drops
    /// the value being overwritten, which releases its ten strings exactly
    /// as `free_urlhandle()` did, and then moves the new one into place.
    /// The atomicity the C code achieves by discipline the borrow checker
    /// here achieves by construction: a caller cannot even name a
    /// half-parsed handle, because `fresh` is a value it owns until this
    /// call consumes it.
    ///
    /// `src/parse/mod.rs` orchestrates the parse; this is only the
    /// mechanism, and it deliberately knows nothing about parsing.
    ///
    /// # A note on `FB2`, which is visible from here
    ///
    /// `parse_hostname_login()` reaches a shared exit label at
    /// `lib/urlapi.c:L323` that assigns null to the handle's user, password
    /// and options at `L328-L330` without releasing what they held, and
    /// that label is reached even on success, at `L273-L275`, for every URL
    /// with no credentials in it. It is harmless on the ordinary parse path
    /// for one reason only: the handle being parsed into is the zeroed
    /// temporary this method receives, whose three fields are already
    /// absent, so nothing is dropped on the floor. The finding is
    /// observable only against a live handle, which is what
    /// `Curl_url_set_authority()` at `L658-L675` operates on and what
    /// `lib/http2.c:L739` passes it. `src/parse/authority.rs` owns the
    /// reproduction; the note is here because the temporary is this type
    /// and the connection is otherwise invisible from this side.
    pub(crate) fn replace(&mut self, fresh: Self) {
        *self = fresh;
    }

    /// Duplicates the handle, reproducing `curl_url_dup()` exactly.
    ///
    /// The port of `lib/urlapi.c:L1310-L1332`. Takes `&self` and never
    /// `&mut self`, because `curl_url_dup()` is declared
    /// `CURLU *curl_url_dup(const CURLU *in)` at
    /// `include/curl/urlapi.h:L126`. That is a soundness matter rather than
    /// a style preference: `src/ffi.rs` receives a `*const CURLU` and must
    /// never form a mutable reference from it, so every read path, this one
    /// included, has to be expressible against a shared reference.
    ///
    /// # Returns
    ///
    /// `None` if any string copy fails to allocate, which is the port of
    /// the `fail:` label at `L1329-L1331`: that label calls
    /// `curl_url_cleanup(u)` on the partially populated copy and returns
    /// `NULL`. Here the partially populated copy is a local that the `?`
    /// operator drops on the way out, which releases whatever it had
    /// already copied. The caller sees a failure and no leak, and
    /// `curl_url_dup()`'s own contract, a null return meaning failure, is
    /// preserved.
    ///
    /// # FB1: `guessed_scheme` is not copied, and that is deliberate
    ///
    /// **Do not "fix" this.** The three scalar copies below are
    /// `lib/urlapi.c:L1324`, `L1325` and `L1326`, and they are all the
    /// scalar copies the C function performs. `guessed_scheme` at `L81` is
    /// a real member of the structure, set by `guess_scheme()` at `L1008`,
    /// and `curl_url_dup()` simply does not copy it, so neither does this.
    /// `docs/KNOWN-DIVERGENCES.md` catalogues it as `FB1` with measurements
    /// from the reference build.
    ///
    /// Two consequences are observable on the copy, and both need
    /// `CURLU_NO_GUESS_SCHEME` to appear at all:
    ///
    /// * Reading `CURLUPART_SCHEME` from the copy returns the guessed
    ///   scheme instead of `CURLUE_NO_SCHEME`, because the guard at
    ///   `lib/urlapi.c:L1559-L1560` tests the flag *and* the member, and on
    ///   the copy the member is false.
    /// * Reading `CURLUPART_URL` from the copy emits the `scheme://`
    ///   prefix instead of suppressing it, for the same reason, at
    ///   `L1512-L1515`.
    ///
    /// curl's own test suite cannot catch it, by construction rather than
    /// by luck. `urldup()` at `tests/libtest/lib1560.c:L1970-L2031` walks a
    /// table that includes the scheme-less `"example.com:1234"` at `L1985`
    /// and parses every entry with `CURLU_GUESS_SCHEME` at `L1998-L1999`,
    /// so the original really does have the bit set -- but it reads the
    /// whole URL back from both handles with a literal flag argument of `0`,
    /// at `L2004` and `L2008`, and compares the strings at `L2012`. With no
    /// flags the condition at `L1512` takes its first branch on both
    /// handles, both strings carry the prefix, and they match. The one flag
    /// that would expose the difference is the one the test never passes.
    ///
    /// A regression test in this module asserts the omission directly, and
    /// `src/ffi.rs` asserts it through the exported `curl_url_dup`, so
    /// "correcting" the line below fails both.
    #[must_use]
    pub(crate) fn dup(&self) -> Option<Self> {
        // curlx_calloc(1, sizeof(struct Curl_URL)) at L1312. The C code
        // tests the result for null and skips every copy if it failed;
        // here the value cannot fail to exist, and `src/ffi.rs` owns the
        // block allocation that can.
        let mut copy = Self::new();

        // The ten DUP() invocations at L1314-L1323, in their own order.
        // Each may abandon the whole duplication, which is the macro's
        // `goto fail` at L1306.
        for which in Self::DUP_ORDER {
            copy.dup_string(self, which)?;
        }

        // L1324-L1326: the three scalar members the C function copies.
        copy.portnum = self.portnum;
        copy.fragment_present = self.fragment_present;
        copy.query_present = self.query_present;

        // FB1. `copy.guessed_scheme` stays false however this handle was
        // built, because L1326 is the last copy `curl_url_dup()` makes:
        // L1327 closes the block and L1328 returns the new handle. There is
        // no fourth scalar copy to port. Reproduced on purpose; see this
        // method's documentation and `docs/KNOWN-DIVERGENCES.md`.

        Some(copy)
    }

    /// Copies one string from `from` into `self`, if `from` has it.
    ///
    /// The port of the `DUP` macro at `lib/urlapi.c:L1301-L1308`. The macro
    /// tests the source member at `L1303`, so an absent field is not an
    /// error and leaves the destination absent; it duplicates at `L1304`
    /// and jumps to `fail` at `L1306` when the duplication returns null.
    ///
    /// The C duplication is `curlx_strdup()`, which copies up to the first
    /// terminator. [`CBuf::from_slice`] over [`CBuf::as_bytes`] copies the
    /// buffer's logical length instead. The two agree for every string this
    /// crate can produce, because a field containing an interior zero byte
    /// would have to have come from input that `Curl_junkscan()` rejects at
    /// `lib/urlapi.c:L223-L246`; where they would differ, this one loses no
    /// data.
    ///
    /// # Returns
    ///
    /// `None` on allocation failure, which the caller propagates with `?`
    /// to reproduce `goto fail`. The unit payload carries no information
    /// because the C macro carries none either: the only failure it can
    /// report is that an allocation returned null.
    fn dup_string(&mut self, from: &Self, which: StringField) -> Option<()> {
        match from.field(which) {
            // if((src)->name) was false at L1303: nothing to copy, and no
            // failure. The destination is already absent.
            None => Some(()),
            Some(source) => {
                // curlx_strdup((src)->name) at L1304, then the null test at
                let copied = CBuf::from_slice(source.as_bytes())?;
                // Stores through the field selector so that the release of
                // any previous value is not duplicated here. On a fresh
                // copy there is never one, but the invariant should not
                // depend on the caller.
                self.store(which, copied);
                Some(())
            }
        }
    }

    /// Borrows one string by selector, or `None` if the field is absent.
    ///
    /// Takes `&self`, so this is one of the read paths that must work
    /// against the `*const CURLU` the API hands out; see [`CurlUrl::dup`]
    /// for why that is a soundness requirement and not a preference.
    #[must_use]
    pub(crate) fn field(&self, which: StringField) -> Option<&CBuf> {
        match which {
            StringField::Scheme => self.scheme.as_ref(),
            StringField::User => self.user.as_ref(),
            StringField::Password => self.password.as_ref(),
            StringField::Options => self.options.as_ref(),
            StringField::Host => self.host.as_ref(),
            StringField::ZoneId => self.zoneid.as_ref(),
            StringField::Port => self.port.as_ref(),
            StringField::Path => self.path.as_ref(),
            StringField::Query => self.query.as_ref(),
            StringField::Fragment => self.fragment.as_ref(),
        }
    }

    /// Borrows one string's bytes by selector, without its terminator.
    ///
    /// The convenient form for the serializer in `src/getset.rs`, which
    /// assembles output from byte slices. Equivalent to reading the C
    /// member and taking `strlen()` of it, except that the length is
    /// already known and is not recomputed.
    #[must_use]
    pub(crate) fn field_bytes(&self, which: StringField) -> Option<&[u8]> {
        self.field(which).map(CBuf::as_bytes)
    }

    /// Whether one string is present, however long it is.
    ///
    /// Presence and emptiness are different states throughout the C
    /// module: `L1059` stores a zero-length query for a bare `?`, and the
    /// getter at `L1613-L1615` then decides between reporting it and
    /// reporting nothing based on `CURLU_GET_EMPTY`. This answers only the
    /// first question.
    #[must_use]
    pub(crate) fn has(&self, which: StringField) -> bool {
        self.field(which).is_some()
    }

    /// Resolves a selector to the field itself, for storing through.
    ///
    /// The direct port of `char **storep` in `curl_url_set()` at
    /// `lib/urlapi.c:L1808`, and the reason the store step lives in this
    /// module: assigning to the returned slot releases the previous value
    /// as part of the assignment, so the `curlx_free(*storep)` at `L1994`
    /// cannot be forgotten at a call site the way it can in C.
    ///
    /// Prefer [`CurlUrl::store`] and [`CurlUrl::clear`], which say what
    /// they do. This exists for the dispatch shape the C code uses, where
    /// the destination is chosen in one `match` and written much later.
    pub(crate) fn field_mut(&mut self, which: StringField) -> &mut Option<CBuf> {
        match which {
            StringField::Scheme => &mut self.scheme,
            StringField::User => &mut self.user,
            StringField::Password => &mut self.password,
            StringField::Options => &mut self.options,
            StringField::Host => &mut self.host,
            StringField::ZoneId => &mut self.zoneid,
            StringField::Port => &mut self.port,
            StringField::Path => &mut self.path,
            StringField::Query => &mut self.query,
            StringField::Fragment => &mut self.fragment,
        }
    }

    /// Stores a buffer in one field, releasing whatever it held.
    ///
    /// The port of `lib/urlapi.c:L1994-L1995`, `curlx_free(*storep)`
    /// followed by `*storep = newp`, and of the three release-then-store
    /// pairs in `parse_hostname_login()` at `L305-L306`, `L310-L311` and
    /// `L315-L316`, and of the host replacement at `L671-L672`, and of the
    /// port regeneration at `L380-L381`, and of the path rewrite at
    /// `L1102-L1103`. Every one of those is this operation.
    ///
    /// The order is not negotiable and is why this is a method rather than
    /// an assignment spelled out at each site: releasing after overwriting
    /// releases the wrong pointer, and not releasing at all leaks on every
    /// repeated set. Here the release is the `Drop` of the value the
    /// assignment displaces, so neither mistake is expressible.
    ///
    /// Takes the buffer by value: ownership moves into the handle, and the
    /// handle's `Drop` will release it.
    pub(crate) fn store(&mut self, which: StringField, value: CBuf) {
        *self.field_mut(which) = Some(value);
    }

    /// Releases one field and leaves it absent.
    ///
    /// The port of `Curl_safefree(u->member)`, which `urlset_clear()` uses
    /// in ten of its eleven arms, at `lib/urlapi.c:L1740`, `L1744`, `L1747`,
    /// `L1750`, `L1753`, `L1756`, `L1760`, `L1763`, `L1766` and `L1770`, and
    /// of the zone-identifier release the host setter performs at `L1848`.
    /// The eleventh arm is the whole-URL one, which is [`CurlUrl::reset`].
    /// The macro frees and then nulls; assigning `None` does both.
    ///
    /// This is also what `src/parse/authority.rs` uses to reproduce the
    /// `FB2` exit label at `L328-L330`. The observable behavior is
    /// identical, a handle whose three credential fields read as absent;
    /// the difference is that this releases the buffers instead of leaking
    /// them, and a leak is not observable through the URL API. Reproducing
    /// the behavior is the requirement; reproducing the leak is not.
    pub(crate) fn clear(&mut self, which: StringField) {
        *self.field_mut(which) = None;
    }

    /// Moves one field's buffer out of the handle, leaving it absent.
    ///
    /// The handle stops owning the buffer and the caller starts, which is
    /// the shape the C module uses when it hands a field's block onward
    /// rather than copying it. Nothing is released here: a caller that
    /// drops the result releases it then, and a caller that hands it to C
    /// through `CBuf::into_raw` transfers the `curl_free()` obligation
    /// across the boundary instead.
    ///
    /// This is destructive to the handle whatever the caller then does with
    /// the result, which is what the `#[must_use]` is for. Discarding the
    /// return value does not leak -- the `Option<CBuf>` is dropped and the
    /// buffer freed -- but the field is gone either way, so a call made
    /// where [`CurlUrl::clear`] was meant is silently the same thing and a
    /// call made where a borrow was meant silently empties the handle.
    #[must_use = "this removes the buffer from the handle even if the \
                  result is discarded; use clear() to release in place or \
                  an accessor to borrow"]
    // No production caller: the port clears a field in place or borrows it,
    // for the reason the paragraph above gives. Retained as the move-out half
    // of the field family, and used by the tests below to check that a taken
    // buffer is released exactly once.
    #[allow(dead_code)]
    pub(crate) fn take(&mut self, which: StringField) -> Option<CBuf> {
        self.field_mut(which).take()
    }

    // The ten named accessors below all borrow: each returns the bytes of
    // one field, in the declaration order of `lib/urlapi.c:L68-L77`, and
    // none of them transfers ownership. `None` means the field is absent,
    // which is a different state from an empty buffer. Only `port` and
    // `path` say more than the field they name, because for those two the
    // absent case has a consequence elsewhere.

    /// `u->scheme`, `lib/urlapi.c:L68`.
    #[must_use]
    pub(crate) fn scheme(&self) -> Option<&[u8]> {
        self.field_bytes(StringField::Scheme)
    }

    /// `u->user`, `lib/urlapi.c:L69`.
    #[must_use]
    pub(crate) fn user(&self) -> Option<&[u8]> {
        self.field_bytes(StringField::User)
    }

    /// `u->password`, `lib/urlapi.c:L70`.
    #[must_use]
    pub(crate) fn password(&self) -> Option<&[u8]> {
        self.field_bytes(StringField::Password)
    }

    /// `u->options`, `lib/urlapi.c:L71`.
    #[must_use]
    pub(crate) fn options(&self) -> Option<&[u8]> {
        self.field_bytes(StringField::Options)
    }

    /// `u->host`, `lib/urlapi.c:L72`.
    #[must_use]
    pub(crate) fn host(&self) -> Option<&[u8]> {
        self.field_bytes(StringField::Host)
    }

    /// `u->zoneid`, `lib/urlapi.c:L73`.
    #[must_use]
    pub(crate) fn zoneid(&self) -> Option<&[u8]> {
        self.field_bytes(StringField::ZoneId)
    }

    /// `u->port`, `lib/urlapi.c:L74`.
    ///
    /// The textual port. [`CurlUrl::portnum`] is the numeric one, and the
    /// two are set together at `L378-L381` and `L1679-L1681`.
    #[must_use]
    pub(crate) fn port(&self) -> Option<&[u8]> {
        self.field_bytes(StringField::Port)
    }

    /// `u->path`, `lib/urlapi.c:L75`.
    ///
    /// `None` means the handle has no path. Substituting `"/"` for it is
    /// the getter's job at `L1606-L1607` and the whole-URL template's job
    /// at `L1528`, not this accessor's.
    #[must_use]
    pub(crate) fn path(&self) -> Option<&[u8]> {
        self.field_bytes(StringField::Path)
    }

    /// `u->query`, `lib/urlapi.c:L76`.
    #[must_use]
    pub(crate) fn query(&self) -> Option<&[u8]> {
        self.field_bytes(StringField::Query)
    }

    /// `u->fragment`, `lib/urlapi.c:L77`.
    #[must_use]
    pub(crate) fn fragment(&self) -> Option<&[u8]> {
        self.field_bytes(StringField::Fragment)
    }

    /// Reads `u->portnum`, `lib/urlapi.c:L78`.
    ///
    /// Meaningful only when [`CurlUrl::port`] is present. The two
    /// comparison sites, `L1472` and `L1599`, both reach this only after
    /// establishing that, and both compare it against a 16-bit `defport`.
    #[must_use]
    pub(crate) const fn portnum(&self) -> u16 {
        self.portnum
    }

    /// Writes `u->portnum`.
    ///
    /// The port of the assignments at `lib/urlapi.c:L378` and `L1681`, and
    /// of the reset to zero in `urlset_clear()` at `L1759`. Both
    /// assignment sites cast a range-checked `curl_off_t` to
    /// `unsigned short`; the caller does the range check, exactly as
    /// `curlx_str_number(&portptr, &port, 0xffff)` at `L375` does for the
    /// C code, and what arrives here already fits.
    pub(crate) fn set_portnum(&mut self, portnum: u16) {
        self.portnum = portnum;
    }

    /// Reads `u->query_present`, `lib/urlapi.c:L79`.
    ///
    /// True when the input carried a `?`, or when a query was assigned,
    /// even if the query itself is empty. This is what lets
    /// `CURLU_GET_EMPTY` distinguish `http://x/?` from `http://x/`.
    #[must_use]
    pub(crate) const fn query_present(&self) -> bool {
        self.query_present
    }

    /// Writes `u->query_present`.
    ///
    /// Set at `lib/urlapi.c:L1039` and `L1865`, cleared at `L1767`.
    pub(crate) fn set_query_present(&mut self, present: bool) {
        self.query_present = present;
    }

    /// Reads `u->fragment_present`, `lib/urlapi.c:L80`.
    ///
    /// The fragment's counterpart to [`CurlUrl::query_present`], and the
    /// reason `CURLU_GET_EMPTY` can report a bare `#`.
    #[must_use]
    pub(crate) const fn fragment_present(&self) -> bool {
        self.fragment_present
    }

    /// Writes `u->fragment_present`.
    ///
    /// Set at `lib/urlapi.c:L1016` and `L1869`, cleared at `L1771`.
    pub(crate) fn set_fragment_present(&mut self, present: bool) {
        self.fragment_present = present;
    }

    /// Reads `u->guessed_scheme`, `lib/urlapi.c:L81`.
    ///
    /// True when `guess_scheme()` chose the scheme from the host name
    /// rather than reading it from the input. Read at `L1512` and `L1559`,
    /// both under `CURLU_NO_GUESS_SCHEME`.
    ///
    /// Always false on a handle produced by [`CurlUrl::dup`], however the
    /// original was built. That is `FB1`, reproduced on purpose.
    #[must_use]
    pub(crate) const fn guessed_scheme(&self) -> bool {
        self.guessed_scheme
    }

    /// Writes `u->guessed_scheme`.
    ///
    /// Set at `lib/urlapi.c:L1008`, the last statement of
    /// `guess_scheme()`, and cleared at `L1662` when a scheme is assigned
    /// explicitly and at `L1741` when the scheme is cleared.
    pub(crate) fn set_guessed_scheme(&mut self, guessed: bool) {
        self.guessed_scheme = guessed;
    }
}

impl Default for CurlUrl {
    /// The same empty handle [`CurlUrl::new`] produces.
    ///
    /// Provided because a type with an argument-free constructor should
    /// have one, and because `Self::default()` reads better than
    /// `Self::new()` at the few sites that only want the zeroed state.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CurlUrl {
    /// Reports the handle's shape without disclosing any of its content.
    ///
    /// Written by hand rather than derived, for the reason given on the
    /// structure: `user`, `password`, `options` and `query` hold secrets,
    /// and a derived formatter would print all ten strings verbatim into
    /// whatever log, panic message or assertion failure asked for them.
    /// That is CWE-532, cleartext storage of sensitive information in a log
    /// file, and it is not a hypothetical for this type: a handle is the
    /// natural thing to format when a parse result surprises someone.
    ///
    /// What is emitted is the presence of each of the ten strings and the
    /// four non-string members verbatim. Presence is the diagnostic that
    /// actually gets used when porting this module -- *which parts did the
    /// parse populate* -- and it is also all that can be emitted safely.
    /// Length is deliberately withheld even for the parts that are not
    /// credentials: a password's length is an attribute of the password,
    /// and offering it here for `scheme` but not for `password` would put
    /// a per-field judgment call in the formatter, where the next member
    /// added would silently inherit whichever branch it landed in. One
    /// rule for all ten leaves nothing to decide.
    ///
    /// The four remaining members disclose nothing. `portnum` is the parsed
    /// form of a port that is already public in the URL, and the three
    /// flags are parser state: `lib/urlapi.c:L79-L81`.
    ///
    /// [`CBuf`]'s own `Debug` reports a length and no bytes, so formatting
    /// one buffer on purpose still says something useful; this implementation
    /// does not reach it, because a count of ten `Option`s formatted as
    /// `"set"` or `"unset"` is smaller and says exactly as much.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// Maps one owned string to a fixed word.
        ///
        /// A closure would be equivalent; a named helper keeps the ten call
        /// sites below narrow enough to read as a table.
        fn present(field: &Option<CBuf>) -> &'static str {
            if field.is_some() {
                "set"
            } else {
                "unset"
            }
        }

        f.debug_struct("CurlUrl")
            .field("scheme", &present(&self.scheme))
            .field("user", &present(&self.user))
            .field("password", &present(&self.password))
            .field("options", &present(&self.options))
            .field("host", &present(&self.host))
            .field("zoneid", &present(&self.zoneid))
            .field("port", &present(&self.port))
            .field("path", &present(&self.path))
            .field("query", &present(&self.query))
            .field("fragment", &present(&self.fragment))
            .field("portnum", &self.portnum)
            .field("query_present", &self.query_present)
            .field("fragment_present", &self.fragment_present)
            .field("guessed_scheme", &self.guessed_scheme)
            .finish()
    }
}

impl Drop for CurlUrl {
    /// Releases the ten strings, as `curl_url_cleanup()` does.
    ///
    /// The port of `lib/urlapi.c:L1293-L1299`, minus one half. That
    /// function does two things: it calls `free_urlhandle(u)` at `L1296`,
    /// which is this, and then `curlx_free(u)` at `L1297`, which releases
    /// the block holding the structure. The second half cannot be here,
    /// because this module never sees the pointer to that block;
    /// `src/ffi.rs` owns it, and the module documentation above gives the
    /// matching recipe. The null guard at `L1295` also lives there, where
    /// the null can actually arrive.
    ///
    /// Strings previously returned to C are not touched, because they were
    /// never fields of this structure: `curl_url_get()` builds each one as
    /// its own buffer and hands ownership straight to the caller.
    /// `include/curl/urlapi.h:L116-L118` promises exactly that.
    fn drop(&mut self) {
        self.release_strings();
    }
}

impl fmt::Display for StringField {
    /// Writes the C member name, so a selector can be formatted directly
    /// into a diagnostic.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's entire job is to panic when an
    // assertion fails, and a test never crosses that boundary, so the
    // denials are relaxed here and only here, enumerated rather than
    // blanket. This mirrors `src/alloc.rs`, which does the same at its own
    // test module for the same reason.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    /// Formatting a populated handle discloses no part content.
    ///
    /// The regression guard for the redacted [`CurlUrl`] formatter. A
    /// derived `Debug` would print all ten strings, and `user`, `password`,
    /// `options` and `query` are secrets: `lib/urlapi.c:L69-L71` and `L76`.
    /// The assertion is deliberately over all ten rather than only the four,
    /// because the formatter's rule is one rule for every string, and a
    /// later member added to the structure has to inherit it.
    #[test]
    fn formatting_a_handle_discloses_no_part_content() {
        let url = populated();
        let text = format!("{url:?}");

        for which in StringField::ALL {
            let secret = core::str::from_utf8(sample(which)).unwrap();
            assert!(!text.contains(secret), "{which} content leaked into {text}");
        }
        // The distinguishing tail of every sample value, checked once more
        // on its own so that a formatter printing bytes without the
        // "sample-" prefix could not slip past the loop above.
        for tail in [
            "scheme", "user", "password", "options", "host", "zoneid", "port", "path", "query",
            "fragment",
        ] {
            assert!(
                !text.contains(&format!("sample-{tail}")),
                "{tail} content leaked into {text}"
            );
        }

        // What it does say: the shape. Ten names, each answered with a
        // fixed word, and the four non-string members verbatim.
        for which in StringField::ALL {
            assert!(text.contains(which.name()), "{which} name missing");
        }
        assert!(text.contains("set"), "presence missing");
        assert!(text.contains("8080"), "portnum missing");
        assert!(text.contains("query_present"), "query_present missing");
        assert!(
            text.contains("fragment_present"),
            "fragment_present missing"
        );
        assert!(text.contains("guessed_scheme"), "guessed_scheme missing");

        // A fresh handle reports the same fourteen members, all absent.
        let fresh = format!("{:?}", CurlUrl::new());
        assert!(fresh.contains("unset"), "absence missing");
        assert!(!fresh.contains("sample-"), "fresh handle leaked");
        for which in StringField::ALL {
            assert!(fresh.contains(which.name()), "{which} name missing");
        }
    }

    // Imported by name rather than through a glob, which is the rule the
    // plan sets for the whole crate at 0.4.3.
    use super::{CurlUrl, StringField};
    use crate::alloc::CBuf;

    /// Builds an owned C-allocator buffer from a literal.
    ///
    /// Every string a test stores in a handle comes through here, so every
    /// one of them is a real C-allocator block and a run under
    /// `valgrind --leak-check=full` measures the real teardown rather than a
    /// Rust-allocated stand-in.
    fn buf(bytes: &[u8]) -> CBuf {
        CBuf::from_slice(bytes).unwrap()
    }

    /// A distinct, recognizable value per field, so a copy that crosses two
    /// fields over is caught rather than passing by coincidence.
    ///
    /// Written out rather than derived from [`StringField::name`], so that a
    /// miswired `name()` cannot make a miswired `field()` look correct, and
    /// so that no test needs a heap-allocated `Vec` to hold a fixture.
    fn sample(which: StringField) -> &'static [u8] {
        match which {
            StringField::Scheme => b"sample-scheme",
            StringField::User => b"sample-user",
            StringField::Password => b"sample-password",
            StringField::Options => b"sample-options",
            StringField::Host => b"sample-host",
            StringField::ZoneId => b"sample-zoneid",
            StringField::Port => b"sample-port",
            StringField::Path => b"sample-path",
            StringField::Query => b"sample-query",
            StringField::Fragment => b"sample-fragment",
        }
    }

    /// A handle with all fourteen members set to non-default values.
    ///
    /// `guessed_scheme` is deliberately among them: the `FB1` test needs an
    /// original whose flag is set, and every other test benefits from
    /// asserting that the member it cares about is not simply left at its
    /// initial value.
    fn populated() -> CurlUrl {
        let mut url = CurlUrl::new();
        for which in StringField::ALL {
            url.store(which, buf(sample(which)));
        }
        url.set_portnum(8080);
        url.set_query_present(true);
        url.set_fragment_present(true);
        url.set_guessed_scheme(true);
        url
    }

    /// Asserts a handle is in the state `curl_url()` produces.
    fn assert_fresh(url: &CurlUrl) {
        for which in StringField::ALL {
            assert!(
                url.field(which).is_none(),
                "{which} should be absent on a fresh handle"
            );
            assert!(!url.has(which), "has({which}) should be false");
            assert_eq!(url.field_bytes(which), None, "{which} bytes");
        }
        assert_eq!(url.portnum(), 0, "portnum starts at zero");
        assert!(!url.query_present(), "query_present starts clear");
        assert!(!url.fragment_present(), "fragment_present starts clear");
        assert!(!url.guessed_scheme(), "guessed_scheme starts clear");
    }

    /// The structure has fourteen members: ten strings, one port number and
    /// three flags.
    ///
    /// Guards implicit requirement `I4`. A reader who expects the ten
    /// strings of the public API will read this as a mistake, so the count
    /// is asserted where the mistake would be noticed.
    #[test]
    fn the_handle_has_fourteen_members() {
        assert_eq!(StringField::ALL.len(), 10, "ten heap strings");
        let url = populated();
        // The four members that are not strings, each reachable and each
        // holding the value set above rather than its initial one.
        assert_eq!(url.portnum(), 8080);
        assert!(url.query_present());
        assert!(url.fragment_present());
        assert!(url.guessed_scheme());
    }

    /// `curl_url()` yields ten absent strings, port number zero and three
    /// clear flags, `lib/urlapi.c:L1288-L1291`.
    #[test]
    fn a_fresh_handle_is_entirely_empty() {
        assert_fresh(&CurlUrl::new());
        assert_fresh(&CurlUrl::default());
    }

    /// Every selector reaches its own field, and the named accessors agree
    /// with the selector-based ones.
    ///
    /// A crossed wire in either `match` would make the port store the host
    /// where the path belongs, which no higher-level test could diagnose.
    #[test]
    fn selectors_and_named_accessors_address_the_same_fields() {
        let url = populated();
        for which in StringField::ALL {
            assert_eq!(
                url.field_bytes(which),
                Some(sample(which)),
                "selector {which}"
            );
        }
        assert_eq!(url.scheme(), Some(sample(StringField::Scheme)));
        assert_eq!(url.user(), Some(sample(StringField::User)));
        assert_eq!(url.password(), Some(sample(StringField::Password)));
        assert_eq!(url.options(), Some(sample(StringField::Options)));
        assert_eq!(url.host(), Some(sample(StringField::Host)));
        assert_eq!(url.zoneid(), Some(sample(StringField::ZoneId)));
        assert_eq!(url.port(), Some(sample(StringField::Port)));
        assert_eq!(url.path(), Some(sample(StringField::Path)));
        assert_eq!(url.query(), Some(sample(StringField::Query)));
        assert_eq!(url.fragment(), Some(sample(StringField::Fragment)));
    }

    /// Storing over a populated field replaces its content.
    ///
    /// The release of the displaced buffer is the point of
    /// `lib/urlapi.c:L1994-L1995`; it is not observable from Rust, so this
    /// asserts the visible half and `valgrind` measures the other.
    #[test]
    fn storing_replaces_the_previous_value() {
        let mut url = CurlUrl::new();
        url.store(StringField::Host, buf(b"first.example"));
        url.store(StringField::Host, buf(b"second.example"));
        assert_eq!(url.host(), Some(b"second.example".as_slice()));
        // Repeated stores, each of which displaces a live buffer, so a
        // leak-checked run has something to measure.
        for _ in 0..16 {
            url.store(StringField::Host, buf(b"again.example"));
        }
        assert_eq!(url.host(), Some(b"again.example".as_slice()));
    }

    /// Storing through the `storep` analogue behaves as `store` does.
    ///
    /// `curl_url_set()` chooses its destination in one `match` at
    /// `lib/urlapi.c:L1828-L1875` and writes through it much later at
    /// `L1994-L1995`; this is that shape.
    #[test]
    fn storing_through_the_field_slot_releases_the_old_value() {
        let mut url = CurlUrl::new();
        url.store(StringField::Query, buf(b"a=1"));
        let storep = url.field_mut(StringField::Query);
        *storep = Some(buf(b"b=2"));
        assert_eq!(url.query(), Some(b"b=2".as_slice()));
        *url.field_mut(StringField::Query) = None;
        assert_eq!(url.query(), None);
    }

    /// `Curl_safefree(u->member)` leaves the field absent,
    /// `lib/urlapi.c:L1740-L1770`.
    #[test]
    fn clearing_releases_a_field_and_leaves_it_absent() {
        let mut url = populated();
        for which in StringField::ALL {
            url.clear(which);
            assert!(!url.has(which), "{which} should be absent after clear");
        }
        // Clearing an already absent field is a no-op, as the macro is.
        url.clear(StringField::Host);
        assert!(!url.has(StringField::Host));
        // The four non-string members are untouched by clearing strings,
        // which matches the per-part arms: only the scheme, port, query and
        // fragment arms touch a flag, and they do it themselves.
        assert_eq!(url.portnum(), 8080);
        assert!(url.query_present());
        assert!(url.fragment_present());
        assert!(url.guessed_scheme());
    }

    /// Taking a field moves the buffer to the caller.
    #[test]
    fn taking_a_field_transfers_the_buffer_out() {
        let mut url = populated();
        let taken = url.take(StringField::Path).unwrap();
        assert_eq!(taken.as_bytes(), sample(StringField::Path));
        assert!(!url.has(StringField::Path));
        assert!(url.take(StringField::Path).is_none());
        // `taken` is released here, by this scope rather than by the
        // handle, which is the ownership transfer the method documents.
        drop(taken);
        assert_eq!(url.path(), None);
    }

    /// `urlset_clear(CURLUPART_URL)` returns a populated handle to the
    /// fresh state, `lib/urlapi.c:L1735-L1738`.
    #[test]
    fn resetting_returns_a_populated_handle_to_the_fresh_state() {
        let mut url = populated();
        url.reset();
        assert_fresh(&url);
        // Still usable afterwards: a reset is not a destruction, which is
        // what `clear_url()` in `tests/libtest/lib1560.c` depends on.
        url.store(StringField::Scheme, buf(b"https"));
        assert_eq!(url.scheme(), Some(b"https".as_slice()));
        // And resetting twice is harmless.
        url.reset();
        url.reset();
        assert_fresh(&url);
    }

    /// `parseurl_and_replace()` swaps a fresh handle into a live one,
    /// `lib/urlapi.c:L1197-L1209`.
    #[test]
    fn replacing_installs_the_fresh_handle_and_releases_the_old_one() {
        let mut live = populated();
        let mut fresh = CurlUrl::new();
        fresh.store(StringField::Scheme, buf(b"ftp"));
        fresh.store(StringField::Host, buf(b"ftp.example"));
        fresh.set_portnum(21);
        live.replace(fresh);
        assert_eq!(live.scheme(), Some(b"ftp".as_slice()));
        assert_eq!(live.host(), Some(b"ftp.example".as_slice()));
        assert_eq!(live.portnum(), 21);
        // Everything the old handle held is gone, not merged.
        assert_eq!(live.user(), None);
        assert_eq!(live.query(), None);
        assert!(!live.query_present());
        assert!(!live.guessed_scheme());
    }

    /// Duplication copies all ten strings and the three scalar members the
    /// C function copies, `lib/urlapi.c:L1314-L1326`.
    #[test]
    fn duplication_copies_the_ten_strings_and_three_scalars() {
        let original = populated();
        let copy = original.dup().unwrap();
        for which in StringField::ALL {
            assert_eq!(
                copy.field_bytes(which),
                Some(sample(which)),
                "{which} should be copied"
            );
        }
        assert_eq!(copy.portnum(), 8080, "L1324 copies portnum");
        assert!(copy.fragment_present(), "L1325 copies fragment_present");
        assert!(copy.query_present(), "L1326 copies query_present");
    }

    /// **FB1**: duplication does not copy `guessed_scheme`, on purpose.
    ///
    /// If this test fails, someone has "fixed" `CurlUrl::dup` by copying
    /// `guessed_scheme`. That is not a fix. `curl_url_dup()` at
    /// `lib/urlapi.c:L1310-L1332` copies the ten strings and exactly three
    /// scalars, `portnum` at `L1324`, `fragment_present` at `L1325` and
    /// `query_present` at `L1326`, and it does not copy the member declared
    /// at `L81`. Removing the divergence makes the parity diff disagree
    /// with the C implementation for any caller passing
    /// `CURLU_NO_GUESS_SCHEME` to a duplicated handle. Read the `FB1` entry
    /// in `docs/KNOWN-DIVERGENCES.md`, which carries the measurements from
    /// the reference build, before changing anything here.
    #[test]
    fn fb1_duplication_does_not_copy_the_guessed_scheme_flag() {
        let mut original = CurlUrl::new();
        original.store(StringField::Scheme, buf(b"http"));
        original.store(StringField::Host, buf(b"example.com"));
        original.set_portnum(1234);
        original.set_guessed_scheme(true);
        assert!(original.guessed_scheme(), "the original knows it guessed");

        let copy = original.dup().unwrap();

        // The observable half of FB1. Everything else came across.
        assert!(
            !copy.guessed_scheme(),
            "FB1: curl_url_dup() does not copy guessed_scheme, and neither \
             does this port. See docs/KNOWN-DIVERGENCES.md before changing \
             this."
        );
        assert_eq!(copy.scheme(), Some(b"http".as_slice()));
        assert_eq!(copy.host(), Some(b"example.com".as_slice()));
        assert_eq!(copy.portnum(), 1234);
    }

    /// Duplication copies exactly the fields the original has, leaving the
    /// rest absent, which is the `if((src)->name)` test at
    /// `lib/urlapi.c:L1303`.
    #[test]
    fn duplication_copies_only_the_present_fields() {
        let mut original = CurlUrl::new();
        original.store(StringField::Scheme, buf(b"https"));
        original.store(StringField::Host, buf(b"example.com"));
        original.store(StringField::Path, buf(b"/"));
        // An empty string is present, not absent: `L1059` stores exactly
        // this for a bare `?`, and the distinction drives
        // `CURLU_GET_EMPTY`.
        original.store(StringField::Query, buf(b""));
        original.set_query_present(true);

        let copy = original.dup().unwrap();
        assert_eq!(copy.scheme(), Some(b"https".as_slice()));
        assert_eq!(copy.host(), Some(b"example.com".as_slice()));
        assert_eq!(copy.path(), Some(b"/".as_slice()));
        assert_eq!(copy.query(), Some(b"".as_slice()));
        assert!(copy.query_present());
        for which in [
            StringField::User,
            StringField::Password,
            StringField::Options,
            StringField::ZoneId,
            StringField::Port,
            StringField::Fragment,
        ] {
            assert!(!copy.has(which), "{which} was absent and stays absent");
        }
        assert_eq!(copy.portnum(), 0);
        assert!(!copy.fragment_present());
    }

    /// Duplicating an empty handle yields an empty handle.
    #[test]
    fn duplicating_a_fresh_handle_yields_a_fresh_handle() {
        let copy = CurlUrl::new().dup().unwrap();
        assert_fresh(&copy);
    }

    /// The copy owns its strings: mutating one handle leaves the other
    /// alone, and both are released independently.
    ///
    /// This is the property a derived `Clone` would have broken, and the
    /// reason `CurlUrl` derives neither `Clone` nor `Copy`.
    #[test]
    fn a_duplicate_owns_its_own_buffers() {
        let mut original = populated();
        let copy = original.dup().unwrap();
        original.store(StringField::Host, buf(b"changed.example"));
        original.clear(StringField::Path);
        assert_eq!(original.host(), Some(b"changed.example".as_slice()));
        assert_eq!(
            copy.field_bytes(StringField::Host),
            Some(sample(StringField::Host)),
            "the copy is unaffected"
        );
        assert_eq!(
            copy.path(),
            Some(sample(StringField::Path)),
            "clearing the original does not clear the copy"
        );
        drop(original);
        // The copy's buffers are still live after the original is gone.
        assert_eq!(
            copy.field_bytes(StringField::Host),
            Some(sample(StringField::Host))
        );
    }

    /// Every read path works through a shared reference.
    ///
    /// Implicit requirement `I8`: `curl_url_get()` and `curl_url_dup()`
    /// take `const CURLU *` at `include/curl/urlapi.h:L133` and `L126`, so
    /// `src/ffi.rs` must never form a `&mut` from those pointers. This
    /// function accepts `&CurlUrl` and reaches every reader, so the
    /// requirement is enforced by the compiler rather than by review: if an
    /// accessor were ever changed to take `&mut self`, this stops
    /// compiling.
    #[test]
    fn every_reader_is_reachable_through_a_shared_reference() {
        fn read_everything(url: &CurlUrl) -> usize {
            let mut total = 0;
            for which in StringField::ALL {
                if let Some(field) = url.field(which) {
                    total += field.len();
                }
                if let Some(bytes) = url.field_bytes(which) {
                    total += bytes.len();
                }
                if url.has(which) {
                    total += 1;
                }
            }
            for bytes in [
                url.scheme(),
                url.user(),
                url.password(),
                url.options(),
                url.host(),
                url.zoneid(),
                url.port(),
                url.path(),
                url.query(),
                url.fragment(),
            ] {
                total += bytes.map_or(0, <[u8]>::len);
            }
            total += usize::from(url.portnum());
            total += usize::from(url.query_present());
            total += usize::from(url.fragment_present());
            total += usize::from(url.guessed_scheme());
            // The duplicator is a reader too, which is the whole point of
            // it taking `&self`.
            total += url
                .dup()
                .map_or(0, |copy| copy.host().map_or(0, <[u8]>::len));
            total
        }

        let url = populated();
        let shared: &CurlUrl = &url;
        assert!(read_everything(shared) > 0);
        // Two shared borrows at once, which a `&mut self` reader would
        // have made impossible.
        let (first, second) = (&url, &url);
        assert_eq!(first.host(), second.host());
    }

    /// The port number is sixteen bits wide, as `unsigned short` is.
    ///
    /// The width is what makes the comparisons against a scheme's
    /// `defport` at `lib/urlapi.c:L1472` and `L1599` behave identically.
    #[test]
    fn the_port_number_is_sixteen_bits() {
        let mut url = CurlUrl::new();
        url.set_portnum(u16::MAX);
        assert_eq!(url.portnum(), 65535);
        url.set_portnum(0);
        assert_eq!(url.portnum(), 0);
        assert_eq!(core::mem::size_of_val(&url.portnum()), 2);
    }

    /// The three flags are independent of one another and of the strings.
    #[test]
    fn the_three_flags_are_independent() {
        let mut url = CurlUrl::new();
        url.set_query_present(true);
        assert!(url.query_present());
        assert!(!url.fragment_present());
        assert!(!url.guessed_scheme());
        url.set_fragment_present(true);
        url.set_query_present(false);
        assert!(!url.query_present());
        assert!(url.fragment_present());
        url.set_guessed_scheme(true);
        assert!(url.guessed_scheme());
        url.set_guessed_scheme(false);
        assert!(!url.guessed_scheme());
        assert!(url.fragment_present());
    }

    /// The duplication order is the C one and covers every field exactly
    /// once, `lib/urlapi.c:L1314-L1323`.
    ///
    /// Asserted rather than trusted, because the order differs from the
    /// declaration order and looks like a transcription error.
    #[test]
    fn the_duplication_order_matches_the_c_macro_sequence() {
        assert_eq!(
            CurlUrl::DUP_ORDER,
            [
                StringField::Scheme,
                StringField::User,
                StringField::Password,
                StringField::Options,
                StringField::Host,
                StringField::Port,
                StringField::Path,
                StringField::Query,
                StringField::Fragment,
                StringField::ZoneId,
            ],
            "L1314-L1323: port precedes path, and zoneid comes last"
        );
        assert_ne!(
            CurlUrl::DUP_ORDER,
            StringField::ALL,
            "the copy order is deliberately not the declaration order"
        );
        // A permutation of the declaration order: every field copied
        // exactly once, none copied twice and none left out. Checked by
        // marking rather than by sorting, so the fixture needs no heap.
        let mut copied = [false; 10];
        for which in CurlUrl::DUP_ORDER {
            let index = StringField::ALL
                .iter()
                .position(|candidate| *candidate == which)
                .unwrap();
            assert!(!copied[index], "{which} appears twice in DUP_ORDER");
            copied[index] = true;
        }
        assert!(
            copied.iter().all(|marked| *marked),
            "every field must appear in DUP_ORDER"
        );
    }

    /// Selector names match the C member names, since diagnostics quote
    /// them, and `StringField::ALL` is in the declaration order of
    /// `lib/urlapi.c:L68-L77`.
    #[test]
    fn selector_names_are_the_c_member_names() {
        // Paired explicitly rather than as two parallel lists, so that a
        // mismatch names the field it is about.
        let expected: [(StringField, &str); 10] = [
            (StringField::Scheme, "scheme"),
            (StringField::User, "user"),
            (StringField::Password, "password"),
            (StringField::Options, "options"),
            (StringField::Host, "host"),
            (StringField::ZoneId, "zoneid"),
            (StringField::Port, "port"),
            (StringField::Path, "path"),
            (StringField::Query, "query"),
            (StringField::Fragment, "fragment"),
        ];
        assert_eq!(expected.len(), StringField::ALL.len());
        for (index, (which, name)) in expected.into_iter().enumerate() {
            assert_eq!(which.name(), name, "C member name of {which:?}");
            assert_eq!(
                which,
                StringField::ALL[index],
                "ALL must follow the declaration order at L68-L77"
            );
        }
        // The `Display` and `Debug` implementations both work, which the
        // assertion messages above rely on.
        assert_eq!(format!("{}", StringField::ZoneId), "zoneid");
        assert_eq!(format!("{:?}", StringField::ZoneId), "ZoneId");
    }

    /// Dropping a fully populated handle releases all ten strings.
    ///
    /// There is nothing observable to assert from inside the process: the
    /// buffers are C-allocator blocks and their release is only visible to
    /// a leak checker. The test exists so that
    /// `valgrind --leak-check=full cargo test` has a case that allocates
    /// ten blocks per handle and then drops the handle, which is what
    /// verifies `free_urlhandle()`'s ten `curlx_free()` calls were all
    /// ported. Many iterations, so a single missed field shows up as a
    /// definite loss rather than as noise.
    #[test]
    fn dropping_a_handle_releases_every_string() {
        for _ in 0..64 {
            let url = populated();
            assert!(url.has(StringField::Fragment));
            drop(url);
        }
        // The same through the duplicator, which allocates a second set.
        for _ in 0..64 {
            let original = populated();
            let copy = original.dup().unwrap();
            assert!(copy.has(StringField::ZoneId));
        }
        // And through a reset, which releases without destroying.
        let mut url = populated();
        for _ in 0..64 {
            url.reset();
            for which in StringField::ALL {
                url.store(which, buf(sample(which)));
            }
        }
        assert!(url.has(StringField::Scheme));
    }
}
