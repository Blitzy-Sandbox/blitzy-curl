// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The authority: credentials, host and port, and the setter C calls.
//!
//! Four C functions, from two files, ported into one module because they
//! are one pipeline over one span of the URL:
//!
//! | C function | Line | Ported as |
//! |---|---|---|
//! | `parse_hostname_login` | L248-L333 | [`parse_hostname_login`] |
//! | `parse_authority` | L604-L655 | [`parse_authority`] |
//! | `Curl_url_set_authority` | L658-L675 | [`url_set_authority`] |
//! | `Curl_parse_login_details` | `lib/url.c`:L2466-L2527 | [`parse_login_details`] |
//!
//! The first three are `lib/urlapi.c`. The fourth is not, and that is why it
//! is here: `lib/url.c` is out of scope and unmodifiable, so the helper the
//! module borrows across a translation-unit boundary is re-implemented
//! inside the crate instead of imported. `docs/PORTING-NOTES.md` records the
//! same four rows, and this is the one parser stage whose C sources span two
//! files.
//!
//! Only the third crosses into C. `Curl_url_set_authority` is one of the
//! eight globals `lib/urlapi.o` defines -- declared for the rest of libcurl
//! at `lib/urlapi-int.h`:L31, marked at `lib/urlapi.c`:L657 as being for
//! HTTP/2 server push, and called at `lib/http2.c`:L739 -- so a crate
//! exporting only the five public functions could not replace that object
//! file. The export attribute is not here, though: `src/ffi.rs` owns every
//! `#[no_mangle] extern "C"` symbol and the `*const c_char` conversion in
//! front of this one, and this module carries `#![forbid(unsafe_code)]`
//! below to make that a compiler guarantee rather than a convention.
//!
//! # The shape being parsed
//!
//! `lib/urlapi.c`:L261-L267 states the entry contract in the C's own words:
//! every other special case has been dealt with by the time this runs, so
//! the span is at most
//!
//! ```text
//! [user[:password][;options]]@]hostname
//! ```
//!
//! and `lib/url.c`:L2442-L2450 enumerates the ten login shapes the
//! credential half accepts, from a bare `user` to `;options:password`.
//!
//! # The login arithmetic is asymmetric on purpose
//!
//! [`parse_login_details`] locates two separators and derives three lengths
//! from them, and each of the three handles both orderings of the pair. The
//! C at `lib/url.c`:L2488-L2497 is three nested conditionals; the guards
//! `psep > osep` and `osep > psep` are what make both orderings work, and
//! the two worked examples below are the fastest way to see it. Both use a
//! twenty-one byte span and both end with the same three parts:
//!
//! | Input | `psep` | `osep` | `ulen` | `plen` | `olen` |
//! |---|---|---|---|---|---|
//! | `user;options:password` | 12 | 4 | 4 | 8 | 7 |
//! | `user:password;options` | 4 | 13 | 4 | 8 | 7 |
//!
//! In the first row `psep > osep`, so the user stops at the `;` and the
//! options run from the `;` to the `:`, while the password runs from the `:`
//! to the end. In the second row the roles swap and the same three
//! subtractions produce the same three answers. The `- 1` on `plen` and
//! `olen` is the separator byte itself, and it can never underflow, because
//! each expression is evaluated only when its own separator was found and a
//! found separator leaves at least one byte to subtract.
//!
//! # Two rules that look like details and are not
//!
//! **The user buffer is always allocated.** `lib/url.c`:L2500 calls
//! `curlx_memdup0(login, ulen)` unconditionally, and `curlx_memdup0` at
//! `lib/curlx/strdup.c`:L85-L96 allocates `length + 1` bytes and terminates
//! them, so a zero length still yields a non-null pointer. Three
//! consequences follow, and all three are observable:
//!
//! 1. `if(userp)` at `lib/urlapi.c`:L299 is *always* true on the success
//!    path. The port's [`LoginDetails::user`] is therefore not an `Option`,
//!    which states the property in the type rather than in a comment.
//! 2. `CURLU_DISALLOW_USER` consequently fires for *any* authority
//!    containing an `@`, even `@host`, which carries no username at all.
//!    That is why [`url_set_authority`] -- which passes that flag at
//!    `lib/urlapi.c`:L667 -- rejects every authority with an `@` in it.
//! 3. An empty username is a *present* username. `tests/libtest/lib1560.c`
//!    L794-L795 asserts that `http:/@example.com:123` round-trips as
//!    `http://@example.com:123/`, with the `@` still there.
//!
//! **An empty password is present; empty options are absent.** The password
//! is gated on the separator, `if(psep)` at L2505, so `user:` yields a
//! zero-length password that reads back as present. The options are gated on
//! the length, `if(olen)` at L2514, so `user;` yields no options at all. The
//! two branches sit nine lines apart and disagree; reproducing the
//! disagreement is the requirement.
//!
//! # `FB2`: the credential exit path clears three handle fields
//!
//! `docs/KNOWN-DIVERGENCES.md` records this as `FB2`, and this module is
//! where it lives. The C's shared exit label at `lib/urlapi.c`:L323 releases
//! the three *local* pointers at L325-L327 and then assigns null to
//! `u->user`, `u->password` and `u->options` at L328-L330 -- without
//! releasing what those three held. The same function's success path is
//! careful: L305, L310 and L315 each free the old value before storing the
//! new one. The defect is at the label alone.
//!
//! The label is reached three ways and **one of them is a success**:
//!
//! - (a) L273-L275, no `@` in the span, with `result` still holding the
//!   `CURLUE_OK` it was given at L254. Every URL without credentials takes
//!   this path, so the clearing is not an error path at all -- it is what
//!   makes an authority without credentials wipe any the handle already
//!   carried.
//! - (b) L292-L296, an allocation failure inside the login parser, mapped to
//!   `CURLUE_OUT_OF_MEMORY`. The comment at L293-L294 records that this is
//!   the only failure that call can report.
//! - (c) L300-L303, `CURLU_DISALLOW_USER` against an input carrying a
//!   username, giving `CURLUE_USER_NOT_ALLOWED`.
//!
//! Why it is harmless in one caller and not the other:
//! `parseurl_and_replace` at L1197-L1209 declares a `CURLU` at L1201, zeroes
//! it at L1202 and parses into that temporary, moving it into place at L1206
//! only on success -- so on the ordinary parse path the three fields are
//! already null and the assignments discard nothing. `url_set_authority` has
//! no temporary: L666-L667 hands the caller's own live handle to
//! `parse_authority`, so whatever it carried is dropped there.
//!
//! What this port reproduces, and the half it does not:
//!
//! | Aspect | C | This port |
//! |---|---|---|
//! | The three parts after any of the three exits | absent | absent, identical |
//! | The previous values | leaked | released |
//! | Distinguishable through the public API | -- | no |
//!
//! The second row is a real divergence and is recorded rather than hidden.
//! The fields here are owned buffers, so [`crate::handle::CurlUrl::clear`]
//! runs `Drop` and releases them; reproducing the leak would mean
//! deliberately constructing one, which this port does not do.
//! `KNOWN-DIVERGENCES.md` carries the full entry and the measurement note.
//!
//! Do not "improve" any of this. Moving the clearing into the two failure
//! paths, or skipping it on path (a), would change observable behavior for
//! every authority that has no `@` in it.
//!
//! # Stage order in [`parse_authority`] is behavior
//!
//! L617-L651 runs five stages, and the order is load-bearing because each
//! one mutates the buffer the next one reads:
//!
//! | Order | Stage | Line |
//! |---|---|---|
//! | 1 | strip the credentials | L617 |
//! | 2 | append what is left to the host buffer | L621 |
//! | 3 | split off the port | L627 |
//! | 4 | reject an empty host | L631 |
//! | 5 | classify and normalize the host | L634 |
//!
//! Stage 3 before stage 5 is why `host:8080` normalizes a host that no
//! longer has the port on it. Stage 3 before stage 4 is why an authority of
//! just `":80"` is `CURLUE_NO_HOST` rather than a host named `:80`: the port
//! stage truncates at the colon first, leaving nothing. And stage 4 uses a
//! plain `return` where every other failure uses `goto out`; the two are
//! identical here because the label does nothing but return, and the port
//! writes both as returns.
//!
//! # The host buffer is handed over, not copied
//!
//! [`url_set_authority`] transfers the dynamic buffer's block into the
//! handle rather than duplicating it, which is what `u->host =
//! curlx_dyn_ptr(&host)` at L672 does. One subtlety comes with it.
//! `ipv6_parse` rewrites the address in place and never calls
//! `curlx_dyn_setlen`, so the buffer's recorded length is deliberately left
//! stale -- `crate::parse::ipv6` documents that, and names this call site as
//! the reason it is safe. It is safe in C because what L672 takes is a
//! pointer, and the C string ends at the first terminator. A `CBuf` carries
//! a length instead of relying on a terminator, so the handover here trims
//! to the C string window first. Without that, normalizing `[0000::1]`
//! would store nine bytes, `[::1]` followed by a zero and three bytes of the
//! old address, where C stores five. The trim costs nothing -- it is a
//! length assignment, not a copy -- and it is what keeps the two
//! implementations byte-identical.
//!
//! # Ownership
//!
//! Every buffer this module allocates comes from `crate::alloc`, which uses
//! the C allocator, so a later `curl_free()` on it is correct;
//! `docs/MEMORY-OWNERSHIP.md` carries the resolution chain and
//! `CString::into_raw` is banned crate-wide for the reason recorded there.
//! Three sites allocate: the user, the password and the options portions at
//! `lib/url.c`:L2500, L2506 and L2515. Each becomes a handle field, and the
//! handle's `Drop` releases it.
//!
//! Nothing here frees the host buffer on a failure inside
//! [`parse_authority`], and neither does the C: the buffer belongs to the
//! caller, which releases it at L669 or L1189. A failed append is the one
//! case that needs no release at all, because `crate::dynbuf` has already
//! performed it -- contract 1 of that module -- which is why the C carries
//! no free of its own at L622-L625 either.
//!
//! # Verification
//!
//! The unit tests below cover the four functions in isolation, and their
//! vectors come from the credential-bearing and host-bearing rows of
//! `tests/libtest/lib1560.c` -- L442, L445, L601, L658, L769, L773, L791,
//! L794 and L797 -- which is a read-only reference and is never modified.
//! Two of them
//! exist to guard `FB2` specifically, one for its success exit and one for
//! its `CURLU_DISALLOW_USER` exit, because a suite that only checked result
//! codes could not see either. End-to-end verification is the parity run,
//! `rust-urlapi/scripts/run-parity.sh`, which builds the unmodified
//! `tests/libtest/lib1560.c` against the reference C library and against
//! this crate and diffs the two outputs byte for byte.

// Reachability here is decided by two modules that do not exist yet.
// `parse_authority` is called from the parse pipeline at `lib/urlapi.c`
// L1149, and `Curl_url_set_authority` is re-exported to C for
// `lib/http2.c` L739, so its consumers are `src/parse/mod.rs` and
// `src/ffi.rs`.
//
// This file is currently unreachable from any module tree, which is a
// consequence of the delivery order and not a defect: `src/parse/` holds no
// `mod.rs` and there is no `src/parse.rs`, so under edition 2021 no `mod`
// declaration can reach it. THE CHECKPOINT THAT CREATES src/parse/mod.rs
// MUST DECLARE `mod authority;` THERE, or this module is compiled by nothing
// and its tests never run.
//
// DEAD-CODE POLICY, TIME-BOXED. Identical in every module of this crate; grep
// for "DEAD-CODE POLICY" to find them all. They are removed together, by the
// checkpoint that creates src/getset.rs, and replaced there by one crate-level
// allowance in src/lib.rs carrying this same note. Until src/ffi.rs and
// src/getset.rs exist, most of this crate has no consumer, and a crate held to
// zero warnings cannot build clean without this. Scoped to this module and to
// this lint alone.
#![allow(dead_code)]
// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1).
// `forbid` rather than `deny` because an inner `allow` here would be a
// design change and should have to be argued for, not slipped in. This
// module needs nothing from C, so the attribute costs it nothing and turns
// the crate's single-unsafe-island property into a compiler guarantee
// instead of a convention.
#![forbid(unsafe_code)]

use core::ffi::c_uint;

// `CURLUE_BAD_HOSTNAME` is deliberately absent from this list. It is the
// code the C's unreachable `default` arm at L648-L649 would have produced,
// and the exhaustive `match` in `parse_authority` proves that arm absent
// rather than writing it; the two live arms that can report it -- the IPv6
// and host-name stages -- return it from the modules that own them.
use crate::abi::{
    CURLUcode, CURLUE_NO_HOST, CURLUE_OK, CURLUE_OUT_OF_MEMORY, CURLUE_USER_NOT_ALLOWED,
    CURLU_DISALLOW_USER, CURL_MAX_INPUT_LENGTH,
};
use crate::alloc::CBuf;
use crate::dynbuf::DynBuf;
use crate::error::{cc2cu, CURLcode};
use crate::handle::{CurlUrl, StringField};
use crate::parse::host::{hostname_check, ipv4_normalize, urldecode_host, HostKind};
use crate::parse::ipv6::ipv6_parse;
use crate::parse::port::parse_port;
use crate::scheme::{getn_scheme, SchemeInfo};

/// The bytes a C function reading through this pointer would see: the prefix
/// up to the first NUL, or all of them if there is none.
///
/// Two call sites need it, and both are places where the C works from a
/// `char *` while this module holds a slice whose length comes from
/// somewhere else:
///
/// - the scheme handed to the lookup at `lib/urlapi.c`:L284, where
///   `Curl_get_scheme` forwards to `Curl_getn_scheme(scheme, strlen(scheme))`
///   at `lib/url.c`:L1469-L1471;
/// - the host buffer handed over at L672, whose recorded length
///   `crate::parse::ipv6` deliberately leaves stale after normalizing an
///   address in place.
///
/// Neither call site can actually produce an interior zero today.
/// `Curl_junkscan` at L223-L246 refuses every byte at or below `0x20` in the
/// input, and a stored scheme comes either from `Curl_is_absolute_url`, whose
/// scan at L194-L205 accepts only alphanumerics and three punctuation bytes,
/// or from `set_url_scheme`, whose loop at L1650-L1656 accepts the same set.
/// So this is a faithfulness measure and not a correction -- but the host case
/// is not hypothetical at all: after `[0000::1]` is normalized the zero is
/// real, and it is exactly what bounds the string C hands to the handle.
///
/// `src/parse/host.rs` and `src/parse/port.rs` each carry an identical
/// private helper and `src/encode.rs` an equivalent one. None is imported:
/// this file's dependency whitelist does not include those modules, and a
/// helper this small is better duplicated than reached for across a boundary
/// the plan drew on purpose.
fn cstring_window(content: &[u8]) -> &[u8] {
    match content.iter().position(|&byte| byte == 0) {
        // The prefix is in bounds by construction, so the fallback is
        // unreachable; `get` is used anyway so that the bound is checked by
        // the compiler rather than argued for in a comment.
        Some(nul) => content.get(..nul).unwrap_or(content),
        None => content,
    }
}

/// A subslice of `bytes` starting at `from` and running for `len` bytes.
///
/// The C's `curlx_memdup0(login, ulen)` and `curlx_memdup0(&psep[1], plen)`
/// at `lib/url.c`:L2500, L2506 and L2515 are a pointer and a count; this is
/// the same pair over a slice. Every one of the three calls is in bounds by
/// construction -- each length is derived by subtracting its own offset from
/// either a larger offset or the span length -- so the empty fallback is
/// unreachable. It is written rather than asserted because an assertion
/// would be a panic path and this crate has none.
fn portion(bytes: &[u8], from: usize, len: usize) -> &[u8] {
    let end = from.saturating_add(len);
    bytes.get(from..end).unwrap_or(&[])
}

/// Clears `u->user`, `u->password` and `u->options`, reproducing
/// `lib/urlapi.c`:L328-L330.
///
/// This is `FB2`, and the module documentation carries the whole finding:
/// which three exits reach it, why one of them is a success, why it is
/// harmless on the parse path and harmful on the authority path, and which
/// half of it this port reproduces. The three lines are collected into one
/// function because the C reaches them through a single label from three
/// places, and a reader chasing `FB2` should find one definition rather than
/// three copies.
///
/// [`crate::handle::CurlUrl::clear`] releases the previous value, where
/// L328-L330 overwrite it. The API-visible result is identical -- all three
/// parts read back absent -- and the difference is recorded as a residual
/// divergence in `docs/KNOWN-DIVERGENCES.md`.
fn clear_credentials(u: &mut CurlUrl) {
    // L328.
    u.clear(StringField::User);
    // L329.
    u.clear(StringField::Password);
    // L330.
    u.clear(StringField::Options);
}

/// The three parts `Curl_parse_login_details` writes through its
/// out-parameters.
///
/// `lib/url.c`:L2467-L2468 declares them as `char **userp`, `char **passwdp`
/// and `char **optionsp`, and L2521-L2522 assign the first two while L2519
/// assigns the third. Returning them together is what makes the C's
/// "everything or nothing" property structural: the C reaches its `error:`
/// label at L2524 without having written any out-parameter, and a caller
/// that ignored the return code would read its own uninitialized locals.
/// Here there is nothing to read.
///
/// [`LoginDetails::user`] is not an `Option`, and that is the whole point.
/// The C allocates it unconditionally, so `if(userp)` at `lib/urlapi.c`:L299
/// is always true and `CURLU_DISALLOW_USER` always fires; the module
/// documentation lists the three consequences.
pub(crate) struct LoginDetails {
    /// The user portion, always present, possibly zero length.
    pub(crate) user: CBuf,
    /// The password portion. `Some` whenever a `:` was found, even for a
    /// zero-length password -- `lib/url.c`:L2505 gates on the separator.
    pub(crate) password: Option<CBuf>,
    /// The options portion. `Some` only when a `;` was found *and* something
    /// followed it -- `lib/url.c`:L2514 gates on the length, unlike the
    /// password nine lines above. Always `None` when the caller did not ask
    /// for options.
    pub(crate) options: Option<CBuf>,
}

/// Splits a login span into its user, password and options portions.
///
/// `Curl_parse_login_details` at `lib/url.c`:L2466-L2527, ported inline
/// because `lib/url.c` is out of scope and an object file standing in for
/// `lib/urlapi.o` cannot borrow the symbol back. The module documentation
/// carries the asymmetric arithmetic with both worked orderings and the two
/// allocation rules that look like details and are not.
///
/// This is the one borrowed helper that must **not** be exported, even
/// though it is a global in the C. `lib/url.c` keeps defining it -- the port
/// replaces `lib/urlapi.o` alone, and `lib/setopt.c`:L147 is a second caller
/// that still resolves against `url.c` -- so a `#[no_mangle]` here would be
/// a duplicate definition in the drop-in link. It stays crate-internal, and
/// `lib/urlapi.c`:L288 is the only call site it has to satisfy.
///
/// # Parameters
///
/// - `login`: the bytes before the `@`, which is what `lib/urlapi.c`:L288
///   passes as `login` with the length `ptr - login - 1`. The C's separate
///   `len` parameter is this slice's length.
/// - `want_options`: whether the caller supplied a destination for the
///   options, which in C is `optionsp != NULL`. The pointer carries two
///   meanings there, a destination and a request; the request half becomes
///   this flag and the destination half becomes
///   [`LoginDetails::options`]. When it is false a `;` is an ordinary byte
///   of the user or the password, which is why
///   `http://user:pass;option@server/path` keeps `pass;option` as its
///   password at `tests/libtest/lib1560.c`:L445-L446 while the `imap` row
///   above it does not.
///
/// # Returns
///
/// All three portions, with the user portion always allocated.
///
/// # Errors
///
/// `crate::error::CURLcode::CURLE_OUT_OF_MEMORY`, from L2527, and nothing
/// else. There is no malformed-input path: any byte sequence at all splits
/// into three portions. The C's comment at `lib/urlapi.c`:L293-L294 says the
/// same thing from the caller's side, which is why that caller folds every
/// failure into one code.
#[must_use = "the three portions are the output and must be stored or dropped"]
pub(crate) fn parse_login_details(
    login: &[u8],
    want_options: bool,
) -> Result<LoginDetails, CURLcode> {
    // L2466 receives `const size_t len`; a slice arrives measured.
    let len = login.len();

    // L2481-L2482: `psep = memchr(login, ':', len)`.
    let psep = login.iter().position(|&byte| byte == b':');

    // L2484-L2486: `if(optionsp) osep = memchr(login, ';', len)`. The search
    // is conditional, not just the storing of its result.
    let osep = if want_options {
        login.iter().position(|&byte| byte == b';')
    } else {
        None
    };

    // L2488-L2497, one `match` per length, in the C's order. Offsets stand
    // in for the C's pointers, so every `- x` below is the same subtraction
    // the C performs on `const char *`. The saturating forms cannot
    // underflow and cannot mask a real underflow either: each arm runs only
    // when its own separator was found, and a found separator sits at an
    // offset below `len`, which leaves at least the one byte the `- 1`
    // removes.
    let ulen = match (psep, osep) {
        // `osep && psep > osep`: the options separator comes first, so the
        // user stops there.
        (Some(p), Some(o)) if p > o => o,
        // `psep - login`.
        (Some(p), _) => p,
        // No password separator: stop at the options separator, or take
        // everything.
        (None, Some(o)) => o,
        (None, None) => len,
    };
    let plen = match (psep, osep) {
        // `osep && osep > psep`: the password runs from the `:` to the `;`.
        (Some(p), Some(o)) if o > p => o.saturating_sub(p).saturating_sub(1),
        // `login + len - psep`: from the `:` to the end of the span.
        (Some(p), _) => len.saturating_sub(p).saturating_sub(1),
        // `psep ? ... : 0`.
        (None, _) => 0,
    };
    let olen = match (osep, psep) {
        // `psep && psep > osep`: the options run from the `;` to the `:`.
        (Some(o), Some(p)) if p > o => p.saturating_sub(o).saturating_sub(1),
        // `login + len - osep`: from the `;` to the end of the span.
        (Some(o), _) => len.saturating_sub(o).saturating_sub(1),
        // `osep ? ... : 0`.
        (None, _) => 0,
    };

    // L2499-L2502. Unconditional, and a zero length still allocates: the
    // comment at L2499 says "which can be zero length" and
    // `lib/curlx/strdup.c`:L87 asks the allocator for `length + 1`. The
    // module documentation lists what depends on that.
    let Some(user) = CBuf::from_slice(portion(login, 0, ulen)) else {
        // L2501-L2502 jumps to `error:` at L2524, which frees the two locals
        // it may have taken and reports out of memory. Here the locals are
        // owned values that have not been created yet, so there is nothing
        // to release.
        return Err(CURLcode::CURLE_OUT_OF_MEMORY);
    };

    // L2504-L2509: gated on the separator, so `user:` yields a zero-length
    // password that reads back as present.
    let password = match psep {
        Some(p) => {
            let Some(buf) = CBuf::from_slice(portion(login, p.saturating_add(1), plen)) else {
                // L2507-L2508. `user` is released by its own `Drop` on the
                // way out, which is the `curlx_free(ubuf)` at L2525.
                return Err(CURLcode::CURLE_OUT_OF_MEMORY);
            };
            Some(buf)
        }
        None => None,
    };

    // L2511-L2520: gated on the *length*, so `user;` yields no options at
    // all. `obuf` starts as NULL at L2513 and is assigned through at L2519
    // whether or not the allocation happened, which is this `None`.
    let options = match osep {
        Some(o) if olen != 0 => {
            let Some(buf) = CBuf::from_slice(portion(login, o.saturating_add(1), olen)) else {
                // L2516-L2517. Both locals are released on the way out,
                // L2525-L2526.
                return Err(CURLcode::CURLE_OUT_OF_MEMORY);
            };
            Some(buf)
        }
        _ => None,
    };

    // L2521-L2523.
    Ok(LoginDetails {
        user,
        password,
        options,
    })
}

/// Strips any credentials off the front of an authority and stores them on
/// the handle.
///
/// `parse_hostname_login` at `lib/urlapi.c`:L248-L333. The module
/// documentation carries the shape being parsed, the two allocation rules
/// that make `CURLU_DISALLOW_USER` fire more often than it looks like it
/// should, and the whole of `FB2`.
///
/// Not exported to C: the C function is `static`, appears in no header, and
/// is not one of the eight globals `lib/urlapi.o` defines.
///
/// # Parameters
///
/// - `u`: the handle. Three fields are written on every path -- the user,
///   the password and the options -- and which values they end up holding is
///   `FB2`. Nothing else on the handle is touched, and `u->scheme` is read
///   but not modified.
/// - `login`: the authority, starting at the first byte after the scheme's
///   slashes. `lib/urlapi.c`:L1149 passes `hostp`, which runs to the end of
///   the URL rather than to the end of the authority, which is what `len` is
///   for.
/// - `len`: how many bytes of `login` belong to the authority, which is
///   `hostlen` from L1143. The C's `memchr(login, '@', len)` at L273 never
///   looks past it and neither does this, so a `@` in the path cannot be
///   mistaken for a credential separator.
/// - `flags`: the caller's flag word. Only `CURLU_DISALLOW_USER` is
///   consulted, at L300.
///
/// # Returns
///
/// The offset within `login` at which the host starts: `ptr - login` from
/// L320, which is one past the `@`, or the zero L272 writes when there is no
/// `@` at all. The caller appends from there.
///
/// # Errors
///
/// - `crate::abi::CURLUE_OUT_OF_MEMORY` when a credential portion cannot be
///   duplicated, L292-L297.
/// - `crate::abi::CURLUE_USER_NOT_ALLOWED` when the caller passed
///   `CURLU_DISALLOW_USER` and the authority carries an `@`, L300-L304. Note
///   "carries an `@`" and not "carries a username": the two are the same
///   condition here, for the reason the module documentation gives.
///
/// The C writes its `*offset` to zero at L272, *before* either failure can
/// happen, so a caller that read the offset after a failure would see zero.
/// A `Result` makes it unreadable instead, which is the same guarantee in a
/// stronger form; the sole caller does not read it, at L618-L619.
#[must_use = "the host offset is the output and the failure codes must be handled"]
pub(crate) fn parse_hostname_login(
    u: &mut CurlUrl,
    login: &[u8],
    len: usize,
    flags: c_uint,
) -> Result<usize, CURLUcode> {
    // The pointer-and-length pair of L249-L250, narrowed to the bytes the C
    // can reach. `parse_authority` has already clamped, so the two agree at
    // the one call site; the parameter is kept because the C has it and
    // because that is what makes this function independently correct.
    let login = login.get(..len).unwrap_or(login);

    // L270 is `DEBUGASSERT(login)`, which a slice makes unrepresentable.
    //
    // L272-L275. The offset is written first, so the no-`@` path leaves it
    // at zero and the whole authority becomes the host. This arm is `FB2`
    // path (a): the C jumps to the exit label with `result` still holding
    // the `CURLUE_OK` from L254, so the label is a *success* exit here and
    // the clearing below is not an error path. It is what makes an authority
    // without credentials wipe any the handle already carried.
    let Some(at) = login.iter().position(|&byte| byte == b'@') else {
        clear_credentials(u);
        return Ok(0);
    };

    // L277-L280 steps past the `@`; the offset does that arithmetic once, at
    // the end.
    //
    // L282-L284: `if(u->scheme) h = Curl_get_scheme(u->scheme)`, and L287's
    // comment is explicit that `h` may legitimately be NULL -- an unknown or
    // absent scheme simply means no options are parsed. L290 then tests
    // `h->flags & PROTOPT_URLOPTIONS`, the only bit of the descriptor this
    // stage reads, which exactly six schemes carry: `imap`, `imaps`, `pop3`,
    // `pop3s`, `smtp` and `smtps`.
    //
    // `Curl_get_scheme` is a one-line forward to
    // `Curl_getn_scheme(scheme, strlen(scheme))` at `lib/url.c`:L1469-L1471,
    // so the length-delimited entry point reaches the same table without
    // building a C string. `crate::scheme` owns both, and owns the
    // compile-time choice between libcurl's table and the crate's own; this
    // module declares nothing foreign, which is what
    // `#![forbid(unsafe_code)]` above enforces.
    let want_options = u
        .scheme()
        .map(cstring_window)
        .and_then(getn_scheme)
        .is_some_and(SchemeInfo::has_url_options);

    // L288-L291. The span handed over is `ptr - login - 1`, everything
    // before the `@`.
    let credentials = login.get(..at).unwrap_or(login);
    let details = match parse_login_details(credentials, want_options) {
        Ok(details) => details,
        // L292-L297, `FB2` path (b). Every failure that call can report is
        // out of memory, which its own comment at L293-L294 states.
        Err(_) => {
            clear_credentials(u);
            return Err(CURLUE_OUT_OF_MEMORY);
        }
    };

    // L299 is `if(userp)`, and it is *always* true: the user portion is
    // allocated unconditionally, so there is no branch left to write here.
    // The module documentation carries the three consequences.
    //
    // L300-L304, `FB2` path (c). The `details` value is still alive at this
    // point and its three buffers are released when it goes out of scope,
    // which is the `curlx_free` of the three locals at L325-L327. The C
    // releases the locals before clearing the fields; the order between the
    // two is not observable, since neither is reachable afterwards.
    if flags & CURLU_DISALLOW_USER != 0 {
        clear_credentials(u);
        return Err(CURLUE_USER_NOT_ALLOWED);
    }

    // L305-L306, L310-L311 and L315-L316: each field is released before the
    // new value is stored. `crate::handle::CurlUrl::store` is that pair,
    // with the release being the `Drop` of the value the assignment
    // displaces, so the ordering cannot be got wrong here the way it can in
    // C.
    u.store(StringField::User, details.user);
    if let Some(password) = details.password {
        u.store(StringField::Password, password);
    }
    if let Some(options) = details.options {
        u.store(StringField::Options, options);
    }

    // L319-L321: `*offset = ptr - login`, one past the `@`. `at` is an
    // offset below `len`, so the increment cannot overflow; the saturating
    // form is used because the crate denies unchecked arithmetic and there
    // is no value to gain from a checked form that cannot fail.
    Ok(at.saturating_add(1))
}

/// Parses an authority into the handle and the host buffer.
///
/// `parse_authority` at `lib/urlapi.c`:L604-L655. The module documentation
/// carries the stage order and why it is behavior rather than style.
///
/// Not exported to C, for the same reason as
/// [`parse_hostname_login`]: the C function is `static`.
///
/// # Parameters
///
/// - `u`: the handle. The credentials, the port and the zone identifier may
///   all be written; the host is not, and is left to the caller, which is
///   what makes the two callers differ. On the parse path `u` is the zeroed
///   temporary from L1201-L1202; through [`url_set_authority`] it is the
///   caller's own live handle.
/// - `auth`: the authority, and possibly more, as L1149 passes it.
/// - `authlen`: how much of `auth` is the authority, from L1143.
/// - `flags`: the caller's flag word, forwarded to
///   [`parse_hostname_login`], which reads `CURLU_DISALLOW_USER` from it.
/// - `host`: the buffer the host is assembled in. Appended to at L621 and
///   then rewritten in place by the port, decode and normalize stages. It is
///   **not** released on any failure path here, and the C does not release
///   it either: it belongs to the caller, which frees it at L669 or L1189.
/// - `has_scheme`: whether the handle has a scheme, which is `u->scheme !=
///   NULL` at L1150 and `!!u->scheme` at L667. Only the port stage reads it,
///   for the bare-colon leniency `docs/KNOWN-DIVERGENCES.md` records as
///   `FB4`.
///
/// # Returns
///
/// `crate::abi::CURLUE_OK` with the host in `host`, which is L654 reached
/// with `uc` still holding a success.
///
/// # Errors
///
/// Everything the five stages can report:
/// `crate::abi::CURLUE_OUT_OF_MEMORY` and `crate::abi::CURLUE_USER_NOT_ALLOWED`
/// from L617; `crate::abi::CURLUE_TOO_LARGE` or
/// `crate::abi::CURLUE_OUT_OF_MEMORY` from the append at L621-L625;
/// `crate::abi::CURLUE_BAD_PORT_NUMBER` or `crate::abi::CURLUE_BAD_IPV6` from
/// L627; `crate::abi::CURLUE_NO_HOST` from L631; and
/// `crate::abi::CURLUE_BAD_IPV6`, `crate::abi::CURLUE_BAD_HOSTNAME` or
/// `crate::abi::CURLUE_OUT_OF_MEMORY` from the classification at L634-L651.
#[must_use = "the parse verdict is the return value and must be handled"]
pub(crate) fn parse_authority(
    u: &mut CurlUrl,
    auth: &[u8],
    authlen: usize,
    flags: c_uint,
    host: &mut DynBuf,
    has_scheme: bool,
) -> CURLUcode {
    // The pointer-and-length pair of L605, narrowed once so that every stage
    // below sees exactly the bytes the C's arithmetic reaches.
    let auth = auth.get(..authlen).unwrap_or(auth);

    // Stage 1, L614-L619. `goto out` at L619 is a bare return, since the
    // label at L653 does nothing else.
    let offset = match parse_hostname_login(u, auth, auth.len(), flags) {
        Ok(offset) => offset,
        Err(code) => return code,
    };

    // Stage 2, L621-L625: `curlx_dyn_addn(host, auth + offset, authlen -
    // offset)`. The offset is at most `auth.len()`, so the tail cannot be
    // out of range and the empty fallback is unreachable -- an authority of
    // exactly `user@` appends nothing and is rejected two stages later by
    // the empty-host test.
    let result = host.addn(auth.get(offset..).unwrap_or(&[]));
    if result.is_err() {
        // L622-L624. The failed append has already released the buffer,
        // contract 1 of `crate::dynbuf`, which is why neither the C nor this
        // adds a release of its own.
        return cc2cu(result);
    }

    // Stage 3, L627-L629. This runs *before* the classification, which is
    // why a host with a port on it is normalized without the port attached,
    // and *before* the empty-host test, which is why an authority of just
    // `":80"` is a no-host error.
    let uc = parse_port(u, host, has_scheme);
    if uc != CURLUE_OK {
        return uc;
    }

    // Stage 4, L631-L632. The C writes this one as a `return` rather than a
    // `goto out`; the two are identical because the label only returns.
    if host.is_empty() {
        return CURLUE_NO_HOST;
    }

    // Stage 5, L634-L651. The C's `switch` has a `default` arm at L648-L649
    // that yields `CURLUE_BAD_HOSTNAME`, and it is unreachable:
    // `ipv4_normalize` returns exactly the four values L477-L481 define.
    // `crate::parse::host::HostKind` has exactly those four variants, so
    // this `match` is exhaustive without a catch-all and the arm is proven
    // absent rather than lost. No fifth variant should be invented to carry
    // it.
    //
    // The C declares `uc` uninitialized at L611 and every path assigns it
    // before use, so the value each arm produces is stated here instead of
    // being carried in a mutable binding.
    match ipv4_normalize(host) {
        // L635-L636 is a bare `break`, leaving `uc` at the success the port
        // stage returned at L627 and the test at L628 confirmed. That value
        // is `CURLUE_OK`, written out.
        HostKind::Ipv4 => CURLUE_OK,
        // L637-L639. The length is read before the mutable view is taken,
        // and the view spans `len + 1` bytes so that the terminator slot is
        // writable, which is `FB6` and which
        // `crate::parse::ipv6::ipv6_parse` documents as its entry contract.
        HostKind::Ipv6 => {
            let hlen = host.len();
            let mut view = host.content_mut();
            ipv6_parse(u, &mut view, hlen)
        }
        // L640-L644. Decode first, then check, and check only if the decode
        // succeeded -- the C's `uc = urldecode_host(host); if(!uc) uc =
        // hostname_check(...)`, written as one value rather than two
        // assignments. The order cannot be swapped: `%` is in the set
        // `hostname_check` refuses, so checking first would reject every
        // percent-encoded host.
        HostKind::Name => {
            let decoded = urldecode_host(host);
            if decoded != CURLUE_OK {
                decoded
            } else {
                let hlen = host.len();
                let mut view = host.content_mut();
                hostname_check(u, &mut view, hlen)
            }
        }
        // L645-L646. The buffer has already been released by the failed
        // append inside `ipv4_normalize`, as above.
        HostKind::Error => CURLUE_OUT_OF_MEMORY,
    }
}

/// Replaces the handle's host, user, password, options and port from an
/// authority string.
///
/// `Curl_url_set_authority` at `lib/urlapi.c`:L658-L675, added for HTTP/2
/// server push per the comment at L657 and called at `lib/http2.c`:L739. One
/// of the eight globals `lib/urlapi.o` defines, declared for the rest of
/// libcurl at `lib/urlapi-int.h`:L31 as
///
/// ```c
/// CURLUcode Curl_url_set_authority(CURLU *u, const char *authority);
/// ```
///
/// The export attribute is deliberately not here. `src/ffi.rs` owns every
/// `#[no_mangle] extern "C"` symbol in this crate, and owns the two things
/// that go with this one: the `*const c_char` to `&[u8]` conversion, which
/// is where the C's `strlen(authority)` at L666 happens, and the null-handle
/// precondition that reports `CURLUE_BAD_HANDLE`. The C has no such
/// precondition on the authority pointer -- L663 is
/// `DEBUGASSERT(authority)`, so the caller guarantees it -- which is why the
/// shape here takes a plain slice.
///
/// # Parameters
///
/// - `u`: the caller's own live handle. There is no temporary anywhere in
///   this path, which is what makes `FB2` reachable: an authority with no
///   `@` in it clears the three credential fields, and an authority *with*
///   an `@` is rejected outright.
/// - `authority`: the bytes of the authority, which the C measures with
///   `strlen` at L666.
///
/// # Returns
///
/// `crate::abi::CURLUE_OK`, with the host replaced and the buffer's block now
/// owned by the handle.
///
/// # Errors
///
/// Whatever [`parse_authority`] reported, unchanged, L674. The host buffer
/// is released on every one of those paths, L668-L669, and the handle's own
/// host is left exactly as it was -- but the credentials may not be, which
/// is `FB2`.
///
/// `CURLUE_USER_NOT_ALLOWED` deserves singling out: this is the only caller
/// that passes `CURLU_DISALLOW_USER`, at L667, and because the user portion
/// is always allocated, *any* `@` in the authority produces that code. Even
/// `@example.com`.
#[must_use = "the result code reports a rejected authority and must be handled"]
pub(crate) fn url_set_authority(u: &mut CurlUrl, authority: &[u8]) -> CURLUcode {
    // L661 and L664: `struct dynbuf host` with the ceiling
    // `CURL_MAX_INPUT_LENGTH`, which is the same ceiling the parse path uses
    // at L1122.
    let mut host = DynBuf::new(CURL_MAX_INPUT_LENGTH);

    // L667's `!!u->scheme`, read before the call because the call borrows
    // the handle. The C evaluates it as an argument, and the value cannot
    // differ: nothing between here and there writes the scheme.
    let has_scheme = u.has(StringField::Scheme);

    // L666-L667. The flag word is exactly `CURLU_DISALLOW_USER` and nothing
    // else -- no `CURLU_URLENCODE`, no `CURLU_NO_AUTHORITY` -- so an
    // authority is taken as already encoded.
    let result = parse_authority(
        u,
        authority,
        authority.len(),
        CURLU_DISALLOW_USER,
        &mut host,
        has_scheme,
    );

    if result != CURLUE_OK {
        // L668-L669: `curlx_dyn_free(&host)`. Harmless when a failed append
        // has already released the block, exactly as the C's
        // `Curl_safefree` is.
        host.free();
        return result;
    }

    // L670-L672: `curlx_free(u->host); u->host = curlx_dyn_ptr(&host)`.
    //
    // The C takes the pointer rather than a copy, so ownership of the block
    // moves into the handle and the local `struct dynbuf` is left dangling
    // as it goes out of scope. `crate::dynbuf::DynBuf::into_cbuf` is that
    // same move, made typed: the buffer is consumed, so there is no dangling
    // value left to misuse, and the block's release obligation travels with
    // the `CBuf` into the handle.
    //
    // The trim in front of it is the C string bound, and it is load-bearing
    // rather than tidy. `ipv6_parse` rewrote the address in place without
    // telling the buffer, so a normalized `[0000::1]` leaves nine recorded
    // bytes over a five-byte C string. C never notices, because a `char *`
    // ends at its terminator; a `CBuf` carries a length, so the length is
    // brought down to what C would measure. `setlen` cannot refuse -- the
    // window is never longer than the content -- and its `bool` is the
    // return value both C call sites drop, for the reasons
    // `crate::dynbuf::DynBuf::setlen` records.
    let measured = cstring_window(host.as_bytes()).len();
    host.setlen(measured);
    match host.into_cbuf() {
        // L671-L672 as one operation: `crate::handle::CurlUrl::store`
        // releases the old host as part of the assignment.
        Some(buf) => u.store(StringField::Host, buf),
        // `curlx_dyn_ptr` on a buffer that never allocated returns NULL, and
        // the C would assign that. Unreachable from here, because stage 4 of
        // `parse_authority` has already rejected an empty host, and modelled
        // anyway so that the C's assignment has a counterpart rather than an
        // argument.
        None => u.clear(StringField::Host),
    }

    // L674 is `return result`, and on this branch `result` is the success the
    // test above established, so the value is written out rather than carried.
    CURLUE_OK
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's entire job is to panic when an
    // assertion fails, and a test never crosses that boundary, so the
    // denials are relaxed here and only here. The allowance is scoped to
    // this module and enumerated rather than blanket, matching
    // `src/parse/host.rs` and `src/parse/ipv6.rs`.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    // The snapshots below copy the buffers out of the handle so that an
    // assertion can be written after the handle is gone, and they reach the
    // heap through the `alloc` crate rather than through `std`, so that this
    // module compiles the same way whichever the crate root turns out to
    // declare. Every other module in this crate imports from `core` alone,
    // and this keeps that property intact.
    extern crate alloc;

    // Imported by name rather than through a glob, as everywhere else in the
    // crate, so each use site names its source.
    use super::{
        cstring_window, parse_authority, parse_hostname_login, parse_login_details,
        url_set_authority,
    };
    use crate::abi::{
        CURLUcode, CURLUE_BAD_HOSTNAME, CURLUE_BAD_PORT_NUMBER, CURLUE_NO_HOST, CURLUE_OK,
        CURLUE_USER_NOT_ALLOWED, CURLU_DISALLOW_USER, CURL_MAX_INPUT_LENGTH,
    };
    use crate::alloc::CBuf;
    use crate::dynbuf::DynBuf;
    use crate::handle::{CurlUrl, StringField};
    use alloc::vec::Vec;
    use core::ffi::c_uint;

    /// Two schemes and one non-scheme, chosen so that every case below works
    /// under both scheme backends.
    ///
    /// `crate::scheme` compiles either the crate's own table or libcurl's
    /// `Curl_get_scheme`, and in the second configuration a test binary
    /// resolves the symbol against the four-row double in `src/ffi.rs`. The
    /// intersection of the two is `https`, `imap`, `file` and `rtmp`, so
    /// these tests use the first two and never `http`, which the double does
    /// not carry. `imap` is one of the six schemes with
    /// `PROTOPT_URLOPTIONS`; `https` is not; and `nosuch` is in neither
    /// table while staying inside the seven-byte bound
    /// `Curl_getn_scheme` imposes, so it exercises "not found" rather than
    /// "too long".
    const SCHEME_WITH_OPTIONS: &[u8] = b"imap";
    const SCHEME_WITHOUT_OPTIONS: &[u8] = b"https";
    const SCHEME_UNKNOWN: &[u8] = b"nosuch";

    /// The three credential fields of the handle, copied out.
    ///
    /// Every case asserts all three, including the failing ones, because
    /// `FB2` is a statement about what a *failing* call -- and one
    /// particular *succeeding* call -- does to fields it was not asked to
    /// touch. A suite that only checked result codes could not see it.
    #[derive(Debug, PartialEq, Eq)]
    struct Credentials {
        /// `u->user`.
        user: Option<Vec<u8>>,
        /// `u->password`.
        password: Option<Vec<u8>>,
        /// `u->options`.
        options: Option<Vec<u8>>,
    }

    impl Credentials {
        /// All three absent, which is what `FB2` leaves behind.
        fn none() -> Self {
            Self::of_parts(None, None, None)
        }

        /// The expectation, written as three optional byte strings.
        fn of_parts(user: Option<&[u8]>, password: Option<&[u8]>, options: Option<&[u8]>) -> Self {
            Self {
                user: user.map(Vec::from),
                password: password.map(Vec::from),
                options: options.map(Vec::from),
            }
        }

        /// Reads the three fields off a handle.
        fn of(u: &CurlUrl) -> Self {
            Self {
                user: u.user().map(Vec::from),
                password: u.password().map(Vec::from),
                options: u.options().map(Vec::from),
            }
        }
    }

    /// Everything one [`parse_authority`] or [`url_set_authority`] call
    /// leaves behind.
    #[derive(Debug, PartialEq, Eq)]
    struct Outcome {
        /// The `CURLUcode` returned.
        code: CURLUcode,
        /// The host as a C consumer would read it. See [`host_of`] for why
        /// this is the C string window and not the buffer's own length.
        host: Vec<u8>,
        /// `u->port`, the textual port.
        port: Option<Vec<u8>>,
        /// `u->portnum`.
        portnum: u16,
        /// The three credential fields.
        credentials: Credentials,
    }

    /// A fresh handle, optionally carrying a scheme.
    fn handle(scheme: Option<&[u8]>) -> CurlUrl {
        let mut u = CurlUrl::new();
        if let Some(scheme) = scheme {
            u.store(StringField::Scheme, CBuf::from_slice(scheme).unwrap());
        }
        u
    }

    /// Stores a value in one field of a handle, for the live-handle cases.
    fn preset(u: &mut CurlUrl, which: StringField, value: &[u8]) {
        u.store(which, CBuf::from_slice(value).unwrap());
    }

    /// The host a C caller would see: the buffer's bytes up to the first
    /// terminator.
    ///
    /// Not `DynBuf::as_bytes`, deliberately. `ipv6_parse` rewrites the
    /// address behind the buffer's back and never calls `curlx_dyn_setlen`,
    /// so after normalization the recorded length overstates the C string.
    /// `parse_authority` leaves it that way, exactly as the C does, and
    /// [`url_set_authority`] is where the two are reconciled -- which is
    /// what `the_setter_stores_a_normalized_address_as_a_c_string` below
    /// pins.
    fn host_of(host: &DynBuf) -> Vec<u8> {
        Vec::from(cstring_window(host.as_bytes()))
    }

    /// Runs [`parse_hostname_login`] over `login` with the given scheme and
    /// flags, and reports the verdict together with the three fields.
    fn split(
        scheme: Option<&[u8]>,
        login: &[u8],
        flags: c_uint,
    ) -> (Result<usize, CURLUcode>, Credentials) {
        split_over(scheme, login, login.len(), flags, &[])
    }

    /// [`split`] with an explicit length and with fields already populated,
    /// which is the live-handle shape `url_set_authority` produces.
    fn split_over(
        scheme: Option<&[u8]>,
        login: &[u8],
        len: usize,
        flags: c_uint,
        existing: &[(StringField, &[u8])],
    ) -> (Result<usize, CURLUcode>, Credentials) {
        let mut u = handle(scheme);
        for &(which, value) in existing {
            preset(&mut u, which, value);
        }
        let verdict = parse_hostname_login(&mut u, login, len, flags);
        (verdict, Credentials::of(&u))
    }

    /// Runs [`parse_authority`] over the whole of `auth`.
    fn authority(scheme: Option<&[u8]>, auth: &[u8], flags: c_uint) -> Outcome {
        authority_over(scheme, auth, auth.len(), flags, &[])
    }

    /// [`authority`] with an explicit `authlen` and with fields already
    /// populated.
    ///
    /// `has_scheme` is derived from the handle the way L1150 and L667 both
    /// derive it, so a case that wants it false simply passes no scheme.
    fn authority_over(
        scheme: Option<&[u8]>,
        auth: &[u8],
        authlen: usize,
        flags: c_uint,
        existing: &[(StringField, &[u8])],
    ) -> Outcome {
        let mut u = handle(scheme);
        for &(which, value) in existing {
            preset(&mut u, which, value);
        }
        let mut host = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        let has_scheme = u.has(StringField::Scheme);
        let code = parse_authority(&mut u, auth, authlen, flags, &mut host, has_scheme);
        Outcome {
            code,
            host: host_of(&host),
            port: u.port().map(Vec::from),
            portnum: u.portnum(),
            credentials: Credentials::of(&u),
        }
    }

    /// Runs [`url_set_authority`] and reports what the handle holds
    /// afterwards. The host comes from the handle here, not from a buffer,
    /// because the transfer is what this shape is testing.
    fn set_authority(
        scheme: Option<&[u8]>,
        authority: &[u8],
        existing: &[(StringField, &[u8])],
    ) -> Outcome {
        let mut u = handle(scheme);
        for &(which, value) in existing {
            preset(&mut u, which, value);
        }
        let code = url_set_authority(&mut u, authority);
        Outcome {
            code,
            host: u.host().map(Vec::from).unwrap_or_default(),
            port: u.port().map(Vec::from),
            portnum: u.portnum(),
            credentials: Credentials::of(&u),
        }
    }

    /// The three portions of one [`parse_login_details`] call, copied out.
    fn portions(login: &[u8], want_options: bool) -> (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) {
        let details = parse_login_details(login, want_options).unwrap();
        (
            Vec::from(details.user.as_bytes()),
            details
                .password
                .as_ref()
                .map(|buf| Vec::from(buf.as_bytes())),
            details
                .options
                .as_ref()
                .map(|buf| Vec::from(buf.as_bytes())),
        )
    }

    /// `user:password` is the second of the ten shapes `lib/url.c`:L2442-L2450
    /// lists, and the options stay absent whether or not they were asked for.
    #[test]
    fn a_login_splits_into_user_and_password() {
        for want_options in [false, true] {
            let (user, password, options) = portions(b"user:pass", want_options);
            assert_eq!(&user[..], b"user");
            assert_eq!(password.as_deref(), Some(&b"pass"[..]));
            assert_eq!(options, None, "want_options {want_options}");
        }
    }

    /// The user portion is allocated even when it is empty, `lib/url.c`:L2500,
    /// which is what makes `:password` and a bare `@` work at all.
    #[test]
    fn the_user_portion_is_always_allocated() {
        let (user, password, options) = portions(b"", false);
        assert_eq!(&user[..], b"");
        assert_eq!(password, None);
        assert_eq!(options, None);

        let (user, password, _) = portions(b":pass", false);
        assert_eq!(&user[..], b"");
        assert_eq!(password.as_deref(), Some(&b"pass"[..]));
    }

    /// The two gates disagree by design: the password is gated on its
    /// separator at `lib/url.c`:L2505, the options on their length at L2514.
    /// So `user:` has an empty password and `user;` has no options.
    #[test]
    fn an_empty_password_is_present_and_empty_options_are_absent() {
        let (user, password, options) = portions(b"user:", true);
        assert_eq!(&user[..], b"user");
        assert_eq!(password.as_deref(), Some(&b""[..]));
        assert_eq!(options, None);

        let (user, password, options) = portions(b"user;", true);
        assert_eq!(&user[..], b"user");
        assert_eq!(password, None);
        assert_eq!(options, None);
    }

    /// Both orderings of the two separators produce the same three portions,
    /// which is what the `psep > osep` and `osep > psep` guards at
    /// `lib/url.c`:L2490 and L2493-L2496 are for. These are the two rows of
    /// the table in the module documentation.
    #[test]
    fn both_separator_orderings_split_the_same_way() {
        for login in [&b"user;options:password"[..], &b"user:password;options"[..]] {
            let (user, password, options) = portions(login, true);
            assert_eq!(&user[..], b"user", "login {login:?}");
            assert_eq!(
                password.as_deref(),
                Some(&b"password"[..]),
                "login {login:?}"
            );
            assert_eq!(options.as_deref(), Some(&b"options"[..]), "login {login:?}");
        }
    }

    /// Without a destination for the options a `;` is an ordinary byte, which
    /// is exactly the difference between the two adjacent rows at
    /// `tests/libtest/lib1560.c`:L442-L447: the `imap` URL splits `option`
    /// out and the `http` one keeps `pass;option` as its password.
    #[test]
    fn a_semicolon_is_an_ordinary_byte_when_options_are_not_wanted() {
        let (user, password, options) = portions(b"user:pass;option", false);
        assert_eq!(&user[..], b"user");
        assert_eq!(password.as_deref(), Some(&b"pass;option"[..]));
        assert_eq!(options, None);

        let (user, password, options) = portions(b"user:pass;option", true);
        assert_eq!(&user[..], b"user");
        assert_eq!(password.as_deref(), Some(&b"pass"[..]));
        assert_eq!(options.as_deref(), Some(&b"option"[..]));
    }

    /// The offset lands one past the `@`, `lib/urlapi.c`:L320, so the caller
    /// appends from the first byte of the host.
    #[test]
    fn a_credential_split_reports_the_offset_of_the_host() {
        let login = b"user:pass@host";
        let (verdict, credentials) = split(Some(SCHEME_WITHOUT_OPTIONS), login, 0);
        assert_eq!(verdict, Ok(10));
        assert_eq!(&login[10..], b"host");
        assert_eq!(
            credentials,
            Credentials::of_parts(Some(b"user"), Some(b"pass"), None)
        );
    }

    /// No colon, no password field at all -- absent, not empty.
    #[test]
    fn a_password_is_absent_when_the_login_has_no_colon() {
        let (verdict, credentials) = split(Some(SCHEME_WITHOUT_OPTIONS), b"user@host", 0);
        assert_eq!(verdict, Ok(5));
        assert_eq!(
            credentials,
            Credentials::of_parts(Some(b"user"), None, None)
        );
    }

    /// A bare `@` yields an empty but *present* user, which
    /// `tests/libtest/lib1560.c`:L794-L795 asserts end to end:
    /// `http:/@example.com:123` round-trips as `http://@example.com:123/`,
    /// `@` included.
    #[test]
    fn an_empty_user_is_still_a_present_user() {
        let (verdict, credentials) = split(Some(SCHEME_WITHOUT_OPTIONS), b"@host", 0);
        assert_eq!(verdict, Ok(1));
        assert_eq!(credentials, Credentials::of_parts(Some(b""), None, None));

        // `tests/libtest/lib1560.c`:L797-L798, the companion row: an empty
        // user with a password.
        let (verdict, credentials) = split(Some(SCHEME_WITHOUT_OPTIONS), b":password@host", 0);
        assert_eq!(verdict, Ok(10));
        assert_eq!(
            credentials,
            Credentials::of_parts(Some(b""), Some(b"password"), None)
        );
    }

    /// No `@` at all: the offset stays at the zero L272 wrote, so the whole
    /// authority is the host.
    #[test]
    fn an_authority_without_credentials_leaves_the_offset_at_zero() {
        let (verdict, credentials) = split(Some(SCHEME_WITHOUT_OPTIONS), b"host", 0);
        assert_eq!(verdict, Ok(0));
        assert_eq!(credentials, Credentials::none());
    }

    /// The options are parsed only for a scheme carrying
    /// `PROTOPT_URLOPTIONS`, L290. `tests/libtest/lib1560.c`:L442-L447 is the
    /// same pair of rows end to end.
    #[test]
    fn options_are_parsed_only_for_a_scheme_that_allows_them() {
        let (verdict, credentials) = split(Some(SCHEME_WITH_OPTIONS), b"user;opt@host", 0);
        assert_eq!(verdict, Ok(9));
        assert_eq!(
            credentials,
            Credentials::of_parts(Some(b"user"), None, Some(b"opt"))
        );

        let (verdict, credentials) = split(Some(SCHEME_WITHOUT_OPTIONS), b"user;opt@host", 0);
        assert_eq!(verdict, Ok(9));
        assert_eq!(
            credentials,
            Credentials::of_parts(Some(b"user;opt"), None, None)
        );
    }

    /// L283 skips the lookup when there is no scheme, and L287's comment says
    /// `h` may be NULL when there is one the table does not know. Both mean no
    /// options.
    #[test]
    fn an_absent_or_unknown_scheme_parses_no_options() {
        for scheme in [None, Some(SCHEME_UNKNOWN)] {
            let (verdict, credentials) = split(scheme, b"user;opt@host", 0);
            assert_eq!(verdict, Ok(9), "scheme {scheme:?}");
            assert_eq!(
                credentials,
                Credentials::of_parts(Some(b"user;opt"), None, None),
                "scheme {scheme:?}"
            );
        }
    }

    /// Both orderings again, this time through to the handle.
    /// `tests/libtest/lib1560.c`:L769-L771 is the second of the two as a
    /// round trip.
    #[test]
    fn both_separator_orderings_reach_the_handle() {
        for login in [&b"user;opt:pass@host"[..], &b"user:pass;opt@host"[..]] {
            let (verdict, credentials) = split(Some(SCHEME_WITH_OPTIONS), login, 0);
            assert_eq!(verdict, Ok(14), "login {login:?}");
            assert_eq!(
                credentials,
                Credentials::of_parts(Some(b"user"), Some(b"pass"), Some(b"opt")),
                "login {login:?}"
            );
        }
    }

    /// `memchr` finds the *first* `@`, L273, so a second one stays in the
    /// host, where the host-name check rejects it later.
    #[test]
    fn only_the_first_at_sign_separates_the_credentials() {
        let (verdict, credentials) = split(Some(SCHEME_WITHOUT_OPTIONS), b"user@name@host", 0);
        assert_eq!(verdict, Ok(5));
        assert_eq!(
            credentials,
            Credentials::of_parts(Some(b"user"), None, None)
        );
    }

    /// The length bounds the search, L273, which is what stops a `@` in the
    /// path from being read as a credential separator. L1143 computes that
    /// length from `strcspn(hostp, "/?#")`.
    #[test]
    fn the_length_bounds_the_at_sign_search() {
        let login = b"host/user@path";
        let (verdict, credentials) = split_over(Some(SCHEME_WITHOUT_OPTIONS), login, 4, 0, &[]);
        assert_eq!(verdict, Ok(0));
        assert_eq!(credentials, Credentials::none());

        // The same bytes with the whole slice in scope do find it, which
        // proves the bound above is what made the difference.
        let (verdict, _) = split(Some(SCHEME_WITHOUT_OPTIONS), login, 0);
        assert_eq!(verdict, Ok(10));
    }

    /// `FB2` path (c), and the `CURLU_DISALLOW_USER` rule.
    /// `tests/libtest/lib1560.c`:L791-L793 asserts the code for
    /// `http://hello:fool@example.com`; the second half here is the part no
    /// result-code check can see, that the three fields the handle already
    /// held are cleared on the way out.
    #[test]
    fn disallow_user_rejects_the_login_and_clears_the_fields() {
        let existing: &[(StringField, &[u8])] = &[
            (StringField::User, b"old-user"),
            (StringField::Password, b"old-pass"),
            (StringField::Options, b"old-opt"),
        ];
        let (verdict, credentials) = split_over(
            Some(SCHEME_WITH_OPTIONS),
            b"hello:fool@example.com",
            22,
            CURLU_DISALLOW_USER,
            existing,
        );
        assert_eq!(verdict, Err(CURLUE_USER_NOT_ALLOWED));
        assert_eq!(credentials, Credentials::none());
    }

    /// The same rejection for an authority that carries no username at all,
    /// because the user portion is allocated unconditionally. This is why
    /// [`url_set_authority`] refuses every `@`.
    #[test]
    fn disallow_user_rejects_an_at_sign_with_no_username() {
        let (verdict, credentials) = split(
            Some(SCHEME_WITHOUT_OPTIONS),
            b"@example.com",
            CURLU_DISALLOW_USER,
        );
        assert_eq!(verdict, Err(CURLUE_USER_NOT_ALLOWED));
        assert_eq!(credentials, Credentials::none());
    }

    /// `FB2` path (a), and the regression guard for it: the exit label is
    /// reached with `result` still `CURLUE_OK`, so an authority with no `@`
    /// **succeeds** and still clears all three fields. Reproducing this is a
    /// requirement, not an accident; the module documentation and
    /// `docs/KNOWN-DIVERGENCES.md` carry the finding.
    #[test]
    fn an_authority_without_an_at_sign_clears_pre_existing_credentials() {
        let existing: &[(StringField, &[u8])] = &[
            (StringField::User, b"old-user"),
            (StringField::Password, b"old-pass"),
            (StringField::Options, b"old-opt"),
        ];
        let (verdict, credentials) =
            split_over(Some(SCHEME_WITH_OPTIONS), b"example.com", 11, 0, existing);
        assert_eq!(verdict, Ok(0));
        assert_eq!(credentials, Credentials::none());
    }

    /// The mirror image of the success path: each of the three stores is
    /// guarded by its own portion being present, L299, L309 and L314, so a
    /// login that carries only a user replaces only the user and leaves a
    /// pre-existing password and options untouched.
    #[test]
    fn a_login_replaces_only_the_portions_it_carries() {
        let existing: &[(StringField, &[u8])] = &[
            (StringField::User, b"old-user"),
            (StringField::Password, b"old-pass"),
            (StringField::Options, b"old-opt"),
        ];
        let (verdict, credentials) =
            split_over(Some(SCHEME_WITH_OPTIONS), b"new@host", 8, 0, existing);
        assert_eq!(verdict, Ok(4));
        assert_eq!(
            credentials,
            Credentials::of_parts(Some(b"new"), Some(b"old-pass"), Some(b"old-opt"))
        );
    }

    /// The whole pipeline on the ordinary case: the port is split off the
    /// host, and the host that reaches the classification no longer carries
    /// it.
    #[test]
    fn an_authority_splits_into_host_and_port() {
        let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), b"example.com:8080", 0);
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"example.com");
        assert_eq!(outcome.port.as_deref(), Some(&b"8080"[..]));
        assert_eq!(outcome.portnum, 8080);
        assert_eq!(outcome.credentials, Credentials::none());
    }

    /// Stage 3 before stage 4: the port stage truncates at the colon, and the
    /// empty-host test then fires on what is left. That ordering is the only
    /// reason `":80"` is `CURLUE_NO_HOST` rather than a host named `:80`.
    #[test]
    fn an_authority_that_is_only_a_port_is_a_no_host_error() {
        let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), b":80", 0);
        assert_eq!(outcome.code, CURLUE_NO_HOST);
        assert_eq!(&outcome.host[..], b"");
        // The port was still parsed before the host was found wanting, which
        // is what makes this a truncation and not a rejection.
        assert_eq!(outcome.port.as_deref(), Some(&b"80"[..]));
        assert_eq!(outcome.portnum, 80);
    }

    /// An empty authority never reaches the classification either. The
    /// append at L621 is of zero bytes, which forces the first allocation
    /// without adding content, so L631 sees an empty buffer.
    #[test]
    fn an_empty_authority_is_a_no_host_error() {
        let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), b"", 0);
        assert_eq!(outcome.code, CURLUE_NO_HOST);
        assert_eq!(&outcome.host[..], b"");
        assert_eq!(outcome.port, None);
    }

    /// An authority that is nothing but credentials leaves no host behind,
    /// and the credentials are stored before that is discovered.
    #[test]
    fn an_authority_of_credentials_alone_is_a_no_host_error() {
        let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), b"user:pass@", 0);
        assert_eq!(outcome.code, CURLUE_NO_HOST);
        assert_eq!(
            outcome.credentials,
            Credentials::of_parts(Some(b"user"), Some(b"pass"), None)
        );
    }

    /// The `HOST_IPV4` arm is a bare `break` at L635-L636, so a dotted quad
    /// comes back unchanged with the success the port stage left behind.
    #[test]
    fn a_dotted_quad_passes_through_unchanged() {
        let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), b"1.2.3.4", 0);
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"1.2.3.4");
    }

    /// The same arm rewrites the shorthand forms in place.
    /// `tests/libtest/lib1560.c`:L601 and L658 assert both of these end to
    /// end: `https://0x7f.1` becomes `127.0.0.1` and `https://16843009`
    /// becomes `1.1.1.1`.
    #[test]
    fn a_partial_ipv4_address_is_normalized() {
        for (input, expected) in [
            (&b"16843009"[..], &b"1.1.1.1"[..]),
            (&b"0x7f.1"[..], &b"127.0.0.1"[..]),
        ] {
            let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), input, 0);
            assert_eq!(outcome.code, CURLUE_OK, "input {input:?}");
            assert_eq!(&outcome.host[..], expected, "input {input:?}");
        }
    }

    /// The `HOST_IPV6` arm, L637-L639. The recorded length is left stale
    /// here, exactly as in C, which is why the assertion reads the C string
    /// window; [`url_set_authority`] is where that is reconciled.
    #[test]
    fn a_bracketed_address_takes_the_ipv6_path() {
        for (input, expected) in [
            (&b"[::1]"[..], &b"[::1]"[..]),
            (&b"[0000::1]"[..], &b"[::1]"[..]),
        ] {
            let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), input, 0);
            assert_eq!(outcome.code, CURLUE_OK, "input {input:?}");
            assert_eq!(&outcome.host[..], expected, "input {input:?}");
        }

        // A bracketed host with a port on it still splits, because stage 3
        // runs first and understands the closing bracket.
        let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), b"[::1]:8080", 0);
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"[::1]");
        assert_eq!(outcome.portnum, 8080);
    }

    /// The `HOST_NAME` arm, L640-L644: decode first, then check. The first
    /// row only works because of that order, and the second only fails
    /// because of it -- `%2f` decodes to a `/`, which the check refuses.
    #[test]
    fn a_percent_encoded_host_is_decoded_before_it_is_checked() {
        let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), b"ex%61mple.com", 0);
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"example.com");

        let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), b"exa%2fmple.com", 0);
        assert_eq!(outcome.code, CURLUE_BAD_HOSTNAME);
    }

    /// Stage 1 before stage 2: the credentials never reach the host buffer.
    #[test]
    fn credentials_are_stripped_before_the_host_is_appended() {
        let outcome = authority(
            Some(SCHEME_WITH_OPTIONS),
            b"user:pass;opt@example.com:8080",
            0,
        );
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"example.com");
        assert_eq!(outcome.portnum, 8080);
        assert_eq!(
            outcome.credentials,
            Credentials::of_parts(Some(b"user"), Some(b"pass"), Some(b"opt"))
        );
    }

    /// `has_scheme` reaches the port stage and nothing else. With a scheme a
    /// digit-less colon is tolerated and the name is cut short -- `FB4` --
    /// and without one the same input is rejected, so that a long run of
    /// characters followed by a colon cannot pass for a host.
    #[test]
    fn the_bare_colon_leniency_needs_a_scheme() {
        let outcome = authority(Some(SCHEME_WITHOUT_OPTIONS), b"example.com:", 0);
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"example.com");
        assert_eq!(outcome.port, None);
        assert_eq!(outcome.portnum, 0);

        let outcome = authority(None, b"example.com:", 0);
        assert_eq!(outcome.code, CURLUE_BAD_PORT_NUMBER);
    }

    /// `authlen` bounds the whole pipeline, not just the credential scan:
    /// L621 appends `authlen - offset` bytes, so the path stays out of the
    /// host.
    #[test]
    fn the_authority_length_bounds_what_is_parsed() {
        let outcome = authority_over(
            Some(SCHEME_WITHOUT_OPTIONS),
            b"example.com/some/path",
            11,
            0,
            &[],
        );
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"example.com");
    }

    /// `FB2` reaching the pipeline: a rejected authority leaves the three
    /// fields cleared and no host behind.
    #[test]
    fn a_rejected_authority_clears_the_credentials() {
        let existing: &[(StringField, &[u8])] = &[
            (StringField::User, b"old-user"),
            (StringField::Password, b"old-pass"),
        ];
        let outcome = authority_over(
            Some(SCHEME_WITHOUT_OPTIONS),
            b"user@example.com",
            16,
            CURLU_DISALLOW_USER,
            existing,
        );
        assert_eq!(outcome.code, CURLUE_USER_NOT_ALLOWED);
        assert_eq!(&outcome.host[..], b"");
        assert_eq!(outcome.credentials, Credentials::none());
    }

    /// The setter replaces the host and takes the buffer's block with it,
    /// L670-L672.
    #[test]
    fn the_setter_replaces_the_host() {
        let existing: &[(StringField, &[u8])] = &[(StringField::Host, b"old.example")];
        let outcome = set_authority(Some(SCHEME_WITHOUT_OPTIONS), b"example.com:443", existing);
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"example.com");
        assert_eq!(outcome.port.as_deref(), Some(&b"443"[..]));
        assert_eq!(outcome.portnum, 443);
    }

    /// The stale-length guard. `[0000::1]` normalizes to five bytes inside a
    /// nine-byte buffer whose recorded length nobody updated, and what the
    /// handle must end up holding is the five -- the same bytes a C caller
    /// would read through `u->host`. Without the trim at L670-L672 this
    /// assertion sees `[::1]\0:1]`.
    #[test]
    fn the_setter_stores_a_normalized_address_as_a_c_string() {
        let outcome = set_authority(Some(SCHEME_WITHOUT_OPTIONS), b"[0000::1]", &[]);
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"[::1]");
        assert_eq!(outcome.host.len(), 5);
    }

    /// The setter passes `CURLU_DISALLOW_USER` at L667 and nothing else, so
    /// any `@` at all is refused -- with or without a username in front of
    /// it. The host is left as it was, and the credentials are not, which is
    /// `FB2`.
    #[test]
    fn the_setter_rejects_any_at_sign() {
        for input in [&b"user:pass@example.com"[..], &b"@example.com"[..]] {
            let existing: &[(StringField, &[u8])] = &[
                (StringField::Host, b"old.example"),
                (StringField::User, b"old-user"),
            ];
            let outcome = set_authority(Some(SCHEME_WITHOUT_OPTIONS), input, existing);
            assert_eq!(outcome.code, CURLUE_USER_NOT_ALLOWED, "input {input:?}");
            assert_eq!(&outcome.host[..], b"old.example", "input {input:?}");
            assert_eq!(outcome.credentials, Credentials::none(), "input {input:?}");
        }
    }

    /// Every other failure also leaves the old host in place, because L668
    /// releases the buffer instead of storing it.
    #[test]
    fn the_setter_keeps_the_old_host_when_it_fails() {
        let existing: &[(StringField, &[u8])] = &[(StringField::Host, b"old.example")];
        for input in [&b""[..], &b":80"[..], &b"exa%2fmple.com"[..], &b"[::"[..]] {
            let outcome = set_authority(Some(SCHEME_WITHOUT_OPTIONS), input, existing);
            assert_ne!(outcome.code, CURLUE_OK, "input {input:?}");
            assert_eq!(&outcome.host[..], b"old.example", "input {input:?}");
        }
    }

    /// `!!u->scheme` at L667, observed through the port stage: the same
    /// authority is accepted on a handle that has a scheme and rejected on
    /// one that does not.
    #[test]
    fn the_setter_derives_has_scheme_from_the_handle() {
        let outcome = set_authority(Some(SCHEME_WITHOUT_OPTIONS), b"example.com:", &[]);
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"example.com");

        let outcome = set_authority(None, b"example.com:", &[]);
        assert_eq!(outcome.code, CURLUE_BAD_PORT_NUMBER);
    }

    /// The one call sequence in the tree, `lib/http2.c`:L723-L741: a fresh
    /// handle, the scheme set from the `:scheme` pseudo-header, then the
    /// authority from `:authority`. Nothing leaks there because nothing was
    /// there, which is the point of the `FB2` write-up.
    #[test]
    fn the_setter_matches_the_http2_call_sequence() {
        let outcome = set_authority(Some(SCHEME_WITHOUT_OPTIONS), b"example.com:8080", &[]);
        assert_eq!(outcome.code, CURLUE_OK);
        assert_eq!(&outcome.host[..], b"example.com");
        assert_eq!(outcome.portnum, 8080);
        assert_eq!(outcome.credentials, Credentials::none());
    }
}
