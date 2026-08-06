// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Percent-encoding: all of it, on both sides of the URL API.
//!
//! curl percent-encodes in three places and by three different rules. They
//! look alike. They are not alike, and the differences between them are the
//! behaviour rather than an accident of how the C happens to be written.
//! All three live here, as three separate functions, each carrying the
//! lines it was ported from:
//!
//! | Rule set | C source | Ported as |
//! |---|---|---|
//! | retrieval-side encoder | `lib/urlapi.c`:L130-L172 | [`urlencode_str`] |
//! | whole-URL retrieval path | `lib/escape.c`:L50-L87 | [`easy_escape`] |
//! | assignment-side encoder | `lib/urlapi.c`:L1887-L1915 | [`encode_part`] |
//!
//! Two supporting pieces come with them. [`find_host_sep`], the host
//! boundary search at `lib/urlapi.c`:L104-L118, is what the first rule set
//! needs in order to leave a host alone. [`allowed_in_path`], the
//! eighteen-byte extension set at L1779-L1803, is what the third one needs
//! in order to leave a path readable. A fourth transformation,
//! [`add_preencoded`] at L1916-L1933, is not a fourth encoder at all: it is
//! the `else` arm of the same `if(urlencode)` whose `if` arm is
//! [`encode_part`], and it runs when the caller says the value arrives
//! already encoded.
//!
//! **Do not merge them.** A refactor that folds any two of these together
//! necessarily changes one of them, because no two agree on what they
//! preserve. Transformation rule T6 of the Agent Action Plan, faithful over
//! correct, is the governing rule for this whole file.
//!
//! # The three rule sets, side by side
//!
//! Three questions separate them, and each one has three different answers.
//!
//! What a space becomes:
//!
//! - [`urlencode_str`]: `%20` before the first `?`, `+` after it.
//! - [`easy_escape`]: `%20`, always, because a space is not unreserved and
//!   this rule set has no plus form at all.
//! - [`encode_part`]: `+` when plus-encoding is armed, otherwise `%20`.
//!
//! What is preserved:
//!
//! - [`urlencode_str`]: every byte from `0x21` through `0x7e`.
//! - [`easy_escape`]: the 66 unreserved bytes.
//! - [`encode_part`]: the 66 unreserved bytes, plus the 18 path bytes in path
//!   mode, plus the first `=` when appending to a query.
//!
//! What happens to a host:
//!
//! - [`urlencode_str`]: nothing at all; it is copied verbatim.
//! - [`easy_escape`]: it is encoded like any other run of bytes.
//! - [`encode_part`]: not applicable; the caller has already chosen a part.
//!
//! All three emit upper-case escapes, which is the one thing they agree on.
//!
//! The second question is the one that surprises people. [`urlencode_str`]
//! preserves `%`, `+`, `&`, `=`, `<` and `>` exactly as they arrive, because
//! its test is a range check and not a set membership test, so handing it an
//! already-encoded string changes nothing. [`encode_part`] preserves none of
//! those, so handing *it* an already-encoded string encodes the `%` a second
//! time and turns `%3C` into `%253C`.
//!
//! # The host exemption, and the one path that does not honour it
//!
//! This is the single most counter-intuitive thing in the file, and it is
//! not a bug in either direction.
//!
//! [`urlencode_str`] never encodes a host. The rationale is in the source,
//! at `lib/urlapi.c`:L124-L128: "urlencode_str() writes data into an output
//! dynbuf and URL-encodes the spaces in the source URL accordingly. URL
//! encoding should be skipped for hostnames, otherwise IDN resolution will
//! fail." Percent-escaping the bytes of an internationalized host name would
//! hand libidn2 a string it cannot convert, so the authority is located with
//! [`find_host_sep`] and copied through untouched, spaces and all.
//!
//! The whole-URL retrieval path does the opposite. `urlget_url()` at
//! `lib/urlapi.c`:L1492-L1496 calls `curl_easy_escape(NULL, u->host, 0)`
//! when `CURLU_URLENCODE` is set, which escapes every byte of the host that
//! is not unreserved. It gets away with it because it is assembling a URL
//! for a caller to look at rather than one to resolve, and because the
//! bracketed-address and punycode branches above it at L1480-L1510 have
//! already claimed the cases where a host has to stay machine-readable.
//!
//! So the same flag, `CURLU_URLENCODE`, leaves a host alone on one path and
//! escapes it on the other. Both paths are ported. Neither may be "aligned"
//! with the other.
//!
//! # The case asymmetry, also not a bug
//!
//! Every escape this file emits is upper case, because [`hexbyte`] indexes
//! `Curl_udigits`, `"0123456789ABCDEF"` at `lib/mprintf.c`:L39. Every escape
//! that arrives *already present* in a value handed to `curl_url_set()` is
//! lower-cased instead, by the pass at `lib/urlapi.c`:L1922-L1932 that
//! [`lowercase_escapes`] ports.
//!
//! The two are reachable from one call. Setting a path to `a<b` with
//! `CURLU_URLENCODE` stores `a%3Cb`; setting it to `a%3Cb` with no flags
//! stores `a%3cb`. `tests/libtest/lib1560.c` asserts both, so harmonising
//! either one fails the parity diff.
//!
//! # Memory and ownership
//!
//! Nothing here allocates on its own account. Every output byte goes into a
//! [`DynBuf`], which allocates through `src/alloc.rs` and therefore through
//! the **C allocator**. That is what makes the documented contract hold: a
//! buffer that eventually reaches a caller of `curl_url_get()` is released
//! with `curl_free()`, per `docs/libcurl/curl_url_get.md`:L45 and
//! `include/curl/urlapi.h`:L130-L131, and that call is correct only because
//! the block came from the C allocator in the first place.
//!
//! Two of the six entry points hand a buffer onward and the ownership note
//! sits on each: [`easy_escape`] and [`easy_escape_bytes`] return an owned
//! [`DynBuf`] whose block the caller must either convert with
//! `DynBuf::into_cbuf` or release by dropping. The other four write into a
//! buffer the caller already owns and take nothing.
//!
//! `CString::into_raw` is banned crate-wide, because its pointer has to
//! return to Rust to be released, and it appears nowhere in this file.
//!
//! # No `unsafe`
//!
//! The module is `forbid(unsafe_code)`. Everything below is a computation
//! over byte slices, and the two-byte lookaheads that C writes as `p[1]` and
//! `p[2]` are `get` calls here, so a truncated escape at the end of a buffer
//! is a `None` rather than a read past the end.
//!
//! # See also
//!
//! `src/decode.rs` is the inverse operation, `Curl_urldecode` at
//! `lib/escape.c`:L105-L154. `src/ctype.rs` owns the byte classification and
//! the hexadecimal formatting. `docs/PORTING-NOTES.md` carries the
//! function-by-function map, and `docs/MEMORY-OWNERSHIP.md` the whole
//! ownership chain.

// The plan puts every `unsafe` block in `src/ffi.rs` (AAP 0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1). This
// module needs none: the `DynBuf` API is shaped so that an encoder can be
// written over slices. `forbid` rather than `deny`, so that an inner `allow`
// has to be argued for rather than slipped in.
#![forbid(unsafe_code)]

use core::ffi::c_int;

use crate::abi::{CURLUcode, CURLUE_OK, CURLUE_OUT_OF_MEMORY};
use crate::ctype::{hexbyte, is_unreserved, is_upper, is_xdigit, raw_tolower};
use crate::dynbuf::DynBuf;
use crate::error::cc2cu;

/// The largest input `curl_easy_escape` will accept.
///
/// `lib/escape.c`:L63-L64 rejects a length above `SIZE_MAX / 16` and the
/// number is transcribed from that line rather than chosen. The reason it
/// exists is the ceiling computed immediately afterwards at L66,
/// `length * 3 + 1`: without the guard that multiplication can wrap and size
/// the buffer far too small for the data about to be written into it.
///
/// A sixteenth of the address space is a very long way above
/// `crate::abi::CURL_MAX_INPUT_LENGTH`, so no input that reaches the URL API
/// through its public entry points can approach it. The guard is a guard,
/// not a policy.
const MAX_ESCAPE_INPUT: usize = usize::MAX / 16;

/// The bytes a C string function would see, given a byte slice.
///
/// C's string primitives stop at the terminator, and three of the ported
/// sites depend on that: the `strstr()` and the pointer walk inside
/// `find_host_sep()` at `lib/urlapi.c`:L107 and L114, the
/// `for(i = part; *i; i++)` loop guard of the assignment-side encoder at
/// L1890, and the `strlen()` folded into `curlx_dyn_add()` at L1918.
///
/// The truncation is faithful rather than defensive. A caller that passes a
/// slice holding an interior zero byte gets exactly what C would give it:
/// the prefix before that byte. No call site can produce one anyway, because
/// `Curl_junkscan()` rejects every byte below `0x21` in the input at
/// `lib/urlapi.c`:L232-L236, but reproducing the rule costs nothing and
/// removes the question.
///
/// Note that [`urlencode_str`]'s own byte loop is **not** built on this.
/// That loop is length-driven, `for(iptr = host_sep; len && !result; ...)`
/// at L150, so it encodes a zero byte as `%00` rather than stopping at it.
/// The difference is real and is tested.
fn cstring_window(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&byte| byte == 0) {
        // `position` reports an index inside the slice by definition, so the
        // `get` cannot fail; the fallback exists only so that no unwrap
        // appears in a crate that denies them.
        Some(nul) => bytes.get(..nul).unwrap_or(bytes),
        None => bytes,
    }
}

/// The index of the first `"//"` in `text`, or `None`.
///
/// `strstr(url, "//")` at `lib/urlapi.c`:L107. The caller has already
/// narrowed `text` to the C string view with [`cstring_window`], which is
/// what makes this equivalent to the C: `strstr()` would stop at the
/// terminator too.
///
/// A match at index `at` guarantees `at + 2 <= text.len()`, which is what
/// lets the caller step past the pair without a bounds question.
fn find_double_slash(text: &[u8]) -> Option<usize> {
    // `windows(2)` yields nothing at all for a slice shorter than two bytes,
    // which is the `strstr()` miss. The slice pattern is the comparison, so
    // no array-versus-slice equality is involved.
    text.windows(2)
        .position(|pair| matches!(pair, [b'/', b'/']))
}

/// The index at which the authority ends, reproducing `find_host_sep`.
///
/// `lib/urlapi.c`:L104-L118 in full:
///
/// ```c
/// static const char *find_host_sep(const char *url)
/// {
///   /* Find the start of the hostname */
///   const char *sep = strstr(url, "//");
///   if(!sep)
///     sep = url;
///   else
///     sep += 2;
///
///   /* Find first / or ? */
///   while(*sep && *sep != '/' && *sep != '?')
///     sep++;
///
///   return sep;
/// }
/// ```
///
/// An index is returned where C returns a pointer, so that the one caller
/// stays free of pointer arithmetic and of `unsafe`. The index is always
/// within `0..=cstring_window(url).len()`, so slicing with it cannot fail.
///
/// # The search is not anchored to a scheme, and that is not a mistake
///
/// `strstr()` looks for `"//"` **anywhere** in the string. There is no test
/// that what precedes it is a scheme, and no test that a scheme is present
/// at all. So `a//b/c` is treated as having its authority at `b`, and the
/// returned index is 4, the position of the second `/`. Do not "fix" this:
/// the one caller, [`urlencode_str`] at `lib/urlapi.c`:L142, is reached with
/// `relative == false` from exactly one place, the relative-URL rebuild at
/// L1275, where the string being scanned has already been assembled from a
/// parsed handle and therefore does begin with a scheme.
///
/// # The two ways the walk stops
///
/// At a `/` or a `?`, which is the authority's real end, or at the end of
/// the string, in which case the whole remainder is authority. A URL with a
/// query but no path, `http://www.example.com?id=2380` from the comment at
/// L101-L102, takes the `?` branch, which is why the comment mentions it.
#[must_use]
pub(crate) fn find_host_sep(url: &[u8]) -> usize {
    let text = cstring_window(url);

    // L107-L111. The miss leaves the search at the very start of the string,
    // so a URL with no `//` is scanned from byte zero.
    let mut idx = match find_double_slash(text) {
        None => 0,
        // `saturating_add` because the crate denies arithmetic that could
        // wrap. It is exact: a match at `at` means `at + 2` is a real index
        // bound of a slice, so it is representable.
        Some(at) => at.saturating_add(2),
    };

    // L114-L115. The `*sep` half of the C's loop guard is the `get` here:
    // running off the end of the C string view ends the walk exactly as
    // reaching the terminator does.
    while let Some(&byte) = text.get(idx) {
        if byte == b'/' || byte == b'?' {
            break;
        }
        idx = idx.saturating_add(1);
    }

    idx
}

/// The retrieval-side encoder: `urlencode_str` at `lib/urlapi.c`:L130-L172.
///
/// Rule set one of three. It exists to make a URL that curl parsed safe to
/// hand back as text, and its whole preserved set is "printable ASCII except
/// the space", which is why it is so much more permissive than the other
/// two. `%`, `+`, `&`, `=`, `<` and `>` all pass through unchanged.
///
/// # Parameters
///
/// - `o`: the destination. It is the caller's buffer, and this function never
///   frees it: a failed append has already released it, which is contract 1
///   of `src/dynbuf.rs`, and every other path leaves it alone.
/// - `url`: the bytes to encode.
/// - `len`: how many of them, counted from the start of `url`. It is a
///   separate parameter because four of the five C call sites pass a window
///   into the middle of a longer string rather than a whole one, for instance
///   `urlencode_str(&enc, query + 1, qlen - 1, TRUE, TRUE)` at L1046. A
///   `len` beyond the slice is clamped, which is the only defined behaviour
///   available; C would read past the caller's buffer.
/// - `relative`: `false` means "this is a whole URL, so it has an authority
///   that must not be touched". See the host exemption below.
/// - `query`: `true` means "these bytes are the query part", which starts the
///   space rule in its second state. See the `left` flag below.
///
/// # The `left` flag, and why "space becomes plus" is positional
///
/// L135 is `bool left = !query;`, the **negation**, and everything about the
/// space rule follows from it:
///
/// - a space becomes `%20` while `left` is true, L152-L153;
/// - a space becomes `+` once `left` is false, L154-L155;
/// - `left` becomes false when a `?` is copied through, L164-L165, and
///   nothing ever sets it back.
///
/// So for a part that is *not* flagged as the query, the plus form applies to
/// everything after the first `?` in the input, which is the query and the
/// fragment together rather than a part named "query". And for a part that
/// *is* flagged as the query, `left` starts false, so the very first space
/// becomes `+` with no `?` needed. A caller passing a whole URL and a caller
/// passing a query part therefore get different answers for the same bytes,
/// by design.
///
/// # The verbatim host prefix
///
/// When `relative` is false, L140-L148 locates the end of the authority with
/// [`find_host_sep`] and appends everything up to it in **one** length-bounded
/// append, with no inspection of the bytes at all. A space inside a host
/// survives as a space. The in-source reason is at L124-L128: "URL encoding
/// should be skipped for hostnames, otherwise IDN resolution will fail."
///
/// The prefix length is then subtracted from `len` at L147, so the byte loop
/// covers `url[prefix .. len]` and the two together cover exactly `len`
/// bytes. C spells that subtraction `len -= n`, which would wrap if the
/// prefix were somehow longer than `len`; this port saturates instead. The
/// difference is unobservable, because the only C call site that passes
/// `relative == false` is L1275, which passes `strlen(useurl)` as `len`, and
/// [`find_host_sep`] cannot return an index beyond the string it was given.
///
/// # Returns
///
/// `crate::abi::CURLUE_OK`, or the fold of a failed append through
/// `crate::error::cc2cu`, which is L169-L170. That fold is lossy on purpose;
/// `src/error.rs` documents why.
// The range test at L157 is transcribed as C writes it, two comparisons
// against two literals, and clippy would rewrite it as
// `!(b' '..0x7f).contains(&byte)`. The suggestion is behaviourally correct
// and is not taken, for the reason `src/ctype.rs` gives above its own range
// predicates: a reviewer diffing this function against L157 has to read the
// same two literals in the same shape in order to confirm the port, and a
// `contains` call with an exclusive upper bound hides the one detail most
// worth checking, namely that 0x7f itself is on the escaped side. The allow
// is scoped to this function and to this one lint.
#[allow(clippy::manual_range_contains)]
#[must_use = "the result code reports a failed append and must be handled"]
pub(crate) fn urlencode_str(
    o: &mut DynBuf,
    url: &[u8],
    len: usize,
    relative: bool,
    query: bool,
) -> CURLUcode {
    // L135. The negation is the whole space rule; see the doc comment.
    let mut left = !query;

    // L137: `host_sep` starts at `url`, which is index zero here, and the
    // byte loop then covers all `len` bytes.
    let mut start: usize = 0;
    let mut remaining = len;

    if !relative {
        let sep = find_host_sep(url);
        // L145-L146: `n = host_sep - url` and then one append of the whole
        // prefix, unexamined. `find_host_sep` cannot exceed the slice, so the
        // `get` succeeds; the fallback exists only so that no unwrap appears.
        let prefix = url.get(..sep).unwrap_or(url);
        let result = o.addn(prefix);
        if result.is_err() {
            // L169-L170. The buffer has already been released by the failed
            // append, contract 1 of `src/dynbuf.rs`, so there is nothing to
            // clean up here and freeing it again would be a double free.
            return cc2cu(result);
        }
        // L147: `len -= n`. Saturating rather than wrapping; see the doc
        // comment for why the two cannot differ at any reachable call site.
        start = sep;
        remaining = len.saturating_sub(sep);
    }

    // L150: the window the byte loop walks, `iptr` from `host_sep` for
    // `remaining` bytes. Both `get` calls clamp rather than trust, which is
    // where a `len` beyond the slice is absorbed.
    let tail = url.get(start..).unwrap_or_default();
    let window = tail.get(..remaining).unwrap_or(tail);

    for &byte in window {
        // The three arms are in the C's order, L151, L157 and L162, and the
        // order matters: a space is `0x20`, which is not below `' '`, so the
        // first arm is the only thing that keeps a space out of the second.
        let result = if byte == b' ' {
            if left {
                o.addn(b"%20")
            } else {
                o.addn(b"+")
            }
        } else if byte < b' ' || byte >= 0x7f {
            // L157-L161. The upper bound is inclusive of 0x7f, so DEL and
            // every byte above it is escaped. This is a wider set than
            // `src/decode.rs`'s `UrlReject::Ctrl`, which rejects only below
            // 0x20, and the two are deliberately not the same.
            //
            // Upper-case hexadecimal, from `Curl_hexbyte` at
            // `lib/escape.c`:L222 over `Curl_udigits`. Destructured rather
            // than indexed, because the crate root denies indexing.
            let [high, low] = hexbyte(byte);
            o.addn(&[b'%', high, low])
        } else {
            // L162-L166. The append happens first and the flag is set
            // afterwards, exactly as the C orders them, so a `?` that fails
            // to append still flips the flag before the loop unwinds. That
            // is unobservable, since the failure returns immediately, and it
            // is reproduced rather than tidied.
            let appended = o.addn(&[byte]);
            if byte == b'?' {
                left = false;
            }
            appended
        };
        if result.is_err() {
            // C leaves the loop through its `!result` guard at L150 and folds
            // the code at L169-L170; returning here is the same thing with
            // one fewer state variable. The buffer is already released.
            return cc2cu(result);
        }
    }

    CURLUE_OK
}

/// Whether a byte survives unencoded inside a path, reproducing
/// `allowed_in_path`.
///
/// `lib/urlapi.c`:L1779-L1803 is a `switch` with eighteen `case` labels and
/// one `return TRUE`, and the eighteen are transcribed below in the order the
/// C lists them so that the two can be diffed label for label:
///
/// ```c
/// case '!': case '$': case '&': case '\'': case '(': case ')':
/// case '{': case '}': case '[': case ']': case '*': case '+':
/// case ',': case ';': case '=': case ':': case '@': case '/':
///   return TRUE;
/// ```
///
/// It extends, and never replaces, the unreserved set: [`encode_part`] tests
/// `crate::ctype::is_unreserved` first and reaches this only for a byte that
/// failed it, at L1897-L1898. The two sets are disjoint, which a test below
/// pins over all 256 byte values, so the order of the two tests is not
/// observable and the extension is exactly eighteen bytes wide.
///
/// # What is deliberately absent
///
/// `%` is not in the set. A path handed to `curl_url_set()` with
/// `CURLU_URLENCODE` therefore has each of its own escapes escaped again,
/// `%3C` becoming `%253C`, and the way to store a pre-encoded path is to omit
/// the flag and let [`add_preencoded`] take it instead.
///
/// `?` and `#` are not in the set either, which is what keeps an encoded path
/// from growing a query or a fragment delimiter it did not have.
///
/// Written as a `match` rather than as a lookup table because the crate root
/// denies direct indexing, and `const` so that it can be used in a constant
/// context and so that the compiler is free to fold it into a bit test.
#[must_use]
pub(crate) const fn allowed_in_path(x: u8) -> bool {
    matches!(
        x,
        b'!' | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'{'
            | b'}'
            | b'['
            | b']'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'@'
            | b'/'
    )
}

/// The assignment-side encoder: `lib/urlapi.c`:L1887-L1915.
///
/// Rule set three of three, and the `if` arm of the `if(urlencode)` at L1887
/// whose `else` arm is [`add_preencoded`]. `src/getset.rs` owns the dispatch
/// that decides which arm runs and what the flags below are set to; this
/// function owns the byte-level transformation and nothing else.
///
/// # Parameters
///
/// - `enc`: the destination, which may already hold content. The path setter
///   appends a leading `/` into it at L1882-L1886 before this runs, and this
///   function neither knows nor cares.
/// - `part`: the value to encode. The C loop guard is `*i`, so the walk stops
///   at the first zero byte; [`cstring_window`] reproduces that.
/// - `pathmode`: set only for `CURLUPART_PATH`, at L1856. It admits the
///   eighteen bytes of [`allowed_in_path`].
/// - `plusencode`: set only for `CURLUPART_QUERY`, and there only when
///   encoding was requested, at L1861. It turns a space into `+`.
/// - `equalsencode`: set only for `CURLUPART_QUERY`, and there only when
///   `CURLU_APPENDQUERY` was given, at L1862-L1863. It admits the **first**
///   `=` and disarms itself; see below.
///
/// # The first-`=`-only rule
///
/// L1899-L1902, whose own comment is "only skip the first equals sign":
///
/// ```c
/// ((*i == '=') && equalsencode)) {
///   if((*i == '=') && equalsencode)
///     /* only skip the first equals sign */
///     equalsencode = FALSE;
/// ```
///
/// The flag arms the exemption once. Appending `name=value=more` to a query
/// therefore stores `name=value%3Dmore`, keeping the key-value separator
/// readable while encoding every later `=` as data. This is easy to miss and
/// directly observable, so it is tested with three equals signs below.
///
/// One structural detail is reproduced rather than simplified: the inner `if`
/// sits inside the branch and runs whichever of the three disjuncts admitted
/// the byte. So in path mode, where `=` is already admitted by
/// [`allowed_in_path`], an armed `equalsencode` is still consumed by the first
/// `=`. That is unobservable, both because the byte passes either way and
/// because no part sets `pathmode` and `equalsencode` together, but the shape
/// is kept so that no future reader has to reason about it twice.
///
/// # Returns
///
/// `crate::abi::CURLUE_OK`, or a failure code from a failed append. Note the
/// **asymmetry in the failure mapping**, which is faithful and not tidied:
/// the space branch at L1894-L1895 returns `CURLUE_OUT_OF_MEMORY` directly,
/// while the other two branches fold through `crate::error::cc2cu` at L1905
/// and L1912. A `CURLE_TOO_LARGE` from the space branch is therefore reported
/// as out of memory. `src/error.rs` names this site in its own documentation
/// and states that the port reproduces it here. It is unreachable in
/// practice: `src/getset.rs` sizes the buffer as `nalloc * 3 + 1 +
/// leadingslash` at L1880, and one input byte can never produce more than
/// three output bytes, so the ceiling cannot be hit.
#[must_use = "the result code reports a failed append and must be handled"]
pub(crate) fn encode_part(
    enc: &mut DynBuf,
    part: &[u8],
    pathmode: bool,
    plusencode: bool,
    equalsencode: bool,
) -> CURLUcode {
    // C mutates its caller's local; the port takes it by value and shadows it
    // so that the caller cannot observe the disarming, which the C caller
    // cannot either, the loop being the last use of the flag.
    let mut equalsencode = equalsencode;

    // L1890: `for(i = (const unsigned char *)part; *i; i++)`.
    for &byte in cstring_window(part) {
        if byte == b' ' && plusencode {
            let result = enc.addn(b"+");
            if result.is_err() {
                // L1895, verbatim: this one branch does not fold through
                // cc2cu. See the Returns section above before "fixing" it.
                return CURLUE_OUT_OF_MEMORY;
            }
        } else if is_unreserved(byte)
            || (pathmode && allowed_in_path(byte))
            || (byte == b'=' && equalsencode)
        {
            if byte == b'=' && equalsencode {
                // L1900-L1902: only skip the first equals sign.
                equalsencode = false;
            }
            let result = enc.addn(&[byte]);
            if result.is_err() {
                return cc2cu(result);
            }
        } else {
            // L1907-L1913. Upper-case hexadecimal from `Curl_hexbyte`,
            // destructured rather than indexed.
            let [high, low] = hexbyte(byte);
            let result = enc.addn(&[b'%', high, low]);
            if result.is_err() {
                return cc2cu(result);
            }
        }
    }

    CURLUE_OK
}

/// Lower-cases the two hexadecimal digits of every percent escape in a
/// buffer, in place.
///
/// `lib/urlapi.c`:L1921-L1932, the second half of the `else` arm that
/// [`add_preencoded`] ports:
///
/// ```c
/// p = curlx_dyn_ptr(&enc);
/// while(*p) {
///   /* make sure percent encoded are lower case */
///   if((*p == '%') && ISXDIGIT(p[1]) && ISXDIGIT(p[2]) &&
///      (ISUPPER(p[1]) || ISUPPER(p[2]))) {
///     p[1] = Curl_raw_tolower(p[1]);
///     p[2] = Curl_raw_tolower(p[2]);
///     p += 3;
///   }
///   else
///     p++;
/// }
/// ```
///
/// # What to pass
///
/// `DynBuf::content_mut()`, and the whole buffer rather than just
/// the value that was appended. C takes the pointer from the start of the
/// buffer at L1921, so the walk covers a leading `/` the path setter added at
/// L1883 as well as the value itself. Passing a narrower slice would be a
/// behaviour change for any part whose buffer has a prefix.
///
/// The walk stops at the first zero byte, which is the `while(*p)` guard, or
/// at the end of the slice, whichever comes first. Handing it the
/// terminator-inclusive view is therefore both correct and cheap.
///
/// # Why the test has four parts and not two
///
/// The two `ISXDIGIT` tests are what stop `%zz` and a trailing `%` from being
/// touched. The `ISUPPER` disjunction is a fast path: an escape that is
/// already entirely lower case is left alone, and the walk then advances by
/// one byte rather than three. That is observable only in one place, and it
/// is worth knowing: for input `%%41`, the second `%` begins `%41`, whose
/// digits are `4` and `1`, neither of which is upper case, so the escape is
/// skipped by the disjunction and not rewritten. Nothing is lost, since there
/// was nothing to lower-case, but a port that dropped the disjunction and
/// advanced by three unconditionally would still agree on the output, while a
/// port that dropped it and advanced by one would not.
///
/// # Not a decoder
///
/// The escape is left in place. Only the case of its digits changes, and the
/// length of the buffer never changes, which is what makes an in-place
/// rewrite possible at all.
pub(crate) fn lowercase_escapes(buf: &mut [u8]) {
    let mut idx: usize = 0;

    loop {
        // `while(*p)`: stop at the terminator, or at the end of the slice.
        let Some(&first) = buf.get(idx) else {
            return;
        };
        if first == 0 {
            return;
        }

        // L1924-L1925, with the C's short-circuit order preserved: the
        // lookaheads are only consulted for a `%`, and `get` answers `None`
        // where C would have found the terminator, so a truncated escape at
        // the end of the buffer falls through to the `p++` arm.
        let escape = if first == b'%' {
            let high = buf.get(idx.saturating_add(1)).copied();
            let low = buf.get(idx.saturating_add(2)).copied();
            match (high, low) {
                (Some(high), Some(low))
                    if is_xdigit(high) && is_xdigit(low) && (is_upper(high) || is_upper(low)) =>
                {
                    Some((high, low))
                }
                _ => None,
            }
        } else {
            None
        };

        match escape {
            Some((high, low)) => {
                // L1926-L1928. Two separate writes, because the reads above
                // have already ended and a fresh mutable borrow is needed for
                // each. Both `get_mut` calls succeed, since the `Some` arm
                // above proves both indices are inside the slice; the `if
                // let` shape exists only so that no unwrap appears.
                if let Some(slot) = buf.get_mut(idx.saturating_add(1)) {
                    *slot = raw_tolower(high);
                }
                if let Some(slot) = buf.get_mut(idx.saturating_add(2)) {
                    *slot = raw_tolower(low);
                }
                idx = idx.saturating_add(3);
            }
            None => idx = idx.saturating_add(1),
        }
    }
}

/// Stores a value that arrives already encoded: `lib/urlapi.c`:L1916-L1933.
///
/// The `else` arm of the `if(urlencode)` at L1887, and the counterpart to
/// [`encode_part`]. `src/getset.rs` chooses between the two on the caller's
/// `CURLU_URLENCODE` flag. The C comment that explains what this arm assumes
/// about its input is at L1975-L1976, in the hostname check further down: "if
/// the hostname part was not URL encoded here, it was set ready URL encoded".
///
/// It is **not** a plain append, and the difference is directly observable:
///
/// 1. L1918 appends the value unchanged, and
/// 2. L1921-L1932 then walks the whole buffer and lower-cases the two digits
///    of every percent escape already in it, which is [`lowercase_escapes`].
///
/// So `curl_url_set(u, CURLUPART_PATH, "/%2F", 0)` stores `/%2f`. The escape
/// survives, its case does not. Compare [`encode_part`], which would have
/// stored `/%252F` for the same input, and note that both are correct for
/// their own flag.
///
/// # Parameters
///
/// - `enc`: the destination, which may already hold a leading `/`. The
///   lower-casing pass covers that prefix too, because C takes its pointer
///   from the start of the buffer.
/// - `part`: the value. `curlx_dyn_add()` measures it with `strlen()` at
///   L1918, so the append stops at the first zero byte; [`cstring_window`]
///   reproduces that.
///
/// # Returns
///
/// `crate::abi::CURLUE_OK`, or the fold of a failed append through
/// `crate::error::cc2cu`, which is L1919-L1920. The lower-casing pass cannot
/// fail: it allocates nothing and changes no length.
#[must_use = "the result code reports a failed append and must be handled"]
pub(crate) fn add_preencoded(enc: &mut DynBuf, part: &[u8]) -> CURLUcode {
    // L1918: `curlx_dyn_add(&enc, part)`. `addn` over the C string view is
    // the same call; `src/dynbuf.rs` documents that it subsumes `add` for
    // every caller that already holds bytes.
    let result = enc.addn(cstring_window(part));
    if result.is_err() {
        // L1919-L1920. The buffer is already released, contract 1.
        return cc2cu(result);
    }

    // L1921-L1932. The terminator-inclusive view, and the whole buffer rather
    // than the appended tail, because L1921 takes the pointer from the start.
    // The view is a guard: whatever this pass does, the buffer is terminated
    // again when the borrow ends.
    {
        let mut content = enc.content_mut();
        lowercase_escapes(&mut content);
    }

    CURLUE_OK
}

/// The bytes `curl_easy_escape` would walk, given `string` and `inlength`.
///
/// `lib/escape.c`:L59, `length = (inlength ? (size_t)inlength : strlen(string))`.
/// The same overload `Curl_urldecode` carries at L115, and `src/decode.rs`
/// resolves it with the same rule, deliberately: one convention for
/// "zero means measure it" across the crate.
///
/// A `length` beyond the slice is clamped rather than trusted. C would read
/// past the caller's buffer; clamping is the only defined behaviour available
/// here, and the single call site inside the URL API passes zero anyway.
// Dead only because its single caller, `easy_escape`, is: this is that
// function's `inlength` rule and nothing else uses it.
#[allow(dead_code)]
fn escape_window(string: &[u8], length: usize) -> &[u8] {
    if length == 0 {
        cstring_window(string)
    } else {
        string.get(..length).unwrap_or(string)
    }
}

/// The body of `curl_easy_escape` once its window is resolved:
/// `lib/escape.c`:L60-L86.
///
/// Split out so that [`easy_escape`] and [`easy_escape_bytes`] share one
/// implementation and cannot drift apart. Every early return corresponds to a
/// `return NULL` in the C.
///
/// # Ownership
///
/// **The returned buffer is owned by the caller.** Its block came from the C
/// allocator by way of `src/alloc.rs`, so a `curl_free()` on the pointer
/// `DynBuf::into_cbuf` or `DynBuf::into_raw` yields is the correct
/// deallocator, which is what `docs/libcurl/curl_url_get.md`:L45 requires of
/// anything the URL API hands back. Dropping the value instead releases it
/// here. Nothing is leaked on any failure path, because the value never
/// escapes one.
fn escape_all(window: &[u8]) -> Option<DynBuf> {
    let length = window.len();

    if length == 0 {
        // L60-L61: `if(!length) return curlx_strdup("")`. An **allocated
        // empty string**, not a null pointer, and the distinction is
        // load-bearing: the one call site inside the URL API,
        // `lib/urlapi.c`:L1493-L1495, treats a null result as
        // `CURLUE_OUT_OF_MEMORY`, so returning nothing for an empty host
        // would turn a legal handle into an allocation failure.
        //
        // A one-byte ceiling reproduces `curlx_strdup("")` exactly, and a
        // zero-length append still allocates, which `src/dynbuf.rs` documents
        // on its growth policy. The result is a one-byte block holding just
        // the terminator, so `DynBuf::into_cbuf` yields `Some` rather than
        // `None`.
        let mut empty = DynBuf::new(1);
        if empty.addn(&[]).is_err() {
            return None;
        }
        return Some(empty);
    }

    // L63-L64. See `MAX_ESCAPE_INPUT` for why the guard exists at all.
    if length > MAX_ESCAPE_INPUT {
        return None;
    }

    // L66: `curlx_dyn_init(&d, length * 3 + 1)`. The worst case is every byte
    // escaping to three, plus the terminator that `toobig` bounds. Checked
    // arithmetic because the crate denies the panicking kind; the guard above
    // has already made an overflow unreachable, so `None` here is defensive
    // and reports the only honest answer, that no buffer could be sized.
    let ceiling = length.checked_mul(3).and_then(|room| room.checked_add(1))?;
    let mut escaped = DynBuf::new(ceiling);

    // L68-L84: `while(length--)`, one byte at a time, treated unsigned. The
    // slice iteration is already unsigned, which is what the C's cast at L70
    // is for.
    for &byte in window {
        let result = if is_unreserved(byte) {
            escaped.addn(&[byte])
        } else {
            // L77-L83. Upper-case hexadecimal, destructured rather than
            // indexed. Note the preserved set here is the unreserved 66 and
            // nothing more: a space becomes `%20`, never `+`, and this is the
            // rule set that escapes a host.
            let [high, low] = hexbyte(byte);
            escaped.addn(&[b'%', high, low])
        };
        if result.is_err() {
            // L75 and L82 both `return NULL`. The buffer has already been
            // released by the failed append, contract 1 of `src/dynbuf.rs`,
            // and dropping the value here is a no-op on an empty buffer
            // rather than a second free. C leaks the same allocation at these
            // two sites only in the sense that it cannot; `dyn_nappend()`
            // freed it first, which is why the C omits a free of its own.
            return None;
        }
    }

    // L86: `return curlx_dyn_ptr(&d)`. Non-null by construction, because
    // `length` was proved nonzero above and at least one append has run.
    Some(escaped)
}

/// Percent-escapes a string with the unreserved set, reproducing
/// `curl_easy_escape`.
///
/// `lib/escape.c`:L50-L87. Rule set two of three, and the one the whole-URL
/// retrieval path uses on a **host**: `urlget_url()` calls
/// `curl_easy_escape(NULL, u->host, 0)` at `lib/urlapi.c`:L1493 when
/// `CURLU_URLENCODE` is set. See the module documentation for why that does
/// not contradict [`urlencode_str`]'s host exemption.
///
/// The C's first parameter, a `CURL *`, has been ignored since 7.82.0, as its
/// own comment at L48 says, so it has no counterpart here.
///
/// # Parameters
///
/// - `string`: `None` is the C's null pointer test at L56. When `inlength` is
///   zero the slice is expected to be NUL-terminated, as a C `char *` always
///   is; a slice with no terminator is measured to its own end, which is the
///   same answer for every input the C could have been given.
/// - `inlength`: the number of bytes to escape, or zero to measure `string`
///   to its first NUL. A negative value yields `None`, the second half of the
///   test at L56.
///
/// Prefer [`easy_escape_bytes`] when the slice already is the window; it says
/// so in the name and removes the question of what zero would have meant.
///
/// # Returns
///
/// An owned buffer holding the escaped bytes and a terminator, or `None` for
/// every case in which the C returns null: a null input, a negative length,
/// an input above `MAX_ESCAPE_INPUT`, or a failed allocation.
///
/// An **empty** input is not one of those cases. It yields an allocated,
/// terminated, zero-length buffer, which is L60-L61.
///
/// # Ownership
///
/// As [`escape_all`]: the caller owns the result, its block came from the C
/// allocator, and `curl_free()` is therefore the correct release for the
/// pointer `DynBuf::into_cbuf` or `DynBuf::into_raw` produces. Until one of
/// those is called, `Drop` releases it.
// No production caller: `curl_easy_escape` is defined in `lib/escape.c`
// and is not one of the symbols this crate replaces, so no path inside the
// URL API reaches it. Retained because the AAP requires this module to
// carry the escape helper at `lib/escape.c` L50, and the tests below pin
// it against the C's behaviour for a negative and an oversized length.
#[allow(dead_code)]
#[must_use = "the escaped buffer is owned; dropping it releases the memory"]
pub(crate) fn easy_escape(string: Option<&[u8]>, inlength: c_int) -> Option<DynBuf> {
    // L56-L57, in the C's order: the null test first, then the sign test.
    let string = string?;
    // `try_from` is the sign test and the widening in one step, so no cast
    // appears. A negative `inlength` cannot convert, which is exactly the
    // `(inlength < 0)` half of L56.
    let requested = usize::try_from(inlength).ok()?;

    // L59, then L60-L86.
    escape_all(escape_window(string, requested))
}

/// Percent-escapes exactly `input`, with no measure-it overload.
///
/// The shape a Rust caller wants, and the one `src/getset.rs` uses for the
/// host at `lib/urlapi.c`:L1493, where the C has to pass zero and let the
/// callee run `strlen()` over a pointer it already has the length of.
///
/// It differs from `easy_escape(Some(input), 0)` only when `input` contains an
/// interior zero byte, which that form stops at and this one escapes through
/// as `%00`. It differs from a length-carrying `easy_escape` call in nothing
/// at all, except that a length above `c_int::MAX` is expressible here.
///
/// # Returns
///
/// As [`easy_escape`], including that an empty input yields an allocated
/// empty buffer rather than `None`.
///
/// # Ownership
///
/// As [`easy_escape`].
#[must_use = "the escaped buffer is owned; dropping it releases the memory"]
pub(crate) fn easy_escape_bytes(input: &[u8]) -> Option<DynBuf> {
    escape_all(input)
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's whole job is to panic when an
    // assertion fails, and no test crosses that boundary, so the denials are
    // relaxed here and only here, enumerated rather than blanket. This is the
    // same allowance, for the same reason, as the one in `src/decode.rs`.
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]

    // The assertions below need somewhere to copy an encoder's output, and
    // they reach the heap through the `alloc` crate rather than through `std`
    // so that this module compiles the same way whichever the crate root
    // turns out to declare. Every other import here comes from `core` or from
    // a sibling module.
    extern crate alloc;

    use super::{add_preencoded, allowed_in_path, cstring_window, easy_escape};
    use super::{easy_escape_bytes, encode_part, escape_window, find_double_slash};
    use super::{find_host_sep, lowercase_escapes, urlencode_str, DynBuf, MAX_ESCAPE_INPUT};
    use crate::abi::{CURLUE_OK, CURLUE_OUT_OF_MEMORY, CURLUE_TOO_LARGE, CURL_MAX_INPUT_LENGTH};
    use crate::ctype::{hexbyte, is_unreserved};
    use crate::decode::{urldecode_bytes, UrlReject};
    use alloc::vec::Vec;

    /// Runs [`urlencode_str`] over an explicit window and copies the result
    /// out, asserting that the encode itself succeeded.
    ///
    /// The ceiling is the one `lib/urlapi.c` uses at its own call sites,
    /// `CURL_MAX_INPUT_LENGTH` per `lib/urldata.h:L131`, so nothing here can
    /// fail for want of room; the ceiling failures are tested separately with
    /// a deliberately tiny buffer.
    fn encode(url: &[u8], len: usize, relative: bool, query: bool) -> Vec<u8> {
        let mut out = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        let code = urlencode_str(&mut out, url, len, relative, query);
        assert_eq!(code, CURLUE_OK, "urlencode_str reported {code}");
        out.as_bytes().to_vec()
    }

    /// The same, with the window being the whole slice.
    fn encode_full(url: &[u8], relative: bool, query: bool) -> Vec<u8> {
        encode(url, url.len(), relative, query)
    }

    /// Runs [`encode_part`] and copies the result out.
    ///
    /// The ceiling is the one `curl_url_set()` computes at
    /// `lib/urlapi.c:L1880`, `nalloc * 3 + 1`, so the worst case fits exactly
    /// and the assertion below cannot fail for want of room.
    fn set_encoded(part: &[u8], pathmode: bool, plusencode: bool, equalsencode: bool) -> Vec<u8> {
        let mut enc = DynBuf::new(part.len() * 3 + 1);
        let code = encode_part(&mut enc, part, pathmode, plusencode, equalsencode);
        assert_eq!(code, CURLUE_OK, "encode_part reported {code}");
        enc.as_bytes().to_vec()
    }

    /// Runs [`add_preencoded`] into a buffer that already holds `prefix`, and
    /// copies the result out.
    ///
    /// The prefix stands for the leading slash the path setter appends at
    /// `lib/urlapi.c:L1883` before the encoding block runs.
    fn set_preencoded_with_prefix(prefix: &[u8], part: &[u8]) -> Vec<u8> {
        let mut enc = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        assert!(enc.addn(prefix).is_ok(), "the prefix must fit");
        let code = add_preencoded(&mut enc, part);
        assert_eq!(code, CURLUE_OK, "add_preencoded reported {code}");
        enc.as_bytes().to_vec()
    }

    /// The same, with no prefix.
    fn set_preencoded(part: &[u8]) -> Vec<u8> {
        set_preencoded_with_prefix(b"", part)
    }

    /// Runs [`easy_escape_bytes`] and copies the result out.
    fn escape_bytes(input: &[u8]) -> Vec<u8> {
        let escaped = easy_escape_bytes(input).unwrap();
        escaped.as_bytes().to_vec()
    }

    /// `%XX` for one byte, built with the encoder's own primitive.
    ///
    /// `crate::ctype::hexbyte` is the port of `Curl_hexbyte` at
    /// `lib/escape.c:L222`, which is what every encoding site in the C tree
    /// uses. Building the expected value with it rather than with a second
    /// hand-written formatter is what makes the sweeps below genuine.
    fn expect_escape(byte: u8) -> [u8; 3] {
        let [high, low] = hexbyte(byte);
        [b'%', high, low]
    }

    /// [`cstring_window`] is C's implicit `strlen` boundary.
    #[test]
    fn cstring_window_truncates_at_the_first_nul() {
        assert_eq!(cstring_window(b"abc"), b"abc");
        assert_eq!(cstring_window(b"abc\0def"), b"abc");
        assert_eq!(cstring_window(b"\0abc"), b"");
        assert_eq!(cstring_window(b""), b"");
    }

    /// [`find_double_slash`] is `strstr(url, "//")` at `lib/urlapi.c:L107`.
    #[test]
    fn find_double_slash_reproduces_strstr() {
        assert_eq!(find_double_slash(b"http://x"), Some(5));
        assert_eq!(find_double_slash(b"//"), Some(0));
        assert_eq!(find_double_slash(b"a///b"), Some(1));
        assert_eq!(find_double_slash(b"/"), None);
        assert_eq!(find_double_slash(b"a/b/c"), None);
        assert_eq!(find_double_slash(b""), None);
    }

    /// The ordinary cases: the authority ends at a `/`, at a `?` or at the
    /// end of the string.
    ///
    /// The `?` case is the one the comment at `lib/urlapi.c:L101-L102` calls
    /// out with `http://www.example.com?id=2380`.
    #[test]
    fn find_host_sep_locates_the_authority_end() {
        assert_eq!(find_host_sep(b"http://example.com/path"), 18);
        assert_eq!(find_host_sep(b"http://www.example.com?id=2380"), 22);
        assert_eq!(find_host_sep(b"http://example.com"), 18);
        assert_eq!(find_host_sep(b""), 0);
    }

    /// With no `//` at all the scan starts at byte zero, which is the
    /// `if(!sep) sep = url;` at `lib/urlapi.c:L108-L109`.
    #[test]
    fn find_host_sep_without_a_double_slash_scans_from_the_start() {
        assert_eq!(find_host_sep(b"example.com/path"), 11);
        assert_eq!(find_host_sep(b"example.com"), 11);
        assert_eq!(find_host_sep(b"/path"), 0);
        assert_eq!(find_host_sep(b"?query"), 0);
    }

    /// The documented quirk: `strstr()` matches `//` anywhere, with no test
    /// that a scheme precedes it.
    ///
    /// `a//b/c` is therefore treated as having its authority at `b`. Faithful
    /// per transformation rule T6, and unreachable in practice because the
    /// only `relative == false` call site, `lib/urlapi.c:L1275`, scans a
    /// string rebuilt from a parsed handle.
    #[test]
    fn find_host_sep_matches_a_double_slash_anywhere() {
        assert_eq!(find_host_sep(b"a//b/c"), 4);
        assert_eq!(find_host_sep(b"//host/path"), 6);
        assert_eq!(find_host_sep(b"x//"), 3);
        // Three slashes: the pair is found at the first two, so the walk
        // starts on the third and stops there immediately.
        assert_eq!(find_host_sep(b"http:///path"), 7);
    }

    /// Both halves of the C function stop at the terminator, so the search is
    /// confined to the C string view.
    #[test]
    fn find_host_sep_stops_at_an_interior_nul() {
        assert_eq!(find_host_sep(b"ab\0//c/"), 2);
        assert_eq!(find_host_sep(b"http://ex\0ample.com/p"), 9);
    }

    /// The host exemption: the authority is appended in one unexamined
    /// append, so a space inside it survives as a space.
    ///
    /// `lib/urlapi.c:L140-L148`, with the reason at L124-L128: "URL encoding
    /// should be skipped for hostnames, otherwise IDN resolution will fail."
    #[test]
    fn urlencode_str_copies_the_host_prefix_verbatim() {
        assert_eq!(
            encode_full(b"http://ex ample.com/pa th", false, false).as_slice(),
            b"http://ex ample.com/pa%20th"
        );
    }

    /// The same bytes with `relative` set take no prefix at all, which is the
    /// contrast that shows the prefix is doing real work.
    #[test]
    fn urlencode_str_relative_takes_no_host_prefix() {
        assert_eq!(
            encode_full(b"http://ex ample.com/", true, false).as_slice(),
            b"http://ex%20ample.com/"
        );
        assert_eq!(
            encode_full(b"http://ex ample.com/", false, false).as_slice(),
            b"http://ex ample.com/"
        );
    }

    /// A space before the first `?` becomes `%20`, `lib/urlapi.c:L152-L153`.
    #[test]
    fn urlencode_str_space_becomes_percent_twenty_while_left() {
        assert_eq!(encode_full(b"a b", true, false).as_slice(), b"a%20b");
    }

    /// A space after the first `?` becomes `+`, `lib/urlapi.c:L154-L155`.
    ///
    /// The flag is cleared by the `?` itself at L164-L165, so the change of
    /// behaviour is positional rather than tied to a named part.
    #[test]
    fn urlencode_str_space_becomes_plus_after_the_query_delimiter() {
        assert_eq!(
            encode_full(b"a b?c d", true, false).as_slice(),
            b"a%20b?c+d"
        );
    }

    /// A part flagged as the query starts with `left` already false, because
    /// `lib/urlapi.c:L135` is `bool left = !query;`.
    ///
    /// No `?` is needed for the plus form to apply.
    #[test]
    fn urlencode_str_query_part_starts_with_left_already_false() {
        assert_eq!(encode_full(b"a b", true, true).as_slice(), b"a+b");
        assert_eq!(encode_full(b"a b?c d", true, true).as_slice(), b"a+b?c+d");
    }

    /// The flag flips once and stays flipped: nothing sets it back.
    #[test]
    fn urlencode_str_left_flips_once_and_stays_false() {
        assert_eq!(
            encode_full(b"a?b c?d e", true, false).as_slice(),
            b"a?b+c?d+e"
        );
    }

    /// The boundaries of `(*iptr < ' ') || (*iptr >= 0x7f)` at
    /// `lib/urlapi.c:L157`, plus the space arm above it.
    ///
    /// High bytes are written as escapes rather than as literal UTF-8,
    /// because `scripts/spacecheck.pl` rejects non-ASCII in tracked files.
    /// Note that `0x7f` is on the escaped side, which is a wider set than
    /// `src/decode.rs`'s `UrlReject::Ctrl`.
    #[test]
    fn urlencode_str_escapes_exactly_the_control_and_high_bytes() {
        assert_eq!(encode_full(b"\x00", true, false).as_slice(), b"%00");
        assert_eq!(encode_full(b"\x1f", true, false).as_slice(), b"%1F");
        assert_eq!(encode_full(b"\x20", true, false).as_slice(), b"%20");
        assert_eq!(encode_full(b"\x21", true, false).as_slice(), b"!");
        assert_eq!(encode_full(b"\x7e", true, false).as_slice(), b"~");
        assert_eq!(encode_full(b"\x7f", true, false).as_slice(), b"%7F");
        assert_eq!(encode_full(b"\x80", true, false).as_slice(), b"%80");
        assert_eq!(encode_full(b"\xff", true, false).as_slice(), b"%FF");
    }

    /// Emitted escapes are upper case, because `Curl_hexbyte` indexes
    /// `Curl_udigits`, `"0123456789ABCDEF"` at `lib/mprintf.c:L39`.
    #[test]
    fn urlencode_str_emits_upper_case_escapes() {
        assert_eq!(
            encode_full(b"\xab\xcd\xef", true, false).as_slice(),
            b"%AB%CD%EF"
        );
    }

    /// Every byte from `0x21` through `0x7e` passes through unchanged, which
    /// is what makes this rule set so much more permissive than the other
    /// two: `%`, `+`, `&`, `=`, `<` and `>` are all preserved.
    #[test]
    fn urlencode_str_preserves_every_printable_byte_except_space() {
        for byte in 0x21_u8..=0x7e {
            let encoded = encode_full(&[byte], true, false);
            assert_eq!(
                encoded.as_slice(),
                &[byte],
                "byte {byte:#04x} should pass through"
            );
        }
        // Spelled out for the four that matter most, since a reader should
        // not have to run the loop in their head.
        assert_eq!(encode_full(b"a%3Cb", true, false).as_slice(), b"a%3Cb");
        assert_eq!(encode_full(b"a+b&c=d", true, false).as_slice(), b"a+b&c=d");
    }

    /// Four of the five C call sites pass a window into the middle of a
    /// longer string, for instance `query + 1, qlen - 1` at
    /// `lib/urlapi.c:L1046`, so a `len` shorter than the slice is the normal
    /// case rather than an edge one.
    #[test]
    fn urlencode_str_honours_a_window_shorter_than_the_slice() {
        assert_eq!(encode(b"a b?c d", 3, true, false).as_slice(), b"a%20b");
        // A `len` beyond the slice is clamped rather than trusted. C would
        // read past the caller's buffer; no call site does this.
        assert_eq!(encode(b"a b", 99, true, false).as_slice(), b"a%20b");
    }

    /// `len -= n` at `lib/urlapi.c:L147` saturates here where C would wrap.
    ///
    /// The whole prefix is still appended, exactly as C appends it at L146
    /// before touching `len`, and the byte loop then covers nothing at all
    /// rather than the enormous count a wrap would have produced. Unreachable
    /// in practice, because the only `relative == false` call site passes
    /// `strlen(useurl)`; the assertion pins the guard.
    #[test]
    fn urlencode_str_saturates_a_length_shorter_than_the_host_prefix() {
        assert_eq!(
            encode(b"http://host/p", 4, false, false).as_slice(),
            b"http://host"
        );
    }

    /// A failed append is folded through `crate::error::cc2cu`, which is
    /// `lib/urlapi.c:L169-L170`.
    ///
    /// A ceiling of one admits nothing beyond the terminator, so the very
    /// first append reports `CURLE_TOO_LARGE` and the fold yields
    /// `CURLUE_TOO_LARGE`. The buffer has already released itself, contract 1
    /// of `src/dynbuf.rs`, which is why none of these paths frees it.
    #[test]
    fn urlencode_str_folds_a_failed_append() {
        let mut tiny = DynBuf::new(1);
        assert_eq!(
            urlencode_str(&mut tiny, b"ab", 2, true, false),
            CURLUE_TOO_LARGE
        );
        // The prefix append at L146 folds through the same return at L169.
        let mut tiny = DynBuf::new(1);
        assert_eq!(
            urlencode_str(&mut tiny, b"http://h/p", 10, false, false),
            CURLUE_TOO_LARGE
        );
    }

    /// The eighteen `case` labels of `allowed_in_path` at
    /// `lib/urlapi.c:L1782-L1799`, written out a second time independently.
    #[test]
    fn allowed_in_path_matches_the_eighteen_case_labels() {
        const EXPECTED: &[u8] = b"!$&'(){}[]*+,;=:@/";
        assert_eq!(EXPECTED.len(), 18, "the C switch has eighteen case labels");
        for byte in 0..=u8::MAX {
            assert_eq!(
                allowed_in_path(byte),
                EXPECTED.contains(&byte),
                "byte {byte:#04x} classified wrongly"
            );
        }
    }

    /// The path set extends the unreserved set and never overlaps it, which
    /// is why the order of the two tests at `lib/urlapi.c:L1897-L1898` is not
    /// observable.
    #[test]
    fn allowed_in_path_is_disjoint_from_the_unreserved_set() {
        for byte in 0..=u8::MAX {
            assert!(
                !(allowed_in_path(byte) && is_unreserved(byte)),
                "byte {byte:#04x} is in both sets"
            );
        }
        // Two exclusions worth naming, because both are observable.
        assert!(!allowed_in_path(b'%'), "an existing escape is re-encoded");
        assert!(!allowed_in_path(b'?') && !allowed_in_path(b'#'));
    }

    /// Outside path mode the preserved set is exactly the unreserved 66, and
    /// every other byte becomes an upper-case escape.
    ///
    /// Byte zero is excluded because the C loop guard is `*i` at
    /// `lib/urlapi.c:L1890`, so it has no encoded form at all; the next test
    /// covers it.
    #[test]
    fn encode_part_preserves_the_unreserved_set() {
        for byte in 1..=u8::MAX {
            let encoded = set_encoded(&[byte], false, false, false);
            if is_unreserved(byte) {
                assert_eq!(encoded.as_slice(), &[byte], "byte {byte:#04x} should pass");
            } else {
                assert_eq!(
                    encoded.as_slice(),
                    &expect_escape(byte),
                    "byte {byte:#04x} should escape"
                );
            }
        }
    }

    /// `for(i = part; *i; i++)` at `lib/urlapi.c:L1890` stops at the first
    /// zero byte.
    #[test]
    fn encode_part_stops_at_an_interior_nul() {
        assert_eq!(
            set_encoded(b"ab\0cd", false, false, false).as_slice(),
            b"ab"
        );
        assert!(set_encoded(b"\0", false, false, false).is_empty());
    }

    /// Path mode admits exactly the eighteen extra bytes and nothing else.
    #[test]
    fn encode_part_path_mode_admits_exactly_the_eighteen() {
        for &byte in b"!$&'(){}[]*+,;=:@/" {
            assert_eq!(
                set_encoded(&[byte], true, false, false).as_slice(),
                &[byte],
                "byte {byte:#04x} is allowed in a path"
            );
            assert_eq!(
                set_encoded(&[byte], false, false, false).as_slice(),
                &expect_escape(byte),
                "byte {byte:#04x} is not allowed outside a path"
            );
        }
    }

    /// The assignment-side space rule differs from the retrieval-side one:
    /// `+` only when plus-encoding is armed, and `%20` otherwise.
    ///
    /// `lib/urlapi.c:L1892-L1896`. A space is neither unreserved nor one of
    /// the eighteen, so path mode alone does not admit it.
    #[test]
    fn encode_part_space_rule_differs_from_the_retrieval_side() {
        assert_eq!(set_encoded(b"a b", false, true, false).as_slice(), b"a+b");
        assert_eq!(
            set_encoded(b"a b", false, false, false).as_slice(),
            b"a%20b"
        );
        assert_eq!(set_encoded(b"a b", true, false, false).as_slice(), b"a%20b");
        // The space arm is tested first, so it wins over path mode too.
        assert_eq!(set_encoded(b"a b", true, true, false).as_slice(), b"a+b");
    }

    /// Only the first `=` survives, `lib/urlapi.c:L1899-L1902`.
    ///
    /// Three of them, because the rule is easy to miss with fewer.
    #[test]
    fn encode_part_skips_only_the_first_equals_sign() {
        assert_eq!(
            set_encoded(b"a=b=c=d", false, false, true).as_slice(),
            b"a=b%3Dc%3Dd"
        );
        // Unarmed, every one of the three encodes.
        assert_eq!(
            set_encoded(b"a=b=c=d", false, false, false).as_slice(),
            b"a%3Db%3Dc%3Dd"
        );
        // A leading equals sign is still the first one.
        assert_eq!(set_encoded(b"==", false, false, true).as_slice(), b"=%3D");
        assert_eq!(set_encoded(b"=", false, false, true).as_slice(), b"=");
    }

    /// Path mode admits every `=` through [`allowed_in_path`], so the
    /// first-equals rule makes no difference there.
    ///
    /// The C consumes the armed flag on the first `=` regardless of which
    /// disjunct admitted the byte, which this pins as unobservable rather
    /// than leaving it to be rediscovered.
    #[test]
    fn encode_part_path_mode_admits_every_equals_sign() {
        assert_eq!(
            set_encoded(b"a=b=c", true, false, false).as_slice(),
            b"a=b=c"
        );
        assert_eq!(
            set_encoded(b"a=b=c", true, false, true).as_slice(),
            b"a=b=c"
        );
    }

    /// `%` is not preserved, so an already-encoded value is encoded again.
    ///
    /// This is the counterpart to [`add_preencoded`], and the reason the two
    /// arms of the `if(urlencode)` at `lib/urlapi.c:L1887` must not be
    /// merged: for the same input they produce different, both-correct
    /// answers.
    #[test]
    fn encode_part_double_encodes_an_existing_escape() {
        assert_eq!(
            set_encoded(b"a%3Cb", false, false, false).as_slice(),
            b"a%253Cb"
        );
        assert_eq!(
            set_encoded(b"a<b", false, false, false).as_slice(),
            b"a%3Cb"
        );
        assert_eq!(set_preencoded(b"a%3Cb").as_slice(), b"a%3cb");
    }

    /// The space branch reports out of memory where the other two fold
    /// through `cc2cu`, `lib/urlapi.c:L1894-L1895` against L1905 and L1912.
    ///
    /// Faithful and directly observable: the same buffer and the same
    /// underlying `CURLE_TOO_LARGE` yields two different codes depending on
    /// which branch hit it. `src/error.rs` names this site and states that
    /// the port reproduces it here. Unreachable through the public API,
    /// because `src/getset.rs` sizes the buffer at `nalloc * 3 + 1` and one
    /// input byte can never produce four output bytes.
    #[test]
    fn encode_part_space_branch_reports_out_of_memory_not_too_large() {
        let mut tiny = DynBuf::new(1);
        assert_eq!(
            encode_part(&mut tiny, b" ", false, true, false),
            CURLUE_OUT_OF_MEMORY
        );
        let mut tiny = DynBuf::new(1);
        assert_eq!(
            encode_part(&mut tiny, b"a", false, true, false),
            CURLUE_TOO_LARGE
        );
        let mut tiny = DynBuf::new(1);
        assert_eq!(
            encode_part(&mut tiny, b"<", false, true, false),
            CURLUE_TOO_LARGE
        );
    }

    /// An escape already present in the value is lower-cased in place,
    /// `lib/urlapi.c:L1922-L1932`.
    #[test]
    fn add_preencoded_lower_cases_an_existing_escape() {
        assert_eq!(set_preencoded(b"%2F").as_slice(), b"%2f");
        assert_eq!(set_preencoded(b"%2f").as_slice(), b"%2f");
        assert_eq!(set_preencoded(b"%2F%3A").as_slice(), b"%2f%3a");
        assert_eq!(set_preencoded(b"%aB").as_slice(), b"%ab");
        assert_eq!(set_preencoded(b"%Ab").as_slice(), b"%ab");
        assert_eq!(set_preencoded(b"%4A").as_slice(), b"%4a");
        // The last three bytes of the buffer are still a whole escape.
        assert_eq!(set_preencoded(b"x%AB").as_slice(), b"x%ab");
    }

    /// Anything that is not a complete escape is left exactly alone.
    ///
    /// The two `ISXDIGIT` tests at `lib/urlapi.c:L1924` are what stop `%G0`
    /// and a trailing `%` from being touched.
    #[test]
    fn add_preencoded_leaves_a_non_escape_alone() {
        assert_eq!(set_preencoded(b"%").as_slice(), b"%");
        assert_eq!(set_preencoded(b"%G0").as_slice(), b"%G0");
        assert_eq!(set_preencoded(b"%2").as_slice(), b"%2");
        assert_eq!(set_preencoded(b"100%").as_slice(), b"100%");
        assert_eq!(set_preencoded(b"plain-text").as_slice(), b"plain-text");
        // The ISUPPER disjunction at L1925: `%41` has no upper-case digit, so
        // the escape is skipped and the walk advances by one rather than
        // three. Nothing was there to lower-case, so the output agrees; a
        // port that dropped the disjunction and advanced by one would not.
        assert_eq!(set_preencoded(b"%%41").as_slice(), b"%%41");
    }

    /// The walk starts at the beginning of the buffer, not at the value.
    ///
    /// `lib/urlapi.c:L1921` takes the pointer from `curlx_dyn_ptr(&enc)`, so
    /// a prefix the caller already appended is inside the walk. Narrowing the
    /// slice would be a behaviour change for every part with a prefix, which
    /// is every path.
    #[test]
    fn add_preencoded_walks_a_prefix_the_caller_already_appended() {
        assert_eq!(
            set_preencoded_with_prefix(b"/", b"A%2Fb").as_slice(),
            b"/A%2fb"
        );
        assert_eq!(
            set_preencoded_with_prefix(b"%2F", b"%3A").as_slice(),
            b"%2f%3a"
        );
    }

    /// `curlx_dyn_add()` measures the value with `strlen()` at
    /// `lib/urlapi.c:L1918`.
    #[test]
    fn add_preencoded_stops_at_an_interior_nul() {
        assert_eq!(set_preencoded(b"%2F\0%3A").as_slice(), b"%2f");
    }

    /// The `while(*p)` guard at `lib/urlapi.c:L1922`, exercised directly:
    /// only the escape inside the C string is rewritten.
    #[test]
    fn lowercase_escapes_stops_at_the_terminator() {
        let mut buf = *b"%2F\0%2F";
        lowercase_escapes(&mut buf);
        assert_eq!(&buf, b"%2f\0%2F");
    }

    /// A truncated escape at the very end of the slice is safe.
    ///
    /// C reaches its terminator and fails `ISXDIGIT`; the port's two-byte
    /// lookahead answers `None` from `get` and falls through to the `p++`
    /// arm. Neither reads past the end.
    #[test]
    fn lowercase_escapes_handles_a_truncated_escape_at_the_end() {
        let mut buf = *b"x%A";
        lowercase_escapes(&mut buf);
        assert_eq!(&buf, b"x%A");

        let mut buf = *b"x%";
        lowercase_escapes(&mut buf);
        assert_eq!(&buf, b"x%");

        let mut empty: [u8; 0] = [];
        lowercase_escapes(&mut empty);
        assert_eq!(&empty, b"");
    }

    /// A null input or a negative length yields nothing,
    /// `lib/escape.c:L56-L57`.
    #[test]
    fn easy_escape_rejects_a_null_input_and_a_negative_length() {
        assert!(easy_escape(None, 0).is_none());
        assert!(easy_escape(None, 5).is_none());
        assert!(easy_escape(Some(b"abc"), -1).is_none());
        assert!(easy_escape(Some(b"abc"), c_int_min()).is_none());
    }

    /// The smallest `c_int`, obtained without a cast or a literal.
    fn c_int_min() -> core::ffi::c_int {
        core::ffi::c_int::MIN
    }

    /// An empty input yields an **allocated** empty string, not nothing:
    /// `lib/escape.c:L60-L61` is `curlx_strdup("")`.
    ///
    /// The distinction is load-bearing. The one call site inside the URL API,
    /// `lib/urlapi.c:L1493-L1495`, treats a null result as
    /// `CURLUE_OUT_OF_MEMORY`, so returning nothing here would turn a legal
    /// handle into an allocation failure. The terminator-inclusive view is
    /// the proof: a buffer that never allocated reports an empty slice, and
    /// one that did reports the single zero byte.
    #[test]
    fn easy_escape_yields_an_allocated_empty_string_for_an_empty_input() {
        let escaped = easy_escape_bytes(b"").unwrap();
        assert_eq!(escaped.len(), 0);
        assert_eq!(escaped.as_bytes_with_nul(), b"\0");
        assert_eq!(
            escaped.capacity(),
            1,
            "curlx_strdup(\"\") allocates one byte"
        );

        // The measure-it overload reaches the same branch through a string
        // whose first byte is the terminator.
        let measured = easy_escape(Some(b"\0"), 0).unwrap();
        assert_eq!(measured.as_bytes_with_nul(), b"\0");
    }

    /// The preserved set is exactly the unreserved 66 and nothing more.
    ///
    /// Byte zero is included, unlike in [`encode_part`], because
    /// [`easy_escape_bytes`] takes the slice as the window rather than as a C
    /// string.
    #[test]
    fn easy_escape_preserves_the_unreserved_set_and_escapes_the_rest() {
        for byte in 0..=u8::MAX {
            let escaped = escape_bytes(&[byte]);
            if is_unreserved(byte) {
                assert_eq!(escaped.as_slice(), &[byte], "byte {byte:#04x} should pass");
            } else {
                assert_eq!(
                    escaped.as_slice(),
                    &expect_escape(byte),
                    "byte {byte:#04x} should escape"
                );
            }
        }
    }

    /// This rule set has no plus form at all, which is one of the three ways
    /// it differs from the other two.
    #[test]
    fn easy_escape_escapes_a_space_as_percent_twenty_never_as_plus() {
        assert_eq!(escape_bytes(b"a b").as_slice(), b"a%20b");
        assert_eq!(escape_bytes(b"a+b").as_slice(), b"a%2Bb");
        assert_eq!(escape_bytes(b"a b?c d").as_slice(), b"a%20b%3Fc%20d");
    }

    /// The asymmetry the module documentation is loudest about.
    ///
    /// `urlget_url()` escapes `u->host` with this function at
    /// `lib/urlapi.c:L1493`, while [`urlencode_str`] copies the whole
    /// authority through untouched. Same flag, opposite treatment, both
    /// ported.
    #[test]
    fn easy_escape_escapes_a_host_which_urlencode_str_would_not() {
        assert_eq!(escape_bytes(b"ex ample.com").as_slice(), b"ex%20ample.com");
        assert_eq!(
            encode_full(b"http://ex ample.com/", false, false).as_slice(),
            b"http://ex ample.com/"
        );
    }

    /// The length overload, `lib/escape.c:L59`.
    #[test]
    fn easy_escape_honours_an_explicit_length() {
        assert_eq!(easy_escape(Some(b"abcdef"), 3).unwrap().as_bytes(), b"abc");
        // Zero means measure to the terminator.
        assert_eq!(
            easy_escape(Some(b"abc\0def"), 0).unwrap().as_bytes(),
            b"abc"
        );
        // A length beyond the slice is clamped rather than trusted.
        assert_eq!(easy_escape(Some(b"ab"), 99).unwrap().as_bytes(), b"ab");
        // Unlike the C-shaped entry point, the byte-window one escapes an
        // interior zero rather than stopping at it.
        assert_eq!(escape_bytes(b"a\0b").as_slice(), b"a%00b");
    }

    /// [`escape_window`] resolves the `length ? length : strlen()` overload.
    #[test]
    fn escape_window_resolves_the_length_overload() {
        assert_eq!(escape_window(b"abcdef", 3), b"abc");
        assert_eq!(escape_window(b"abc\0def", 0), b"abc");
        assert_eq!(escape_window(b"abc", 0), b"abc");
        assert_eq!(escape_window(b"abc", 99), b"abc");
        assert_eq!(escape_window(b"", 0), b"");
    }

    /// The escape ceiling sits far above the URL API's own input limit.
    ///
    /// Asserted at compile time rather than in a test body, because both
    /// operands are constants and a runtime `assert!` over two constants is
    /// a lint of its own. The relationship is what makes
    /// `lib/escape.c:L63-L64` a guard rather than a policy: nothing that
    /// arrives through a public entry point of the URL API can reach it,
    /// because `Curl_junkscan()` has already capped the input at
    /// `CURL_MAX_INPUT_LENGTH`.
    ///
    /// The allow is spelled the same way `src/inet.rs`, `src/ffi.rs` and
    /// `src/parse/ipv6.rs` spell theirs, and `src/inet.rs` carries the measured
    /// account of it. In short: on the pinned toolchain, clippy 1.97, the lint
    /// fires only for a literal or a named `bool` condition, so the comparison
    /// below is not reported and dropping the attribute would currently be
    /// silent. It is retained deliberately -- the crate declares a 1.75 minimum
    /// this toolchain cannot exercise, and the lint's own advice, "remove the
    /// assertion", is the opposite of what a compile-time check is for. A
    /// scoped exception, then, not a suppressed finding, and not a claim about
    /// what later releases do.
    #[allow(clippy::assertions_on_constants)]
    const CEILING_IS_ABOVE_THE_URL_API_LIMIT: () =
        assert!(MAX_ESCAPE_INPUT > CURL_MAX_INPUT_LENGTH);

    /// The guard at `lib/escape.c:L63-L64` is a sixteenth of the address
    /// space, and that number is what keeps `length * 3 + 1` at L66 from
    /// wrapping.
    #[test]
    fn the_escape_input_ceiling_is_a_sixteenth_of_the_address_space() {
        assert_eq!(MAX_ESCAPE_INPUT, usize::MAX / 16);
        // Three times a value this large is still representable, which is the
        // whole reason the guard is placed before the multiplication.
        assert!(MAX_ESCAPE_INPUT.checked_mul(3).is_some());
        // Reached so that the compile-time assertion above is not dead.
        let () = CEILING_IS_ABOVE_THE_URL_API_LIMIT;
    }

    /// Every one of the 256 byte values survives a trip through each encoder
    /// and back out through `src/decode.rs`.
    ///
    /// The decoder is the inverse operation, `Curl_urldecode` at
    /// `lib/escape.c:L105`, and `UrlReject::Nada` is used so that the
    /// round-trip is tested rather than the rejection policy. Byte zero has
    /// no [`encode_part`] form, because that loop's guard is `*i`.
    #[test]
    fn every_byte_round_trips_through_the_decoder() {
        for byte in 0..=u8::MAX {
            let escaped = escape_bytes(&[byte]);
            let decoded = urldecode_bytes(&escaped, UrlReject::Nada).unwrap();
            assert_eq!(decoded.as_bytes(), &[byte], "easy_escape, byte {byte:#04x}");

            let retrieved = encode_full(&[byte], true, false);
            let decoded = urldecode_bytes(&retrieved, UrlReject::Nada).unwrap();
            assert_eq!(
                decoded.as_bytes(),
                &[byte],
                "urlencode_str, byte {byte:#04x}"
            );

            if byte != 0 {
                let assigned = set_encoded(&[byte], false, false, false);
                let decoded = urldecode_bytes(&assigned, UrlReject::Nada).unwrap();
                assert_eq!(decoded.as_bytes(), &[byte], "encode_part, byte {byte:#04x}");
            }
        }
    }

    /// The three rule sets disagree, and the disagreement is the behaviour.
    ///
    /// One input, three answers, each one correct for its own site. A
    /// refactor that merged any two of these functions would have to break
    /// one of these assertions.
    #[test]
    fn the_three_rule_sets_disagree_on_the_same_input() {
        const INPUT: &[u8] = b"a b=c%3D+d/e";

        // Rule set one: everything printable except the space survives, and
        // the space takes the `%20` form because no `?` has been seen.
        assert_eq!(
            encode_full(INPUT, true, false).as_slice(),
            b"a%20b=c%3D+d/e"
        );
        // Rule set two: only the unreserved 66 survive.
        assert_eq!(escape_bytes(INPUT).as_slice(), b"a%20b%3Dc%253D%2Bd%2Fe");
        // Rule set three, in path mode: the eighteen extras survive too.
        assert_eq!(
            set_encoded(INPUT, true, false, false).as_slice(),
            b"a%20b=c%253D+d/e"
        );
        // Rule set three, as a query with plus-encoding and the first-equals
        // exemption armed.
        assert_eq!(
            set_encoded(INPUT, false, true, true).as_slice(),
            b"a+b=c%253D%2Bd%2Fe"
        );
    }
}
