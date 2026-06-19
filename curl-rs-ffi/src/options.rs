//! Easy-option metadata introspection — the `curl_easy_option_*` C ABI
//! (`include/curl/options.h`).
//!
//! This module exposes the three `CURL_EXTERN` runtime-introspection symbols
//! that let a consumer enumerate libcurl's easy options and discover the
//! `CURLoption` id and value type behind each option name:
//!
//! * [`curl_easy_option_by_name`] — look an option up by its (case-insensitive)
//!   name;
//! * [`curl_easy_option_by_id`] — look the canonical option up by its
//!   `CURLoption` id;
//! * [`curl_easy_option_next`] — iterate the whole option table.
//!
//! Together they contribute exactly **3** of the 100 `curl_*` symbols in
//! `lib/libcurl.def` (AAP §0.7.2). The C declarations they mirror live at
//! `include/curl/options.h:L58-L65`; the behavioural oracle is curl's
//! `lib/easygetopt.c` (the `lookup()`/`curl_easy_option_*` functions) layered
//! over the generated table in `lib/easyoptions.c`.
//!
//! # The data lives in the safe core; this module only re-shapes it for C
//!
//! The option inventory itself — every name, `CURLoption` id, value type and
//! the `CURLOT_FLAG_ALIAS` markers — is owned by the safe core in
//! [`curl_rs_lib::options`] ([`EASY_OPTIONS`](core_opts::EASY_OPTIONS), a slice
//! of [`EasyOption`](core_opts::EasyOption)). That slice is curl's
//! `Curl_easyopts[]` reproduced verbatim, in curl's exact ASCII-ascending order,
//! including curl's intentional quirks (legacy alias spellings such as
//! `MAIL_RCPT_ALLLOWFAILS`). This module's sole job is to project that safe data
//! into the C `#[repr(C)]` [`curl_easyoption`] view and apply curl's exact
//! lookup semantics, so the safe core stays the single source of truth.
//!
//! # The C-visible table is static, immutable and `'static`
//!
//! The pointers returned by all three functions point into one process-lifetime
//! table built exactly once (lazily, via a [`OnceLock`]). The table is a
//! contiguous `Vec<curl_easyoption>` whose rows are index-aligned 1:1 with
//! [`EASY_OPTIONS`](core_opts::EASY_OPTIONS) and which is terminated by a
//! sentinel row with a `NULL` `name` — exactly the layout curl's iterator
//! relies on. Each row's `name` is a deliberately **leaked** [`CString`]: it is
//! valid for the entire program and is **never freed by the caller** (the
//! `curl_easy_option_*` API has no free function — the data is static, just as
//! curl's generated `const` array is). Because the table is never mutated or
//! reallocated after initialization, every returned pointer is stable for the
//! lifetime of the process, matching the C ABI's promise.
//!
//! # Behavioural parity with `lib/easygetopt.c`
//!
//! * `by_name` matches **case-insensitively** (curl uses `curl_strequal`) and
//!   resolves alias entries — `"encoding"`, `"ENCODING"` and `"AcCePt_EnCoDiNg"`
//!   all resolve.
//! * `by_id` returns the **canonical** entry for an id, deliberately skipping
//!   alias rows (curl's `lookup()` tests `!(o->flags & CURLOT_FLAG_ALIAS)`).
//! * `next` returns the first row for a `NULL` argument, the following row
//!   otherwise, and `NULL` once the sentinel is reached.
//!
//! The lookup *logic* is delegated to the core's pinned
//! [`option_by_name`](core_opts::option_by_name) /
//! [`option_by_id`](core_opts::option_by_id) functions and then mapped onto the
//! C table by index, so the C behaviour can never drift from the core's
//! test-pinned behaviour.
//!
//! # Memory safety
//!
//! Per the crate-wide mandate (AAP §0.7.1) every `unsafe` block here carries a
//! `// SAFETY:` comment, and the workspace `unsafe_op_in_unsafe_fn = "deny"`
//! lint means each raw-pointer dereference inside an `unsafe extern "C" fn`
//! sits in its own explicit `unsafe { … }` block. The only raw pointers read
//! are the caller-supplied `name`/`prev` (whose validity is the caller's
//! documented `# Safety` obligation) and the module's own `'static` table rows.

use core::ffi::c_char;
use core::ptr;
use std::ffi::{CStr, CString};
use std::sync::OnceLock;

use curl_rs_lib::options as core_opts;

use crate::types::{curl_easyoption, curl_easytype, CURLoption};

// =============================================================================
// Static, process-lifetime `curl_easyoption` table
// =============================================================================

/// Translates the safe core's [`CurlOptType`](core_opts::CurlOptType) into the
/// C-visible [`curl_easytype`].
///
/// The two enumerations share discriminants one-for-one (`Long`/`CURLOT_LONG`
/// = 0 … `Function`/`CURLOT_FUNCTION` = 8), but they are distinct Rust types, so
/// the mapping is written out explicitly. The `match` is exhaustive: adding a
/// value type to either enum without updating this function is a compile error,
/// which is exactly the guard we want for an ABI-facing table.
const fn easytype_from_core(typ: core_opts::CurlOptType) -> curl_easytype {
    use core_opts::CurlOptType;
    match typ {
        CurlOptType::Long => curl_easytype::CURLOT_LONG,
        CurlOptType::Values => curl_easytype::CURLOT_VALUES,
        CurlOptType::OffT => curl_easytype::CURLOT_OFF_T,
        CurlOptType::Object => curl_easytype::CURLOT_OBJECT,
        CurlOptType::String => curl_easytype::CURLOT_STRING,
        CurlOptType::Slist => curl_easytype::CURLOT_SLIST,
        CurlOptType::Cbptr => curl_easytype::CURLOT_CBPTR,
        CurlOptType::Blob => curl_easytype::CURLOT_BLOB,
        CurlOptType::Function => curl_easytype::CURLOT_FUNCTION,
    }
}

/// Newtype wrapper that lets the `curl_easyoption` table live in a `static`.
///
/// [`curl_easyoption`] holds a raw `*const c_char` `name`, which makes it
/// `!Send + !Sync`, so a `OnceLock<Vec<curl_easyoption>>` could not be a
/// `static`. Wrapping the `Vec` and asserting the marker traits below confines
/// that reasoning to one auditable place.
struct EasyOptionTable(Vec<curl_easyoption>);

// SAFETY: an `EasyOptionTable` is only ever produced once, inside the
// `OPTION_TABLE` `OnceLock`, and is never mutated or reallocated afterwards.
// Its `*const c_char` name pointers each reference a leaked, immutable,
// `'static` `CString` that is never freed. Moving the (immutable) table to
// another thread therefore transfers only shared-immutable data, which is
// sound.
unsafe impl Send for EasyOptionTable {}

// SAFETY: as above — after the one-time initialization the table is deeply
// immutable and its name pointers reference leaked `'static` data that is never
// freed or mutated, so handing out `&EasyOptionTable` to multiple threads only
// ever exposes shared reads, which is sound.
unsafe impl Sync for EasyOptionTable {}

/// Process-lifetime storage for the assembled C-visible option table.
static OPTION_TABLE: OnceLock<EasyOptionTable> = OnceLock::new();

/// Builds the C-visible option table from the safe core's
/// [`EASY_OPTIONS`](core_opts::EASY_OPTIONS).
///
/// The resulting `Vec` has one [`curl_easyoption`] row per core option, in the
/// same order, followed by a single terminating sentinel row whose `name` is
/// `NULL` (mirroring the trailing `{ NULL, … }` row of curl's generated
/// `Curl_easyopts[]`, which [`curl_easy_option_next`] uses to detect the end).
/// Each row's `name` is a leaked `CString` and so is valid for the whole
/// program; this leak is intentional and matches curl's `const` static array,
/// which is likewise never freed.
fn build_table() -> Vec<curl_easyoption> {
    let source = core_opts::EASY_OPTIONS;
    let mut table = Vec::with_capacity(source.len() + 1);

    for opt in source {
        // Leak a NUL-terminated copy of the name; it lives for the entire
        // program and is never reclaimed (there is no free function for this
        // API). `CString::new` only fails on an interior NUL, which curl option
        // names never contain; should that invariant ever be violated we fall
        // back to a NULL name rather than panic across the FFI boundary (a NULL
        // here would merely make the row look like the sentinel).
        let name: *const c_char = match CString::new(opt.name) {
            Ok(owned) => owned.into_raw() as *const c_char,
            Err(_) => ptr::null(),
        };

        table.push(curl_easyoption {
            name,
            id: opt.id.as_i32(),
            r#type: easytype_from_core(opt.typ),
            flags: opt.flags,
        });
    }

    // Terminating sentinel: a NULL `name` marks the end of the table exactly as
    // curl's generated array does.
    table.push(curl_easyoption {
        name: ptr::null(),
        id: 0,
        r#type: curl_easytype::CURLOT_LONG,
        flags: 0,
    });

    table
}

/// Returns the process-lifetime option table as a `'static` slice, building it
/// on first use.
///
/// The slice has `EASY_OPTIONS.len()` real rows followed by the sentinel row,
/// and its element addresses are stable for the lifetime of the process.
fn option_table() -> &'static [curl_easyoption] {
    OPTION_TABLE
        .get_or_init(|| EasyOptionTable(build_table()))
        .0
        .as_slice()
}

/// Maps a core lookup result onto a pointer into the C-visible table.
///
/// The safe-core lookups return a reference *into*
/// [`EASY_OPTIONS`](core_opts::EASY_OPTIONS); its index there is, by
/// construction, the same as the matching row's index in [`option_table`]. We
/// recover that index by identity ([`ptr::eq`]) and hand back the address of
/// the corresponding C row, or `NULL` when there was no match.
fn pointer_for(found: Option<&'static core_opts::EasyOption>) -> *const curl_easyoption {
    let Some(found) = found else {
        return ptr::null();
    };
    match core_opts::EASY_OPTIONS
        .iter()
        .position(|candidate| ptr::eq(candidate, found))
    {
        // `option_table()` always has at least `EASY_OPTIONS.len()` rows, so
        // `index` is in bounds; `get` keeps this total and panic-free anyway.
        // (`row as *const _` is used rather than `ptr::from_ref`, which is only
        // stable since Rust 1.76 — the workspace MSRV is 1.75.)
        Some(index) => match option_table().get(index) {
            Some(row) => row as *const curl_easyoption,
            None => ptr::null(),
        },
        None => ptr::null(),
    }
}

// =============================================================================
// Exported symbol 1 / 3 — curl_easy_option_by_name
// =============================================================================

/// Look up an easy-option's metadata by name (`curl_easy_option_by_name`).
///
/// Returns a pointer to the [`curl_easyoption`] whose `name` matches `name`
/// **case-insensitively** (curl compares with `curl_strequal`), or `NULL` when
/// `name` is `NULL` or no option matches. Alias entries are eligible matches,
/// so legacy spellings resolve just as they do in curl.
///
/// The returned pointer references a `'static`, immutable table row; it remains
/// valid for the lifetime of the process and must **not** be freed by the
/// caller.
///
/// # Safety
///
/// `name` must be `NULL`, or a pointer to a valid NUL-terminated C string that
/// remains valid and unaliased for the duration of the call. The bytes are only
/// read, never retained.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_option_by_name(name: *const c_char) -> *const curl_easyoption {
    if name.is_null() {
        return ptr::null();
    }

    // SAFETY: per the `# Safety` contract `name` is a valid NUL-terminated C
    // string for the duration of the call; `CStr::from_ptr` only borrows it.
    let cstr = unsafe { CStr::from_ptr(name) };

    // curl option names are ASCII, so any non-UTF-8 input cannot name an
    // option; treat it as "no match" rather than erroring.
    let Ok(name_str) = cstr.to_str() else {
        return ptr::null();
    };

    pointer_for(core_opts::option_by_name(name_str))
}

// =============================================================================
// Exported symbol 2 / 3 — curl_easy_option_by_id
// =============================================================================

/// Look up an easy-option's metadata by its `CURLoption` id
/// (`curl_easy_option_by_id`).
///
/// Returns a pointer to the **canonical** [`curl_easyoption`] with the given
/// `id`, or `NULL` when no option has that id. Alias rows are deliberately
/// skipped (curl's `lookup()` tests `!(o->flags & CURLOT_FLAG_ALIAS)`), so an id
/// that has both a canonical entry and one or more aliases always resolves to
/// the canonical one.
///
/// The returned pointer references a `'static`, immutable table row and must
/// **not** be freed by the caller. This function takes no pointer arguments and
/// is therefore safe to call from any context.
#[no_mangle]
pub extern "C" fn curl_easy_option_by_id(id: CURLoption) -> *const curl_easyoption {
    // `CurlOption::from_i32` rejects ids that are not real options (returning
    // `None`); `option_by_id` then resolves to the canonical, non-alias row.
    let found = core_opts::CurlOption::from_i32(id).and_then(core_opts::option_by_id);
    pointer_for(found)
}

// =============================================================================
// Exported symbol 3 / 3 — curl_easy_option_next
// =============================================================================

/// Iterate the easy-option table (`curl_easy_option_next`).
///
/// * With `prev == NULL`, returns a pointer to the **first** option row.
/// * Otherwise, returns the row immediately following `prev`.
/// * Returns `NULL` once iteration reaches the end of the table.
///
/// This mirrors `lib/easygetopt.c` exactly, including its guard against being
/// handed the terminating sentinel row. Returned pointers reference `'static`,
/// immutable table rows and must **not** be freed by the caller. A typical
/// loop is `for(o = curl_easy_option_next(NULL); o; o = curl_easy_option_next(o))`.
///
/// # Safety
///
/// `prev` must be `NULL`, or a pointer previously returned by one of the
/// `curl_easy_option_*` functions (i.e. a row of this module's internal table).
/// Passing any other pointer is undefined behaviour, exactly as in curl.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_option_next(
    prev: *const curl_easyoption,
) -> *const curl_easyoption {
    // No previous entry: hand back the first row (`&Curl_easyopts[0]`).
    if prev.is_null() {
        return option_table().as_ptr();
    }

    // SAFETY: per the `# Safety` contract `prev` is a row of the internal table,
    // so it is valid to read. A NULL `name` marks the terminating sentinel;
    // there is nothing after it.
    if unsafe { (*prev).name }.is_null() {
        return ptr::null();
    }

    // SAFETY: `prev` points at a non-sentinel row of the contiguous,
    // sentinel-terminated table, so advancing by one element stays in bounds
    // (at worst it lands on the sentinel).
    let next = unsafe { prev.add(1) };

    // SAFETY: `next` is in bounds (at most the sentinel) and valid to read. A
    // NULL `name` means we advanced onto the sentinel, i.e. iteration is done.
    if unsafe { (*next).name }.is_null() {
        ptr::null()
    } else {
        next
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CURLOT_FLAG_ALIAS;
    use core::ffi::c_uint;

    /// Reads the `name` of a table row as a `&str`, returning `None` for a NULL
    /// pointer or the NULL-named sentinel row.
    fn name_of(row: *const curl_easyoption) -> Option<&'static str> {
        if row.is_null() {
            return None;
        }
        // SAFETY: in these tests `row` is always either NULL (handled above) or
        // a row of the module's own `'static` table, which is valid to read.
        let name = unsafe { (*row).name };
        if name.is_null() {
            return None;
        }
        // SAFETY: a non-NULL row `name` is a valid `'static` NUL-terminated C
        // string built by `build_table`.
        unsafe { CStr::from_ptr(name) }.to_str().ok()
    }

    /// Reads the `id` of a non-NULL table row.
    fn id_of(row: *const curl_easyoption) -> CURLoption {
        // SAFETY: `row` is a non-NULL row of the module's `'static` table.
        unsafe { (*row).id }
    }

    /// Reads the `type` of a non-NULL table row.
    fn type_of(row: *const curl_easyoption) -> curl_easytype {
        // SAFETY: `row` is a non-NULL row of the module's `'static` table.
        unsafe { (*row).r#type }
    }

    /// Reads the `flags` of a non-NULL table row.
    fn flags_of(row: *const curl_easyoption) -> c_uint {
        // SAFETY: `row` is a non-NULL row of the module's `'static` table.
        unsafe { (*row).flags }
    }

    #[test]
    fn table_has_323_rows_plus_sentinel() {
        let table = option_table();
        // 323 real options (matching curl's `Curl_easyopts[]`) + 1 sentinel.
        assert_eq!(table.len(), core_opts::EASY_OPTIONS.len() + 1);
        assert_eq!(table.len(), 324);

        // The first row is curl's alphabetically-first option…
        assert_eq!(name_of(table.as_ptr()), Some("ABSTRACT_UNIX_SOCKET"));
        // …and the final row is the NULL-named sentinel.
        let sentinel = &table[table.len() - 1];
        assert!(sentinel.name.is_null());
    }

    #[test]
    fn iterate_next_from_null_counts_323() {
        let mut count = 0usize;
        // SAFETY: NULL is an explicitly valid argument to `curl_easy_option_next`.
        let mut cur = unsafe { curl_easy_option_next(ptr::null()) };
        while !cur.is_null() {
            // Every yielded row must be a real (non-sentinel) option.
            assert!(name_of(cur).is_some(), "iterator yielded a NULL-named row");
            count += 1;
            // SAFETY: `cur` is a valid non-sentinel row returned by the iterator.
            cur = unsafe { curl_easy_option_next(cur) };
            assert!(count <= 1000, "iteration failed to terminate");
        }
        assert_eq!(count, 323);
    }

    #[test]
    fn next_from_null_is_first_row() {
        // SAFETY: NULL is a valid argument.
        let first = unsafe { curl_easy_option_next(ptr::null()) };
        assert!(!first.is_null());
        assert!(ptr::eq(first, option_table().as_ptr()));
        assert_eq!(name_of(first), Some("ABSTRACT_UNIX_SOCKET"));
    }

    #[test]
    fn next_past_last_real_row_is_null() {
        // Walk to the last real row.
        // SAFETY: NULL is valid; each returned pointer is a valid row.
        let mut cur = unsafe { curl_easy_option_next(ptr::null()) };
        assert!(!cur.is_null());
        loop {
            // SAFETY: `cur` is a valid non-sentinel row.
            let nxt = unsafe { curl_easy_option_next(cur) };
            if nxt.is_null() {
                break;
            }
            cur = nxt;
        }
        // `cur` is now the last real row; stepping past it yields NULL.
        // SAFETY: `cur` is the last valid non-sentinel row.
        let past_end = unsafe { curl_easy_option_next(cur) };
        assert!(past_end.is_null());
    }

    #[test]
    fn by_name_null_returns_null() {
        // SAFETY: NULL is an explicitly valid argument.
        let result = unsafe { curl_easy_option_by_name(ptr::null()) };
        assert!(result.is_null());
    }

    #[test]
    fn by_name_unknown_returns_null() {
        let needle = CString::new("DEFINITELY_NOT_AN_OPTION").unwrap();
        // SAFETY: `needle` is a valid NUL-terminated C string kept alive here.
        let result = unsafe { curl_easy_option_by_name(needle.as_ptr()) };
        assert!(result.is_null());
    }

    #[test]
    fn by_name_url_and_by_id_url_agree() {
        let url = CString::new("URL").unwrap();
        // SAFETY: `url` is a valid NUL-terminated C string kept alive here.
        let by_name = unsafe { curl_easy_option_by_name(url.as_ptr()) };
        let by_id = curl_easy_option_by_id(core_opts::CurlOption::CURLOPT_URL.as_i32());

        assert!(!by_name.is_null(), "by_name(URL) must resolve");
        assert!(!by_id.is_null(), "by_id(CURLOPT_URL) must resolve");
        // Both lookups must return the very same `'static` table row.
        assert!(ptr::eq(by_name, by_id));
        assert_eq!(name_of(by_name), Some("URL"));
        assert_eq!(id_of(by_name), core_opts::CurlOption::CURLOPT_URL.as_i32());
        assert_eq!(type_of(by_name), curl_easytype::CURLOT_STRING);
        // URL is canonical, not an alias.
        assert_eq!(flags_of(by_name) & CURLOT_FLAG_ALIAS, 0);
    }

    #[test]
    fn by_name_is_case_insensitive() {
        let canonical = CString::new("URL").unwrap();
        // SAFETY: valid NUL-terminated C string kept alive here.
        let want = unsafe { curl_easy_option_by_name(canonical.as_ptr()) };
        assert!(!want.is_null());

        for variant in ["url", "Url", "uRl", "URL"] {
            let probe = CString::new(variant).unwrap();
            // SAFETY: valid NUL-terminated C string kept alive here.
            let got = unsafe { curl_easy_option_by_name(probe.as_ptr()) };
            assert!(
                ptr::eq(got, want),
                "case variant {variant:?} did not resolve to the URL row"
            );
        }
    }

    #[test]
    fn by_name_resolves_aliases() {
        // "ENCODING" is curl's legacy alias of CURLOPT_ACCEPT_ENCODING; a name
        // lookup must resolve it (curl does not skip aliases by name).
        let alias = CString::new("ENCODING").unwrap();
        // SAFETY: valid NUL-terminated C string kept alive here.
        let row = unsafe { curl_easy_option_by_name(alias.as_ptr()) };
        assert!(!row.is_null(), "ENCODING alias must resolve by name");
        assert_eq!(name_of(row), Some("ENCODING"));
        assert_ne!(
            flags_of(row) & CURLOT_FLAG_ALIAS,
            0,
            "ENCODING must carry the alias flag"
        );
        assert_eq!(
            id_of(row),
            core_opts::CurlOption::CURLOPT_ACCEPT_ENCODING.as_i32()
        );
    }

    #[test]
    fn by_id_skips_aliases_and_returns_canonical() {
        // The id shared by the "ENCODING" alias and the canonical
        // "ACCEPT_ENCODING" option must resolve to the canonical row.
        let id = core_opts::CurlOption::CURLOPT_ACCEPT_ENCODING.as_i32();
        let row = curl_easy_option_by_id(id);
        assert!(!row.is_null());
        assert_eq!(name_of(row), Some("ACCEPT_ENCODING"));
        assert_eq!(
            flags_of(row) & CURLOT_FLAG_ALIAS,
            0,
            "by_id must return the canonical (non-alias) row"
        );
        assert_eq!(id_of(row), id);
    }

    #[test]
    fn by_id_unknown_returns_null() {
        assert!(curl_easy_option_by_id(-1).is_null());
        assert!(curl_easy_option_by_id(987_654).is_null());
        // 0 is not a valid CURLoption id either.
        assert!(curl_easy_option_by_id(0).is_null());
    }

    #[test]
    fn returned_pointers_are_stable_across_calls() {
        let url = CString::new("URL").unwrap();
        // SAFETY: valid NUL-terminated C string kept alive here.
        let a = unsafe { curl_easy_option_by_name(url.as_ptr()) };
        // SAFETY: valid NUL-terminated C string kept alive here.
        let b = unsafe { curl_easy_option_by_name(url.as_ptr()) };
        let c = curl_easy_option_by_id(core_opts::CurlOption::CURLOPT_URL.as_i32());
        assert!(!a.is_null());
        assert!(
            ptr::eq(a, b),
            "repeated by_name calls must be address-stable"
        );
        assert!(ptr::eq(a, c), "by_name and by_id must share one table row");

        // The iterator's first row is likewise stable.
        // SAFETY: NULL is a valid argument.
        let first1 = unsafe { curl_easy_option_next(ptr::null()) };
        // SAFETY: NULL is a valid argument.
        let first2 = unsafe { curl_easy_option_next(ptr::null()) };
        assert!(ptr::eq(first1, first2));
    }

    #[test]
    fn every_core_option_is_reachable_by_name_and_id() {
        // Round-trip the whole inventory: each core option must be findable by
        // name, and every canonical (non-alias) option by id, with matching
        // value types — the property `tests/libtest` and curl tooling rely on.
        for opt in core_opts::EASY_OPTIONS {
            let cname = CString::new(opt.name).unwrap();
            // SAFETY: valid NUL-terminated C string kept alive here.
            let by_name = unsafe { curl_easy_option_by_name(cname.as_ptr()) };
            assert!(!by_name.is_null(), "{} unreachable by name", opt.name);
            assert_eq!(id_of(by_name), opt.id.as_i32());
            assert_eq!(type_of(by_name), easytype_from_core(opt.typ));

            if !opt.is_alias() {
                let by_id = curl_easy_option_by_id(opt.id.as_i32());
                assert!(!by_id.is_null(), "{} unreachable by id", opt.name);
                assert_eq!(name_of(by_id), Some(opt.name));
                assert_eq!(flags_of(by_id) & CURLOT_FLAG_ALIAS, 0);
            }
        }
    }

    #[test]
    fn repr_c_layout_is_pointer_id_type_flags() {
        use core::mem::{align_of, size_of};
        // On every target in the support matrix (all 64-bit) the C layout is
        // `{ const char *; CURLoption; curl_easytype; unsigned int; }` =
        // 8 + 4 + 4 + 4 = 20 bytes, padded to the 8-byte pointer alignment = 24.
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(align_of::<curl_easyoption>(), 8);
            assert_eq!(size_of::<curl_easyoption>(), 24);
        }
        // Regardless of width, the size must be a multiple of the alignment.
        assert_eq!(
            size_of::<curl_easyoption>() % align_of::<curl_easyoption>(),
            0
        );
    }
}
