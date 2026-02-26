//! FFI bindings for the curl option introspection API.
//!
//! Exposes the three `curl_easy_option_*` extern symbols from
//! `include/curl/options.h` as `#[no_mangle] pub unsafe extern "C"`
//! functions, along with the nine `CURLOT_*` type-tag constants for
//! the `curl_easytype` enum.
//!
//! # Design
//!
//! A lazily-initialised static table of [`curl_easyoption`] entries is
//! built from the Rust-native option metadata in
//! [`curl_rs_lib::options::OPTIONS`].  Each entry's `name` field points
//! to a permanently-allocated [`CString`] buffer.  All three
//! lookup / iteration functions return pointers into this table,
//! satisfying the C contract that returned pointers remain valid for the
//! lifetime of the process.
//!
//! # C Header Reference
//!
//! These functions correspond exactly to the three `CURL_EXTERN` symbols
//! declared in `include/curl/options.h`:
//!
//! ```c
//! CURL_EXTERN const struct curl_easyoption *
//!     curl_easy_option_by_name(const char *name);
//!
//! CURL_EXTERN const struct curl_easyoption *
//!     curl_easy_option_by_id(CURLoption id);
//!
//! CURL_EXTERN const struct curl_easyoption *
//!     curl_easy_option_next(const struct curl_easyoption *prev);
//! ```

use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::OnceLock;

use libc::{c_char, c_int, c_uint};

use crate::types::{curl_easyoption, curl_easytype, CURLoption, CURLOT_FLAG_ALIAS};
use curl_rs_lib::options::{
    option_by_id as lib_option_by_id, option_by_name as lib_option_by_name,
    option_next as lib_option_next, CurlOption, OptionType, OPTIONS,
};

// ============================================================================
// Section 1: CURLOT_* Type-Tag Constants
// Derived from: include/curl/options.h (lines 31–41)
//
// These constants define the possible values for the `type_` field of
// `curl_easyoption`.  Each value identifies the expected C type for the
// corresponding `curl_easy_setopt` option.  The integer values are
// identical to the C `curl_easytype` enum discriminants.
// ============================================================================

/// `CURLOT_LONG` — the option takes a `long` value (or range of values).
pub const CURLOT_LONG: curl_easytype = 0;

/// `CURLOT_VALUES` — the option takes a defined set or bitmask value
/// (stored as `long`).
pub const CURLOT_VALUES: curl_easytype = 1;

/// `CURLOT_OFF_T` — the option takes a `curl_off_t` (64-bit signed) value.
pub const CURLOT_OFF_T: curl_easytype = 2;

/// `CURLOT_OBJECT` — the option takes a `void *` pointer.
pub const CURLOT_OBJECT: curl_easytype = 3;

/// `CURLOT_STRING` — the option takes a `const char *` null-terminated string.
pub const CURLOT_STRING: curl_easytype = 4;

/// `CURLOT_SLIST` — the option takes a `struct curl_slist *`.
pub const CURLOT_SLIST: curl_easytype = 5;

/// `CURLOT_CBPTR` — the option takes a `void *` passed as-is to a callback.
pub const CURLOT_CBPTR: curl_easytype = 6;

/// `CURLOT_BLOB` — the option takes a `struct curl_blob *`.
pub const CURLOT_BLOB: curl_easytype = 7;

/// `CURLOT_FUNCTION` — the option takes a function pointer.
pub const CURLOT_FUNCTION: curl_easytype = 8;

// ============================================================================
// Section 2: Static FFI Option Table
//
// The FFI option table is a lazily-initialised parallel array of
// `curl_easyoption` entries, one per entry in the Rust library's
// `OPTIONS` table.  The two arrays share the same ordering (sorted
// alphabetically by name), so index `i` in the FFI table corresponds
// exactly to index `i` in `OPTIONS`.
// ============================================================================

/// Wrapper holding the lazily-initialised FFI option table and the backing
/// `CString` name buffers whose lifetimes must match the table entries.
struct FfiOptionTable {
    /// Parallel array of `curl_easyoption` entries, one per library
    /// [`CurlOption`].  The `name` pointer in each entry points into the
    /// corresponding element of `_names`.
    entries: Box<[curl_easyoption]>,
    /// Backing storage for the `name` field C strings.  Kept alive so the
    /// raw `*const c_char` pointers in `entries` remain valid for the
    /// lifetime of the process.
    _names: Box<[CString]>,
}

// SAFETY: `curl_easyoption` contains `*const c_char` which prevents the
// automatic `Sync`/`Send` derivation for `FfiOptionTable`.  The
// pointed-to data consists of heap-allocated `CString` buffers that are
// permanently held alive by the `_names` field.  The `FfiOptionTable`
// itself lives inside a `OnceLock` (write-once, read-many), so no
// mutation occurs after initialisation.  Cross-thread shared read access
// is therefore safe.
unsafe impl Sync for FfiOptionTable {}
// SAFETY: See above — the table is immutable after creation.
unsafe impl Send for FfiOptionTable {}

/// Process-lifetime storage for the FFI option table.  Initialised
/// exactly once on first access via [`get_ffi_table`].
static FFI_TABLE: OnceLock<FfiOptionTable> = OnceLock::new();

/// Convert a library [`OptionType`] enum variant to the corresponding
/// `curl_easytype` ([`c_int`]) constant.
///
/// The mapping is one-to-one with the C `curl_easytype` enum from
/// `include/curl/options.h`.
fn option_type_to_ffi(ot: OptionType) -> curl_easytype {
    match ot {
        OptionType::Long => CURLOT_LONG,
        OptionType::Values => CURLOT_VALUES,
        OptionType::OffT => CURLOT_OFF_T,
        OptionType::ObjectPoint => CURLOT_OBJECT,
        OptionType::StringPoint => CURLOT_STRING,
        OptionType::SList => CURLOT_SLIST,
        OptionType::CbPoint => CURLOT_CBPTR,
        OptionType::Blob => CURLOT_BLOB,
        OptionType::FunctionPoint => CURLOT_FUNCTION,
    }
}

/// Convert library option flags (`u32`) to FFI-compatible [`c_uint`]
/// flags.
///
/// Currently the only defined flag is [`CURLOT_FLAG_ALIAS`] (bit 0),
/// which marks an option entry as an alias for a preferred name.
fn convert_flags(lib_flags: u32) -> c_uint {
    let mut ffi_flags: c_uint = 0;
    if lib_flags & 1 != 0 {
        ffi_flags |= CURLOT_FLAG_ALIAS;
    }
    ffi_flags
}

/// Lazily initialise and return a reference to the static FFI option
/// table.
///
/// The table is built once on first access by iterating over the
/// library's [`OPTIONS`] table and converting each [`CurlOption`] into a
/// C-compatible [`curl_easyoption`].  Subsequent calls return the cached
/// reference without re-initialisation.
fn get_ffi_table() -> &'static FfiOptionTable {
    FFI_TABLE.get_or_init(|| {
        // Step 1: allocate all CString name buffers.  Once collected into
        // a boxed slice, each CString's internal heap buffer is stable and
        // will not be relocated.
        let names: Box<[CString]> = OPTIONS
            .iter()
            .map(|opt: &CurlOption| {
                CString::new(opt.name)
                    .expect("option name must not contain interior NUL bytes")
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        // Step 2: build the parallel curl_easyoption entries.  Each entry
        // references its CString buffer via `as_ptr()`.  The CString
        // objects are held alive by `_names` in the returned struct.
        let entries: Box<[curl_easyoption]> = names
            .iter()
            .zip(OPTIONS.iter())
            .map(|(cname, opt)| curl_easyoption {
                name: cname.as_ptr(),
                id: opt.id as CURLoption,
                type_: option_type_to_ffi(opt.option_type),
                flags: convert_flags(opt.flags),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        FfiOptionTable {
            entries,
            _names: names,
        }
    })
}

/// Compute the index of a library [`CurlOption`] reference within the
/// static [`OPTIONS`] slice using pointer arithmetic.
///
/// # Panics
///
/// Panics in debug mode if `opt` does not point into [`OPTIONS`].
fn lib_option_index(opt: &CurlOption) -> usize {
    let base = OPTIONS.as_ptr();
    let ptr = opt as *const CurlOption;
    // SAFETY: Both `base` and `ptr` are derived from the same static
    // allocation (the `OPTIONS` slice).  `ptr` was returned by one of the
    // library lookup functions which only return references into that
    // slice, so `ptr >= base` and the offset is within bounds.
    let idx = unsafe { ptr.offset_from(base) } as usize;
    debug_assert!(
        idx < OPTIONS.len(),
        "CurlOption reference is outside the OPTIONS slice"
    );
    idx
}

/// Compute the index of a [`curl_easyoption`] pointer within the FFI
/// table's `entries` array.
///
/// Returns `None` if the pointer falls outside the table bounds (which
/// indicates a caller error — `prev` was not obtained from a prior
/// option-introspection call).
fn ffi_option_index(ptr: *const curl_easyoption, table: &FfiOptionTable) -> Option<usize> {
    let base = table.entries.as_ptr();
    // SAFETY: `ptr` was returned by a prior call to one of the
    // `curl_easy_option_*` functions, which all yield pointers into the
    // `entries` boxed slice.  Both `ptr` and `base` therefore belong to
    // the same allocation, making `offset_from` well-defined.
    let offset = unsafe { ptr.offset_from(base) };
    if offset >= 0 && (offset as usize) < table.entries.len() {
        Some(offset as usize)
    } else {
        None
    }
}

// ============================================================================
// Section 3: extern "C" Functions
// ============================================================================

/// Look up an easy-handle option by its name string (case-insensitive).
///
/// Returns a pointer to a statically-allocated [`curl_easyoption`] entry
/// if the option name matches, or a null pointer if no match is found.
///
/// The `name` parameter should be the option name without the `CURLOPT_`
/// prefix (e.g. `"URL"`, `"VERBOSE"`).  Comparison is case-insensitive.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN const struct curl_easyoption *
/// curl_easy_option_by_name(const char *name);
/// ```
///
/// # Safety
///
/// `name` must be either null or a valid pointer to a NUL-terminated
/// C string that remains valid for the duration of the call.
// SAFETY: This function is `unsafe extern "C"` because it dereferences the
// raw `name` pointer via `CStr::from_ptr`.  The caller guarantees that
// `name` is either null or a valid, NUL-terminated C string.  All
// returned pointers reference the process-lifetime static FFI table.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_option_by_name(
    name: *const c_char,
) -> *const curl_easyoption {
    if name.is_null() {
        return ptr::null();
    }

    // SAFETY: The caller guarantees that `name` points to a valid,
    // NUL-terminated C string.  We checked for null above.
    let c_str = CStr::from_ptr(name);
    let name_str = match c_str.to_str() {
        Ok(s) => s,
        // Non-UTF-8 input cannot match any option name (all option names
        // are pure ASCII), so return null.
        Err(_) => return ptr::null(),
    };

    let table = get_ffi_table();

    match lib_option_by_name(name_str) {
        Some(opt) => {
            let idx = lib_option_index(opt);
            &table.entries[idx] as *const curl_easyoption
        }
        None => ptr::null(),
    }
}

/// Look up an easy-handle option by its numeric [`CURLoption`] identifier.
///
/// Returns a pointer to the canonical (non-alias) [`curl_easyoption`]
/// entry if an option with the given ID exists, or a null pointer
/// otherwise.
///
/// Alias entries (those with [`CURLOT_FLAG_ALIAS`] set in their `flags`
/// field) are skipped so that the returned entry is always the
/// preferred/canonical name for the given ID.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN const struct curl_easyoption *
/// curl_easy_option_by_id(CURLoption id);
/// ```
///
/// # Safety
///
/// No special safety requirements — the `id` parameter is a plain
/// integer.  The function is `unsafe extern "C"` solely because it is an
/// FFI entry point.
// SAFETY: No raw pointers are dereferenced.  The `id` parameter is a
// plain `c_int`.  All returned pointers reference the process-lifetime
// static FFI table.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_option_by_id(id: CURLoption) -> *const curl_easyoption {
    let table = get_ffi_table();

    match lib_option_by_id(id as u32) {
        Some(opt) => {
            let idx = lib_option_index(opt);
            &table.entries[idx] as *const curl_easyoption
        }
        None => ptr::null(),
    }
}

/// Iterate through all known easy-handle options.
///
/// Pass a null pointer to retrieve the first option in the table.  Pass
/// a pointer previously returned by any of the `curl_easy_option_*`
/// functions to retrieve the next entry.  Returns a null pointer when
/// the iteration is complete (i.e. when `prev` pointed to the last
/// entry).
///
/// Typical C usage pattern:
///
/// ```c
/// const struct curl_easyoption *opt = NULL;
/// while ((opt = curl_easy_option_next(opt)) != NULL) {
///     printf("option: %s (id %d)\n", opt->name, opt->id);
/// }
/// ```
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN const struct curl_easyoption *
/// curl_easy_option_next(const struct curl_easyoption *prev);
/// ```
///
/// # Safety
///
/// `prev` must be either null or a pointer previously returned by
/// `curl_easy_option_by_name`, `curl_easy_option_by_id`, or a prior
/// call to `curl_easy_option_next`.  Passing any other pointer results
/// in undefined behaviour.
// SAFETY: This function is `unsafe extern "C"` because `prev` is a raw
// pointer that must either be null or point into the static FFI option
// table.  The function performs pointer arithmetic on `prev` to derive
// the table index.  The caller guarantees the pointer was obtained from
// a prior option-introspection call, so the arithmetic is well-defined.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_option_next(
    prev: *const curl_easyoption,
) -> *const curl_easyoption {
    let table = get_ffi_table();

    if prev.is_null() {
        // Start iteration from the beginning of the option table.
        match lib_option_next(None) {
            Some(opt) => {
                let idx = lib_option_index(opt);
                &table.entries[idx] as *const curl_easyoption
            }
            None => ptr::null(),
        }
    } else {
        // Determine the current position in the FFI table.
        let ffi_idx = match ffi_option_index(prev, table) {
            Some(idx) => idx,
            None => return ptr::null(),
        };

        // Map the FFI index back to the library's OPTIONS entry and
        // delegate to the library's option_next for sequencing logic.
        let lib_ref: &CurlOption = &OPTIONS[ffi_idx];
        match lib_option_next(Some(lib_ref)) {
            Some(next_opt) => {
                let next_idx = lib_option_index(next_opt);
                &table.entries[next_idx] as *const curl_easyoption
            }
            None => ptr::null(),
        }
    }
}

// ============================================================================
// Section 4: Compile-Time Assertions
// ============================================================================

/// Compile-time verification that `curl_easytype` is indeed `c_int`.
/// This ensures our `CURLOT_*` constants have the correct type.
const _: [(); 0] = [(); {
    // Both types must have the same size for ABI compatibility.
    // (curl_easytype is defined as c_int in types.rs)
    (std::mem::size_of::<curl_easytype>() == std::mem::size_of::<c_int>()) as usize - 1
}];
