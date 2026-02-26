<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# `curlx`

Functions that are prefixed with `curlx_` are internal global functions that
are written in a way to allow them to be "borrowed" and used outside of the
library: in the curl tool and in the curl test suite.

The `curlx` functions are not part of the libcurl API, but are stand-alone
functions whose sources can be built and used outside of libcurl. There are
not API or ABI guarantees. The functions are not written or meant to be used
outside of the curl project.

Only functions actually used by the library are provided here.

## Ways to success

- Do not use `struct Curl_easy` in these files
- Do not use the printf defines in these files
- Make them as stand-alone as possible

## curl-rs Rust Workspace — Utility Replacements

In the curl-rs Rust workspace, the `curlx_` utility functions described above
are replaced by idiomatic Rust equivalents in the `curl-rs-lib/src/util/`
module. Instead of C standalone functions with the `curlx_` prefix, Rust uses
standard library types and dedicated modules with proper module privacy.

Key replacement modules:

- `util/base64.rs` — Base64 encoding/decoding via the `base64` crate (replaces `curlx/base64.c`)
- `util/dynbuf.rs` — dynamic buffer using Rust `Vec<u8>` (replaces `curlx/dynbuf.c`)
- `util/strparse.rs` — string parsing utilities (replaces `curlx/strparse.c`)
- `util/timediff.rs` — time difference calculations (replaces `curlx/timediff.c`)
- `util/timeval.rs` — timestamp utilities (replaces `curlx/timeval.c`)
- `util/nonblock.rs` — non-blocking socket helpers using Tokio (replaces `curlx/nonblock.c`)
- `util/warnless.rs` — type conversions, largely unnecessary in Rust's type system (replaces `curlx/warnless.c`)

Additional utility modules in `curl-rs-lib/src/util/`: `fnmatch`, `parsedate`,
`rand`, `hash`, `llist`, `splay`, `bufq`, `select`, `sendf`, `strerror`,
`hmac`, `md5`, `sha256`, and `mprintf`.

Many C portability shims originally in `lib/curlx/` (e.g., `inet_ntop`,
`inet_pton`, `version_win32`) are unnecessary in Rust due to standard library
support and are not carried over to the Rust workspace.
