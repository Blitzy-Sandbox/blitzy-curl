//! Wildcard / glob pattern matching for FTP wildcard download.
//!
//! This module is a Rust rewrite of `lib/curl_fnmatch.c` (385 lines) — FTP
//! wildcard matching with bracket expressions, keyword character classes, and
//! recursive star matching. Used primarily by the FTP wildcard download feature
//! to match filenames against glob patterns.
//!
//! # Pattern Syntax
//!
//! | Pattern  | Meaning                                      |
//! |----------|----------------------------------------------|
//! | `*`      | Matches zero or more characters               |
//! | `?`      | Matches exactly one character                 |
//! | `[abc]`  | Bracket expression matching any of a, b, c    |
//! | `[a-z]`  | Character range in bracket expression         |
//! | `[!abc]` | Negated bracket expression (also `[^abc]`)    |
//! | `\x`     | Escaped literal character                     |
//! | `[[:alpha:]]` | POSIX character class                   |
//!
//! # Supported POSIX Character Classes
//!
//! `alnum`, `alpha`, `digit`, `xdigit`, `print`, `graph`, `space`, `blank`,
//! `upper`, `lower`. These are the exact set supported by curl 8.x; other
//! POSIX classes (`cntrl`, `punct`) are **not** supported and will cause a
//! parse error for functional parity with the C implementation.
//!
//! # Recursion Depth
//!
//! The `*` wildcard uses recursive backtracking. A depth limit of 2 is
//! enforced (matching the C implementation's `maxstars` parameter) to prevent
//! stack overflow on pathological patterns.

#[allow(unused_imports)]
use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Constants — match C `CURLFNM_*` layout
// ---------------------------------------------------------------------------

/// Size of the ASCII character set portion of the charset array.
const CHARSET_LEN: usize = 256;

/// Total charset array size including special flag slots.
const CHSET_SIZE: usize = CHARSET_LEN + 15;

/// Index of the negation flag in the charset array.
const NEGATE_IDX: usize = CHARSET_LEN;

/// Index of the `[:alnum:]` POSIX class flag.
const ALNUM_IDX: usize = CHARSET_LEN + 1;

/// Index of the `[:digit:]` POSIX class flag.
const DIGIT_IDX: usize = CHARSET_LEN + 2;

/// Index of the `[:xdigit:]` POSIX class flag.
const XDIGIT_IDX: usize = CHARSET_LEN + 3;

/// Index of the `[:alpha:]` POSIX class flag.
const ALPHA_IDX: usize = CHARSET_LEN + 4;

/// Index of the `[:print:]` POSIX class flag.
const PRINT_IDX: usize = CHARSET_LEN + 5;

/// Index of the `[:blank:]` POSIX class flag.
const BLANK_IDX: usize = CHARSET_LEN + 6;

/// Index of the `[:lower:]` POSIX class flag.
const LOWER_IDX: usize = CHARSET_LEN + 7;

/// Index of the `[:graph:]` POSIX class flag.
const GRAPH_IDX: usize = CHARSET_LEN + 8;

/// Index of the `[:space:]` POSIX class flag.
const SPACE_IDX: usize = CHARSET_LEN + 9;

/// Index of the `[:upper:]` POSIX class flag.
const UPPER_IDX: usize = CHARSET_LEN + 10;

/// Maximum number of recursive `*` expansions allowed.
/// Matches the C implementation's initial `maxstars` value of 2.
const MAX_STARS: i32 = 2;

// ---------------------------------------------------------------------------
// FnMatchResult — match result enum
// ---------------------------------------------------------------------------

/// Result of a wildcard pattern match operation.
///
/// Integer values match the C constants for FFI compatibility:
/// - `CURL_FNMATCH_MATCH  = 0`
/// - `CURL_FNMATCH_NOMATCH = 1`
/// - `CURL_FNMATCH_FAIL   = 2`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum FnMatchResult {
    /// The string matches the pattern (CURL_FNMATCH_MATCH = 0).
    Match = 0,
    /// The string does not match the pattern (CURL_FNMATCH_NOMATCH = 1).
    NoMatch = 1,
    /// A syntax or internal error prevented matching (CURL_FNMATCH_FAIL = 2).
    Error = 2,
}

// ---------------------------------------------------------------------------
// Character classification helpers
// ---------------------------------------------------------------------------

/// Character class categories for range-aware bracket expressions.
///
/// When a bracket expression contains a range like `[a-z]`, only characters
/// belonging to the same class as the endpoints are included. For example,
/// `[a-z]` includes only lowercase ASCII letters, not the punctuation
/// characters between 'Z' (90) and 'a' (97) in the ASCII table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharClass {
    Other,
    Digit,
    Upper,
    Lower,
}

/// Classify a byte into one of the character classes.
///
/// Matches the C `charclass()` function exactly.
#[inline]
fn char_class(c: u8) -> CharClass {
    if c.is_ascii_uppercase() {
        CharClass::Upper
    } else if c.is_ascii_lowercase() {
        CharClass::Lower
    } else if c.is_ascii_digit() {
        CharClass::Digit
    } else {
        CharClass::Other
    }
}

/// Check whether a byte is alphanumeric (ASCII).
#[inline]
fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// Check whether a byte is printable ASCII (0x20..=0x7E).
#[inline]
fn is_print(c: u8) -> bool {
    (0x20..=0x7E).contains(&c)
}

/// Check whether a byte is a "blank" character (space or horizontal tab).
///
/// The C implementation uses `ISBLANK` for **both** the `[:space:]` and
/// `[:blank:]` POSIX classes. We replicate that exact behavior for
/// functional parity.
#[inline]
fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// Check whether a byte is a graphical character (printable, non-space).
#[inline]
fn is_graph(c: u8) -> bool {
    is_print(c) && c != b' '
}

// ---------------------------------------------------------------------------
// Bracket expression parser
// ---------------------------------------------------------------------------

/// States for the bracket expression (`setcharset`) parser state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetcharsetState {
    Default,
    RightBr,
    RightBrLeftBr,
}

/// States for the POSIX keyword (`parsekeyword`) parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseKeyState {
    Init,
    Ddot,
}

/// Parse a POSIX character class keyword from the pattern bytes.
///
/// Expects `pos` to point at the first character **after** the opening `[:`
/// sequence. On success, advances `pos` past the closing `:]` and sets the
/// corresponding flag in `charset`. Returns `true` on success.
///
/// Supported keywords (matching curl 8.x exactly):
/// `digit`, `alnum`, `alpha`, `xdigit`, `print`, `graph`, `space`, `blank`,
/// `upper`, `lower`.
fn parse_keyword(pattern: &[u8], pos: &mut usize, charset: &mut [u8; CHSET_SIZE]) -> bool {
    let mut state = ParseKeyState::Init;
    let mut keyword = [0u8; 10];
    let mut ki: usize = 0;
    let mut p = *pos;

    loop {
        if p >= pattern.len() {
            return false;
        }
        let c = pattern[p];
        p += 1;

        if ki >= keyword.len() {
            return false;
        }

        match state {
            ParseKeyState::Init => {
                if c.is_ascii_lowercase() {
                    keyword[ki] = c;
                    ki += 1;
                } else if c == b':' {
                    state = ParseKeyState::Ddot;
                } else {
                    return false;
                }
            }
            ParseKeyState::Ddot => {
                if c == b']' {
                    // Found the closing `:]` — identify the keyword.
                    *pos = p;
                    let kw = &keyword[..ki];
                    if kw == b"digit" {
                        charset[DIGIT_IDX] = 1;
                    } else if kw == b"alnum" {
                        charset[ALNUM_IDX] = 1;
                    } else if kw == b"alpha" {
                        charset[ALPHA_IDX] = 1;
                    } else if kw == b"xdigit" {
                        charset[XDIGIT_IDX] = 1;
                    } else if kw == b"print" {
                        charset[PRINT_IDX] = 1;
                    } else if kw == b"graph" {
                        charset[GRAPH_IDX] = 1;
                    } else if kw == b"space" {
                        charset[SPACE_IDX] = 1;
                    } else if kw == b"blank" {
                        charset[BLANK_IDX] = 1;
                    } else if kw == b"upper" {
                        charset[UPPER_IDX] = 1;
                    } else if kw == b"lower" {
                        charset[LOWER_IDX] = 1;
                    } else {
                        return false;
                    }
                    return true;
                } else {
                    return false;
                }
            }
        }
    }
}

/// Include a single character or a character range in the charset.
///
/// Reads the character at `pattern[*pos]`, marks it in `charset`, and then
/// checks whether the subsequent bytes form a valid range (e.g. `a-z`).
/// Ranges are class-aware: `[a-z]` only includes lowercase letters, not the
/// non-letter ASCII bytes between 'Z' and 'a'.
///
/// Advances `*pos` past the consumed characters.
fn set_char_or_range(pattern: &[u8], pos: &mut usize, charset: &mut [u8; CHSET_SIZE]) {
    let start_pos = *pos;
    if start_pos >= pattern.len() {
        return;
    }

    let c = pattern[start_pos];
    *pos = start_pos + 1; // Always advance past at least the first character.
    charset[c as usize] = 1;

    // Check for a range: the char must be alphanumeric and followed by '-'.
    if is_alnum(c) {
        let dash_pos = *pos;
        if dash_pos < pattern.len() && pattern[dash_pos] == b'-' {
            let cc = char_class(c);
            let mut after_dash = dash_pos + 1;

            if after_dash >= pattern.len() {
                return;
            }

            let mut end_range = pattern[after_dash];
            after_dash += 1;

            // Handle escaped end-of-range character.
            if end_range == b'\\' {
                if after_dash >= pattern.len() {
                    return;
                }
                end_range = pattern[after_dash];
                after_dash += 1;
            }

            // Validate the range: end must be >= start and same class.
            if end_range >= c && char_class(end_range) == cc {
                let mut fill = c;
                while fill != end_range {
                    fill += 1;
                    if char_class(fill) == cc {
                        charset[fill as usize] = 1;
                    }
                }
                *pos = after_dash;
            }
            // If not a valid range, only the single character is consumed
            // (pos already advanced past the first char above).
        }
    }
}

/// Parse the contents of a bracket expression `[...]` and populate `charset`.
///
/// Expects `*pos` to point at the first byte **inside** the brackets (i.e.
/// after the opening `[`). On success, advances `*pos` to the byte **after**
/// the closing `]` and returns `true`.
///
/// This is a faithful translation of the C `setcharset()` function, including
/// its three-state machine for handling `]` as the first character and `[]`
/// sequences.
fn set_charset(pattern: &[u8], pos: &mut usize, charset: &mut [u8; CHSET_SIZE]) -> bool {
    let mut state = SetcharsetState::Default;
    let mut something_found = false;

    // Zero out the charset array.
    *charset = [0u8; CHSET_SIZE];

    loop {
        if *pos >= pattern.len() {
            return false; // Unterminated bracket expression.
        }
        let c = pattern[*pos];
        if c == 0 {
            return false;
        }

        match state {
            SetcharsetState::Default => {
                if c == b']' {
                    if something_found {
                        // End of bracket expression.
                        *pos += 1;
                        return true;
                    }
                    // `]` as the first character — treat as literal.
                    something_found = true;
                    state = SetcharsetState::RightBr;
                    charset[c as usize] = 1;
                    *pos += 1;
                } else if c == b'[' {
                    // Check for POSIX class `[:keyword:]`.
                    let mut pp = *pos + 1;
                    if pp < pattern.len() && pattern[pp] == b':' {
                        pp += 1; // Skip the ':'.
                        if parse_keyword(pattern, &mut pp, charset) {
                            *pos = pp;
                        } else {
                            // Not a valid keyword — treat `[` as literal.
                            charset[c as usize] = 1;
                            *pos += 1;
                        }
                    } else {
                        charset[c as usize] = 1;
                        *pos += 1;
                    }
                    something_found = true;
                } else if c == b'^' || c == b'!' {
                    if !something_found {
                        if charset[NEGATE_IDX] != 0 {
                            // Second negation char — treat as literal.
                            charset[c as usize] = 1;
                            something_found = true;
                        } else {
                            // First negation char — set negate flag.
                            charset[NEGATE_IDX] = 1;
                        }
                    } else {
                        // Not in leading position — treat as literal.
                        charset[c as usize] = 1;
                    }
                    *pos += 1;
                } else if c == b'\\' {
                    *pos += 1; // Skip the backslash.
                    if *pos < pattern.len() && pattern[*pos] != 0 {
                        set_char_or_range(pattern, pos, charset);
                    } else {
                        // Trailing backslash — treat as literal.
                        charset[b'\\' as usize] = 1;
                    }
                    something_found = true;
                } else {
                    set_char_or_range(pattern, pos, charset);
                    something_found = true;
                }
            }

            SetcharsetState::RightBr => {
                if c == b'[' {
                    state = SetcharsetState::RightBrLeftBr;
                    charset[c as usize] = 1;
                    *pos += 1;
                } else if c == b']' {
                    // `[]` — end of expression.
                    *pos += 1;
                    return true;
                } else if is_print(c) {
                    charset[c as usize] = 1;
                    *pos += 1;
                    state = SetcharsetState::Default;
                } else {
                    return false;
                }
            }

            SetcharsetState::RightBrLeftBr => {
                if c == b']' {
                    *pos += 1;
                    return true;
                }
                state = SetcharsetState::Default;
                charset[c as usize] = 1;
                *pos += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core matching loop
// ---------------------------------------------------------------------------

/// Internal recursive matching engine.
///
/// This is a direct translation of the C `loop()` function. It performs
/// recursive backtracking for `*` wildcards with a depth limit of
/// `max_stars` to prevent stack overflow on pathological patterns.
///
/// # Arguments
///
/// * `pattern` — the full pattern byte slice
/// * `pp` — current position in the pattern
/// * `string` — the full string byte slice
/// * `sp` — current position in the string
/// * `max_stars` — remaining allowed `*` recursion depth
fn matching_loop(
    pattern: &[u8],
    mut pp: usize,
    string: &[u8],
    mut sp: usize,
    max_stars: i32,
) -> FnMatchResult {
    let mut charset = [0u8; CHSET_SIZE];

    loop {
        if pp >= pattern.len() {
            // End of pattern — match if end of string too.
            return if sp >= string.len() {
                FnMatchResult::Match
            } else {
                FnMatchResult::NoMatch
            };
        }

        match pattern[pp] {
            b'*' => {
                if max_stars <= 0 {
                    return FnMatchResult::NoMatch;
                }

                // Regroup consecutive `*` and `?` characters.
                // `*?*?*` is equivalent to `??*`.
                loop {
                    pp += 1;
                    if pp >= pattern.len() {
                        // Trailing `*` matches everything remaining.
                        return FnMatchResult::Match;
                    }
                    if pattern[pp] == b'?' {
                        if sp >= string.len() {
                            return FnMatchResult::NoMatch;
                        }
                        sp += 1;
                    } else if pattern[pp] != b'*' {
                        break;
                    }
                }

                // Try matching the suffix pattern against each remaining
                // position in the string. Decrement max_stars to bound
                // recursion depth.
                let new_max = max_stars - 1;
                while sp < string.len() {
                    if matching_loop(pattern, pp, string, sp, new_max) == FnMatchResult::Match {
                        return FnMatchResult::Match;
                    }
                    sp += 1;
                }
                return FnMatchResult::NoMatch;
            }

            b'?' => {
                if sp >= string.len() {
                    return FnMatchResult::NoMatch;
                }
                sp += 1;
                pp += 1;
            }

            b'\\' => {
                // Escape: if next pattern byte exists, advance past backslash.
                if pp + 1 < pattern.len() {
                    pp += 1;
                }
                // Compare escaped char with string char.
                if sp >= string.len() || string[sp] != pattern[pp] {
                    return FnMatchResult::NoMatch;
                }
                sp += 1;
                pp += 1;
            }

            b'[' => {
                let mut bracket_pos = pp + 1; // Position after the opening `[`.
                if set_charset(pattern, &mut bracket_pos, &mut charset) {
                    if sp >= string.len() {
                        return FnMatchResult::NoMatch;
                    }

                    let sc = string[sp];
                    let mut found = false;

                    // Check direct character membership first.
                    if charset[sc as usize] != 0 {
                        found = true;
                    }
                    // Then check POSIX class flags (else-if chain matches C).
                    if !found && charset[ALNUM_IDX] != 0 {
                        found = sc.is_ascii_alphanumeric();
                    } else if !found && charset[ALPHA_IDX] != 0 {
                        found = sc.is_ascii_alphabetic();
                    } else if !found && charset[DIGIT_IDX] != 0 {
                        found = sc.is_ascii_digit();
                    } else if !found && charset[XDIGIT_IDX] != 0 {
                        found = sc.is_ascii_hexdigit();
                    } else if !found && charset[PRINT_IDX] != 0 {
                        found = is_print(sc);
                    } else if !found && charset[SPACE_IDX] != 0 {
                        // C uses ISBLANK for both [:space:] and [:blank:].
                        found = is_blank(sc);
                    } else if !found && charset[UPPER_IDX] != 0 {
                        found = sc.is_ascii_uppercase();
                    } else if !found && charset[LOWER_IDX] != 0 {
                        found = sc.is_ascii_lowercase();
                    } else if !found && charset[BLANK_IDX] != 0 {
                        found = is_blank(sc);
                    } else if !found && charset[GRAPH_IDX] != 0 {
                        found = is_graph(sc);
                    }

                    // Apply negation.
                    if charset[NEGATE_IDX] != 0 {
                        found = !found;
                    }

                    if !found {
                        return FnMatchResult::NoMatch;
                    }

                    pp = bracket_pos;
                    sp += 1;
                } else {
                    // Malformed bracket expression — treated as no-match
                    // (matches C behavior which returns NOMATCH).
                    return FnMatchResult::NoMatch;
                }
            }

            literal => {
                if sp >= string.len() || literal != string[sp] {
                    return FnMatchResult::NoMatch;
                }
                pp += 1;
                sp += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Match a string against a wildcard pattern.
///
/// This is the main entry point, equivalent to the C `Curl_fnmatch` function.
/// Pattern syntax supports `*`, `?`, bracket expressions `[...]` with POSIX
/// character classes, ranges, negation, and backslash escaping.
///
/// Matching is case-sensitive, which is appropriate for FTP filenames.
///
/// # Arguments
///
/// * `pattern` — the glob pattern to match against.
/// * `string` — the string to test.
///
/// # Returns
///
/// - [`FnMatchResult::Match`] if `string` matches `pattern`.
/// - [`FnMatchResult::NoMatch`] if `string` does not match `pattern`.
/// - [`FnMatchResult::Error`] on malformed input (currently: `None` input in
///   the C API; in Rust, empty strings are valid, and the only error case from
///   the Rust interface perspective would be internal issues).
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::fnmatch::{curl_fnmatch, FnMatchResult};
///
/// assert_eq!(curl_fnmatch("*.txt", "file.txt"), FnMatchResult::Match);
/// assert_eq!(curl_fnmatch("*.txt", "file.rs"), FnMatchResult::NoMatch);
/// assert_eq!(curl_fnmatch("file?.log", "file1.log"), FnMatchResult::Match);
/// assert_eq!(curl_fnmatch("[abc]", "b"), FnMatchResult::Match);
/// ```
pub fn curl_fnmatch(pattern: &str, string: &str) -> FnMatchResult {
    matching_loop(
        pattern.as_bytes(),
        0,
        string.as_bytes(),
        0,
        MAX_STARS,
    )
}

/// C-compatible callback wrapper returning integer result codes.
///
/// This function provides the same matching logic as [`curl_fnmatch`] but
/// returns an `i32` matching the C `CURL_FNMATCH_*` constants, suitable for
/// use by the FFI layer implementing `CURLOPT_FNMATCH_FUNCTION`.
///
/// # Return values
///
/// | Value | Meaning                          |
/// |-------|----------------------------------|
/// | `0`   | Match (`CURL_FNMATCH_MATCH`)     |
/// | `1`   | No match (`CURL_FNMATCH_NOMATCH`)|
/// | `2`   | Error (`CURL_FNMATCH_FAIL`)      |
pub fn fnmatch_callback(pattern: &str, string: &str) -> i32 {
    curl_fnmatch(pattern, string) as i32
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Basic literal matching ---

    #[test]
    fn test_exact_match() {
        assert_eq!(curl_fnmatch("hello", "hello"), FnMatchResult::Match);
    }

    #[test]
    fn test_exact_no_match() {
        assert_eq!(curl_fnmatch("hello", "world"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_empty_pattern_empty_string() {
        assert_eq!(curl_fnmatch("", ""), FnMatchResult::Match);
    }

    #[test]
    fn test_empty_pattern_nonempty_string() {
        assert_eq!(curl_fnmatch("", "a"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_nonempty_pattern_empty_string() {
        assert_eq!(curl_fnmatch("a", ""), FnMatchResult::NoMatch);
    }

    // --- Star wildcard ---

    #[test]
    fn test_star_matches_all() {
        assert_eq!(curl_fnmatch("*", "anything"), FnMatchResult::Match);
    }

    #[test]
    fn test_star_matches_empty() {
        assert_eq!(curl_fnmatch("*", ""), FnMatchResult::Match);
    }

    #[test]
    fn test_star_suffix() {
        assert_eq!(curl_fnmatch("*.txt", "file.txt"), FnMatchResult::Match);
    }

    #[test]
    fn test_star_suffix_no_match() {
        assert_eq!(curl_fnmatch("*.txt", "file.rs"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_star_prefix() {
        assert_eq!(curl_fnmatch("file*", "filename.txt"), FnMatchResult::Match);
    }

    #[test]
    fn test_star_middle() {
        assert_eq!(curl_fnmatch("f*e", "file"), FnMatchResult::Match);
    }

    #[test]
    fn test_star_middle_no_match() {
        assert_eq!(curl_fnmatch("f*e", "filx"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_double_star() {
        assert_eq!(curl_fnmatch("*test*", "my_test_file"), FnMatchResult::Match);
    }

    #[test]
    fn test_consecutive_stars() {
        assert_eq!(curl_fnmatch("***", "anything"), FnMatchResult::Match);
    }

    // --- Question mark ---

    #[test]
    fn test_question_mark() {
        assert_eq!(curl_fnmatch("file?.txt", "file1.txt"), FnMatchResult::Match);
    }

    #[test]
    fn test_question_mark_no_match_empty() {
        assert_eq!(curl_fnmatch("?", ""), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_question_mark_single() {
        assert_eq!(curl_fnmatch("?", "a"), FnMatchResult::Match);
    }

    #[test]
    fn test_multiple_question_marks() {
        assert_eq!(curl_fnmatch("???", "abc"), FnMatchResult::Match);
    }

    #[test]
    fn test_question_too_short() {
        assert_eq!(curl_fnmatch("???", "ab"), FnMatchResult::NoMatch);
    }

    // --- Bracket expressions ---

    #[test]
    fn test_bracket_simple() {
        assert_eq!(curl_fnmatch("[abc]", "a"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[abc]", "b"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[abc]", "c"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[abc]", "d"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_bracket_range_lower() {
        assert_eq!(curl_fnmatch("[a-z]", "m"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[a-z]", "A"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_bracket_range_upper() {
        assert_eq!(curl_fnmatch("[A-Z]", "M"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[A-Z]", "m"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_bracket_range_digit() {
        assert_eq!(curl_fnmatch("[0-9]", "5"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[0-9]", "a"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_bracket_negate_excl() {
        assert_eq!(curl_fnmatch("[!abc]", "d"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[!abc]", "a"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_bracket_negate_caret() {
        assert_eq!(curl_fnmatch("[^abc]", "d"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[^abc]", "b"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_bracket_literal_right_bracket() {
        // `]` as first char is literal.
        assert_eq!(curl_fnmatch("[]a]", "]"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[]a]", "a"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[]a]", "b"), FnMatchResult::NoMatch);
    }

    // --- POSIX character classes ---

    #[test]
    fn test_posix_digit() {
        assert_eq!(curl_fnmatch("[[:digit:]]", "5"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:digit:]]", "a"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_posix_alpha() {
        assert_eq!(curl_fnmatch("[[:alpha:]]", "a"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:alpha:]]", "5"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_posix_alnum() {
        assert_eq!(curl_fnmatch("[[:alnum:]]", "a"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:alnum:]]", "5"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:alnum:]]", "!"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_posix_upper() {
        assert_eq!(curl_fnmatch("[[:upper:]]", "A"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:upper:]]", "a"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_posix_lower() {
        assert_eq!(curl_fnmatch("[[:lower:]]", "a"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:lower:]]", "A"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_posix_xdigit() {
        assert_eq!(curl_fnmatch("[[:xdigit:]]", "f"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:xdigit:]]", "F"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:xdigit:]]", "9"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:xdigit:]]", "g"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_posix_print() {
        assert_eq!(curl_fnmatch("[[:print:]]", " "), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:print:]]", "a"), FnMatchResult::Match);
    }

    #[test]
    fn test_posix_blank() {
        assert_eq!(curl_fnmatch("[[:blank:]]", " "), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:blank:]]", "\t"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:blank:]]", "a"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_posix_graph() {
        assert_eq!(curl_fnmatch("[[:graph:]]", "a"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:graph:]]", " "), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_posix_space() {
        // In curl C, [:space:] uses ISBLANK (space or tab).
        assert_eq!(curl_fnmatch("[[:space:]]", " "), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:space:]]", "\t"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("[[:space:]]", "a"), FnMatchResult::NoMatch);
    }

    // --- Escape handling ---

    #[test]
    fn test_escape_star() {
        assert_eq!(curl_fnmatch("\\*", "*"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("\\*", "a"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_escape_question() {
        assert_eq!(curl_fnmatch("\\?", "?"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("\\?", "a"), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_escape_backslash() {
        assert_eq!(curl_fnmatch("\\\\", "\\"), FnMatchResult::Match);
    }

    #[test]
    fn test_escape_bracket() {
        assert_eq!(curl_fnmatch("\\[", "["), FnMatchResult::Match);
    }

    #[test]
    fn test_trailing_backslash() {
        // C treats trailing backslash as literal — matches `\` in string.
        assert_eq!(curl_fnmatch("\\", "\\"), FnMatchResult::Match);
    }

    // --- fnmatch_callback ---

    #[test]
    fn test_callback_match() {
        assert_eq!(fnmatch_callback("*.txt", "file.txt"), 0);
    }

    #[test]
    fn test_callback_no_match() {
        assert_eq!(fnmatch_callback("*.txt", "file.rs"), 1);
    }

    // --- Complex patterns ---

    #[test]
    fn test_combined_star_question() {
        assert_eq!(curl_fnmatch("*?*", "a"), FnMatchResult::Match);
        assert_eq!(curl_fnmatch("*?*", ""), FnMatchResult::NoMatch);
    }

    #[test]
    fn test_combined_bracket_star() {
        assert_eq!(
            curl_fnmatch("[a-z]*.txt", "file.txt"),
            FnMatchResult::Match
        );
        assert_eq!(
            curl_fnmatch("[a-z]*.txt", "1file.txt"),
            FnMatchResult::NoMatch
        );
    }

    #[test]
    fn test_ftp_wildcard_pattern() {
        assert_eq!(
            curl_fnmatch("*.csv", "report_2024.csv"),
            FnMatchResult::Match
        );
        assert_eq!(
            curl_fnmatch("data_[0-9][0-9][0-9][0-9].csv", "data_2024.csv"),
            FnMatchResult::Match
        );
    }

    #[test]
    fn test_max_stars_limit() {
        // With maxstars=2, this pattern has three `*` — the third recursive
        // expansion will return NoMatch due to depth limit.
        // However, consecutive stars are collapsed, so `***` acts as one `*`.
        assert_eq!(curl_fnmatch("***", "test"), FnMatchResult::Match);
    }

    #[test]
    fn test_enum_repr_values() {
        assert_eq!(FnMatchResult::Match as i32, 0);
        assert_eq!(FnMatchResult::NoMatch as i32, 1);
        assert_eq!(FnMatchResult::Error as i32, 2);
    }
}
