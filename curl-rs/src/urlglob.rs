//! URL globbing and range expansion module.
//!
//! Rust rewrite of `src/tool_urlglob.c` and `src/tool_urlglob.h`.
//! Implements URL pattern expansion for brace `{set}` and bracket `[range]`
//! expressions in URLs.
//!
//! # Pattern Syntax
//!
//! - `{item1,item2,...}` — alternation set (max 100,000 elements)
//! - `[min-max]` — numeric or alphabetic range
//! - `[min-max:step]` — stepped range
//! - `[01-99]` — zero-padded numeric range
//! - Backslash `\` escapes `{`, `}`, `[`, `]` characters
//! - IPv6 literals in brackets `[::1]` are detected and skipped

use anyhow::{bail, anyhow, Result};
use std::fmt::Write;

/// Maximum number of pattern segments in a single URL template.
const MAX_GLOB_PATTERNS: usize = 255;

/// Maximum number of elements in a single `{set}` expression.
const MAX_SET_ELEMENTS: usize = 100_000;

/// Represents a single segment of a URL glob pattern.
#[derive(Debug, Clone)]
pub enum GlobPattern {
    /// A literal URL segment with no expansion.
    Fixed(String),

    /// A brace alternation set `{item1,item2,...}`.
    Set {
        /// The list of alternative values.
        elements: Vec<String>,
        /// 0-based index among non-fixed patterns (for `#N` matching).
        glob_index: usize,
    },

    /// A numeric range `[min-max]` or `[min-max:step]`.
    NumRange {
        /// Range minimum (inclusive).
        min: i64,
        /// Range maximum (inclusive).
        max: i64,
        /// Step value (always positive).
        step: i64,
        /// Minimum display width for zero-padding.
        pad_width: usize,
        /// 0-based index among non-fixed patterns (for `#N` matching).
        glob_index: usize,
    },

    /// An alphabetic character range `[a-z]` or `[a-z:step]`.
    CharRange {
        /// Range start character (inclusive).
        min: char,
        /// Range end character (inclusive).
        max: char,
        /// Step value (always positive).
        step: i64,
        /// 0-based index among non-fixed patterns (for `#N` matching).
        glob_index: usize,
    },
}

impl GlobPattern {
    /// Returns the number of values this pattern expands to.
    fn count(&self) -> i64 {
        match self {
            GlobPattern::Fixed(_) => 1,
            GlobPattern::Set { elements, .. } => elements.len() as i64,
            GlobPattern::NumRange { min, max, step, .. } => {
                if *step == 0 {
                    return 1;
                }
                ((max - min) / step) + 1
            }
            GlobPattern::CharRange { min, max, step, .. } => {
                if *step == 0 {
                    return 1;
                }
                let diff = (*max as i64) - (*min as i64);
                (diff / step) + 1
            }
        }
    }

    /// Returns the string value at the given iteration index.
    fn value_at(&self, index: usize) -> String {
        match self {
            GlobPattern::Fixed(s) => s.clone(),
            GlobPattern::Set { elements, .. } => {
                if index < elements.len() {
                    elements[index].clone()
                } else {
                    String::new()
                }
            }
            GlobPattern::NumRange {
                min, step, pad_width, ..
            } => {
                let val = min + (index as i64) * step;
                if *pad_width > 0 {
                    format!("{:0>width$}", val, width = *pad_width)
                } else {
                    format!("{}", val)
                }
            }
            GlobPattern::CharRange { min, step, .. } => {
                let code = (*min as i64) + (index as i64) * step;
                // Clamp to valid char range
                if let Some(ch) = char::from_u32(code as u32) {
                    String::from(ch)
                } else {
                    String::new()
                }
            }
        }
    }

    /// Returns the current value of this pattern given the current iteration index.
    fn current_value(&self, idx: usize) -> String {
        self.value_at(idx)
    }

    /// Returns true if this is a non-fixed (expandable) pattern.
    fn is_glob(&self) -> bool {
        !matches!(self, GlobPattern::Fixed(_))
    }
}

/// URL glob state holding parsed patterns and iteration state.
#[derive(Debug, Clone)]
pub struct URLGlob {
    /// Parsed pattern segments in order.
    patterns: Vec<GlobPattern>,
    /// Current iteration index for each pattern.
    indices: Vec<usize>,
    /// Total number of URL combinations.
    total_count: i64,
    /// Number of non-fixed (expandable) patterns encountered.
    glob_count: usize,
    /// Whether `next_url()` has been called at least once.
    been_here: bool,
}

impl Default for URLGlob {
    fn default() -> Self {
        Self::new()
    }
}

impl URLGlob {
    /// Creates a new empty URLGlob.
    pub fn new() -> Self {
        URLGlob {
            patterns: Vec::new(),
            indices: Vec::new(),
            total_count: 1,
            glob_count: 0,
            been_here: false,
        }
    }

    /// Returns the next expanded URL, or `None` when all combinations are exhausted.
    ///
    /// This implements odometer-style iteration: the rightmost non-fixed pattern
    /// advances first, with carry propagating leftward.
    pub fn next_url(&mut self) -> Option<String> {
        if self.patterns.is_empty() {
            return None;
        }

        if self.been_here {
            // Advance the iteration: rightmost pattern first, carry left
            let mut carry = true;
            for i in (0..self.patterns.len()).rev() {
                if !carry {
                    break;
                }
                let max_idx = self.patterns[i].count() as usize;
                if max_idx <= 1 {
                    // Fixed patterns have only one value, always carry
                    continue;
                }
                self.indices[i] += 1;
                if self.indices[i] >= max_idx {
                    self.indices[i] = 0;
                    // carry continues
                } else {
                    carry = false;
                }
            }
            if carry {
                // All combinations exhausted
                return None;
            }
        }

        self.been_here = true;

        // Build the URL from current pattern values
        let mut url = String::new();
        for (i, pat) in self.patterns.iter().enumerate() {
            let _ = write!(url, "{}", pat.current_value(self.indices[i]));
        }
        Some(url)
    }

    /// Expands `#N` placeholders in `filename` with current pattern values.
    ///
    /// `#1` refers to the first non-fixed pattern, `#2` to the second, etc.
    /// `#` alone (without a digit) is passed through literally.
    /// Used for output filename generation with the `-o` option.
    pub fn match_url(&self, filename: &str) -> String {
        glob_match_url(self, filename)
    }

    /// Returns the total number of URL combinations this glob will produce.
    pub fn amount(&self) -> i64 {
        self.total_count
    }

    /// Returns `true` if any glob patterns were parsed (i.e., the URL contained
    /// expandable `{set}` or `[range]` expressions).
    pub fn inuse(&self) -> bool {
        !self.patterns.is_empty()
    }
}

/// Checks if the content starting at `input` (after an opening `[`) looks like
/// an IPv6 literal address, which should be skipped by the glob parser.
///
/// Heuristic: if the bracket-enclosed content contains 2+ colons and no
/// hyphens, it's treated as an IPv6 literal.
fn peek_ipv6(input: &str) -> bool {
    // Find the closing bracket
    if let Some(close_pos) = input.find(']') {
        let content = &input[..close_pos];
        let colon_count = content.chars().filter(|&c| c == ':').count();
        let has_hyphen = content.contains('-');
        // IPv6 addresses have multiple colons and no hyphens
        // Ranges have exactly one hyphen and typically 0-1 colons
        colon_count >= 2 && !has_hyphen
    } else {
        // No closing bracket — not IPv6, not a valid range either
        false
    }
}

/// Parses a `{item1,item2,...}` set expression.
///
/// `input` should point to the character immediately after the opening `{`.
/// Returns the parsed `GlobPattern::Set` and the remaining unparsed input
/// (after the closing `}`).
fn glob_set(input: &str, glob_index: usize, pos_offset: usize) -> Result<(GlobPattern, &str)> {
    let mut elements: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = input.char_indices();
    let end_pos: usize;

    loop {
        match chars.next() {
            None => {
                // Reached end of string without finding closing brace
                bail!(
                    "globbing error: unmatched brace at column {}",
                    pos_offset
                );
            }
            Some((idx, '\\')) => {
                // Escape: next char is literal
                if let Some((_next_idx, next_ch)) = chars.next() {
                    current.push(next_ch);
                } else {
                    bail!(
                        "globbing error: trailing backslash at column {}",
                        pos_offset + idx + 1
                    );
                }
            }
            Some((idx, '{')) | Some((idx, '[')) => {
                // Nested braces/brackets are not allowed
                bail!(
                    "globbing error: nested braces/brackets not supported at column {}",
                    pos_offset + idx + 1
                );
            }
            Some((_idx, ',')) => {
                // Element separator — push current element, start new one
                elements.push(current);
                current = String::new();
                if elements.len() > MAX_SET_ELEMENTS {
                    bail!(
                        "globbing error: too many set elements (max {})",
                        MAX_SET_ELEMENTS
                    );
                }
            }
            Some((idx, '}')) => {
                // Closing brace — push final element
                elements.push(current);
                end_pos = idx;
                break;
            }
            Some((_idx, ch)) => {
                current.push(ch);
            }
        }
    }

    // Reject empty sets (just "{}")
    if elements.len() == 1 && elements[0].is_empty() {
        bail!(
            "globbing error: empty brace expression at column {}",
            pos_offset
        );
    }

    let remaining = &input[end_pos + 1..];
    Ok((
        GlobPattern::Set {
            elements,
            glob_index,
        },
        remaining,
    ))
}

/// Parses a `[min-max]` or `[min-max:step]` range expression.
///
/// `input` should point to the character immediately after the opening `[`.
/// Supports both numeric ranges (e.g., `[1-10]`, `[01-99:2]`) and alphabetic
/// character ranges (e.g., `[a-z]`, `[a-z:2]`).
///
/// Returns the parsed `GlobPattern` variant and the remaining unparsed input
/// (after the closing `]`).
fn glob_range(input: &str, glob_index: usize, pos_offset: usize) -> Result<(GlobPattern, &str)> {
    // Find the closing bracket
    let close_pos = input
        .find(']')
        .ok_or_else(|| anyhow!("globbing error: unmatched bracket at column {}", pos_offset))?;

    let content = &input[..close_pos];
    let remaining = &input[close_pos + 1..];

    // Find the hyphen separator (the range delimiter)
    // We need to handle negative numbers: if content starts with '-', it's a negative min
    let hyphen_pos = find_range_separator(content)?;

    let min_str = &content[..hyphen_pos];
    let after_hyphen = &content[hyphen_pos + 1..];

    // Check for optional step after ':'
    let (max_str, step_str) = if let Some(colon_pos) = after_hyphen.find(':') {
        (&after_hyphen[..colon_pos], Some(&after_hyphen[colon_pos + 1..]))
    } else {
        (after_hyphen, None)
    };

    // Determine if this is a character range or numeric range
    let is_alpha = min_str.len() == 1
        && max_str.len() == 1
        && min_str.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && max_str.chars().next().is_some_and(|c| c.is_ascii_alphabetic());

    if is_alpha {
        parse_char_range(min_str, max_str, step_str, glob_index, pos_offset, remaining)
    } else {
        parse_num_range(min_str, max_str, step_str, glob_index, pos_offset, remaining)
    }
}

/// Finds the position of the range separator hyphen in a bracket range expression.
///
/// Handles the case where the range starts with a negative number (leading '-'),
/// which must not be confused with the separator.
fn find_range_separator(content: &str) -> Result<usize> {
    let bytes = content.as_bytes();
    // If content starts with '-', skip it (negative min)
    let start = if !bytes.is_empty() && bytes[0] == b'-' { 1 } else { 0 };

    // Find the next '-' after start
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if b == b'-' {
            return Ok(i);
        }
    }

    bail!("globbing error: bad range specification (missing '-' separator)")
}

/// Parses an alphabetic character range like `[a-z]` or `[a-z:2]`.
fn parse_char_range<'a>(
    min_str: &str,
    max_str: &str,
    step_str: Option<&str>,
    glob_index: usize,
    pos_offset: usize,
    remaining: &'a str,
) -> Result<(GlobPattern, &'a str)> {
    let min_ch = min_str
        .chars()
        .next()
        .ok_or_else(|| anyhow!("globbing error: empty range min at column {}", pos_offset))?;
    let max_ch = max_str
        .chars()
        .next()
        .ok_or_else(|| anyhow!("globbing error: empty range max at column {}", pos_offset))?;

    // Validate both are in the same case class (both uppercase or both lowercase)
    if min_ch.is_ascii_uppercase() != max_ch.is_ascii_uppercase() {
        bail!(
            "globbing error: mixed case character range '[{}-{}]' at column {}",
            min_ch,
            max_ch,
            pos_offset
        );
    }

    let step: i64 = if let Some(s) = step_str {
        s.parse::<i64>().map_err(|_| {
            anyhow!(
                "globbing error: bad step value '{}' at column {}",
                s,
                pos_offset
            )
        })?
    } else {
        1
    };

    if step <= 0 {
        bail!(
            "globbing error: step must be positive at column {}",
            pos_offset
        );
    }

    // Determine direction: if min > max, we go backwards but step is still used as magnitude
    let (actual_min, actual_max) = if min_ch <= max_ch {
        (min_ch, max_ch)
    } else {
        (max_ch, min_ch)
    };

    Ok((
        GlobPattern::CharRange {
            min: actual_min,
            max: actual_max,
            step,
            glob_index,
        },
        remaining,
    ))
}

/// Parses a numeric range like `[1-10]`, `[01-99]`, or `[1-100:2]`.
fn parse_num_range<'a>(
    min_str: &str,
    max_str: &str,
    step_str: Option<&str>,
    glob_index: usize,
    pos_offset: usize,
    remaining: &'a str,
) -> Result<(GlobPattern, &'a str)> {
    let min_val: i64 = min_str.parse().map_err(|_| {
        anyhow!(
            "globbing error: bad range value '{}' at column {}",
            min_str,
            pos_offset
        )
    })?;

    let max_val: i64 = max_str.parse().map_err(|_| {
        anyhow!(
            "globbing error: bad range value '{}' at column {}",
            max_str,
            pos_offset
        )
    })?;

    let step: i64 = if let Some(s) = step_str {
        s.parse::<i64>().map_err(|_| {
            anyhow!(
                "globbing error: bad step value '{}' at column {}",
                s,
                pos_offset
            )
        })?
    } else {
        1
    };

    if step <= 0 {
        bail!(
            "globbing error: step must be positive at column {}",
            pos_offset
        );
    }

    // Determine zero-padding width from the min_str representation
    // E.g., "01" has pad_width=2, "001" has pad_width=3, "1" has pad_width=0
    let pad_width = detect_pad_width(min_str, max_str);

    // Ensure min <= max (swap if needed, matching C behavior)
    let (actual_min, actual_max) = if min_val <= max_val {
        (min_val, max_val)
    } else {
        (max_val, min_val)
    };

    Ok((
        GlobPattern::NumRange {
            min: actual_min,
            max: actual_max,
            step,
            pad_width,
            glob_index,
        },
        remaining,
    ))
}

/// Detects zero-padding width from the string representation of numeric range values.
///
/// If either `min_str` or `max_str` has a leading zero (and the value is not just "0"),
/// the width of the longer representation is used as the padding width.
fn detect_pad_width(min_str: &str, max_str: &str) -> usize {
    let min_has_leading_zero = has_leading_zero(min_str);
    let max_has_leading_zero = has_leading_zero(max_str);

    if min_has_leading_zero || max_has_leading_zero {
        // Use the longer of the two representations as pad width
        std::cmp::max(min_str.len(), max_str.len())
    } else {
        0
    }
}

/// Returns true if a numeric string has a meaningful leading zero.
///
/// "0" itself is not considered as having a leading zero.
/// "01", "001", etc. have leading zeros.
/// Negative numbers: "-01" has leading zero (checking after the minus sign).
fn has_leading_zero(s: &str) -> bool {
    let trimmed = s.strip_prefix('-').unwrap_or(s);
    trimmed.len() > 1 && trimmed.starts_with('0')
}

/// Safely multiplies two i64 values, returning an error on overflow.
///
/// This matches the C `multiply()` function that prevents integer overflow
/// in the total URL count computation.
fn multiply(a: i64, b: i64) -> Result<i64> {
    a.checked_mul(b)
        .ok_or_else(|| anyhow!("globbing error: range overflow"))
}

/// Internal main parsing function.
///
/// Scans the URL string and splits it into a sequence of `GlobPattern` segments:
/// - Literal text becomes `Fixed` patterns
/// - `{...}` becomes `Set` patterns via `glob_set`
/// - `[...]` becomes `NumRange` or `CharRange` patterns via `glob_range`
/// - IPv6 literals in brackets are preserved as literal text
/// - Backslash escapes `\{`, `\}`, `\[`, `\]`
fn glob_parse(url: &str) -> Result<(Vec<GlobPattern>, i64, usize)> {
    let mut patterns: Vec<GlobPattern> = Vec::new();
    let mut total_count: i64 = 1;
    let mut glob_count: usize = 0;
    let mut remaining = url;
    let mut literal_buf = String::new();
    let full_len = url.len();

    while !remaining.is_empty() {
        // Track our position in the original URL for error messages (1-based)
        let current_pos = full_len - remaining.len() + 1;

        let first_byte = remaining.as_bytes()[0];

        match first_byte {
            b'\\' => {
                // Escape character: next char is literal
                if remaining.len() > 1 {
                    let next_ch = remaining.as_bytes()[1] as char;
                    match next_ch {
                        '{' | '}' | '[' | ']' => {
                            literal_buf.push(next_ch);
                            remaining = &remaining[2..];
                        }
                        _ => {
                            // Pass the backslash and next char through literally
                            literal_buf.push('\\');
                            literal_buf.push(next_ch);
                            remaining = &remaining[2..];
                        }
                    }
                } else {
                    // Trailing backslash — include it literally
                    literal_buf.push('\\');
                    remaining = &remaining[1..];
                }
            }
            b'{' => {
                // Flush any accumulated literal text as a Fixed pattern
                if !literal_buf.is_empty() {
                    if patterns.len() >= MAX_GLOB_PATTERNS {
                        bail!(
                            "globbing error: too many patterns (max {})",
                            MAX_GLOB_PATTERNS
                        );
                    }
                    patterns.push(GlobPattern::Fixed(literal_buf.clone()));
                    literal_buf.clear();
                }

                // Parse the set expression
                if patterns.len() >= MAX_GLOB_PATTERNS {
                    bail!(
                        "globbing error: too many patterns (max {})",
                        MAX_GLOB_PATTERNS
                    );
                }
                let (pattern, rest) = glob_set(&remaining[1..], glob_count, current_pos)?;
                let count = pattern.count();
                total_count = multiply(total_count, count)?;
                patterns.push(pattern);
                glob_count += 1;
                remaining = rest;
            }
            b'[' => {
                // Check if this is an IPv6 literal — if so, treat as literal text
                let bracket_content = &remaining[1..];
                if peek_ipv6(bracket_content) {
                    // IPv6 literal: include the entire `[...]` as literal text
                    if let Some(close_pos) = bracket_content.find(']') {
                        literal_buf.push('[');
                        literal_buf.push_str(&bracket_content[..close_pos]);
                        literal_buf.push(']');
                        remaining = &bracket_content[close_pos + 1..];
                    } else {
                        // No closing bracket — just push '[' and advance
                        literal_buf.push('[');
                        remaining = bracket_content;
                    }
                } else {
                    // Flush any accumulated literal text as a Fixed pattern
                    if !literal_buf.is_empty() {
                        if patterns.len() >= MAX_GLOB_PATTERNS {
                            bail!(
                                "globbing error: too many patterns (max {})",
                                MAX_GLOB_PATTERNS
                            );
                        }
                        patterns.push(GlobPattern::Fixed(literal_buf.clone()));
                        literal_buf.clear();
                    }

                    // Parse the range expression
                    if patterns.len() >= MAX_GLOB_PATTERNS {
                        bail!(
                            "globbing error: too many patterns (max {})",
                            MAX_GLOB_PATTERNS
                        );
                    }
                    let (pattern, rest) = glob_range(bracket_content, glob_count, current_pos)?;
                    let count = pattern.count();
                    total_count = multiply(total_count, count)?;
                    patterns.push(pattern);
                    glob_count += 1;
                    remaining = rest;
                }
            }
            b'}' => {
                bail!(
                    "globbing error: unmatched closing brace at column {}",
                    current_pos
                );
            }
            b']' => {
                bail!(
                    "globbing error: unmatched closing bracket at column {}",
                    current_pos
                );
            }
            _ => {
                // Regular character — add to literal buffer
                literal_buf.push(first_byte as char);
                remaining = &remaining[1..];
            }
        }
    }

    // Flush any remaining literal text
    if !literal_buf.is_empty() {
        if patterns.len() >= MAX_GLOB_PATTERNS {
            bail!(
                "globbing error: too many patterns (max {})",
                MAX_GLOB_PATTERNS
            );
        }
        patterns.push(GlobPattern::Fixed(literal_buf));
    }

    Ok((patterns, total_count, glob_count))
}

/// Parses a URL template containing glob patterns and returns a `URLGlob`
/// ready for iteration, along with the total number of URL combinations.
///
/// # Arguments
///
/// * `url` — The URL template string, possibly containing `{set}` and `[range]`
///   glob expressions.
///
/// # Returns
///
/// A tuple of `(URLGlob, total_count)` where `total_count` is the product
/// of all pattern expansion counts (i.e., the total number of URLs that
/// `glob_next_url` will produce).
///
/// # Errors
///
/// Returns an error if:
/// - The URL contains malformed glob expressions (unmatched braces/brackets)
/// - A numeric range has invalid bounds or step
/// - The total number of patterns exceeds 255
/// - A set has more than 100,000 elements
/// - The total count overflows `i64`
///
/// # Examples
///
/// ```ignore
/// let (glob, count) = glob_url("http://example.com/file[1-3].txt")?;
/// assert_eq!(count, 3);
/// ```
pub fn glob_url(url: &str) -> Result<(URLGlob, i64)> {
    let (patterns, total_count, glob_count) = glob_parse(url)?;

    let indices = vec![0usize; patterns.len()];

    let glob = URLGlob {
        patterns,
        indices,
        total_count,
        glob_count,
        been_here: false,
    };

    Ok((glob, total_count))
}

/// Returns the next expanded URL from a `URLGlob`, or `None` when all
/// combinations are exhausted.
///
/// This is a convenience wrapper around `URLGlob::next_url()`.
pub fn glob_next_url(glob: &mut URLGlob) -> Option<String> {
    glob.next_url()
}

/// Expands `#N` placeholders in `filename` with values from the current
/// glob iteration state.
///
/// `#1` refers to the first non-fixed (expandable) pattern, `#2` to the
/// second, etc. A lone `#` without a following number is passed through
/// literally. Multiple digits are supported (e.g., `#10`).
///
/// This function is used for output filename generation with the `-o` option
/// in conjunction with URL globbing.
pub fn glob_match_url(glob: &URLGlob, filename: &str) -> String {
    // Build a list of values for non-fixed patterns: glob_index 0 -> current_value
    let mut glob_values: Vec<String> = Vec::with_capacity(glob.glob_count);

    for (i, pat) in glob.patterns.iter().enumerate() {
        if pat.is_glob() {
            glob_values.push(pat.current_value(glob.indices[i]));
        }
    }

    let mut result = String::with_capacity(filename.len());
    let bytes = filename.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'#' {
            // Check if followed by one or more digits
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }

            if end > start {
                // Parse the number (1-based index)
                if let Ok(num) = std::str::from_utf8(&bytes[start..end])
                    .unwrap_or("0")
                    .parse::<usize>()
                {
                    if num >= 1 && num <= glob_values.len() {
                        // Replace with the glob value (1-based to 0-based)
                        result.push_str(&glob_values[num - 1]);
                    } else {
                        // Out of range — pass through literally
                        result.push('#');
                        result.push_str(
                            std::str::from_utf8(&bytes[start..end]).unwrap_or(""),
                        );
                    }
                } else {
                    // Parse failed — pass through literally
                    result.push('#');
                    result.push_str(
                        std::str::from_utf8(&bytes[start..end]).unwrap_or(""),
                    );
                }
                i = end;
            } else {
                // '#' not followed by digit — pass through literally
                result.push('#');
                i += 1;
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    result
}

/// Returns `true` if the `URLGlob` has any parsed patterns (i.e., the URL
/// contained expandable expressions).
///
/// This is a convenience wrapper around `URLGlob::inuse()`.
pub fn glob_inuse(glob: &URLGlob) -> bool {
    glob.inuse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_expansion() {
        let (mut glob, count) = glob_url("http://example.com/{a,b,c}/page").unwrap();
        assert_eq!(count, 3);
        assert_eq!(glob.next_url().unwrap(), "http://example.com/a/page");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/b/page");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/c/page");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_numeric_range() {
        let (mut glob, count) = glob_url("http://example.com/file[1-3].txt").unwrap();
        assert_eq!(count, 3);
        assert_eq!(glob.next_url().unwrap(), "http://example.com/file1.txt");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/file2.txt");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/file3.txt");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_char_range() {
        let (mut glob, count) = glob_url("http://example.com/[a-c].html").unwrap();
        assert_eq!(count, 3);
        assert_eq!(glob.next_url().unwrap(), "http://example.com/a.html");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/b.html");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/c.html");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_padded_numeric_range() {
        let (mut glob, count) = glob_url("http://example.com/img[001-003].png").unwrap();
        assert_eq!(count, 3);
        assert_eq!(glob.next_url().unwrap(), "http://example.com/img001.png");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/img002.png");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/img003.png");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_stepped_range() {
        let (mut glob, count) = glob_url("http://example.com/p[1-5:2].html").unwrap();
        assert_eq!(count, 3);
        assert_eq!(glob.next_url().unwrap(), "http://example.com/p1.html");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/p3.html");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/p5.html");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_multiple_patterns() {
        let (mut glob, count) = glob_url("http://{a,b}.example.com/[1-2].txt").unwrap();
        assert_eq!(count, 4);
        assert_eq!(glob.next_url().unwrap(), "http://a.example.com/1.txt");
        assert_eq!(glob.next_url().unwrap(), "http://a.example.com/2.txt");
        assert_eq!(glob.next_url().unwrap(), "http://b.example.com/1.txt");
        assert_eq!(glob.next_url().unwrap(), "http://b.example.com/2.txt");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_ipv6_literal_skip() {
        let (mut glob, count) = glob_url("http://[::1]/path").unwrap();
        assert_eq!(count, 1);
        assert_eq!(glob.next_url().unwrap(), "http://[::1]/path");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_ipv6_with_port() {
        let (mut glob, count) = glob_url("http://[fe80::1%25eth0]:8080/").unwrap();
        assert_eq!(count, 1);
        assert_eq!(glob.next_url().unwrap(), "http://[fe80::1%25eth0]:8080/");
    }

    #[test]
    fn test_escaped_braces() {
        let (mut glob, count) = glob_url("http://example.com/\\{literal\\}").unwrap();
        assert_eq!(count, 1);
        assert_eq!(glob.next_url().unwrap(), "http://example.com/{literal}");
    }

    #[test]
    fn test_glob_match_url_basic() {
        let (glob, _) = glob_url("http://{host1,host2}/[1-2].txt").unwrap();
        let result = glob_match_url(&glob, "output_#1_#2.txt");
        assert_eq!(result, "output_host1_1.txt");
    }

    #[test]
    fn test_glob_match_url_no_hash() {
        let (glob, _) = glob_url("http://example.com/{a,b}/page").unwrap();
        let result = glob_match_url(&glob, "output.txt");
        assert_eq!(result, "output.txt");
    }

    #[test]
    fn test_glob_inuse_true() {
        let (glob, _) = glob_url("http://example.com/{a,b}/page").unwrap();
        assert!(glob_inuse(&glob));
        assert!(glob.inuse());
    }

    #[test]
    fn test_no_glob_patterns() {
        let (glob, count) = glob_url("http://example.com/simple").unwrap();
        assert_eq!(count, 1);
        assert!(glob.inuse());
    }

    #[test]
    fn test_amount() {
        let (glob, count) = glob_url("http://example.com/{a,b,c}/[1-5]").unwrap();
        assert_eq!(count, 15);
        assert_eq!(glob.amount(), 15);
    }

    #[test]
    fn test_unmatched_brace_error() {
        assert!(glob_url("http://example.com/{a,b").is_err());
    }

    #[test]
    fn test_unmatched_bracket_error() {
        assert!(glob_url("http://example.com/[1-10").is_err());
    }

    #[test]
    fn test_unmatched_close_brace_error() {
        assert!(glob_url("http://example.com/a}").is_err());
    }

    #[test]
    fn test_unmatched_close_bracket_error() {
        assert!(glob_url("http://example.com/a]").is_err());
    }

    #[test]
    fn test_empty_brace_error() {
        assert!(glob_url("http://example.com/{}").is_err());
    }

    #[test]
    fn test_peek_ipv6_true() {
        assert!(peek_ipv6("::1]"));
        assert!(peek_ipv6("fe80::1]:8080"));
        assert!(peek_ipv6("2001:db8::1]"));
    }

    #[test]
    fn test_peek_ipv6_false() {
        assert!(!peek_ipv6("1-10]"));
        assert!(!peek_ipv6("a-z]"));
        assert!(!peek_ipv6("01-99:2]"));
    }

    #[test]
    fn test_hash_literal_passthrough() {
        let (glob, _) = glob_url("http://example.com/{a,b}").unwrap();
        let result = glob_match_url(&glob, "output#.txt");
        assert_eq!(result, "output#.txt");
    }

    #[test]
    fn test_hash_out_of_range() {
        let (glob, _) = glob_url("http://example.com/{a,b}").unwrap();
        let result = glob_match_url(&glob, "output_#5.txt");
        assert_eq!(result, "output_#5.txt");
    }

    #[test]
    fn test_single_element_set() {
        let (mut glob, count) = glob_url("http://example.com/{only}").unwrap();
        assert_eq!(count, 1);
        assert_eq!(glob.next_url().unwrap(), "http://example.com/only");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_char_range_step() {
        let (mut glob, count) = glob_url("http://example.com/[a-e:2]").unwrap();
        assert_eq!(count, 3);
        assert_eq!(glob.next_url().unwrap(), "http://example.com/a");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/c");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/e");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_padded_stepped_range() {
        let (mut glob, count) = glob_url("http://example.com/[001-005:2]").unwrap();
        assert_eq!(count, 3);
        assert_eq!(glob.next_url().unwrap(), "http://example.com/001");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/003");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/005");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_escape_in_set() {
        let (mut glob, count) = glob_url("http://example.com/{a\\,b,c}").unwrap();
        assert_eq!(count, 2);
        assert_eq!(glob.next_url().unwrap(), "http://example.com/a,b");
        assert_eq!(glob.next_url().unwrap(), "http://example.com/c");
        assert!(glob.next_url().is_none());
    }

    #[test]
    fn test_new_urlglob() {
        let glob = URLGlob::new();
        assert_eq!(glob.amount(), 1);
        assert!(!glob.inuse());
    }

    #[test]
    fn test_detect_pad_width() {
        assert_eq!(detect_pad_width("01", "99"), 2);
        assert_eq!(detect_pad_width("001", "100"), 3);
        assert_eq!(detect_pad_width("1", "10"), 0);
        assert_eq!(detect_pad_width("0", "9"), 0);
    }

    #[test]
    fn test_has_leading_zero() {
        assert!(has_leading_zero("01"));
        assert!(has_leading_zero("001"));
        assert!(!has_leading_zero("0"));
        assert!(!has_leading_zero("1"));
        assert!(!has_leading_zero("10"));
        assert!(has_leading_zero("-01"));
    }

    #[test]
    fn test_multiply_overflow() {
        assert!(multiply(i64::MAX, 2).is_err());
        assert_eq!(multiply(100, 200).unwrap(), 20000);
    }

    #[test]
    fn test_match_url_after_iteration() {
        let (mut glob, _) = glob_url("http://{host1,host2}/[1-2].txt").unwrap();
        // Consume first URL
        let _ = glob.next_url().unwrap();
        // Consume second URL — now indices should be [0, 1] for the glob patterns
        let _ = glob.next_url().unwrap();
        // At this point, #1="host1", #2="2"
        let result = glob.match_url("file_#1_#2.txt");
        assert_eq!(result, "file_host1_2.txt");
    }

    #[test]
    fn test_three_patterns() {
        let (mut glob, count) = glob_url("{a,b}[1-2]{x,y}").unwrap();
        assert_eq!(count, 8);
        assert_eq!(glob.next_url().unwrap(), "a1x");
        assert_eq!(glob.next_url().unwrap(), "a1y");
        assert_eq!(glob.next_url().unwrap(), "a2x");
        assert_eq!(glob.next_url().unwrap(), "a2y");
        assert_eq!(glob.next_url().unwrap(), "b1x");
        assert_eq!(glob.next_url().unwrap(), "b1y");
        assert_eq!(glob.next_url().unwrap(), "b2x");
        assert_eq!(glob.next_url().unwrap(), "b2y");
        assert!(glob.next_url().is_none());
    }
}
