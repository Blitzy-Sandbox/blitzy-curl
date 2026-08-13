// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Two-way agreement between the oracle's symbol register and its error
//! documentation.
//!
//! The oracle ships a helper that compares the same two files and prints what
//! it finds, and its descriptor declares no expectation over that output, so a
//! mismatch is reported and the case still passes. This module is the enforcing
//! replacement: it applies the helper's own selection rules and fails the run
//! when either direction is non-empty.
//!
//! Selection mirrors the helper exactly rather than improving on it. A register
//! row is a live error code when its first field names one and its second field
//! is a version; a row whose third field starts with a version is skipped,
//! which the helper reaches for as removal and which at the pinned tag is the
//! deprecation column. A documentation heading is a live error code when the
//! first word after the heading marker names one and that word does not carry
//! the obsolete marker.
//!
//! Rationale is `DL-0280`.

use std::collections::BTreeSet;

use curl_audit::fs::Files;
use curl_audit::report::Report;

/// Symbol register the comparison reads.
pub const REGISTER: &str = "original/docs/libcurl/symbols-in-versions";

/// Error documentation the comparison reads.
pub const DOCUMENTATION: &str = "original/docs/libcurl/libcurl-errors.md";

/// Prefixes an error-code name carries.
const FAMILIES: [&str; 2] = ["CURLE_", "CURLM_"];

/// Marker that excludes a documentation heading.
const OBSOLETE: &str = "OBSOLETE";

/// Heading marker a documented code carries.
const HEADING: &str = "## ";

/// What the two files say, and where they disagree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Agreement {
    /// Live error codes the register carries.
    pub registered: BTreeSet<String>,
    /// Error codes the documentation carries a heading for.
    pub documented: BTreeSet<String>,
    /// Register rows skipped because a later field carries a version.
    pub superseded: usize,
    /// Headings skipped because the name carries the obsolete marker.
    pub obsolete: usize,
    /// Registered codes with no heading.
    pub undocumented: Vec<String>,
    /// Documented codes with no register row.
    pub unregistered: Vec<String>,
}

/// Whether `name` belongs to one of the two error families.
fn is_error_code(name: &str) -> bool {
    FAMILIES
        .iter()
        .any(|family| name.starts_with(family) && name.len() > family.len())
}

/// Whether `field` is a version: a non-empty run of digits and dots.
fn is_version(field: &str) -> bool {
    !field.is_empty() && field.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// The live error code a register row names, and whether it was superseded.
///
/// Returns `None` for any line the helper's pattern does not match, `Some(None)`
/// for a row the helper skips, and `Some(Some(name))` for a live code.
fn register_row(line: &str) -> Option<Option<&str>> {
    let line = line.trim_end_matches('\r');
    let mut fields = line.split([' ', '\t']).filter(|field| !field.is_empty());
    let name = fields.next()?;
    if !is_error_code(name) || !line.starts_with(name) {
        return None;
    }
    if !is_version(fields.next()?) {
        return None;
    }
    match fields.next() {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit() || c == '.') => Some(None),
        _ => Some(Some(name)),
    }
}

/// The error code a documentation heading names, and whether it is obsolete.
///
/// Returns `None` when the line is not a heading naming an error code,
/// `Some(None)` for an obsolete heading and `Some(Some(name))` otherwise.
fn documentation_heading(line: &str) -> Option<Option<&str>> {
    let rest = line.trim_end_matches('\r').strip_prefix(HEADING)?;
    let name = rest.split(' ').next()?;
    if !is_error_code(name) {
        return None;
    }
    if name.contains(OBSOLETE) {
        return Some(None);
    }
    Some(Some(name))
}

/// Reads both files and compares them in both directions.
#[must_use]
pub fn agreement(files: &dyn Files) -> Agreement {
    let mut found = Agreement::default();
    if let Some(body) = files.read(REGISTER) {
        for line in body.lines() {
            match register_row(line) {
                Some(Some(name)) => {
                    found.registered.insert(name.to_owned());
                }
                Some(None) => found.superseded += 1,
                None => {}
            }
        }
    }
    if let Some(body) = files.read(DOCUMENTATION) {
        for line in body.lines() {
            match documentation_heading(line) {
                Some(Some(name)) => {
                    found.documented.insert(name.to_owned());
                }
                Some(None) => found.obsolete += 1,
                None => {}
            }
        }
    }
    found.undocumented = found
        .registered
        .difference(&found.documented)
        .cloned()
        .collect();
    found.unregistered = found
        .documented
        .difference(&found.registered)
        .cloned()
        .collect();
    found
}

/// Compares the two files and records a check per gate.
pub fn audit(files: &dyn Files, report: &mut Report) -> Agreement {
    let found = agreement(files);

    let absent: Vec<&str> = [REGISTER, DOCUMENTATION]
        .into_iter()
        .filter(|path| !files.exists(path))
        .collect();
    report.assert(
        absent.is_empty(),
        "errordocs/sources-present",
        if absent.is_empty() {
            format!("{REGISTER} and {DOCUMENTATION} both read")
        } else {
            format!("absent: {}", absent.join(", "))
        },
    );

    report.assert(
        !found.registered.is_empty(),
        "errordocs/register-enumerated",
        format!(
            "{} live error code(s), {} row(s) skipped as superseded",
            found.registered.len(),
            found.superseded
        ),
    );

    report.assert(
        !found.documented.is_empty(),
        "errordocs/documentation-enumerated",
        format!(
            "{} documented code(s), {} heading(s) skipped as obsolete",
            found.documented.len(),
            found.obsolete
        ),
    );

    report.assert(
        found.undocumented.is_empty(),
        "errordocs/every-registered-code-documented",
        if found.undocumented.is_empty() {
            format!(
                "every one of {} registered code(s) has a heading",
                found.registered.len()
            )
        } else {
            format!(
                "{} without a heading: {}",
                found.undocumented.len(),
                found.undocumented.join(", ")
            )
        },
    );

    report.assert(
        found.unregistered.is_empty(),
        "errordocs/every-documented-code-registered",
        if found.unregistered.is_empty() {
            format!(
                "every one of {} documented code(s) has a register row",
                found.documented.len()
            )
        } else {
            format!(
                "{} without a register row: {}",
                found.unregistered.len(),
                found.unregistered.join(", ")
            )
        },
    );

    found
}

#[cfg(test)]
mod tests {
    use curl_audit::fs::MapFiles;
    use curl_audit::report::Report;

    use super::{Agreement, DOCUMENTATION, REGISTER, agreement, audit};

    const REGISTER_BODY: &str = "\
 Name                           Introduced  Deprecated  Last
CURL_BLOB_COPY                  7.71.0
CURLE_OK                        7.1
CURLM_OK                        7.9.6
CURLE_ALREADY_COMPLETE          7.7.2         7.8
CURLSSLSET_OK                   7.56.0
";

    const DOCUMENTATION_BODY: &str = "\
# libcurl-errors
## CURLE_OK (0)
All fine.
## CURLM_OK (0)
Fine.
## CURLE_OBSOLETE10 (10)
Not used.
### CURLE_NOT_A_HEADING
";

    fn tree(register: &str, documentation: &str) -> MapFiles {
        MapFiles::new()
            .with(REGISTER, register)
            .with(DOCUMENTATION, documentation)
    }

    fn resolved(register: &str, documentation: &str) -> (Agreement, String) {
        let mut report = Report::new("test");
        let found = audit(&tree(register, documentation), &mut report);
        (found, report.render())
    }

    #[test]
    fn selection_mirrors_the_helper_the_oracle_ships() {
        let found = agreement(&tree(REGISTER_BODY, DOCUMENTATION_BODY));
        assert_eq!(
            found
                .registered
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["CURLE_OK", "CURLM_OK"],
            "only the two live error codes are registered"
        );
        assert_eq!(found.superseded, 1, "the deprecated row is skipped");
        assert_eq!(
            found
                .documented
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["CURLE_OK", "CURLM_OK"],
            "the obsolete heading and the deeper heading are not documented codes"
        );
        assert_eq!(found.obsolete, 1, "the obsolete heading is counted");
        assert!(found.undocumented.is_empty() && found.unregistered.is_empty());
    }

    #[test]
    fn an_agreeing_pair_passes_every_gate() {
        let (found, rendered) = resolved(REGISTER_BODY, DOCUMENTATION_BODY);
        assert!(
            rendered.contains("PASS errordocs/every-registered-code-documented"),
            "{rendered}"
        );
        assert!(
            rendered.contains("PASS errordocs/every-documented-code-registered"),
            "{rendered}"
        );
        assert!(!rendered.contains("FAIL"), "{rendered}");
        assert_eq!(found.registered, found.documented);
    }

    #[test]
    fn a_registered_code_with_no_heading_fails_the_forward_direction() {
        let register = format!("{REGISTER_BODY}CURLE_GONE_MISSING             7.90.0\n");
        let (found, rendered) = resolved(&register, DOCUMENTATION_BODY);
        assert_eq!(found.undocumented, vec!["CURLE_GONE_MISSING".to_owned()]);
        assert!(
            rendered.contains("FAIL errordocs/every-registered-code-documented"),
            "{rendered}"
        );
        assert!(
            rendered.contains("PASS errordocs/every-documented-code-registered"),
            "{rendered}"
        );
    }

    #[test]
    fn a_documented_code_with_no_register_row_fails_the_reverse_direction() {
        let documentation = format!("{DOCUMENTATION_BODY}## CURLE_INVENTED (99)\n");
        let (found, rendered) = resolved(REGISTER_BODY, &documentation);
        assert_eq!(found.unregistered, vec!["CURLE_INVENTED".to_owned()]);
        assert!(
            rendered.contains("FAIL errordocs/every-documented-code-registered"),
            "{rendered}"
        );
        assert!(
            rendered.contains("PASS errordocs/every-registered-code-documented"),
            "{rendered}"
        );
    }

    #[test]
    fn absent_or_empty_sources_fail_rather_than_agreeing_vacuously() {
        let mut report = Report::new("test");
        let found = audit(&MapFiles::new(), &mut report);
        let rendered = report.render();
        assert!(found.registered.is_empty() && found.documented.is_empty());
        assert!(
            rendered.contains("FAIL errordocs/sources-present"),
            "{rendered}"
        );
        assert!(
            rendered.contains("FAIL errordocs/register-enumerated"),
            "{rendered}"
        );
        assert!(
            rendered.contains("FAIL errordocs/documentation-enumerated"),
            "{rendered}"
        );
    }
}
