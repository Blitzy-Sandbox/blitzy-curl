// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Check outcomes and the rendered report every audit returns.

use std::fmt::Write as _;

/// Outcome of a single check.
///
/// There are two outcomes and no third. A check that cannot observe the thing
/// it asserts reports [`Status::Fail`] rather than reporting success, which is
/// what keeps an empty graph or a zero match from reading as a pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// The asserted condition holds.
    Pass,
    /// The asserted condition does not hold, or could not be observed.
    Fail,
}

impl Status {
    /// The four-character tag this status renders as.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }
}

/// One named assertion and what was observed for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Check {
    /// Stable identifier of the assertion, used in reports and CI logs.
    pub name: String,
    /// Whether the assertion holds.
    pub status: Status,
    /// What was observed: counts, versions, offending paths.
    pub detail: String,
}

/// The ordered set of checks one audit produced.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Name of the audit that produced these checks.
    pub audit: String,
    /// Checks in the order they ran.
    pub checks: Vec<Check>,
}

impl Report {
    /// Starts an empty report for the named audit.
    #[must_use]
    pub fn new(audit: impl Into<String>) -> Self {
        Self {
            audit: audit.into(),
            checks: Vec::new(),
        }
    }

    /// Records a passing check.
    pub fn pass(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status: Status::Pass,
            detail: detail.into(),
        });
    }

    /// Records a failing check.
    pub fn fail(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status: Status::Fail,
            detail: detail.into(),
        });
    }

    /// Records a check whose status is `Pass` when `condition` holds.
    pub fn assert(&mut self, condition: bool, name: impl Into<String>, detail: impl Into<String>) {
        if condition {
            self.pass(name, detail);
        } else {
            self.fail(name, detail);
        }
    }

    /// Appends every check of `other`, keeping order.
    pub fn absorb(&mut self, other: Self) {
        self.checks.extend(other.checks);
    }

    /// Number of failing checks.
    #[must_use]
    pub fn failures(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == Status::Fail)
            .count()
    }

    /// Whether every check passed. An empty report is not a pass.
    #[must_use]
    pub fn passed(&self) -> bool {
        !self.checks.is_empty() && self.failures() == 0
    }

    /// Renders the report as one line per check plus a trailing summary.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "== {} ==", self.audit);
        for check in &self.checks {
            let _ = writeln!(
                out,
                "{} {}: {}",
                check.status.tag(),
                check.name,
                check.detail
            );
        }
        if self.checks.is_empty() {
            let _ = writeln!(out, "FAIL {}: no check ran", self.audit);
        } else {
            let _ = writeln!(
                out,
                "-- {}: {} checks, {} failing",
                self.audit,
                self.checks.len(),
                self.failures()
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{Report, Status};

    #[test]
    fn empty_report_is_not_a_pass() {
        let report = Report::new("empty");
        assert!(!report.passed());
        assert!(report.render().contains("FAIL empty: no check ran"));
    }

    #[test]
    fn failure_count_and_rendering() {
        let mut report = Report::new("demo");
        report.pass("first", "1 observed");
        report.fail("second", "0 observed");
        report.assert(true, "third", "ok");
        assert_eq!(report.failures(), 1);
        assert!(!report.passed());
        let rendered = report.render();
        assert!(rendered.contains("PASS first: 1 observed"));
        assert!(rendered.contains("FAIL second: 0 observed"));
        assert!(rendered.contains("-- demo: 3 checks, 1 failing"));
    }

    #[test]
    fn absorb_keeps_order_and_status() {
        let mut left = Report::new("left");
        left.pass("a", "");
        let mut right = Report::new("right");
        right.fail("b", "");
        left.absorb(right);
        assert_eq!(left.checks.len(), 2);
        assert_eq!(left.checks[1].status, Status::Fail);
        assert_eq!(Status::Pass.tag(), "PASS");
    }
}
