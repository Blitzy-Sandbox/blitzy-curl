// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! The observability contract and the sensitive-flow gate.
//!
//! Two questions are answered mechanically here. The first is what the oracle
//! already provides, because the observability rule instructs implementers to
//! reuse what exists rather than add a parallel facility, and a claim of reuse
//! is only worth as much as the locator behind it - so every declared surface
//! is read at the tag and must still carry the token that names it.
//!
//! The second is where a credential reaches a diagnostic surface. Counting the
//! emitters directly is not enough: the four line protocols do not call the
//! emitter at all, they call an exported wrapper, and a count of direct
//! emissions therefore reports those four files as having no trace surface
//! while every one of their authentication commands is written out. The gate
//! follows the wrapper instead, discovers its call sites, and requires a
//! declaration for each one whose shape is in the declared vocabulary.

use std::collections::{BTreeMap, BTreeSet};

use curl_audit::fs::Files;
use curl_audit::report::Report;
use curl_audit::workspace::{AuditError, AuditResult};
use toml::Value;

use crate::reverse::project_files;

/// A diagnostic surface the oracle already provides.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reused {
    /// Which of the rule's elements it provides.
    pub element: String,
    /// What the surface is.
    pub surface: String,
    /// Oracle path carrying it.
    pub path: String,
    /// Line the token appears on.
    pub line: usize,
    /// Token that must still be there.
    pub evidence: String,
    /// Decision the reuse rests on.
    pub decision: String,
}

/// Something this project adds on top of the reused surfaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Added {
    /// Which of the rule's elements it delivers.
    pub element: String,
    /// What it is.
    pub detail: String,
    /// Where it lives.
    pub at: String,
    /// Whether it is a no-op with no subscriber installed.
    pub inert: bool,
    /// Whether it lives in the verification tree.
    pub in_verification_tree: bool,
    /// Decision it rests on.
    pub decision: String,
}

/// A place the oracle writes a value to a diagnostic surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sink {
    /// Identifier, unique across the inventory.
    pub id: String,
    /// Oracle path.
    pub path: String,
    /// Line the emitter appears on.
    pub line: usize,
    /// Emitter that must still be there.
    pub emitter: String,
    /// Which diagnostic surface it writes to.
    pub kind: String,
    /// What a reader of that surface learns.
    pub discloses: String,
    /// Whether it is reached through an exported wrapper.
    pub shared: bool,
    /// Wrappers that reach it, for a shared sink.
    pub reached_through: Vec<String>,
    /// Verdict the port holds.
    pub verdict: String,
    /// Decision it rests on.
    pub decision: String,
}

/// A call shape that makes a shared-sink call site a disclosure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Shape {
    /// First string literal of the call.
    pub format: String,
    /// Text that must follow that literal, where the format alone is ambiguous.
    pub argument: Option<String>,
    /// Whether the line carries a secret or only names a mechanism.
    pub class: String,
    /// What a reader of the surface learns.
    pub discloses: String,
}

/// A declared consumer of a shared sink, with its frozen call-site count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Caller {
    /// Sink it reaches.
    pub sink: String,
    /// Oracle path of the consumer.
    pub path: String,
    /// Call sites the discovery pass must find.
    pub sites: usize,
    /// Decision it rests on.
    pub decision: String,
}

/// One call site of a shared sink whose shape is in the vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Disclosure {
    /// Sink it reaches.
    pub sink: String,
    /// Oracle path.
    pub path: String,
    /// Line of the call.
    pub line: usize,
    /// Class the shape assigns.
    pub class: String,
    /// Decision it rests on.
    pub decision: String,
}

/// A call site the discovery pass found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Site {
    /// Oracle path.
    pub path: String,
    /// Line of the call.
    pub line: usize,
    /// Class the matched shape assigns, where one matched.
    pub class: Option<String>,
}

/// The whole contract, as declared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Contract {
    /// Surfaces reused from the oracle.
    pub reused: Vec<Reused>,
    /// Elements this project adds.
    pub added: Vec<Added>,
    /// Diagnostic sinks.
    pub sinks: Vec<Sink>,
    /// Disclosure shape vocabulary.
    pub shapes: Vec<Shape>,
    /// Declared consumers of the shared sinks.
    pub callers: Vec<Caller>,
    /// Declared disclosures.
    pub disclosures: Vec<Disclosure>,
    /// Field names added instrumentation may not carry.
    pub sensitive: Vec<String>,
    /// Instrumentation call shapes the field gate scans for.
    pub instrumentation: Vec<String>,
}

/// What the discovery pass observed, for rendering.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Flow {
    /// Every call site of every shared sink's wrappers.
    pub sites: Vec<Site>,
    /// Sites whose shape is in the vocabulary.
    pub matched: usize,
    /// Project-authored Rust files the field gate read.
    pub scanned: usize,
}

fn text<'a>(value: &'a Value, key: &str, at: &str) -> AuditResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::new(format!("{at}: {key} missing")))
}

fn number(value: &Value, key: &str, at: &str) -> AuditResult<usize> {
    value
        .get(key)
        .and_then(Value::as_integer)
        .and_then(|found| usize::try_from(found).ok())
        .ok_or_else(|| AuditError::new(format!("{at}: {key} missing")))
}

fn strings(value: &Value, key: &str, path: &str) -> AuditResult<Vec<String>> {
    let array = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| AuditError::new(format!("{path}: {key} missing")))?;
    let mut found = Vec::new();
    for item in array {
        found.push(
            item.as_str()
                .ok_or_else(|| AuditError::new(format!("{path}: {key} holds a non-string")))?
                .to_owned(),
        );
    }
    if found.is_empty() {
        return Err(AuditError::new(format!("{path}: {key} is empty")));
    }
    Ok(found)
}

fn table<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |array| array.iter().collect())
}

/// The first double-quoted literal of a call, and the text after it.
///
/// Escapes are honoured so a literal containing a quote does not end early.
fn literal(call: &str) -> Option<(String, &str)> {
    let bytes = call.as_bytes();
    let start = call.find('"')?;
    let mut index = start + 1;
    let mut value = String::new();
    while index < bytes.len() {
        match bytes[index] {
            b'\\' if index + 1 < bytes.len() => {
                value.push('\\');
                value.push(bytes[index + 1] as char);
                index += 2;
            }
            b'"' => return Some((value, &call[index + 1..])),
            byte => {
                value.push(byte as char);
                index += 1;
            }
        }
    }
    None
}

/// Accumulates a call that continues past the line it starts on.
fn call_text(lines: &[&str], start: usize) -> String {
    let mut text = lines[start].to_owned();
    let mut index = start + 1;
    while text.matches('(').count() > text.matches(')').count() && index < lines.len() {
        text.push(' ');
        text.push_str(lines[index]);
        index += 1;
    }
    text
}

impl Contract {
    /// Reads the declared contract.
    pub fn load(files: &dyn Files, path: &str) -> AuditResult<Self> {
        let body = files
            .read(path)
            .ok_or_else(|| AuditError::new(format!("{path} is missing")))?;
        let value: Value =
            toml::from_str(&body).map_err(|error| AuditError::new(format!("{path}: {error}")))?;

        let mut reused = Vec::new();
        for entry in table(&value, "reused") {
            let surface = text(entry, "surface", path)?;
            reused.push(Reused {
                element: text(entry, "element", surface)?.to_owned(),
                surface: surface.to_owned(),
                path: text(entry, "path", surface)?.to_owned(),
                line: number(entry, "line", surface)?,
                evidence: text(entry, "evidence", surface)?.to_owned(),
                decision: text(entry, "decision", surface)?.to_owned(),
            });
        }
        if reused.is_empty() {
            return Err(AuditError::new(format!("{path}: no reused surface")));
        }

        let mut added = Vec::new();
        for entry in table(&value, "added") {
            let element = text(entry, "element", path)?;
            added.push(Added {
                element: element.to_owned(),
                detail: text(entry, "detail", element)?.to_owned(),
                at: text(entry, "at", element)?.to_owned(),
                inert: entry
                    .get("inert-without-subscriber")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        AuditError::new(format!("{element}: inert-without-subscriber missing"))
                    })?,
                in_verification_tree: entry
                    .get("in-verification-tree")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        AuditError::new(format!("{element}: in-verification-tree missing"))
                    })?,
                decision: text(entry, "decision", element)?.to_owned(),
            });
        }
        if added.is_empty() {
            return Err(AuditError::new(format!("{path}: no added element")));
        }

        let mut sinks = Vec::new();
        for entry in table(&value, "sink") {
            let id = text(entry, "id", path)?;
            let shared = entry
                .get("shared")
                .and_then(Value::as_bool)
                .ok_or_else(|| AuditError::new(format!("{id}: shared missing")))?;
            sinks.push(Sink {
                id: id.to_owned(),
                path: text(entry, "path", id)?.to_owned(),
                line: number(entry, "line", id)?,
                emitter: text(entry, "emitter", id)?.to_owned(),
                kind: text(entry, "kind", id)?.to_owned(),
                discloses: text(entry, "discloses", id)?.to_owned(),
                shared,
                reached_through: if shared {
                    strings(entry, "reached-through", id)?
                } else {
                    Vec::new()
                },
                verdict: text(entry, "verdict", id)?.to_owned(),
                decision: text(entry, "decision", id)?.to_owned(),
            });
        }
        if sinks.is_empty() {
            return Err(AuditError::new(format!("{path}: no sink")));
        }

        let mut shapes = Vec::new();
        for entry in table(&value, "shape") {
            let format = text(entry, "format", path)?;
            shapes.push(Shape {
                format: format.to_owned(),
                argument: entry
                    .get("argument")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                class: text(entry, "class", format)?.to_owned(),
                discloses: text(entry, "discloses", format)?.to_owned(),
            });
        }
        if shapes.is_empty() {
            return Err(AuditError::new(format!("{path}: no disclosure shape")));
        }

        let mut callers = Vec::new();
        for entry in table(&value, "caller") {
            let at = text(entry, "path", path)?;
            callers.push(Caller {
                sink: text(entry, "sink", at)?.to_owned(),
                path: at.to_owned(),
                sites: number(entry, "sites", at)?,
                decision: text(entry, "decision", at)?.to_owned(),
            });
        }

        let mut disclosures = Vec::new();
        for entry in table(&value, "disclosure") {
            let at = text(entry, "path", path)?;
            disclosures.push(Disclosure {
                sink: text(entry, "sink", at)?.to_owned(),
                path: at.to_owned(),
                line: number(entry, "line", at)?,
                class: text(entry, "class", at)?.to_owned(),
                decision: text(entry, "decision", at)?.to_owned(),
            });
        }

        Ok(Self {
            reused,
            added,
            sinks,
            shapes,
            callers,
            disclosures,
            sensitive: strings(&value, "sensitive-fields", path)?,
            instrumentation: strings(&value, "instrumentation-macros", path)?,
        })
    }

    /// Discovers every call site of every shared sink's wrappers.
    ///
    /// This is the whole point of the module: the sites are found by reading the
    /// oracle rather than by trusting a list, so a call site added upstream
    /// appears here whether or not anyone remembered to declare it.
    #[must_use]
    pub fn discover(&self, files: &dyn Files) -> Flow {
        let wrappers: BTreeSet<&str> = self
            .sinks
            .iter()
            .filter(|sink| sink.shared)
            .flat_map(|sink| sink.reached_through.iter().map(String::as_str))
            .collect();
        let mut flow = Flow::default();
        for caller in &self.callers {
            let Some(body) = files.read(&caller.path) else {
                continue;
            };
            let lines: Vec<&str> = body.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                if !wrappers
                    .iter()
                    .any(|wrapper| line.contains(&format!("{wrapper}(")))
                {
                    continue;
                }
                let call = call_text(&lines, index);
                let class = literal(&call).and_then(|(format, rest)| {
                    self.shapes
                        .iter()
                        .find(|shape| {
                            shape.format == format
                                && shape
                                    .argument
                                    .as_ref()
                                    .is_none_or(|argument| rest.contains(argument.as_str()))
                        })
                        .map(|shape| shape.class.clone())
                });
                if class.is_some() {
                    flow.matched += 1;
                }
                flow.sites.push(Site {
                    path: caller.path.clone(),
                    line: index + 1,
                    class,
                });
            }
        }
        flow
    }

    /// Runs every observability gate.
    pub fn audit(
        &self,
        files: &dyn Files,
        decisions: &BTreeSet<String>,
        report: &mut Report,
    ) -> Flow {
        let flow = self.discover(files);
        self.surfaces(files, decisions, report);
        self.emitters(files, decisions, report);
        self.flows(&flow, report);
        self.fields(files, report);
        flow
    }

    /// The reused surfaces still carry the tokens that name them.
    fn surfaces(&self, files: &dyn Files, decisions: &BTreeSet<String>, report: &mut Report) {
        let mut stale = Vec::new();
        for entry in &self.reused {
            let present = files.read(&entry.path).is_some_and(|body| {
                body.lines()
                    .nth(entry.line.saturating_sub(1))
                    .is_some_and(|line| line.contains(&entry.evidence))
            });
            if !present {
                stale.push(format!("{}:{}", entry.path, entry.line));
            }
        }
        report.assert(
            stale.is_empty(),
            "observability/reused-surfaces-present",
            if stale.is_empty() {
                format!(
                    "{} reused surface(s) across {} element(s), each verified at its locator",
                    self.reused.len(),
                    self.reused
                        .iter()
                        .map(|entry| entry.element.as_str())
                        .collect::<BTreeSet<&str>>()
                        .len()
                )
            } else {
                format!("locator carries no evidence: {}", stale.join(", "))
            },
        );

        let unbounded: Vec<&str> = self
            .added
            .iter()
            .filter(|entry| !entry.inert || !decisions.contains(&entry.decision))
            .map(|entry| entry.element.as_str())
            .collect();
        report.assert(
            unbounded.is_empty(),
            "observability/added-elements-inert",
            if unbounded.is_empty() {
                format!(
                    "{} added element(s), each inert without a subscriber and each resolving",
                    self.added.len()
                )
            } else {
                format!("not inert or not resolving: {}", unbounded.join(", "))
            },
        );

        let network: Vec<&str> = self
            .added
            .iter()
            .filter(|entry| {
                matches!(
                    entry.element.as_str(),
                    "metrics endpoint" | "health and readiness checks"
                ) && !entry.in_verification_tree
            })
            .map(|entry| entry.element.as_str())
            .collect();
        report.assert(
            network.is_empty(),
            "observability/endpoints-in-the-verification-tree",
            if network.is_empty() {
                "every network-exposed element lives in the verification tree".to_owned()
            } else {
                format!(
                    "exposed from the implementation tree: {}",
                    network.join(", ")
                )
            },
        );
    }

    /// Every declared sink still emits where it is declared to.
    fn emitters(&self, files: &dyn Files, decisions: &BTreeSet<String>, report: &mut Report) {
        let identifiers: BTreeSet<&str> = self.sinks.iter().map(|sink| sink.id.as_str()).collect();
        report.assert(
            identifiers.len() == self.sinks.len(),
            "observability/sink-identifiers-unique",
            format!(
                "{} sink(s), {} distinct identifier(s)",
                self.sinks.len(),
                identifiers.len()
            ),
        );

        let mut stale = Vec::new();
        for sink in &self.sinks {
            let present = files.read(&sink.path).is_some_and(|body| {
                body.lines()
                    .nth(sink.line.saturating_sub(1))
                    .is_some_and(|line| line.contains(&sink.emitter))
            });
            if !present {
                stale.push(format!("{}: {}:{}", sink.id, sink.path, sink.line));
            }
        }
        report.assert(
            stale.is_empty(),
            "observability/sinks-emit",
            if stale.is_empty() {
                format!(
                    "{} sink(s), each emitting at its locator, {} of them shared",
                    self.sinks.len(),
                    self.sinks.iter().filter(|sink| sink.shared).count()
                )
            } else {
                format!("no emitter at the locator: {}", stale.join(", "))
            },
        );

        let unaccountable: Vec<&str> = self
            .sinks
            .iter()
            .filter(|sink| {
                !decisions.contains(&sink.decision)
                    || sink.discloses.trim().is_empty()
                    || sink.verdict != "reproduce"
            })
            .map(|sink| sink.id.as_str())
            .collect();
        report.assert(
            unaccountable.is_empty(),
            "observability/sinks-accountable",
            if unaccountable.is_empty() {
                "every sink names what it discloses, reproduces it, and resolves".to_owned()
            } else {
                format!("incomplete: {}", unaccountable.join(", "))
            },
        );
    }

    /// The discovered flow agrees with the declared one, in both directions.
    fn flows(&self, flow: &Flow, report: &mut Report) {
        let mut wrappers = 0;
        for sink in self.sinks.iter().filter(|sink| sink.shared) {
            wrappers += sink.reached_through.len();
            let declared: BTreeSet<&str> = self
                .callers
                .iter()
                .filter(|caller| caller.sink == sink.id)
                .map(|caller| caller.path.as_str())
                .collect();
            report.assert(
                !declared.is_empty(),
                "observability/shared-sinks-have-consumers",
                if declared.is_empty() {
                    format!("{}: shared with no declared consumer", sink.id)
                } else {
                    format!(
                        "{}: {} consumer(s) through {} wrapper(s)",
                        sink.id,
                        declared.len(),
                        sink.reached_through.len()
                    )
                },
            );
        }
        let _ = wrappers;

        let mut found: BTreeMap<&str, usize> = BTreeMap::new();
        for site in &flow.sites {
            *found.entry(site.path.as_str()).or_default() += 1;
        }
        let drift: Vec<String> = self
            .callers
            .iter()
            .filter(|caller| found.get(caller.path.as_str()).copied().unwrap_or(0) != caller.sites)
            .map(|caller| {
                format!(
                    "{}: {} declared, {} found",
                    caller.path,
                    caller.sites,
                    found.get(caller.path.as_str()).copied().unwrap_or(0)
                )
            })
            .collect();
        report.assert(
            drift.is_empty() && !self.callers.is_empty(),
            "observability/call-sites-frozen",
            if drift.is_empty() {
                format!(
                    "{} call site(s) across {} consumer(s)",
                    flow.sites.len(),
                    self.callers.len()
                )
            } else {
                format!("count drift: {}", drift.join(", "))
            },
        );

        let declared: BTreeMap<(&str, usize), &Disclosure> = self
            .disclosures
            .iter()
            .map(|entry| ((entry.path.as_str(), entry.line), entry))
            .collect();
        let matched: BTreeMap<(&str, usize), &Site> = flow
            .sites
            .iter()
            .filter(|site| site.class.is_some())
            .map(|site| ((site.path.as_str(), site.line), site))
            .collect();

        let undeclared: Vec<String> = matched
            .keys()
            .filter(|key| !declared.contains_key(*key))
            .map(|(path, line)| format!("{path}:{line}"))
            .collect();
        report.assert(
            undeclared.is_empty() && !matched.is_empty(),
            "observability/disclosures-declared",
            if undeclared.is_empty() {
                format!(
                    "{} disclosure(s) of {} call site(s), each declared",
                    matched.len(),
                    flow.sites.len()
                )
            } else {
                format!("discovered and undeclared: {}", undeclared.join(", "))
            },
        );

        let phantom: Vec<String> = declared
            .keys()
            .filter(|key| !matched.contains_key(*key))
            .map(|(path, line)| format!("{path}:{line}"))
            .collect();
        report.assert(
            phantom.is_empty(),
            "observability/disclosures-discovered",
            if phantom.is_empty() {
                "every declared disclosure names a discovered call site".to_owned()
            } else {
                format!("declared and not discovered: {}", phantom.join(", "))
            },
        );

        let misclassified: Vec<String> = declared
            .iter()
            .filter(|(key, entry)| {
                matched
                    .get(*key)
                    .and_then(|site| site.class.as_deref())
                    .is_some_and(|class| class != entry.class)
            })
            .map(|((path, line), _)| format!("{path}:{line}"))
            .collect();
        report.assert(
            misclassified.is_empty(),
            "observability/disclosures-classified",
            if misclassified.is_empty() {
                format!(
                    "{} credential-bearing and {} mechanism-only site(s)",
                    self.disclosures
                        .iter()
                        .filter(|entry| entry.class == "credential")
                        .count(),
                    self.disclosures
                        .iter()
                        .filter(|entry| entry.class == "mechanism")
                        .count()
                )
            } else {
                format!(
                    "class disagrees with the shape: {}",
                    misclassified.join(", ")
                )
            },
        );
    }

    /// No added instrumentation carries a sensitive field.
    ///
    /// The check reads the project's own Rust rather than the oracle, so it is
    /// vacuous until instrumentation is written and bites the moment it is.
    fn fields(&self, files: &dyn Files, report: &mut Report) {
        let mut offending = Vec::new();
        let mut scanned = 0;
        for path in project_files(files) {
            if !path.ends_with(".rs") {
                continue;
            }
            let Some(body) = files.read(&path) else {
                continue;
            };
            scanned += 1;
            for (index, line) in body.lines().enumerate() {
                if !self
                    .instrumentation
                    .iter()
                    .any(|macro_name| line.contains(macro_name.as_str()))
                {
                    continue;
                }
                let lowered = line.to_ascii_lowercase();
                for field in &self.sensitive {
                    if lowered.contains(&format!("{field} ="))
                        || lowered.contains(&format!("%{field}"))
                        || lowered.contains(&format!("?{field}"))
                    {
                        offending.push(format!("{}:{}: {field}", path, index + 1));
                    }
                }
            }
        }
        report.assert(
            offending.is_empty(),
            "observability/added-fields-clean",
            if offending.is_empty() {
                format!(
                    "{scanned} project-authored Rust file(s) scanned, no instrumentation carries one of {} sensitive field name(s)",
                    self.sensitive.len()
                )
            } else {
                format!("sensitive field in instrumentation: {}", offending.join(", "))
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use curl_audit::fs::MapFiles;
    use curl_audit::report::Report;

    use super::{Contract, literal};

    const GOOD: &str = r#"
schema = 1
sensitive-fields = ["password", "user"]
instrumentation-macros = ["trace!", "counter!"]

[[shape]]
format = "USER %s"
class = "credential"
discloses = "the account name"

[[shape]]
format = "%s"
argument = "Curl_bufref_ptr(resp)"
class = "credential"
discloses = "one continuation"

[[shape]]
format = "AUTH %s"
class = "mechanism"
discloses = "the mechanism"

[[reused]]
element = "structured logging"
surface = "trace registry"
path = "original/lib/curl_trc.h"
line = 2
evidence = "curl_trc_feat"
decision = "DL-0232"

[[added]]
element = "metrics endpoint"
detail = "Prometheus format"
at = "testing/observability"
inert-without-subscriber = true
in-verification-tree = true
decision = "DL-0232"

[[sink]]
id = "SK-0001"
path = "original/lib/pingpong.c"
line = 2
emitter = "Curl_debug"
kind = "CURLINFO_HEADER_OUT"
discloses = "every command line"
shared = true
reached-through = ["Curl_pp_sendf"]
verdict = "reproduce"
decision = "DL-0116"

[[caller]]
sink = "SK-0001"
path = "original/lib/pop3.c"
sites = 3
decision = "DL-0232"

[[disclosure]]
sink = "SK-0001"
path = "original/lib/pop3.c"
line = 1
class = "credential"
decision = "DL-0116"

[[disclosure]]
sink = "SK-0001"
path = "original/lib/pop3.c"
line = 2
class = "mechanism"
decision = "DL-0116"
"#;

    const POP3: &str = concat!(
        "  result = Curl_pp_sendf(data, &pop3c->pp, \"USER %s\", user);\n",
        "  result = Curl_pp_sendf(data, &pop3c->pp, \"AUTH %s\", mech);\n",
        "  result = Curl_pp_sendf(data, &pop3c->pp, \"CAPA\");\n",
    );

    fn tree() -> MapFiles {
        MapFiles::new()
            .with("data/observability.toml", GOOD)
            .with("original/lib/curl_trc.h", "a\nstruct curl_trc_feat {\n")
            .with(
                "original/lib/pingpong.c",
                "a\n  Curl_debug(data, CURLINFO_HEADER_OUT, s, n);\n",
            )
            .with("original/lib/pop3.c", POP3)
    }

    fn decisions() -> BTreeSet<String> {
        ["DL-0116", "DL-0232"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn a_literal_ends_at_an_unescaped_quote() {
        assert_eq!(
            literal(r#"f(a, "USER %s", user)"#),
            Some(("USER %s".to_owned(), ", user)"))
        );
        assert_eq!(literal("f(a, b)"), None);
        assert_eq!(
            literal(r#"f("a\"b", c)"#),
            Some((r#"a\"b"#.to_owned(), ", c)"))
        );
    }

    #[test]
    fn a_missing_or_empty_contract_is_an_error() {
        assert!(Contract::load(&MapFiles::new(), "data/observability.toml").is_err());
        let files = MapFiles::new().with("data/observability.toml", "schema = 1\n");
        assert!(Contract::load(&files, "data/observability.toml").is_err());
    }

    #[test]
    fn a_complete_contract_passes_every_gate() {
        let files = tree();
        let contract = Contract::load(&files, "data/observability.toml").expect("loads");
        let mut report = Report::new("test");
        let flow = contract.audit(&files, &decisions(), &mut report);
        let rendered = report.render();
        assert!(report.passed(), "{rendered}");
        assert_eq!(flow.sites.len(), 3);
        assert_eq!(flow.matched, 2);
        assert!(rendered.contains("PASS observability/reused-surfaces-present"));
        assert!(rendered.contains("PASS observability/sinks-emit"));
        assert!(rendered.contains("PASS observability/disclosures-declared"));
        assert!(rendered.contains("PASS observability/added-fields-clean"));
    }

    #[test]
    fn a_stale_reused_locator_fails() {
        let text = GOOD.replace("line = 2\nevidence", "line = 1\nevidence");
        let files = tree().with("data/observability.toml", &text);
        let contract = Contract::load(&files, "data/observability.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = contract.audit(&files, &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL observability/reused-surfaces-present")
        );
    }

    #[test]
    fn a_sink_that_does_not_emit_at_its_locator_fails() {
        let files = tree().with("original/lib/pingpong.c", "a\n  infof(data, \"x\");\n");
        let contract = Contract::load(&files, "data/observability.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = contract.audit(&files, &decisions(), &mut report);
        assert!(report.render().contains("FAIL observability/sinks-emit"));
    }

    #[test]
    fn an_undeclared_credential_call_site_fails() {
        let text = GOOD.replace(
            "[[disclosure]]\nsink = \"SK-0001\"\npath = \"original/lib/pop3.c\"\nline = 1\nclass = \"credential\"\ndecision = \"DL-0116\"\n",
            "",
        );
        let files = tree().with("data/observability.toml", &text);
        let contract = Contract::load(&files, "data/observability.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = contract.audit(&files, &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL observability/disclosures-declared")
        );
    }

    #[test]
    fn a_new_call_site_upstream_is_discovered_and_fails_the_frozen_count() {
        let body = format!("{POP3}  result = Curl_pp_sendf(data, &pop3c->pp, \"PASS %s\", pw);\n");
        let files = tree().with("original/lib/pop3.c", &body);
        let contract = Contract::load(&files, "data/observability.toml").expect("loads");
        let mut report = Report::new("test");
        let flow = contract.audit(&files, &decisions(), &mut report);
        assert_eq!(flow.sites.len(), 4);
        assert!(
            report
                .render()
                .contains("FAIL observability/call-sites-frozen")
        );
    }

    #[test]
    fn a_declared_disclosure_that_no_site_carries_fails() {
        let text = GOOD.replace(
            "line = 1\nclass = \"credential\"",
            "line = 3\nclass = \"credential\"",
        );
        let files = tree().with("data/observability.toml", &text);
        let contract = Contract::load(&files, "data/observability.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = contract.audit(&files, &decisions(), &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL observability/disclosures-discovered"),
            "{rendered}"
        );
    }

    #[test]
    fn a_misclassified_disclosure_fails() {
        let text = GOOD.replace(
            "line = 2\nclass = \"mechanism\"",
            "line = 2\nclass = \"credential\"",
        );
        let files = tree().with("data/observability.toml", &text);
        let contract = Contract::load(&files, "data/observability.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = contract.audit(&files, &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL observability/disclosures-classified")
        );
    }

    #[test]
    fn a_sensitive_field_in_added_instrumentation_fails() {
        let field = concat!("pass", "word");
        let body = format!("fn f() {{ trace!(target: \"ftp\", {field} = s, \"sent\"); }}\n");
        let files = tree().with("refactor/curl-core/src/trc.rs", &body);
        let contract = Contract::load(&files, "data/observability.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = contract.audit(&files, &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL observability/added-fields-clean")
        );
    }

    #[test]
    fn an_endpoint_outside_the_verification_tree_fails() {
        let text = GOOD.replace(
            "in-verification-tree = true",
            "in-verification-tree = false",
        );
        let files = tree().with("data/observability.toml", &text);
        let contract = Contract::load(&files, "data/observability.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = contract.audit(&files, &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL observability/endpoints-in-the-verification-tree")
        );
    }
}
