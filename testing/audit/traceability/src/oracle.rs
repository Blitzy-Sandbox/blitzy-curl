// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Mechanical enumeration of the vendored oracle.
//!
//! Every list here is produced by reading `original/` on the invocation that
//! needs it. No figure is read from a manifest or from the decision log, which
//! is what makes a drifted count visible instead of asserted.

use std::collections::{BTreeMap, BTreeSet};

use curl_audit::fs::Files;

/// Root of the vendored oracle.
pub const ORACLE: &str = "original";

/// One entry of the symbol register.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterEntry {
    /// Symbol name.
    pub name: String,
    /// Version that first provided it.
    pub introduced: String,
    /// Version that first marked it deprecated, empty when none did.
    pub deprecated: String,
    /// Last version that featured it, empty when it is current.
    pub last: String,
}

/// One command-line option of the tool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliOption {
    /// Long option name as the alias table spells it.
    pub name: String,
    /// Identifier the table maps it to.
    pub identifier: String,
    /// Argument-type descriptor as the table spells it, flags included.
    pub descriptor: String,
    /// Whether a dispatch arm anywhere in the tool names the identifier.
    pub dispatched: bool,
    /// Whether the descriptor marks it deprecated.
    pub deprecated: bool,
}

/// One build flag or build-system option.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildFlag {
    /// User-facing spelling.
    pub name: String,
    /// File that declares it.
    pub source: String,
}

/// One internal-surface case and the internal headers it includes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceCase {
    /// Repository-relative path of the case.
    pub path: String,
    /// Internal headers it includes, excluding the shared check header.
    pub includes: Vec<String>,
}

/// One exported symbol and how it is reached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Export {
    /// Exported name.
    pub name: String,
    /// Public headers whose declarations name it.
    pub headers: Vec<String>,
    /// Whether the declaration is variadic or takes an argument list.
    pub variadic: bool,
}

/// One generator, harness or configuration asset of the oracle.
///
/// The class the other families cannot hold: a file that is neither a
/// translation unit nor a header, and therefore carries no symbol, no option
/// and no case number to be enumerated by. `DL-0273` records it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessAsset {
    /// Repository-relative path inside the oracle.
    pub path: String,
    /// Enumeration root it was found under.
    pub root: String,
    /// `<manifest>:<line>` that registers it, empty when nothing does.
    pub registration: String,
}

/// Everything the oracle carries, enumerated once per invocation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Survey {
    /// Translation units under `original/lib` and `original/src`.
    pub units: Vec<String>,
    /// Internal headers under `original/lib` and `original/src`.
    pub headers: Vec<String>,
    /// Public headers under `original/include/curl`.
    pub public_headers: Vec<String>,
    /// Exported names, from the export list.
    pub exports: Vec<Export>,
    /// Symbol-register entries.
    pub register: Vec<RegisterEntry>,
    /// Command-line options of the tool.
    pub cli_options: Vec<CliOption>,
    /// Output-format variables of the tool.
    pub writeout_variables: Vec<String>,
    /// Build flags and build-system options.
    pub build_flags: Vec<BuildFlag>,
    /// Internal-surface cases.
    pub cases: Vec<SurfaceCase>,
    /// Generator, harness and configuration assets.
    pub harness: Vec<HarnessAsset>,
    /// Manifest words naming no file, as `<manifest>: <word>`.
    pub harness_absent: Vec<String>,
}

/// Whether `path` names a directory in this view.
fn is_directory(files: &dyn Files, path: &str) -> bool {
    !files.list(path).is_empty()
}

/// Every file under `directory` whose name ends with `suffix`, recursively.
pub fn walk(files: &dyn Files, directory: &str, suffix: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![directory.to_owned()];
    while let Some(current) = pending.pop() {
        for name in files.list(&current) {
            let child = format!("{current}/{name}");
            if is_directory(files, &child) {
                pending.push(child);
            } else if name.ends_with(suffix) {
                found.push(child);
            }
        }
    }
    found.sort();
    found
}

/// Names in the export list, in file order.
pub fn exported_names(files: &dyn Files) -> Vec<String> {
    let Some(text) = files.read("original/lib/libcurl.def") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut started = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("EXPORTS") {
            started = true;
            continue;
        }
        if !started || trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        names.push(trimmed.to_owned());
    }
    names
}

/// Removes double-quoted spans.
///
/// A deprecation message names another entry point, so a block that kept its
/// string literals would attribute that entry point's signature to the wrong
/// name.
fn without_strings(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut inside = false;
    for character in text.chars() {
        if character == '"' {
            inside = !inside;
            continue;
        }
        if !inside {
            out.push(character);
        }
    }
    out
}

/// Declaration blocks in one public header: each starts at an external marker
/// and runs to the first semicolon, with string literals removed.
fn declaration_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if current.is_none() && line.contains("CURL_EXTERN") {
            current = Some(String::new());
        }
        if let Some(block) = current.as_mut() {
            block.push(' ');
            block.push_str(&without_strings(line.trim()));
            if line.contains(';') {
                blocks.push(current.take().unwrap_or_default());
            }
        }
    }
    blocks
}

/// Resolves every exported name to the public headers that declare it, and
/// records whether the declaration is variadic.
pub fn exports(files: &dyn Files, public_headers: &[String]) -> Vec<Export> {
    let blocks: Vec<(String, Vec<String>)> = public_headers
        .iter()
        .map(|header| {
            let text = files.read(header).unwrap_or_default();
            (header.clone(), declaration_blocks(&text))
        })
        .collect();
    exported_names(files)
        .into_iter()
        .map(|name| {
            let needle = format!("{name}(");
            let mut headers = Vec::new();
            let mut variadic = false;
            for (header, header_blocks) in &blocks {
                for block in header_blocks {
                    if block.contains(&needle) {
                        if !headers.contains(header) {
                            headers.push(header.clone());
                        }
                        if block.contains("...") || block.contains("va_list") {
                            variadic = true;
                        }
                    }
                }
            }
            Export {
                name,
                headers,
                variadic,
            }
        })
        .collect()
}

/// Whether a field looks like a released version.
fn is_version(field: &str) -> bool {
    !field.is_empty()
        && field.starts_with(|c: char| c.is_ascii_digit())
        && field.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Entries of the symbol register.
pub fn register(files: &dyn Files) -> Vec<RegisterEntry> {
    let Some(text) = files.read("original/docs/libcurl/symbols-in-versions") else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for line in text.lines() {
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 || !is_version(fields[1]) {
            continue;
        }
        let column = |index: usize| -> String {
            match fields.get(index) {
                Some(&"-") | None => String::new(),
                Some(value) => (*value).to_owned(),
            }
        };
        entries.push(RegisterEntry {
            name: fields[0].to_owned(),
            introduced: fields[1].to_owned(),
            deprecated: column(2),
            last: column(3),
        });
    }
    entries
}

/// Text between the first `"` pair of a line.
fn quoted(line: &str) -> Option<&str> {
    let start = line.find('"')? + 1;
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Command-line options, from the tool's alias table.
pub fn cli_options(files: &dyn Files) -> Vec<CliOption> {
    let Some(text) = files.read("original/src/tool_getparam.c") else {
        return Vec::new();
    };
    let dispatched = dispatch_labels(&text);
    let mut options = Vec::new();
    let mut inside = false;
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        index += 1;
        if line.contains("aliases[]") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if line.starts_with("};") {
            break;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        // A row may wrap: accumulate to its closing brace before reading it,
        // because the identifier is the last field and a wrapped row puts it on
        // the following line.
        let mut row = trimmed.to_owned();
        while !row.contains('}') && index < lines.len() {
            row.push(' ');
            row.push_str(lines[index].trim());
            index += 1;
        }
        let Some(name) = quoted(&row) else {
            continue;
        };
        let identifier = row
            .split_once('}')
            .map_or(row.as_str(), |(head, _)| head)
            .trim_end_matches(|c: char| c == ',' || c.is_whitespace())
            .rsplit(',')
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        let descriptor = row.split(',').nth(1).unwrap_or_default().trim().to_owned();
        options.push(CliOption {
            name: name.to_owned(),
            deprecated: descriptor.contains("ARG_DEPR"),
            descriptor,
            dispatched: dispatched.contains(&identifier),
            identifier,
        });
    }
    options
}

/// Identifiers a dispatch arm of the tool names.
///
/// The alias table and the dispatch arms are two separate lists in one file, and
/// nothing in the oracle checks that they agree - which is why an option can be
/// accepted, have its argument consumed and then be discarded with no
/// diagnostic. Reading both is the only way to see that.
fn dispatch_labels(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("case C_")
            && let Some(name) = rest.split(':').next()
        {
            found.insert(format!("C_{name}"));
        }
    }
    found
}

/// Output-format variables, from the tool's variable table.
pub fn writeout_variables(files: &dyn Files) -> Vec<String> {
    let Some(text) = files.read("original/src/tool_writeout.c") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if line.contains("variables[]") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if line.starts_with("};") {
            break;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with("{ \"") && !trimmed.starts_with("{\"") {
            continue;
        }
        if let Some(name) = quoted(trimmed) {
            names.push(name.to_owned());
        }
    }
    names
}

/// The argument a macro invocation opens with.
///
/// A macro argument never contains whitespace here, so the first comma, close
/// parenthesis or space ends it; that covers both the autoconf form, which is
/// comma-separated, and the build-system form, which is space-separated.
fn first_argument(line: &str, macro_name: &str) -> Option<String> {
    let start = line.find(macro_name)? + macro_name.len();
    let rest = line[start..].trim_start();
    let rest = rest.strip_prefix('(')?;
    let end = rest
        .find(|c: char| c == ',' || c == ')' || c.is_whitespace())
        .unwrap_or(rest.len());
    let argument = rest[..end].trim_matches(['[', ']', '"']).trim();
    (!argument.is_empty()).then(|| argument.to_owned())
}

/// Build flags and build-system options the baseline declares.
pub fn build_flags(files: &dyn Files) -> Vec<BuildFlag> {
    let mut autoconf: Vec<String> = vec![
        "original/configure.ac".to_owned(),
        "original/acinclude.m4".to_owned(),
    ];
    autoconf.extend(walk(files, "original/m4", ".m4"));
    let mut cmake: Vec<String> = vec![
        "original/CMakeLists.txt".to_owned(),
        "original/lib/CMakeLists.txt".to_owned(),
        "original/src/CMakeLists.txt".to_owned(),
        "original/scripts/CMakeLists.txt".to_owned(),
    ];
    cmake.extend(walk(files, "original/CMake", ".cmake"));

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut flags = Vec::new();
    let mut record = |name: String, source: &str, flags: &mut Vec<BuildFlag>| {
        if seen.insert(name.clone()) {
            flags.push(BuildFlag {
                name,
                source: source.to_owned(),
            });
        }
    };
    for path in autoconf {
        let Some(text) = files.read(&path) else {
            continue;
        };
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("dnl") || trimmed.starts_with('#') {
                continue;
            }
            if let Some(name) = first_argument(trimmed, "AC_ARG_WITH") {
                record(
                    format!("--with-{}", name.replace('_', "-")),
                    &path,
                    &mut flags,
                );
            }
            if let Some(name) = first_argument(trimmed, "AC_ARG_ENABLE") {
                record(
                    format!("--enable-{}", name.replace('_', "-")),
                    &path,
                    &mut flags,
                );
            }
        }
    }
    for path in cmake {
        let Some(text) = files.read(&path) else {
            continue;
        };
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') {
                continue;
            }
            let macro_name = if trimmed.starts_with("cmake_dependent_option") {
                "cmake_dependent_option"
            } else if trimmed.starts_with("option") {
                "option"
            } else {
                continue;
            };
            if let Some(name) = first_argument(trimmed, macro_name) {
                record(name, &path, &mut flags);
            }
        }
    }
    flags
}

/// Internal-surface cases and the internal headers each includes.
pub fn cases(files: &dyn Files) -> Vec<SurfaceCase> {
    let mut found = Vec::new();
    for directory in ["original/tests/unit", "original/tests/tunit"] {
        for path in walk(files, directory, ".c") {
            let text = files.read(&path).unwrap_or_default();
            let includes: Vec<String> = text
                .lines()
                .filter(|line| line.starts_with("#include \""))
                .filter_map(quoted)
                .filter(|name| *name != "unitcheck.h")
                .map(str::to_owned)
                .collect();
            found.push(SurfaceCase { path, includes });
        }
    }
    found.sort_by(|left, right| left.path.cmp(&right.path));
    found
}

/// Roots the asset enumeration covers, and whether each is read recursively.
///
/// The two source roots are read whole; the test root is read at its top level
/// only, its subdirectories being the subject of the case and test-data
/// families. `DL-0273` records the boundary.
pub const HARNESS_ROOTS: [(&str, bool); 3] = [
    ("original/lib", true),
    ("original/src", true),
    ("original/tests", false),
];

/// Where a substituted build input is registered when no manifest names it.
pub const CONFIGURE: &str = "original/configure.ac";

/// Distribution lists whose words the manifest side of the family is read from.
const DISTRIBUTION_LISTS: [&str; 2] = ["EXTRA_DIST", "TESTSCRIPTS"];

/// One root's automake manifest and every manifest it includes, in read order.
fn manifest_chain(files: &dyn Files, root: &str) -> Vec<String> {
    let mut chain = vec![format!("{root}/Makefile.am")];
    let mut index = 0;
    while index < chain.len() {
        let current = chain[index].clone();
        index += 1;
        let Some(text) = files.read(&current) else {
            continue;
        };
        let base = current.rsplit_once('/').map_or("", |(head, _)| head);
        for line in text.lines() {
            let Some(rest) = line.trim().strip_prefix("include ") else {
                continue;
            };
            let child = format!("{base}/{}", rest.trim());
            if !chain.contains(&child) && files.read(&child).is_some() {
                chain.push(child);
            }
        }
    }
    chain.retain(|path| files.read(path).is_some());
    chain
}

/// Whether `line` names `word` as a delimited token outside a comment.
///
/// A comment line is skipped so a locator points at a registration rather than
/// at prose that happens to mention the name.
fn names_token(line: &str, word: &str) -> bool {
    if line.trim_start().starts_with('#') {
        return false;
    }
    let boundary = |character: Option<char>| {
        character.is_none_or(|value| " \t=([]),\\".contains(value) || value == '\'')
    };
    line.match_indices(word).any(|(offset, _)| {
        boundary(line[..offset].chars().next_back())
            && boundary(line[offset + word.len()..].chars().next())
    })
}

/// First `<manifest>:<line>` of `chain` naming `word`, empty when none does.
fn registration(files: &dyn Files, chain: &[String], word: &str) -> String {
    for manifest in chain {
        let Some(text) = files.read(manifest) else {
            continue;
        };
        if let Some((index, _)) = text
            .lines()
            .enumerate()
            .find(|(_, line)| names_token(line, word))
        {
            return format!("{manifest}:{}", index + 1);
        }
    }
    String::new()
}

/// Registration of a substituted input, from the configure script.
///
/// A configure output `<root>/<stem>` is produced from `<stem>.in`, and
/// `<root>/Makefile` from `Makefile.am`, so those two shapes resolve where no
/// distribution list names the input itself.
fn substituted(files: &dyn Files, root: &str, name: &str) -> String {
    let leaf = root.rsplit('/').next().unwrap_or(root);
    let probe = if name == "Makefile.am" {
        format!("{leaf}/Makefile")
    } else if let Some(stem) = name.strip_suffix(".in") {
        format!("{leaf}/{stem}")
    } else {
        return String::new();
    };
    registration(files, &[CONFIGURE.to_owned()], &probe)
}

/// Words of every distribution list the manifest chain declares.
///
/// Continuations are followed and variable references are left alone: a
/// reference names another list rather than a file.
fn distribution_words(files: &dyn Files, chain: &[String]) -> Vec<String> {
    let mut words = Vec::new();
    for manifest in chain {
        let Some(text) = files.read(manifest) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index];
            index += 1;
            let Some((head, rest)) = line.split_once('=') else {
                continue;
            };
            let name = head.trim().trim_end_matches('+').trim();
            if !DISTRIBUTION_LISTS.contains(&name) && !name.ends_with("_DIST") {
                continue;
            }
            let mut body = rest.to_owned();
            while body.trim_end().ends_with('\\') {
                let trimmed = body.trim_end();
                body.truncate(trimmed.len() - 1);
                if index >= lines.len() {
                    break;
                }
                body.push(' ');
                body.push_str(lines[index]);
                index += 1;
            }
            words.extend(body.split_whitespace().map(str::to_owned));
        }
    }
    words
}

/// Generator, harness and configuration assets, with the manifest words that
/// name no file.
///
/// The files are enumerated from the tree and the registration is looked up,
/// rather than the reverse, so a file a distribution list forgets still takes a
/// row instead of disappearing.
#[must_use]
pub fn harness(files: &dyn Files) -> (Vec<HarnessAsset>, Vec<String>) {
    let mut assets = Vec::new();
    let mut absent = BTreeSet::new();
    for (root, recursive) in HARNESS_ROOTS {
        let chain = manifest_chain(files, root);
        let mut found: Vec<String> = if recursive {
            walk(files, root, "")
                .into_iter()
                .filter(|path| !path.ends_with(".c") && !path.ends_with(".h"))
                .collect()
        } else {
            files
                .list(root)
                .into_iter()
                .map(|name| format!("{root}/{name}"))
                .filter(|child| !is_directory(files, child))
                .collect()
        };
        found.sort();
        for path in found {
            let name = path.rsplit('/').next().unwrap_or(&path).to_owned();
            let mut located = registration(files, &chain, &name);
            if located.is_empty() {
                located = substituted(files, root, &name);
            }
            assets.push(HarnessAsset {
                path,
                root: root.to_owned(),
                registration: located,
            });
        }
        for word in distribution_words(files, &chain) {
            if word.starts_with('$') {
                continue;
            }
            if !files.exists(&format!("{root}/{word}")) {
                absent.insert(format!("{root}/{word}"));
            }
        }
    }
    assets.sort_by(|left, right| left.path.cmp(&right.path));
    (assets, absent.into_iter().collect())
}

impl Survey {
    /// Enumerates every construct family.
    #[must_use]
    pub fn collect(files: &dyn Files) -> Self {
        let mut units = walk(files, "original/lib", ".c");
        units.extend(walk(files, "original/src", ".c"));
        units.sort();
        let mut headers = walk(files, "original/lib", ".h");
        headers.extend(walk(files, "original/src", ".h"));
        headers.sort();
        let public_headers = walk(files, "original/include/curl", ".h");
        let exports = exports(files, &public_headers);
        let (harness, harness_absent) = harness(files);
        Self {
            units,
            headers,
            public_headers,
            exports,
            register: register(files),
            cli_options: cli_options(files),
            writeout_variables: writeout_variables(files),
            build_flags: build_flags(files),
            cases: cases(files),
            harness,
            harness_absent,
        }
    }

    /// Every enumerated path, for same-stem resolution.
    #[must_use]
    pub fn paths(&self) -> BTreeSet<String> {
        self.units
            .iter()
            .chain(self.headers.iter())
            .cloned()
            .collect()
    }

    /// Counts of every family, for the rendered preamble.
    #[must_use]
    pub fn counts(&self) -> BTreeMap<&'static str, usize> {
        BTreeMap::from([
            ("translation-unit", self.units.len()),
            ("internal-header", self.headers.len()),
            ("public-header", self.public_headers.len()),
            ("exported-symbol", self.exports.len()),
            ("symbol-register", self.register.len()),
            ("cli-option", self.cli_options.len()),
            ("writeout-variable", self.writeout_variables.len()),
            ("build-flag", self.build_flags.len()),
            ("internal-surface-case", self.cases.len()),
            ("harness-asset", self.harness.len()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use curl_audit::fs::MapFiles;

    use super::{
        Survey, build_flags, cases, cli_options, declaration_blocks, exported_names, exports,
        first_argument, harness, names_token, register, walk, writeout_variables,
    };

    fn files() -> MapFiles {
        MapFiles::new()
            .with("original/lib/http.c", "")
            .with("original/lib/http.h", "")
            .with("original/lib/curlx/base64.c", "")
            .with("original/src/tool_main.c", "")
            .with(
                "original/lib/libcurl.def",
                "EXPORTS\ncurl_easy_init\ncurl_easy_setopt\n; comment\n",
            )
            .with(
                "original/include/curl/easy.h",
                "CURL_EXTERN CURL *curl_easy_init(void);\nCURL_EXTERN CURLcode curl_easy_setopt(CURL *handle,\n  CURLoption option, ...);\n",
            )
            .with(
                "original/docs/libcurl/symbols-in-versions",
                "Name                Introduced  Deprecated  Last\n\nCURLOPT_URL          7.1\nCURL_EASY_NONE       7.14.0      -           7.15.4\n",
            )
            .with(
                "original/src/tool_getparam.c",
                "static const struct LongShort aliases[]= {\n  {\"alpn\", ARG_BOOL, ' ', C_ALPN},\n  {\"append\", ARG_BOOL, 'a', C_APPEND},\n};\n",
            )
            .with(
                "original/src/tool_writeout.c",
                "static const struct writeoutvar variables[] = {\n  { \"certs\", VAR_CERT, CURLINFO_NONE, writeString },\n  { \"conn_id\", VAR_CONN_ID, CURLINFO_CONN_ID, writeOffset },\n};\n",
            )
            .with(
                "original/configure.ac",
                "AC_ARG_WITH(openssl,\ndnl AC_ARG_WITH(ignored,\nAC_ARG_ENABLE(threaded_resolver,\n",
            )
            .with(
                "original/CMakeLists.txt",
                "option(CURL_USE_OPENSSL \"text\" OFF)\n# option(IGNORED \"\" OFF)\ncmake_dependent_option(CURL_DISABLE_LDAPS \"\" ON \"\" OFF)\n",
            )
            .with(
                "original/tests/unit/unit1300.c",
                "#include \"unitcheck.h\"\n#include \"llist.h\"\n",
            )
            .with(
                "original/tests/tunit/tool1394.c",
                "#include \"unitcheck.h\"\n#include \"tool_getparam.h\"\n",
            )
    }

    #[test]
    fn walking_finds_files_recursively_and_sorted() {
        let files = files();
        assert_eq!(
            walk(&files, "original/lib", ".c"),
            vec![
                "original/lib/curlx/base64.c".to_owned(),
                "original/lib/http.c".to_owned()
            ]
        );
        assert!(walk(&files, "original/absent", ".c").is_empty());
    }

    #[test]
    fn exports_resolve_to_headers_and_record_variadics() {
        let files = files();
        assert_eq!(exported_names(&files).len(), 2);
        let resolved = exports(&files, &["original/include/curl/easy.h".to_owned()]);
        assert_eq!(resolved.len(), 2);
        let init = &resolved[0];
        assert_eq!(init.name, "curl_easy_init");
        assert_eq!(init.headers.len(), 1);
        assert!(!init.variadic);
        let setopt = &resolved[1];
        assert!(setopt.variadic);
        assert_eq!(declaration_blocks("no declarations here").len(), 0);
    }

    #[test]
    fn a_deprecation_message_does_not_attribute_a_signature() {
        // The message names another entry point, and the declaration it sits on
        // is variadic; only the declared name may be marked so.
        let files = MapFiles::new()
            .with("original/lib/libcurl.def", "EXPORTS\ncurl_formadd\ncurl_mime_init\n")
            .with(
                "original/include/curl/curl.h",
                "CURL_EXTERN CURLFORMcode CURL_DEPRECATED(7.56.0, \"Use curl_mime_init()\")\ncurl_formadd(struct curl_httppost **p, ...);\nCURL_EXTERN curl_mime *curl_mime_init(CURL *easy);\n",
            );
        let resolved = exports(&files, &["original/include/curl/curl.h".to_owned()]);
        let formadd = resolved
            .iter()
            .find(|e| e.name == "curl_formadd")
            .expect("present");
        let mime = resolved
            .iter()
            .find(|e| e.name == "curl_mime_init")
            .expect("present");
        assert!(formadd.variadic);
        assert!(
            !mime.variadic,
            "a message must not make its subject variadic"
        );
    }

    #[test]
    fn the_register_skips_its_own_column_headings() {
        let entries = register(&files());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "CURLOPT_URL");
        assert!(entries[0].deprecated.is_empty());
        assert_eq!(entries[1].last, "7.15.4");
    }

    #[test]
    fn tool_tables_are_read() {
        let files = files();
        let options = cli_options(&files);
        assert_eq!(options.len(), 2);
        assert_eq!(options[0].name, "alpn");
        assert_eq!(options[0].identifier, "C_ALPN");
        assert_eq!(writeout_variables(&files), vec!["certs", "conn_id"]);
    }

    #[test]
    fn build_flags_skip_comments_and_normalise_names() {
        let flags = build_flags(&files());
        let names: Vec<&str> = flags.iter().map(|flag| flag.name.as_str()).collect();
        assert!(names.contains(&"--with-openssl"));
        assert!(names.contains(&"--enable-threaded-resolver"));
        assert!(names.contains(&"CURL_USE_OPENSSL"));
        assert!(names.contains(&"CURL_DISABLE_LDAPS"));
        assert!(!names.iter().any(|name| name.contains("ignored")));
        assert!(!names.iter().any(|name| name.contains("IGNORED")));
        assert_eq!(first_argument("option", "option"), None);
    }

    #[test]
    fn cases_carry_their_internal_includes() {
        let found = cases(&files());
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].includes, vec!["tool_getparam.h"]);
        assert_eq!(found[1].includes, vec!["llist.h"]);
    }

    #[test]
    fn a_survey_counts_every_family() {
        let survey = Survey::collect(&files());
        let counts = survey.counts();
        assert_eq!(counts["translation-unit"], 5);
        assert_eq!(counts["internal-header"], 1);
        assert_eq!(counts["exported-symbol"], 2);
        assert_eq!(counts["internal-surface-case"], 2);
        assert!(survey.paths().contains("original/lib/http.c"));
        let empty = Survey::collect(&MapFiles::new());
        assert!(empty.units.is_empty());
        assert!(empty.register.is_empty());
    }

    /// A view carrying the three asset roots and their manifest chain.
    fn assets() -> MapFiles {
        MapFiles::new()
            .with("original/lib/http.c", "")
            .with("original/lib/http.h", "")
            .with(
                "original/lib/Makefile.am",
                "include Makefile.inc\nEXTRA_DIST = optiontable.pl $(LIB_RCFILES) gone.h.in\n",
            )
            .with("original/lib/Makefile.inc", "LIB_RCFILES = libcurl.rc\n")
            .with("original/lib/optiontable.pl", "")
            .with("original/lib/libcurl.rc", "")
            .with("original/lib/libcurl.vers.in", "")
            .with("original/lib/.gitignore", "")
            .with(
                "original/src/Makefile.am",
                "# mkhelp.pl is named in this comment only\nEXTRA_DIST = mkhelp.pl\n",
            )
            .with("original/src/mkhelp.pl", "")
            .with("original/src/tool_main.c", "")
            .with(
                "original/tests/Makefile.am",
                "TESTSCRIPTS = \\\n  test1175.pl\nEXTRA_DIST = runtests.pl $(TESTSCRIPTS)\n",
            )
            .with("original/tests/runtests.pl", "")
            .with("original/tests/test1175.pl", "")
            .with("original/tests/config.in", "")
            .with("original/tests/unit/unit1300.c", "")
            .with(
                "original/configure.ac",
                "AC_CONFIG_FILES([\\\n  lib/libcurl.vers \\\n  tests/config \\\n])\n",
            )
    }

    #[test]
    fn a_token_is_not_read_out_of_a_comment() {
        assert!(names_token("EXTRA_DIST = mkhelp.pl", "mkhelp.pl"));
        assert!(!names_token("# mkhelp.pl in prose", "mkhelp.pl"));
        assert!(!names_token("EXTRA_DIST = curl_config.in", "config.in"));
        assert!(names_token("  tests/config \\", "tests/config"));
    }

    #[test]
    fn assets_are_enumerated_from_the_tree_and_registration_looked_up() {
        let files = assets();
        let (found, absent) = harness(&files);
        let paths: Vec<&str> = found.iter().map(|asset| asset.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "original/lib/.gitignore",
                "original/lib/Makefile.am",
                "original/lib/Makefile.inc",
                "original/lib/libcurl.rc",
                "original/lib/libcurl.vers.in",
                "original/lib/optiontable.pl",
                "original/src/Makefile.am",
                "original/src/mkhelp.pl",
                "original/tests/Makefile.am",
                "original/tests/config.in",
                "original/tests/runtests.pl",
                "original/tests/test1175.pl",
            ],
            "no unit, no header and no subdirectory of the test root"
        );
        let of = |path: &str| {
            found
                .iter()
                .find(|asset| asset.path == path)
                .expect("enumerated")
                .registration
                .clone()
        };
        // A word of an included manifest, a wrapped list and a comment-only
        // mention each resolve the way the manifests declare them.
        assert_eq!(
            of("original/lib/optiontable.pl"),
            "original/lib/Makefile.am:2"
        );
        assert_eq!(of("original/lib/libcurl.rc"), "original/lib/Makefile.inc:1");
        assert_eq!(of("original/src/mkhelp.pl"), "original/src/Makefile.am:2");
        assert_eq!(
            of("original/tests/test1175.pl"),
            "original/tests/Makefile.am:2"
        );
        assert_eq!(
            of("original/lib/libcurl.vers.in"),
            "original/configure.ac:2"
        );
        assert_eq!(of("original/tests/config.in"), "original/configure.ac:3");
        assert!(of("original/lib/.gitignore").is_empty(), "nothing names it");
        assert_eq!(absent, vec!["original/lib/gone.h.in".to_owned()]);
    }

    #[test]
    fn an_empty_view_enumerates_no_asset() {
        let (found, absent) = harness(&MapFiles::new());
        assert!(found.is_empty());
        assert!(absent.is_empty());
        assert_eq!(Survey::collect(&assets()).counts()["harness-asset"], 12);
    }
}
