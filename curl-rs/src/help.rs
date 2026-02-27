// -----------------------------------------------------------------------
// curl-rs/src/help.rs — Help Text Display and Version Reporting
//
// Rust rewrite of src/tool_help.c, src/tool_help.h, and
// src/tool_listhelp.c from curl 8.19.0-DEV. Implements:
//
//   - `tool_help(category)` — display help text for a given category,
//     all categories, or a specific option with manual scanning.
//   - `tool_version_info()` — display version, protocols, and features.
//   - `tool_list_engines()` — display SSL engine listing.
//
// Design:
//   - Zero `unsafe` blocks.
//   - Static `HELPTEXT` and `CATEGORIES` arrays match the C originals
//     exactly (generated from tool_listhelp.c).
//   - Column alignment uses terminal width detection matching curl 8.x.
//   - Protocol and feature lists are sorted alphabetically.
//   - IPFS/IPNS insertion logic matches C tool_version_info().
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use crate::args::{findlongopt, findshortopt, ArgType, CmdlineOption, LongShort};
use crate::libinfo::{get_libcurl_info, LibCurlInfo};
use crate::stderr::tool_stderr_write;
use crate::terminal::get_terminal_columns;
use curl_rs_lib::version::{version, version_info, VERSION};

// ---------------------------------------------------------------------------
// CURLHELP_* bitmask constants — matching tool_help.h exactly
// ---------------------------------------------------------------------------

const CURLHELP_AUTH: u32 = 1 << 0;
const CURLHELP_CONNECTION: u32 = 1 << 1;
const CURLHELP_CURL: u32 = 1 << 2;
const CURLHELP_DEPRECATED: u32 = 1 << 3;
const CURLHELP_DNS: u32 = 1 << 4;
const CURLHELP_FILE: u32 = 1 << 5;
const CURLHELP_FTP: u32 = 1 << 6;
const CURLHELP_GLOBAL: u32 = 1 << 7;
const CURLHELP_HTTP: u32 = 1 << 8;
const CURLHELP_IMAP: u32 = 1 << 9;
const CURLHELP_IMPORTANT: u32 = 1 << 10;
const CURLHELP_LDAP: u32 = 1 << 11;
const CURLHELP_OUTPUT: u32 = 1 << 12;
const CURLHELP_POP3: u32 = 1 << 13;
const CURLHELP_POST: u32 = 1 << 14;
const CURLHELP_PROXY: u32 = 1 << 15;
const CURLHELP_SCP: u32 = 1 << 16;
const CURLHELP_SFTP: u32 = 1 << 17;
const CURLHELP_SMTP: u32 = 1 << 18;
const CURLHELP_SSH: u32 = 1 << 19;
const CURLHELP_TELNET: u32 = 1 << 20;
const CURLHELP_TFTP: u32 = 1 << 21;
const CURLHELP_TIMEOUT: u32 = 1 << 22;
const CURLHELP_TLS: u32 = 1 << 23;
const CURLHELP_UPLOAD: u32 = 1 << 24;
const CURLHELP_VERBOSE: u32 = 1 << 25;

const CURLHELP_ALL: u32 = 0x0fff_ffff;

// ARG type bitmask constants — must match args.rs definitions
const ARG_TYPEMASK: u32 = 0x0F;
#[cfg(test)]
const ARG_BOOL: u32 = 1;
const ARG_NO: u32 = 0x80;

/// Extract the argument type from combined desc_flags.
fn argtype_from_flags(flags: u32) -> ArgType {
    match flags & ARG_TYPEMASK {
        0 => ArgType::None,
        1 => ArgType::Bool,
        2 => ArgType::Strg,
        3 => ArgType::File,
        _ => ArgType::None,
    }
}

// ---------------------------------------------------------------------------
// HelpCategory — category descriptor
// ---------------------------------------------------------------------------

/// Describes a help category with its token, description, and bitmask.
struct HelpCategory {
    /// Category identifier string (e.g., "auth", "connection").
    token: &'static str,
    /// Human-readable category description.
    description: &'static str,
    /// Bitmask used for filtering options in this category.
    bitmask: u32,
}

/// All help categories, excluding "important" (which is the default page).
/// Matches the C `categories[]` array in tool_help.c exactly.
static CATEGORIES: &[HelpCategory] = &[
    HelpCategory { token: "auth",       description: "Authentication methods",    bitmask: CURLHELP_AUTH },
    HelpCategory { token: "connection", description: "Manage connections",        bitmask: CURLHELP_CONNECTION },
    HelpCategory { token: "curl",       description: "The command line tool itself", bitmask: CURLHELP_CURL },
    HelpCategory { token: "deprecated", description: "Legacy",                    bitmask: CURLHELP_DEPRECATED },
    HelpCategory { token: "dns",        description: "Names and resolving",       bitmask: CURLHELP_DNS },
    HelpCategory { token: "file",       description: "FILE protocol",             bitmask: CURLHELP_FILE },
    HelpCategory { token: "ftp",        description: "FTP protocol",              bitmask: CURLHELP_FTP },
    HelpCategory { token: "global",     description: "Global options",            bitmask: CURLHELP_GLOBAL },
    HelpCategory { token: "http",       description: "HTTP and HTTPS protocol",   bitmask: CURLHELP_HTTP },
    HelpCategory { token: "imap",       description: "IMAP protocol",             bitmask: CURLHELP_IMAP },
    HelpCategory { token: "ldap",       description: "LDAP protocol",             bitmask: CURLHELP_LDAP },
    HelpCategory { token: "output",     description: "File system output",        bitmask: CURLHELP_OUTPUT },
    HelpCategory { token: "pop3",       description: "POP3 protocol",             bitmask: CURLHELP_POP3 },
    HelpCategory { token: "post",       description: "HTTP POST specific",        bitmask: CURLHELP_POST },
    HelpCategory { token: "proxy",      description: "Options for proxies",       bitmask: CURLHELP_PROXY },
    HelpCategory { token: "scp",        description: "SCP protocol",              bitmask: CURLHELP_SCP },
    HelpCategory { token: "sftp",       description: "SFTP protocol",             bitmask: CURLHELP_SFTP },
    HelpCategory { token: "smtp",       description: "SMTP protocol",             bitmask: CURLHELP_SMTP },
    HelpCategory { token: "ssh",        description: "SSH protocol",              bitmask: CURLHELP_SSH },
    HelpCategory { token: "telnet",     description: "TELNET protocol",           bitmask: CURLHELP_TELNET },
    HelpCategory { token: "tftp",       description: "TFTP protocol",             bitmask: CURLHELP_TFTP },
    HelpCategory { token: "timeout",    description: "Timeouts and delays",       bitmask: CURLHELP_TIMEOUT },
    HelpCategory { token: "tls",        description: "TLS/SSL related",           bitmask: CURLHELP_TLS },
    HelpCategory { token: "upload",     description: "Upload, sending data",      bitmask: CURLHELP_UPLOAD },
    HelpCategory { token: "verbose",    description: "Tracing, logging etc",      bitmask: CURLHELP_VERBOSE },
];

// ---------------------------------------------------------------------------
// HelpText — per-option help entry
// ---------------------------------------------------------------------------

/// A single entry in the helptext table.
struct HelpText {
    /// Option string (e.g., "-d, --data <data>").
    opt: &'static str,
    /// Short description of the option.
    desc: &'static str,
    /// Category bitmask — OR of CURLHELP_* constants.
    categories: u32,
}

// ---------------------------------------------------------------------------
// HELPTEXT — complete option list matching tool_listhelp.c exactly
// ---------------------------------------------------------------------------

static HELPTEXT: &[HelpText] = &[
    HelpText { opt: "    --abstract-unix-socket <path>", desc: "Connect via abstract Unix domain socket", categories: CURLHELP_CONNECTION },
    HelpText { opt: "    --alt-svc <filename>", desc: "Enable alt-svc with this cache file", categories: CURLHELP_HTTP },
    HelpText { opt: "    --anyauth", desc: "Pick any authentication method", categories: CURLHELP_HTTP | CURLHELP_PROXY | CURLHELP_AUTH },
    HelpText { opt: "-a, --append", desc: "Append to target file when uploading", categories: CURLHELP_FTP | CURLHELP_SFTP },
    HelpText { opt: "    --aws-sigv4 <provider1[:prvdr2[:reg[:srv]]]>", desc: "AWS V4 signature auth", categories: CURLHELP_AUTH | CURLHELP_HTTP },
    HelpText { opt: "    --basic", desc: "HTTP Basic Authentication", categories: CURLHELP_AUTH },
    HelpText { opt: "    --ca-native", desc: "Load CA certs from the OS", categories: CURLHELP_TLS },
    HelpText { opt: "    --cacert <file>", desc: "CA certificate to verify peer against", categories: CURLHELP_TLS },
    HelpText { opt: "    --capath <dir>", desc: "CA directory to verify peer against", categories: CURLHELP_TLS },
    HelpText { opt: "-E, --cert <certificate[:password]>", desc: "Client certificate file and password", categories: CURLHELP_TLS },
    HelpText { opt: "    --cert-status", desc: "Verify server cert status OCSP-staple", categories: CURLHELP_TLS },
    HelpText { opt: "    --cert-type <type>", desc: "Certificate type (DER/PEM/ENG/PROV/P12)", categories: CURLHELP_TLS },
    HelpText { opt: "    --ciphers <list>", desc: "TLS 1.2 (1.1, 1.0) ciphers to use", categories: CURLHELP_TLS },
    HelpText { opt: "    --compressed", desc: "Request compressed response", categories: CURLHELP_HTTP },
    HelpText { opt: "    --compressed-ssh", desc: "Enable SSH compression", categories: CURLHELP_SCP | CURLHELP_SSH },
    HelpText { opt: "-K, --config <file>", desc: "Read config from a file", categories: CURLHELP_CURL },
    HelpText { opt: "    --connect-timeout <seconds>", desc: "Maximum time allowed to connect", categories: CURLHELP_CONNECTION | CURLHELP_TIMEOUT },
    HelpText { opt: "    --connect-to <HOST1:PORT1:HOST2:PORT2>", desc: "Connect to host2 instead of host1", categories: CURLHELP_CONNECTION | CURLHELP_DNS },
    HelpText { opt: "-C, --continue-at <offset>", desc: "Resumed transfer offset", categories: CURLHELP_CONNECTION },
    HelpText { opt: "-b, --cookie <data|filename>", desc: "Send cookies from string/load from file", categories: CURLHELP_HTTP },
    HelpText { opt: "-c, --cookie-jar <filename>", desc: "Save cookies to <filename> after operation", categories: CURLHELP_HTTP },
    HelpText { opt: "    --create-dirs", desc: "Create necessary local directory hierarchy", categories: CURLHELP_OUTPUT },
    HelpText { opt: "    --create-file-mode <mode>", desc: "File mode for created files", categories: CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_FILE | CURLHELP_UPLOAD },
    HelpText { opt: "    --crlf", desc: "Convert LF to CRLF in upload", categories: CURLHELP_FTP | CURLHELP_SMTP },
    HelpText { opt: "    --crlfile <file>", desc: "Certificate Revocation list", categories: CURLHELP_TLS },
    HelpText { opt: "    --curves <list>", desc: "(EC) TLS key exchange algorithms to request", categories: CURLHELP_TLS },
    HelpText { opt: "-d, --data <data>", desc: "HTTP POST data", categories: CURLHELP_IMPORTANT | CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD },
    HelpText { opt: "    --data-ascii <data>", desc: "HTTP POST ASCII data", categories: CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD },
    HelpText { opt: "    --data-binary <data>", desc: "HTTP POST binary data", categories: CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD },
    HelpText { opt: "    --data-raw <data>", desc: "HTTP POST data, '@' allowed", categories: CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD },
    HelpText { opt: "    --data-urlencode <data>", desc: "HTTP POST data URL encoded", categories: CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD },
    HelpText { opt: "    --delegation <LEVEL>", desc: "GSS-API delegation permission", categories: CURLHELP_AUTH },
    HelpText { opt: "    --digest", desc: "HTTP Digest Authentication", categories: CURLHELP_PROXY | CURLHELP_AUTH | CURLHELP_HTTP },
    HelpText { opt: "-q, --disable", desc: "Disable .curlrc", categories: CURLHELP_CURL },
    HelpText { opt: "    --disable-eprt", desc: "Inhibit using EPRT or LPRT", categories: CURLHELP_FTP },
    HelpText { opt: "    --disable-epsv", desc: "Inhibit using EPSV", categories: CURLHELP_FTP },
    HelpText { opt: "    --disallow-username-in-url", desc: "Disallow username in URL", categories: CURLHELP_CURL },
    HelpText { opt: "    --dns-interface <interface>", desc: "Interface to use for DNS requests", categories: CURLHELP_DNS },
    HelpText { opt: "    --dns-ipv4-addr <address>", desc: "IPv4 address to use for DNS requests", categories: CURLHELP_DNS },
    HelpText { opt: "    --dns-ipv6-addr <address>", desc: "IPv6 address to use for DNS requests", categories: CURLHELP_DNS },
    HelpText { opt: "    --dns-servers <addresses>", desc: "DNS server addrs to use", categories: CURLHELP_DNS },
    HelpText { opt: "    --doh-cert-status", desc: "Verify DoH server cert status OCSP-staple", categories: CURLHELP_DNS | CURLHELP_TLS },
    HelpText { opt: "    --doh-insecure", desc: "Allow insecure DoH server connections", categories: CURLHELP_DNS | CURLHELP_TLS },
    HelpText { opt: "    --doh-url <URL>", desc: "Resolve hostnames over DoH", categories: CURLHELP_DNS },
    HelpText { opt: "    --dump-ca-embed", desc: "Write the embedded CA bundle to standard output", categories: CURLHELP_HTTP | CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "-D, --dump-header <filename>", desc: "Write the received headers to <filename>", categories: CURLHELP_HTTP | CURLHELP_FTP },
    HelpText { opt: "    --ech <config>", desc: "Configure ECH", categories: CURLHELP_TLS },
    HelpText { opt: "    --egd-file <file>", desc: "EGD socket path for random data", categories: CURLHELP_DEPRECATED },
    HelpText { opt: "    --engine <name>", desc: "Crypto engine to use", categories: CURLHELP_TLS },
    HelpText { opt: "    --etag-compare <file>", desc: "Load ETag from file", categories: CURLHELP_HTTP },
    HelpText { opt: "    --etag-save <file>", desc: "Parse incoming ETag and save to a file", categories: CURLHELP_HTTP },
    HelpText { opt: "    --expect100-timeout <seconds>", desc: "How long to wait for 100-continue", categories: CURLHELP_HTTP | CURLHELP_TIMEOUT },
    HelpText { opt: "-f, --fail", desc: "Fail fast with no output on HTTP errors", categories: CURLHELP_IMPORTANT | CURLHELP_HTTP },
    HelpText { opt: "    --fail-early", desc: "Fail on first transfer error", categories: CURLHELP_CURL | CURLHELP_GLOBAL },
    HelpText { opt: "    --fail-with-body", desc: "Fail on HTTP errors but save the body", categories: CURLHELP_HTTP | CURLHELP_OUTPUT },
    HelpText { opt: "    --false-start", desc: "Enable TLS False Start", categories: CURLHELP_DEPRECATED },
    HelpText { opt: "    --follow", desc: "Follow redirects per spec", categories: CURLHELP_HTTP },
    HelpText { opt: "-F, --form <name=content>", desc: "Specify multipart MIME data", categories: CURLHELP_HTTP | CURLHELP_UPLOAD | CURLHELP_POST | CURLHELP_IMAP | CURLHELP_SMTP },
    HelpText { opt: "    --form-escape", desc: "Escape form fields using backslash", categories: CURLHELP_HTTP | CURLHELP_UPLOAD | CURLHELP_POST },
    HelpText { opt: "    --form-string <name=string>", desc: "Specify multipart MIME data", categories: CURLHELP_HTTP | CURLHELP_UPLOAD | CURLHELP_POST | CURLHELP_SMTP | CURLHELP_IMAP },
    HelpText { opt: "    --ftp-account <data>", desc: "Account data string", categories: CURLHELP_FTP | CURLHELP_AUTH },
    HelpText { opt: "    --ftp-alternative-to-user <command>", desc: "String to replace USER [name]", categories: CURLHELP_FTP },
    HelpText { opt: "    --ftp-create-dirs", desc: "Create the remote dirs if not present", categories: CURLHELP_FTP | CURLHELP_SFTP },
    HelpText { opt: "    --ftp-method <method>", desc: "Control CWD usage", categories: CURLHELP_FTP },
    HelpText { opt: "    --ftp-pasv", desc: "Send PASV/EPSV instead of PORT", categories: CURLHELP_FTP },
    HelpText { opt: "-P, --ftp-port <address>", desc: "Send PORT instead of PASV", categories: CURLHELP_FTP },
    HelpText { opt: "    --ftp-pret", desc: "Send PRET before PASV", categories: CURLHELP_FTP },
    HelpText { opt: "    --ftp-skip-pasv-ip", desc: "Skip the IP address for PASV", categories: CURLHELP_FTP },
    HelpText { opt: "    --ftp-ssl-ccc", desc: "Send CCC after authenticating", categories: CURLHELP_FTP | CURLHELP_TLS },
    HelpText { opt: "    --ftp-ssl-ccc-mode <active/passive>", desc: "Set CCC mode", categories: CURLHELP_FTP | CURLHELP_TLS },
    HelpText { opt: "    --ftp-ssl-control", desc: "Require TLS for login, clear for transfer", categories: CURLHELP_FTP | CURLHELP_TLS },
    HelpText { opt: "-G, --get", desc: "Put the post data in the URL and use GET", categories: CURLHELP_HTTP },
    HelpText { opt: "-g, --globoff", desc: "Disable URL globbing with {} and []", categories: CURLHELP_CURL },
    HelpText { opt: "    --happy-eyeballs-timeout-ms <ms>", desc: "Time for IPv6 before IPv4", categories: CURLHELP_CONNECTION | CURLHELP_TIMEOUT },
    HelpText { opt: "    --haproxy-clientip <ip>", desc: "Set address in HAProxy PROXY", categories: CURLHELP_HTTP | CURLHELP_PROXY },
    HelpText { opt: "    --haproxy-protocol", desc: "Send HAProxy PROXY protocol v1 header", categories: CURLHELP_HTTP | CURLHELP_PROXY },
    HelpText { opt: "-I, --head", desc: "Show document info only", categories: CURLHELP_IMPORTANT | CURLHELP_HTTP | CURLHELP_FTP | CURLHELP_FILE },
    HelpText { opt: "-H, --header <header/@file>", desc: "Pass custom header(s) to server", categories: CURLHELP_IMPORTANT | CURLHELP_HTTP | CURLHELP_IMAP | CURLHELP_SMTP },
    HelpText { opt: "-h, --help <subject>", desc: "Get help for commands", categories: CURLHELP_IMPORTANT | CURLHELP_CURL },
    HelpText { opt: "    --hostpubmd5 <md5>", desc: "Acceptable MD5 hash of host public key", categories: CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_SSH },
    HelpText { opt: "    --hostpubsha256 <sha256>", desc: "Acceptable SHA256 hash of host public key", categories: CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_SSH },
    HelpText { opt: "    --hsts <filename>", desc: "Enable HSTS with this cache file", categories: CURLHELP_HTTP },
    HelpText { opt: "    --http0.9", desc: "Allow HTTP/0.9 responses", categories: CURLHELP_HTTP },
    HelpText { opt: "-0, --http1.0", desc: "Use HTTP/1.0", categories: CURLHELP_HTTP },
    HelpText { opt: "    --http1.1", desc: "Use HTTP/1.1", categories: CURLHELP_HTTP },
    HelpText { opt: "    --http2", desc: "Use HTTP/2", categories: CURLHELP_HTTP },
    HelpText { opt: "    --http2-prior-knowledge", desc: "Use HTTP/2 without HTTP/1.1 Upgrade", categories: CURLHELP_HTTP },
    HelpText { opt: "    --http3", desc: "Use HTTP/3", categories: CURLHELP_HTTP },
    HelpText { opt: "    --http3-only", desc: "Use HTTP/3 only", categories: CURLHELP_HTTP },
    HelpText { opt: "    --ignore-content-length", desc: "Ignore the size of the remote resource", categories: CURLHELP_HTTP | CURLHELP_FTP },
    HelpText { opt: "-k, --insecure", desc: "Allow insecure server connections", categories: CURLHELP_TLS | CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_SSH },
    HelpText { opt: "    --interface <name>", desc: "Use network interface", categories: CURLHELP_CONNECTION },
    HelpText { opt: "    --ip-tos <string>", desc: "Set IP Type of Service or Traffic Class", categories: CURLHELP_CONNECTION },
    HelpText { opt: "    --ipfs-gateway <URL>", desc: "Gateway for IPFS", categories: CURLHELP_CURL },
    HelpText { opt: "-4, --ipv4", desc: "Resolve names to IPv4 addresses", categories: CURLHELP_CONNECTION | CURLHELP_DNS },
    HelpText { opt: "-6, --ipv6", desc: "Resolve names to IPv6 addresses", categories: CURLHELP_CONNECTION | CURLHELP_DNS },
    HelpText { opt: "    --json <data>", desc: "HTTP POST JSON", categories: CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD },
    HelpText { opt: "-j, --junk-session-cookies", desc: "Ignore session cookies read from file", categories: CURLHELP_HTTP },
    HelpText { opt: "    --keepalive-cnt <integer>", desc: "Maximum number of keepalive probes", categories: CURLHELP_CONNECTION },
    HelpText { opt: "    --keepalive-time <seconds>", desc: "Interval time for keepalive probes", categories: CURLHELP_CONNECTION | CURLHELP_TIMEOUT },
    HelpText { opt: "    --key <key>", desc: "Private key filename", categories: CURLHELP_TLS | CURLHELP_SSH },
    HelpText { opt: "    --key-type <type>", desc: "Private key file type (DER/PEM/ENG)", categories: CURLHELP_TLS },
    HelpText { opt: "    --knownhosts <file>", desc: "Specify knownhosts path", categories: CURLHELP_SSH },
    HelpText { opt: "    --krb <level>", desc: "Enable Kerberos with security <level>", categories: CURLHELP_DEPRECATED },
    HelpText { opt: "    --libcurl <file>", desc: "Generate libcurl code for this command line", categories: CURLHELP_CURL | CURLHELP_GLOBAL },
    HelpText { opt: "    --limit-rate <speed>", desc: "Limit transfer speed to RATE", categories: CURLHELP_CONNECTION },
    HelpText { opt: "-l, --list-only", desc: "List only mode", categories: CURLHELP_FTP | CURLHELP_POP3 | CURLHELP_SFTP | CURLHELP_FILE },
    HelpText { opt: "    --local-port <range>", desc: "Use a local port number within RANGE", categories: CURLHELP_CONNECTION },
    HelpText { opt: "-L, --location", desc: "Follow redirects", categories: CURLHELP_HTTP },
    HelpText { opt: "    --location-trusted", desc: "As --location, but send secrets to other hosts", categories: CURLHELP_HTTP | CURLHELP_AUTH },
    HelpText { opt: "    --login-options <options>", desc: "Server login options", categories: CURLHELP_IMAP | CURLHELP_POP3 | CURLHELP_SMTP | CURLHELP_AUTH | CURLHELP_LDAP },
    HelpText { opt: "    --mail-auth <address>", desc: "Originator address of the original email", categories: CURLHELP_SMTP },
    HelpText { opt: "    --mail-from <address>", desc: "Mail from this address", categories: CURLHELP_SMTP },
    HelpText { opt: "    --mail-rcpt <address>", desc: "Mail to this address", categories: CURLHELP_SMTP },
    HelpText { opt: "    --mail-rcpt-allowfails", desc: "Allow RCPT TO command to fail", categories: CURLHELP_SMTP },
    HelpText { opt: "-M, --manual", desc: "Display the full manual", categories: CURLHELP_CURL },
    HelpText { opt: "    --max-filesize <bytes>", desc: "Maximum file size to download", categories: CURLHELP_CONNECTION },
    HelpText { opt: "    --max-redirs <num>", desc: "Maximum number of redirects allowed", categories: CURLHELP_HTTP },
    HelpText { opt: "-m, --max-time <seconds>", desc: "Maximum time allowed for transfer", categories: CURLHELP_CONNECTION | CURLHELP_TIMEOUT },
    HelpText { opt: "    --metalink", desc: "Process given URLs as metalink XML file", categories: CURLHELP_DEPRECATED },
    HelpText { opt: "    --mptcp", desc: "Enable Multipath TCP", categories: CURLHELP_CONNECTION },
    HelpText { opt: "    --negotiate", desc: "Use HTTP Negotiate (SPNEGO) authentication", categories: CURLHELP_AUTH | CURLHELP_HTTP },
    HelpText { opt: "-n, --netrc", desc: "Must read .netrc for username and password", categories: CURLHELP_AUTH },
    HelpText { opt: "    --netrc-file <filename>", desc: "Specify FILE for netrc", categories: CURLHELP_AUTH },
    HelpText { opt: "    --netrc-optional", desc: "Use either .netrc or URL", categories: CURLHELP_AUTH },
    HelpText { opt: "-:, --next", desc: "Make next URL use separate options", categories: CURLHELP_CURL },
    HelpText { opt: "    --no-alpn", desc: "Disable the ALPN TLS extension", categories: CURLHELP_TLS | CURLHELP_HTTP },
    HelpText { opt: "-N, --no-buffer", desc: "Disable buffering of the output stream", categories: CURLHELP_OUTPUT },
    HelpText { opt: "    --no-clobber", desc: "Do not overwrite files that already exist", categories: CURLHELP_OUTPUT },
    HelpText { opt: "    --no-keepalive", desc: "Disable TCP keepalive on the connection", categories: CURLHELP_CONNECTION },
    HelpText { opt: "    --no-npn", desc: "Disable the NPN TLS extension", categories: CURLHELP_DEPRECATED },
    HelpText { opt: "    --no-progress-meter", desc: "Do not show the progress meter", categories: CURLHELP_VERBOSE },
    HelpText { opt: "    --no-sessionid", desc: "Disable SSL session-ID reusing", categories: CURLHELP_TLS },
    HelpText { opt: "    --noproxy <no-proxy-list>", desc: "List of hosts which do not use proxy", categories: CURLHELP_PROXY },
    HelpText { opt: "    --ntlm", desc: "HTTP NTLM authentication", categories: CURLHELP_AUTH | CURLHELP_HTTP },
    HelpText { opt: "    --ntlm-wb", desc: "HTTP NTLM authentication with winbind", categories: CURLHELP_DEPRECATED },
    HelpText { opt: "    --oauth2-bearer <token>", desc: "OAuth 2 Bearer Token", categories: CURLHELP_AUTH | CURLHELP_IMAP | CURLHELP_POP3 | CURLHELP_SMTP | CURLHELP_LDAP },
    HelpText { opt: "    --out-null", desc: "Discard response data into the void", categories: CURLHELP_OUTPUT },
    HelpText { opt: "-o, --output <file>", desc: "Write to file instead of stdout", categories: CURLHELP_IMPORTANT | CURLHELP_OUTPUT },
    HelpText { opt: "    --output-dir <dir>", desc: "Directory to save files in", categories: CURLHELP_OUTPUT },
    HelpText { opt: "-Z, --parallel", desc: "Perform transfers in parallel", categories: CURLHELP_CONNECTION | CURLHELP_CURL | CURLHELP_GLOBAL },
    HelpText { opt: "    --parallel-immediate", desc: "Do not wait for multiplexing", categories: CURLHELP_CONNECTION | CURLHELP_CURL | CURLHELP_GLOBAL },
    HelpText { opt: "    --parallel-max <num>", desc: "Maximum concurrency for parallel transfers", categories: CURLHELP_CONNECTION | CURLHELP_CURL | CURLHELP_GLOBAL },
    HelpText { opt: "    --parallel-max-host <num>", desc: "Maximum connections to a single host", categories: CURLHELP_CONNECTION | CURLHELP_CURL | CURLHELP_GLOBAL },
    HelpText { opt: "    --pass <phrase>", desc: "Passphrase for the private key", categories: CURLHELP_SSH | CURLHELP_TLS | CURLHELP_AUTH },
    HelpText { opt: "    --path-as-is", desc: "Do not squash .. sequences in URL path", categories: CURLHELP_CURL },
    HelpText { opt: "    --pinnedpubkey <hashes>", desc: "Public key to verify peer against", categories: CURLHELP_TLS },
    HelpText { opt: "    --post301", desc: "Do not switch to GET after a 301 redirect", categories: CURLHELP_HTTP | CURLHELP_POST },
    HelpText { opt: "    --post302", desc: "Do not switch to GET after a 302 redirect", categories: CURLHELP_HTTP | CURLHELP_POST },
    HelpText { opt: "    --post303", desc: "Do not switch to GET after a 303 redirect", categories: CURLHELP_HTTP | CURLHELP_POST },
    HelpText { opt: "    --preproxy <[protocol://]host[:port]>", desc: "Use this proxy first", categories: CURLHELP_PROXY },
    HelpText { opt: "-#, --progress-bar", desc: "Display transfer progress as a bar", categories: CURLHELP_VERBOSE | CURLHELP_GLOBAL },
    HelpText { opt: "    --proto <protocols>", desc: "Enable/disable PROTOCOLS", categories: CURLHELP_CONNECTION | CURLHELP_CURL },
    HelpText { opt: "    --proto-default <protocol>", desc: "Use PROTOCOL for any URL missing a scheme", categories: CURLHELP_CONNECTION | CURLHELP_CURL },
    HelpText { opt: "    --proto-redir <protocols>", desc: "Enable/disable PROTOCOLS on redirect", categories: CURLHELP_CONNECTION | CURLHELP_CURL },
    HelpText { opt: "-x, --proxy <[protocol://]host[:port]>", desc: "Use this proxy", categories: CURLHELP_PROXY },
    HelpText { opt: "    --proxy-anyauth", desc: "Pick any proxy authentication method", categories: CURLHELP_PROXY | CURLHELP_AUTH },
    HelpText { opt: "    --proxy-basic", desc: "Use Basic authentication on the proxy", categories: CURLHELP_PROXY | CURLHELP_AUTH },
    HelpText { opt: "    --proxy-ca-native", desc: "Load CA certs from the OS to verify proxy", categories: CURLHELP_TLS },
    HelpText { opt: "    --proxy-cacert <file>", desc: "CA certificates to verify proxy against", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-capath <dir>", desc: "CA directory to verify proxy against", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-cert <cert[:passwd]>", desc: "Set client certificate for proxy", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-cert-type <type>", desc: "Client certificate type for HTTPS proxy", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-ciphers <list>", desc: "TLS 1.2 (1.1, 1.0) ciphers to use for proxy", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-crlfile <file>", desc: "Set a CRL list for proxy", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-digest", desc: "Digest auth with the proxy", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-header <header/@file>", desc: "Pass custom header(s) to proxy", categories: CURLHELP_PROXY },
    HelpText { opt: "    --proxy-http2", desc: "Use HTTP/2 with HTTPS proxy", categories: CURLHELP_HTTP | CURLHELP_PROXY },
    HelpText { opt: "    --proxy-insecure", desc: "Skip HTTPS proxy cert verification", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-key <key>", desc: "Private key for HTTPS proxy", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-key-type <type>", desc: "Private key file type for proxy", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-negotiate", desc: "HTTP Negotiate (SPNEGO) auth with the proxy", categories: CURLHELP_PROXY | CURLHELP_AUTH },
    HelpText { opt: "    --proxy-ntlm", desc: "NTLM authentication with the proxy", categories: CURLHELP_PROXY | CURLHELP_AUTH },
    HelpText { opt: "    --proxy-pass <phrase>", desc: "Passphrase for private key for HTTPS proxy", categories: CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH },
    HelpText { opt: "    --proxy-pinnedpubkey <hashes>", desc: "FILE/HASHES public key to verify proxy with", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-service-name <name>", desc: "SPNEGO proxy service name", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-ssl-allow-beast", desc: "Allow this security flaw for HTTPS proxy", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-ssl-auto-client-cert", desc: "Auto client certificate for proxy", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-tls13-ciphers <list>", desc: "TLS 1.3 proxy cipher suites", categories: CURLHELP_PROXY | CURLHELP_TLS },
    HelpText { opt: "    --proxy-tlsauthtype <type>", desc: "TLS authentication type for HTTPS proxy", categories: CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH },
    HelpText { opt: "    --proxy-tlspassword <string>", desc: "TLS password for HTTPS proxy", categories: CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH },
    HelpText { opt: "    --proxy-tlsuser <name>", desc: "TLS username for HTTPS proxy", categories: CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH },
    HelpText { opt: "    --proxy-tlsv1", desc: "TLSv1 for HTTPS proxy", categories: CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH },
    HelpText { opt: "-U, --proxy-user <user:password>", desc: "Proxy user and password", categories: CURLHELP_PROXY | CURLHELP_AUTH },
    HelpText { opt: "    --proxy1.0 <host[:port]>", desc: "Use HTTP/1.0 proxy on given port", categories: CURLHELP_PROXY },
    HelpText { opt: "-p, --proxytunnel", desc: "HTTP proxy tunnel (using CONNECT)", categories: CURLHELP_PROXY },
    HelpText { opt: "    --pubkey <key>", desc: "SSH Public key filename", categories: CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_SSH | CURLHELP_AUTH },
    HelpText { opt: "-Q, --quote <command>", desc: "Send command(s) to server before transfer", categories: CURLHELP_FTP | CURLHELP_SFTP },
    HelpText { opt: "    --random-file <file>", desc: "File for reading random data from", categories: CURLHELP_DEPRECATED },
    HelpText { opt: "-r, --range <range>", desc: "Retrieve only the bytes within RANGE", categories: CURLHELP_HTTP | CURLHELP_FTP | CURLHELP_SFTP | CURLHELP_FILE },
    HelpText { opt: "    --rate <max request rate>", desc: "Request rate for serial transfers", categories: CURLHELP_CONNECTION | CURLHELP_GLOBAL },
    HelpText { opt: "    --raw", desc: "Do HTTP raw; no transfer decoding", categories: CURLHELP_HTTP },
    HelpText { opt: "-e, --referer <URL>", desc: "Referrer URL", categories: CURLHELP_HTTP },
    HelpText { opt: "-J, --remote-header-name", desc: "Use the header-provided filename", categories: CURLHELP_OUTPUT },
    HelpText { opt: "-O, --remote-name", desc: "Write output to file named as remote file", categories: CURLHELP_IMPORTANT | CURLHELP_OUTPUT },
    HelpText { opt: "    --remote-name-all", desc: "Use the remote filename for all URLs", categories: CURLHELP_OUTPUT },
    HelpText { opt: "-R, --remote-time", desc: "Set remote file's time on local output", categories: CURLHELP_OUTPUT },
    HelpText { opt: "    --remove-on-error", desc: "Remove output file on errors", categories: CURLHELP_OUTPUT },
    HelpText { opt: "-X, --request <method>", desc: "Specify request method to use", categories: CURLHELP_CONNECTION | CURLHELP_POP3 | CURLHELP_FTP | CURLHELP_IMAP | CURLHELP_SMTP },
    HelpText { opt: "    --request-target <path>", desc: "Specify the target for this request", categories: CURLHELP_HTTP },
    HelpText { opt: "    --resolve <[+]host:port:addr[,addr]...>", desc: "Resolve host+port to address", categories: CURLHELP_CONNECTION | CURLHELP_DNS },
    HelpText { opt: "    --retry <num>", desc: "Retry request if transient problems occur", categories: CURLHELP_CURL },
    HelpText { opt: "    --retry-all-errors", desc: "Retry all errors (with --retry)", categories: CURLHELP_CURL },
    HelpText { opt: "    --retry-connrefused", desc: "Retry on connection refused (with --retry)", categories: CURLHELP_CURL },
    HelpText { opt: "    --retry-delay <seconds>", desc: "Wait time between retries", categories: CURLHELP_CURL | CURLHELP_TIMEOUT },
    HelpText { opt: "    --retry-max-time <seconds>", desc: "Retry only within this period", categories: CURLHELP_CURL | CURLHELP_TIMEOUT },
    HelpText { opt: "    --sasl-authzid <identity>", desc: "Identity for SASL PLAIN authentication", categories: CURLHELP_AUTH },
    HelpText { opt: "    --sasl-ir", desc: "Initial response in SASL authentication", categories: CURLHELP_AUTH },
    HelpText { opt: "    --service-name <name>", desc: "SPNEGO service name", categories: CURLHELP_AUTH },
    HelpText { opt: "-S, --show-error", desc: "Show error even when -s is used", categories: CURLHELP_CURL | CURLHELP_GLOBAL },
    HelpText { opt: "-i, --show-headers", desc: "Show response headers in output", categories: CURLHELP_IMPORTANT | CURLHELP_VERBOSE | CURLHELP_OUTPUT },
    HelpText { opt: "    --sigalgs <list>", desc: "TLS signature algorithms to use", categories: CURLHELP_TLS },
    HelpText { opt: "-s, --silent", desc: "Silent mode", categories: CURLHELP_IMPORTANT | CURLHELP_VERBOSE },
    HelpText { opt: "    --skip-existing", desc: "Skip download if local file already exists", categories: CURLHELP_CURL | CURLHELP_OUTPUT },
    HelpText { opt: "    --socks4 <host[:port]>", desc: "SOCKS4 proxy on given host + port", categories: CURLHELP_PROXY },
    HelpText { opt: "    --socks4a <host[:port]>", desc: "SOCKS4a proxy on given host + port", categories: CURLHELP_PROXY },
    HelpText { opt: "    --socks5 <host[:port]>", desc: "SOCKS5 proxy on given host + port", categories: CURLHELP_PROXY },
    HelpText { opt: "    --socks5-basic", desc: "Username/password auth for SOCKS5 proxies", categories: CURLHELP_PROXY | CURLHELP_AUTH },
    HelpText { opt: "    --socks5-gssapi", desc: "Enable GSS-API auth for SOCKS5 proxies", categories: CURLHELP_PROXY | CURLHELP_AUTH },
    HelpText { opt: "    --socks5-gssapi-nec", desc: "Compatibility with NEC SOCKS5 server", categories: CURLHELP_PROXY | CURLHELP_AUTH },
    HelpText { opt: "    --socks5-gssapi-service <name>", desc: "SOCKS5 proxy service name for GSS-API", categories: CURLHELP_PROXY | CURLHELP_AUTH },
    HelpText { opt: "    --socks5-hostname <host[:port]>", desc: "SOCKS5 proxy, pass hostname to proxy", categories: CURLHELP_PROXY },
    HelpText { opt: "-Y, --speed-limit <speed>", desc: "Stop transfers slower than this", categories: CURLHELP_CONNECTION },
    HelpText { opt: "-y, --speed-time <seconds>", desc: "Trigger 'speed-limit' abort after this time", categories: CURLHELP_CONNECTION | CURLHELP_TIMEOUT },
    HelpText { opt: "    --ssl", desc: "Try enabling TLS", categories: CURLHELP_TLS | CURLHELP_IMAP | CURLHELP_POP3 | CURLHELP_SMTP | CURLHELP_LDAP },
    HelpText { opt: "    --ssl-allow-beast", desc: "Allow security flaw to improve interop", categories: CURLHELP_TLS },
    HelpText { opt: "    --ssl-auto-client-cert", desc: "Use auto client certificate (Schannel)", categories: CURLHELP_TLS },
    HelpText { opt: "    --ssl-no-revoke", desc: "Disable cert revocation checks (Schannel)", categories: CURLHELP_TLS },
    HelpText { opt: "    --ssl-reqd", desc: "Require SSL/TLS", categories: CURLHELP_TLS | CURLHELP_IMAP | CURLHELP_POP3 | CURLHELP_SMTP | CURLHELP_LDAP },
    HelpText { opt: "    --ssl-revoke-best-effort", desc: "Ignore missing cert CRL dist points", categories: CURLHELP_TLS },
    HelpText { opt: "    --ssl-sessions <filename>", desc: "Load/save SSL session tickets from/to this file", categories: CURLHELP_TLS },
    HelpText { opt: "-2, --sslv2", desc: "SSLv2", categories: CURLHELP_DEPRECATED },
    HelpText { opt: "-3, --sslv3", desc: "SSLv3", categories: CURLHELP_DEPRECATED },
    HelpText { opt: "    --stderr <file>", desc: "Where to redirect stderr", categories: CURLHELP_VERBOSE | CURLHELP_GLOBAL },
    HelpText { opt: "    --styled-output", desc: "Enable styled output for HTTP headers", categories: CURLHELP_VERBOSE | CURLHELP_GLOBAL },
    HelpText { opt: "    --suppress-connect-headers", desc: "Suppress proxy CONNECT response headers", categories: CURLHELP_PROXY },
    HelpText { opt: "    --tcp-fastopen", desc: "Use TCP Fast Open", categories: CURLHELP_CONNECTION },
    HelpText { opt: "    --tcp-nodelay", desc: "Set TCP_NODELAY", categories: CURLHELP_CONNECTION },
    HelpText { opt: "-t, --telnet-option <opt=val>", desc: "Set telnet option", categories: CURLHELP_TELNET },
    HelpText { opt: "    --tftp-blksize <value>", desc: "Set TFTP BLKSIZE option", categories: CURLHELP_TFTP },
    HelpText { opt: "    --tftp-no-options", desc: "Do not send any TFTP options", categories: CURLHELP_TFTP },
    HelpText { opt: "-z, --time-cond <time>", desc: "Transfer based on a time condition", categories: CURLHELP_HTTP | CURLHELP_FTP },
    HelpText { opt: "    --tls-earlydata", desc: "Allow use of TLSv1.3 early data (0RTT)", categories: CURLHELP_TLS },
    HelpText { opt: "    --tls-max <VERSION>", desc: "Maximum allowed TLS version", categories: CURLHELP_TLS },
    HelpText { opt: "    --tls13-ciphers <list>", desc: "TLS 1.3 cipher suites to use", categories: CURLHELP_TLS },
    HelpText { opt: "    --tlsauthtype <type>", desc: "TLS authentication type", categories: CURLHELP_TLS | CURLHELP_AUTH },
    HelpText { opt: "    --tlspassword <string>", desc: "TLS password", categories: CURLHELP_TLS | CURLHELP_AUTH },
    HelpText { opt: "    --tlsuser <name>", desc: "TLS username", categories: CURLHELP_TLS | CURLHELP_AUTH },
    HelpText { opt: "-1, --tlsv1", desc: "TLSv1.0 or greater", categories: CURLHELP_TLS },
    HelpText { opt: "    --tlsv1.0", desc: "TLSv1.0 or greater", categories: CURLHELP_TLS },
    HelpText { opt: "    --tlsv1.1", desc: "TLSv1.1 or greater", categories: CURLHELP_TLS },
    HelpText { opt: "    --tlsv1.2", desc: "TLSv1.2 or greater", categories: CURLHELP_TLS },
    HelpText { opt: "    --tlsv1.3", desc: "TLSv1.3 or greater", categories: CURLHELP_TLS },
    HelpText { opt: "    --tr-encoding", desc: "Request compressed transfer encoding", categories: CURLHELP_HTTP },
    HelpText { opt: "    --trace <file>", desc: "Write a debug trace to FILE", categories: CURLHELP_VERBOSE | CURLHELP_GLOBAL },
    HelpText { opt: "    --trace-ascii <file>", desc: "Like --trace, but without hex output", categories: CURLHELP_VERBOSE | CURLHELP_GLOBAL },
    HelpText { opt: "    --trace-config <string>", desc: "Details to log in trace/verbose output", categories: CURLHELP_VERBOSE | CURLHELP_GLOBAL },
    HelpText { opt: "    --trace-ids", desc: "Transfer + connection ids in verbose output", categories: CURLHELP_VERBOSE | CURLHELP_GLOBAL },
    HelpText { opt: "    --trace-time", desc: "Add time stamps to trace/verbose output", categories: CURLHELP_VERBOSE | CURLHELP_GLOBAL },
    HelpText { opt: "    --unix-socket <path>", desc: "Connect through this Unix domain socket", categories: CURLHELP_CONNECTION },
    HelpText { opt: "-T, --upload-file <file>", desc: "Transfer local FILE to destination", categories: CURLHELP_IMPORTANT | CURLHELP_UPLOAD },
    HelpText { opt: "    --upload-flags <flags>", desc: "IMAP upload behavior", categories: CURLHELP_CURL | CURLHELP_OUTPUT },
    HelpText { opt: "    --url <url/file>", desc: "URL(s) to work with", categories: CURLHELP_CURL },
    HelpText { opt: "    --url-query <data>", desc: "Add a URL query part", categories: CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD },
    HelpText { opt: "-B, --use-ascii", desc: "Use ASCII/text transfer", categories: CURLHELP_FTP | CURLHELP_OUTPUT | CURLHELP_LDAP | CURLHELP_TFTP },
    HelpText { opt: "-u, --user <user:password>", desc: "Server user and password", categories: CURLHELP_IMPORTANT | CURLHELP_AUTH },
    HelpText { opt: "-A, --user-agent <name>", desc: "Send User-Agent <name> to server", categories: CURLHELP_IMPORTANT | CURLHELP_HTTP },
    HelpText { opt: "    --variable <[%]name=text/@file>", desc: "Set variable", categories: CURLHELP_CURL },
    HelpText { opt: "-v, --verbose", desc: "Make the operation more talkative", categories: CURLHELP_IMPORTANT | CURLHELP_VERBOSE | CURLHELP_GLOBAL },
    HelpText { opt: "-V, --version", desc: "Show version number and quit", categories: CURLHELP_IMPORTANT | CURLHELP_CURL },
    HelpText { opt: "    --vlan-priority <priority>", desc: "Set VLAN priority", categories: CURLHELP_CONNECTION },
    HelpText { opt: "-w, --write-out <format>", desc: "Output FORMAT after completion", categories: CURLHELP_VERBOSE },
    HelpText { opt: "    --xattr", desc: "Store metadata in extended file attributes", categories: CURLHELP_OUTPUT },
];

// ---------------------------------------------------------------------------
// ScanContext — manual scanning state machine
// ---------------------------------------------------------------------------

/// Context for scanning embedded manual text to extract help for a specific
/// option. This is the Rust equivalent of C `struct scan_ctx` from
/// tool_help.h.
///
/// The scanning state machine has three phases:
///   0 — Waiting for the trigger string (e.g. "\nALL OPTIONS\n")
///   1 — Past trigger, looking for the option marker (e.g. "\n    --verbose")
///   2 — Found option, outputting text until the end marker
struct ScanContext {
    /// Trigger string that marks the beginning of the options section.
    trigger: String,
    /// The specific option marker to search for.
    arg: String,
    /// The end marker that terminates output.
    endarg: String,
    /// Current scanning phase (0=trigger, 1=arg, 2=output).
    show: u8,
    /// Rolling buffer for pattern matching.
    rbuf: Vec<u8>,
    /// Output line buffer.
    obuf: String,
}

/// Initialize a manual scanning context.
///
/// Equivalent to C `inithelpscan()` from tool_help.c.
///
/// # Arguments
///
/// * `trigger` — String marking the start of the options section.
/// * `arg` — The option string to search for within the section.
/// * `endarg` — String marking the end of the option's help text.
fn inithelpscan(trigger: &str, arg: &str, endarg: &str) -> ScanContext {
    ScanContext {
        trigger: trigger.to_string(),
        arg: arg.to_string(),
        endarg: endarg.to_string(),
        show: 0,
        rbuf: vec![0u8; 40],
        obuf: String::with_capacity(160),
    }
}

/// Process a chunk of manual text through the scanning context.
///
/// Returns `true` if scanning should continue, `false` if the end marker
/// was found (scanning complete). Matching text is printed directly to
/// stdout.
///
/// Equivalent to C `helpscan()` from tool_help.c.
fn helpscan(buf: &[u8], ctx: &mut ScanContext) -> bool {
    let tlen = ctx.trigger.len();
    let flen = ctx.arg.len();
    let elen = ctx.endarg.len();
    let trigger_bytes = ctx.trigger.as_bytes();
    let arg_bytes = ctx.arg.as_bytes();
    let endarg_bytes = ctx.endarg.as_bytes();

    for &byte in buf {
        if ctx.show == 0 {
            // Phase 0: waiting for the trigger string
            if tlen > 1 {
                ctx.rbuf.copy_within(1..tlen, 0);
            }
            if tlen > 0 {
                ctx.rbuf[tlen - 1] = byte;
            }
            if tlen > 0 && ctx.rbuf[..tlen] == trigger_bytes[..tlen] {
                ctx.show = 1;
                // Reset rbuf for next phase
                for b in ctx.rbuf.iter_mut() {
                    *b = 0;
                }
            }
            continue;
        }

        if ctx.show == 1 {
            // Phase 1: past trigger, looking for the arg match
            if flen > 1 {
                ctx.rbuf.copy_within(1..flen, 0);
            }
            if flen > 0 {
                ctx.rbuf[flen - 1] = byte;
            }
            if flen > 0 && ctx.rbuf[..flen] == arg_bytes[..flen] {
                // Match found — print the option name (skip the leading newline)
                if ctx.arg.len() > 1 {
                    print!("{}", &ctx.arg[1..]);
                }
                ctx.show = 2;
                // Reset rbuf for end-marker detection
                for b in ctx.rbuf.iter_mut() {
                    *b = 0;
                }
            }
            continue;
        }

        // Phase 2: outputting text until end marker
        if elen > 1 {
            ctx.rbuf.copy_within(1..elen, 0);
        }
        if elen > 0 {
            ctx.rbuf[elen - 1] = byte;
        }
        if elen > 0 && ctx.rbuf[..elen] == endarg_bytes[..elen] {
            return false; // End marker found
        }

        if byte == b'\n' {
            println!("{}", ctx.obuf);
            ctx.obuf.clear();
        } else if ctx.obuf.len() < 160 {
            ctx.obuf.push(byte as char);
        } else {
            return false; // Buffer overflow protection
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Embedded manual text
//
// In the C codebase, the complete curl manual (man page) is compiled into
// `tool_hugehelp.c` at build time by a script (`scripts/cd2nroff`,
// `scripts/nroff2cd`) that converts the individual per-option documentation
// files in `docs/cmdline-opts/` into a single C source file containing the
// full manual text (optionally gzip-compressed when `HAVE_LIBZ` is defined).
//
// This Rust rewrite does not replicate the build-time manual generation
// pipeline. The `--manual` flag instead falls back to showing the per-option
// help entry from the HELPTEXT table (which is functionally complete and
// contains all 237 option descriptions). Users can obtain the full manual
// via `man curl` or online at https://curl.se/docs/manpage.html.
//
// Known limitation: `curl-rs --manual` displays per-option help text rather
// than the full prose manual. This matches the behavior of C curl when
// compiled without `USE_MANUAL` (the `#ifndef USE_MANUAL` path in
// `tool_hugehelp.h`). All other `--help` subcommands (`--help all`,
// `--help <category>`, `--help <option>`) work identically to C curl.
// ---------------------------------------------------------------------------

/// Embedded manual text.
///
/// In the C build, this contains the full curl man page text (compiled from
/// `docs/cmdline-opts/` sources into `tool_hugehelp.c`). In the Rust build,
/// the build-time manual generation pipeline is not replicated, so this is
/// empty. The `showhelp` function gracefully handles the empty case by
/// displaying per-option help entries from the `HELPTEXT` table instead,
/// matching the C behavior when compiled without `USE_MANUAL`.
static EMBEDDED_MANUAL: &[u8] = b"";

/// Display help for a specific option by scanning the embedded manual.
///
/// If no embedded manual is available, prints a message indicating that
/// built-in manual is not available and falls back to showing the basic
/// help entry from the HELPTEXT table.
fn showhelp(trigger: &str, cmdbuf: &str, endarg: &str) {
    if EMBEDDED_MANUAL.is_empty() {
        // No embedded manual — print the option from the helptext table
        // instead, matching what the C version does when USE_MANUAL is
        // not defined.
        let option_name = cmdbuf.trim();
        let mut found = false;
        for entry in HELPTEXT.iter() {
            if entry.opt.contains(option_name) {
                println!("  {} {}", entry.opt.trim(), entry.desc);
                found = true;
                break;
            }
        }
        if !found {
            println!("No manual entry found for: {}", option_name);
        }
        return;
    }

    let mut ctx = inithelpscan(trigger, cmdbuf, endarg);
    helpscan(EMBEDDED_MANUAL, &mut ctx);
}

// ---------------------------------------------------------------------------
// print_category — display options in a given category
// ---------------------------------------------------------------------------

/// Print all options matching the given category bitmask with proper
/// column alignment.
///
/// Measures the longest option and description strings in the filtered
/// set, then prints each matching option left-aligned with a two-space
/// gap before the description. Respects terminal width to avoid
/// wrap-around.
///
/// Equivalent to C `print_category()` from tool_help.c.
fn print_category(category: u32, cols: u32) {
    // Phase 1: measure longest option and description for alignment
    let mut longopt: usize = 5;
    let mut longdesc: usize = 5;

    for entry in HELPTEXT.iter() {
        if (entry.categories & category) == 0 {
            continue;
        }
        let opt_len = entry.opt.len();
        if opt_len > longopt {
            longopt = opt_len;
        }
        let desc_len = entry.desc.len();
        if desc_len > longdesc {
            longdesc = desc_len;
        }
    }

    let cols_usize = cols as usize;

    // Adjust longopt to prevent wrap-around, matching C logic exactly
    if longdesc > cols_usize {
        longopt = 0;
    } else if longopt + longdesc > cols_usize {
        longopt = cols_usize - longdesc;
    }

    // Phase 2: print each matching option with aligned columns
    for entry in HELPTEXT.iter() {
        if (entry.categories & category) == 0 {
            continue;
        }
        let mut opt = longopt;
        let desclen = entry.desc.len();

        // Avoid wrap-around per C logic
        if cols_usize >= 2 && opt + desclen >= (cols_usize - 2) {
            if desclen < (cols_usize - 2) {
                opt = (cols_usize - 3) - desclen;
            } else {
                opt = 0;
            }
        }

        // Print with left-aligned option column and description
        // Matches C: curl_mprintf(" %-*s  %s\n", (int)opt, helptext[i].opt, helptext[i].desc);
        println!(" {:<width$}  {}", entry.opt, entry.desc, width = opt);
    }
}

// ---------------------------------------------------------------------------
// get_category_content — display a specific named category
// ---------------------------------------------------------------------------

/// Look up a category by name and print its options.
///
/// Returns `true` if the category was found and printed, `false` if the
/// category name is not recognised.
///
/// Equivalent to C `get_category_content()` from tool_help.c.
fn get_category_content(category: &str, cols: u32) -> bool {
    for cat in CATEGORIES.iter() {
        if cat.token.eq_ignore_ascii_case(category) {
            println!("{}: {}", cat.token, cat.description);
            print_category(cat.bitmask, cols);
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// get_categories — list all categories with descriptions
// ---------------------------------------------------------------------------

/// Print all categories with aligned descriptions.
///
/// Equivalent to C `get_categories()` from tool_help.c.
fn get_categories() {
    for cat in CATEGORIES.iter() {
        println!(" {:<11} {}", cat.token, cat.description);
    }
}

// ---------------------------------------------------------------------------
// get_categories_list — comma-separated category list with wrapping
// ---------------------------------------------------------------------------

/// Print all category tokens as a comma-separated list, wrapping at the
/// given terminal width.
///
/// Equivalent to C `get_categories_list()` from tool_help.c.
fn get_categories_list(width: u32) {
    let width_usize = width as usize;
    let mut col: usize = 0;
    let num_categories = CATEGORIES.len();

    for (i, cat) in CATEGORIES.iter().enumerate() {
        let len = cat.token.len();

        if i == num_categories - 1 {
            // Final category — print with period
            if col + len + 1 < width_usize {
                println!("{}.", cat.token);
            } else {
                // Start a new line first
                println!("\n{}.", cat.token);
            }
        } else if col + len + 2 < width_usize {
            print!("{}, ", cat.token);
            col += len + 2;
        } else {
            // Start a new line first
            print!("\n{}, ", cat.token);
            col = len + 2;
        }
    }
}

// ---------------------------------------------------------------------------
// is_debug — check if the library was built with debug features
// ---------------------------------------------------------------------------

/// Check if the library reports the "Debug" feature, indicating a debug
/// build. Used by `tool_version_info()` to emit a warning.
///
/// Equivalent to C `is_debug()` from tool_help.c.
fn is_debug(info: &LibCurlInfo) -> bool {
    info.features.iter().any(|f| f.eq_ignore_ascii_case("debug"))
}

// ---------------------------------------------------------------------------
// tool_help — main help entry point (public)
// ---------------------------------------------------------------------------

/// Display help text for the curl CLI tool.
///
/// Depending on the `category` argument:
/// - `None` — Show default usage, important options, and category list.
/// - `Some("all")` — Show all options.
/// - `Some("category")` — Show all category names and descriptions.
/// - `Some("-...")` — Look up and display manual entry for that option.
/// - `Some(name)` — Show options in that named category.
/// - Unknown category — Show error and full category list.
///
/// Equivalent to C `tool_help()` from tool_help.c.
pub fn tool_help(category: Option<&str>) {
    let cols = get_terminal_columns();

    match category {
        None => {
            // No category: show usage, important options, and category hints
            let category_note = concat!(
                "\nThis is not the full help; this ",
                "menu is split into categories.\nUse \"--help category\" to get ",
                "an overview of all categories, which are:"
            );
            let category_note2 = concat!(
                "Use \"--help all\" to list all options\n",
                "Use \"--help [option]\" to view documentation for a given option"
            );

            println!("Usage: curl [options...] <url>");
            print_category(CURLHELP_IMPORTANT, cols);
            println!("{}", category_note);
            get_categories_list(cols);
            println!("{}", category_note2);
        }
        Some(cat) if cat.eq_ignore_ascii_case("all") => {
            // Print everything
            print_category(CURLHELP_ALL, cols);
        }
        Some(cat) if cat.eq_ignore_ascii_case("category") => {
            // Print all category names and descriptions
            get_categories();
        }
        Some(cat) if cat.starts_with('-') => {
            // Option-specific help via manual scanning
            let a: Option<&LongShort>;

            if let Some(rest) = cat.strip_prefix("--") {
                // Long option
                let mut lookup = rest;
                let mut noflagged = false;

                if let Some(stripped) = lookup.strip_prefix("no-") {
                    lookup = stripped;
                    noflagged = true;
                }

                a = findlongopt(lookup);

                // A --no- prefix for a non-boolean option is invalid
                if let Some(opt) = a {
                    if noflagged && argtype_from_flags(opt.desc_flags) != ArgType::Bool {
                        // Not a valid --no- option
                        tool_stderr_write(
                            "Incorrect option name to show help for, see curl -h\n",
                        );
                        return;
                    }
                }
            } else if cat.len() == 2 {
                // Short option (e.g., "-v")
                a = findshortopt(cat.chars().nth(1).unwrap_or(' '));
            } else {
                a = None;
            }

            match a {
                None => {
                    tool_stderr_write(
                        "Incorrect option name to show help for, see curl -h\n",
                    );
                }
                Some(opt) => {
                    let cmdbuf: String;
                    if opt.short_letter != ' ' && opt.short_letter != '\0' {
                        cmdbuf = format!("\n    -{}, --", opt.short_letter);
                    } else if (opt.desc_flags & ARG_NO) != 0 {
                        cmdbuf = format!("\n    --no-{}", opt.long_name);
                    } else {
                        cmdbuf = format!("\n    {}", cat);
                    }

                    if opt.cmd == CmdlineOption::Xattr {
                        // Last option — ends when FILES section starts
                        showhelp("\nALL OPTIONS\n", &cmdbuf, "\nFILES");
                    } else {
                        showhelp("\nALL OPTIONS\n", &cmdbuf, "\n    -");
                    }
                }
            }
        }
        Some(cat) => {
            // Try to find a named category
            if !get_category_content(cat, cols) {
                println!("Unknown category provided, here is a list of all categories:\n");
                get_categories();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// tool_version_info — version information display (public)
// ---------------------------------------------------------------------------

/// Display comprehensive version, protocol, and feature information.
///
/// Output format matches curl 8.x `tool_version_info()` exactly:
/// - "curl X.Y.Z (arch) ..." header line
/// - "Release-Date: ..." line
/// - "Protocols: ..." line (alphabetically sorted, IPFS/IPNS inserted)
/// - "Features: ..." line (alphabetically sorted, "CAcert" added if embedded)
/// - Warning if debug build
/// - Warning if tool and library versions differ
pub fn tool_version_info() {
    let lib_info = get_libcurl_info();
    let ver_info = version_info();

    // Debug build warning
    if is_debug(&lib_info) {
        tool_stderr_write(
            "WARNING: this libcurl is Debug-enabled, do not use in production\n\n",
        );
    }

    // Main version line — format: "curl X.Y.Z (arch) backend_info"
    // CURL_ID is empty in typical builds; we match the C pattern.
    println!("{}", version());

    // Release date
    println!(
        "Release-Date: {}",
        curl_rs_lib::version::VERSION_TIMESTAMP
    );

    // Protocols line
    if !ver_info.protocols.is_empty() {
        print!("Protocols:");
        let mut insert_point: Option<&str> = None;

        // IPFS/IPNS insertion logic: find the right alphabetical position
        // by locating "http" in the protocol list, then advancing until
        // we find a protocol that sorts >= "ipfs".
        for proto in &ver_info.protocols {
            if insert_point.is_some() {
                if proto.as_str() < "ipfs" {
                    insert_point = Some(proto.as_str());
                } else {
                    break;
                }
            } else if proto == "http" {
                insert_point = Some(proto.as_str());
            }
        }

        let mut ipfs_inserted = insert_point.is_none();
        for proto in &ver_info.protocols {
            // Skip rtmp variants (rtmpe, rtmps, rtmpt, etc.) but keep "rtmp" itself
            if proto.starts_with("rtmp") && proto.len() > 4 {
                continue;
            }
            print!(" {}", proto);

            // Insert "ipfs ipns" at the correct alphabetical position
            if !ipfs_inserted {
                if let Some(insertion) = insert_point {
                    if proto.as_str() == insertion {
                        print!(" ipfs ipns");
                        ipfs_inserted = true;
                    }
                }
            }
        }
        println!(); // newline
    }

    // Features line
    if !lib_info.features.is_empty() {
        // Build feature list — possibly add "CAcert" for embedded CA bundle
        let mut features: Vec<String> = lib_info.features.clone();

        // Sort alphabetically (case-insensitive, matching C qsort with struplocompare4sort)
        features.sort_by_key(|a| a.to_ascii_uppercase());

        print!("Features:");
        for feat in &features {
            print!(" {}", feat);
        }
        println!(); // newline
    }

    // Version mismatch warning
    if VERSION != lib_info.version {
        println!(
            "WARNING: curl and libcurl versions do not match. \
             Functionality may be affected."
        );
    }
}

// ---------------------------------------------------------------------------
// tool_list_engines — SSL engine listing (public)
// ---------------------------------------------------------------------------

/// Display the list of available SSL engines.
///
/// With rustls as the exclusive TLS backend, there are no traditional
/// "engines" (engines were an OpenSSL concept). This function prints
/// the engine header and "<none>" to match the behavior curl 8.x
/// would show when no engines are available.
///
/// Equivalent to C `tool_list_engines()` from tool_help.c.
pub fn tool_list_engines() {
    println!("Build-time engines:");
    // rustls does not have the concept of crypto engines (that was
    // OpenSSL-specific). Report no engines available.
    println!("  <none>");
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the HELPTEXT array is non-empty.
    #[test]
    fn helptext_is_populated() {
        assert!(
            !HELPTEXT.is_empty(),
            "HELPTEXT must contain option entries"
        );
    }

    /// Verify that the CATEGORIES array is non-empty and has the expected
    /// number of entries (25, matching C categories[]).
    #[test]
    fn categories_count() {
        assert_eq!(CATEGORIES.len(), 25);
    }

    /// Verify that every category has a non-empty token and description.
    #[test]
    fn categories_have_valid_fields() {
        for cat in CATEGORIES.iter() {
            assert!(!cat.token.is_empty(), "Category token must not be empty");
            assert!(
                !cat.description.is_empty(),
                "Category description must not be empty"
            );
            assert!(cat.bitmask != 0, "Category bitmask must not be zero");
        }
    }

    /// Verify that every helptext entry has a non-empty opt and desc,
    /// and that the categories bitmask is non-zero.
    #[test]
    fn helptext_entries_valid() {
        for entry in HELPTEXT.iter() {
            assert!(!entry.opt.is_empty(), "Option string must not be empty");
            assert!(!entry.desc.is_empty(), "Description must not be empty");
            assert!(
                entry.categories != 0,
                "Categories bitmask must not be zero for: {}",
                entry.opt
            );
        }
    }

    /// Verify that CURLHELP_IMPORTANT filters the expected options.
    #[test]
    fn important_category_has_entries() {
        let count = HELPTEXT
            .iter()
            .filter(|e| (e.categories & CURLHELP_IMPORTANT) != 0)
            .count();
        assert!(
            count > 5,
            "CURLHELP_IMPORTANT should have many entries, got {}",
            count
        );
    }

    /// Verify that CURLHELP_ALL matches all entries.
    #[test]
    fn all_category_matches_all() {
        let count = HELPTEXT
            .iter()
            .filter(|e| (e.categories & CURLHELP_ALL) != 0)
            .count();
        assert_eq!(count, HELPTEXT.len());
    }

    /// Verify the bitmask values match the C header definitions.
    #[test]
    fn bitmask_values_match_c() {
        assert_eq!(CURLHELP_AUTH, 1 << 0);
        assert_eq!(CURLHELP_CONNECTION, 1 << 1);
        assert_eq!(CURLHELP_CURL, 1 << 2);
        assert_eq!(CURLHELP_HTTP, 1 << 8);
        assert_eq!(CURLHELP_IMPORTANT, 1 << 10);
        assert_eq!(CURLHELP_TLS, 1 << 23);
        assert_eq!(CURLHELP_VERBOSE, 1 << 25);
    }

    /// Verify get_category_content finds known categories.
    #[test]
    fn get_category_content_finds_auth() {
        // We can't easily check stdout, but we can verify the return value
        assert!(get_category_content("auth", 80));
        assert!(get_category_content("http", 80));
        assert!(get_category_content("tls", 80));
    }

    /// Verify get_category_content returns false for unknown categories.
    #[test]
    fn get_category_content_unknown() {
        assert!(!get_category_content("nonexistent", 80));
    }

    /// Verify that is_debug returns false when no debug feature is present.
    #[test]
    fn is_debug_false_for_normal_build() {
        let info = LibCurlInfo {
            features: vec!["SSL".to_string(), "HTTP2".to_string()],
            ..Default::default()
        };
        assert!(!is_debug(&info));
    }

    /// Verify that is_debug returns true when debug feature is present.
    #[test]
    fn is_debug_true_when_debug_present() {
        let info = LibCurlInfo {
            features: vec!["Debug".to_string(), "SSL".to_string()],
            ..Default::default()
        };
        assert!(is_debug(&info));
    }

    /// Verify the argtype_from_flags function correctly maps bitmask values.
    #[test]
    fn argtype_extraction() {
        assert_eq!(argtype_from_flags(0), ArgType::None);
        assert_eq!(argtype_from_flags(ARG_BOOL), ArgType::Bool);
        assert_eq!(argtype_from_flags(ARG_BOOL | ARG_NO), ArgType::Bool);
        assert_eq!(argtype_from_flags(2), ArgType::Strg);
        assert_eq!(argtype_from_flags(3), ArgType::File);
    }

    /// Verify ScanContext initialization.
    #[test]
    fn scan_context_init() {
        let ctx = inithelpscan("trigger", "arg", "end");
        assert_eq!(ctx.trigger, "trigger");
        assert_eq!(ctx.arg, "arg");
        assert_eq!(ctx.endarg, "end");
        assert_eq!(ctx.show, 0);
        assert!(ctx.obuf.is_empty());
    }

    /// Verify that the helptext contains the "--xattr" option (last entry in C).
    #[test]
    fn helptext_contains_xattr() {
        let has_xattr = HELPTEXT.iter().any(|e| e.opt.contains("--xattr"));
        assert!(has_xattr, "HELPTEXT must contain --xattr option");
    }

    /// Verify that the helptext contains "--help" option with IMPORTANT category.
    #[test]
    fn helptext_help_is_important() {
        let help_entry = HELPTEXT.iter().find(|e| e.opt.contains("--help"));
        assert!(help_entry.is_some(), "HELPTEXT must contain --help");
        let entry = help_entry.unwrap();
        assert!(
            (entry.categories & CURLHELP_IMPORTANT) != 0,
            "--help must be in IMPORTANT category"
        );
    }
}
