//! `--help` / `-h` usage rendering — the Rust port of curl's `src/tool_help.c`
//! and the generated option table in `src/tool_listhelp.c`.
//!
//! # Why this module exists
//!
//! curl's CLI prints its option help from a generated table (`helptext[]`,
//! produced by `make listhelp`) rendered by the category-aware logic in
//! `tool_help.c` (`tool_help`, `print_category`, `get_categories`,
//! `get_categories_list`, `get_category_content`). The dual-model parser in
//! [`crate::args`] owns only the *parsing* half; this module is the *rendering*
//! half, invoked from the `HelpRequested` arm of [`crate::operate`] so that
//! `--help`, `-h`, `--help all`, `--help category` and `--help <category>` emit
//! the exact categorized listing curl does (AAP G5 — `curl --help all`
//! functionally identical).
//!
//! # Manual coupling
//!
//! Two help surfaces are gated on `USE_MANUAL` in C: the extra
//! `"Use \"--help [option]\" …"` note on the default page, and the
//! `--help <-option>` per-option documentation. curl-rs is built **without** the
//! built-in manual (a first-class `--disable-manual` curl configuration; the
//! manual is build-generated content — `docs/curl.1` / `tool_hugehelp.c` — not
//! present in the source tree). This module therefore matches curl's `#else`
//! behavior on both surfaces: the note is omitted and `--help <-option>` reports
//! `"Cannot comply. This curl was built without built-in manual"`, byte-for-byte
//! identical to `curl --disable-manual`.
//!
//! The option *strings*, descriptions and category bitmasks below are ported
//! verbatim from `src/tool_listhelp.c`, so the rendered text matches curl.

use std::io::{self, Write};

use crate::messages::terminal_columns;

/// Category bitmask constants — the Rust analogue of the `CURLHELP_*` macros in
/// `src/tool_help.h`. Values match curl bit-for-bit (`ALL` is curl's
/// `0xfffffffU`).
pub(crate) mod cat {
    pub const AUTH: u32 = 1 << 0;
    pub const CONNECTION: u32 = 1 << 1;
    pub const CURL: u32 = 1 << 2;
    pub const DEPRECATED: u32 = 1 << 3;
    pub const DNS: u32 = 1 << 4;
    pub const FILE: u32 = 1 << 5;
    pub const FTP: u32 = 1 << 6;
    pub const GLOBAL: u32 = 1 << 7;
    pub const HTTP: u32 = 1 << 8;
    pub const IMAP: u32 = 1 << 9;
    pub const IMPORTANT: u32 = 1 << 10;
    pub const LDAP: u32 = 1 << 11;
    pub const OUTPUT: u32 = 1 << 12;
    pub const POP3: u32 = 1 << 13;
    pub const POST: u32 = 1 << 14;
    pub const PROXY: u32 = 1 << 15;
    pub const SCP: u32 = 1 << 16;
    pub const SFTP: u32 = 1 << 17;
    pub const SMTP: u32 = 1 << 18;
    pub const SSH: u32 = 1 << 19;
    pub const TELNET: u32 = 1 << 20;
    pub const TFTP: u32 = 1 << 21;
    pub const TIMEOUT: u32 = 1 << 22;
    pub const TLS: u32 = 1 << 23;
    pub const UPLOAD: u32 = 1 << 24;
    pub const VERBOSE: u32 = 1 << 25;
    /// `CURLHELP_ALL` — every category bit set (curl's `0xfffffffU`).
    pub const ALL: u32 = 0xfff_ffff;
}

/// One option-help entry (← `struct helptxt`, `src/tool_help.h`).
struct H {
    /// The formatted option column, e.g. `"-a, --append"` (← `helptxt.opt`).
    opt: &'static str,
    /// The one-line description (← `helptxt.desc`).
    desc: &'static str,
    /// Bitwise-OR of the [`cat`] bits this option belongs to
    /// (← `helptxt.categories`).
    categories: u32,
}

/// The full option-help table, ported verbatim from `helptext[]`
/// (`src/tool_listhelp.c`) — **273 entries**, in curl's order.
static HELPTEXT: &[H] = &[
    H { opt: "    --abstract-unix-socket <path>", desc: "Connect via abstract Unix domain socket", categories: cat::CONNECTION },
    H { opt: "    --alt-svc <filename>", desc: "Enable alt-svc with this cache file", categories: cat::HTTP },
    H { opt: "    --anyauth", desc: "Pick any authentication method", categories: cat::HTTP | cat::PROXY | cat::AUTH },
    H { opt: "-a, --append", desc: "Append to target file when uploading", categories: cat::FTP | cat::SFTP },
    H { opt: "    --aws-sigv4 <provider1[:prvdr2[:reg[:srv]]]>", desc: "AWS V4 signature auth", categories: cat::AUTH | cat::HTTP },
    H { opt: "    --basic", desc: "HTTP Basic Authentication", categories: cat::AUTH },
    H { opt: "    --ca-native", desc: "Load CA certs from the OS", categories: cat::TLS },
    H { opt: "    --cacert <file>", desc: "CA certificate to verify peer against", categories: cat::TLS },
    H { opt: "    --capath <dir>", desc: "CA directory to verify peer against", categories: cat::TLS },
    H { opt: "-E, --cert <certificate[:password]>", desc: "Client certificate file and password", categories: cat::TLS },
    H { opt: "    --cert-status", desc: "Verify server cert status OCSP-staple", categories: cat::TLS },
    H { opt: "    --cert-type <type>", desc: "Certificate type (DER/PEM/ENG/PROV/P12)", categories: cat::TLS },
    H { opt: "    --ciphers <list>", desc: "TLS 1.2 (1.1, 1.0) ciphers to use", categories: cat::TLS },
    H { opt: "    --compressed", desc: "Request compressed response", categories: cat::HTTP },
    H { opt: "    --compressed-ssh", desc: "Enable SSH compression", categories: cat::SCP | cat::SSH },
    H { opt: "-K, --config <file>", desc: "Read config from a file", categories: cat::CURL },
    H { opt: "    --connect-timeout <seconds>", desc: "Maximum time allowed to connect", categories: cat::CONNECTION | cat::TIMEOUT },
    H { opt: "    --connect-to <HOST1:PORT1:HOST2:PORT2>", desc: "Connect to host2 instead of host1", categories: cat::CONNECTION | cat::DNS },
    H { opt: "-C, --continue-at <offset>", desc: "Resumed transfer offset", categories: cat::CONNECTION },
    H { opt: "-b, --cookie <data|filename>", desc: "Send cookies from string/load from file", categories: cat::HTTP },
    H { opt: "-c, --cookie-jar <filename>", desc: "Save cookies to <filename> after operation", categories: cat::HTTP },
    H { opt: "    --create-dirs", desc: "Create necessary local directory hierarchy", categories: cat::OUTPUT },
    H { opt: "    --create-file-mode <mode>", desc: "File mode for created files", categories: cat::SFTP | cat::SCP | cat::FILE | cat::UPLOAD },
    H { opt: "    --crlf", desc: "Convert LF to CRLF in upload", categories: cat::FTP | cat::SMTP },
    H { opt: "    --crlfile <file>", desc: "Certificate Revocation list", categories: cat::TLS },
    H { opt: "    --curves <list>", desc: "(EC) TLS key exchange algorithms to request", categories: cat::TLS },
    H { opt: "-d, --data <data>", desc: "HTTP POST data", categories: cat::IMPORTANT | cat::HTTP | cat::POST | cat::UPLOAD },
    H { opt: "    --data-ascii <data>", desc: "HTTP POST ASCII data", categories: cat::HTTP | cat::POST | cat::UPLOAD },
    H { opt: "    --data-binary <data>", desc: "HTTP POST binary data", categories: cat::HTTP | cat::POST | cat::UPLOAD },
    H { opt: "    --data-raw <data>", desc: "HTTP POST data, '@' allowed", categories: cat::HTTP | cat::POST | cat::UPLOAD },
    H { opt: "    --data-urlencode <data>", desc: "HTTP POST data URL encoded", categories: cat::HTTP | cat::POST | cat::UPLOAD },
    H { opt: "    --delegation <LEVEL>", desc: "GSS-API delegation permission", categories: cat::AUTH },
    H { opt: "    --digest", desc: "HTTP Digest Authentication", categories: cat::PROXY | cat::AUTH | cat::HTTP },
    H { opt: "-q, --disable", desc: "Disable .curlrc", categories: cat::CURL },
    H { opt: "    --disable-eprt", desc: "Inhibit using EPRT or LPRT", categories: cat::FTP },
    H { opt: "    --disable-epsv", desc: "Inhibit using EPSV", categories: cat::FTP },
    H { opt: "    --disallow-username-in-url", desc: "Disallow username in URL", categories: cat::CURL },
    H { opt: "    --dns-interface <interface>", desc: "Interface to use for DNS requests", categories: cat::DNS },
    H { opt: "    --dns-ipv4-addr <address>", desc: "IPv4 address to use for DNS requests", categories: cat::DNS },
    H { opt: "    --dns-ipv6-addr <address>", desc: "IPv6 address to use for DNS requests", categories: cat::DNS },
    H { opt: "    --dns-servers <addresses>", desc: "DNS server addrs to use", categories: cat::DNS },
    H { opt: "    --doh-cert-status", desc: "Verify DoH server cert status OCSP-staple", categories: cat::DNS | cat::TLS },
    H { opt: "    --doh-insecure", desc: "Allow insecure DoH server connections", categories: cat::DNS | cat::TLS },
    H { opt: "    --doh-url <URL>", desc: "Resolve hostnames over DoH", categories: cat::DNS },
    H { opt: "    --dump-ca-embed", desc: "Write the embedded CA bundle to standard output", categories: cat::HTTP | cat::PROXY | cat::TLS },
    H { opt: "-D, --dump-header <filename>", desc: "Write the received headers to <filename>", categories: cat::HTTP | cat::FTP },
    H { opt: "    --ech <config>", desc: "Configure ECH", categories: cat::TLS },
    H { opt: "    --egd-file <file>", desc: "EGD socket path for random data", categories: cat::DEPRECATED },
    H { opt: "    --engine <name>", desc: "Crypto engine to use", categories: cat::TLS },
    H { opt: "    --etag-compare <file>", desc: "Load ETag from file", categories: cat::HTTP },
    H { opt: "    --etag-save <file>", desc: "Parse incoming ETag and save to a file", categories: cat::HTTP },
    H { opt: "    --expect100-timeout <seconds>", desc: "How long to wait for 100-continue", categories: cat::HTTP | cat::TIMEOUT },
    H { opt: "-f, --fail", desc: "Fail fast with no output on HTTP errors", categories: cat::IMPORTANT | cat::HTTP },
    H { opt: "    --fail-early", desc: "Fail on first transfer error", categories: cat::CURL | cat::GLOBAL },
    H { opt: "    --fail-with-body", desc: "Fail on HTTP errors but save the body", categories: cat::HTTP | cat::OUTPUT },
    H { opt: "    --false-start", desc: "Enable TLS False Start", categories: cat::DEPRECATED },
    H { opt: "    --follow", desc: "Follow redirects per spec", categories: cat::HTTP },
    H { opt: "-F, --form <name=content>", desc: "Specify multipart MIME data", categories: cat::HTTP | cat::UPLOAD | cat::POST | cat::IMAP | cat::SMTP },
    H { opt: "    --form-escape", desc: "Escape form fields using backslash", categories: cat::HTTP | cat::UPLOAD | cat::POST },
    H { opt: "    --form-string <name=string>", desc: "Specify multipart MIME data", categories: cat::HTTP | cat::UPLOAD | cat::POST | cat::SMTP | cat::IMAP },
    H { opt: "    --ftp-account <data>", desc: "Account data string", categories: cat::FTP | cat::AUTH },
    H { opt: "    --ftp-alternative-to-user <command>", desc: "String to replace USER [name]", categories: cat::FTP },
    H { opt: "    --ftp-create-dirs", desc: "Create the remote dirs if not present", categories: cat::FTP | cat::SFTP },
    H { opt: "    --ftp-method <method>", desc: "Control CWD usage", categories: cat::FTP },
    H { opt: "    --ftp-pasv", desc: "Send PASV/EPSV instead of PORT", categories: cat::FTP },
    H { opt: "-P, --ftp-port <address>", desc: "Send PORT instead of PASV", categories: cat::FTP },
    H { opt: "    --ftp-pret", desc: "Send PRET before PASV", categories: cat::FTP },
    H { opt: "    --ftp-skip-pasv-ip", desc: "Skip the IP address for PASV", categories: cat::FTP },
    H { opt: "    --ftp-ssl-ccc", desc: "Send CCC after authenticating", categories: cat::FTP | cat::TLS },
    H { opt: "    --ftp-ssl-ccc-mode <active/passive>", desc: "Set CCC mode", categories: cat::FTP | cat::TLS },
    H { opt: "    --ftp-ssl-control", desc: "Require TLS for login, clear for transfer", categories: cat::FTP | cat::TLS },
    H { opt: "-G, --get", desc: "Put the post data in the URL and use GET", categories: cat::HTTP },
    H { opt: "-g, --globoff", desc: "Disable URL globbing with {} and []", categories: cat::CURL },
    H { opt: "    --happy-eyeballs-timeout-ms <ms>", desc: "Time for IPv6 before IPv4", categories: cat::CONNECTION | cat::TIMEOUT },
    H { opt: "    --haproxy-clientip <ip>", desc: "Set address in HAProxy PROXY", categories: cat::HTTP | cat::PROXY },
    H { opt: "    --haproxy-protocol", desc: "Send HAProxy PROXY protocol v1 header", categories: cat::HTTP | cat::PROXY },
    H { opt: "-I, --head", desc: "Show document info only", categories: cat::IMPORTANT | cat::HTTP | cat::FTP | cat::FILE },
    H { opt: "-H, --header <header/@file>", desc: "Pass custom header(s) to server", categories: cat::IMPORTANT | cat::HTTP | cat::IMAP | cat::SMTP },
    H { opt: "-h, --help <subject>", desc: "Get help for commands", categories: cat::IMPORTANT | cat::CURL },
    H { opt: "    --hostpubmd5 <md5>", desc: "Acceptable MD5 hash of host public key", categories: cat::SFTP | cat::SCP | cat::SSH },
    H { opt: "    --hostpubsha256 <sha256>", desc: "Acceptable SHA256 hash of host public key", categories: cat::SFTP | cat::SCP | cat::SSH },
    H { opt: "    --hsts <filename>", desc: "Enable HSTS with this cache file", categories: cat::HTTP },
    H { opt: "    --http0.9", desc: "Allow HTTP/0.9 responses", categories: cat::HTTP },
    H { opt: "-0, --http1.0", desc: "Use HTTP/1.0", categories: cat::HTTP },
    H { opt: "    --http1.1", desc: "Use HTTP/1.1", categories: cat::HTTP },
    H { opt: "    --http2", desc: "Use HTTP/2", categories: cat::HTTP },
    H { opt: "    --http2-prior-knowledge", desc: "Use HTTP/2 without HTTP/1.1 Upgrade", categories: cat::HTTP },
    H { opt: "    --http3", desc: "Use HTTP/3", categories: cat::HTTP },
    H { opt: "    --http3-only", desc: "Use HTTP/3 only", categories: cat::HTTP },
    H { opt: "    --ignore-content-length", desc: "Ignore the size of the remote resource", categories: cat::HTTP | cat::FTP },
    H { opt: "-k, --insecure", desc: "Allow insecure server connections", categories: cat::TLS | cat::SFTP | cat::SCP | cat::SSH },
    H { opt: "    --interface <name>", desc: "Use network interface", categories: cat::CONNECTION },
    H { opt: "    --ip-tos <string>", desc: "Set IP Type of Service or Traffic Class", categories: cat::CONNECTION },
    H { opt: "    --ipfs-gateway <URL>", desc: "Gateway for IPFS", categories: cat::CURL },
    H { opt: "-4, --ipv4", desc: "Resolve names to IPv4 addresses", categories: cat::CONNECTION | cat::DNS },
    H { opt: "-6, --ipv6", desc: "Resolve names to IPv6 addresses", categories: cat::CONNECTION | cat::DNS },
    H { opt: "    --json <data>", desc: "HTTP POST JSON", categories: cat::HTTP | cat::POST | cat::UPLOAD },
    H { opt: "-j, --junk-session-cookies", desc: "Ignore session cookies read from file", categories: cat::HTTP },
    H { opt: "    --keepalive-cnt <integer>", desc: "Maximum number of keepalive probes", categories: cat::CONNECTION },
    H { opt: "    --keepalive-time <seconds>", desc: "Interval time for keepalive probes", categories: cat::CONNECTION | cat::TIMEOUT },
    H { opt: "    --key <key>", desc: "Private key filename", categories: cat::TLS | cat::SSH },
    H { opt: "    --key-type <type>", desc: "Private key file type (DER/PEM/ENG)", categories: cat::TLS },
    H { opt: "    --knownhosts <file>", desc: "Specify knownhosts path", categories: cat::SSH },
    H { opt: "    --krb <level>", desc: "Enable Kerberos with security <level>", categories: cat::DEPRECATED },
    H { opt: "    --libcurl <file>", desc: "Generate libcurl code for this command line", categories: cat::CURL | cat::GLOBAL },
    H { opt: "    --limit-rate <speed>", desc: "Limit transfer speed to RATE", categories: cat::CONNECTION },
    H { opt: "-l, --list-only", desc: "List only mode", categories: cat::FTP | cat::POP3 | cat::SFTP | cat::FILE },
    H { opt: "    --local-port <range>", desc: "Use a local port number within RANGE", categories: cat::CONNECTION },
    H { opt: "-L, --location", desc: "Follow redirects", categories: cat::HTTP },
    H { opt: "    --location-trusted", desc: "As --location, but send secrets to other hosts", categories: cat::HTTP | cat::AUTH },
    H { opt: "    --login-options <options>", desc: "Server login options", categories: cat::IMAP | cat::POP3 | cat::SMTP | cat::AUTH | cat::LDAP },
    H { opt: "    --mail-auth <address>", desc: "Originator address of the original email", categories: cat::SMTP },
    H { opt: "    --mail-from <address>", desc: "Mail from this address", categories: cat::SMTP },
    H { opt: "    --mail-rcpt <address>", desc: "Mail to this address", categories: cat::SMTP },
    H { opt: "    --mail-rcpt-allowfails", desc: "Allow RCPT TO command to fail", categories: cat::SMTP },
    H { opt: "-M, --manual", desc: "Display the full manual", categories: cat::CURL },
    H { opt: "    --max-filesize <bytes>", desc: "Maximum file size to download", categories: cat::CONNECTION },
    H { opt: "    --max-redirs <num>", desc: "Maximum number of redirects allowed", categories: cat::HTTP },
    H { opt: "-m, --max-time <seconds>", desc: "Maximum time allowed for transfer", categories: cat::CONNECTION | cat::TIMEOUT },
    H { opt: "    --metalink", desc: "Process given URLs as metalink XML file", categories: cat::DEPRECATED },
    H { opt: "    --mptcp", desc: "Enable Multipath TCP", categories: cat::CONNECTION },
    H { opt: "    --negotiate", desc: "Use HTTP Negotiate (SPNEGO) authentication", categories: cat::AUTH | cat::HTTP },
    H { opt: "-n, --netrc", desc: "Must read .netrc for username and password", categories: cat::AUTH },
    H { opt: "    --netrc-file <filename>", desc: "Specify FILE for netrc", categories: cat::AUTH },
    H { opt: "    --netrc-optional", desc: "Use either .netrc or URL", categories: cat::AUTH },
    H { opt: "-:, --next", desc: "Make next URL use separate options", categories: cat::CURL },
    H { opt: "    --no-alpn", desc: "Disable the ALPN TLS extension", categories: cat::TLS | cat::HTTP },
    H { opt: "-N, --no-buffer", desc: "Disable buffering of the output stream", categories: cat::OUTPUT },
    H { opt: "    --no-clobber", desc: "Do not overwrite files that already exist", categories: cat::OUTPUT },
    H { opt: "    --no-keepalive", desc: "Disable TCP keepalive on the connection", categories: cat::CONNECTION },
    H { opt: "    --no-npn", desc: "Disable the NPN TLS extension", categories: cat::DEPRECATED },
    H { opt: "    --no-progress-meter", desc: "Do not show the progress meter", categories: cat::VERBOSE },
    H { opt: "    --no-sessionid", desc: "Disable SSL session-ID reusing", categories: cat::TLS },
    H { opt: "    --noproxy <no-proxy-list>", desc: "List of hosts which do not use proxy", categories: cat::PROXY },
    H { opt: "    --ntlm", desc: "HTTP NTLM authentication", categories: cat::AUTH | cat::HTTP },
    H { opt: "    --ntlm-wb", desc: "HTTP NTLM authentication with winbind", categories: cat::DEPRECATED },
    H { opt: "    --oauth2-bearer <token>", desc: "OAuth 2 Bearer Token", categories: cat::AUTH | cat::IMAP | cat::POP3 | cat::SMTP | cat::LDAP },
    H { opt: "    --out-null", desc: "Discard response data into the void", categories: cat::OUTPUT },
    H { opt: "-o, --output <file>", desc: "Write to file instead of stdout", categories: cat::IMPORTANT | cat::OUTPUT },
    H { opt: "    --output-dir <dir>", desc: "Directory to save files in", categories: cat::OUTPUT },
    H { opt: "-Z, --parallel", desc: "Perform transfers in parallel", categories: cat::CONNECTION | cat::CURL | cat::GLOBAL },
    H { opt: "    --parallel-immediate", desc: "Do not wait for multiplexing", categories: cat::CONNECTION | cat::CURL | cat::GLOBAL },
    H { opt: "    --parallel-max <num>", desc: "Maximum concurrency for parallel transfers", categories: cat::CONNECTION | cat::CURL | cat::GLOBAL },
    H { opt: "    --parallel-max-host <num>", desc: "Maximum connections to a single host", categories: cat::CONNECTION | cat::CURL | cat::GLOBAL },
    H { opt: "    --pass <phrase>", desc: "Passphrase for the private key", categories: cat::SSH | cat::TLS | cat::AUTH },
    H { opt: "    --path-as-is", desc: "Do not squash .. sequences in URL path", categories: cat::CURL },
    H { opt: "    --pinnedpubkey <hashes>", desc: "Public key to verify peer against", categories: cat::TLS },
    H { opt: "    --post301", desc: "Do not switch to GET after a 301 redirect", categories: cat::HTTP | cat::POST },
    H { opt: "    --post302", desc: "Do not switch to GET after a 302 redirect", categories: cat::HTTP | cat::POST },
    H { opt: "    --post303", desc: "Do not switch to GET after a 303 redirect", categories: cat::HTTP | cat::POST },
    H { opt: "    --preproxy <[protocol://]host[:port]>", desc: "Use this proxy first", categories: cat::PROXY },
    H { opt: "-#, --progress-bar", desc: "Display transfer progress as a bar", categories: cat::VERBOSE | cat::GLOBAL },
    H { opt: "    --proto <protocols>", desc: "Enable/disable PROTOCOLS", categories: cat::CONNECTION | cat::CURL },
    H { opt: "    --proto-default <protocol>", desc: "Use PROTOCOL for any URL missing a scheme", categories: cat::CONNECTION | cat::CURL },
    H { opt: "    --proto-redir <protocols>", desc: "Enable/disable PROTOCOLS on redirect", categories: cat::CONNECTION | cat::CURL },
    H { opt: "-x, --proxy <[protocol://]host[:port]>", desc: "Use this proxy", categories: cat::PROXY },
    H { opt: "    --proxy-anyauth", desc: "Pick any proxy authentication method", categories: cat::PROXY | cat::AUTH },
    H { opt: "    --proxy-basic", desc: "Use Basic authentication on the proxy", categories: cat::PROXY | cat::AUTH },
    H { opt: "    --proxy-ca-native", desc: "Load CA certs from the OS to verify proxy", categories: cat::TLS },
    H { opt: "    --proxy-cacert <file>", desc: "CA certificates to verify proxy against", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-capath <dir>", desc: "CA directory to verify proxy against", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-cert <cert[:passwd]>", desc: "Set client certificate for proxy", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-cert-type <type>", desc: "Client certificate type for HTTPS proxy", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-ciphers <list>", desc: "TLS 1.2 (1.1, 1.0) ciphers to use for proxy", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-crlfile <file>", desc: "Set a CRL list for proxy", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-digest", desc: "Digest auth with the proxy", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-header <header/@file>", desc: "Pass custom header(s) to proxy", categories: cat::PROXY },
    H { opt: "    --proxy-http2", desc: "Use HTTP/2 with HTTPS proxy", categories: cat::HTTP | cat::PROXY },
    H { opt: "    --proxy-insecure", desc: "Skip HTTPS proxy cert verification", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-key <key>", desc: "Private key for HTTPS proxy", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-key-type <type>", desc: "Private key file type for proxy", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-negotiate", desc: "HTTP Negotiate (SPNEGO) auth with the proxy", categories: cat::PROXY | cat::AUTH },
    H { opt: "    --proxy-ntlm", desc: "NTLM authentication with the proxy", categories: cat::PROXY | cat::AUTH },
    H { opt: "    --proxy-pass <phrase>", desc: "Passphrase for private key for HTTPS proxy", categories: cat::PROXY | cat::TLS | cat::AUTH },
    H { opt: "    --proxy-pinnedpubkey <hashes>", desc: "FILE/HASHES public key to verify proxy with", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-service-name <name>", desc: "SPNEGO proxy service name", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-ssl-allow-beast", desc: "Allow this security flaw for HTTPS proxy", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-ssl-auto-client-cert", desc: "Auto client certificate for proxy", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-tls13-ciphers <list>", desc: "TLS 1.3 proxy cipher suites", categories: cat::PROXY | cat::TLS },
    H { opt: "    --proxy-tlsauthtype <type>", desc: "TLS authentication type for HTTPS proxy", categories: cat::PROXY | cat::TLS | cat::AUTH },
    H { opt: "    --proxy-tlspassword <string>", desc: "TLS password for HTTPS proxy", categories: cat::PROXY | cat::TLS | cat::AUTH },
    H { opt: "    --proxy-tlsuser <name>", desc: "TLS username for HTTPS proxy", categories: cat::PROXY | cat::TLS | cat::AUTH },
    H { opt: "    --proxy-tlsv1", desc: "TLSv1 for HTTPS proxy", categories: cat::PROXY | cat::TLS | cat::AUTH },
    H { opt: "-U, --proxy-user <user:password>", desc: "Proxy user and password", categories: cat::PROXY | cat::AUTH },
    H { opt: "    --proxy1.0 <host[:port]>", desc: "Use HTTP/1.0 proxy on given port", categories: cat::PROXY },
    H { opt: "-p, --proxytunnel", desc: "HTTP proxy tunnel (using CONNECT)", categories: cat::PROXY },
    H { opt: "    --pubkey <key>", desc: "SSH Public key filename", categories: cat::SFTP | cat::SCP | cat::SSH | cat::AUTH },
    H { opt: "-Q, --quote <command>", desc: "Send command(s) to server before transfer", categories: cat::FTP | cat::SFTP },
    H { opt: "    --random-file <file>", desc: "File for reading random data from", categories: cat::DEPRECATED },
    H { opt: "-r, --range <range>", desc: "Retrieve only the bytes within RANGE", categories: cat::HTTP | cat::FTP | cat::SFTP | cat::FILE },
    H { opt: "    --rate <max request rate>", desc: "Request rate for serial transfers", categories: cat::CONNECTION | cat::GLOBAL },
    H { opt: "    --raw", desc: "Do HTTP raw; no transfer decoding", categories: cat::HTTP },
    H { opt: "-e, --referer <URL>", desc: "Referrer URL", categories: cat::HTTP },
    H { opt: "-J, --remote-header-name", desc: "Use the header-provided filename", categories: cat::OUTPUT },
    H { opt: "-O, --remote-name", desc: "Write output to file named as remote file", categories: cat::IMPORTANT | cat::OUTPUT },
    H { opt: "    --remote-name-all", desc: "Use the remote filename for all URLs", categories: cat::OUTPUT },
    H { opt: "-R, --remote-time", desc: "Set remote file's time on local output", categories: cat::OUTPUT },
    H { opt: "    --remove-on-error", desc: "Remove output file on errors", categories: cat::OUTPUT },
    H { opt: "-X, --request <method>", desc: "Specify request method to use", categories: cat::CONNECTION | cat::POP3 | cat::FTP | cat::IMAP | cat::SMTP },
    H { opt: "    --request-target <path>", desc: "Specify the target for this request", categories: cat::HTTP },
    H { opt: "    --resolve <[+]host:port:addr[,addr]...>", desc: "Resolve host+port to address", categories: cat::CONNECTION | cat::DNS },
    H { opt: "    --retry <num>", desc: "Retry request if transient problems occur", categories: cat::CURL },
    H { opt: "    --retry-all-errors", desc: "Retry all errors (with --retry)", categories: cat::CURL },
    H { opt: "    --retry-connrefused", desc: "Retry on connection refused (with --retry)", categories: cat::CURL },
    H { opt: "    --retry-delay <seconds>", desc: "Wait time between retries", categories: cat::CURL | cat::TIMEOUT },
    H { opt: "    --retry-max-time <seconds>", desc: "Retry only within this period", categories: cat::CURL | cat::TIMEOUT },
    H { opt: "    --sasl-authzid <identity>", desc: "Identity for SASL PLAIN authentication", categories: cat::AUTH },
    H { opt: "    --sasl-ir", desc: "Initial response in SASL authentication", categories: cat::AUTH },
    H { opt: "    --service-name <name>", desc: "SPNEGO service name", categories: cat::AUTH },
    H { opt: "-S, --show-error", desc: "Show error even when -s is used", categories: cat::CURL | cat::GLOBAL },
    H { opt: "-i, --show-headers", desc: "Show response headers in output", categories: cat::IMPORTANT | cat::VERBOSE | cat::OUTPUT },
    H { opt: "    --sigalgs <list>", desc: "TLS signature algorithms to use", categories: cat::TLS },
    H { opt: "-s, --silent", desc: "Silent mode", categories: cat::IMPORTANT | cat::VERBOSE },
    H { opt: "    --skip-existing", desc: "Skip download if local file already exists", categories: cat::CURL | cat::OUTPUT },
    H { opt: "    --socks4 <host[:port]>", desc: "SOCKS4 proxy on given host + port", categories: cat::PROXY },
    H { opt: "    --socks4a <host[:port]>", desc: "SOCKS4a proxy on given host + port", categories: cat::PROXY },
    H { opt: "    --socks5 <host[:port]>", desc: "SOCKS5 proxy on given host + port", categories: cat::PROXY },
    H { opt: "    --socks5-basic", desc: "Username/password auth for SOCKS5 proxies", categories: cat::PROXY | cat::AUTH },
    H { opt: "    --socks5-gssapi", desc: "Enable GSS-API auth for SOCKS5 proxies", categories: cat::PROXY | cat::AUTH },
    H { opt: "    --socks5-gssapi-nec", desc: "Compatibility with NEC SOCKS5 server", categories: cat::PROXY | cat::AUTH },
    H { opt: "    --socks5-gssapi-service <name>", desc: "SOCKS5 proxy service name for GSS-API", categories: cat::PROXY | cat::AUTH },
    H { opt: "    --socks5-hostname <host[:port]>", desc: "SOCKS5 proxy, pass hostname to proxy", categories: cat::PROXY },
    H { opt: "-Y, --speed-limit <speed>", desc: "Stop transfers slower than this", categories: cat::CONNECTION },
    H { opt: "-y, --speed-time <seconds>", desc: "Trigger 'speed-limit' abort after this time", categories: cat::CONNECTION | cat::TIMEOUT },
    H { opt: "    --ssl", desc: "Try enabling TLS", categories: cat::TLS | cat::IMAP | cat::POP3 | cat::SMTP | cat::LDAP },
    H { opt: "    --ssl-allow-beast", desc: "Allow security flaw to improve interop", categories: cat::TLS },
    H { opt: "    --ssl-auto-client-cert", desc: "Use auto client certificate (Schannel)", categories: cat::TLS },
    H { opt: "    --ssl-no-revoke", desc: "Disable cert revocation checks (Schannel)", categories: cat::TLS },
    H { opt: "    --ssl-reqd", desc: "Require SSL/TLS", categories: cat::TLS | cat::IMAP | cat::POP3 | cat::SMTP | cat::LDAP },
    H { opt: "    --ssl-revoke-best-effort", desc: "Ignore missing cert CRL dist points", categories: cat::TLS },
    H { opt: "    --ssl-sessions <filename>", desc: "Load/save SSL session tickets from/to this file", categories: cat::TLS },
    H { opt: "-2, --sslv2", desc: "SSLv2", categories: cat::DEPRECATED },
    H { opt: "-3, --sslv3", desc: "SSLv3", categories: cat::DEPRECATED },
    H { opt: "    --stderr <file>", desc: "Where to redirect stderr", categories: cat::VERBOSE | cat::GLOBAL },
    H { opt: "    --styled-output", desc: "Enable styled output for HTTP headers", categories: cat::VERBOSE | cat::GLOBAL },
    H { opt: "    --suppress-connect-headers", desc: "Suppress proxy CONNECT response headers", categories: cat::PROXY },
    H { opt: "    --tcp-fastopen", desc: "Use TCP Fast Open", categories: cat::CONNECTION },
    H { opt: "    --tcp-nodelay", desc: "Set TCP_NODELAY", categories: cat::CONNECTION },
    H { opt: "-t, --telnet-option <opt=val>", desc: "Set telnet option", categories: cat::TELNET },
    H { opt: "    --tftp-blksize <value>", desc: "Set TFTP BLKSIZE option", categories: cat::TFTP },
    H { opt: "    --tftp-no-options", desc: "Do not send any TFTP options", categories: cat::TFTP },
    H { opt: "-z, --time-cond <time>", desc: "Transfer based on a time condition", categories: cat::HTTP | cat::FTP },
    H { opt: "    --tls-earlydata", desc: "Allow use of TLSv1.3 early data (0RTT)", categories: cat::TLS },
    H { opt: "    --tls-max <VERSION>", desc: "Maximum allowed TLS version", categories: cat::TLS },
    H { opt: "    --tls13-ciphers <list>", desc: "TLS 1.3 cipher suites to use", categories: cat::TLS },
    H { opt: "    --tlsauthtype <type>", desc: "TLS authentication type", categories: cat::TLS | cat::AUTH },
    H { opt: "    --tlspassword <string>", desc: "TLS password", categories: cat::TLS | cat::AUTH },
    H { opt: "    --tlsuser <name>", desc: "TLS username", categories: cat::TLS | cat::AUTH },
    H { opt: "-1, --tlsv1", desc: "TLSv1.0 or greater", categories: cat::TLS },
    H { opt: "    --tlsv1.0", desc: "TLSv1.0 or greater", categories: cat::TLS },
    H { opt: "    --tlsv1.1", desc: "TLSv1.1 or greater", categories: cat::TLS },
    H { opt: "    --tlsv1.2", desc: "TLSv1.2 or greater", categories: cat::TLS },
    H { opt: "    --tlsv1.3", desc: "TLSv1.3 or greater", categories: cat::TLS },
    H { opt: "    --tr-encoding", desc: "Request compressed transfer encoding", categories: cat::HTTP },
    H { opt: "    --trace <file>", desc: "Write a debug trace to FILE", categories: cat::VERBOSE | cat::GLOBAL },
    H { opt: "    --trace-ascii <file>", desc: "Like --trace, but without hex output", categories: cat::VERBOSE | cat::GLOBAL },
    H { opt: "    --trace-config <string>", desc: "Details to log in trace/verbose output", categories: cat::VERBOSE | cat::GLOBAL },
    H { opt: "    --trace-ids", desc: "Transfer + connection ids in verbose output", categories: cat::VERBOSE | cat::GLOBAL },
    H { opt: "    --trace-time", desc: "Add time stamps to trace/verbose output", categories: cat::VERBOSE | cat::GLOBAL },
    H { opt: "    --unix-socket <path>", desc: "Connect through this Unix domain socket", categories: cat::CONNECTION },
    H { opt: "-T, --upload-file <file>", desc: "Transfer local FILE to destination", categories: cat::IMPORTANT | cat::UPLOAD },
    H { opt: "    --upload-flags <flags>", desc: "IMAP upload behavior", categories: cat::CURL | cat::OUTPUT },
    H { opt: "    --url <url/file>", desc: "URL(s) to work with", categories: cat::CURL },
    H { opt: "    --url-query <data>", desc: "Add a URL query part", categories: cat::HTTP | cat::POST | cat::UPLOAD },
    H { opt: "-B, --use-ascii", desc: "Use ASCII/text transfer", categories: cat::FTP | cat::OUTPUT | cat::LDAP | cat::TFTP },
    H { opt: "-u, --user <user:password>", desc: "Server user and password", categories: cat::IMPORTANT | cat::AUTH },
    H { opt: "-A, --user-agent <name>", desc: "Send User-Agent <name> to server", categories: cat::IMPORTANT | cat::HTTP },
    H { opt: "    --variable <[%]name=text/@file>", desc: "Set variable", categories: cat::CURL },
    H { opt: "-v, --verbose", desc: "Make the operation more talkative", categories: cat::IMPORTANT | cat::VERBOSE | cat::GLOBAL },
    H { opt: "-V, --version", desc: "Show version number and quit", categories: cat::IMPORTANT | cat::CURL },
    H { opt: "    --vlan-priority <priority>", desc: "Set VLAN priority", categories: cat::CONNECTION },
    H { opt: "-w, --write-out <format>", desc: "Output FORMAT after completion", categories: cat::VERBOSE },
    H { opt: "    --xattr", desc: "Store metadata in extended file attributes", categories: cat::OUTPUT },
];

/// A category descriptor (← `struct category_descriptors`, `src/tool_help.c`).
struct CatDesc {
    /// The category name accepted by `--help <name>` (← `.opt`).
    opt: &'static str,
    /// The human-readable category description (← `.desc`).
    desc: &'static str,
    /// The single category bit this descriptor selects (← `.category`).
    category: u32,
}

/// The category list (← `categories[]`, `src/tool_help.c`). `important` is
/// deliberately omitted because it is the default help page, exactly as curl
/// notes in that table.
static CATEGORIES: &[CatDesc] = &[
    CatDesc { opt: "auth", desc: "Authentication methods", category: cat::AUTH },
    CatDesc { opt: "connection", desc: "Manage connections", category: cat::CONNECTION },
    CatDesc { opt: "curl", desc: "The command line tool itself", category: cat::CURL },
    CatDesc { opt: "deprecated", desc: "Legacy", category: cat::DEPRECATED },
    CatDesc { opt: "dns", desc: "Names and resolving", category: cat::DNS },
    CatDesc { opt: "file", desc: "FILE protocol", category: cat::FILE },
    CatDesc { opt: "ftp", desc: "FTP protocol", category: cat::FTP },
    CatDesc { opt: "global", desc: "Global options", category: cat::GLOBAL },
    CatDesc { opt: "http", desc: "HTTP and HTTPS protocol", category: cat::HTTP },
    CatDesc { opt: "imap", desc: "IMAP protocol", category: cat::IMAP },
    CatDesc { opt: "ldap", desc: "LDAP protocol", category: cat::LDAP },
    CatDesc { opt: "output", desc: "File system output", category: cat::OUTPUT },
    CatDesc { opt: "pop3", desc: "POP3 protocol", category: cat::POP3 },
    CatDesc { opt: "post", desc: "HTTP POST specific", category: cat::POST },
    CatDesc { opt: "proxy", desc: "Options for proxies", category: cat::PROXY },
    CatDesc { opt: "scp", desc: "SCP protocol", category: cat::SCP },
    CatDesc { opt: "sftp", desc: "SFTP protocol", category: cat::SFTP },
    CatDesc { opt: "smtp", desc: "SMTP protocol", category: cat::SMTP },
    CatDesc { opt: "ssh", desc: "SSH protocol", category: cat::SSH },
    CatDesc { opt: "telnet", desc: "TELNET protocol", category: cat::TELNET },
    CatDesc { opt: "tftp", desc: "TFTP protocol", category: cat::TFTP },
    CatDesc { opt: "timeout", desc: "Timeouts and delays", category: cat::TIMEOUT },
    CatDesc { opt: "tls", desc: "TLS/SSL related", category: cat::TLS },
    CatDesc { opt: "upload", desc: "Upload, sending data", category: cat::UPLOAD },
    CatDesc { opt: "verbose", desc: "Tracing, logging etc", category: cat::VERBOSE },
];

/// Prints every option in `category`, column-aligned (← `print_category`,
/// `tool_help.c`).
///
/// The opt column width is the longest opt in the category (min 5), shrunk to
/// avoid wrapping past `cols`; each line is `" {opt:<width}  {desc}"` — a leading
/// space, the left-justified opt, two spaces, then the description — exactly
/// curl's `curl_mprintf(" %-*s  %s\n", opt, ...)`.
fn print_category(out: &mut dyn Write, category: u32, cols: usize) -> io::Result<()> {
    let mut longopt: usize = 5;
    let mut longdesc: usize = 5;
    for h in HELPTEXT {
        if h.categories & category == 0 {
            continue;
        }
        longopt = longopt.max(h.opt.len());
        longdesc = longdesc.max(h.desc.len());
    }

    if longdesc > cols {
        longopt = 0; // avoid wrap-around
    } else if longopt + longdesc > cols {
        longopt = cols - longdesc;
    }

    for h in HELPTEXT {
        if h.categories & category != 0 {
            let mut opt = longopt;
            let desclen = h.desc.len();
            // avoid wrap-around (curl's per-line adjustment)
            if cols >= 2 && opt + desclen >= (cols - 2) {
                if desclen < (cols - 2) {
                    opt = (cols - 3) - desclen;
                } else {
                    opt = 0;
                }
            }
            writeln!(out, " {:<width$}  {}", h.opt, h.desc, width = opt)?;
        }
    }
    Ok(())
}

/// Prints `"<name>: <desc>"` then the category's options when `category` names a
/// known category; returns `true` if found (← `get_category_content`, which
/// returns 0 on found / 1 otherwise).
fn get_category_content(out: &mut dyn Write, category: &str, cols: usize) -> io::Result<bool> {
    for c in CATEGORIES {
        if c.opt.eq_ignore_ascii_case(category) {
            writeln!(out, "{}: {}", c.opt, c.desc)?;
            print_category(out, c.category, cols)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Prints every category and its description, `" {name:<11} {desc}"`
/// (← `get_categories`, curl's `" %-11s %s\n"`).
fn get_categories(out: &mut dyn Write) -> io::Result<()> {
    for c in CATEGORIES {
        writeln!(out, " {:<11} {}", c.opt, c.desc)?;
    }
    Ok(())
}

/// Prints all category names as a comma-separated list wrapped to `width`,
/// ending with `"."` (← `get_categories_list`).
fn get_categories_list(out: &mut dyn Write, width: usize) -> io::Result<()> {
    let mut col: usize = 0;
    let n = CATEGORIES.len();
    for (i, c) in CATEGORIES.iter().enumerate() {
        let len = c.opt.len();
        if i == n - 1 {
            // final category
            if col + len + 1 < width {
                writeln!(out, "{}.", c.opt)?;
            } else {
                writeln!(out, "\n{}.", c.opt)?;
            }
        } else if col + len + 2 < width {
            write!(out, "{}, ", c.opt)?;
            col += len + 2;
        } else {
            write!(out, "\n{}, ", c.opt)?;
            col = len + 2;
        }
    }
    Ok(())
}

/// Renders curl's help for the given optional `category` to `out` (← the body of
/// `tool_help`), using `cols` as the terminal width.
///
/// * `None` → the default page: `Usage`, the IMPORTANT options, the
///   split-into-categories note, the category list, then the
///   `Use "--help all" …` note (the manual note is omitted; see module docs).
/// * `"all"` → every option.
/// * `"category"` → the category list with descriptions.
/// * a `-`-prefixed token → the no-built-in-manual diagnostic on stderr.
/// * any other token → that category's options, or the unknown-category notice
///   followed by the category list.
fn tool_help_to(out: &mut dyn Write, category: Option<&str>, cols: usize) -> io::Result<()> {
    match category {
        None => {
            writeln!(out, "Usage: curl [options...] <url>")?;
            print_category(out, cat::IMPORTANT, cols)?;
            // category_note (curl's `puts` appends the trailing newline).
            writeln!(
                out,
                "\nThis is not the full help; this menu is split into categories.\n\
                 Use \"--help category\" to get an overview of all categories, which are:"
            )?;
            get_categories_list(out, cols)?;
            // category_note2 — no-manual build omits the "--help [option]" line.
            writeln!(out, "Use \"--help all\" to list all options")?;
        }
        Some(c) if c.eq_ignore_ascii_case("all") => {
            print_category(out, cat::ALL, cols)?;
        }
        Some(c) if c.eq_ignore_ascii_case("category") => {
            get_categories(out)?;
        }
        Some(c) if c.as_bytes().first() == Some(&b'-') => {
            // Per-option help requires the built-in manual (USE_MANUAL), which
            // this build does not bundle. Match curl's `#else` branch exactly,
            // routing to the diagnostic stream (`--stderr`-aware).
            crate::messages::emit_raw(
                b"Cannot comply. This curl was built without built-in manual\n",
            );
        }
        Some(c) => {
            if !get_category_content(out, c, cols)? {
                writeln!(
                    out,
                    "Unknown category provided, here is a list of all categories:\n"
                )?;
                get_categories(out)?;
            }
        }
    }
    Ok(())
}

/// Public entry point (← `void tool_help(const char *category)`): renders help
/// for the optional `category` to stdout, using the current terminal width.
///
/// I/O errors are swallowed, matching curl's unchecked `puts`/`curl_mprintf`
/// help writes — a broken stdout must not change the program result.
pub fn tool_help(category: Option<&str>) {
    let cols = terminal_columns();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let _ = tool_help_to(&mut out, category, cols);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(category: Option<&str>, cols: usize) -> String {
        let mut buf: Vec<u8> = Vec::new();
        tool_help_to(&mut buf, category, cols).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn table_has_273_entries() {
        // Matches the C `helptext[]` count (`src/tool_listhelp.c`), guarding
        // against a truncated port.
        assert_eq!(HELPTEXT.len(), 273);
    }

    #[test]
    fn categories_has_25_entries() {
        // The 25 categories of `categories[]` (`src/tool_help.c`): `auth`
        // through `verbose`, with `important` excluded (it is the default page).
        assert_eq!(CATEGORIES.len(), 25);
    }

    #[test]
    fn every_helptext_categories_nonzero() {
        // Each entry must belong to at least one category, or it would never be
        // printed by any `--help` variant.
        for h in HELPTEXT {
            assert_ne!(h.categories, 0, "entry has no category: {}", h.opt);
        }
    }

    #[test]
    fn default_page_has_usage_and_notes() {
        let s = render(None, 79);
        assert!(s.starts_with("Usage: curl [options...] <url>\n"));
        assert!(s.contains("This is not the full help; this menu is split into categories."));
        assert!(s.contains("Use \"--help category\" to get an overview"));
        assert!(s.contains("Use \"--help all\" to list all options"));
        // No-manual build: the per-option note must NOT appear.
        assert!(!s.contains("--help [option]"));
        // The category list ends with the final category and a period.
        assert!(s.contains("verbose."));
        // An IMPORTANT option (e.g. --verbose) is on the default page.
        assert!(s.contains("--verbose"));
    }

    #[test]
    fn help_all_lists_many_options() {
        let s = render(Some("all"), 79);
        // A representative spread of options across categories.
        for opt in [
            "--abstract-unix-socket",
            "--append",
            "--write-out",
            "--xattr",
            "--cacert",
            "--verbose",
        ] {
            assert!(s.contains(opt), "--help all missing {opt}");
        }
        // "all" must be a superset of the default page in option count.
        assert!(s.lines().count() > render(None, 79).lines().count());
    }

    #[test]
    fn help_category_lists_categories() {
        let s = render(Some("category"), 79);
        assert!(s.contains("auth"));
        assert!(s.contains("Authentication methods"));
        assert!(s.contains("verbose"));
        assert!(s.contains("Tracing, logging etc"));
    }

    #[test]
    fn help_named_category_prints_header_and_options() {
        let s = render(Some("http"), 79);
        assert!(s.starts_with("http: HTTP and HTTPS protocol\n"));
        // An HTTP-category option must appear.
        assert!(s.contains("--alt-svc"));
    }

    #[test]
    fn help_named_category_is_case_insensitive() {
        // curl uses `curl_strequal` (case-insensitive) for the category match.
        assert_eq!(render(Some("HTTP"), 79), render(Some("http"), 79));
    }

    #[test]
    fn help_unknown_category_lists_all_categories() {
        let s = render(Some("bogus"), 79);
        assert!(s.starts_with("Unknown category provided, here is a list of all categories:\n"));
        assert!(s.contains("auth"));
        assert!(s.contains("verbose"));
    }

    #[test]
    fn print_category_lines_start_with_space() {
        // Every option line begins with a single space (curl's " %-*s  %s").
        let s = render(Some("http"), 79);
        for line in s.lines().skip(1) {
            // skip the "http: ..." header line
            if !line.is_empty() {
                assert!(line.starts_with(' '), "line not space-prefixed: {line:?}");
            }
        }
    }
}
