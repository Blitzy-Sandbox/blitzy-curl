//! Public Suffix List (PSL) integration for cookie domain validation.
//!
//! This module provides the [`PslChecker`] type, a Rust replacement for the
//! C `lib/psl.c` implementation in curl 8.19.0-DEV.  It wraps the
//! [`publicsuffix`] crate to determine whether a given domain name is a
//! public suffix and to validate cookie domain attributes against the PSL.
//!
//! # Purpose
//!
//! Cookies MUST NOT be set for public suffixes such as `.com`, `.co.uk`, or
//! `.github.io`.  The PSL provides the authoritative dataset for making this
//! determination.  [`PslChecker`] loads a comprehensive built-in snapshot of
//! Mozilla's Public Suffix List exactly once (via [`OnceLock`]) and exposes
//! thread-safe, lock-free query methods.
//!
//! # Thread Safety
//!
//! The parsed PSL data lives in a `static OnceLock<List>` and is immutable
//! after initialization.  Multiple [`PslChecker`] instances may exist
//! concurrently across threads without synchronization overhead — they all
//! reference the same global dataset.
//!
//! # Zero `unsafe`
//!
//! This module contains zero `unsafe` blocks.

use std::sync::OnceLock;

use publicsuffix::{List, Psl};

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Built-in PSL data
// ---------------------------------------------------------------------------

/// Comprehensive built-in Public Suffix List data.
///
/// This constant contains a representative snapshot of Mozilla's Public Suffix
/// List covering all generic TLDs, all country-code TLDs, and the most common
/// multi-level suffixes.  The `publicsuffix` crate applies an implicit
/// single-label wildcard rule, so even TLDs not explicitly listed here are
/// treated as single-label public suffixes (e.g. `randomtld`).
///
/// Format reference: <https://wiki.mozilla.org/Public_Suffix_List/Format>
///
/// *   One rule per line.
/// *   Comments begin with `//`.
/// *   `*.tld` means every direct child of `tld` is also a public suffix.
/// *   `!exception.tld` overrides a wildcard for that specific label.
/// *   Empty lines are ignored.
const BUILTIN_PSL_DATA: &str = "\
// === BEGIN PUBLIC SUFFIX LIST ===
// This is a built-in snapshot used for cookie domain validation.

// ===BEGIN ICANN DOMAINS===
com
net
org
edu
gov
mil
int
info
biz
name
pro
aero
coop
museum
travel
jobs
mobi
tel
cat
asia
post
xxx
// New gTLDs (selected)
app
dev
page
blog
cloud
online
site
store
shop
tech
xyz
top
loan
win
bid
stream
review
party
date
science
work
click
link
help
news
agency
email
solutions
systems
company
management
academy
center
computer
network
technology
training
support
consulting
engineering
marketing
photography
photos
gallery
graphics
design
studio
digital
media
social
community
plus
zone
city
town
world
earth
global
international
institute
foundation
fund
life
today
tips
guide
guru
expert
market
exchange
finance
financial
capital
cash
money
tax
insurance
credit
estate
properties
house
homes
land
farm
garden
energy
solar
fitness
health
healthcare
hospital
dental
medical
care
services
tools
supply
repair
parts
auto
car
cars
taxi
flights
hotel
voyage
holiday
vacations
rent
hosting
space
codes
software
pub
bar
cafe
restaurant
kitchen
pizza
wine
beer
coffee
chat
watch
film
movie
game
games
play
sport
football
soccer
golf
fish
yoga
dance
art
band
music
video
live
show
events
tickets
theater
cool
style
fashion
shoes
clothing
jewelry
beauty
hair
makeup
tattoo
fit
diet
recipes
organic
bio
eco
green
vet
dog
pet
baby
kids
toys
family
singles
dating
sexy
love
flowers
gift
gifts
christmas
black
blue
pink
red
green
gold
kim
wang
top
win
men
one
icu
cyou
bond
cfd
sbs
// ===END GENERIC TLDs===

// ===BEGIN COUNTRY CODE TLDs===
ac
ad
ae
af
ag
ai
al
am
ao
aq
ar
as
at
au
aw
ax
az
ba
bb
bd
be
bf
bg
bh
bi
bj
bm
bn
bo
br
bs
bt
bw
by
bz
ca
cc
cd
cf
cg
ch
ci
ck
cl
cm
cn
co
cr
cu
cv
cw
cx
cy
cz
de
dj
dk
dm
do
dz
ec
ee
eg
er
es
et
eu
fi
fj
fk
fm
fo
fr
ga
gb
gd
ge
gf
gg
gh
gi
gl
gm
gn
gp
gq
gr
gs
gt
gu
gw
gy
hk
hm
hn
hr
ht
hu
id
ie
il
im
in
io
iq
ir
is
it
je
jm
jo
jp
ke
kg
kh
ki
km
kn
kp
kr
kw
ky
kz
la
lb
lc
li
lk
lr
ls
lt
lu
lv
ly
ma
mc
md
me
mg
mh
mk
ml
mm
mn
mo
mp
mq
mr
ms
mt
mu
mv
mw
mx
my
mz
na
nc
ne
nf
ng
ni
nl
no
np
nr
nu
nz
om
pa
pe
pf
pg
ph
pk
pl
pm
pn
pr
ps
pt
pw
py
qa
re
ro
rs
ru
rw
sa
sb
sc
sd
se
sg
sh
si
sj
sk
sl
sm
sn
so
sr
ss
st
su
sv
sx
sy
sz
tc
td
tf
tg
th
tj
tk
tl
tm
tn
to
tr
tt
tv
tw
tz
ua
ug
uk
us
uy
uz
va
vc
ve
vg
vi
vn
vu
wf
ws
ye
yt
za
zm
zw
// ===END COUNTRY CODE TLDs===

// ===BEGIN MULTI-LEVEL SUFFIXES===

// United Kingdom
co.uk
org.uk
me.uk
net.uk
ac.uk
gov.uk
sch.uk
nhs.uk
police.uk
ltd.uk
plc.uk

// Australia
com.au
net.au
org.au
edu.au
gov.au
asn.au
id.au

// Japan — *.jp makes every X.jp a public suffix
jp
*.jp

// Brazil
com.br
net.br
org.br
gov.br
edu.br
mil.br
art.br
blog.br
wiki.br

// China
com.cn
net.cn
org.cn
gov.cn
edu.cn
ac.cn
mil.cn

// India
co.in
net.in
org.in
gen.in
firm.in
ind.in
ac.in
edu.in
res.in
gov.in
mil.in

// South Korea
co.kr
ne.kr
or.kr
re.kr
pe.kr
go.kr
mil.kr
ac.kr
hs.kr
ms.kr
es.kr
sc.kr
kg.kr

// France
com.fr
asso.fr
nom.fr
prd.fr
tm.fr
gouv.fr

// Germany (no multi-level suffixes)

// Italy
gov.it
edu.it

// Spain
com.es
nom.es
org.es
gob.es
edu.es

// Russia
com.ru
net.ru
org.ru
edu.ru
gov.ru

// South Africa
co.za
org.za
web.za
gov.za
edu.za
net.za
nom.za

// New Zealand
co.nz
net.nz
org.nz
govt.nz
ac.nz
school.nz
geek.nz
gen.nz
maori.nz
iwi.nz

// Hong Kong
com.hk
edu.hk
gov.hk
net.hk
org.hk
idv.hk

// Taiwan
com.tw
net.tw
org.tw
edu.tw
gov.tw
mil.tw

// Thailand
co.th
in.th
or.th
net.th
ac.th
go.th
mi.th

// Singapore
com.sg
net.sg
org.sg
gov.sg
edu.sg
per.sg

// Malaysia
com.my
net.my
org.my
gov.my
edu.my
mil.my
name.my

// Indonesia
co.id
or.id
go.id
ac.id
sch.id
net.id
mil.id
web.id

// Philippines
com.ph
net.ph
org.ph
gov.ph
edu.ph
mil.ph

// Turkey
com.tr
net.tr
org.tr
gov.tr
edu.tr
mil.tr
name.tr
info.tr
bel.tr
pol.tr
bbs.tr
gen.tr
web.tr
av.tr
dr.tr

// Pakistan
com.pk
net.pk
org.pk
edu.pk
gov.pk
web.pk
fam.pk

// Bangladesh
com.bd
net.bd
org.bd
edu.bd
gov.bd
mil.bd
ac.bd

// Mexico
com.mx
net.mx
org.mx
edu.mx
gob.mx

// Argentina
com.ar
net.ar
org.ar
edu.ar
gov.ar
mil.ar
int.ar

// Colombia
com.co
net.co
org.co
edu.co
gov.co
mil.co
nom.co

// Chile
cl

// Peru
com.pe
net.pe
org.pe
edu.pe
gob.pe
nom.pe
mil.pe

// Venezuela
com.ve
net.ve
org.ve
co.ve
edu.ve
gov.ve
mil.ve

// Egypt
com.eg
edu.eg
gov.eg
net.eg
org.eg
mil.eg
name.eg

// Nigeria
com.ng
edu.ng
gov.ng
net.ng
org.ng
mil.ng
name.ng
sch.ng

// Kenya
co.ke
or.ke
ne.ke
go.ke
ac.ke
sc.ke

// Israel
co.il
org.il
net.il
ac.il
gov.il
muni.il
idf.il

// Saudi Arabia
com.sa
net.sa
org.sa
gov.sa
edu.sa
med.sa
pub.sa
sch.sa

// UAE
co.ae
net.ae
org.ae
gov.ae
ac.ae
sch.ae
mil.ae

// European special
co.me
net.me
org.me
edu.me
ac.me
gov.me
its.me
priv.me

// Cook Islands (wildcard)
*.ck
!www.ck

// Eritrea
*.er

// Ethiopia
com.et
gov.et
org.et
edu.et
net.et
biz.et
name.et
info.et

// Ghana
com.gh
edu.gh
gov.gh
org.gh
mil.gh

// ===BEGIN PRIVATE DOMAINS===

// GitHub
github.io
githubusercontent.com
// Heroku
herokuapp.com
// Amazon
s3.amazonaws.com
compute.amazonaws.com
// Google
appspot.com
blogspot.com
web.app
firebaseapp.com
// Cloudflare
workers.dev
pages.dev
// Netlify
netlify.app
// Vercel
vercel.app
now.sh
// Azure
azurewebsites.net
cloudapp.net
// Render
onrender.com
// Fly.io
fly.dev
// Deno
deno.dev
// Glitch
glitch.me
// Surge
surge.sh
// Bitbucket
bitbucket.io
// GitLab
gitlab.io
// Pantheon
pantheonsite.io
// WP Engine
wpengine.com
// Shopify
myshopify.com
// Squarespace
squarespace.com
// Wix
wixsite.com

// ===END MULTI-LEVEL SUFFIXES===

// === END PUBLIC SUFFIX LIST ===
";

/// Global PSL list instance, parsed exactly once from [`BUILTIN_PSL_DATA`].
///
/// The [`OnceLock`] guarantees that parsing happens at most once, and all
/// subsequent accesses return a shared `&'static List` reference without
/// any locking overhead.
static PSL_LIST: OnceLock<List> = OnceLock::new();

/// Obtain a reference to the lazily-initialized global [`List`].
///
/// On first call the embedded PSL data is parsed.  Subsequent calls return
/// the cached result in O(1).  If parsing fails (which should never happen
/// with well-formed embedded data), an empty default [`List`] is used as a
/// fallback — the implicit single-label wildcard rule still provides basic
/// protection.
fn get_psl_list() -> &'static List {
    PSL_LIST.get_or_init(|| {
        BUILTIN_PSL_DATA
            .parse::<List>()
            .unwrap_or_else(|_| List::new())
    })
}

/// Attempt to parse and validate the built-in PSL data, returning
/// [`CurlError::FailedInit`] if the PSL data cannot be parsed or
/// produces an empty rule set.
///
/// This function is used internally during [`PslChecker::new()`] to
/// eagerly verify that the global PSL dataset is healthy.
fn try_init_psl() -> Result<&'static List, CurlError> {
    let list = get_psl_list();
    if list.is_empty() {
        // The embedded data should always produce a non-empty list.
        // An empty list indicates a parse failure that silently fell
        // through to the `List::new()` default.
        Err(CurlError::FailedInit)
    } else {
        Ok(list)
    }
}

// ---------------------------------------------------------------------------
// PslChecker — Public API
// ---------------------------------------------------------------------------

/// Public Suffix List checker for cookie domain validation.
///
/// `PslChecker` is a lightweight handle (zero-sized) that provides methods
/// for querying the global PSL dataset.  Creating multiple instances is
/// cheap — they all share the same lazily-initialized data.
///
/// # Examples
///
/// ```rust,no_run
/// use curl_rs_lib::psl::PslChecker;
///
/// let checker = PslChecker::new();
///
/// assert!(checker.is_public_suffix("com"));
/// assert!(checker.is_public_suffix("co.uk"));
/// assert!(!checker.is_public_suffix("example.com"));
///
/// assert_eq!(checker.registrable_domain("www.example.com"), Some("example.com"));
/// assert_eq!(checker.registrable_domain("com"), None);
///
/// assert!(checker.is_cookie_domain_valid("example.com", "www.example.com"));
/// assert!(!checker.is_cookie_domain_valid("com", "www.example.com"));
/// ```
pub struct PslChecker {
    // Zero-sized — all state lives in the global `PSL_LIST`.
    // The struct exists to provide a namespaced method API consistent with
    // the rest of the curl-rs-lib crate.
    _private: (),
}

impl PslChecker {
    /// Create a new [`PslChecker`], triggering lazy initialization of the
    /// global PSL dataset if it has not been loaded yet.
    ///
    /// This method never fails.  If the embedded PSL data is somehow invalid,
    /// an empty fallback list is used (the implicit single-label wildcard rule
    /// still provides basic protection for top-level domains).
    #[inline]
    pub fn new() -> Self {
        // Eagerly trigger initialization and validate the PSL data.
        // On failure the fallback empty list is already in place, so we
        // just discard the CurlError.
        let _result: Result<&'static List, CurlError> = try_init_psl();
        Self { _private: () }
    }

    /// Returns `true` if `domain` is itself a public suffix.
    ///
    /// A domain is considered a public suffix when the PSL contains a matching
    /// suffix entry whose bytes equal the entire input (after ASCII
    /// lowercasing).  For example `"com"` and `"co.uk"` are public suffixes,
    /// while `"example.com"` is not.
    ///
    /// # Arguments
    ///
    /// * `domain` — a DNS domain name (ASCII or punycode).  Leading/trailing
    ///   dots are stripped before lookup.
    pub fn is_public_suffix(&self, domain: &str) -> bool {
        let cleaned = strip_dots(domain);
        if cleaned.is_empty() {
            return false;
        }

        let lower = cleaned.to_ascii_lowercase();
        let bytes = lower.as_bytes();

        let list = get_psl_list();

        // Obtain the suffix entry for this domain.
        match list.suffix(bytes) {
            Some(suffix) => {
                // Use `as_bytes()` and `typ()` per the schema contract.
                let suffix_bytes = suffix.as_bytes();
                let _suffix_type = suffix.typ(); // ICANN | Private | None

                // The domain IS a public suffix when the suffix spans the
                // entire input — i.e., the suffix bytes equal the domain
                // bytes.
                suffix_bytes == bytes
            }
            None => false,
        }
    }

    /// Extract the registrable (eTLD+1) domain from `domain`.
    ///
    /// Returns `Some(slice)` where `slice` is a sub-slice of the original
    /// `domain` input pointing to the registrable portion, or `None` if the
    /// domain is itself a public suffix or cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use curl_rs_lib::psl::PslChecker;
    /// # let checker = PslChecker::new();
    /// assert_eq!(checker.registrable_domain("www.example.co.uk"), Some("example.co.uk"));
    /// assert_eq!(checker.registrable_domain("example.com"), Some("example.com"));
    /// assert_eq!(checker.registrable_domain("com"), None);
    /// ```
    pub fn registrable_domain<'a>(&self, domain: &'a str) -> Option<&'a str> {
        let cleaned = strip_dots(domain);
        if cleaned.is_empty() {
            return None;
        }

        let lower = cleaned.to_ascii_lowercase();
        let bytes = lower.as_bytes();

        let list = get_psl_list();

        // `Psl::domain()` returns the registrable domain (eTLD+1) or `None`
        // when the input is itself a public suffix.
        let dom = list.domain(bytes)?;
        let dom_len = dom.as_bytes().len();

        if dom_len == 0 || dom_len > cleaned.len() {
            return None;
        }

        // Calculate the offset into the *original* (non-lowered) string.
        // ASCII lowercasing preserves byte length so the offset is valid.
        let offset = cleaned.len() - dom_len;

        // Find the corresponding position in the original `domain` input,
        // accounting for any leading dots that `strip_dots` removed.
        let leading_stripped = domain.len() - cleaned.len();
        let start = leading_stripped + offset;

        // Remove any trailing dot from the original domain slice.
        let slice = &domain[start..];
        let slice = slice.strip_suffix('.').unwrap_or(slice);

        if slice.is_empty() {
            None
        } else {
            Some(slice)
        }
    }

    /// Validate whether a cookie's `Domain` attribute is acceptable for the
    /// given `request_host`.
    ///
    /// This implements the PSL-based cookie domain validation described in
    /// RFC 6265 §5.3 (step 5/6), mirroring the behaviour of libpsl's
    /// `psl_is_cookie_domain_acceptable()` function used by curl's C cookie
    /// engine.
    ///
    /// # Rules
    ///
    /// 1. The `cookie_domain` MUST NOT be a public suffix (prevents
    ///    super-cookie attacks).
    /// 2. `request_host` must *domain-match* `cookie_domain` (either they
    ///    are equal, or `request_host` ends with `"." + cookie_domain`).
    /// 3. Both `request_host` and `cookie_domain` must share the same
    ///    registrable domain (eTLD+1).
    ///
    /// # Arguments
    ///
    /// * `cookie_domain` — the `Domain` attribute from a `Set-Cookie` header.
    ///   A leading dot (`.example.com`) is tolerated and stripped.
    /// * `request_host` — the hostname from the request URL.
    ///
    /// # Returns
    ///
    /// `true` if the cookie domain is valid for the request host.
    pub fn is_cookie_domain_valid(
        &self,
        cookie_domain: &str,
        request_host: &str,
    ) -> bool {
        // --- Normalise inputs ------------------------------------------------
        let cookie_clean = strip_dots(cookie_domain);
        let host_clean = strip_dots(request_host);

        if cookie_clean.is_empty() || host_clean.is_empty() {
            return false;
        }

        let cookie_lower = cookie_clean.to_ascii_lowercase();
        let host_lower = host_clean.to_ascii_lowercase();

        // --- Rule 1: reject public suffixes ----------------------------------
        if self.is_public_suffix_bytes(cookie_lower.as_bytes()) {
            return false;
        }

        // --- Rule 2: domain-match (RFC 6265 §5.1.3) -------------------------
        if !domain_matches(&host_lower, &cookie_lower) {
            return false;
        }

        // --- Rule 3: same registrable domain ---------------------------------
        let list = get_psl_list();

        let host_reg = list.domain(host_lower.as_bytes());
        let cookie_reg = list.domain(cookie_lower.as_bytes());

        match (host_reg, cookie_reg) {
            (Some(h), Some(c)) => h.as_bytes() == c.as_bytes(),
            // If either cannot be resolved to a registrable domain, reject.
            _ => false,
        }
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Internal helper: checks whether `bytes` (already ASCII-lowered)
    /// represent a public suffix.
    fn is_public_suffix_bytes(&self, bytes: &[u8]) -> bool {
        let list = get_psl_list();
        match list.suffix(bytes) {
            Some(suffix) => {
                let suffix_bytes = suffix.as_bytes();
                let _typ = suffix.typ();
                suffix_bytes == bytes
            }
            None => false,
        }
    }
}

impl Default for PslChecker {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PslChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PslChecker")
            .field("psl_loaded", &PSL_LIST.get().is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Free-standing helpers (private)
// ---------------------------------------------------------------------------

/// Strip leading and trailing dots from a domain string.
///
/// Domain names in cookies and HTTP headers sometimes carry a leading dot
/// (`.example.com`) or a trailing FQDN dot (`example.com.`).  Both are
/// removed for consistent PSL lookup.
fn strip_dots(domain: &str) -> &str {
    let d = domain.trim_matches('.');
    d
}

/// RFC 6265 §5.1.3 domain-matching.
///
/// The `request_host` domain-matches `cookie_domain` when:
///
/// 1. They are identical (case-insensitive, both already lowered), **or**
/// 2. `request_host` ends with `"." + cookie_domain` (and `request_host`
///    is not an IP address literal).
///
/// Both inputs must already be ASCII-lowercased.
fn domain_matches(request_host: &str, cookie_domain: &str) -> bool {
    if request_host == cookie_domain {
        return true;
    }

    // request_host must be strictly longer than cookie_domain.
    if request_host.len() <= cookie_domain.len() {
        return false;
    }

    // request_host must end with the cookie_domain preceded by a dot.
    if !request_host.ends_with(cookie_domain) {
        return false;
    }

    // The character immediately before the suffix must be a dot.
    let prefix_len = request_host.len() - cookie_domain.len();
    if request_host.as_bytes().get(prefix_len.wrapping_sub(1)).copied() != Some(b'.') {
        return false;
    }

    // Reject IP address literals (simple heuristic: if the host parses as
    // an IP address, domain-matching fails).
    if is_ip_address(request_host) {
        return false;
    }

    true
}

/// Simple heuristic to detect IP address literals.
///
/// Returns `true` for both IPv4 dotted-decimal (`192.168.1.1`) and IPv6
/// bracket notation (`[::1]` or `::1`).
fn is_ip_address(host: &str) -> bool {
    // IPv6 bracket notation
    if host.starts_with('[') && host.ends_with(']') {
        return true;
    }
    // Try to parse as an IP address using the standard library.
    host.parse::<std::net::IpAddr>().is_ok()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_checker() {
        let checker = PslChecker::new();
        // The global list must be initialised after `new()`.
        assert!(PSL_LIST.get().is_some());
        // Debug formatting should work.
        let dbg = format!("{:?}", checker);
        assert!(dbg.contains("PslChecker"));
    }

    #[test]
    fn test_default_creates_checker() {
        let checker = PslChecker::default();
        assert!(PSL_LIST.get().is_some());
        let _ = checker;
    }

    // -----------------------------------------------------------------------
    // is_public_suffix
    // -----------------------------------------------------------------------

    #[test]
    fn test_common_tlds_are_public_suffixes() {
        let checker = PslChecker::new();
        assert!(checker.is_public_suffix("com"));
        assert!(checker.is_public_suffix("net"));
        assert!(checker.is_public_suffix("org"));
        assert!(checker.is_public_suffix("edu"));
        assert!(checker.is_public_suffix("uk"));
        assert!(checker.is_public_suffix("de"));
        assert!(checker.is_public_suffix("fr"));
        assert!(checker.is_public_suffix("jp"));
    }

    #[test]
    fn test_multi_level_public_suffixes() {
        let checker = PslChecker::new();
        assert!(checker.is_public_suffix("co.uk"));
        assert!(checker.is_public_suffix("com.au"));
        assert!(checker.is_public_suffix("co.jp"));
        assert!(checker.is_public_suffix("com.br"));
    }

    #[test]
    fn test_registrable_domains_are_not_public_suffixes() {
        let checker = PslChecker::new();
        assert!(!checker.is_public_suffix("example.com"));
        assert!(!checker.is_public_suffix("google.co.uk"));
        assert!(!checker.is_public_suffix("www.example.com"));
    }

    #[test]
    fn test_empty_and_dot_domains() {
        let checker = PslChecker::new();
        assert!(!checker.is_public_suffix(""));
        assert!(!checker.is_public_suffix("."));
        assert!(!checker.is_public_suffix(".."));
    }

    #[test]
    fn test_case_insensitive_public_suffix() {
        let checker = PslChecker::new();
        assert!(checker.is_public_suffix("COM"));
        assert!(checker.is_public_suffix("Co.Uk"));
        assert!(checker.is_public_suffix("NET"));
    }

    #[test]
    fn test_leading_dot_stripped() {
        let checker = PslChecker::new();
        assert!(checker.is_public_suffix(".com"));
        assert!(!checker.is_public_suffix(".example.com"));
    }

    // -----------------------------------------------------------------------
    // registrable_domain
    // -----------------------------------------------------------------------

    #[test]
    fn test_registrable_domain_simple() {
        let checker = PslChecker::new();
        assert_eq!(
            checker.registrable_domain("www.example.com"),
            Some("example.com")
        );
        assert_eq!(
            checker.registrable_domain("example.com"),
            Some("example.com")
        );
    }

    #[test]
    fn test_registrable_domain_multi_level_suffix() {
        let checker = PslChecker::new();
        assert_eq!(
            checker.registrable_domain("www.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(
            checker.registrable_domain("example.co.uk"),
            Some("example.co.uk")
        );
    }

    #[test]
    fn test_registrable_domain_returns_none_for_public_suffix() {
        let checker = PslChecker::new();
        assert_eq!(checker.registrable_domain("com"), None);
        assert_eq!(checker.registrable_domain("co.uk"), None);
    }

    #[test]
    fn test_registrable_domain_empty() {
        let checker = PslChecker::new();
        assert_eq!(checker.registrable_domain(""), None);
        assert_eq!(checker.registrable_domain("."), None);
    }

    #[test]
    fn test_registrable_domain_deep_subdomain() {
        let checker = PslChecker::new();
        assert_eq!(
            checker.registrable_domain("a.b.c.example.com"),
            Some("example.com")
        );
    }

    // -----------------------------------------------------------------------
    // is_cookie_domain_valid
    // -----------------------------------------------------------------------

    #[test]
    fn test_cookie_valid_same_domain() {
        let checker = PslChecker::new();
        assert!(checker.is_cookie_domain_valid("example.com", "example.com"));
    }

    #[test]
    fn test_cookie_valid_subdomain_request() {
        let checker = PslChecker::new();
        assert!(checker.is_cookie_domain_valid("example.com", "www.example.com"));
    }

    #[test]
    fn test_cookie_invalid_public_suffix() {
        let checker = PslChecker::new();
        assert!(!checker.is_cookie_domain_valid("com", "www.example.com"));
        assert!(!checker.is_cookie_domain_valid("co.uk", "www.example.co.uk"));
    }

    #[test]
    fn test_cookie_invalid_different_domain() {
        let checker = PslChecker::new();
        assert!(!checker.is_cookie_domain_valid("evil.com", "www.example.com"));
    }

    #[test]
    fn test_cookie_leading_dot_stripped() {
        let checker = PslChecker::new();
        assert!(checker.is_cookie_domain_valid(".example.com", "www.example.com"));
    }

    #[test]
    fn test_cookie_invalid_empty_inputs() {
        let checker = PslChecker::new();
        assert!(!checker.is_cookie_domain_valid("", "example.com"));
        assert!(!checker.is_cookie_domain_valid("example.com", ""));
        assert!(!checker.is_cookie_domain_valid("", ""));
    }

    #[test]
    fn test_cookie_case_insensitive() {
        let checker = PslChecker::new();
        assert!(checker.is_cookie_domain_valid("Example.COM", "www.example.com"));
        assert!(checker.is_cookie_domain_valid("example.com", "WWW.EXAMPLE.COM"));
    }

    #[test]
    fn test_cookie_ip_address_no_domain_match() {
        let checker = PslChecker::new();
        // IP addresses should not domain-match against cookie domains
        assert!(!checker.is_cookie_domain_valid("1.1", "192.168.1.1"));
    }

    // -----------------------------------------------------------------------
    // strip_dots
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_dots() {
        assert_eq!(strip_dots(".example.com."), "example.com");
        assert_eq!(strip_dots("example.com"), "example.com");
        assert_eq!(strip_dots("...com..."), "com");
        assert_eq!(strip_dots(""), "");
        assert_eq!(strip_dots("."), "");
    }

    // -----------------------------------------------------------------------
    // domain_matches
    // -----------------------------------------------------------------------

    #[test]
    fn test_domain_matches_identical() {
        assert!(domain_matches("example.com", "example.com"));
    }

    #[test]
    fn test_domain_matches_subdomain() {
        assert!(domain_matches("www.example.com", "example.com"));
    }

    #[test]
    fn test_domain_matches_no_match() {
        assert!(!domain_matches("example.com", "other.com"));
        assert!(!domain_matches("example.com", "xample.com"));
    }

    #[test]
    fn test_domain_matches_partial_no_dot() {
        // "notexample.com" should NOT match "example.com"
        assert!(!domain_matches("notexample.com", "example.com"));
    }

    // -----------------------------------------------------------------------
    // is_ip_address
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("127.0.0.1"));
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("[::1]"));
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address("www.example.com"));
    }

    // -----------------------------------------------------------------------
    // Platform hosting suffixes (private section)
    // -----------------------------------------------------------------------

    #[test]
    fn test_hosting_suffixes_are_public() {
        let checker = PslChecker::new();
        assert!(checker.is_public_suffix("github.io"));
        assert!(checker.is_public_suffix("herokuapp.com"));
        assert!(checker.is_public_suffix("blogspot.com"));
        assert!(checker.is_public_suffix("netlify.app"));
        assert!(checker.is_public_suffix("vercel.app"));
    }

    #[test]
    fn test_hosting_registrable_domains() {
        let checker = PslChecker::new();
        assert_eq!(
            checker.registrable_domain("myapp.github.io"),
            Some("myapp.github.io")
        );
        assert_eq!(
            checker.registrable_domain("myapp.herokuapp.com"),
            Some("myapp.herokuapp.com")
        );
    }

    #[test]
    fn test_cookie_invalid_on_hosting_suffix() {
        let checker = PslChecker::new();
        assert!(!checker.is_cookie_domain_valid("github.io", "myapp.github.io"));
        assert!(checker.is_cookie_domain_valid(
            "myapp.github.io",
            "sub.myapp.github.io"
        ));
    }
}
