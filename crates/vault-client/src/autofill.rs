//! Autofill matching (spec, Autofill matching): which items fill a page, in which frames, and
//! what a submitted form offers to save. The inputs are plain data, so the Firefox (WASM) and
//! Android clients run the same code; the host supplies the known public suffix of a host from
//! its platform's copy of the Public Suffix List.
//!
//! A [`Page`] is a Firefox page URL, an Android web page from an allowlisted browser, or an
//! Android app page. The functions that take a page URL as text are the Firefox (web) forms of
//! [`page_candidates`] and [`page_save_offer`].

use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};
use vault_core::body::{AndroidApp, Item, MatchMode};
use vault_core::json::Map;

/// The host's Public Suffix List lookup.
pub trait SuffixList {
    /// The longest public suffix that an explicit rule gives `host`, ICANN and private sections
    /// both, or `None` when only the default `*` rule applies. `host` is lowercase ASCII without
    /// a trailing `.`.
    fn known_suffix(&self, host: &str) -> Option<String>;
}

impl<F: Fn(&str) -> Option<String>> SuffixList for F {
    fn known_suffix(&self, host: &str) -> Option<String> {
        self(host)
    }
}

/// A host after parsing, with one trailing `.` removed from a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlHost {
    /// A domain in lowercase ASCII.
    Domain(String),
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address.
    Ipv6(Ipv6Addr),
}

impl UrlHost {
    /// The host as a WHATWG URL serialises it: an IPv6 address compressed, in brackets.
    pub fn text(&self) -> String {
        match self {
            UrlHost::Domain(d) => d.clone(),
            UrlHost::Ipv4(a) => Host::<String>::Ipv4(*a).to_string(),
            UrlHost::Ipv6(a) => Host::<String>::Ipv6(*a).to_string(),
        }
    }
}

/// An `http` or `https` URL prepared for matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// `http` or `https`.
    pub scheme: String,
    /// The host.
    pub host: UrlHost,
    /// The port, or `None` for the scheme's default.
    pub port: Option<u16>,
    /// The serialised path followed, when a query is present, by `?` and the query.
    pub path_query: String,
}

impl Prepared {
    fn from_url(u: &Url) -> Option<Prepared> {
        if !matches!(u.scheme(), "http" | "https") {
            return None;
        }
        let host = match u.host()? {
            Host::Domain(d) => {
                // One trailing `.` goes; a domain with an empty label left never matches.
                let d = d.strip_suffix('.').unwrap_or(d);
                if d.split('.').any(str::is_empty) {
                    return None;
                }
                UrlHost::Domain(d.to_owned())
            }
            Host::Ipv4(a) => UrlHost::Ipv4(a),
            Host::Ipv6(a) => UrlHost::Ipv6(a),
        };
        let mut path_query = u.path().to_owned();
        if let Some(q) = u.query() {
            path_query.push('?');
            path_query.push_str(q);
        }
        Some(Prepared {
            scheme: u.scheme().to_owned(),
            host,
            port: u.port(),
            path_query,
        })
    }

    /// Whether the origins (scheme, host, and port) are equal.
    pub fn same_origin(&self, other: &Prepared) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port == other.port
    }

    /// The origin serialised: the scheme, `://`, the host, and a non-default port.
    pub fn origin(&self) -> String {
        match self.port {
            Some(p) => format!("{}://{}:{p}", self.scheme, self.host.text()),
            None => format!("{}://{}", self.scheme, self.host.text()),
        }
    }
}

/// A page URL from the browser: `None` unless it parses with the scheme `http` or `https` and a
/// host, and its domain has no empty label once one trailing `.` is removed.
pub fn page_url(url: &str) -> Option<Prepared> {
    Prepared::from_url(&Url::parse(url).ok()?)
}

/// Prepares an item URI: trims ASCII whitespace, prefixes `https://` unless it starts with a
/// scheme and `://`, and parses it. `None` when it fails to parse, its scheme is not `http` or `https`, or it has user
/// information, as `mailto:x@example.com` has once prefixed.
pub fn prepare_uri(uri: &str) -> Option<Prepared> {
    let t = uri.trim_matches(|c: char| c.is_ascii_whitespace());
    let u = if starts_with_scheme(t) {
        Url::parse(t)
    } else {
        Url::parse(&format!("https://{t}"))
    }
    .ok()?;
    if !u.username().is_empty() || u.password().is_some() {
        return None;
    }
    Prepared::from_url(&u)
}

/// A known-suffix answer that is neither the whole host nor a sequence of its trailing labels.
/// A URI whose host or page host gets one does not match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadSuffixAnswer;

/// Whether `t` starts with a scheme followed by `://`: an ASCII letter, then ASCII letters,
/// digits, `+`, `-`, or `.`.
fn starts_with_scheme(t: &str) -> bool {
    let Some((scheme, _)) = t.split_once("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The known suffix of a domain from `suffixes`, checked: it equals the whole domain or a
/// sequence of its trailing labels.
pub fn known_suffix(
    domain: &str,
    suffixes: &dyn SuffixList,
) -> Result<Option<String>, BadSuffixAnswer> {
    let Some(s) = suffixes.known_suffix(domain) else {
        return Ok(None);
    };
    let whole_labels = domain
        .strip_suffix(s.as_str())
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'));
    if !s.is_empty() && whole_labels {
        Ok(Some(s))
    } else {
        Err(BadSuffixAnswer)
    }
}

/// The checked known suffix of a host; an IP address has none.
fn host_suffix(
    host: &UrlHost,
    suffixes: &dyn SuffixList,
) -> Result<Option<String>, BadSuffixAnswer> {
    match host {
        UrlHost::Domain(d) => known_suffix(d, suffixes),
        _ => Ok(None),
    }
}

/// The registrable domain of a host, as its URL text: the host itself when it is an IP address,
/// has no known suffix, or equals its known suffix, and otherwise the known suffix with the one
/// label before it.
pub fn registrable_domain(
    host: &UrlHost,
    suffixes: &dyn SuffixList,
) -> Result<String, BadSuffixAnswer> {
    Ok(registrable(host, host_suffix(host, suffixes)?.as_deref()))
}

fn registrable(host: &UrlHost, suffix: Option<&str>) -> String {
    match (host, suffix) {
        (UrlHost::Domain(d), Some(s)) if s.len() < d.len() => {
            let rest = &d[..d.len() - s.len() - 1];
            let label = rest.rsplit('.').next().unwrap_or(rest);
            format!("{label}.{s}")
        }
        _ => host.text(),
    }
}

/// Whether a page host is a local host under the scheme rule.
pub fn is_local_host(host: &UrlHost, suffixes: &dyn SuffixList) -> Result<bool, BadSuffixAnswer> {
    Ok(local(host, host_suffix(host, suffixes)?.as_deref()))
}

fn local(host: &UrlHost, suffix: Option<&str>) -> bool {
    match host {
        UrlHost::Domain(d) => suffix.is_none() || d == "home.arpa" || d.ends_with(".home.arpa"),
        UrlHost::Ipv4(a) => {
            let o = a.octets();
            o[0] == 127
                || o[0] == 10
                || (o[0] == 172 && (16..32).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
        }
        UrlHost::Ipv6(a) => {
            let s = a.segments();
            *a == Ipv6Addr::LOCALHOST || s[0] & 0xfe00 == 0xfc00 || s[0] & 0xffc0 == 0xfe80
        }
    }
}

/// The outcome of a URI or an item against a page, ordered from worst to best.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    /// No match.
    None,
    /// A match that fills only after the user confirms it.
    Confirm,
    /// A match that fills.
    Fill,
}

/// Whether a prepared item URI matches a page under `mode`, with the scheme rule applied. A
/// known-suffix answer that fails its check, for either host, means no match in every mode.
pub fn match_prepared(
    page: &Prepared,
    item: &Prepared,
    mode: MatchMode,
    suffixes: &dyn SuffixList,
) -> Outcome {
    let (Ok(page_suffix), Ok(item_suffix)) = (
        host_suffix(&page.host, suffixes),
        host_suffix(&item.host, suffixes),
    ) else {
        return Outcome::None;
    };
    let holds = match mode {
        MatchMode::BaseDomain => {
            registrable(&page.host, page_suffix.as_deref())
                == registrable(&item.host, item_suffix.as_deref())
        }
        MatchMode::Host => page.host == item.host && page.port == item.port,
        MatchMode::StartsWith => {
            page.same_origin(item) && page.path_query.starts_with(&item.path_query)
        }
        MatchMode::Exact => page.same_origin(item) && page.path_query == item.path_query,
        MatchMode::Never => false,
    };
    if !holds {
        Outcome::None
    } else if item.scheme == "https" && page.scheme == "http" {
        if local(&page.host, page_suffix.as_deref()) {
            Outcome::Confirm
        } else {
            Outcome::None
        }
    } else {
        Outcome::Fill
    }
}

/// The outcome of one item URI, with its `match` value, against a page.
pub fn match_uri(
    page: &Prepared,
    uri: &str,
    mode: MatchMode,
    suffixes: &dyn SuffixList,
) -> Outcome {
    match prepare_uri(uri) {
        Some(item) => match_prepared(page, &item, mode, suffixes),
        None => Outcome::None,
    }
}

/// An item's outcome against a page: for a web page, the best of its URIs (`None` for an item
/// that is not a login or has no URIs); for an app page, the outcome of its [`AppMatch`].
pub fn item_outcome(page: &Page, item: &Item, suffixes: &dyn SuffixList) -> Outcome {
    match page {
        Page::App(app) => app_match(item, app).map_or(Outcome::None, AppMatch::outcome),
        Page::Web(p) | Page::AndroidWeb(p) => {
            let android = matches!(page, Page::AndroidWeb(_));
            item.login().map_or(Outcome::None, |l| {
                l.uris
                    .iter()
                    .map(|u| match prepare_uri(&u.uri) {
                        Some(i) if android => match_android(p, &i, u.match_mode(), suffixes),
                        Some(i) => match_prepared(p, &i, u.match_mode(), suffixes),
                        None => Outcome::None,
                    })
                    .max()
                    .unwrap_or(Outcome::None)
            })
        }
    }
}

/// The candidates for a fill on `page`: the items whose outcome is not `None`, `Fill` first, then
/// by `name` compared as Unicode code points, then by `id`. For an app page these are exactly
/// the items with an association with the app.
pub fn page_candidates<'a>(
    page: &Page,
    items: &'a [Item],
    suffixes: &dyn SuffixList,
) -> Vec<(&'a Item, Outcome)> {
    let mut out: Vec<(&Item, Outcome)> = items
        .iter()
        .map(|i| (i, item_outcome(page, i, suffixes)))
        .filter(|(_, o)| *o != Outcome::None)
        .collect();
    out.sort_by(|(a, oa), (b, ob)| {
        ob.cmp(oa)
            .then_with(|| name(a).cmp(name(b)))
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

/// The candidates for a fill on the Firefox page URL `page_url_text`, as [`page_candidates`]
/// gives them for a web page. Empty when the URL is not a page URL.
pub fn candidates<'a>(
    page_url_text: &str,
    items: &'a [Item],
    suffixes: &dyn SuffixList,
) -> Vec<(&'a Item, Outcome)> {
    match page_url(page_url_text) {
        Some(p) => page_candidates(&Page::Web(p), items, suffixes),
        None => Vec::new(),
    }
}

fn name(i: &Item) -> &str {
    i.fields().map_or("", |f| f.name.as_str())
}

/// The frames to fill: of `frames`, given as frame ID and URL and including the top frame
/// itself, those whose origin equals the origin of the top frame's URL. Empty when the top frame
/// is not a page URL. A frame whose URL is not a page URL, such as `about:blank`, never fills.
pub fn frames_to_fill(top_url: &str, frames: &[(u64, &str)]) -> Vec<u64> {
    let Some(top) = page_url(top_url) else {
        return Vec::new();
    };
    frames
        .iter()
        .filter(|(_, url)| page_url(url).is_some_and(|f| f.same_origin(&top)))
        .map(|(id, _)| *id)
        .collect()
}

/// What a submitted form on a Firefox page offers to save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveOffer {
    /// Nothing to offer.
    None,
    /// Update the password of the item with this `id`.
    Update {
        /// The item's `id`.
        id: String,
    },
    /// Save a new login item with the submitted username and password, this name, and this one
    /// URI with `match` set to `base_domain`.
    New {
        /// The page host.
        name: String,
        /// The page origin.
        uri: String,
    },
}

/// The save offer for a form submitted on the Firefox page URL `page_url_text` with `username`
/// and `password`, as [`page_save_offer`] gives it for a web page.
pub fn save_offer(
    page_url_text: &str,
    username: &str,
    password: &str,
    items: &[Item],
    suffixes: &dyn SuffixList,
) -> SaveOffer {
    let Some(page) = page_url(page_url_text) else {
        return SaveOffer::None;
    };
    match page_save_offer(&Page::Web(page), username, password, items, suffixes) {
        Offer::None => SaveOffer::None,
        Offer::Update { id } => SaveOffer::Update { id },
        Offer::New(mut n) => SaveOffer::New {
            name: std::mem::take(&mut n.name),
            uri: n.uris.pop().map(|u| u.uri).unwrap_or_default(),
        },
    }
}

/// A page the matching rules see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    /// A Firefox page URL, from [`page_url`].
    Web(Prepared),
    /// An Android web page from an allowlisted browser, from [`android_web_page`]: no port, and
    /// the path `/`.
    AndroidWeb(Prepared),
    /// An Android app that is not an allowlisted browser.
    App(AppPage),
}

/// The Android web page for the scheme and host an allowlisted browser reports: the URL
/// `<scheme>://<host>/` parsed as a page URL. `None` when the scheme is not `http` or `https`,
/// when the host is not a host alone (it contains `/`, `\`, `?`, `#`, `@`, `:`, ASCII whitespace,
/// or a control character, except `:` inside an IPv6 address in brackets), or when it does not
/// parse; the client then treats the browser as not allowlisted. A host with a port, the default
/// included, is not a host alone, because Android browsers never report one.
pub fn android_web_page(scheme: &str, host: &str) -> Option<Prepared> {
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    // The URL parser absorbs a stray `/`, `\`, `@`, or a trailing `:` into another part of the
    // URL, so the host is checked as text first.
    let bracketed = host.len() > 2 && host.starts_with('[') && host.ends_with(']');
    let inner = if bracketed {
        &host[1..host.len() - 1]
    } else {
        host
    };
    let forbidden = |c: char| {
        matches!(c, '/' | '\\' | '?' | '#' | '@' | '[' | ']')
            || (c == ':' && !bracketed)
            || c == ' '
            || c.is_control()
    };
    if inner.is_empty() || inner.chars().any(forbidden) {
        return None;
    }
    let u = Url::parse(&format!("{scheme}://{host}/")).ok()?;
    let plain = u.port().is_none()
        && u.path() == "/"
        && u.query().is_none()
        && u.fragment().is_none()
        && u.username().is_empty()
        && u.password().is_none();
    plain.then(|| Prepared::from_url(&u)).flatten()
}

/// An item URI against an Android web page (spec, Android web pages), with the scheme rule
/// applied.
fn match_android(
    page: &Prepared,
    item: &Prepared,
    mode: MatchMode,
    suffixes: &dyn SuffixList,
) -> Outcome {
    let (Ok(page_suffix), Ok(item_suffix)) = (
        host_suffix(&page.host, suffixes),
        host_suffix(&item.host, suffixes),
    ) else {
        return Outcome::None;
    };
    let page_local = local(&page.host, page_suffix.as_deref());
    let same_host = page.host == item.host;
    let by_mode = match mode {
        MatchMode::BaseDomain
            if registrable(&page.host, page_suffix.as_deref())
                == registrable(&item.host, item_suffix.as_deref()) =>
        {
            Outcome::Fill
        }
        MatchMode::Host if same_host && item.port.is_none() && !page_local => Outcome::Fill,
        MatchMode::Host if same_host => Outcome::Confirm,
        MatchMode::StartsWith | MatchMode::Exact if same_host && page.scheme == item.scheme => {
            Outcome::Confirm
        }
        _ => Outcome::None,
    };
    if by_mode == Outcome::None || !(item.scheme == "https" && page.scheme == "http") {
        by_mode
    } else if page_local {
        Outcome::Confirm
    } else {
        Outcome::None
    }
}

/// An Android app page: the requesting app's package name and its signing certificates. It is
/// built only through [`AppPage::new`], which checks the digests and the history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPage {
    package: String,
    signers: Vec<String>,
    history: Vec<String>,
    multiple_signers: bool,
}

/// Why [`AppPage::new`] refused a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadAppPage {
    /// The package name is empty.
    Package,
    /// A digest is not 64 lowercase hex characters.
    Digest,
    /// An app without multiple signers lists more than one current digest.
    Signers,
    /// The history does not fit the signers: for one signer it is empty or does not end with the
    /// current digest; for more than one signer, or none read, it is not empty.
    History,
}

impl AppPage {
    /// An app page from what Android reports (spec, App pages): every digest 64 lowercase hex
    /// characters; with one signer, a history that ends with its digest; with more than one
    /// signer, or when the signing information could not be read (no signers), no history.
    /// Clients build pages through this constructor.
    pub fn new(
        package: String,
        signers: Vec<String>,
        history: Vec<String>,
        multiple_signers: bool,
    ) -> Result<AppPage, BadAppPage> {
        let digest = |d: &String| {
            d.len() == 64
                && d.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if package.is_empty() {
            return Err(BadAppPage::Package);
        }
        if !signers.iter().chain(&history).all(digest) {
            return Err(BadAppPage::Digest);
        }
        let history_fits = match (multiple_signers, signers.as_slice()) {
            (false, [one]) => history.last() == Some(one),
            (false, []) | (true, _) => history.is_empty(),
            (false, _) => return Err(BadAppPage::Signers),
        };
        if !history_fits {
            return Err(BadAppPage::History);
        }
        Ok(AppPage {
            package,
            signers,
            history,
            multiple_signers,
        })
    }

    /// The package name.
    pub fn package(&self) -> &str {
        &self.package
    }

    /// The current signing certificate digests (SHA-256 of the DER encoding, 64 lowercase hex
    /// characters): one for an app with one signer, several for an app with more than one, and
    /// none when the signing information could not be read.
    pub fn signers(&self) -> &[String] {
        &self.signers
    }

    /// The signing certificate history, oldest first and ending with the current digest, for an
    /// app with one signer; empty otherwise.
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Whether the app has more than one signer.
    pub fn multiple_signers(&self) -> bool {
        self.multiple_signers
    }

    /// The one current digest, unless the app has more than one signer or none could be read.
    pub fn current(&self) -> Option<&str> {
        match self.signers.as_slice() {
            [one] if !self.multiple_signers => Some(one),
            _ => None,
        }
    }

    fn unbound(&self, uri: &str) -> bool {
        let t = uri.trim_matches(|c: char| c.is_ascii_whitespace());
        t.get(..13)
            .is_some_and(|p| p.eq_ignore_ascii_case("androidapp://"))
            && t[13..] == *self.package
    }
}

/// How an item's association with an app page fills, in order of precedence (spec, App pages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMatch {
    /// A bound association whose certificate is the app's current one: fills.
    Fill,
    /// A bound association whose certificate is in the app's signing history: confirms, and a
    /// confirmed fill moves the association to the current certificate.
    Rebind,
    /// A bound association whose certificate is not in the history: confirms with a warning that
    /// the app's signature changed, and binds nothing.
    SignatureChanged,
    /// An unbound association: confirms, and a confirmed fill adds a bound association.
    Bind,
    /// The app has more than one signer, or its signing information could not be read: confirms
    /// and never binds.
    Unverified,
}

impl AppMatch {
    /// `Fill` for [`AppMatch::Fill`], and `Confirm` for every other kind.
    pub fn outcome(self) -> Outcome {
        match self {
            AppMatch::Fill => Outcome::Fill,
            _ => Outcome::Confirm,
        }
    }

    /// The kind's name, as `spec/vectors/autofill.json` spells it.
    pub fn code(self) -> &'static str {
        match self {
            AppMatch::Fill => "fill",
            AppMatch::Rebind => "rebind",
            AppMatch::SignatureChanged => "signature_changed",
            AppMatch::Bind => "bind",
            AppMatch::Unverified => "unverified",
        }
    }
}

/// How `item` fills `app`, or `None` when the item has no association with the app: no bound
/// association (`login.apps` entry for the package) and no unbound one (a `uris` entry
/// `androidapp://<package>` whose mode is not `never`).
pub fn app_match(item: &Item, app: &AppPage) -> Option<AppMatch> {
    let login = item.login()?;
    let bound: Vec<&str> = login
        .apps
        .iter()
        .filter(|a| a.package == app.package)
        .map(|a| a.cert_sha256.as_str())
        .collect();
    let unbound = login
        .uris
        .iter()
        .any(|u| u.match_mode() != MatchMode::Never && app.unbound(&u.uri));
    if bound.is_empty() && !unbound {
        return None;
    }
    let Some(current) = app.current() else {
        return Some(AppMatch::Unverified);
    };
    let in_history = |c: &str| app.history.iter().any(|h| h == c);
    Some(if bound.contains(&current) {
        AppMatch::Fill
    } else if bound.iter().any(|c| in_history(c)) {
        AppMatch::Rebind
    } else if !bound.is_empty() {
        AppMatch::SignatureChanged
    } else {
        AppMatch::Bind
    })
}

/// The item's `login.apps` after a confirmed fill on `app`, or `None` when the fill records
/// nothing. `Bind` adds an entry for the current certificate; `Rebind` moves each entry for the
/// package whose certificate is in the history to the current one, and keeps only the first of
/// any entries that became equal. The client applies the result as a local edit.
pub fn apps_after_fill(item: &Item, app: &AppPage) -> Option<Vec<AndroidApp>> {
    let kind = app_match(item, app)?;
    let current = app.current()?;
    let mut apps = item.login()?.apps.clone();
    match kind {
        AppMatch::Bind => apps.push(AndroidApp {
            package: app.package.clone(),
            cert_sha256: current.to_owned(),
            extra: Map::new(),
        }),
        AppMatch::Rebind => {
            // Rewrite the entries in the history, then drop each rewritten entry that has the
            // same package and digest as an entry before it. Entries not rewritten stay as they
            // are, duplicates included.
            let mut out: Vec<AndroidApp> = Vec::with_capacity(apps.len());
            for mut a in apps {
                let rewritten = a.package == app.package && app.history.contains(&a.cert_sha256);
                if rewritten {
                    a.cert_sha256 = current.to_owned();
                    if out
                        .iter()
                        .any(|b| b.package == a.package && b.cert_sha256 == a.cert_sha256)
                    {
                        continue;
                    }
                }
                out.push(a);
            }
            apps = out;
        }
        _ => return None,
    }
    Some(apps)
}

/// A URI of a new login item: the `uri` and its `match` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUri {
    /// The URI.
    pub uri: String,
    /// Its `match` value.
    pub match_value: String,
}

/// A bound association of a new login item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApp {
    /// The package name.
    pub package: String,
    /// The signing certificate digest.
    pub cert_sha256: String,
}

/// A new login item a save offer proposes, besides the submitted username and password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLogin {
    /// The item's name.
    pub name: String,
    /// Its `login.uris`.
    pub uris: Vec<NewUri>,
    /// Its `login.apps`.
    pub apps: Vec<NewApp>,
}

/// What a submitted form on any page offers to save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offer {
    /// Nothing to offer.
    None,
    /// Update the password of the item with this `id`.
    Update {
        /// The item's `id`.
        id: String,
    },
    /// Save a new login item.
    New(NewLogin),
}

/// The save offer for a form submitted on `page` with `username` and `password` (spec, Save
/// offers and Android save offers).
pub fn page_save_offer(
    page: &Page,
    username: &str,
    password: &str,
    items: &[Item],
    suffixes: &dyn SuffixList,
) -> Offer {
    if password.is_empty() {
        return Offer::None;
    }
    let same_user: Vec<&Item> = page_candidates(page, items, suffixes)
        .into_iter()
        .filter(|(_, o)| *o == Outcome::Fill)
        .map(|(i, _)| i)
        .filter(|i| i.login().is_some_and(|l| l.username == username))
        .collect();
    if same_user
        .iter()
        .any(|i| i.login().is_some_and(|l| l.password == password))
    {
        return Offer::None;
    }
    if let Some(i) = same_user.first() {
        return Offer::Update { id: i.id.clone() };
    }
    Offer::New(match page {
        Page::Web(p) | Page::AndroidWeb(p) => NewLogin {
            name: p.host.text(),
            uris: vec![NewUri {
                uri: p.origin(),
                match_value: "base_domain".into(),
            }],
            apps: Vec::new(),
        },
        Page::App(app) => match app.current() {
            Some(c) => NewLogin {
                name: app.package.clone(),
                uris: Vec::new(),
                apps: vec![NewApp {
                    package: app.package.clone(),
                    cert_sha256: c.to_owned(),
                }],
            },
            None => NewLogin {
                name: app.package.clone(),
                uris: vec![NewUri {
                    uri: format!("androidapp://{}", app.package),
                    match_value: "base_domain".into(),
                }],
                apps: Vec::new(),
            },
        },
    })
}
