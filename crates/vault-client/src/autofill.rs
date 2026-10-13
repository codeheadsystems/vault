//! Autofill matching (spec, Autofill matching): which items fill a page, in which frames, and
//! what a submitted form offers to save. The inputs are plain data, so the Firefox (WASM) and
//! Android clients run the same code; the host supplies the known public suffix of a host from
//! its platform's copy of the Public Suffix List.

use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};
use vault_core::body::{Item, MatchMode};

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

/// An item's outcome: the best of its URIs; `None` for an item that is not a login or has no
/// URIs.
pub fn item_outcome(page: &Prepared, item: &Item, suffixes: &dyn SuffixList) -> Outcome {
    item.login().map_or(Outcome::None, |l| {
        l.uris
            .iter()
            .map(|u| match_uri(page, &u.uri, u.match_mode(), suffixes))
            .max()
            .unwrap_or(Outcome::None)
    })
}

/// The candidates for a fill on `page_url`: the items whose outcome is not `None`, `Fill` first,
/// then by `name` compared as Unicode code points, then by `id`. Empty when the URL is not a
/// page URL.
pub fn candidates<'a>(
    page_url_text: &str,
    items: &'a [Item],
    suffixes: &dyn SuffixList,
) -> Vec<(&'a Item, Outcome)> {
    let Some(page) = page_url(page_url_text) else {
        return Vec::new();
    };
    let mut out: Vec<(&Item, Outcome)> = items
        .iter()
        .map(|i| (i, item_outcome(&page, i, suffixes)))
        .filter(|(_, o)| *o != Outcome::None)
        .collect();
    out.sort_by(|(a, oa), (b, ob)| {
        ob.cmp(oa)
            .then_with(|| name(a).cmp(name(b)))
            .then_with(|| a.id.cmp(&b.id))
    });
    out
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

/// What a submitted form offers to save.
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

/// The save offer for a form submitted on `page_url_text` with `username` and `password`.
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
    if password.is_empty() {
        return SaveOffer::None;
    }
    let same_user: Vec<&Item> = candidates(page_url_text, items, suffixes)
        .into_iter()
        .filter(|(_, o)| *o == Outcome::Fill)
        .map(|(i, _)| i)
        .filter(|i| i.login().is_some_and(|l| l.username == username))
        .collect();
    if same_user
        .iter()
        .any(|i| i.login().is_some_and(|l| l.password == password))
    {
        return SaveOffer::None;
    }
    match same_user.first() {
        Some(i) => SaveOffer::Update { id: i.id.clone() },
        None => SaveOffer::New {
            name: page.host.text(),
            uri: page.origin(),
        },
    }
}
