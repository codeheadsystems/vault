//! Autofill for Kotlin (spec, Autofill matching; docs/android.md, Pages): Android web and app
//! pages, candidates, save offers, and the binding a confirmed app fill records. The session's
//! methods use the compiled-in Public Suffix List; the free functions take a [`KnownSuffix`], so
//! the spec vectors' table can stand in for it.

use crate::error::{Result, VaultError};
use crate::psl;
use std::sync::Arc;
use vault_client::autofill::{self, BadAppPage, Offer, Outcome as CoreOutcome, SuffixList};
use vault_core::body::{Body, Item};
use vault_core::json::{Map, Value};

/// A known-suffix lookup: the longest public suffix an explicit Public Suffix List rule gives
/// `host`, or `None` when only the default `*` rule applies. `host` is lowercase ASCII without
/// a trailing `.`. Only Kotlin implements it: the library hands out no Rust-backed instance, so
/// none can cross back as an argument after it was closed.
#[uniffi::export(with_foreign)]
pub trait KnownSuffix: Send + Sync {
    /// The known suffix of `host`.
    fn known_suffix(&self, host: String) -> Option<String>;
}

/// A [`KnownSuffix`] as `vault-client` takes it.
struct Lookup<'a>(&'a dyn KnownSuffix);

/// Runs `f` with `suffixes`, or the compiled-in list when `None`.
fn with_lookup<R>(
    suffixes: Option<Arc<dyn KnownSuffix>>,
    f: impl FnOnce(&dyn SuffixList) -> R,
) -> R {
    match suffixes {
        Some(s) => f(&Lookup(s.as_ref())),
        None => f(psl::list()),
    }
}

impl SuffixList for Lookup<'_> {
    fn known_suffix(&self, host: &str) -> Option<String> {
        self.0.known_suffix(host.to_owned())
    }
}

/// An app that is not an allowlisted browser (spec, App pages). Signing information that does
/// not fit the shape below makes the page `unverified`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppPage {
    /// The package name.
    pub package_name: String,
    /// The current signing certificate digests, lowercase hex SHA-256 of each DER encoding: one
    /// for one signer, several for more than one, none when the lookup failed.
    pub signers: Vec<String>,
    /// `signingCertificateHistory`, oldest first, for one signer; empty otherwise.
    pub history: Vec<String>,
    /// Whether the app has more than one signer.
    pub multiple_signers: bool,
}

impl AppPage {
    /// The page through `AppPage::new`. Signing information that does not fit the spec's shape
    /// (a malformed digest, several current digests without the flag, or a history that does
    /// not end with the current digest) counts as unread: the page is `unverified`. An empty
    /// package name is refused with `usage`.
    pub(crate) fn core(&self) -> Result<autofill::AppPage> {
        let page = |signers, history, multiple| {
            autofill::AppPage::new(self.package_name.clone(), signers, history, multiple)
        };
        match page(
            self.signers.clone(),
            self.history.clone(),
            self.multiple_signers,
        ) {
            Ok(p) => Ok(p),
            Err(BadAppPage::Package) => Err(VaultError::usage("the package name is empty")),
            Err(_) => page(Vec::new(), Vec::new(), false)
                .map_err(|_| VaultError::usage("the package name is empty")),
        }
    }
}

/// The page a fill or save request comes from (docs/android.md, Pages).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Page {
    /// An allowlisted browser's `webScheme` and `webDomain`. One that [`android_web_page`]
    /// refuses matches nothing.
    AndroidWeb {
        /// The scheme.
        scheme: String,
        /// The host.
        host: String,
    },
    /// Any other app.
    App {
        /// The app.
        app: AppPage,
    },
}

impl Page {
    /// The page as `vault-client` takes it; `None` for an Android web page that
    /// [`android_web_page`] refuses.
    fn core(&self) -> Result<Option<autofill::Page>> {
        Ok(match self {
            Page::AndroidWeb { scheme, host } => {
                autofill::android_web_page(scheme, host).map(autofill::Page::AndroidWeb)
            }
            Page::App { app } => Some(autofill::Page::App(app.core()?)),
        })
    }
}

/// An Android web page as parsed: no port, and the path `/`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WebPage {
    /// `http` or `https`.
    pub scheme: String,
    /// The host as a WHATWG URL serialises it, without a trailing `.`.
    pub host: String,
    /// The origin, `<scheme>://<host>`.
    pub origin: String,
}

/// A candidate's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Outcome {
    /// Fills.
    Fill,
    /// Fills only after the user confirms it.
    Confirm,
}

/// How an item's association with an app fills (spec, App pages).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AppMatch {
    /// The bound certificate is the app's current one.
    Fill,
    /// The bound certificate is in the app's history; a confirmed fill rebinds.
    Rebind,
    /// The bound certificate is not in the history; the app's signature changed.
    SignatureChanged,
    /// An unbound association; a confirmed fill binds.
    Bind,
    /// More than one signer, or no signing information; nothing is ever bound.
    Unverified,
}

impl From<autofill::AppMatch> for AppMatch {
    fn from(m: autofill::AppMatch) -> Self {
        match m {
            autofill::AppMatch::Fill => AppMatch::Fill,
            autofill::AppMatch::Rebind => AppMatch::Rebind,
            autofill::AppMatch::SignatureChanged => AppMatch::SignatureChanged,
            autofill::AppMatch::Bind => AppMatch::Bind,
            autofill::AppMatch::Unverified => AppMatch::Unverified,
        }
    }
}

/// A fill candidate, without secrets.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Candidate {
    /// The item ID.
    pub id: String,
    /// The name.
    pub name: String,
    /// The username.
    pub username: String,
    /// The outcome.
    pub outcome: Outcome,
    /// On an app page, the kind of the item's association; `None` on a web page.
    pub app_match: Option<AppMatch>,
}

/// A login URI and its `match` value.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemUri {
    /// The URI.
    pub uri: String,
    /// The `match` value, such as `base_domain`.
    pub match_value: String,
}

/// A bound association: a `login.apps` entry.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppBinding {
    /// The package name.
    pub package_name: String,
    /// The signing certificate digest, 64 lowercase hex characters.
    pub cert_sha256: String,
}

/// What a submitted form offers to save (spec, Save offers and Android save offers).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SaveOffer {
    /// Nothing to offer.
    None,
    /// Update the password of this item.
    Update {
        /// The item ID.
        id: String,
    },
    /// Save a new login item with the submitted username and password.
    New {
        /// The name: the page host or the package name.
        name: String,
        /// Its `login.uris`.
        uris: Vec<ItemUri>,
        /// Its `login.apps`.
        apps: Vec<AppBinding>,
    },
}

impl From<Offer> for SaveOffer {
    fn from(o: Offer) -> Self {
        match o {
            Offer::None => SaveOffer::None,
            Offer::Update { id } => SaveOffer::Update { id },
            Offer::New(n) => SaveOffer::New {
                name: n.name,
                uris: n
                    .uris
                    .into_iter()
                    .map(|u| ItemUri {
                        uri: u.uri,
                        match_value: u.match_value,
                    })
                    .collect(),
                apps: n
                    .apps
                    .into_iter()
                    .map(|a| AppBinding {
                        package_name: a.package,
                        cert_sha256: a.cert_sha256,
                    })
                    .collect(),
            },
        }
    }
}

/// The candidates for `page` among `items`, in candidate order.
pub(crate) fn candidates(
    page: &Page,
    items: &[Item],
    suffixes: &dyn SuffixList,
) -> Result<Vec<Candidate>> {
    let Some(p) = page.core()? else {
        return Ok(Vec::new());
    };
    Ok(autofill::page_candidates(&p, items, suffixes)
        .into_iter()
        .filter_map(|(i, o)| {
            let outcome = match o {
                CoreOutcome::Fill => Outcome::Fill,
                CoreOutcome::Confirm => Outcome::Confirm,
                CoreOutcome::None => return None,
            };
            let app_match = match &p {
                autofill::Page::App(a) => autofill::app_match(i, a).map(AppMatch::from),
                _ => None,
            };
            Some(Candidate {
                id: i.id.clone(),
                name: i.fields().map_or_else(String::new, |f| f.name.clone()),
                username: i.login().map_or_else(String::new, |l| l.username.clone()),
                outcome,
                app_match,
            })
        })
        .collect())
}

/// The save offer for a form submitted on `page`.
pub(crate) fn save_offer(
    page: &Page,
    username: &str,
    password: &str,
    items: &[Item],
    suffixes: &dyn SuffixList,
) -> Result<SaveOffer> {
    Ok(match page.core()? {
        None => SaveOffer::None,
        Some(p) => autofill::page_save_offer(&p, username, password, items, suffixes).into(),
    })
}

/// Whether an item without an association may fill `page` through an explicit choice
/// (docs/android.md, App matching): always on an app page; on an Android web page, unless it is
/// `http` and its host is not a local host.
pub(crate) fn explicit_choice(page: &Page, suffixes: &dyn SuffixList) -> bool {
    match page.core().ok().flatten() {
        None => false,
        Some(autofill::Page::AndroidWeb(p)) => {
            p.scheme == "https" || autofill::is_local_host(&p.host, suffixes) == Ok(true)
        }
        Some(_) => true,
    }
}

/// Parses body-schema items from a JSON array.
pub(crate) fn parse_items(json: &str) -> Result<Vec<Item>> {
    let items = vault_core::json::parse(json.as_bytes())?;
    if !matches!(items, Value::Array(_)) {
        return Err(VaultError::usage("the items are not a JSON array"));
    }
    let body = Map::from([
        ("v".to_owned(), Value::Number(1)),
        ("horizon".to_owned(), Value::Number(0)),
        ("items".to_owned(), items),
        ("tombstones".to_owned(), Value::Array(Vec::new())),
    ]);
    Ok(Body::from_value(Value::Object(body))?.items.clone())
}

/// Parses one body-schema item from its JSON object.
pub(crate) fn parse_item(json: &str) -> Result<Item> {
    parse_items(&format!("[{json}]"))?
        .pop()
        .ok_or_else(|| VaultError::usage("no item"))
}

/// The known suffix of `host` from the compiled-in Public Suffix List.
#[uniffi::export]
pub fn known_suffix(host: String) -> Option<String> {
    psl::list().known_suffix(&host)
}

/// The Android web page for the scheme and host an allowlisted browser reports, or `None`, in
/// which case the browser is treated as not allowlisted (spec, Android web pages).
#[uniffi::export]
pub fn android_web_page(scheme: String, host: String) -> Option<WebPage> {
    autofill::android_web_page(&scheme, &host).map(|p| WebPage {
        scheme: p.scheme.clone(),
        host: p.host.text(),
        origin: p.origin(),
    })
}

/// The candidates for `page` among `items` (a JSON array of body-schema items), in candidate
/// order, by `suffixes` or, when `None`, the compiled-in list.
#[uniffi::export]
pub fn page_candidates(
    page: Page,
    items: String,
    suffixes: Option<Arc<dyn KnownSuffix>>,
) -> Result<Vec<Candidate>> {
    let items = parse_items(&items)?;
    with_lookup(suffixes, |l| candidates(&page, &items, l))
}

/// The save offer for a form submitted on `page`, among `items` (a JSON array of body-schema
/// items), by `suffixes` or, when `None`, the compiled-in list.
#[uniffi::export]
pub fn page_save_offer(
    page: Page,
    username: String,
    password: String,
    items: String,
    suffixes: Option<Arc<dyn KnownSuffix>>,
) -> Result<SaveOffer> {
    let items = parse_items(&items)?;
    with_lookup(suffixes, |l| {
        save_offer(&page, &username, &password, &items, l)
    })
}

/// The `login.apps` of `item` (a body-schema item as JSON) after a confirmed fill on `app`, or
/// `None` when the fill records nothing.
#[uniffi::export]
pub fn apps_after_fill(item: String, app: AppPage) -> Result<Option<Vec<AppBinding>>> {
    let item = parse_item(&item)?;
    Ok(autofill::apps_after_fill(&item, &app.core()?).map(|apps| {
        apps.iter()
            .map(|a| AppBinding {
                package_name: a.package.clone(),
                cert_sha256: a.cert_sha256.clone(),
            })
            .collect()
    }))
}

/// Whether an item without an association may fill `page` through "Choose another item" and a
/// confirmation, by the compiled-in Public Suffix List.
#[uniffi::export]
pub fn explicit_choice_allowed(page: Page) -> bool {
    explicit_choice(&page, psl::list())
}
