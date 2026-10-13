//! Autofill bindings (spec, Autofill matching): the known-suffix lookup from JavaScript, and the
//! functions that need no unlocked vault.

use crate::convert::{get, to_js, usage};
use js_sys::{Function, Object, Reflect};
use serde_json::json;
use vault_client::autofill::{self, Outcome, Prepared, SuffixList};
use vault_core::body::LoginUri;
use wasm_bindgen::prelude::*;

/// `browser.publicSuffix.getKnownSuffix` as a synchronous function, or its answers as a record.
pub(crate) enum KnownSuffix {
    Function(Function),
    Record(Object),
}

/// An answer that fails the known-suffix check, so the URI does not match.
fn failed() -> Option<String> {
    Some(String::new())
}

fn answer(v: JsValue) -> Option<String> {
    if v.is_null() {
        None
    } else {
        v.as_string().or_else(failed)
    }
}

impl KnownSuffix {
    pub(crate) fn from_js(v: JsValue) -> Result<KnownSuffix, JsValue> {
        if let Some(f) = v.dyn_ref::<Function>() {
            Ok(KnownSuffix::Function(f.clone()))
        } else if v.is_object() {
            Ok(KnownSuffix::Record(v.unchecked_into()))
        } else {
            Err(usage("knownSuffix is neither a function nor a record"))
        }
    }
}

impl SuffixList for KnownSuffix {
    /// A throw, a `Promise`, a missing record entry, or any value that is neither a string nor
    /// `null` counts as a failed answer.
    fn known_suffix(&self, host: &str) -> Option<String> {
        match self {
            KnownSuffix::Function(f) => match f.call1(&JsValue::NULL, &host.into()) {
                Ok(v) => answer(v),
                Err(_) => failed(),
            },
            KnownSuffix::Record(r) => match Reflect::has(r, &host.into()) {
                Ok(true) => answer(get(r, host)),
                _ => failed(),
            },
        }
    }
}

pub(crate) fn outcome(o: Outcome) -> &'static str {
    match o {
        Outcome::Fill => "fill",
        Outcome::Confirm => "confirm",
        Outcome::None => "none",
    }
}

fn prepared(p: Option<Prepared>) -> JsValue {
    match p {
        None => JsValue::NULL,
        Some(p) => to_js(&json!({
            "scheme": p.scheme,
            "host": p.host.text(),
            "port": p.port,
            "pathQuery": p.path_query,
            "origin": p.origin(),
        })),
    }
}

/// A page URL from the browser, or `null` when it never fills.
#[wasm_bindgen(js_name = pageUrl)]
pub fn page_url(url: &str) -> JsValue {
    prepared(autofill::page_url(url))
}

/// An item URI prepared for matching, or `null` when it never matches.
#[wasm_bindgen(js_name = prepareUri)]
pub fn prepare_uri(uri: &str) -> JsValue {
    prepared(autofill::prepare_uri(uri))
}

/// The registrable domain of a page URL's host, or `null` when the URL never fills or the
/// known-suffix answer fails its check.
#[wasm_bindgen(js_name = registrableDomain)]
pub fn registrable_domain(url: &str, known_suffix: JsValue) -> Result<JsValue, JsValue> {
    let ks = KnownSuffix::from_js(known_suffix)?;
    Ok(autofill::page_url(url)
        .and_then(|p| autofill::registrable_domain(&p.host, &ks).ok())
        .map_or(JsValue::NULL, |d| d.into()))
}

/// The outcome of one item URI with its `match` value against a page URL.
#[wasm_bindgen(js_name = matchUri)]
pub fn match_uri(
    page_url: &str,
    uri: &str,
    match_value: &str,
    known_suffix: JsValue,
) -> Result<String, JsValue> {
    let ks = KnownSuffix::from_js(known_suffix)?;
    let mode = LoginUri {
        uri: String::new(),
        match_value: match_value.to_owned(),
        extra: Default::default(),
    }
    .match_mode();
    let o = autofill::page_url(page_url)
        .map_or(Outcome::None, |p| autofill::match_uri(&p, uri, mode, &ks));
    Ok(outcome(o).to_owned())
}

/// The IDs of the frames to fill: of `frames` (`webNavigation.getAllFrames` results, the top
/// frame included, as `{ frameId, url }`), those whose origin equals the top frame's.
#[wasm_bindgen(js_name = framesToFill)]
pub fn frames_to_fill(top_url: &str, frames: &JsValue) -> Result<JsValue, JsValue> {
    let list = crate::convert::js_array(frames.clone(), "frames")?;
    let mut parsed = Vec::with_capacity(list.length() as usize);
    for f in list.iter() {
        let id = get(&f, "frameId")
            .as_f64()
            .filter(|n| n.fract() == 0.0 && *n >= 0.0)
            .ok_or_else(|| usage("frameId is not a whole number"))?;
        let url = get(&f, "url")
            .as_string()
            .ok_or_else(|| usage("url is not a string"))?;
        parsed.push((id as u64, url));
    }
    let refs: Vec<(u64, &str)> = parsed.iter().map(|(i, u)| (*i, u.as_str())).collect();
    // Frame IDs are below 2^53, so they cross as exact JavaScript numbers.
    Ok(to_js(&json!(autofill::frames_to_fill(top_url, &refs))))
}
