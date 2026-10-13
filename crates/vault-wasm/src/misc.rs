//! Setup text, secret key text, the state summary, the revision list, and password generation.

use crate::WebRng;
use crate::convert::{array, client_err, core_err, state, state_text, to_js, usage};
use js_sys::Uint8Array;
use serde_json::json;
use vault_client::state::StopReason;
use vault_core::generate::{self, Classes};
use vault_core::secret::SecretKey;
use wasm_bindgen::prelude::*;

/// Parses setup text: `{ url, token, fp, loopbackHttp }`, where `token` is the text form for the
/// `Authorization` header and `fp` is lowercase hex or `null`.
#[wasm_bindgen(js_name = parseSetupText)]
pub fn parse_setup_text(text: &str) -> Result<JsValue, JsValue> {
    let s = vault_core::setup::parse_setup(text).map_err(core_err)?;
    let server = vault_core::setup::check_server_url(&s.url).map_err(core_err)?;
    let token = vault_core::token::encode(&s.token);
    Ok(to_js(&json!({
        "url": s.url,
        "token": token.as_str(),
        "fp": s.fp.map(hex::encode),
        "loopbackHttp": server.loopback_http,
    })))
}

/// Decodes a secret key's text form; a typo throws `secret_key_typo` before any derivation.
#[wasm_bindgen(js_name = decodeSecretKey)]
pub fn decode_secret_key(text: &str) -> Result<Uint8Array, JsValue> {
    let sk = vault_core::secret_key_text::decode(text).map_err(core_err)?;
    Ok(Uint8Array::from(&sk.expose()[..]))
}

/// The secret key's text form, for the emergency kit.
#[wasm_bindgen(js_name = encodeSecretKey)]
pub fn encode_secret_key(key: &JsValue) -> Result<String, JsValue> {
    let sk = SecretKey::from_bytes(*array::<16>(key, "key")?);
    Ok(vault_core::secret_key_text::encode(&sk).as_str().to_owned())
}

/// What the popup shows without unlocking: the vault ID, the accepted generation, unpushed
/// changes, why sync stopped, a pending secret key, the last sync, and dropped item names.
#[wasm_bindgen(js_name = stateSummary)]
pub fn state_summary(text: &str) -> Result<JsValue, JsValue> {
    let s = state(text)?;
    let stopped = s.stopped.as_ref().map(|st| {
        json!({
            "reason": match st.reason {
                StopReason::Integrity => "integrity",
                StopReason::Token => "token",
                StopReason::Credentials => "credentials",
            },
            "code": st.code,
            "at": st.at,
        })
    });
    Ok(to_js(&json!({
        "vaultId": hex::encode(s.vault_id),
        "generation": s.accepted.as_ref().map(|a| a.generation),
        "unpushed": s.unpushed(),
        "stopped": stopped,
        "pendingSecretKey": s.pending_secret_key,
        "lastSync": s.last_sync,
        "dropped": s.dropped,
    })))
}

/// The state with its list of dropped item names cleared, after they were shown.
#[wasm_bindgen(js_name = clearDropped)]
pub fn clear_dropped(text: &str) -> Result<String, JsValue> {
    let mut s = state(text)?;
    s.dropped.clear();
    Ok(state_text(&s))
}

/// Parses a `GET /v1/revisions` body.
#[wasm_bindgen(js_name = parseRevisions)]
pub fn parse_revisions(body: &[u8]) -> Result<JsValue, JsValue> {
    let list = vault_client::revisions::parse_revisions(body).map_err(client_err)?;
    let out: Vec<serde_json::Value> = list
        .into_iter()
        .map(|r| {
            json!({"id": r.id, "etag": r.etag, "size": r.size, "created": r.created, "token": r.token})
        })
        .collect();
    Ok(to_js(&json!(out)))
}

fn flag(o: &JsValue, key: &str) -> Result<bool, JsValue> {
    crate::convert::get(o, key)
        .as_bool()
        .ok_or_else(|| usage(&format!("{key} is not a boolean")))
}

/// A random password: `{ value, bits }`. Every selected class appears at least once.
#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(options: &JsValue) -> Result<JsValue, JsValue> {
    let length = crate::convert::get(options, "length")
        .as_f64()
        .filter(|l| l.fract() == 0.0 && *l >= 0.0)
        .ok_or_else(|| usage("length is not a whole number"))? as usize;
    let classes = Classes {
        upper: flag(options, "upper")?,
        lower: flag(options, "lower")?,
        digits: flag(options, "digits")?,
        symbols: flag(options, "symbols")?,
        avoid_ambiguous: flag(options, "avoidAmbiguous")?,
    };
    let value = generate::password(&mut WebRng, length, &classes).map_err(core_err)?;
    let bits = generate::password_bits(length, &classes).map_err(core_err)?;
    Ok(secret_value(&value, bits))
}

/// A random passphrase from the BIP-39 English list: `{ value, bits }`.
#[wasm_bindgen(js_name = generatePassphrase)]
pub fn generate_passphrase(words: usize, separator: &str) -> Result<JsValue, JsValue> {
    let value = generate::passphrase(&mut WebRng, words, separator).map_err(core_err)?;
    Ok(secret_value(&value, generate::passphrase_bits(words)))
}

/// `{ value, bits }`, built without an intermediate JSON copy of the value.
fn secret_value(value: &str, bits: f64) -> JsValue {
    let o: JsValue = js_sys::Object::new().into();
    crate::convert::set(&o, "value", &value.into());
    crate::convert::set(&o, "bits", &bits.into());
    o
}
