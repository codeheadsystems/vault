//! Conversions between JavaScript values and the Rust types: errors with a `code`, plain objects
//! built from JSON, byte arrays, and the arguments the bindings read.

use js_sys::{Reflect, Uint8Array};
use vault_client::{ClientError, ClientState};
use wasm_bindgen::{JsCast, JsValue};
use zeroize::Zeroizing;

/// A JavaScript `Error` with a string `code`.
pub(crate) fn js_err(code: &str, message: &str) -> JsValue {
    let e = js_sys::Error::new(message);
    let _ = Reflect::set(&e, &"code".into(), &code.into());
    e.into()
}

pub(crate) fn client_err(e: ClientError) -> JsValue {
    js_err(e.code(), &e.to_string())
}

pub(crate) fn core_err(e: vault_core::Error) -> JsValue {
    js_err(e.code(), &e.to_string())
}

/// An error for an argument of the wrong shape.
pub(crate) fn usage(message: &str) -> JsValue {
    js_err("usage", message)
}

/// A plain JavaScript object or array from JSON.
pub(crate) fn to_js(v: &serde_json::Value) -> JsValue {
    js_sys::JSON::parse(&v.to_string()).expect("serde_json writes valid JSON")
}

/// Sets `key` on a JavaScript object.
pub(crate) fn set(obj: &JsValue, key: &str, value: &JsValue) {
    let _ = Reflect::set(obj, &key.into(), value);
}

/// A new `Uint8Array` holding a copy of `b`.
pub(crate) fn bytes(b: &[u8]) -> JsValue {
    Uint8Array::from(b).into()
}

/// The property `key`, or `undefined`.
pub(crate) fn get(obj: &JsValue, key: &str) -> JsValue {
    Reflect::get(obj, &key.into()).unwrap_or(JsValue::UNDEFINED)
}

/// A string property, `None` when absent.
pub(crate) fn get_str(obj: &JsValue, key: &str) -> Result<Option<String>, JsValue> {
    let v = get(obj, key);
    if v.is_undefined() || v.is_null() {
        return Ok(None);
    }
    v.as_string()
        .map(Some)
        .ok_or_else(|| usage(&format!("{key} is not a string")))
}

/// A `Uint8Array` property of exactly `N` bytes, copied into zeroizing memory; `None` when absent.
pub(crate) fn get_array<const N: usize>(
    obj: &JsValue,
    key: &str,
) -> Result<Option<Zeroizing<[u8; N]>>, JsValue> {
    let v = get(obj, key);
    if v.is_undefined() || v.is_null() {
        return Ok(None);
    }
    array(&v, key).map(Some)
}

/// A `Uint8Array` of exactly `N` bytes, copied into zeroizing memory.
pub(crate) fn array<const N: usize>(
    v: &JsValue,
    what: &str,
) -> Result<Zeroizing<[u8; N]>, JsValue> {
    let a = v
        .dyn_ref::<Uint8Array>()
        .ok_or_else(|| usage(&format!("{what} is not a Uint8Array")))?;
    if a.length() as usize != N {
        return Err(usage(&format!("{what} is not {N} bytes")));
    }
    let mut out = Zeroizing::new([0u8; N]);
    a.copy_to(out.as_mut());
    Ok(out)
}

/// The bytes of a `Uint8Array`.
pub(crate) fn byte_vec(v: &JsValue, what: &str) -> Result<Vec<u8>, JsValue> {
    v.dyn_ref::<Uint8Array>()
        .map(Uint8Array::to_vec)
        .ok_or_else(|| usage(&format!("{what} is not a Uint8Array")))
}

/// A JavaScript array, checked.
pub(crate) fn js_array(v: JsValue, what: &str) -> Result<js_sys::Array, JsValue> {
    if js_sys::Array::is_array(&v) {
        Ok(v.unchecked_into())
    } else {
        Err(usage(&format!("{what} is not an array")))
    }
}

/// The local state from its `local.json` text.
pub(crate) fn state(text: &str) -> Result<ClientState, JsValue> {
    ClientState::from_json(text.as_bytes()).map_err(client_err)
}

/// The local state as `local.json` text.
pub(crate) fn state_text(s: &ClientState) -> String {
    String::from_utf8(s.to_json()).expect("the state is JSON")
}
