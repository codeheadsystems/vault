//! Helpers shared by the integration tests.

#![allow(dead_code, reason = "each test crate uses a different subset")]

use vault_core::body::{Body, Item};
use vault_core::rng::Rng;
use vault_interop::{Export, ImportOptions, ImportReport, PlainExport, import, parse};

pub const DEV: [u8; 16] = [0xd1; 16];
pub const NOW: u64 = 1_760_000_000_000;

/// A counter-based stream, for tests that need many draws but no particular bytes.
pub struct TestRng(pub u64);

impl Rng for TestRng {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        for b in dest.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *b = (self.0 >> 33) as u8;
        }
        Ok(())
    }
}

pub fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

pub fn plain(bytes: &[u8]) -> PlainExport {
    match parse(bytes) {
        Ok(Export::Plain(p)) => p,
        Ok(Export::Protected(_)) => panic!("password-protected"),
        Err(e) => panic!("{e:?}"),
    }
}

pub fn import_at(body: &mut Body, export: &PlainExport, folder: &str, now: u64) -> ImportReport {
    let options = ImportOptions {
        folder: folder.to_owned(),
    };
    import(body, export, &options, now, &DEV, &mut TestRng(now)).unwrap()
}

/// A body holding the import of `bytes`.
pub fn imported(bytes: &[u8]) -> Body {
    let mut body = Body::default();
    import_at(&mut body, &plain(bytes), "", NOW);
    body
}

pub fn json(v: &vault_core::json::Value) -> serde_json::Value {
    serde_json::from_slice(&vault_core::json::to_vec(v)).unwrap()
}

/// The item as JSON, without the keys every import sets afresh: `id`, `modified`, and
/// `modified_by`.
pub fn content(item: &Item) -> serde_json::Value {
    let mut v = json(&item.to_value());
    let m = v.as_object_mut().unwrap();
    for k in ["id", "modified", "modified_by"] {
        m.remove(k);
    }
    v
}

pub fn origin_id(item: &Item) -> Option<&str> {
    match item.fields()?.origin.as_ref()?.get("bitwarden")? {
        vault_core::json::Value::Object(b) => match b.get("id")? {
            vault_core::json::Value::String(s) => Some(s),
            _ => None,
        },
        _ => None,
    }
}

pub fn by_origin<'a>(body: &'a Body, bw_id: &str) -> &'a Item {
    body.items
        .iter()
        .find(|i| origin_id(i) == Some(bw_id))
        .unwrap_or_else(|| panic!("no item from {bw_id}"))
}
