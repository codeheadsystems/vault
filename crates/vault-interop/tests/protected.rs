//! Password-protected exports: decryption with both KDFs, a wrong password, tampering, and the
//! KDF bounds.

mod common;

use common::*;
use vault_core::body::Body;
use vault_interop::{Error, Export, Kdf, ProtectedExport, parse};

const PASSWORD: &str = "correct horse battery staple";

fn protected(bytes: &[u8]) -> ProtectedExport {
    match parse(bytes) {
        Ok(Export::Protected(p)) => p,
        Ok(Export::Plain(_)) => panic!("plain"),
        Err(e) => panic!("{e:?}"),
    }
}

/// The body of a decrypted export equals the body of the plain fixture it encrypts.
fn opens_to_full(name: &str, kdf: Kdf) {
    let export = parse(&fixture(name)).unwrap();
    assert!(export.needs_password());
    let Export::Protected(p) = export else {
        unreachable!()
    };
    assert_eq!(p.kdf(), kdf);
    let plain = p.decrypt(PASSWORD).unwrap();
    let mut body = Body::default();
    let r = import_at(&mut body, &plain, "", NOW);
    assert_eq!((r.added, r.skipped.len(), r.collections), (6, 1, 1));
    assert!(body == imported(&fixture("full.json")));
}

#[test]
fn pbkdf2_export_opens() {
    opens_to_full("protected-pbkdf2.json", Kdf::Pbkdf2 { iterations: 5000 });
}

#[test]
fn argon2id_export_opens() {
    opens_to_full(
        "protected-argon2id.json",
        Kdf::Argon2id {
            memory_mib: 16,
            iterations: 2,
            parallelism: 2,
        },
    );
}

#[test]
fn wrong_password() {
    for name in ["protected-pbkdf2.json", "protected-argon2id.json"] {
        let p = protected(&fixture(name));
        assert_eq!(
            p.decrypt("Correct horse battery staple").err(),
            Some(Error::WrongPassword)
        );
        assert_eq!(p.decrypt("").err(), Some(Error::WrongPassword));
    }
}

/// The fixture with one base64 character of `part` (1 IV, 2 ciphertext, 3 MAC) of the encrypted
/// string under `key` changed.
fn tampered(key: &str, part: usize) -> Vec<u8> {
    let mut v: serde_json::Value =
        serde_json::from_slice(&fixture("protected-pbkdf2.json")).unwrap();
    let enc = v[key].as_str().unwrap().to_owned();
    let mut parts: Vec<String> = enc[2..].split('|').map(str::to_owned).collect();
    let p = &mut parts[part - 1];
    let c = if p.starts_with('A') { "B" } else { "A" };
    p.replace_range(0..1, c);
    v[key] = serde_json::Value::String(format!("2.{}", parts.join("|")));
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn tampering_fails_the_mac() {
    for part in 1..=3 {
        let p = protected(&tampered("data", part));
        assert_eq!(
            p.decrypt(PASSWORD).err(),
            Some(Error::Corrupt),
            "data part {part}"
        );
        let p = protected(&tampered("encKeyValidation_DO_NOT_EDIT", part));
        assert_eq!(
            p.decrypt(PASSWORD).err(),
            Some(Error::WrongPassword),
            "validation part {part}"
        );
    }
}

/// The export with `changes` applied to its top-level keys; `None` removes a key.
fn with_kdf(changes: &[(&str, Option<serde_json::Value>)]) -> Vec<u8> {
    let mut v: serde_json::Value =
        serde_json::from_slice(&fixture("protected-argon2id.json")).unwrap();
    let m = v.as_object_mut().unwrap();
    for (k, x) in changes {
        match x {
            Some(x) => m.insert((*k).to_owned(), x.clone()),
            None => m.remove(*k),
        };
    }
    serde_json::to_vec(&v).unwrap()
}

/// Number text written by hand, as serde_json would not keep `1e9` or `600000.0` as written.
fn with_raw(key: &str, raw: &str) -> Vec<u8> {
    let text = String::from_utf8(with_kdf(&[(key, Some(serde_json::json!("@")))])).unwrap();
    text.replace("\"@\"", raw).into_bytes()
}

fn argon2(m: u64, t: u64, p: u64) -> Vec<u8> {
    use serde_json::json;
    with_kdf(&[
        ("kdfType", Some(json!(1))),
        ("kdfMemory", Some(json!(m))),
        ("kdfIterations", Some(json!(t))),
        ("kdfParallelism", Some(json!(p))),
    ])
}

fn pbkdf2(i: u64) -> Vec<u8> {
    use serde_json::json;
    with_kdf(&[
        ("kdfType", Some(json!(0))),
        ("kdfIterations", Some(json!(i))),
        ("kdfMemory", Some(json!(null))),
        ("kdfParallelism", Some(json!(null))),
    ])
}

/// The KDF of a parsed export. A refusal is an `Err` from `parse` itself, before any
/// `ProtectedExport` exists, so no key derivation can run for it.
fn kdf_of(bytes: &[u8]) -> Result<Kdf, Error> {
    match parse(bytes)? {
        Export::Protected(p) => Ok(p.kdf()),
        Export::Plain(_) => panic!("plain"),
    }
}

#[test]
fn argon2id_bounds() {
    let ok = |m, t, p| {
        assert_eq!(
            kdf_of(&argon2(m, t, p)),
            Ok(Kdf::Argon2id {
                memory_mib: m as u32,
                iterations: t as u32,
                parallelism: p as u32
            }),
            "{m} {t} {p}"
        );
    };
    let refused = |m, t, p| {
        assert_eq!(
            kdf_of(&argon2(m, t, p)),
            Err(Error::KdfParams),
            "{m} {t} {p}"
        );
    };
    for m in [16, 256] {
        ok(m, 3, 1);
    }
    for t in [2, 10] {
        ok(64, t, 1);
    }
    for p in [1, 16] {
        ok(64, 3, p);
    }
    for m in [15, 257, 4_000_000] {
        refused(m, 3, 1);
    }
    for t in [1, 11] {
        refused(64, t, 1);
    }
    for p in [0, 17] {
        refused(64, 3, p);
    }
}

#[test]
fn pbkdf2_bounds() {
    for i in [5_000, 2_000_000] {
        assert_eq!(
            kdf_of(&pbkdf2(i)),
            Ok(Kdf::Pbkdf2 {
                iterations: i as u32
            })
        );
    }
    for i in [4_999, 2_000_001] {
        assert_eq!(kdf_of(&pbkdf2(i)), Err(Error::KdfParams), "{i}");
    }
    // PBKDF2 ignores the Argon2id fields, whatever they hold.
    use serde_json::json;
    let extra = with_kdf(&[
        ("kdfType", Some(json!(0))),
        ("kdfIterations", Some(json!(600_000))),
        ("kdfMemory", Some(json!(999_999))),
        ("kdfParallelism", Some(json!("x"))),
    ]);
    assert_eq!(
        kdf_of(&extra),
        Ok(Kdf::Pbkdf2 {
            iterations: 600_000
        })
    );
}

#[test]
fn kdf_values_of_the_wrong_kind() {
    use serde_json::json;
    for (key, raw, err) in [
        ("kdfIterations", "\"3\"", Error::NotAnExport),
        ("kdfMemory", "\"64\"", Error::NotAnExport),
        ("kdfParallelism", "null", Error::NotAnExport),
        ("kdfIterations", "-3", Error::KdfParams),
        ("kdfMemory", "64.5", Error::KdfParams),
        ("kdfMemory", "64.0", Error::KdfParams),
        ("kdfIterations", "1e9", Error::KdfParams),
        ("kdfMemory", "1000000000", Error::KdfParams),
        ("kdfIterations", "99999999999999999999", Error::KdfParams),
        ("kdfType", "2", Error::KdfType),
        ("kdfType", "-1", Error::KdfType),
        ("kdfType", "0.5", Error::KdfType),
        ("kdfType", "\"1\"", Error::NotAnExport),
    ] {
        assert_eq!(kdf_of(&with_raw(key, raw)), Err(err), "{key}: {raw}");
    }
    for (changes, err) in [
        (vec![("kdfType", None)], Error::NotAnExport),
        (vec![("kdfIterations", None)], Error::NotAnExport),
        (vec![("salt", Some(json!("")))], Error::NotAnExport),
        (vec![("salt", None)], Error::NotAnExport),
        (
            vec![("data", Some(json!("0.AAAA|AAAA")))],
            Error::NotAnExport,
        ),
        (
            vec![("encKeyValidation_DO_NOT_EDIT", None)],
            Error::NotAnExport,
        ),
        (
            vec![("passwordProtected", Some(json!(false)))],
            Error::AccountRestricted,
        ),
    ] {
        assert_eq!(kdf_of(&with_kdf(&changes)), Err(err), "{changes:?}");
    }
}
