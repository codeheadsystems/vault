//! The `local.json` form of the client state.

mod common;

use common::*;
use vault_client::{ClientError, ClientState, Retired, SecretKeyStore, StopReason, Stopped};
use vault_core::body::Body;
use vault_core::sync::{Accepted, file_hash};

fn full() -> ClientState {
    let fx = Fixture::new(4);
    let file = fx.file(7, &Body::default(), 1);
    let mut s = fx.state(file.clone());
    s.accepted = Some(Accepted {
        generation: 7,
        file_hash: file_hash(&file),
    });
    s.retired = vec![
        Retired {
            nonce: [0xb0; 24],
            revision: Some(41),
        },
        Retired {
            nonce: [0xb1; 24],
            revision: None,
        },
    ];
    s.refused = vec![[0xc0; 24]];
    s.secret_key_store = SecretKeyStore::File;
    s.pending_secret_key = true;
    s.stopped = Some(Stopped {
        reason: StopReason::Credentials,
        code: "sync.credentials_changed".into(),
        at: 1_760_281_445_000,
    });
    s.dropped = vec!["Old \"bank\"".into(), "ünïcode".into()];
    s.last_sync = Some(1_760_281_445_000);
    s
}

#[test]
fn round_trips() {
    for s in [
        full(),
        Fixture::new(5).state(Fixture::new(5).file(1, &Body::default(), 1)),
    ] {
        let json = s.to_json();
        assert_eq!(ClientState::from_json(&json).unwrap(), s);
        assert_eq!(ClientState::from_json(&json).unwrap().to_json(), json);
    }
}

#[test]
fn has_the_documented_shape() {
    let s = full();
    let v: serde_json::Value = serde_json::from_slice(&s.to_json()).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "accepted",
            "dropped",
            "file",
            "last_sync",
            "pending_secret_key",
            "refused",
            "retired",
            "secret_key_store",
            "stopped",
            "v",
            "vault_id",
            "wrap_nonce"
        ]
    );
    assert_eq!(v["v"], 1);
    assert_eq!(v["vault_id"], hex::encode(s.vault_id));
    assert_eq!(v["accepted"]["generation"], 7);
    assert_eq!(v["accepted"]["hash"].as_str().unwrap().len(), 64);
    assert_eq!(v["wrap_nonce"].as_str().unwrap().len(), 48);
    assert_eq!(v["retired"][0]["revision"], 41);
    assert!(v["retired"][1]["revision"].is_null());
    assert_eq!(v["secret_key_store"], "file");
    assert_eq!(v["stopped"]["reason"], "credentials");
    assert_eq!(v["stopped"]["at"], 1_760_281_445_000u64);
    assert_eq!(v["file"], hex::encode(&s.file));
    let fresh = Fixture::new(5).state(Fixture::new(5).file(1, &Body::default(), 1));
    let v: serde_json::Value = serde_json::from_slice(&fresh.to_json()).unwrap();
    assert!(v["accepted"].is_null() && v["stopped"].is_null() && v["last_sync"].is_null());
}

type Mutation = Box<dyn Fn(&mut serde_json::Value)>;

#[test]
fn parsing_is_strict() {
    let good: serde_json::Value = serde_json::from_slice(&full().to_json()).unwrap();
    let bad = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v = good.clone();
        f(&mut v);
        ClientState::from_json(&serde_json::to_vec(&v).unwrap())
    };
    let cases: Vec<(&str, Mutation)> = vec![
        ("v 2", Box::new(|v| v["v"] = 2.into())),
        ("unknown key", Box::new(|v| v["extra"] = 1.into())),
        (
            "missing key",
            Box::new(|v| {
                v.as_object_mut().unwrap().remove("refused");
            }),
        ),
        (
            "upper-case hex",
            Box::new(|v| v["refused"][0] = v["refused"][0].as_str().unwrap().to_uppercase().into()),
        ),
        ("short vault_id", Box::new(|v| v["vault_id"] = "00".into())),
        ("short nonce", Box::new(|v| v["wrap_nonce"] = "00".into())),
        ("odd file hex", Box::new(|v| v["file"] = "abc".into())),
        (
            "generation 0",
            Box::new(|v| v["accepted"]["generation"] = 0.into()),
        ),
        (
            "accepted extra",
            Box::new(|v| v["accepted"]["x"] = 0.into()),
        ),
        (
            "store",
            Box::new(|v| v["secret_key_store"] = "cloud".into()),
        ),
        (
            "reason",
            Box::new(|v| v["stopped"]["reason"] = "other".into()),
        ),
        ("empty code", Box::new(|v| v["stopped"]["code"] = "".into())),
        (
            "pending not bool",
            Box::new(|v| v["pending_secret_key"] = 0.into()),
        ),
        ("negative", Box::new(|v| v["last_sync"] = (-1).into())),
        ("float", Box::new(|v| v["last_sync"] = 1.5.into())),
        (
            "dropped not strings",
            Box::new(|v| v["dropped"] = serde_json::json!([1])),
        ),
        (
            "retired extra",
            Box::new(|v| v["retired"][0]["x"] = 1.into()),
        ),
    ];
    for (name, f) in cases {
        assert_eq!(bad(&*f).err(), Some(ClientError::LocalState), "{name}");
    }
    let json = String::from_utf8(full().to_json()).unwrap();
    let dup = json.replacen("{\"accepted\"", "{\"v\":1,\"accepted\"", 1);
    assert_eq!(
        ClientState::from_json(dup.as_bytes()).err(),
        Some(ClientError::LocalState),
        "duplicate key"
    );
    assert_eq!(
        ClientState::from_json(b"[]").err(),
        Some(ClientError::LocalState)
    );
    assert_eq!(
        ClientState::from_json(b"").err(),
        Some(ClientError::LocalState)
    );
}

#[test]
fn debug_leaves_out_item_names_and_the_file() {
    let s = full();
    let text = format!("{s:?}");
    assert!(!text.contains("bank"));
    assert!(text.contains("dropped: 2"));
    assert!(
        !text.contains(&hex::encode(&s.file[133..165])),
        "no ciphertext"
    );
    assert!(
        !text.contains(&hex::encode(&s.file[85..133])),
        "no wrapped vault key"
    );
    assert!(text.contains(&format!("file_len: {}", s.file.len())));
}

#[test]
fn unpushed_compares_the_file_hash_with_the_accepted_hash() {
    let mut s = full();
    assert!(!s.unpushed());
    s.file[200] ^= 1;
    assert!(s.unpushed());
    s.accepted = None;
    assert!(s.unpushed());
}

#[test]
fn a_retired_nonce_never_becomes_current_again() {
    let mut s = full();
    let current = s.wrap_nonce;
    s.rotate_wrap_nonce([0xc0; 24], Some(50)).unwrap();
    assert_eq!(s.wrap_nonce, [0xc0; 24]);
    assert!(
        s.refused.is_empty(),
        "a refused nonce that now opens leaves the list"
    );
    assert_eq!(
        s.retirement(&current),
        Some(&Retired {
            nonce: current,
            revision: Some(50)
        })
    );
    s.rotate_wrap_nonce([0xc0; 24], Some(60)).unwrap();
    assert_eq!(
        s.retired.len(),
        3,
        "rotating to the current nonce changes nothing"
    );
    assert!(s.rotate_wrap_nonce(current, None).is_err());
    assert!(s.rotate_wrap_nonce([0xb0; 24], None).is_err());
    assert_eq!(s.wrap_nonce, [0xc0; 24]);
}
