//! Fails when vault-core's `insecure-test-kdf` feature is on without `VAULT_EXPECT_TEST_KDF=1`, so
//! a leak of the feature into this crate's build, for example through feature unification, fails
//! `cargo test --workspace`. The run that enables the feature on purpose sets the variable.

#[test]
fn test_kdf_is_allowed_only_when_expected() {
    let expected = std::env::var("VAULT_EXPECT_TEST_KDF").as_deref() == Ok("1");
    assert_eq!(
        vault_core::kdf::TEST_KDF_ALLOWED,
        expected,
        "TEST_KDF_ALLOWED does not match VAULT_EXPECT_TEST_KDF; has insecure-test-kdf leaked?"
    );
}

/// The Android binding moves machines between threads.
#[test]
fn machines_are_send() {
    fn send<T: Send>() {}
    send::<vault_client::Machine<vault_client::sync::SyncReport>>();
    send::<vault_client::Machine<vault_client::passwd::PasswdReport>>();
    send::<vault_client::Machine<vault_client::recover::RecoverReport>>();
    send::<vault_client::Machine<vault_client::restore::Revision>>();
    send::<vault_client::Machine<vault_client::unlock::UnlockReport>>();
    send::<vault_client::Machine<vault_client::setup::InitReport>>();
    send::<vault_client::Machine<()>>();
}
