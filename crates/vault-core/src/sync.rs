//! Sync decisions as pure functions: the `ETag`, the remote header checks against stored state,
//! adopt or push, the next generation, the `404` cases, bounded retries, and the recovery choice.
//! The caller does the HTTP and stores the state.

use crate::body::Body;
use crate::error::{InputKind, IntegrityKind as K, Result, input, integrity};
use crate::file::read_header;
use crate::header::{Header, MAX_GENERATION};
use crate::merge::same_content;
use crate::prim::sha256;

/// The SHA-256 of a vault file, as the accepted hash stores it.
pub fn file_hash(file: &[u8]) -> [u8; 32] {
    sha256(&[file])
}

/// The `ETag` of a vault file: its lowercase hex SHA-256, quoted. A client computes it from the
/// bytes it received and never relies on the header.
pub fn etag(file: &[u8]) -> String {
    format!("\"{}\"", hex::encode(file_hash(file)))
}

/// The generation and hash of the file a client last accepted from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The accepted generation.
    pub generation: u64,
    /// The SHA-256 of the accepted file.
    pub file_hash: [u8; 32],
}

/// What a client stores per vault, from a file that opened. It changes in the same atomic write
/// as the local vault file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    /// The vault ID.
    pub vault_id: [u8; 16],
    /// The last accepted file, or `None` before the first accepted pull or push.
    pub accepted: Option<Accepted>,
    /// The current `wrap_nonce`.
    pub wrap_nonce: [u8; 24],
    /// Every retired `wrap_nonce`.
    pub retired_wrap_nonces: Vec<[u8; 24]>,
}

impl SyncState {
    /// Whether `n` is a retired `wrap_nonce`.
    pub fn is_retired(&self, n: &[u8; 24]) -> bool {
        self.retired_wrap_nonces.contains(n)
    }

    /// Records a file the client adopted or pushed successfully.
    pub fn accept(&mut self, generation: u64, file: &[u8]) {
        self.accepted = Some(Accepted {
            generation,
            file_hash: file_hash(file),
        });
    }

    /// After a credential change lands, here or on another device: moves the current
    /// `wrap_nonce` to the retired list and makes `new` current. A retired `wrap_nonce` stays
    /// retired for the life of the vault, so a `new` that is already retired is an integrity
    /// error. Rotating to the current `wrap_nonce` changes nothing.
    pub fn rotate_wrap_nonce(&mut self, new: [u8; 24]) -> Result<()> {
        if new == self.wrap_nonce {
            return Ok(());
        }
        if self.is_retired(&new) {
            return integrity(K::RetiredWrapNonce);
        }
        if !self.is_retired(&self.wrap_nonce) {
            self.retired_wrap_nonces.push(self.wrap_nonce);
        }
        self.wrap_nonce = new;
        Ok(())
    }
}

/// How a remote header's wrap relates to the client's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapStatus {
    /// The client's current `wrap_nonce`: open with the cached vault key.
    Current,
    /// Neither current nor retired: another device changed the credentials.
    Changed,
}

/// A remote file that passed the header checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCheck {
    /// The remote header, not yet authenticated.
    pub header: Header,
    /// The SHA-256 of the remote file.
    pub file_hash: [u8; 32],
    /// The `ETag` for the conditional `PUT`.
    pub etag: String,
    /// How the remote wrap relates to the client's.
    pub wrap: WrapStatus,
}

/// Sync step 2: checks a pulled file's header against the stored state. Its `vault_id` equals
/// the stored one; its `generation` is at least the accepted generation, and where equal, the
/// file's SHA-256 equals the stored hash; its `wrap_nonce` is not retired. Any failure is an
/// integrity error.
pub fn check_remote(state: &SyncState, file: &[u8]) -> Result<RemoteCheck> {
    let header = read_header(file)?;
    let hash = file_hash(file);
    if header.vault_id != state.vault_id {
        return integrity(K::VaultIdMismatch);
    }
    if let Some(a) = &state.accepted {
        if header.generation < a.generation {
            return integrity(K::GenerationRollback);
        }
        if header.generation == a.generation && hash != a.file_hash {
            return integrity(K::GenerationFork);
        }
    }
    if state.is_retired(&header.wrap_nonce) {
        return integrity(K::RetiredWrapNonce);
    }
    let wrap = if header.wrap_nonce == state.wrap_nonce {
        WrapStatus::Current
    } else {
        WrapStatus::Changed
    };
    Ok(RemoteCheck {
        header,
        file_hash: hash,
        etag: etag(file),
        wrap,
    })
}

/// The header check for a client being set up, which has no stored state and accepts whatever
/// generation it first pulls. With a secret key from the emergency kit, `kit_vault_id` is the
/// kit's vault ID, and the remote `vault_id` must equal it.
pub fn check_remote_for_setup(file: &[u8], kit_vault_id: Option<&[u8; 16]>) -> Result<Header> {
    let header = read_header(file)?;
    if kit_vault_id.is_some_and(|id| *id != header.vault_id) {
        return integrity(K::VaultIdMismatch);
    }
    Ok(header)
}

/// `generation + 1`, refused past `2^48`.
pub fn next_generation(generation: u64) -> Result<u64> {
    match generation.checked_add(1) {
        Some(g) if g <= MAX_GENERATION => Ok(g),
        _ => input(InputKind::GenerationLimit),
    }
}

/// What sync step 5 does with the merged body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncAction {
    /// The merged body equals the remote body: adopt the remote file, store its generation and
    /// hash, and push nothing.
    Adopt,
    /// Seal the merged body under the remote header at `generation` with a fresh `body_nonce`, and
    /// send `PUT /v1/vault` with `If-Match` set to the pulled `ETag`.
    Push {
        /// The remote generation plus one.
        generation: u64,
    },
}

/// Sync step 5: adopt when the merged body has the remote body's content, push otherwise.
pub fn adopt_or_push(merged: &Body, remote: &Body, remote_generation: u64) -> Result<SyncAction> {
    if same_content(merged, remote) {
        Ok(SyncAction::Adopt)
    } else {
        Ok(SyncAction::Push {
            generation: next_generation(remote_generation)?,
        })
    }
}

/// What a client does when `GET /v1/vault` returns `404`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotFoundAction {
    /// Push the local file at `generation` with `If-None-Match: *`: generation 1 after
    /// `vault init`, or the accepted generation plus one to restore a server that lost its data.
    Push {
        /// The generation to push.
        generation: u64,
    },
    /// A client being set up: report that the server holds no vault and do nothing.
    NoVault,
}

/// The `404` cases. `state` is `None` for a client being set up, with no local vault.
pub fn on_not_found(state: Option<&SyncState>) -> Result<NotFoundAction> {
    match state {
        None => Ok(NotFoundAction::NoVault),
        Some(SyncState { accepted: None, .. }) => Ok(NotFoundAction::Push { generation: 1 }),
        Some(SyncState {
            accepted: Some(a), ..
        }) => Ok(NotFoundAction::Push {
            generation: next_generation(a.generation)?,
        }),
    }
}

/// The precondition a `PUT` carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutCondition {
    /// `If-Match: <etag>`, after a `200` on `GET`.
    IfMatch,
    /// `If-None-Match: *`, after a `404` on `GET`.
    IfNoneMatch,
}

/// Whether a sync tries again after a `412`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// Start again at the pull.
    Again,
    /// Report the failure; the local file is unaffected and the next sync starts afresh.
    GiveUp,
}

/// The most consecutive `412` responses one sync accepts.
pub const MAX_CONFLICTS: u32 = 5;
/// The most `404`-then-`412` rounds in a row one sync accepts.
pub const MAX_CREATE_CONFLICTS: u32 = 2;

/// Counts `412` responses within one sync.
// Every `412` counts toward the five; a `412` on `If-Match` ends a run of `404` then `412`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetryCounter {
    conflicts: u32,
    create_conflicts: u32,
}

impl RetryCounter {
    /// A counter for a new sync.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a `412` on a `PUT` with `condition`.
    pub fn precondition_failed(&mut self, condition: PutCondition) -> Retry {
        self.conflicts += 1;
        match condition {
            PutCondition::IfMatch => self.create_conflicts = 0,
            PutCondition::IfNoneMatch => self.create_conflicts += 1,
        }
        if self.conflicts >= MAX_CONFLICTS || self.create_conflicts >= MAX_CREATE_CONFLICTS {
            Retry::GiveUp
        } else {
            Retry::Again
        }
    }
}

/// What `vault sync --recover` does with the retained revisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// Recovery step 2: these revisions carry a `wrap_nonce` that is neither current nor
    /// retired, highest generation first. The client runs the credential change on another
    /// device flow with them and stops; a revision whose wrap does not open counts as garbage.
    CredentialChange(Vec<u64>),
    /// Recovery step 3: these revisions qualify, highest generation first. The client opens
    /// them in order with the vault key and takes the first that opens; it merges the local body
    /// into it and pushes at its generation plus one. When none opens, it pushes the local file
    /// at the accepted generation plus one. Both pushes use `If-Match` with the current `ETag`.
    Candidates(Vec<u64>),
}

/// Plans recovery from `(revision ID, file)` pairs. Files whose header does not decode, or whose
/// `vault_id` differs, are left out. With `past_unknown_wraps`, which a client sets only after the
/// credential change flow failed and the user confirmed that no credential change was made,
/// revisions under an unknown `wrap_nonce` are ignored instead of stopping the plan.
pub fn plan_recovery(
    state: &SyncState,
    revisions: &[(u64, &[u8])],
    past_unknown_wraps: bool,
) -> Recovery {
    let mut changed = Vec::new();
    let mut candidates = Vec::new();
    for (id, file) in revisions {
        let Ok(h) = read_header(file) else { continue };
        if h.vault_id != state.vault_id {
            continue;
        }
        if h.wrap_nonce == state.wrap_nonce {
            if state
                .accepted
                .as_ref()
                .is_none_or(|a| h.generation >= a.generation)
            {
                candidates.push((h.generation, *id));
            }
        } else if !state.is_retired(&h.wrap_nonce) {
            changed.push((h.generation, *id));
        }
    }
    let ordered = |mut v: Vec<(u64, u64)>| {
        v.sort_by(|a, b| b.cmp(a));
        v.into_iter().map(|(_, id)| id).collect()
    };
    if !changed.is_empty() && !past_unknown_wraps {
        Recovery::CredentialChange(ordered(changed))
    } else {
        Recovery::Candidates(ordered(candidates))
    }
}

/// The generation a recovery push uses: the chosen revision's generation plus one, or, when no
/// revision opened, the accepted generation plus one.
pub fn recovery_generation(state: &SyncState, chosen_generation: Option<u64>) -> Result<u64> {
    match (chosen_generation, &state.accepted) {
        (Some(g), _) => next_generation(g),
        (None, Some(a)) => next_generation(a.generation),
        (None, None) => Ok(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::file::seal_file;
    use crate::kdf::FLOOR;
    use crate::secret::{Kek, VaultKey};

    const VID: [u8; 16] = [1; 16];
    const WRAP: [u8; 24] = [3; 24];
    const OLD_WRAP: [u8; 24] = [4; 24];
    const NEW_WRAP: [u8; 24] = [5; 24];

    fn vk() -> VaultKey {
        VaultKey::from_bytes([9; 32])
    }

    fn file(vault_id: [u8; 16], generation: u64, wrap: [u8; 24], nonce: u8) -> Vec<u8> {
        let h = Header::wrap(
            false,
            vault_id,
            generation,
            FLOOR,
            [2; 16],
            wrap,
            &Kek::from_bytes([7; 32]),
            &vk(),
        );
        seal_file(&h, &vk(), &[nonce; 24], &Body::default()).unwrap()
    }

    fn state(accepted: Option<&[u8]>, generation: u64) -> SyncState {
        SyncState {
            vault_id: VID,
            accepted: accepted.map(|f| Accepted {
                generation,
                file_hash: file_hash(f),
            }),
            wrap_nonce: WRAP,
            retired_wrap_nonces: vec![OLD_WRAP],
        }
    }

    fn kind(r: Result<RemoteCheck>) -> Option<K> {
        match r {
            Err(Error::Integrity(k)) => Some(k),
            Err(_) => panic!("not an integrity error"),
            Ok(_) => None,
        }
    }

    #[test]
    fn etag_from_bytes() {
        assert_eq!(
            etag(b""),
            "\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\""
        );
        assert_eq!(
            etag(b"abc"),
            "\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\""
        );
    }

    #[test]
    fn remote_header_checks() {
        let accepted = file(VID, 5, WRAP, 1);
        let s = state(Some(&accepted), 5);
        assert_eq!(kind(check_remote(&s, &accepted)), None);
        assert_eq!(
            check_remote(&s, &accepted).unwrap().wrap,
            WrapStatus::Current
        );
        assert_eq!(kind(check_remote(&s, &file(VID, 6, WRAP, 1))), None);
        assert_eq!(
            kind(check_remote(&s, &file(VID, 4, WRAP, 1))),
            Some(K::GenerationRollback)
        );
        assert_eq!(
            kind(check_remote(&s, &file(VID, 5, WRAP, 2))),
            Some(K::GenerationFork),
            "equal generation, different bytes"
        );
        assert_eq!(
            kind(check_remote(&s, &file([2; 16], 6, WRAP, 1))),
            Some(K::VaultIdMismatch)
        );
        assert_eq!(
            kind(check_remote(&s, &file(VID, 6, OLD_WRAP, 1))),
            Some(K::RetiredWrapNonce)
        );
        let changed = check_remote(&s, &file(VID, 6, NEW_WRAP, 1)).unwrap();
        assert_eq!(changed.wrap, WrapStatus::Changed);
        assert_eq!(changed.etag, etag(&file(VID, 6, NEW_WRAP, 1)));
        assert_eq!(kind(check_remote(&s, b"garbage")), Some(K::Truncated));
        // Without an accepted generation, any generation passes.
        let fresh = state(None, 0);
        assert_eq!(kind(check_remote(&fresh, &file(VID, 1, WRAP, 1))), None);
    }

    #[test]
    fn setup_checks_the_kit_vault_id() {
        let f = file(VID, 9, WRAP, 1);
        assert!(check_remote_for_setup(&f, None).is_ok());
        assert!(check_remote_for_setup(&f, Some(&VID)).is_ok());
        assert_eq!(
            check_remote_for_setup(&f, Some(&[2; 16])).err(),
            Some(Error::Integrity(K::VaultIdMismatch))
        );
    }

    #[test]
    fn generations() {
        assert_eq!(next_generation(1), Ok(2));
        assert_eq!(next_generation(MAX_GENERATION - 1), Ok(MAX_GENERATION));
        assert_eq!(
            next_generation(MAX_GENERATION),
            Err(Error::InvalidInput(InputKind::GenerationLimit))
        );
        assert_eq!(
            next_generation(u64::MAX),
            Err(Error::InvalidInput(InputKind::GenerationLimit))
        );
    }

    #[test]
    fn adopt_with_an_unknown_top_level_key() {
        let remote =
            Body::from_json(br#"{"v":1,"horizon":0,"items":[],"tombstones":[],"future":{"a":1}}"#)
                .unwrap();
        let merged = crate::merge::merge(&Body::default(), &remote, 1_800_000_000_000).body;
        assert_eq!(adopt_or_push(&merged, &remote, 7), Ok(SyncAction::Adopt));
        let local =
            Body::from_json(br#"{"v":1,"horizon":0,"items":[],"tombstones":[],"local_only":1}"#)
                .unwrap();
        let merged = crate::merge::merge(&local, &remote, 1_800_000_000_000).body;
        assert_eq!(
            adopt_or_push(&merged, &remote, 7),
            Ok(SyncAction::Push { generation: 8 })
        );
    }

    #[test]
    fn not_found_cases() {
        assert_eq!(on_not_found(None), Ok(NotFoundAction::NoVault));
        let f = file(VID, 5, WRAP, 1);
        assert_eq!(
            on_not_found(Some(&state(None, 0))),
            Ok(NotFoundAction::Push { generation: 1 })
        );
        assert_eq!(
            on_not_found(Some(&state(Some(&f), 5))),
            Ok(NotFoundAction::Push { generation: 6 })
        );
    }

    #[test]
    fn retries_are_bounded() {
        let mut c = RetryCounter::new();
        for _ in 0..4 {
            assert_eq!(c.precondition_failed(PutCondition::IfMatch), Retry::Again);
        }
        assert_eq!(c.precondition_failed(PutCondition::IfMatch), Retry::GiveUp);
        let mut c = RetryCounter::new();
        assert_eq!(
            c.precondition_failed(PutCondition::IfNoneMatch),
            Retry::Again
        );
        assert_eq!(
            c.precondition_failed(PutCondition::IfNoneMatch),
            Retry::GiveUp
        );
        let mut c = RetryCounter::new();
        assert_eq!(
            c.precondition_failed(PutCondition::IfNoneMatch),
            Retry::Again
        );
        assert_eq!(c.precondition_failed(PutCondition::IfMatch), Retry::Again);
        assert_eq!(
            c.precondition_failed(PutCondition::IfNoneMatch),
            Retry::Again,
            "not twice in a row"
        );
        assert_eq!(c.precondition_failed(PutCondition::IfMatch), Retry::Again);
        assert_eq!(
            c.precondition_failed(PutCondition::IfMatch),
            Retry::GiveUp,
            "five 412 responses of either kind"
        );
    }

    #[test]
    fn recovery_takes_the_highest_qualifying_generation() {
        let accepted = file(VID, 5, WRAP, 1);
        let s = state(Some(&accepted), 5);
        let revs = [
            (10, file(VID, 4, WRAP, 1)),
            (11, file(VID, 5, WRAP, 1)),
            (12, file(VID, 7, WRAP, 2)),
            (13, file(VID, 6, WRAP, 3)),
            (14, file([2; 16], 9, WRAP, 1)),
            (15, file(VID, 8, OLD_WRAP, 1)),
            (16, b"garbage".to_vec()),
        ];
        let refs: Vec<(u64, &[u8])> = revs.iter().map(|(i, f)| (*i, &f[..])).collect();
        assert_eq!(
            plan_recovery(&s, &refs, false),
            Recovery::Candidates(vec![12, 13, 11])
        );
        assert_eq!(recovery_generation(&s, Some(7)), Ok(8));
        assert_eq!(recovery_generation(&s, None), Ok(6));
    }

    #[test]
    fn recovery_stops_at_an_unknown_wrap_nonce() {
        let accepted = file(VID, 5, WRAP, 1);
        let s = state(Some(&accepted), 5);
        let revs = [
            (20, file(VID, 6, WRAP, 1)),
            (21, file(VID, 7, NEW_WRAP, 1)),
            (22, file(VID, 3, [6; 24], 1)),
        ];
        let refs: Vec<(u64, &[u8])> = revs.iter().map(|(i, f)| (*i, &f[..])).collect();
        assert_eq!(
            plan_recovery(&s, &refs, false),
            Recovery::CredentialChange(vec![21, 22])
        );
        assert_eq!(
            plan_recovery(&s, &refs, true),
            Recovery::Candidates(vec![20])
        );
    }

    #[test]
    fn garbage_at_the_top_generation_never_wins() {
        // A garbage file under the current wrap at generation 2^48 is the first candidate; it
        // never opens, so the client moves on to the honest revision.
        let accepted = file(VID, 5, WRAP, 1);
        let s = state(Some(&accepted), 5);
        let mut garbage = file(VID, MAX_GENERATION, WRAP, 1);
        let last = garbage.len() - 1;
        garbage[last] ^= 1;
        let honest = file(VID, 6, WRAP, 1);
        let refs: Vec<(u64, &[u8])> = vec![(29, &accepted), (30, &garbage), (31, &honest)];
        let Recovery::Candidates(order) = plan_recovery(&s, &refs, false) else {
            panic!("no unknown wrap here")
        };
        assert_eq!(
            order,
            vec![30, 31, 29],
            "garbage first, by its claimed generation"
        );
        let first_open = |order: &[u64]| {
            order
                .iter()
                .map(|id| refs.iter().find(|(i, _)| i == id).unwrap())
                .find_map(|(i, f)| crate::file::open_file(f, &vk()).ok().map(|(h, _)| (*i, h)))
        };
        let (id, h) = first_open(&order).unwrap();
        assert_eq!((id, h.generation), (31, 6));
        assert_eq!(recovery_generation(&s, Some(h.generation)), Ok(7));
        // Nothing opens: push the local file at the accepted generation plus one.
        let only_garbage: Vec<(u64, &[u8])> = vec![(30, &garbage)];
        let Recovery::Candidates(order) = plan_recovery(&s, &only_garbage, false) else {
            panic!()
        };
        assert_eq!(order, vec![30]);
        assert!(
            order
                .iter()
                .all(|_| crate::file::open_file(&garbage, &vk()).is_err())
        );
        assert_eq!(recovery_generation(&s, None), Ok(6));
    }

    #[test]
    fn garbage_passes_the_header_check_and_fails_to_open() {
        let accepted = file(VID, 5, WRAP, 1);
        let mut s = state(Some(&accepted), 5);
        let mut garbage = file(VID, MAX_GENERATION, WRAP, 1);
        let last = garbage.len() - 1;
        garbage[last] ^= 1;
        // The header check sees only the header, which is well formed.
        let check = check_remote(&s, &garbage).unwrap();
        assert_eq!(check.header.generation, MAX_GENERATION);
        assert_eq!(check.wrap, WrapStatus::Current);
        // Opening fails, so the client never reaches `accept` and its state is unchanged.
        assert_eq!(
            crate::file::open_file(&garbage, &vk()).err(),
            Some(Error::Integrity(K::Aead))
        );
        let before = s.clone();
        if crate::file::open_file(&garbage, &vk()).is_ok() {
            s.accept(check.header.generation, &garbage);
        }
        assert_eq!(s, before);
        assert_eq!(s.accepted.as_ref().unwrap().generation, 5);
    }

    #[test]
    fn re_pushed_old_revision_does_not_resurrect_a_deleted_item() {
        use crate::body::tests::{DEV_A, ID1, login_json};
        let now = 1_800_000_000_000;
        let old_body = Body::from_json(
            format!(
                r#"{{"v":1,"horizon":0,"items":[{}],"tombstones":[]}}"#,
                login_json(ID1, now - 1000, DEV_A, "pw")
            )
            .as_bytes(),
        )
        .unwrap();
        let mut local = old_body.clone();
        crate::edit::delete_item(&mut local, ID1, now - 500, &[0xbb; 16]).unwrap();
        let accepted = file(VID, 5, WRAP, 1);
        let s = state(Some(&accepted), 5);
        // An honest device holding the old body pushes it at a higher generation.
        let h = Header::wrap(
            false,
            VID,
            6,
            FLOOR,
            [2; 16],
            WRAP,
            &Kek::from_bytes([7; 32]),
            &vk(),
        );
        let repushed = seal_file(&h, &vk(), &[9; 24], &old_body).unwrap();
        assert_eq!(
            check_remote(&s, &repushed).unwrap().wrap,
            WrapStatus::Current
        );
        let (_, remote) = crate::file::open_file(&repushed, &vk()).unwrap();
        let merged = crate::merge::merge(&local, &remote, now).body;
        assert!(merged.item(ID1).is_none());
        assert_eq!(merged.tombstones.len(), 1);
        assert_eq!(
            adopt_or_push(&merged, &remote, 6),
            Ok(SyncAction::Push { generation: 7 })
        );
    }

    #[test]
    fn wrap_nonce_rotation() {
        let mut s = state(None, 0);
        s.rotate_wrap_nonce(NEW_WRAP).unwrap();
        assert_eq!(s.wrap_nonce, NEW_WRAP);
        assert_eq!(s.retired_wrap_nonces, vec![OLD_WRAP, WRAP]);
        s.rotate_wrap_nonce(NEW_WRAP).unwrap();
        assert_eq!(s.retired_wrap_nonces, vec![OLD_WRAP, WRAP], "idempotent");
        // A retired nonce never becomes current again, and the state is unchanged.
        for retired in [OLD_WRAP, WRAP] {
            assert_eq!(
                s.rotate_wrap_nonce(retired),
                Err(Error::Integrity(K::RetiredWrapNonce))
            );
            assert_eq!(s.wrap_nonce, NEW_WRAP);
            assert_eq!(s.retired_wrap_nonces, vec![OLD_WRAP, WRAP]);
        }
        let mut f = state(None, 0);
        f.accept(3, b"bytes");
        assert_eq!(
            f.accepted,
            Some(Accepted {
                generation: 3,
                file_hash: file_hash(b"bytes")
            })
        );
    }
}
