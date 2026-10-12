//! Revisions: the files in `revisions/`, the index of their metadata, crash cleanup, the store
//! order, retention, the quota, and the `prune` and `rm` commands.

use crate::datadir::{self, DataDir, TMP_SUFFIX};
use crate::error::{Context, Result};
use crate::time::{self, DAY_MS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The largest vault file the server accepts, 16 MiB.
pub(crate) const MAX_SIZE: u64 = 16 << 20;
/// The most revisions the server retains.
pub(crate) const MAX_REVISIONS: usize = 10_000;
/// Retention keeps at least this many of the newest revisions.
const KEEP_NEWEST: usize = 100;
/// Retention keeps a daily revision per token for this many UTC days, today included.
const KEEP_DAYS: u64 = 90;
const BLOCK: u64 = 4096;

/// A retained revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    /// The revision ID.
    pub id: u64,
    /// The `ETag` recorded when the revision was stored.
    pub etag: String,
    /// The size of the vault file in bytes.
    pub size: u64,
    /// When the server stored it, in ms since the Unix epoch.
    pub created_ms: u64,
    /// The name of the token that pushed it.
    pub token: String,
}

impl Revision {
    /// The creation time as `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn created(&self) -> String {
        time::format(self.created_ms)
    }

    /// What the revision counts against the quota: its size rounded up to 4,096 bytes, plus
    /// 4,096 bytes for its metadata.
    pub(crate) fn charge(&self) -> u64 {
        charge(self.size)
    }
}

/// What a revision of `size` bytes counts against the quota.
pub(crate) fn charge(size: u64) -> u64 {
    size.div_ceil(BLOCK)
        .saturating_mul(BLOCK)
        .saturating_add(BLOCK)
}

/// `revisions/<id>.json`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetaFile {
    etag: String,
    size: u64,
    created: String,
    token: String,
}

/// Parses a revision ID: a decimal `u64` without leading zeros or a sign.
pub(crate) fn parse_id(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok().filter(|n| n.to_string() == s)
}

fn vault_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id}.vault"))
}

fn meta_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// The IDs of the revisions in `dir`: the canonical `<id>.vault` files.
fn list_ids(dir: &Path) -> io::Result<BTreeSet<u64>> {
    let mut ids = BTreeSet::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name();
        if let Some(id) = name
            .to_str()
            .and_then(|n| n.strip_suffix(".vault"))
            .and_then(parse_id)
        {
            ids.insert(id);
        }
    }
    Ok(ids)
}

/// Reads a revision's metadata. When the metadata file is missing or unreadable, the revision is
/// described from its `.vault` file: the `ETag` and size of its bytes, its modification time, and
/// an empty token name. `None` when the `.vault` file is gone.
fn load(dir: &Path, id: u64) -> Option<Revision> {
    let from_meta = datadir::read(&meta_path(dir, id))
        .ok()
        .and_then(|b| serde_json::from_slice::<MetaFile>(&b).ok())
        .and_then(|m| {
            Some(Revision {
                id,
                created_ms: time::parse(&m.created)?,
                etag: m.etag,
                size: m.size,
                token: m.token,
            })
        });
    if from_meta.is_some() {
        return from_meta;
    }
    let mut f = datadir::open_read(&vault_path(dir, id)).ok()?;
    let meta = f.metadata().ok()?;
    let mut bytes = Vec::new();
    io::Read::read_to_end(&mut f, &mut bytes).ok()?;
    Some(Revision {
        id,
        etag: vault_core::sync::etag(&bytes),
        size: bytes.len() as u64,
        created_ms: u64::try_from(meta.mtime())
            .unwrap_or(0)
            .saturating_mul(1000),
        token: String::new(),
    })
}

/// The retained revisions, keyed by ID. Metadata is written once, so an entry read once stays
/// valid; [`Index::refresh`] adds and drops entries as `.vault` files appear and disappear.
#[derive(Debug, Default)]
pub(crate) struct Index {
    revs: BTreeMap<u64, Revision>,
}

impl Index {
    /// Reads `dir`.
    pub(crate) fn read(dir: &Path) -> Result<Index> {
        let mut index = Index::default();
        index.refresh(dir)?;
        Ok(index)
    }

    /// Brings the index up to date with the `.vault` files in `dir`.
    pub(crate) fn refresh(&mut self, dir: &Path) -> Result<()> {
        let ids = list_ids(dir).context(|| format!("reading {}", dir.display()))?;
        self.revs.retain(|id, _| ids.contains(id));
        for id in ids {
            // A revision deleted between the listing and this read is left out.
            if let btree_map::Entry::Vacant(e) = self.revs.entry(id)
                && let Some(r) = load(dir, id)
            {
                e.insert(r);
            }
        }
        Ok(())
    }

    /// The current revision: the one with the highest ID.
    pub(crate) fn current(&self) -> Option<&Revision> {
        self.revs.values().next_back()
    }

    pub(crate) fn get(&self, id: u64) -> Option<&Revision> {
        self.revs.get(&id)
    }

    pub(crate) fn len(&self) -> usize {
        self.revs.len()
    }

    /// The sum of every revision's quota charge.
    pub(crate) fn charged(&self) -> u64 {
        self.revs
            .values()
            .fold(0, |sum, r| sum.saturating_add(r.charge()))
    }

    /// Every revision, newest first.
    pub(crate) fn newest_first(&self) -> Vec<Revision> {
        self.revs.values().rev().cloned().collect()
    }

    fn insert(&mut self, r: Revision) {
        self.revs.insert(r.id, r);
    }

    /// Deletes revisions from disk and from the index. The caller holds the writer lock and has
    /// left the current revision out of `ids`.
    fn delete(&mut self, dir: &Path, ids: &BTreeSet<u64>) -> Result<()> {
        for &id in ids {
            // The `.vault` file goes first: a crash between the two leaves orphan metadata,
            // which the next start removes.
            for path in [vault_path(dir, id), meta_path(dir, id)] {
                match fs::remove_file(&path) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => {
                        return Err(e).context(|| format!("removing {}", path.display()));
                    }
                    _ => {}
                }
            }
            self.revs.remove(&id);
        }
        if !ids.is_empty() {
            datadir::fsync_dir(dir).context(|| format!("syncing {}", dir.display()))?;
        }
        Ok(())
    }
}

/// The revisions that retention keeps at `now_ms`: the newest 100; the newest revision of each
/// token on each UTC day of the last 90 days; the newest revision of each token; and the current
/// revision.
pub(crate) fn retained(revs: &[Revision], now_ms: u64) -> BTreeSet<u64> {
    let mut keep: BTreeSet<u64> = BTreeSet::new();
    let mut ids: Vec<u64> = revs.iter().map(|r| r.id).collect();
    ids.sort_unstable_by(|a, b| b.cmp(a));
    keep.extend(ids.iter().take(KEEP_NEWEST));
    // The 90 UTC days ending today, today included.
    let first_day = (now_ms / DAY_MS).saturating_sub(KEEP_DAYS - 1);
    let mut daily: BTreeMap<(&str, u64), u64> = BTreeMap::new();
    let mut newest: BTreeMap<&str, u64> = BTreeMap::new();
    for r in revs {
        let n = newest.entry(&r.token).or_insert(r.id);
        *n = (*n).max(r.id);
        let day = r.created_ms / DAY_MS;
        if day >= first_day {
            let d = daily.entry((&r.token, day)).or_insert(r.id);
            *d = (*d).max(r.id);
        }
    }
    keep.extend(daily.values());
    keep.extend(newest.values());
    keep.extend(ids.first());
    keep
}

/// Removes temporary files and metadata files without a `.vault` file. The caller holds the
/// writer lock.
pub(crate) fn cleanup(dir: &Path) -> Result<()> {
    let ctx = || format!("cleaning {}", dir.display());
    let ids = list_ids(dir).context(ctx)?;
    for entry in fs::read_dir(dir).context(ctx)? {
        let entry = entry.context(ctx)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let orphan = name
            .strip_suffix(".json")
            .and_then(parse_id)
            .is_some_and(|id| !ids.contains(&id));
        if orphan || name.ends_with(TMP_SUFFIX) {
            let p = entry.path();
            fs::remove_file(&p).context(|| format!("removing {}", p.display()))?;
        }
    }
    datadir::fsync_dir(dir).context(ctx)
}

/// Why a revision was not stored.
#[derive(Debug)]
pub(crate) enum StoreError {
    /// The quota or the revision cap would be exceeded.
    Full,
    /// A file operation failed.
    Io(crate::Error),
}

/// Whether one more revision of `size` bytes fits: the quota and the revision cap.
pub(crate) fn fits(index: &Index, size: u64, quota: u64) -> bool {
    index.len() < MAX_REVISIONS && index.charged().saturating_add(charge(size)) <= quota
}

/// A received body, written and synced to a temporary file in `revisions/`.
pub(crate) struct Upload<'a> {
    pub(crate) path: &'a Path,
    pub(crate) etag: String,
    pub(crate) size: u64,
    pub(crate) token: &'a str,
}

/// Stores an upload as a new revision with an ID of at least `min_id`, then applies retention.
/// The caller holds the PUT lock and the writer lock. Returns the new revision, with the error
/// of a retention deletion that failed after the revision was stored.
pub(crate) fn store(
    dir: &Path,
    index: &mut Index,
    min_id: u64,
    upload: Upload<'_>,
    quota: u64,
    now_ms: u64,
) -> std::result::Result<(Revision, Option<crate::Error>), StoreError> {
    let io_err = StoreError::Io;
    index.refresh(dir).map_err(io_err)?;
    if !fits(index, upload.size, quota) {
        return Err(StoreError::Full);
    }
    let id = index
        .current()
        .map_or(min_id, |c| min_id.max(c.id.saturating_add(1)));
    let size = upload.size;
    let rev = Revision {
        id,
        etag: upload.etag,
        size,
        created_ms: now_ms,
        token: upload.token.to_owned(),
    };
    // The metadata first, then the bytes: a revision exists once its `.vault` file does.
    let meta = MetaFile {
        etag: rev.etag.clone(),
        size,
        created: rev.created(),
        token: rev.token.clone(),
    };
    let mut json = serde_json::to_vec(&meta).expect("metadata serialises");
    json.push(b'\n');
    let mpath = meta_path(dir, id);
    let mtmp = datadir::tmp_path(&mpath);
    let write_meta = || -> io::Result<()> {
        // A temporary file left by an earlier failed write is replaced.
        match fs::remove_file(&mtmp) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut f = datadir::create_new(&mtmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
        fs::rename(&mtmp, &mpath)
    };
    if let Err(e) = write_meta() {
        let _ = fs::remove_file(&mtmp);
        return Err(io_err(crate::Error::Io {
            context: format!("writing {}", mpath.display()),
            source: e,
        }));
    }
    let vpath = vault_path(dir, id);
    if let Err(e) = fs::rename(upload.path, &vpath) {
        let _ = fs::remove_file(&mpath);
        return Err(io_err(crate::Error::Io {
            context: format!("writing {}", vpath.display()),
            source: e,
        }));
    }
    datadir::fsync_dir(dir)
        .context(|| format!("syncing {}", dir.display()))
        .map_err(io_err)?;
    index.insert(rev.clone());
    let all: Vec<Revision> = index.newest_first();
    let keep = retained(&all, now_ms);
    let drop: BTreeSet<u64> = all
        .iter()
        .map(|r| r.id)
        .filter(|id| !keep.contains(id))
        .collect();
    Ok((rev, index.delete(dir, &drop).err()))
}

/// Opens a retained revision's bytes.
pub(crate) fn open(dir: &Path, id: u64) -> io::Result<fs::File> {
    datadir::open_read(&vault_path(dir, id))
}

/// Lists the retained revisions, newest first.
pub fn list(data: &DataDir) -> Result<Vec<Revision>> {
    data.check()?;
    Ok(Index::read(&data.revisions())?.newest_first())
}

/// Deletes every revision with an ID lower than `before`, except the current one. Returns the
/// deleted IDs.
pub fn prune(data: &DataDir, before: u64) -> Result<Vec<u64>> {
    delete_where(data, |r| r.id < before)
}

/// Deletes the revisions that the token named `token` pushed, only those with an ID above
/// `after` when it is given, except the current one. Returns the deleted IDs.
pub fn remove_by_token(data: &DataDir, token: &str, after: Option<u64>) -> Result<Vec<u64>> {
    delete_where(data, |r| r.token == token && after.is_none_or(|a| r.id > a))
}

fn delete_where(data: &DataDir, pred: impl Fn(&Revision) -> bool) -> Result<Vec<u64>> {
    data.check()?;
    let _lock = data.write_lock()?;
    let dir = data.revisions();
    let mut index = Index::read(&dir)?;
    let current = index.current().map(|c| c.id);
    let ids: BTreeSet<u64> = index
        .newest_first()
        .iter()
        .filter(|r| Some(r.id) != current && pred(r))
        .map(|r| r.id)
        .collect();
    index.delete(&dir, &ids)?;
    Ok(ids.into_iter().collect())
}

/// Where a body being received is written: `revisions/upload-<random>.tmp`.
pub(crate) fn upload_path(dir: &Path) -> PathBuf {
    let mut r = [0u8; 8];
    // The name only needs to be unlikely to collide; `create_new` refuses a collision.
    let _ = getrandom::getrandom(&mut r);
    dir.join(format!("upload-{}{TMP_SUFFIX}", hex::encode(r)))
}

/// Whether `body` has the shape of a vault file: it starts with `VAULT`, and its size is 4,269
/// bytes or more with `size - 173` a multiple of 4,096. No key is used.
pub(crate) fn vault_shaped(body: &[u8]) -> bool {
    let n = body.len() as u64;
    body.starts_with(b"VAULT") && n >= 4269 && (n - 173).is_multiple_of(BLOCK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rev(id: u64, token: &str, created_ms: u64) -> Revision {
        Revision {
            id,
            etag: String::new(),
            size: 4269,
            created_ms,
            token: token.into(),
        }
    }

    #[test]
    fn ids() {
        assert_eq!(parse_id("0"), Some(0));
        assert_eq!(parse_id("42"), Some(42));
        assert_eq!(parse_id("18446744073709551615"), Some(u64::MAX));
        for bad in [
            "",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "18446744073709551616",
            "1a",
            "１",
        ] {
            assert_eq!(parse_id(bad), None, "{bad}");
        }
    }

    #[test]
    fn shape() {
        let mut ok = b"VAULT".to_vec();
        ok.resize(4269, 0);
        assert!(vault_shaped(&ok));
        ok.resize(4269 + 4096, 0);
        assert!(vault_shaped(&ok));
        ok.resize(4269 + 1, 0);
        assert!(!vault_shaped(&ok));
        assert!(!vault_shaped(&ok[..173]));
        let mut bad = vec![0u8; 4269];
        bad[..5].copy_from_slice(b"VAULX");
        assert!(!vault_shaped(&bad));
    }

    #[test]
    fn quota_charge() {
        assert_eq!(charge(0), 4096);
        assert_eq!(charge(1), 8192);
        assert_eq!(charge(4096), 8192);
        assert_eq!(charge(4269), 12288);
    }

    #[test]
    fn retention_keeps_newest_hundred_and_current() {
        let now = 1000 * DAY_MS;
        let revs: Vec<Revision> = (1..=150).map(|id| rev(id, "a", now)).collect();
        let keep = retained(&revs, now);
        assert_eq!(keep, (51..=150).collect());
    }

    #[test]
    fn retention_keeps_each_tokens_newest_whatever_its_age() {
        let now = 1000 * DAY_MS;
        let mut revs = vec![
            rev(1, "old", 0),
            rev(2, "old", DAY_MS),
            rev(3, "b", now - 500 * DAY_MS),
        ];
        revs.extend((4..=300).map(|id| rev(id, "thief", now)));
        let keep = retained(&revs, now);
        assert!(!keep.contains(&1));
        assert!(keep.contains(&2) && keep.contains(&3) && keep.contains(&300));
        assert_eq!(keep.len(), 102);
    }

    #[test]
    fn retention_keeps_daily_newest_for_ninety_days() {
        let now = 1000 * DAY_MS + 5;
        let mut revs = Vec::new();
        let mut id = 0;
        // Three revisions per token per day for 100 days, oldest first.
        for day in (0..100).rev() {
            for token in ["a", "b"] {
                for h in 0..3 {
                    id += 1;
                    revs.push(rev(id, token, now - day * DAY_MS - (3 - h)));
                }
            }
        }
        // And 200 later revisions of one token, so the newest 100 are all today's.
        for _ in 0..200 {
            id += 1;
            revs.push(rev(id, "c", now));
        }
        let keep = retained(&revs, now);
        let daily: Vec<&Revision> = revs
            .iter()
            .filter(|r| r.token != "c" && keep.contains(&r.id))
            .collect();
        // Days today-89 ..= today, one per token per day.
        assert_eq!(daily.len(), 180);
        for r in &daily {
            let day = r.created_ms / DAY_MS;
            assert!(day >= now / DAY_MS - 89);
            assert!(
                revs.iter()
                    .filter(|o| o.token == r.token && o.created_ms / DAY_MS == day)
                    .all(|o| o.id <= r.id)
            );
        }
        assert_eq!(keep.len(), 180 + 100);
    }
}
