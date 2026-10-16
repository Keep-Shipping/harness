//! The console's own credentials: the Cloudflare read token, the optional
//! Cloudflare deploy token and the GitHub token. They are envelope-encrypted
//! by `cratefield-secrets`, not by the console's own cipher.
//!
//! The envelope: each store holds one data key (DEK). The DEK is wrapped by
//! `cratefield-kms`'s `WorkerSecretKms` under the master key (KEK), and the
//! wrapped DEK sits in D1 next to the tokens it protects. The KEK never
//! leaves the Worker's secret store: `HARNESS_KEK_CURRENT` names the version
//! that wraps, `HARNESS_KEK_V1`, `HARNESS_KEK_V2`, ... hold the material.
//! A dump of the console's D1 database is ciphertext plus wrapped keys, and
//! nothing there opens without the KEK.
//!
//! Tier: `cratefield-secrets` has two. The global tier holds the harness's
//! own connection strings and platform keys, and only a `HarnessOnly` proof
//! (or the `control-plane` feature, which this venture does not enable) can
//! open it. These tokens are this venture's, in this venture's database, so
//! they live in the tenant tier under [`TENANT`]. The tenant tier is what a
//! module is given, and it is the one whose database is the console's own.
//!
//! Callers never see a store or a key. [`Vault`] is the whole surface: read
//! a token (with the lazy move from the old `HARNESS_SECRET` seal, below),
//! write one, and forget one. A token is never logged, never put in an
//! error and never shown by a `Debug` impl.
//!
//! Migration from the old seal: before this module, the tokens were sealed
//! under `HARNESS_SECRET` in the `console_*_token` tables (see
//! `cloudflare/seal.rs`, legacy). [`Vault::read`] moves a legacy row into the
//! store the first time it is read with the old secret present, then deletes
//! the row. Writes only ever go to the store.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use cratefield_core::{Database, Statement};
use cratefield_kms::{Dek, Kms, KmsError, WorkerSecretKms};
use cratefield_runtime_cloudflare::D1Database;
use cratefield_secrets::{Actor, RewrapReport, SecretBytes, SecretStore, Secrets};
use worker::Env;

use crate::cloudflare::seal::{self, Sealed};

/// The secret name of the Cloudflare read-only token the fleet view reads
/// with. Names follow `cratefield-secrets`' rules: a plain path, 200 bytes
/// at most, nothing shaped like card data.
pub const CLOUDFLARE_READ: &str = "cloudflare/read-token";
/// The secret name of the optional Cloudflare deploy token rollbacks use.
pub const CLOUDFLARE_DEPLOY: &str = "cloudflare/deploy-token";
/// The secret name of the GitHub token the connection page stores.
pub const GITHUB: &str = "github/token";

/// The binding (and secret) name of the current master key version.
pub const KEK_CURRENT: &str = "HARNESS_KEK_CURRENT";
/// The highest KEK version the key ring may name. It mirrors the bound
/// `cratefield-kms` enforces, so a typo cannot fan out into thousands of
/// Secrets Store reads before the crate refuses it.
const MAX_KEK_VERSION: u32 = 1024;

/// The tenant id the console's store is stamped with. Not `global`, which
/// the crate reserves for the harness's own store.
const TENANT: &str = "console";
/// Who the audit trail names for the console's own accesses.
const ACTOR: &str = "console";
/// The D1 binding the console's database is read through.
const DB_BINDING: &str = "DB";

/// What a person is told when the master key is not configured or does not
/// load. Plain words, and the one fix: the operator sets the key.
pub const NO_MASTER_KEY_COPY: &str = "This console has no master key for its stored tokens, so \
     nothing can be read or saved. Set HARNESS_KEK_CURRENT and HARNESS_KEK_V1 in the Secrets \
     Store (see the README, Deploy), then deploy again.";

/// Why a vault operation did not happen. Carries no key or token material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The master key is not configured, or the key ring does not load.
    NoMasterKey,
    /// The database or the store refused, or the KMS could not answer. Worth
    /// trying again.
    Storage,
}

/// The legacy description for a value that never had a sealed row: the
/// GitHub App's secrets (`src/github/app.rs`). Nothing is read from D1 for
/// it, and nothing is deleted.
#[must_use]
pub const fn unsealed() -> Legacy<'static> {
    Legacy { table: "", info: b"", secret: None }
}

/// Saves `value` under `name` in the secrets store, for a caller that holds
/// the Worker `Env`.
///
/// # Errors
///
/// [`Error::NoMasterKey`] or [`Error::Storage`], as [`Vault::write`].
pub async fn put_value(env: &Env, name: &str, value: &str) -> Result<(), Error> {
    Vault::open(env).await?.write(name, value, &unsealed()).await
}

/// A token as read back: the text, and when it was saved. The `Debug` impl
/// names the fields and redacts the token.
pub struct Stored {
    token: String,
    saved_at: String,
}

impl Stored {
    /// The token's text, by value. The caller must not log it.
    #[must_use]
    pub fn into_token(self) -> String {
        self.token
    }

    /// When the token was last saved, RFC 3339 (or `""` when the store does
    /// not say, which the console never shows).
    #[must_use]
    pub fn saved_at(&self) -> &str {
        &self.saved_at
    }
}

impl std::fmt::Debug for Stored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stored")
            .field("token", &"[redacted]")
            .field("saved_at", &self.saved_at)
            .finish()
    }
}

/// Where a token sealed by the old scheme lives: its table, the HKDF info it
/// was sealed under, and the `HARNESS_SECRET` that opens it, when present.
pub struct Legacy<'a> {
    /// The D1 table holding the sealed row (`id = 1`).
    pub table: &'static str,
    /// The seal purpose, which is also the AEAD's associated data.
    pub info: &'static [u8],
    /// The old `HARNESS_SECRET`. `None` means the legacy path is closed: the
    /// deployment no longer has the secret that would open the row.
    pub secret: Option<&'a str>,
}

/// The console's secrets over one database. Built by [`Vault::open`] on the
/// Worker, or by [`Vault::new`] with any [`Kms`] and [`Database`] (the tests).
pub struct Vault {
    store: SecretStore,
    db: Arc<dyn Database>,
}

impl Vault {
    /// A vault over `kms` and `db`. Construction touches neither: a KMS that
    /// refuses every call still builds one, which [`forget`] relies on.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] only if the console's store identity is refused,
    /// which a constant tenant id never is.
    pub fn new(kms: Arc<dyn Kms>, db: Arc<dyn Database>) -> Result<Self, Error> {
        let store =
            Secrets::new(kms).tenant(TENANT, Arc::clone(&db)).map_err(|_| Error::Storage)?;
        Ok(Self { store, db })
    }

    /// The vault the Worker serves with: the master key from the Secrets
    /// Store (or a plain Worker secret), and the `DB` database.
    ///
    /// # Errors
    ///
    /// [`Error::NoMasterKey`] when no usable master key is configured;
    /// [`Error::Storage`] when the database binding is missing.
    pub async fn open(env: &Env) -> Result<Self, Error> {
        let kms = master_key(env).await?;
        Self::new(kms, d1(env)?)
    }

    /// Reads `name` from the store. When the store holds nothing and the legacy
    /// row opens under the old secret, the row is moved into the store (and
    /// deleted from D1) and returned. `Ok(None)` means not connected: nothing
    /// is stored, or there is nothing to move.
    ///
    /// Any other failure (the store unwell, a KEK version missing from the
    /// ring, a row that does not authenticate) is an error, logged by name
    /// only. It is never reported as "not connected": that is a different
    /// fact, and the person is told to try again or to fix the key.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when the store cannot answer or unwrap.
    pub async fn read(&self, name: &str, legacy: &Legacy<'_>) -> Result<Option<Stored>, Error> {
        let actor = actor()?;
        match self.store.get(name, &actor).await {
            Ok(Some(value)) => {
                let token = value.expose_str().map_err(|_| Error::Storage)?.to_owned();
                let saved_at = self.saved_at(name, &actor).await?;
                Ok(Some(Stored { token, saved_at }))
            }
            Ok(None) => self.move_legacy(name, legacy, &actor).await,
            Err(error) => {
                tracing::error!(name, ?error, "console: reading a stored token failed");
                Err(Error::Storage)
            }
        }
    }

    /// Saves `token` as the new value of `name`, and drops any legacy row for
    /// it: the store's value now supersedes the old seal.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when the store refuses the write.
    pub async fn write(&self, name: &str, token: &str, legacy: &Legacy<'_>) -> Result<(), Error> {
        let actor = actor()?;
        self.store.put(name, &SecretBytes::from(token), &actor).await.map_err(|error| {
            tracing::warn!(name, ?error, "console: saving a token failed");
            Error::Storage
        })?;
        // The store holds the new value, so the old row is not read while it
        // does. A failed delete is logged, not returned: the save succeeded.
        if let Err(error) = drop_legacy(self.db.as_ref(), legacy.table).await {
            tracing::warn!(
                table = legacy.table,
                ?error,
                "console: a superseded legacy row could not be deleted"
            );
        }
        Ok(())
    }

    /// Re-wraps every stored data key under the master key's current version.
    /// Nothing is re-encrypted: the tokens keep their ciphertext, and only the
    /// keys that wrap the data keys change.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when a key cannot be unwrapped or re-wrapped.
    pub async fn rewrap(&self) -> Result<RewrapReport, Error> {
        let actor = actor()?;
        self.store.rewrap(&actor, false).await.map_err(|error| {
            tracing::error!(?error, "console: re-wrapping the stored keys failed");
            Error::Storage
        })
    }

    /// The save time of `name`'s latest version, from the store's listing.
    async fn saved_at(&self, name: &str, actor: &Actor) -> Result<String, Error> {
        let listed = self.store.list(actor).await.map_err(|_| Error::Storage)?;
        Ok(listed
            .into_iter()
            .find(|meta| meta.name == name && !meta.deleted)
            .map(|meta| meta.created_at)
            .unwrap_or_default())
    }

    /// The lazy move from the old seal. Runs only when the store is empty for
    /// `name`: the legacy row must open under the old secret, then the value
    /// goes into the store, and only then is the row deleted. Each step is
    /// idempotent, so an interrupted move simply runs again.
    async fn move_legacy(
        &self,
        name: &str,
        legacy: &Legacy<'_>,
        actor: &Actor,
    ) -> Result<Option<Stored>, Error> {
        let Some(stored) = open_legacy(self.db.as_ref(), legacy).await? else {
            return Ok(None);
        };
        if let Err(error) =
            self.store.put(name, &SecretBytes::from(stored.token.as_str()), actor).await
        {
            // A concurrent request may have moved the same row first. If the
            // store now holds a value, that value is the one to return.
            tracing::warn!(
                name,
                ?error,
                "console: moving a legacy token: the store refused, reading back"
            );
            return match self.store.get(name, actor).await {
                Ok(Some(value)) => {
                    let token = value.expose_str().map_err(|_| Error::Storage)?.to_owned();
                    let saved_at = self.saved_at(name, actor).await?;
                    if let Err(error) = drop_legacy(self.db.as_ref(), legacy.table).await {
                        tracing::warn!(
                            table = legacy.table,
                            ?error,
                            "console: a superseded legacy row could not be deleted"
                        );
                    }
                    Ok(Some(Stored { token, saved_at }))
                }
                _ => Err(Error::Storage),
            };
        }
        if let Err(error) = drop_legacy(self.db.as_ref(), legacy.table).await {
            tracing::warn!(
                table = legacy.table,
                ?error,
                "console: the moved legacy row could not be deleted; the store's value is used from now on"
            );
        }
        tracing::info!(table = legacy.table, name, "console: moved a sealed token into the store");
        Ok(Some(stored))
    }
}

/// The token `name` reads as, on the request path. With a master key this is
/// [`Vault::read`]. Without one, and only while the old `HARNESS_SECRET` is
/// still set, the legacy row is read in place, so live tokens keep working
/// until the key exists. That path moves and deletes nothing, and a write
/// still needs the key.
///
/// # Errors
///
/// [`Error::NoMasterKey`] when there is no key and no legacy row to read;
/// [`Error::Storage`] as [`Vault::read`].
pub async fn read(env: &Env, name: &str, legacy: &Legacy<'_>) -> Result<Option<Stored>, Error> {
    match Vault::open(env).await {
        Ok(vault) => vault.read(name, legacy).await,
        Err(Error::NoMasterKey) if legacy.secret.is_some() => {
            let db = d1(env)?;
            open_legacy(db.as_ref(), legacy).await?.ok_or(Error::NoMasterKey).map(Some)
        }
        Err(error) => Err(error),
    }
}

/// Re-wraps the console's data keys under the current master key version.
///
/// # Errors
///
/// [`Error::NoMasterKey`] when no key loads; [`Error::Storage`] otherwise.
pub async fn rewrap(env: &Env) -> Result<RewrapReport, Error> {
    Vault::open(env).await?.rewrap().await
}

/// Loads the master key for this isolate ahead of a caller that holds no `Env`
/// (the edits module's delivery, which runs inside the harness). Failure is
/// harmless: [`read_cached`] then falls back to the legacy row.
pub async fn prime(env: &Env) {
    let _ = master_key(env).await;
}

/// Reads `name` for a caller that holds the database but not the Worker `Env`.
/// With the master key loaded for this isolate this is [`Vault::read`]. Without
/// one, the legacy row is read in place, read-only, so tokens keep working
/// until the key exists; nothing is moved or deleted on that path.
///
/// # Errors
///
/// [`Error::Storage`] when the store or the database cannot answer.
pub async fn read_cached(
    db: Arc<dyn Database>,
    name: &str,
    legacy: &Legacy<'_>,
) -> Result<Option<Stored>, Error> {
    match MASTER_KEY.get() {
        Some(kms) => Vault::new(Arc::clone(kms), db)?.read(name, legacy).await,
        None => open_legacy(db.as_ref(), legacy).await,
    }
}

/// The master key version the console wraps with, as a number, when a key
/// loads. `None` when there is no master key yet.
pub async fn current_key_version(env: &Env) -> Option<u32> {
    let kms = master_key(env).await.ok()?;
    key_version_of(kms.key_ref())
}

/// The version a master key reference names: `worker-secret:HARNESS_KEK_V2`
/// names 2. Anything else is `None`.
#[must_use]
pub fn key_version_of(key_ref: &str) -> Option<u32> {
    key_ref.strip_prefix("worker-secret:HARNESS_KEK_V")?.parse().ok()
}

/// Forgets `name` and any legacy row for it. Soft-deletes in the store, as
/// the crate does (the ciphertext stays, unreadable), and needs no key: the
/// store is opened with a KMS that refuses every call, and `delete` makes
/// none.
///
/// # Errors
///
/// [`Error::Storage`] when the database refuses.
pub async fn forget(env: &Env, name: &str, legacy: &Legacy<'_>) -> Result<(), Error> {
    let vault = Vault::new(Arc::new(NoKeyRing), d1(env)?)?;
    let actor = actor()?;
    vault.store.delete(name, &actor).await.map_err(|error| {
        tracing::warn!(name, ?error, "console: forgetting a stored token failed");
        Error::Storage
    })?;
    drop_legacy(vault.db.as_ref(), legacy.table).await
}

/// The master key once this isolate has loaded it. Set by [`master_key`], read
/// by [`read_cached`] from callers that hold no `Env`.
static MASTER_KEY: OnceLock<Arc<dyn Kms>> = OnceLock::new();

/// The master key for this isolate: built once from the key ring on first
/// use, then reused. Nothing is built or cached while any lookup errors, so
/// the next request tries again, and a key added later works without a
/// redeploy.
async fn master_key(env: &Env) -> Result<Arc<dyn Kms>, Error> {
    if let Some(kms) = MASTER_KEY.get() {
        return Ok(Arc::clone(kms));
    }
    let ring = load_key_ring(env).await?;
    let kms: Arc<dyn Kms> = Arc::new(master_key_from_lookup(|name| ring.get(name).cloned())?);
    Ok(Arc::clone(MASTER_KEY.get_or_init(|| kms)))
}

/// The master key from a lookup, the pure half of [`master_key`]. Every
/// malformation is refused here, by `cratefield-kms`, with the secret's name
/// and the fix, never the value.
///
/// # Errors
///
/// [`Error::NoMasterKey`] for every reason the key ring is unusable.
pub fn master_key_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<WorkerSecretKms, Error> {
    WorkerSecretKms::from_lookup(lookup).map_err(|error| {
        tracing::warn!(%error, "console: the master key is not usable");
        Error::NoMasterKey
    })
}

/// Where the key ring's values come from. One source per deployment, chosen
/// by the bindings wrangler.toml declares. If any `HARNESS_KEK_*` Secrets Store
/// binding exists, every version is read from the store, and a value the store
/// does not hold is absent. Only a deployment with no such binding reads plain
/// Worker secrets. Mixing the two could leave one version stale in one place
/// and current in the other, so it is refused by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeySource {
    SecretsStore,
    WorkerSecrets,
}

impl KeySource {
    /// The source, from the declared bindings. Reads no value, so it is cheap
    /// and cannot fail.
    fn detect(env: &Env) -> Self {
        let declared = std::iter::once(KEK_CURRENT.to_owned())
            .chain((1..=MAX_KEK_VERSION).map(|version| format!("HARNESS_KEK_V{version}")))
            .any(|name| env.secret_store(&name).is_ok());
        if declared { Self::SecretsStore } else { Self::WorkerSecrets }
    }

    /// One named value from this source, trimmed, blank counting as absent.
    /// A failed Secrets Store read is an error, never a silent absence.
    /// Values are never logged.
    async fn get(self, env: &Env, name: &str) -> Result<Option<String>, Error> {
        let raw = match self {
            Self::SecretsStore => match env.secret_store(name) {
                Ok(store) => store.get().await.map_err(|error| {
                    tracing::error!(name, %error, "console: reading a master key version from the Secrets Store failed");
                    Error::Storage
                })?,
                // A version this deployment does not declare.
                Err(_) => None,
            },
            Self::WorkerSecrets => env.secret(name).ok().map(|secret| secret.to_string()),
        };
        Ok(raw.map(|value| value.trim().to_owned()).filter(|value| !value.is_empty()))
    }
}

/// The key ring the lookup reads: `HARNESS_KEK_CURRENT`, then each version from
/// 1 through the current one, so a rotation keeps the old versions readable. A
/// version that is absent is left out, and `cratefield-kms` decides whether
/// that matters. An error from the source stops the load.
async fn load_key_ring(env: &Env) -> Result<HashMap<String, String>, Error> {
    let source = KeySource::detect(env);
    let mut ring = HashMap::new();
    let Some(current) = source.get(env, KEK_CURRENT).await? else {
        return Ok(ring);
    };
    let count = current.parse::<u32>().ok().filter(|count| (1..=MAX_KEK_VERSION).contains(count));
    ring.insert(KEK_CURRENT.to_owned(), current);
    for version in 1..=count.unwrap_or(0) {
        let name = format!("HARNESS_KEK_V{version}");
        if let Some(material) = source.get(env, &name).await? {
            ring.insert(name, material);
        }
    }
    Ok(ring)
}

/// The console's database, as the port the modules use. Shared by the GitHub
/// App (`src/github/app.rs`) and the edits module, which hold no `Env`.
pub(crate) fn d1(env: &Env) -> Result<Arc<dyn Database>, Error> {
    let database = env.d1(DB_BINDING).map_err(|_| Error::Storage)?;
    Ok(Arc::new(D1Database(database)))
}

fn actor() -> Result<Actor, Error> {
    Actor::new(ACTOR).map_err(|_| Error::Storage)
}

/// The legacy row opened under the old secret. Read-only: nothing is moved or
/// deleted. `Ok(None)` when there is no row, no secret, or the row does not open
/// under it (logged by table name).
async fn open_legacy(db: &dyn Database, legacy: &Legacy<'_>) -> Result<Option<Stored>, Error> {
    let Some(secret) = legacy.secret else {
        return Ok(None);
    };
    let Some(row) = legacy_row(db, legacy.table).await? else {
        return Ok(None);
    };
    let sealed = Sealed { nonce: row.nonce, ciphertext: row.ciphertext };
    match seal::open_for(legacy.info, secret, &sealed) {
        Ok(token) => Ok(Some(Stored { token, saved_at: row.updated_at })),
        Err(error) => {
            tracing::warn!(
                table = legacy.table,
                ?error,
                "console: legacy sealed token does not open with HARNESS_SECRET; left in place"
            );
            Ok(None)
        }
    }
}

/// The legacy row's three columns, as D1 returns them.
struct LegacyRow {
    nonce: String,
    ciphertext: String,
    updated_at: String,
}

async fn legacy_row(db: &dyn Database, table: &str) -> Result<Option<LegacyRow>, Error> {
    let rows = db
        .query(&Statement::new(format!(
            "SELECT nonce, ciphertext, updated_at FROM {table} WHERE id = 1"
        )))
        .await
        .map_err(|_| Error::Storage)?;
    Ok(rows.rows.first().and_then(|row| {
        Some(LegacyRow {
            nonce: row.get("nonce")?,
            ciphertext: row.get("ciphertext")?,
            updated_at: row.get("updated_at")?,
        })
    }))
}

fn delete_legacy(table: &str) -> Statement {
    Statement::new(format!("DELETE FROM {table} WHERE id = 1"))
}

/// Deletes a legacy row. A `table` of `""` means the value has no legacy
/// row at all (see [`unsealed`]), so there is nothing to delete.
async fn drop_legacy(db: &dyn Database, table: &str) -> Result<(), Error> {
    if table.is_empty() {
        return Ok(());
    }
    execute(db, &delete_legacy(table)).await
}

async fn execute(db: &dyn Database, statement: &Statement) -> Result<(), Error> {
    db.execute(statement).await.map(|_| ()).map_err(|_| Error::Storage)
}

/// A KMS that answers nothing. [`forget`] opens the store with it, so a
/// disconnect works even after the master key has been removed.
struct NoKeyRing;

#[async_trait::async_trait]
impl Kms for NoKeyRing {
    fn provider(&self) -> &'static str {
        "none"
    }

    fn key_ref(&self) -> &str {
        "none"
    }

    async fn wrap(&self, _dek: &Dek) -> Result<Vec<u8>, KmsError> {
        Err(KmsError::Refused("no master key is loaded for this operation".to_owned()))
    }

    async fn unwrap(&self, _wrapped: &[u8]) -> Result<Dek, KmsError> {
        Err(KmsError::Refused("no master key is loaded for this operation".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare::seal::{GITHUB_INFO, INFO};
    use cratefield_adapter_sqlite::SqliteDatabase;
    use cratefield_core::SqlMigration;

    const TOKEN: &str = "cf-read-AbC_123-example";
    const SECRET: &str = "legacy-harness-secret-0123456789";
    /// Standard base64 of 32 bytes: a KEK version's material.
    const KEK_V1: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const KEK_V2: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    /// The console's legacy tables, from the migrations that created them.
    const LEGACY_READ: &str = "console_cloudflare_token";
    const LEGACY_DEPLOY: &str = "console_cloudflare_deploy_token";
    const LEGACY_GITHUB: &str = "console_github_token";

    fn ring(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
    }

    fn kms_over(ring: &HashMap<String, String>) -> Arc<dyn Kms> {
        Arc::new(master_key_from_lookup(|name| ring.get(name).cloned()).expect("a usable ring"))
    }

    fn v1_ring() -> HashMap<String, String> {
        ring(&[(KEK_CURRENT, "1"), ("HARNESS_KEK_V1", KEK_V1)])
    }

    /// A migrated SQLite database with the store's tables and the three legacy
    /// tables, all created by the venture's own migration files.
    fn database() -> Arc<SqliteDatabase> {
        let db = SqliteDatabase::in_memory().expect("in-memory sqlite");
        db.apply_migrations(
            "console-secrets",
            &[SqlMigration::new(
                "0014",
                "console_secrets",
                include_str!("../migrations/0014_console_secrets.sql"),
            )],
        )
        .expect("the store's schema applies");
        db.apply_migrations(
            "console-legacy",
            &[
                SqlMigration::new(
                    "0009",
                    "console_cloudflare_token",
                    include_str!("../migrations/0009_console_cloudflare_token.sql"),
                ),
                SqlMigration::new(
                    "0010",
                    "console_cloudflare_deploy_token",
                    include_str!("../migrations/0010_console_cloudflare_deploy_token.sql"),
                ),
                SqlMigration::new(
                    "0011",
                    "console_github_token",
                    include_str!("../migrations/0011_console_github_token.sql"),
                ),
            ],
        )
        .expect("the legacy tables apply");
        Arc::new(db)
    }

    fn vault(ring: &HashMap<String, String>, db: &Arc<SqliteDatabase>) -> Vault {
        Vault::new(kms_over(ring), Arc::clone(db) as Arc<dyn Database>).expect("a vault")
    }

    fn legacy<'a>(table: &'static str, info: &'static [u8], secret: Option<&'a str>) -> Legacy<'a> {
        Legacy { table, info, secret }
    }

    /// Writes a legacy row exactly as the old code did: sealed under the old
    /// secret, with the same nonce and ciphertext columns.
    fn insert_legacy(db: &SqliteDatabase, table: &str, info: &[u8], token: &str, when: &str) {
        let sealed = seal::seal_for(info, SECRET, token).expect("seal");
        let sql = format!(
            "INSERT INTO {table} (id, nonce, ciphertext, updated_at) \
             VALUES (1, '{}', '{}', '{when}')",
            sealed.nonce, sealed.ciphertext
        );
        futures_block(db.execute(&Statement::new(sql))).expect("the legacy row inserts");
    }

    fn legacy_rows(db: &SqliteDatabase, table: &str) -> usize {
        futures_block(db.query(&Statement::new(format!("SELECT id FROM {table}"))))
            .expect("query")
            .rows
            .len()
    }

    /// Runs a future to completion on the test thread; the sqlite adapter is
    /// synchronous underneath.
    fn futures_block<T>(future: impl std::future::Future<Output = T>) -> T {
        pollster::block_on(future)
    }

    #[test]
    fn no_master_key_is_a_plain_refusal_not_a_panic() {
        let absent = master_key_from_lookup(|_| None);
        assert!(matches!(absent, Err(Error::NoMasterKey)));
        let blank = master_key_from_lookup(|name| (name == KEK_CURRENT).then(String::new));
        assert!(matches!(blank, Err(Error::NoMasterKey)));
        let wrong_size = master_key_from_lookup(|name| match name {
            KEK_CURRENT => Some("1".to_owned()),
            _ => Some("AAAA".to_owned()),
        });
        assert!(matches!(wrong_size, Err(Error::NoMasterKey)));
    }

    #[test]
    fn a_ring_with_the_current_version_builds_a_worker_secret_kms() {
        let kms = master_key_from_lookup(|name| match name {
            KEK_CURRENT => Some("1".to_owned()),
            "HARNESS_KEK_V1" => Some(KEK_V1.to_owned()),
            _ => None,
        })
        .expect("a usable ring");
        assert_eq!(kms.provider(), "worker-secret");
        assert_eq!(kms.key_ref(), "worker-secret:HARNESS_KEK_V1");
        let shown = format!("{kms:?}");
        assert!(!shown.contains(KEK_V1), "the KEK never prints: {shown}");
    }

    #[test]
    fn the_three_names_round_trip_through_the_store() {
        let db = database();
        let ring = v1_ring();
        let vault = vault(&ring, &db);
        let none = legacy(LEGACY_READ, INFO, None);
        futures_block(async {
            for name in [CLOUDFLARE_READ, CLOUDFLARE_DEPLOY, GITHUB] {
                assert!(vault.read(name, &none).await.expect("read").is_none());
                vault.write(name, TOKEN, &none).await.expect("write");
                let stored = vault.read(name, &none).await.expect("read").expect("stored");
                assert!(!stored.saved_at().is_empty(), "the save time comes from the store");
                let shown = format!("{stored:?}");
                assert!(!shown.contains(TOKEN), "a Debug impl never shows the token: {shown}");
                assert_eq!(stored.into_token(), TOKEN);
            }
        });
    }

    #[test]
    fn the_token_text_is_not_in_the_database() {
        let db = database();
        let ring = v1_ring();
        let vault = vault(&ring, &db);
        let none = legacy(LEGACY_READ, INFO, None);
        futures_block(vault.write(CLOUDFLARE_READ, TOKEN, &none)).expect("write");
        let rows = futures_block(
            db.query(&Statement::new("SELECT ciphertext FROM harness_secrets".to_owned())),
        )
        .expect("query");
        let stored = rows.rows.first().and_then(|row| row.get::<Vec<u8>>("ciphertext"));
        let bytes = stored.expect("a ciphertext row");
        assert!(
            !bytes.windows(TOKEN.len()).any(|window| window == TOKEN.as_bytes()),
            "the token must not appear in the stored bytes"
        );
    }

    #[test]
    fn a_legacy_row_moves_into_the_store_and_is_deleted() {
        let db = database();
        let ring = v1_ring();
        let vault = vault(&ring, &db);
        insert_legacy(&db, LEGACY_READ, INFO, TOKEN, "2026-09-01T10:00:00Z");
        let old = legacy(LEGACY_READ, INFO, Some(SECRET));
        let moved = futures_block(vault.read(CLOUDFLARE_READ, &old))
            .expect("read")
            .expect("the legacy row opens under HARNESS_SECRET");
        assert_eq!(moved.saved_at(), "2026-09-01T10:00:00Z", "the legacy save time is kept");
        assert_eq!(moved.into_token(), TOKEN);
        assert_eq!(legacy_rows(&db, LEGACY_READ), 0, "the old row is gone");
        // Now it is the store's value: a read with no old secret still works.
        let again = futures_block(vault.read(CLOUDFLARE_READ, &legacy(LEGACY_READ, INFO, None)))
            .expect("read")
            .expect("stored");
        assert_eq!(again.into_token(), TOKEN);
    }

    #[test]
    fn a_legacy_row_that_does_not_open_is_left_alone() {
        let db = database();
        let ring = v1_ring();
        let vault = vault(&ring, &db);
        insert_legacy(&db, LEGACY_DEPLOY, seal::DEPLOY_INFO, TOKEN, "2026-09-01T10:00:00Z");
        let wrong = legacy(LEGACY_DEPLOY, seal::DEPLOY_INFO, Some("another-secret"));
        let read = futures_block(vault.read(CLOUDFLARE_DEPLOY, &wrong)).expect("read");
        assert!(read.is_none(), "a row that does not open reads as not connected");
        assert_eq!(legacy_rows(&db, LEGACY_DEPLOY), 1, "and is not deleted");
    }

    #[test]
    fn a_legacy_row_is_never_opened_under_another_purpose() {
        let db = database();
        let ring = v1_ring();
        let vault = vault(&ring, &db);
        insert_legacy(&db, LEGACY_GITHUB, GITHUB_INFO, TOKEN, "2026-09-01T10:00:00Z");
        let wrong_purpose = legacy(LEGACY_GITHUB, INFO, Some(SECRET));
        assert!(futures_block(vault.read(GITHUB, &wrong_purpose)).expect("read").is_none());
        assert_eq!(legacy_rows(&db, LEGACY_GITHUB), 1);
    }

    #[test]
    fn forgetting_clears_the_store_and_the_legacy_row_without_a_key() {
        let db = database();
        let ring = v1_ring();
        let vault = vault(&ring, &db);
        let none = legacy(LEGACY_READ, INFO, None);
        futures_block(vault.write(CLOUDFLARE_READ, TOKEN, &none)).expect("write");
        insert_legacy(&db, LEGACY_READ, INFO, TOKEN, "2026-09-01T10:00:00Z");
        // The removed master key: a forget with no ring at all still works.
        let forgetter =
            Vault::new(Arc::new(NoKeyRing), Arc::clone(&db) as Arc<dyn Database>).expect("a vault");
        futures_block(async {
            forgetter.store.delete(CLOUDFLARE_READ, &actor().expect("actor")).await
        })
        .expect("delete");
        futures_block(execute(db.as_ref(), &delete_legacy(LEGACY_READ))).expect("legacy");
        assert!(futures_block(vault.read(CLOUDFLARE_READ, &none)).expect("read").is_none());
        assert_eq!(legacy_rows(&db, LEGACY_READ), 0);
    }

    #[test]
    fn a_rewrap_moves_the_store_to_a_new_kek_and_the_old_version_can_go() {
        let db = database();
        let first = v1_ring();
        let none = legacy(LEGACY_READ, INFO, None);
        futures_block(vault(&first, &db).write(CLOUDFLARE_READ, TOKEN, &none)).expect("write");

        // Rotation: V2 becomes current, V1 is still held so the old blob opens.
        let second =
            ring(&[(KEK_CURRENT, "2"), ("HARNESS_KEK_V1", KEK_V1), ("HARNESS_KEK_V2", KEK_V2)]);
        let rotated = Secrets::new(kms_over(&second))
            .tenant(TENANT, Arc::clone(&db) as Arc<dyn Database>)
            .expect("a store");
        futures_block(rotated.rewrap(&actor().expect("actor"), false)).expect("rewrap");
        let read_after = futures_block(vault(&second, &db).read(CLOUDFLARE_READ, &none))
            .expect("read")
            .expect("still readable after the rewrap");
        assert_eq!(read_after.into_token(), TOKEN);

        // The runbook's last step: V1 deleted once nothing is wrapped under it.
        let only_v2 = ring(&[(KEK_CURRENT, "2"), ("HARNESS_KEK_V2", KEK_V2)]);
        let read_v2 = futures_block(vault(&only_v2, &db).read(CLOUDFLARE_READ, &none))
            .expect("read")
            .expect("readable under V2 alone");
        assert_eq!(read_v2.into_token(), TOKEN);
    }

    #[test]
    fn the_legacy_row_opens_read_only_while_no_key_exists() {
        let db = database();
        insert_legacy(&db, LEGACY_READ, INFO, TOKEN, "2026-09-01T10:00:00Z");
        let old = legacy(LEGACY_READ, INFO, Some(SECRET));
        let read = futures_block(open_legacy(db.as_ref(), &old))
            .expect("read")
            .expect("the row opens under HARNESS_SECRET");
        assert_eq!(read.saved_at(), "2026-09-01T10:00:00Z");
        assert_eq!(read.into_token(), TOKEN);
        assert_eq!(legacy_rows(&db, LEGACY_READ), 1, "nothing is deleted on the read-only path");
        let ring = v1_ring();
        let store = vault(&ring, &db);
        let none = legacy(LEGACY_READ, INFO, None);
        assert!(
            futures_block(store.read(CLOUDFLARE_READ, &none)).expect("read").is_none(),
            "nothing was moved into the store"
        );
    }

    #[test]
    fn a_key_that_cannot_unwrap_is_an_error_not_an_absent_token() {
        let db = database();
        let first = v1_ring();
        let none = legacy(LEGACY_READ, INFO, None);
        futures_block(vault(&first, &db).write(CLOUDFLARE_READ, TOKEN, &none)).expect("write");
        // Version 1 removed too early: the stored data key cannot be unwrapped.
        let only_v2 = ring(&[(KEK_CURRENT, "2"), ("HARNESS_KEK_V2", KEK_V2)]);
        let result = futures_block(vault(&only_v2, &db).read(CLOUDFLARE_READ, &none));
        assert!(
            matches!(result, Err(Error::Storage)),
            "an unwrap failure must surface as an error, not as not connected"
        );
    }

    #[test]
    fn rewrap_reports_the_keys_it_moved_onto_the_current_version() {
        let db = database();
        let first = v1_ring();
        let none = legacy(LEGACY_READ, INFO, None);
        futures_block(vault(&first, &db).write(CLOUDFLARE_READ, TOKEN, &none)).expect("write");
        let second =
            ring(&[(KEK_CURRENT, "2"), ("HARNESS_KEK_V1", KEK_V1), ("HARNESS_KEK_V2", KEK_V2)]);
        let report = futures_block(vault(&second, &db).rewrap()).expect("rewrap");
        assert_eq!(report.keys, 1);
        assert_eq!(key_version_of(&report.key_ref), Some(2));
        let after = futures_block(vault(&second, &db).read(CLOUDFLARE_READ, &none))
            .expect("read")
            .expect("stored");
        assert_eq!(after.into_token(), TOKEN, "the token itself is unchanged");
    }

    #[test]
    fn a_key_reference_names_its_version_and_nothing_else() {
        assert_eq!(key_version_of("worker-secret:HARNESS_KEK_V2"), Some(2));
        assert_eq!(key_version_of("worker-secret:HARNESS_KEK_V10"), Some(10));
        assert_eq!(key_version_of("worker-secret:HARNESS_KEK_Vx"), None);
        assert_eq!(key_version_of("none"), None);
    }

    #[test]
    fn the_schema_is_the_crate_s_verbatim() {
        // Every SQLite migration cratefield-secrets 0.4.0 ships must appear
        // byte for byte in the venture's 0014 file. A drift fails here.
        let copy = include_str!("../migrations/0014_console_secrets.sql");
        for migration in cratefield_secrets::SQLITE_MIGRATIONS {
            assert!(
                copy.contains(migration.sql),
                "0014_console_secrets.sql is missing the crate's {} verbatim",
                migration.id
            );
        }
    }
}
