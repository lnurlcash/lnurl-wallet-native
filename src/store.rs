//! The wallet file: everything the wallet holds, encrypted at rest.
//!
//! One JSON envelope on disk - argon2id parameters, a salt, a nonce and an
//! XChaCha20-Poly1305 ciphertext. The key is stretched from the password once
//! at unlock and kept in memory (zeroized on drop); every save re-encrypts the
//! whole [`WalletData`] under a fresh nonce and replaces the file atomically,
//! so a crash mid-write leaves the previous version intact rather than a torn
//! one. Plaintext note secrets never touch disk.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const FORMAT: &str = "lnurl-wallet-native/1";
pub const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    /// Ours, spendable, as far as the last contact with the mint knows.
    Live,
    /// A melt was accepted: the payment is IN FLIGHT. Not spent until the
    /// mint says so - a failed payment makes the note spendable again.
    Melting,
    /// A rotate's answer was lost. The fresh secret for it is in the secrets
    /// log; [`crate::wallet::Wallet::resolve`] works out which one is the note.
    Uncertain,
    /// Handed to someone else. Kept, not deleted: a check tells whether they
    /// have claimed it yet, and until then the secret is still money.
    Sent,
    /// The mint reports it burned.
    Spent,
}

impl NoteStatus {
    pub fn label(self) -> &'static str {
        match self {
            NoteStatus::Live => "live",
            NoteStatus::Melting => "melting",
            NoteStatus::Uncertain => "uncertain",
            NoteStatus::Sent => "sent",
            NoteStatus::Spent => "spent",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    /// The full note URL, k1 included. This IS the bearer secret.
    pub url: String,
    /// Authoritative when `verified`: `maxWithdrawable` from the mint, or a
    /// signature that checked out against the pinned key.
    pub amount_msat: u64,
    pub verified: bool,
    pub status: NoteStatus,
    pub added_at: u64,
    pub updated_at: u64,
    /// The last thing worth telling the holder about this note.
    #[serde(default)]
    pub detail: Option<String>,
}

impl Note {
    pub fn k1(&self) -> String {
        lnurlcash_core::note_k1(&self.url).unwrap_or_default()
    }

    /// What the mint files the note under - never the secret itself - and so
    /// the stable handle the UI and the secrets log refer to it by.
    pub fn id(&self) -> String {
        crate::lud25::note_id_of_url(&self.url).unwrap_or_default()
    }

    pub fn mint(&self) -> String {
        lnurlcash_core::server_of(&self.url)
    }

    /// scheme://host[:port], what trust and key pins are keyed by.
    pub fn origin(&self) -> String {
        crate::wallet::origin_of(&self.url)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretState {
    /// Disclosed (or about to be) and not yet known to be a note or not.
    Pending,
    /// Became a note the wallet now holds.
    Adopted,
    /// The mutation definitively did not happen. Kept anyway: never delete a
    /// secret whose hash has been on the wire.
    Discarded,
}

/// A rotate record from before the mutation journal. Kept only so an
/// existing wallet file never loses one on its next save.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    /// The new note's spend: a seed-derived `ck1`, or a pre-seed hex secret.
    pub secret: String,
    /// What was disclosed for it: `cp1<Q>`, or empty for a hex secret whose
    /// output was its hash.
    #[serde(default)]
    pub output: String,
    pub op: String,
    /// The id of the note it replaces.
    pub origin_id: String,
    pub origin_url: String,
    pub expected_amount_msat: u64,
    pub state: SecretState,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    /// Written, and maybe sent. Its inputs are uncertain until resolved.
    Pending,
    Done,
    /// The mint definitively refused: nothing changed.
    Failed,
}

/// A note a mutation burns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalInput {
    pub id: String,
    pub url: String,
    pub amount_msat: u64,
}

/// A note a mutation mints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalOutput {
    /// `cp1<Q>`, as sent in `p1`/`p2`.
    pub output: String,
    /// Our spend for it, or `None` when it is someone else's (a transfer).
    pub k1: Option<String>,
    pub expected_msat: u64,
    /// Who it went to, for a transfer.
    #[serde(default)]
    pub recipient: Option<String>,
}

/// A rotate, merge, split or transfer, written to disk before its request
/// is even built: if the answer is lost, this is how the wallet finds out
/// what happened and where its money is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mutation {
    pub id: String,
    pub op: String,
    pub withdraw_link: String,
    pub inputs: Vec<JournalInput>,
    pub outputs: Vec<JournalOutput>,
    /// A split's `amount`; `None` for a rotate or merge.
    pub split_msat: Option<u64>,
    pub state: JournalState,
    pub created_at: u64,
}

/// A Lightning Address registered at a mint against this seed's branch:
/// payments to it mint purpose-2 notes the wallet then finds by scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    pub username: String,
    pub origin: String,
    pub registered_at: u64,
}

/// A mint the holder chose to deal with. Trust gates receiving and minting,
/// and says where a seed restore looks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintEntry {
    /// scheme://host[:port] of its withdraw endpoint - what notes point at.
    pub origin: String,
    /// The Lightning Address it mints at (`mint@host`), if known.
    pub address: Option<String>,
    /// Its LUD-17 withdraw link, the base every note there hangs off.
    pub withdraw_link: String,
    pub trusted_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MintState {
    /// Invoice issued; waiting for it to be paid and the note credited.
    Waiting,
    Credited,
    /// Hidden by the holder. The key is seed-derived, so a restore still
    /// finds the note if the invoice was paid after all.
    Dismissed,
}

/// A mint in progress: the key is derived and saved before the invoice is
/// even requested, so paying it can never create a note nobody can spend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMint {
    /// `cp1<Q>`, sent as the invoice comment.
    pub output: String,
    /// The `ck1` spend that will be the note.
    pub k1: String,
    pub address: String,
    pub withdraw_link: String,
    pub pr: Option<String>,
    pub paid_msat: u64,
    /// What the note should hold after the mint's advertised fee.
    pub expected_msat: u64,
    pub state: MintState,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activity {
    pub at: u64,
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WalletData {
    pub notes: Vec<Note>,
    pub secrets: Vec<SecretRecord>,
    /// Mint origin (scheme://host[:port]) -> the `mintPubkey` first seen
    /// there. A change is refused, never silently trusted.
    pub mint_keys: BTreeMap<String, String>,
    pub activity: Vec<Activity>,
    /// The BIP39 words every note key derives from. Encrypted with the rest.
    #[serde(default)]
    pub seed_phrase: Option<String>,
    /// Mint domain -> next unused index per purpose (wallet, change,
    /// address). Half the backup: a restore can only see as far as its gap
    /// limit past the last live note.
    #[serde(default)]
    pub counters: BTreeMap<String, [u32; 3]>,
    #[serde(default)]
    pub mints: Vec<MintEntry>,
    #[serde(default)]
    pub pending_mints: Vec<PendingMint>,
    #[serde(default)]
    pub journal: Vec<Mutation>,
    #[serde(default)]
    pub addresses: Vec<Address>,
}

impl WalletData {
    pub fn note(&self, id: &str) -> Option<&Note> {
        self.notes.iter().find(|n| n.id() == id)
    }

    pub fn note_mut(&mut self, id: &str) -> Option<&mut Note> {
        self.notes.iter_mut().find(|n| n.id() == id)
    }

    pub fn mint(&self, origin: &str) -> Option<&MintEntry> {
        self.mints.iter().find(|m| m.origin == origin)
    }

    pub fn log(&mut self, text: impl Into<String>) {
        self.activity.push(Activity {
            at: now(),
            text: text.into(),
        });
    }

    /// Live notes at one mint, largest first.
    pub fn live_at(&self, origin: &str) -> Vec<&Note> {
        let mut notes: Vec<&Note> = self
            .notes
            .iter()
            .filter(|n| n.status == NoteStatus::Live && n.origin() == origin)
            .collect();
        notes.sort_by_key(|n| std::cmp::Reverse(n.amount_msat));
        notes
    }

    pub fn live_balance_msat(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| n.status == NoteStatus::Live)
            .map(|n| n.amount_msat)
            .sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes: OWASP's argon2id baseline with headroom.
    fn default() -> Self {
        KdfParams {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    format: String,
    kdf: KdfParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub struct Store {
    path: PathBuf,
    kdf: KdfParams,
    salt: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    pub data: WalletData,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn derive_key(password: &str, salt: &[u8], kdf: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| anyhow!("bad key-derivation parameters: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

impl Store {
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    pub fn create(path: &Path, password: &str) -> Result<Store> {
        Self::create_with_params(path, password, KdfParams::default())
    }

    pub fn create_with_params(path: &Path, password: &str, kdf: KdfParams) -> Result<Store> {
        if path.exists() {
            bail!("a wallet already exists at {}", path.display());
        }
        if password.chars().count() < MIN_PASSWORD_LEN {
            bail!("the password needs at least {MIN_PASSWORD_LEN} characters");
        }
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let store = Store {
            path: path.to_path_buf(),
            kdf,
            salt,
            key: derive_key(password, &salt, kdf)?,
            data: WalletData::default(),
        };
        store.save()?;
        Ok(store)
    }

    pub fn open(path: &Path, password: &str) -> Result<Store> {
        let raw =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let envelope: Envelope =
            serde_json::from_str(&raw).context("the wallet file is not readable")?;
        if envelope.format != FORMAT {
            bail!("unsupported wallet file format {:?}", envelope.format);
        }
        let salt: [u8; 16] = hex::decode(&envelope.salt)
            .ok()
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| anyhow!("corrupt wallet file (salt)"))?;
        let nonce = hex::decode(&envelope.nonce)
            .ok()
            .filter(|n| n.len() == 24)
            .ok_or_else(|| anyhow!("corrupt wallet file (nonce)"))?;
        let ciphertext =
            hex::decode(&envelope.ciphertext).context("corrupt wallet file (ciphertext)")?;
        let key = derive_key(password, &salt, envelope.kdf)?;
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new(key.as_ref().into())
                .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
                .map_err(|_| anyhow!("wrong password"))?,
        );
        let data = serde_json::from_slice(&plaintext).context("corrupt wallet contents")?;
        Ok(Store {
            path: path.to_path_buf(),
            kdf: envelope.kdf,
            salt,
            key,
            data,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Encrypt and atomically replace the file. Callers that are about to
    /// disclose a secret's hash must see this return `Ok` first.
    pub fn save(&self) -> Result<()> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.data)?);
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ciphertext = XChaCha20Poly1305::new(self.key.as_ref().into())
            .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|_| anyhow!("encryption failed"))?;
        let envelope = Envelope {
            format: FORMAT.into(),
            kdf: self.kdf,
            salt: hex::encode(self.salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        write_atomically(&self.path, serde_json::to_string(&envelope)?.as_bytes())
    }
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = path.with_extension("tmp");
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `$LNURL_WALLET_FILE`, or the platform data directory.
pub fn default_path() -> PathBuf {
    if let Some(path) = std::env::var_os("LNURL_WALLET_FILE") {
        return PathBuf::from(path);
    }
    directories::ProjectDirs::from("cash", "lnurlcash", "lnurl-wallet-native")
        .map(|dirs| dirs.data_dir().join("wallet.json"))
        .unwrap_or_else(|| PathBuf::from("wallet.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn round_trips_and_rejects_a_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let mut store = Store::create_with_params(&path, "correct horse", FAST).unwrap();
        store.data.log("hello");
        store.save().unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("hello"), "plaintext leaked to disk");

        let reopened = Store::open(&path, "correct horse").unwrap();
        assert_eq!(reopened.data.activity[0].text, "hello");
        assert!(Store::open(&path, "wrong horse!").is_err());
    }

    #[test]
    fn refuses_short_passwords_and_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        assert!(Store::create_with_params(&path, "short", FAST).is_err());
        Store::create_with_params(&path, "long enough", FAST).unwrap();
        assert!(Store::create_with_params(&path, "long enough", FAST).is_err());
    }
}
