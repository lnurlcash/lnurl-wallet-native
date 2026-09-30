//! What the wallet does with notes, over lnurlcash-core's `protocol` layer.
//!
//! Every operation is async and UI-free, and holds the store's lock only
//! between network calls, never across one. The ordering rules that keep
//! money from being lost:
//!
//! - Every note the wallet creates is a seed-derived key ([`crate::keys`]).
//!   Its index is reserved and saved before the key is derived, so no index
//!   is ever handed out twice, and a restore from the seed finds the note.
//! - Every rotate, merge, split and transfer is written to the journal
//!   before its request is built. An answer that did not arrive is not a
//!   failure: the inputs turn `Uncertain`, and [`Wallet::resolve`] reads the
//!   journal to work out where the money went.
//! - A melt's `OK` means the payment is in flight. The note turns `Melting`,
//!   and only the mint saying it is burned makes it `Spent`.
//! - A received note is rotated straight away, since whoever sent it still
//!   knows its spend.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{anyhow, bail, Result};
use lnurlcash_core::protocol::{self, MutationKind, WithdrawRequestInfo};
use lnurlcash_core::recoverable::{decode_cx1, derive_note_pubkey, encode_cp1, Cx1};
use lnurlcash_core::{
    build_note_url, decode_bolt11_amount_msat, is_bolt11_invoice, note_k1, resolve_lnurl_input,
    to_bech32_lnurl, to_lud17w, verify_note_signature, with_new_k1, Error,
};

use crate::http::Http;
use crate::keys::{self, KeyNote, PURPOSES, PURPOSE_ADDRESS, PURPOSE_CHANGE, PURPOSE_WALLET};
use crate::lud25;
use crate::store::{
    now, Address, JournalInput, JournalOutput, JournalState, MintEntry, MintState, Mutation, Note,
    NoteStatus, PendingMint, Store,
};

/// Known public mints, for one-click trust: the reference wallet's list.
/// Being here says nothing about a mint's key or solvency - trust is still
/// the holder's call, and every one of them holds the sats behind its notes.
pub const PUBLIC_MINTS: [&str; 6] = [
    "mint@mint.lnurlcash.com",
    "mint@mint.600.wtf",
    "mint@lnurl.21mint.me",
    "mint@moneyer.dev",
    "mint@lnurl.21linz.at",
    "mint@minty.exe.xyz",
];

/// Consecutive unknown indices a restore walks past before it stops.
const GAP_LIMIT: u32 = 20;
/// How far past its counter an address check looks for auto-minted notes.
const ADDRESS_LOOKAHEAD: u32 = 5;
/// Recipient indices an internal transfer tries before giving up.
const TRANSFER_ATTEMPTS: u32 = 25;

/// Refused because the note's mint isn't trusted yet. The UI asks, then
/// calls [`Wallet::receive`] again with `trust_new`.
#[derive(Debug)]
pub struct UntrustedMint(pub String);

impl std::fmt::Display for UntrustedMint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} isn't a trusted mint", self.0)
    }
}

impl std::error::Error for UntrustedMint {}

/// The mint already knows one of the outputs: pick fresh ones and retry.
#[derive(Debug)]
struct OutputInUse;

impl std::fmt::Display for OutputInUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the mint reports that output as already in use")
    }
}

impl std::error::Error for OutputInUse {}

#[derive(Debug, Clone)]
pub struct Wallet {
    store: Arc<Mutex<Store>>,
    http: Http,
    /// Mints a restore asks even when they aren't trusted yet.
    public_mints: Vec<String>,
}

pub fn msat_to_sats(msat: u64) -> String {
    if msat.is_multiple_of(1000) {
        format!("{}", msat / 1000)
    } else {
        format!("{}.{:03}", msat / 1000, msat % 1000)
    }
}

/// scheme://host[:port] - what a mint key is pinned to, so the same host on
/// another port or scheme is a different mint.
pub fn origin_of(url: &str) -> String {
    reqwest::Url::parse(&lnurlcash_core::from_lud17(url))
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_else(|_| url.to_string())
}

/// The note's current spend is known to be burned.
fn is_gone(err: &Error) -> bool {
    matches!(err, Error::NoteSpent { .. } | Error::NoteUnknown { .. })
}

fn strip_lightning_prefix(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix("lightning:")
        .or_else(|| value.strip_prefix("LIGHTNING:"))
        .unwrap_or(value)
}

/// What a mutation is about to do, before any of it is written down.
struct Plan {
    op: &'static str,
    withdraw_link: String,
    callback: String,
    inputs: Vec<JournalInput>,
    input_k1s: Vec<String>,
    outputs: Vec<JournalOutput>,
    split_msat: Option<u64>,
}

/// Notes picked at one mint, with the fresh informational GET each needs.
struct Picked {
    notes: Vec<Note>,
    total_msat: u64,
    info: WithdrawRequestInfo,
}

/// Where a payment goes, once parsed.
enum Destination {
    Invoice(String),
    /// A payRequest; its `text/cpub` hint if the payee registered a branch.
    PayLink {
        pay: protocol::PayRequestInfo,
        cpub: Option<(Cx1, u32)>,
    },
    /// A bare `cx1`, optionally `:<index>`, paid at the chosen mint.
    Branch(Cx1, u32),
}

impl Wallet {
    pub fn new(store: Store, http: Http) -> Self {
        Wallet {
            store: Arc::new(Mutex::new(store)),
            http,
            public_mints: PUBLIC_MINTS.iter().map(|m| m.to_string()).collect(),
        }
    }

    /// A wallet whose restore only looks at the mints it trusts.
    #[cfg(test)]
    pub fn without_public_mints(mut self) -> Self {
        self.public_mints.clear();
        self
    }

    /// The store, for reading. Never hold this across an `.await`.
    pub fn store(&self) -> MutexGuard<'_, Store> {
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn note(&self, id: &str) -> Result<Note> {
        self.store()
            .data
            .note(id)
            .cloned()
            .ok_or_else(|| anyhow!("no such note"))
    }

    /// Change one note and save.
    fn update_note(&self, id: &str, change: impl FnOnce(&mut Note)) -> Result<()> {
        let mut store = self.store();
        let note = store
            .data
            .note_mut(id)
            .ok_or_else(|| anyhow!("no such note"))?;
        change(note);
        note.updated_at = now();
        store.save()
    }

    fn log(&self, text: String) -> Result<()> {
        let mut store = self.store();
        store.data.log(text);
        store.save()
    }

    // ---- the informational GET ----

    /// Never burns or alters the note. Pins the mint's key on first sight and
    /// refuses a changed one.
    async fn fetch_info(&self, url: &str) -> Result<WithdrawRequestInfo, Error> {
        let body = self.http.read(&protocol::note_info_request(url)?).await?;
        let info = protocol::parse_note_info(&body, url, self.http.policy)?;
        if let Some(key) = &info.mint_pubkey {
            self.check_mint_key(url, key)?;
        }
        Ok(info)
    }

    /// The same, for a note that must still be live: a burned one is marked
    /// spent on the way out.
    async fn fetch_live(&self, note: &Note) -> Result<WithdrawRequestInfo> {
        match self.fetch_info(&note.url).await {
            Ok(info) => Ok(info),
            Err(err) if is_gone(&err) => {
                self.mark_gone(&note.id(), &err)?;
                Err(err.into())
            }
            Err(err) => Err(err.into()),
        }
    }

    fn check_mint_key(&self, url: &str, key: &str) -> Result<(), Error> {
        let origin = origin_of(url);
        let mut store = self.store();
        match store.data.mint_keys.get(&origin) {
            Some(pinned) if pinned == key => Ok(()),
            Some(pinned) => Err(Error::RequestRefused(format!(
                "{origin} now presents mint key {key}, but {pinned} is pinned for it - refusing. \
                 If the mint really rotated its key, unpin it under Mints and try again."
            ))),
            None => {
                store.data.mint_keys.insert(origin.clone(), key.to_string());
                store
                    .data
                    .log(format!("Pinned mint key {key} for {origin}"));
                store
                    .save()
                    .map_err(|e| Error::RequestRefused(format!("could not save: {e}")))
            }
        }
    }

    pub fn unpin_mint(&self, origin: &str) -> Result<()> {
        let mut store = self.store();
        store.data.mint_keys.remove(origin);
        store
            .data
            .log(format!("Unpinned the mint key for {origin}"));
        store.save()
    }

    /// A certificate kept only if it verifies for this spend and amount
    /// against the key pinned for the note's mint.
    fn checked_certificate(
        &self,
        url: &str,
        k1: &str,
        amount: u64,
        cs1: Option<String>,
    ) -> Option<String> {
        let key = self.store().data.mint_keys.get(&origin_of(url)).cloned()?;
        let domain = lud25::domain_of(url)?;
        cs1.filter(|cs1| verify_note_signature(k1, &domain, amount, cs1, &key))
    }

    // ---- receive ----

    /// The origin of a pasted note's mint, if it is a note at all. Local
    /// only: lets the UI ask about trust before anything is sent.
    pub fn note_origin(input: &str) -> Option<String> {
        lud25::resolve_note_input(input).map(|url| origin_of(&url))
    }

    pub fn is_trusted(&self, origin: &str) -> bool {
        self.store().data.mint(origin).is_some()
    }

    /// Take a note someone handed over: verify it with the mint, store it,
    /// then rotate it onto a seed key so the sender's copy stops being money.
    /// A note from a mint not yet trusted is refused with [`UntrustedMint`]
    /// unless `trust_new` says the holder agreed to trust it.
    pub async fn receive(&self, input: &str, trust_new: bool) -> Result<String> {
        let url = lud25::resolve_note_input(input).ok_or_else(|| {
            anyhow!("that is not an LNURLcash note - expected an lnurlw:// link, an LNURL or a note URL")
        })?;
        self.seed()?;
        let origin = origin_of(&url);
        if !self.is_trusted(&origin) {
            if !trust_new {
                return Err(UntrustedMint(origin).into());
            }
            let withdraw_link = lud25::withdraw_link_of(&url)
                .ok_or_else(|| anyhow!("that note URL does not parse"))?;
            self.add_mint(&origin, None, &withdraw_link)?;
        }
        let k1 = note_k1(&url).ok_or_else(|| anyhow!("the note has no k1"))?;
        let id =
            lud25::note_id_of_url(&url).ok_or_else(|| anyhow!("the note's k1 is malformed"))?;
        if self
            .store()
            .data
            .note(&id)
            .is_some_and(|n| n.status != NoteStatus::Spent)
        {
            bail!("this note is already in the wallet");
        }

        let info = self.fetch_info(&url).await?;
        let amount = info.max_withdrawable;
        // The mint's own certificate is preferred over whatever the URL
        // carried, and either is only kept if it verifies.
        let offered = info
            .signature
            .clone()
            .or_else(|| lnurlcash_core::note_signature(&url));
        let certificate = self.checked_certificate(&url, &k1, amount, offered.clone());
        let note = Note {
            url: with_new_k1(&url, &k1, amount, certificate.as_deref())
                .ok_or_else(|| anyhow!("that note URL does not parse"))?,
            amount_msat: amount,
            verified: true,
            status: NoteStatus::Live,
            added_at: now(),
            updated_at: now(),
            detail: (offered.is_some() && certificate.is_none())
                .then(|| "its certificate did not verify against the mint key".to_string()),
        };
        let mint = note.mint();
        {
            let mut store = self.store();
            store.data.notes.retain(|n| n.id() != id);
            store.data.notes.push(note);
            store.data.log(format!(
                "Received {} sats from {mint}",
                msat_to_sats(amount)
            ));
            store.save()?;
        }

        match self.rotate_with(&self.note(&id)?, info).await {
            Ok(_) => Ok(format!(
                "Received {} sats from {mint} and rotated it - the sender's copy is dead.",
                msat_to_sats(amount)
            )),
            Err(err) => Ok(format!(
                "Received {} sats from {mint}, but rotating it failed: {err:#}. \
                 Until it is rotated, the sender can still spend it.",
                msat_to_sats(amount)
            )),
        }
    }

    // ---- the mutation journal ----

    /// Journal a plan, send it, and settle what came back. On success
    /// returns the new notes' ids, ours only, in output order.
    async fn execute(&self, plan: Plan) -> Result<Vec<String>> {
        let entry = Mutation {
            id: hex::encode(rand::random::<[u8; 8]>()),
            op: plan.op.to_string(),
            withdraw_link: plan.withdraw_link.clone(),
            inputs: plan.inputs.clone(),
            outputs: plan.outputs.clone(),
            split_msat: plan.split_msat,
            state: JournalState::Pending,
            created_at: now(),
        };
        let outputs: Vec<&str> = plan.outputs.iter().map(|o| o.output.as_str()).collect();
        let (mut request, kind) = match (plan.split_msat, plan.input_k1s.len(), outputs.as_slice())
        {
            (Some(amount), _, [first, change]) => (
                protocol::split_request_with_hash(
                    &plan.callback,
                    &plan.input_k1s,
                    amount,
                    first,
                    change,
                )?,
                MutationKind::Split,
            ),
            (None, 1, [output]) => (
                protocol::rotate_request_with_hash(&plan.callback, &plan.input_k1s[0], output)?,
                MutationKind::Rotate,
            ),
            (None, _, [output]) => (
                protocol::merge_request_with_hash(&plan.callback, &plan.input_k1s, output)?,
                MutationKind::Merge,
            ),
            _ => bail!("a mutation names one output, or two for a split"),
        };
        // the spends of our own outputs: what an ambiguous error carries
        request.new_secrets = plan.outputs.iter().filter_map(|o| o.k1.clone()).collect();

        // Persist before disclose. If this save fails nothing has been sent.
        let journal_id = entry.id.clone();
        {
            let mut store = self.store();
            store.data.journal.push(entry);
            store.save()?;
        }

        match self.http.mutation(&request, kind).await {
            Ok(response) => {
                self.settle(
                    &journal_id,
                    &[response.signature, response.change_signature],
                )
                .await
            }
            // OK came back, just without a proof: the notes exist.
            Err(Error::Unverifiable { .. }) => self.settle(&journal_id, &[]).await,
            Err(Error::ServiceRejected(reason)) if reason.contains("already in use") => {
                self.set_journal_state(&journal_id, JournalState::Failed)?;
                Err(OutputInUse.into())
            }
            // The mutation may have landed. Keep everything; resolve later.
            // Spent/unknown is here too: at a mint that answers a retry rather
            // than replaying it, that is also what an applied mutation looks like.
            Err(err) if err.is_ambiguous() || is_gone(&err) => {
                let message = format!("{err}");
                for input in &plan.inputs {
                    self.update_note(&input.id, |n| {
                        n.status = NoteStatus::Uncertain;
                        n.detail = Some(format!("{} outcome unknown: {message}", plan.op));
                    })?;
                }
                self.log(format!("{} outcome unknown: {message}", plan.op))?;
                bail!(
                    "the {}'s outcome is unknown ({message}). Everything is saved - use Resolve",
                    plan.op
                )
            }
            Err(err) => {
                self.set_journal_state(&journal_id, JournalState::Failed)?;
                Err(err.into())
            }
        }
    }

    fn set_journal_state(&self, journal_id: &str, state: JournalState) -> Result<()> {
        let mut store = self.store();
        if let Some(entry) = store.data.journal.iter_mut().find(|m| m.id == journal_id) {
            entry.state = state;
        }
        store.save()
    }

    /// A journaled mutation landed: our outputs become notes - their amounts
    /// confirmed by `?p=`, which keeps the spends off the wire - and the
    /// inputs are gone. `certificates` are the response's `c`/`c2`, if any.
    async fn settle(
        &self,
        journal_id: &str,
        certificates: &[Option<String>],
    ) -> Result<Vec<String>> {
        let entry = self
            .store()
            .data
            .journal
            .iter()
            .find(|m| m.id == journal_id)
            .cloned()
            .ok_or_else(|| anyhow!("no such journal entry"))?;
        let mut adopted = Vec::new();
        let mut notes = Vec::new();
        for (index, output) in entry.outputs.iter().enumerate() {
            let Some(k1) = &output.k1 else { continue };
            let found = self
                .lookup(&entry.withdraw_link, &output.output)
                .await
                .ok()
                .flatten();
            let (amount, verified) = match &found {
                Some(found) => (found.max_withdrawable, true),
                None => (output.expected_msat, false),
            };
            let base = build_note_url(&entry.withdraw_link, k1, Some(amount))
                .ok_or_else(|| anyhow!("the withdraw link does not parse"))?;
            let offered = certificates.get(index).cloned().flatten();
            let certificate = self.checked_certificate(&base, k1, amount, offered);
            let url = with_new_k1(&base, k1, amount, certificate.as_deref())
                .ok_or_else(|| anyhow!("the withdraw link does not parse"))?;
            let note = Note {
                url,
                amount_msat: amount,
                verified,
                status: NoteStatus::Live,
                added_at: now(),
                updated_at: now(),
                detail: (!verified)
                    .then(|| "the mint didn't confirm this amount yet - Check it".into()),
            };
            adopted.push(note.id());
            notes.push(note);
        }
        let mut store = self.store();
        let burned: Vec<&str> = entry.inputs.iter().map(|i| i.id.as_str()).collect();
        store
            .data
            .notes
            .retain(|n| !burned.contains(&n.id().as_str()));
        for note in notes {
            let id = note.id();
            store.data.notes.retain(|n| n.id() != id);
            store.data.notes.push(note);
        }
        if let Some(stored) = store.data.journal.iter_mut().find(|m| m.id == journal_id) {
            stored.state = JournalState::Done;
        }
        let total: u64 = entry.inputs.iter().map(|i| i.amount_msat).sum();
        let sent: Vec<String> = entry
            .outputs
            .iter()
            .filter_map(|o| {
                o.recipient
                    .as_ref()
                    .map(|r| format!("{} sats to {r}", msat_to_sats(o.expected_msat)))
            })
            .collect();
        let mut line = format!(
            "{} of {} sats at {}",
            capitalize(&entry.op),
            msat_to_sats(total),
            lnurlcash_core::server_of(&entry.withdraw_link)
        );
        if !sent.is_empty() {
            line.push_str(&format!(": {}", sent.join(", ")));
        }
        store.data.log(line);
        store.save()?;
        Ok(adopted)
    }

    /// The pending journal entry a note is an input of, if any.
    fn pending_for(&self, id: &str) -> Option<Mutation> {
        self.store()
            .data
            .journal
            .iter()
            .rev()
            .find(|m| m.state == JournalState::Pending && m.inputs.iter().any(|i| i.id == id))
            .cloned()
    }

    // ---- resolve ----

    /// After a mutation whose answer was lost: did it land? First by asking
    /// about our outputs (`?p=`, nothing spendable sent), then about the
    /// inputs, which the mint already knows.
    pub async fn resolve(&self, id: &str) -> Result<String> {
        let note = self.note(id)?;
        if note.status != NoteStatus::Uncertain {
            bail!("nothing to resolve - this note is {}", note.status.label());
        }
        let entry = self
            .pending_for(id)
            .ok_or_else(|| anyhow!("no pending operation is recorded for this note"))?;

        for output in entry.outputs.iter().filter(|o| o.k1.is_some()) {
            if self
                .lookup(&entry.withdraw_link, &output.output)
                .await?
                .is_some()
            {
                self.settle(&entry.id, &[]).await?;
                return Ok(format!(
                    "The {} did land - your notes are updated.",
                    entry.op
                ));
            }
        }
        let mut burned = false;
        for input in &entry.inputs {
            match self.fetch_info(&input.url).await {
                Ok(_) => {}
                Err(err) if is_gone(&err) => burned = true,
                Err(Error::NotePending) => {
                    bail!("the mint has another operation in flight on these notes - try again shortly")
                }
                Err(err) => bail!("couldn't find out yet, nothing changed: {err}"),
            }
        }
        if burned {
            // Inputs burned and none of our outputs visible: a transfer whose
            // only output was someone else's, or our outputs not indexed yet.
            // Adopt them unverified rather than drop them; Check settles it.
            self.settle(&entry.id, &[]).await?;
            return Ok(format!(
                "The {} landed - Check the new notes to confirm them.",
                entry.op
            ));
        }
        self.set_journal_state(&entry.id, JournalState::Failed)?;
        for input in &entry.inputs {
            self.update_note(&input.id, |n| {
                n.status = NoteStatus::Live;
                n.detail = Some(format!(
                    "the {} never landed; this note is unchanged",
                    entry.op
                ));
            })?;
        }
        self.log(format!("Resolved: the {} never landed", entry.op))?;
        Ok(format!(
            "The {} never landed - your notes are unchanged.",
            entry.op
        ))
    }

    // ---- rotate, merge, split ----

    pub async fn rotate(&self, id: &str) -> Result<String> {
        let note = self.note(id)?;
        if !matches!(note.status, NoteStatus::Live | NoteStatus::Sent) {
            bail!(
                "only a live or sent note can be rotated (this one is {})",
                note.status.label()
            );
        }
        let info = self.fetch_live(&note).await?;
        let reclaimed = note.status == NoteStatus::Sent;
        let new_id = self.rotate_with(&note, info).await?;
        let amount = msat_to_sats(self.note(&new_id)?.amount_msat);
        Ok(if reclaimed {
            format!("Took back {amount} sats - the copy you gave away is dead.")
        } else {
            format!("Rotated {amount} sats onto a fresh key.")
        })
    }

    /// Rotate onto the next wallet key, skipping any the mint already knows.
    async fn rotate_with(&self, note: &Note, info: WithdrawRequestInfo) -> Result<String> {
        let picked = Picked {
            total_msat: info.max_withdrawable,
            notes: vec![note.clone()],
            info,
        };
        for _ in 0..5 {
            let output = self.own_output(&picked, PURPOSE_WALLET, picked.total_msat)?;
            match self
                .execute(self.plan("rotate", &picked, vec![output], None))
                .await
            {
                Ok(ids) => return ids.into_iter().next().ok_or_else(|| anyhow!("no output")),
                Err(err) if err.downcast_ref::<OutputInUse>().is_some() => continue,
                Err(err) => return Err(err),
            }
        }
        bail!("the mint reports every fresh key as already in use - try again")
    }

    /// Merge every live note held at one mint into one.
    pub async fn merge_all(&self, origin: &str) -> Result<String> {
        let ids: Vec<String> = self
            .store()
            .data
            .live_at(origin)
            .iter()
            .map(|n| n.id())
            .collect();
        if ids.len() < 2 {
            bail!("merging needs at least two live notes at {origin}");
        }
        let picked = self.fetch_picked(&ids).await?;
        let id = self.merge_picked(&picked).await?;
        Ok(format!(
            "Merged {} notes into one of {} sats.",
            picked.notes.len(),
            msat_to_sats(self.note(&id)?.amount_msat)
        ))
    }

    async fn merge_picked(&self, picked: &Picked) -> Result<String> {
        for _ in 0..5 {
            let output = self.own_output(picked, PURPOSE_WALLET, picked.total_msat)?;
            match self
                .execute(self.plan("merge", picked, vec![output], None))
                .await
            {
                Ok(ids) => return ids.into_iter().next().ok_or_else(|| anyhow!("no output")),
                Err(err) if err.downcast_ref::<OutputInUse>().is_some() => continue,
                Err(err) => return Err(err),
            }
        }
        bail!("the mint reports every fresh key as already in use - try again")
    }

    /// Split `amount_msat` off the picked notes; the rest comes back as
    /// change. Returns the new exact-amount note's id.
    async fn split_picked(&self, picked: &Picked, amount_msat: u64) -> Result<String> {
        for _ in 0..5 {
            let first = self.own_output(picked, PURPOSE_WALLET, amount_msat)?;
            let change =
                self.own_output(picked, PURPOSE_CHANGE, picked.total_msat - amount_msat)?;
            match self
                .execute(self.plan("split", picked, vec![first, change], Some(amount_msat)))
                .await
            {
                Ok(ids) => return ids.into_iter().next().ok_or_else(|| anyhow!("no output")),
                Err(err) if err.downcast_ref::<OutputInUse>().is_some() => continue,
                Err(err) => return Err(err),
            }
        }
        bail!("the mint reports every fresh key as already in use - try again")
    }

    fn plan(
        &self,
        op: &'static str,
        picked: &Picked,
        outputs: Vec<JournalOutput>,
        split_msat: Option<u64>,
    ) -> Plan {
        Plan {
            op,
            withdraw_link: lud25::withdraw_link_of(&picked.notes[0].url).unwrap_or_default(),
            callback: picked.info.callback.clone(),
            inputs: picked
                .notes
                .iter()
                .map(|n| JournalInput {
                    id: n.id(),
                    url: n.url.clone(),
                    amount_msat: n.amount_msat,
                })
                .collect(),
            input_k1s: picked.notes.iter().map(Note::k1).collect(),
            outputs,
            split_msat,
        }
    }

    /// The next key of ours at the picked notes' mint, as an output.
    fn own_output(
        &self,
        picked: &Picked,
        purpose: u32,
        expected_msat: u64,
    ) -> Result<JournalOutput> {
        let domain = lud25::domain_of(&picked.notes[0].url)
            .ok_or_else(|| anyhow!("that note URL has no host"))?;
        let key = self.next_key_note(&domain, purpose)?;
        Ok(JournalOutput {
            output: key.output,
            k1: Some(key.k1),
            expected_msat,
            recipient: None,
        })
    }

    /// Fresh informational GETs for notes at one mint, which also confirms
    /// they are all live and share a callback.
    async fn fetch_picked(&self, ids: &[String]) -> Result<Picked> {
        let mut notes = Vec::new();
        let mut info = None;
        let mut total = 0u64;
        for id in ids {
            let note = self.note(id)?;
            if note.status != NoteStatus::Live {
                bail!("a note in that selection is {}", note.status.label());
            }
            let fresh = self.fetch_live(&note).await?;
            total += fresh.max_withdrawable;
            if info
                .as_ref()
                .is_some_and(|i: &WithdrawRequestInfo| i.callback != fresh.callback)
            {
                bail!("those notes aren't at the same mint");
            }
            self.update_note(id, |n| n.amount_msat = fresh.max_withdrawable)?;
            notes.push(self.note(id)?);
            info = Some(fresh);
        }
        Ok(Picked {
            notes,
            total_msat: total,
            info: info.ok_or_else(|| anyhow!("no notes picked"))?,
        })
    }

    /// Live notes at `origin` worth at least `amount_msat`: one exact note
    /// if there is one, else the fewest, largest first.
    fn select(&self, origin: &str, amount_msat: u64) -> Result<Vec<String>> {
        let store = self.store();
        let live = store.data.live_at(origin);
        if let Some(exact) = live.iter().find(|n| n.amount_msat == amount_msat) {
            return Ok(vec![exact.id()]);
        }
        let mut picked = Vec::new();
        let mut total = 0u64;
        for note in live {
            picked.push(note.id());
            total += note.amount_msat;
            if total >= amount_msat {
                return Ok(picked);
            }
        }
        bail!(
            "you hold {} sats at {origin}, less than {}",
            msat_to_sats(total),
            msat_to_sats(amount_msat)
        )
    }

    /// A single live note of exactly `amount_msat` at `origin`, made by
    /// splitting and merging whatever is held there.
    pub async fn exact_note(&self, origin: &str, amount_msat: u64) -> Result<String> {
        if amount_msat == 0 {
            bail!("the amount must be more than zero");
        }
        // two rounds at most: a merge whose fee refund overshoots, then a split
        for _ in 0..3 {
            let ids = self.select(origin, amount_msat)?;
            let picked = self.fetch_picked(&ids).await?;
            if picked.notes.len() == 1 && picked.total_msat == amount_msat {
                return Ok(ids[0].clone());
            }
            if picked.total_msat == amount_msat {
                self.merge_picked(&picked).await?;
                continue;
            }
            if picked.total_msat > amount_msat {
                return self.split_picked(&picked, amount_msat).await;
            }
            // amounts moved under us; select again
        }
        bail!(
            "couldn't make a note of exactly {} sats",
            msat_to_sats(amount_msat)
        )
    }

    /// Carve a note of `amount_msat` out of what is held at `origin`, to hand
    /// over. Returns its id; the UI shows it and the holder marks it sent.
    pub async fn note_for_amount(&self, origin: &str, amount_msat: u64) -> Result<String> {
        self.exact_note(origin, amount_msat).await
    }

    // ---- check ----

    /// One informational GET, and what it means for this note's status.
    pub async fn check(&self, id: &str) -> Result<String> {
        let note = self.note(id)?;
        if note.status == NoteStatus::Uncertain {
            return self.resolve(id).await;
        }
        match self.fetch_info(&note.url).await {
            Ok(info) => {
                let amount = info.max_withdrawable;
                let (status, detail) = match note.status {
                    NoteStatus::Melting => (
                        NoteStatus::Live,
                        Some("the melt's payment failed - the note is spendable again".to_string()),
                    ),
                    NoteStatus::Sent => (NoteStatus::Sent, Some("not claimed yet".to_string())),
                    _ => (NoteStatus::Live, None),
                };
                self.update_note(id, |n| {
                    n.status = status;
                    n.amount_msat = amount;
                    n.verified = true;
                    n.detail = detail.clone();
                })?;
                Ok(match detail {
                    Some(detail) => format!("{} sats: {detail}.", msat_to_sats(amount)),
                    None => format!("{} sats, live at {}.", msat_to_sats(amount), note.mint()),
                })
            }
            Err(err) if is_gone(&err) => {
                self.mark_gone(id, &err)?;
                Ok(match note.status {
                    NoteStatus::Melting => "The melt settled - the invoice is paid.".into(),
                    NoteStatus::Sent => "The recipient has claimed it.".into(),
                    _ => format!("The mint reports it burned: {err}"),
                })
            }
            Err(Error::NotePending) => {
                self.update_note(id, |n| {
                    n.status = NoteStatus::Melting;
                    n.detail = Some("a payment is in flight".into());
                })?;
                Ok("A payment is still in flight.".into())
            }
            Err(err) => Err(err.into()),
        }
    }

    fn mark_gone(&self, id: &str, err: &Error) -> Result<()> {
        let message = format!("{err}");
        let was_sent = self.note(id)?.status == NoteStatus::Sent;
        self.update_note(id, |n| {
            n.status = NoteStatus::Spent;
            n.detail = Some(if was_sent {
                "claimed by whoever you gave it to".into()
            } else {
                message
            });
        })
    }

    // ---- pay ----

    /// Pay `destination` from what is held at `origin`: a BOLT-11 invoice, a
    /// Lightning Address or LNURL-pay link, or a `cx1` branch. A payee who
    /// registered a branch at this same mint is paid by internal transfer -
    /// no Lightning, no routing fee. Otherwise an exact note is carved out
    /// and melted into an invoice.
    pub async fn pay(
        &self,
        origin: &str,
        destination: &str,
        amount_msat: Option<u64>,
    ) -> Result<String> {
        match self.parse_destination(destination).await? {
            Destination::Invoice(pr) => {
                let invoiced = decode_bolt11_amount_msat(&pr).ok_or_else(|| {
                    anyhow!("an amountless invoice can't be paid - the mint pays exact amounts")
                })?;
                if amount_msat.is_some_and(|a| a != invoiced) {
                    bail!("the invoice is for {} sats", msat_to_sats(invoiced));
                }
                let id = self.exact_note(origin, invoiced).await?;
                self.melt_into(&id, &pr).await
            }
            Destination::PayLink { pay, cpub } => {
                let amount = amount_msat.ok_or_else(|| anyhow!("enter an amount to send"))?;
                let same_mint = pay
                    .withdraw_link
                    .as_deref()
                    .is_some_and(|link| origin_of(link) == origin);
                if let (Some((cx1, index)), true) = (cpub, same_mint) {
                    return self
                        .transfer(origin, &cx1, index, amount, destination.trim())
                        .await;
                }
                if amount < pay.min_sendable || amount > pay.max_sendable {
                    bail!(
                        "that destination accepts {}-{} sats",
                        msat_to_sats(pay.min_sendable),
                        msat_to_sats(pay.max_sendable)
                    );
                }
                let body = self
                    .http
                    .read(&protocol::invoice_request(&pay.callback, amount)?)
                    .await?;
                let pr = protocol::parse_invoice(&body, amount)?.pr;
                let id = self.exact_note(origin, amount).await?;
                self.melt_into(&id, &pr).await
            }
            Destination::Branch(cx1, index) => {
                let amount = amount_msat.ok_or_else(|| anyhow!("enter an amount to send"))?;
                self.transfer(origin, &cx1, index, amount, "that cx1").await
            }
        }
    }

    async fn parse_destination(&self, destination: &str) -> Result<Destination> {
        let destination = strip_lightning_prefix(destination);
        if is_bolt11_invoice(destination) {
            return Ok(Destination::Invoice(destination.to_string()));
        }
        let (branch, index) = destination.rsplit_once(':').unwrap_or((destination, "0"));
        if let (Some(cx1), Ok(index)) = (decode_cx1(branch), index.parse()) {
            return Ok(Destination::Branch(cx1, index));
        }
        let pay_url = resolve_lnurl_input(destination).ok_or_else(|| {
            anyhow!("expected a BOLT-11 invoice, a Lightning Address, an LNURL-pay link or a cx1")
        })?;
        let body = self
            .http
            .read(&protocol::pay_request_request(&pay_url)?)
            .await?;
        let pay = parse_pay_link(body)?;
        let cpub = lud25::parse_cpub(&pay.metadata);
        Ok(Destination::PayLink { pay, cpub })
    }

    /// LUD-25 internal transfer: credit the payee's next purpose-2 key
    /// directly from notes at the same mint, trying the next index whenever
    /// the hinted one is taken.
    async fn transfer(
        &self,
        origin: &str,
        cx1: &Cx1,
        start: u32,
        amount_msat: u64,
        label: &str,
    ) -> Result<String> {
        let ids = self.select(origin, amount_msat)?;
        let picked = self.fetch_picked(&ids).await?;
        if picked.total_msat < amount_msat {
            bail!("the selected notes are worth less than that now");
        }
        for index in start..start.saturating_add(TRANSFER_ATTEMPTS) {
            let pk =
                derive_note_pubkey(&cx1.pubkey_x_only, &cx1.chain_code, PURPOSE_ADDRESS, index)?;
            let recipient = JournalOutput {
                output: encode_cp1(&pk),
                k1: None,
                expected_msat: amount_msat,
                recipient: Some(label.to_string()),
            };
            let plan = if picked.total_msat == amount_msat {
                let op = if picked.notes.len() == 1 {
                    "transfer"
                } else {
                    "merge transfer"
                };
                self.plan(op, &picked, vec![recipient], None)
            } else {
                let change =
                    self.own_output(&picked, PURPOSE_CHANGE, picked.total_msat - amount_msat)?;
                self.plan(
                    "split transfer",
                    &picked,
                    vec![recipient, change],
                    Some(amount_msat),
                )
            };
            match self.execute(plan).await {
                Ok(_) => {
                    return Ok(format!(
                        "Sent {} sats to {label} inside the mint - no Lightning payment needed.",
                        msat_to_sats(amount_msat)
                    ))
                }
                Err(err) if err.downcast_ref::<OutputInUse>().is_some() => continue,
                Err(err) => return Err(err),
            }
        }
        bail!("every key the payee's branch offered was already in use")
    }

    /// Melt one note of exactly the invoice's amount.
    pub async fn melt(&self, id: &str, destination: &str) -> Result<String> {
        let note = self.note(id)?;
        let pr = match self.parse_destination(destination).await? {
            Destination::Invoice(pr) => pr,
            Destination::PayLink { pay, .. } => {
                let amount = note.amount_msat;
                if amount < pay.min_sendable || amount > pay.max_sendable {
                    bail!(
                        "that destination accepts {}-{} sats; the note holds {}",
                        msat_to_sats(pay.min_sendable),
                        msat_to_sats(pay.max_sendable),
                        msat_to_sats(amount)
                    );
                }
                let body = self
                    .http
                    .read(&protocol::invoice_request(&pay.callback, amount)?)
                    .await?;
                protocol::parse_invoice(&body, amount)?.pr
            }
            Destination::Branch(..) => bail!("to pay a cx1, use Pay"),
        };
        self.melt_into(id, &pr).await
    }

    async fn melt_into(&self, id: &str, pr: &str) -> Result<String> {
        let note = self.note(id)?;
        if note.status != NoteStatus::Live {
            bail!(
                "only a live note can be melted (this one is {})",
                note.status.label()
            );
        }
        let info = self.fetch_live(&note).await?;
        let amount = info.max_withdrawable;
        match decode_bolt11_amount_msat(pr) {
            Some(invoiced) if invoiced == amount => {}
            Some(invoiced) => bail!(
                "the invoice is for {} sats but the note holds {} - a melt pays exactly the note's value",
                msat_to_sats(invoiced),
                msat_to_sats(amount)
            ),
            None => bail!("an amountless invoice can't be melted - the mint pays exactly the note's value"),
        }
        let request = protocol::melt_request(&info.callback, &note.k1(), pr)?;

        self.update_note(id, |n| {
            n.status = NoteStatus::Melting;
            n.detail = Some("melting".into());
        })?;
        match self.http.mutation(&request, MutationKind::Melt).await {
            Ok(_) => {
                self.update_note(id, |n| {
                    n.detail = Some("payment in flight - Check later to confirm it settled".into())
                })?;
                self.log(format!(
                    "Melting {} sats at {}",
                    msat_to_sats(amount),
                    note.mint()
                ))?;
                Ok(format!(
                    "The mint accepted the melt; paying {} sats is in flight. Check later to confirm.",
                    msat_to_sats(amount)
                ))
            }
            Err(err) if is_gone(&err) => {
                self.mark_gone(id, &err)?;
                Err(err.into())
            }
            Err(err) if err.is_definitive() => {
                let message = format!("{err}");
                self.update_note(id, |n| {
                    n.status = NoteStatus::Live;
                    n.detail = Some(format!("melt refused: {message}"));
                })?;
                Err(err.into())
            }
            Err(err) => {
                let message = format!("{err}");
                self.update_note(id, |n| {
                    n.detail = Some(format!(
                        "melt outcome unknown: {message} - Check to find out"
                    ))
                })?;
                bail!("the melt's outcome is unknown ({message}). Check the note to find out")
            }
        }
    }

    // ---- seed ----

    pub fn has_seed(&self) -> bool {
        self.store().data.seed_phrase.is_some()
    }

    pub fn seed_phrase(&self) -> Option<String> {
        self.store().data.seed_phrase.clone()
    }

    fn seed(&self) -> Result<zeroize::Zeroizing<[u8; 64]>> {
        let phrase = self
            .seed_phrase()
            .ok_or_else(|| anyhow!("set up a seed phrase first"))?;
        keys::seed_of(&phrase)
    }

    /// Set the wallet's seed, once. Replacing it would orphan every note key
    /// already derived from the old one.
    pub fn set_seed(&self, phrase: &str) -> Result<()> {
        let phrase = keys::normalize_phrase(phrase)?;
        let mut store = self.store();
        if store.data.seed_phrase.is_some() {
            bail!("this wallet already has a seed phrase");
        }
        store.data.seed_phrase = Some(phrase);
        store.data.log("Seed phrase set");
        store.save()
    }

    /// Reserve the next index for `purpose` at `domain` - saved before the
    /// key is derived, let alone disclosed - and derive its note.
    pub(crate) fn next_key_note(&self, domain: &str, purpose: u32) -> Result<KeyNote> {
        let seed = self.seed()?;
        loop {
            let index = {
                let mut store = self.store();
                let counter = store.data.counters.entry(domain.to_string()).or_default();
                let index = counter[purpose as usize];
                counter[purpose as usize] = index
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("key counter exhausted"))?;
                store.save()?;
                index
            };
            if let Some(note) = keys::key_note(seed.as_ref(), domain, purpose, index) {
                return Ok(note);
            }
        }
    }

    // ---- mints ----

    fn add_mint(&self, origin: &str, address: Option<&str>, withdraw_link: &str) -> Result<()> {
        let mut store = self.store();
        if let Some(entry) = store.data.mints.iter_mut().find(|m| m.origin == origin) {
            if entry.address.is_none() {
                entry.address = address.map(str::to_string);
            }
        } else {
            store.data.mints.push(MintEntry {
                origin: origin.to_string(),
                address: address.map(str::to_string),
                withdraw_link: withdraw_link.to_string(),
                trusted_at: now(),
            });
            store.data.log(format!("Trusted {origin}"));
        }
        store.save()
    }

    /// Resolve a mint's Lightning Address (or bare domain, or LNURL) to what
    /// minting there needs, refusing one that can't mint a current note.
    pub async fn quote_mint(&self, address: &str) -> Result<MintQuote> {
        let address = address.trim();
        let pay_url = lnurlcash_core::resolve_mint_input(address)
            .or_else(|| resolve_lnurl_input(address))
            .ok_or_else(|| {
                anyhow!("expected a mint's Lightning Address, like mint@mint.lnurlcash.com")
            })?;
        let pay = protocol::parse_pay_request(
            &self
                .http
                .read(&protocol::pay_request_request(&pay_url)?)
                .await?,
        )?;
        let withdraw_link = pay
            .withdraw_link
            .as_deref()
            .map(lnurlcash_core::from_lud17)
            .ok_or_else(|| {
                anyhow!("{address} is a Lightning Address, but not an LNURLcash mint")
            })?;
        if !pay.names_mint_output() {
            bail!("{address} doesn't accept the 64-character comment minting needs");
        }
        Ok(MintQuote {
            address: address.to_string(),
            origin: origin_of(&withdraw_link),
            withdraw_link,
            callback: pay.callback,
            min_msat: pay.min_sendable,
            max_msat: pay.max_sendable,
            fee: pay.mint_fee,
        })
    }

    pub async fn trust_mint(&self, address: &str) -> Result<String> {
        let quote = self.quote_mint(address).await?;
        self.add_mint(&quote.origin, Some(&quote.address), &quote.withdraw_link)?;
        Ok(format!("Trusted {}.", quote.address))
    }

    /// Stop trusting a mint - refused while it still holds your money.
    pub fn untrust_mint(&self, origin: &str) -> Result<()> {
        let mut store = self.store();
        let holding = store
            .data
            .notes
            .iter()
            .any(|n| n.origin() == origin && n.status != NoteStatus::Spent);
        if holding {
            bail!("you still hold notes at {origin} - melt or send them first");
        }
        store.data.mints.retain(|m| m.origin != origin);
        store.data.log(format!("Stopped trusting {origin}"));
        store.save()
    }

    /// Mint a note: derive the next key, save it, then ask for an invoice
    /// committing to its `cp1`. The note exists once someone pays it.
    pub async fn start_mint(&self, address: &str, amount_msat: u64) -> Result<String> {
        let quote = self.quote_mint(address).await?;
        if amount_msat < quote.min_msat || amount_msat > quote.max_msat {
            bail!(
                "{} mints between {} and {} sats",
                quote.address,
                msat_to_sats(quote.min_msat),
                msat_to_sats(quote.max_msat)
            );
        }
        self.add_mint(&quote.origin, Some(&quote.address), &quote.withdraw_link)?;
        let domain = lud25::domain_of(&quote.withdraw_link)
            .ok_or_else(|| anyhow!("the mint's withdraw link has no host"))?;
        let key = self.next_key_note(&domain, PURPOSE_WALLET)?;
        let expected_msat = quote
            .fee
            .map(|fee| lnurlcash_core::apply_mint_fee(amount_msat, fee))
            .unwrap_or(amount_msat);
        {
            let mut store = self.store();
            store.data.pending_mints.push(PendingMint {
                output: key.output.clone(),
                k1: key.k1.clone(),
                address: quote.address.clone(),
                withdraw_link: quote.withdraw_link.clone(),
                pr: None,
                paid_msat: amount_msat,
                expected_msat,
                state: MintState::Waiting,
                created_at: now(),
            });
            store.save()?;
        }
        let request =
            protocol::mint_invoice_request_with_hash(&quote.callback, amount_msat, &key.output)?;
        let invoice = protocol::parse_invoice(&self.http.read(&request).await?, amount_msat)?;
        let mut store = self.store();
        if let Some(pending) = store
            .data
            .pending_mints
            .iter_mut()
            .find(|m| m.output == key.output)
        {
            pending.pr = Some(invoice.pr);
        }
        store.data.log(format!(
            "Minting {} sats at {} (invoice for {})",
            msat_to_sats(expected_msat),
            quote.address,
            msat_to_sats(amount_msat)
        ));
        store.save()?;
        Ok(format!(
            "Pay the invoice for {} sats; the note will hold {} sats.",
            msat_to_sats(amount_msat),
            msat_to_sats(expected_msat)
        ))
    }

    /// Ask the mint - by `?p=`, so nothing spendable is sent - whether a
    /// pending mint has been paid. `Some` once the note is in the wallet.
    pub async fn poll_mint(&self, output: &str) -> Result<Option<String>> {
        let pending = self
            .store()
            .data
            .pending_mints
            .iter()
            .find(|m| m.output == output)
            .cloned()
            .ok_or_else(|| anyhow!("no such mint"))?;
        if pending.state == MintState::Credited {
            return Ok(None);
        }
        let Some(found) = self.lookup(&pending.withdraw_link, output).await? else {
            return Ok(None);
        };
        let key = KeyNote {
            k1: pending.k1.clone(),
            output: output.to_string(),
        };
        let amount = self
            .add_key_note(&pending.withdraw_link, &key, found.max_withdrawable)
            .await?;
        Ok(Some(format!(
            "Minted {} sats at {}.",
            msat_to_sats(amount),
            pending.address
        )))
    }

    pub fn dismiss_mint(&self, output: &str) -> Result<()> {
        let mut store = self.store();
        if let Some(pending) = store
            .data
            .pending_mints
            .iter_mut()
            .find(|m| m.output == output)
        {
            if pending.state == MintState::Waiting {
                pending.state = MintState::Dismissed;
            }
        }
        store.save()
    }

    /// A note looked up by its output (`?p=`). `None` for unknown or burned,
    /// which a mint must answer identically.
    async fn lookup(
        &self,
        withdraw_link: &str,
        output: &str,
    ) -> Result<Option<protocol::NoteInfoByHash>, Error> {
        let url = lnurlcash_core::note::build_note_info_url_by_hash(withdraw_link, output)
            .ok_or_else(|| {
                Error::RequestRefused("that withdraw link or output does not parse".into())
            })?;
        let body = self.http.read(&protocol::note_info_request(&url)?).await?;
        match protocol::parse_note_info_by_hash(&body, self.http.policy) {
            Ok(found) => Ok(Some(found)),
            Err(err) if is_gone(&err) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// File a seed-derived note the mint has confirmed: fetch it once by its
    /// spend to pin the mint's key and collect a certificate. Returns its
    /// amount.
    async fn add_key_note(
        &self,
        withdraw_link: &str,
        key: &KeyNote,
        amount_msat: u64,
    ) -> Result<u64> {
        let url = build_note_url(withdraw_link, &key.k1, Some(amount_msat))
            .ok_or_else(|| anyhow!("that withdraw link does not parse"))?;
        let id =
            lud25::note_id_of_url(&url).ok_or_else(|| anyhow!("the derived key is malformed"))?;
        let info = self.fetch_info(&url).await?;
        let amount = info.max_withdrawable;
        let certificate = self.checked_certificate(&url, &key.k1, amount, info.signature);
        let note = Note {
            url: with_new_k1(&url, &key.k1, amount, certificate.as_deref())
                .ok_or_else(|| anyhow!("that note URL does not parse"))?,
            amount_msat: amount,
            verified: true,
            status: NoteStatus::Live,
            added_at: now(),
            updated_at: now(),
            detail: None,
        };
        let mut store = self.store();
        if !store
            .data
            .note(&id)
            .is_some_and(|n| n.status != NoteStatus::Spent)
        {
            store.data.notes.retain(|n| n.id() != id);
            store.data.notes.push(note);
        }
        for pending in store
            .data
            .pending_mints
            .iter_mut()
            .filter(|m| m.output == key.output)
        {
            pending.state = MintState::Credited;
        }
        store.save()?;
        Ok(amount)
    }

    // ---- Lightning Address ----

    /// Register `username` at a trusted mint against this seed's branch
    /// there. The mint then mints a purpose-2 note for every payment to
    /// `username@<mint>`, and publishes the branch so wallets at the same
    /// mint can pay it by internal transfer.
    pub async fn register_address(&self, origin: &str, username: &str) -> Result<String> {
        let username = username.trim().to_ascii_lowercase();
        let valid = !username.is_empty()
            && username.len() <= 32
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
        if !valid {
            bail!("a username is 1-32 of a-z, 0-9, '_', '.' and '-'");
        }
        let url = self.address_proof_url(origin, &username, "register")?;
        let cx1 = self.branch_at(origin)?.cx1()?;
        let url = format!("{url}&cx1={cx1}");
        self.http.call(reqwest::Method::POST, &url).await?;
        let address = format!("{username}@{}", lnurlcash_core::server_of(origin));
        let mut store = self.store();
        store
            .data
            .addresses
            .retain(|a| !(a.origin == origin && a.username == username));
        store.data.addresses.push(Address {
            username,
            origin: origin.to_string(),
            registered_at: now(),
        });
        store.data.log(format!("Registered {address}"));
        store.save()?;
        Ok(format!(
            "Registered {address}: payments to it mint notes to your seed."
        ))
    }

    pub async fn unregister_address(&self, origin: &str, username: &str) -> Result<String> {
        let url = self.address_proof_url(origin, username, "unregister")?;
        self.http.call(reqwest::Method::DELETE, &url).await?;
        let mut store = self.store();
        store
            .data
            .addresses
            .retain(|a| !(a.origin == origin && a.username == username));
        store
            .data
            .log(format!("Unregistered {username} at {origin}"));
        store.save()?;
        Ok(format!(
            "{username} is released at {}.",
            lnurlcash_core::server_of(origin)
        ))
    }

    fn branch_at(&self, origin: &str) -> Result<keys::Branch> {
        let domain = lud25::domain_of(origin).ok_or_else(|| anyhow!("that mint has no host"))?;
        keys::Branch::derive(self.seed()?.as_ref(), &domain)
    }

    /// `{origin}/p/{username}?sig=...`: the reference mint's registration
    /// endpoint, proven by the branch's purpose-0 index-0 key over
    /// `LNURLcash:<action>:<domain>:<username>`.
    fn address_proof_url(&self, origin: &str, username: &str, action: &str) -> Result<String> {
        if !self.is_trusted(origin) {
            bail!("trust {origin} first");
        }
        let domain = lud25::domain_of(origin).ok_or_else(|| anyhow!("that mint has no host"))?;
        let identity = self
            .branch_at(origin)?
            .identity_key()
            .ok_or_else(|| anyhow!("this branch has no usable identity key"))?;
        let sig = lnurlcash_core::sign_address_proof(&identity, action, &domain, username)?;
        Ok(format!("{origin}/p/{username}?sig={}", hex::encode(sig)))
    }

    /// Look for notes the mint auto-minted to our registered addresses:
    /// purpose-2 keys from the counter onward.
    pub async fn check_addresses(&self) -> Result<String> {
        let seed = self.seed()?;
        let origins: Vec<String> = {
            let store = self.store();
            let mut origins: Vec<String> = store
                .data
                .addresses
                .iter()
                .map(|a| a.origin.clone())
                .collect();
            origins.dedup();
            origins
        };
        let mut found = Vec::new();
        for origin in origins {
            let Some(withdraw_link) = self
                .store()
                .data
                .mint(&origin)
                .map(|m| m.withdraw_link.clone())
            else {
                continue;
            };
            let (count, total) = self
                .scan_purpose(
                    seed.as_ref(),
                    &withdraw_link,
                    PURPOSE_ADDRESS,
                    ADDRESS_LOOKAHEAD,
                )
                .await?;
            if count > 0 {
                found.push(format!(
                    "Received {} sats to your address at {}.",
                    msat_to_sats(total),
                    lnurlcash_core::server_of(&origin)
                ));
            }
        }
        if !found.is_empty() {
            self.log(found.join(" "))?;
        }
        Ok(found.join(" "))
    }

    // ---- restore ----

    /// Walk every trusted mint - and every public one - asking by `?p=` about
    /// each key the seed derives, per purpose, until `GAP_LIMIT` unknown in
    /// a row. Found notes are added, their mints trusted, and the counters
    /// moved past them so no index is ever reused.
    pub async fn restore(&self) -> Result<String> {
        let seed = self.seed()?;
        let mut targets: Vec<(Option<String>, String)> = self
            .store()
            .data
            .mints
            .iter()
            .map(|m| (m.address.clone(), m.withdraw_link.clone()))
            .collect();
        let mut tasks = tokio::task::JoinSet::new();
        for address in self.public_mints.clone() {
            let wallet = self.clone();
            tasks.spawn(async move {
                let quote = wallet.quote_mint(&address).await;
                (address, quote)
            });
        }
        while let Some(joined) = tasks.join_next().await {
            if let Ok((address, Ok(quote))) = joined {
                if !targets
                    .iter()
                    .any(|(_, link)| origin_of(link) == quote.origin)
                {
                    targets.push((Some(address), quote.withdraw_link));
                }
            }
        }

        let mut scans = tokio::task::JoinSet::new();
        for (address, withdraw_link) in targets {
            let wallet = self.clone();
            let seed = seed.clone();
            scans.spawn(async move {
                let mut result = Ok((0usize, 0u64));
                for purpose in PURPOSES {
                    // a fresh scan starts every purpose at 0, whatever the counter
                    match wallet
                        .scan_from(seed.as_ref(), &withdraw_link, purpose, 0, GAP_LIMIT)
                        .await
                    {
                        Ok((count, total)) => {
                            if let Ok((c, t)) = &mut result {
                                *c += count;
                                *t += total;
                            }
                        }
                        Err(err) => {
                            result = Err(err);
                            break;
                        }
                    }
                }
                (address, withdraw_link, result)
            });
        }
        let (mut found, mut total, mut failures) = (0usize, 0u64, Vec::new());
        while let Some(joined) = scans.join_next().await {
            let Ok((address, withdraw_link, result)) = joined else {
                continue;
            };
            match result {
                Ok((count, msat)) if count > 0 => {
                    self.add_mint(
                        &origin_of(&withdraw_link),
                        address.as_deref(),
                        &withdraw_link,
                    )?;
                    found += count;
                    total += msat;
                }
                Ok(_) => {}
                Err(err) => failures.push(format!("{}: {err}", origin_of(&withdraw_link))),
            }
        }
        let mut message = format!(
            "Restore found {found} note{} worth {} sats.",
            if found == 1 { "" } else { "s" },
            msat_to_sats(total)
        );
        if !failures.is_empty() {
            message.push_str(&format!(" Couldn't finish: {}.", failures.join("; ")));
        }
        self.log(message.clone())?;
        Ok(message)
    }

    /// Scan one purpose from its saved counter onward.
    async fn scan_purpose(
        &self,
        seed: &[u8],
        withdraw_link: &str,
        purpose: u32,
        gap: u32,
    ) -> Result<(usize, u64)> {
        let domain = lud25::domain_of(withdraw_link).ok_or_else(|| anyhow!("no host"))?;
        let start = self
            .store()
            .data
            .counters
            .get(&domain)
            .map(|c| c[purpose as usize])
            .unwrap_or(0);
        self.scan_from(seed, withdraw_link, purpose, start, gap)
            .await
    }

    /// Ask about each key from `start` until `gap` unknown in a row; add
    /// what is found and move the counter past it.
    async fn scan_from(
        &self,
        seed: &[u8],
        withdraw_link: &str,
        purpose: u32,
        start: u32,
        gap: u32,
    ) -> Result<(usize, u64)> {
        let domain = lud25::domain_of(withdraw_link).ok_or_else(|| anyhow!("no host"))?;
        let (mut count, mut total) = (0usize, 0u64);
        let (mut index, mut misses, mut next_unused) = (start, 0u32, start);
        while misses < gap {
            if let Some(key) = keys::key_note(seed, &domain, purpose, index) {
                match self.lookup(withdraw_link, &key.output).await? {
                    Some(found) => {
                        total += self
                            .add_key_note(withdraw_link, &key, found.max_withdrawable)
                            .await?;
                        count += 1;
                        misses = 0;
                        next_unused = index + 1;
                    }
                    None => misses += 1,
                }
            }
            index += 1;
        }
        let mut store = self.store();
        let counter = store.data.counters.entry(domain).or_default();
        counter[purpose as usize] = counter[purpose as usize].max(next_unused);
        store.save()?;
        Ok((count, total))
    }

    // ---- local-only ----

    pub fn mark_sent(&self, id: &str) -> Result<()> {
        let amount = self.note(id)?.amount_msat;
        self.update_note(id, |n| {
            n.status = NoteStatus::Sent;
            n.detail = Some(
                "given away - Check to see if it was claimed, Take back to rotate it home".into(),
            );
        })?;
        self.log(format!(
            "Marked {} sats as given away",
            msat_to_sats(amount)
        ))
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        let mut store = self.store();
        match store.data.note(id) {
            Some(note) if note.status == NoteStatus::Spent => {}
            Some(_) => bail!("only a spent note can be removed"),
            None => bail!("no such note"),
        }
        store.data.notes.retain(|n| n.id() != id);
        store.save()
    }
}

/// A payRequest to pay into, rather than mint from. lnurlcash-core 0.2.0
/// refuses one that names a `withdrawLink` without room for a 64-character
/// comment - right for minting, but the reference mint's registered
/// Lightning Addresses send exactly that: they auto-mint to the registered
/// branch, so they take no comment. Paying one needs no comment either, so
/// that one refusal is read past, and the link kept for same-mint checks.
fn parse_pay_link(mut body: serde_json::Value) -> Result<protocol::PayRequestInfo> {
    match protocol::parse_pay_request(&body) {
        Err(Error::Protocol(reason)) if reason.contains("output commitment") => {
            let link = body.as_object_mut().and_then(|o| o.remove("withdrawLink"));
            let mut pay = protocol::parse_pay_request(&body)?;
            pay.withdraw_link = link.and_then(|l| l.as_str().map(str::to_string));
            Ok(pay)
        }
        other => Ok(other?),
    }
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// What minting at a mint needs, from its payRequest.
#[derive(Debug, Clone)]
pub struct MintQuote {
    pub address: String,
    pub origin: String,
    pub withdraw_link: String,
    pub callback: String,
    pub min_msat: u64,
    pub max_msat: u64,
    pub fee: Option<lnurlcash_core::MintFee>,
}

/// How a note is handed over: the LUD-17 link to copy, and an uppercase
/// bech32 LNURL for the QR code (alphanumeric mode, the densest).
pub fn export_forms(note: &Note) -> (String, String) {
    let link = to_lud17w(&note.url);
    let qr = to_bech32_lnurl(&note.url)
        .map(|s| s.to_ascii_uppercase())
        .unwrap_or_else(|| link.clone());
    (link, qr)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::mock_mint::{MockMint, State, KEY_B};
    use crate::store::KdfParams;
    use crate::store::MintState;

    const FAST: KdfParams = KdfParams {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
    };
    const PASSWORD: &str = "test password";

    struct Fixture {
        mint: MockMint,
        wallet: Wallet,
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
    }

    async fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let store = Store::create_with_params(&path, PASSWORD, FAST).unwrap();
        let wallet = Wallet::new(store, Http::new(Duration::from_secs(5)));
        wallet.set_seed(&keys::generate_phrase()).unwrap();
        Fixture {
            mint: MockMint::start().await,
            wallet,
            _dir: dir,
            path,
        }
    }

    impl Fixture {
        fn only_note(&self) -> Note {
            let store = self.wallet.store();
            assert_eq!(store.data.notes.len(), 1, "expected exactly one note");
            store.data.notes[0].clone()
        }

        fn reopened(&self) -> Store {
            Store::open(&self.path, PASSWORD).unwrap()
        }
    }

    #[tokio::test]
    async fn receiving_rotates_the_sender_out() {
        let f = fixture().await;
        let sent = f.mint.issue(21_000);
        let message = f.wallet.receive(&sent, true).await.unwrap();
        assert!(message.contains("rotated"), "{message}");

        let note = f.only_note();
        assert_eq!(
            (note.amount_msat, note.status, note.verified),
            (21_000, NoteStatus::Live, true)
        );
        assert!(
            note.detail.is_none(),
            "every certificate verified: {:?}",
            note.detail
        );
        let certificate =
            lnurlcash_core::note_signature(&note.url).expect("the rotated note is certified");
        assert!(verify_note_signature(
            &note.k1(),
            crate::mock_mint::DOMAIN,
            21_000,
            &certificate,
            crate::mock_mint::KEY_A
        ));
        assert_ne!(note.k1(), note_k1(&sent).unwrap());
        assert_eq!(
            f.mint.state_of(&note_k1(&sent).unwrap()),
            Some(State::Burned)
        );
        assert_eq!(f.mint.state_of(&note.k1()), Some(State::Live));

        let saved = f.reopened();
        assert_eq!(
            saved.data.notes[0].k1(),
            note.k1(),
            "the rotated note is on disk"
        );
        assert_eq!(saved.data.journal[0].state, JournalState::Done);
        assert_eq!(saved.data.mint_keys.len(), 1, "the mint key is pinned");

        assert!(
            f.wallet.receive(&sent, true).await.is_err(),
            "the sender's copy is dead"
        );
    }

    #[tokio::test]
    async fn a_lost_answer_is_retried_and_replayed() {
        let f = fixture().await;
        f.mint.with(|m| {
            m.drop_after_apply = 1;
            m.replay = true;
        });
        f.wallet.receive(&f.mint.issue(5_000), true).await.unwrap();
        let note = f.only_note();
        assert_eq!(note.status, NoteStatus::Live);
        assert_eq!(f.mint.state_of(&note.k1()), Some(State::Live));
    }

    #[tokio::test]
    async fn a_rotate_that_landed_unanswered_is_recovered_from_disk() {
        let f = fixture().await;
        let sent = f.mint.issue(8_000);
        // applied, then both the attempt and its retry lose their answer
        f.mint.with(|m| m.drop_after_apply = 2);
        let message = f.wallet.receive(&sent, true).await.unwrap();
        assert!(message.contains("unknown"), "{message}");
        let note = f.only_note();
        assert_eq!(note.status, NoteStatus::Uncertain);

        // the new spend reached disk before its cp1 left the process
        let saved = f.reopened();
        let pending = &saved.data.journal[0];
        assert_eq!(pending.state, JournalState::Pending);
        let spend = pending.outputs[0].k1.clone().unwrap();
        assert_eq!(
            f.mint.state_of(&spend),
            Some(State::Live),
            "it IS the money"
        );

        let message = f.wallet.resolve(&note.id()).await.unwrap();
        assert!(message.contains("did land"), "{message}");
        let note = f.only_note();
        assert_eq!((note.status, note.verified), (NoteStatus::Live, true));
        assert_eq!(note.k1(), spend);
    }

    #[tokio::test]
    async fn a_rotate_that_never_landed_keeps_the_original() {
        let f = fixture().await;
        let sent = f.mint.issue(8_000);
        f.mint.with(|m| m.drop_before_apply = 2);
        f.wallet.receive(&sent, true).await.unwrap();
        let note = f.only_note();
        assert_eq!(note.status, NoteStatus::Uncertain);

        f.wallet.resolve(&note.id()).await.unwrap();
        let note = f.only_note();
        assert_eq!(note.status, NoteStatus::Live);
        assert_eq!(note.k1(), note_k1(&sent).unwrap());
        let saved = f.reopened();
        assert_eq!(
            saved.data.journal[0].state,
            JournalState::Failed,
            "kept, not deleted"
        );

        f.wallet.rotate(&note.id()).await.unwrap();
        assert_ne!(f.only_note().k1(), note_k1(&sent).unwrap());
    }

    #[tokio::test]
    async fn melting_is_in_flight_until_the_mint_says_otherwise() {
        let f = fixture().await;
        f.wallet.receive(&f.mint.issue(10_000), true).await.unwrap();
        let id = f.only_note().id();

        let err = f.wallet.melt(&id, "lnbcrt200n1pqqqqqq").await.unwrap_err();
        assert!(err.to_string().contains("exactly"), "{err}");
        let err = f.wallet.melt(&id, "lnbcrt1pqqqqqq").await.unwrap_err();
        assert!(err.to_string().contains("amountless"), "{err}");
        assert_eq!(f.only_note().status, NoteStatus::Live);

        f.wallet
            .melt(&id, "lightning:lnbcrt100n1pqqqqqq")
            .await
            .unwrap();
        assert_eq!(f.only_note().status, NoteStatus::Melting);
        f.wallet.check(&id).await.unwrap();
        assert_eq!(
            f.only_note().status,
            NoteStatus::Melting,
            "pending is not spent"
        );

        f.mint.finish_melts(false);
        let message = f.wallet.check(&id).await.unwrap();
        assert!(message.contains("failed"), "{message}");
        assert_eq!(f.only_note().status, NoteStatus::Live);

        f.wallet.melt(&id, "lnbcrt100n1pqqqqqq").await.unwrap();
        f.mint.finish_melts(true);
        let message = f.wallet.check(&id).await.unwrap();
        assert!(message.contains("settled"), "{message}");
        assert_eq!(f.only_note().status, NoteStatus::Spent);
        f.wallet.remove(&id).unwrap();
        assert!(f.wallet.store().data.notes.is_empty());
    }

    #[tokio::test]
    async fn melts_to_a_lightning_address() {
        let f = fixture().await;
        f.wallet.receive(&f.mint.issue(12_000), true).await.unwrap();
        let id = f.only_note().id();
        let address = format!("alice@{}", f.mint.base.trim_start_matches("http://"));
        f.wallet.melt(&id, &address).await.unwrap();
        assert_eq!(f.only_note().status, NoteStatus::Melting);
    }

    #[tokio::test]
    async fn a_changed_mint_key_is_refused() {
        let f = fixture().await;
        f.wallet.receive(&f.mint.issue(3_000), true).await.unwrap();
        let id = f.only_note().id();
        f.mint.with(|m| m.key = KEY_B.into());

        let err = f.wallet.rotate(&id).await.unwrap_err();
        assert!(err.to_string().contains("pinned"), "{err}");
        assert!(f.wallet.receive(&f.mint.issue(3_000), true).await.is_err());

        let origin = f
            .wallet
            .store()
            .data
            .mint_keys
            .keys()
            .next()
            .unwrap()
            .clone();
        f.wallet.unpin_mint(&origin).unwrap();
        f.wallet.rotate(&id).await.unwrap();
    }

    #[tokio::test]
    async fn a_sent_note_can_be_taken_back_or_seen_claimed() {
        let f = fixture().await;
        f.wallet.receive(&f.mint.issue(4_000), true).await.unwrap();
        let note = f.only_note();
        f.wallet.mark_sent(&note.id()).unwrap();
        let message = f.wallet.rotate(&note.id()).await.unwrap();
        assert!(message.contains("Took back"), "{message}");
        assert_eq!(f.only_note().status, NoteStatus::Live);

        // hand it over again, and this time the recipient claims it
        let note = f.only_note();
        f.wallet.mark_sent(&note.id()).unwrap();
        let (link, qr) = export_forms(&note);
        assert!(
            link.starts_with("lnurlw://") || link.starts_with("http"),
            "{link}"
        );
        assert_eq!(
            lud25::resolve_note_input(&qr).as_deref().and_then(note_k1),
            Some(note.k1())
        );

        let recipient = fixture().await;
        recipient.wallet.receive(&qr, true).await.unwrap();
        let message = f.wallet.check(&note.id()).await.unwrap();
        assert!(message.contains("claimed"), "{message}");
        assert_eq!(f.only_note().status, NoteStatus::Spent);
    }

    #[tokio::test]
    async fn rotated_notes_are_seed_keys() {
        let f = fixture().await;
        f.wallet.receive(&f.mint.issue(7_000), true).await.unwrap();
        let note = f.only_note();
        assert!(note.k1().starts_with("ck1"), "{}", note.k1());
        let phrase = f.wallet.seed_phrase().unwrap();
        let seed = keys::seed_of(&phrase).unwrap();
        let expected = keys::key_note(seed.as_ref(), crate::mock_mint::DOMAIN, 0, 0).unwrap();
        assert_eq!(note.k1(), expected.k1, "the first wallet-purpose key");
        assert_eq!(
            f.reopened().data.counters[crate::mock_mint::DOMAIN],
            [1, 0, 0]
        );
    }

    #[tokio::test]
    async fn an_untrusted_mint_needs_a_yes() {
        let f = fixture().await;
        let note = f.mint.issue(2_000);
        let err = f.wallet.receive(&note, false).await.unwrap_err();
        assert!(err.downcast_ref::<UntrustedMint>().is_some(), "{err}");
        assert!(f.wallet.store().data.notes.is_empty());
        assert_eq!(
            f.mint.state_of(&note_k1(&note).unwrap()),
            Some(State::Live),
            "nothing sent"
        );

        f.wallet.receive(&note, true).await.unwrap();
        assert_eq!(f.wallet.store().data.mints.len(), 1);
        f.wallet.receive(&f.mint.issue(2_000), false).await.unwrap();
        assert_eq!(f.wallet.store().data.notes.len(), 2);
        assert!(
            f.wallet.untrust_mint(&origin_of(&f.mint.base)).is_err(),
            "still holding notes"
        );
    }

    #[tokio::test]
    async fn mints_a_note_once_the_invoice_is_paid() {
        let f = fixture().await;
        let message = f
            .wallet
            .start_mint(&f.mint.address(), 50_000)
            .await
            .unwrap();
        assert!(message.contains("50"), "{message}");
        let pending = f.reopened().data.pending_mints[0].clone();
        assert_eq!(pending.state, MintState::Waiting);
        assert_eq!(
            pending.pr.as_deref().map(decode_bolt11_amount_msat),
            Some(Some(50_000))
        );
        assert_eq!(
            f.wallet.store().data.mints.len(),
            1,
            "minting there trusts it"
        );

        assert!(f.wallet.poll_mint(&pending.output).await.unwrap().is_none());
        f.mint.pay_invoices();
        let message = f.wallet.poll_mint(&pending.output).await.unwrap().unwrap();
        assert!(message.contains("Minted 50 sats"), "{message}");
        let note = f.only_note();
        assert_eq!((note.amount_msat, note.status), (50_000, NoteStatus::Live));
        assert_eq!(note.k1(), pending.k1);
        let certificate = lnurlcash_core::note_signature(&note.url).expect("certified");
        assert!(verify_note_signature(
            &note.k1(),
            crate::mock_mint::DOMAIN,
            50_000,
            &certificate,
            crate::mock_mint::KEY_A
        ));
        assert_eq!(
            f.wallet.store().data.pending_mints[0].state,
            MintState::Credited
        );
        assert!(f.wallet.poll_mint(&pending.output).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_seed_restores_its_notes_and_counters() {
        let f = fixture().await;
        f.wallet.start_mint(&f.mint.address(), 9_000).await.unwrap();
        f.mint.pay_invoices();
        let output = f.wallet.store().data.pending_mints[0].output.clone();
        f.wallet.poll_mint(&output).await.unwrap().unwrap();
        f.wallet.receive(&f.mint.issue(4_000), true).await.unwrap();
        // rotate the minted note twice: indices 0 (mint), 1 (receive), 2, 3
        let minted = f.wallet.store().data.notes[0].id();
        f.wallet.rotate(&minted).await.unwrap();
        let minted = f.wallet.store().data.notes[0].id();
        f.wallet.rotate(&minted).await.unwrap();
        let held: Vec<String> = f.wallet.store().data.notes.iter().map(Note::k1).collect();

        let restored = {
            let dir = tempfile::tempdir().unwrap();
            let store =
                Store::create_with_params(&dir.path().join("r.json"), PASSWORD, FAST).unwrap();
            let wallet =
                Wallet::new(store, Http::new(Duration::from_secs(5))).without_public_mints();
            wallet.set_seed(&f.wallet.seed_phrase().unwrap()).unwrap();
            // the mock isn't a public mint: trust it so the restore looks there
            wallet.trust_mint(&f.mint.address()).await.unwrap();
            let message = wallet.restore().await.unwrap();
            assert!(message.contains("2 notes worth 13 sats"), "{message}");
            let mut found: Vec<String> = wallet.store().data.notes.iter().map(Note::k1).collect();
            found.sort();
            assert_eq!(wallet.store().data.counters[crate::mock_mint::DOMAIN][0], 4);
            found
        };
        let mut held = held;
        held.sort();
        assert_eq!(restored, held);
    }

    #[tokio::test]
    async fn skips_an_index_the_mint_already_knows() {
        let f = fixture().await;
        f.wallet.receive(&f.mint.issue(1_000), true).await.unwrap();

        // the same seed on a second device, whose counter is still at 0
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create_with_params(&dir.path().join("b.json"), PASSWORD, FAST).unwrap();
        let twin = Wallet::new(store, Http::new(Duration::from_secs(5)));
        twin.set_seed(&f.wallet.seed_phrase().unwrap()).unwrap();
        twin.receive(&f.mint.issue(1_000), true).await.unwrap();
        let note = twin.store().data.notes[0].clone();
        let seed = keys::seed_of(&f.wallet.seed_phrase().unwrap()).unwrap();
        let second = keys::key_note(seed.as_ref(), crate::mock_mint::DOMAIN, 0, 1).unwrap();
        assert_eq!(note.k1(), second.k1, "index 0 was in use, so index 1");
        assert_eq!(twin.store().data.journal[0].state, JournalState::Failed);
    }

    /// A funded wallet at the fixture's mint: one note per amount, each
    /// already rotated onto a seed key.
    async fn funded(amounts: &[u64]) -> Fixture {
        let f = fixture().await;
        for amount in amounts {
            f.wallet
                .receive(&f.mint.issue(*amount), true)
                .await
                .unwrap();
        }
        f
    }

    fn origin(f: &Fixture) -> String {
        origin_of(&f.mint.base)
    }

    fn live_amounts(wallet: &Wallet) -> Vec<u64> {
        let mut amounts: Vec<u64> = wallet
            .store()
            .data
            .notes
            .iter()
            .filter(|n| n.status == NoteStatus::Live)
            .map(|n| n.amount_msat)
            .collect();
        amounts.sort();
        amounts
    }

    #[tokio::test]
    async fn merges_every_note_at_a_mint() {
        let f = funded(&[3_000, 4_000, 5_000]).await;
        let message = f.wallet.merge_all(&origin(&f)).await.unwrap();
        assert!(message.contains("3 notes into one of 12 sats"), "{message}");
        assert_eq!(live_amounts(&f.wallet), vec![12_000]);
        let note = f.only_note();
        assert!(note.verified && note.detail.is_none(), "{:?}", note.detail);
        assert_eq!(f.mint.state_of(&note.k1()), Some(State::Live));
    }

    #[tokio::test]
    async fn carves_an_exact_note_with_change() {
        let f = funded(&[10_000, 4_000]).await;
        f.mint.with(|m| m.base_fee_msat = 1_000);
        let id = f.wallet.note_for_amount(&origin(&f), 7_000).await.unwrap();
        assert_eq!(f.wallet.note(&id).unwrap().amount_msat, 7_000);
        // the 10 sat note split into 7 + 3, less the 1 sat fee on the change
        assert_eq!(live_amounts(&f.wallet), vec![2_000, 4_000, 7_000]);
        let change = f
            .wallet
            .store()
            .data
            .notes
            .iter()
            .find(|n| n.amount_msat == 2_000)
            .cloned()
            .unwrap();
        assert!(change.verified, "the change amount came from the mint");

        // more than one note needed: both go into the split
        let id = f.wallet.note_for_amount(&origin(&f), 12_000).await.unwrap();
        assert_eq!(f.wallet.note(&id).unwrap().amount_msat, 12_000);
        assert!(f.wallet.note_for_amount(&origin(&f), 50_000).await.is_err());
    }

    #[tokio::test]
    async fn pays_any_amount_by_splitting_then_melting() {
        let f = funded(&[10_000]).await;
        let message = f
            .wallet
            .pay(&origin(&f), "lnbcrt60n1pqqqqqq", None)
            .await
            .unwrap();
        assert!(message.contains("6 sats is in flight"), "{message}");
        let melting: Vec<u64> = f
            .wallet
            .store()
            .data
            .notes
            .iter()
            .filter(|n| n.status == NoteStatus::Melting)
            .map(|n| n.amount_msat)
            .collect();
        assert_eq!(melting, vec![6_000]);
        assert_eq!(live_amounts(&f.wallet), vec![4_000]);

        // a Lightning Address with no branch gets a Lightning invoice
        f.wallet
            .pay(&origin(&f), &f.mint.address_of("carol"), Some(4_000))
            .await
            .unwrap();
        assert!(live_amounts(&f.wallet).is_empty());
    }

    #[tokio::test]
    async fn registers_an_address_and_finds_what_it_is_paid() {
        let f = fixture().await;
        f.wallet.trust_mint(&f.mint.address()).await.unwrap();
        let message = f
            .wallet
            .register_address(&origin(&f), "Alice")
            .await
            .unwrap();
        assert!(message.contains("alice@"), "{message}");
        assert!(f.mint.with(|m| m.usernames.contains_key("alice")));

        // someone pays alice@mint twice over Lightning
        let pay = parse_pay_link(
            f.wallet
                .http
                .read(
                    &protocol::pay_request_request(
                        &resolve_lnurl_input(&f.mint.address_of("alice")).unwrap(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        for amount in [2_000, 3_000] {
            f.wallet
                .http
                .read(&protocol::invoice_request(&pay.callback, amount).unwrap())
                .await
                .unwrap();
        }
        f.mint.pay_invoices();
        let message = f.wallet.check_addresses().await.unwrap();
        assert!(message.contains("5 sats"), "{message}");
        assert_eq!(live_amounts(&f.wallet), vec![2_000, 3_000]);
        assert_eq!(
            f.wallet.store().data.counters[crate::mock_mint::DOMAIN][2],
            2
        );
        assert!(
            f.wallet.check_addresses().await.unwrap().is_empty(),
            "nothing new"
        );

        f.wallet
            .unregister_address(&origin(&f), "alice")
            .await
            .unwrap();
        assert!(!f.mint.with(|m| m.usernames.contains_key("alice")));
        assert!(f.wallet.store().data.addresses.is_empty());
    }

    #[tokio::test]
    async fn pays_a_registered_address_at_the_same_mint_internally() {
        let bob = fixture().await;
        bob.wallet.trust_mint(&bob.mint.address()).await.unwrap();
        bob.wallet
            .register_address(&origin(&bob), "bob")
            .await
            .unwrap();

        // alice holds notes at the same mint
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create_with_params(&dir.path().join("a.json"), PASSWORD, FAST).unwrap();
        let alice = Wallet::new(store, Http::new(Duration::from_secs(5)));
        alice.set_seed(&keys::generate_phrase()).unwrap();
        alice.receive(&bob.mint.issue(10_000), true).await.unwrap();

        let message = alice
            .pay(&origin(&bob), &bob.mint.address_of("bob"), Some(6_000))
            .await
            .unwrap();
        assert!(message.contains("inside the mint"), "{message}");
        assert_eq!(live_amounts(&alice), vec![4_000], "change came back");
        assert!(
            bob.mint.with(|m| m.unpaid_to_address.is_empty()),
            "no Lightning invoice"
        );
        assert_eq!(bob.mint.address_balance("bob"), 6_000);

        // exact amount: the whole note goes over as a rotate
        alice
            .pay(&origin(&bob), &bob.mint.address_of("bob"), Some(4_000))
            .await
            .unwrap();
        assert!(live_amounts(&alice).is_empty());

        bob.wallet.check_addresses().await.unwrap();
        assert_eq!(live_amounts(&bob.wallet), vec![4_000, 6_000]);
    }

    #[tokio::test]
    async fn a_lost_split_answer_is_resolved_from_the_journal() {
        let f = funded(&[10_000]).await;
        f.mint.with(|m| m.drop_after_apply = 2);
        let err = f
            .wallet
            .note_for_amount(&origin(&f), 3_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown"), "{err}");
        let uncertain = f.only_note();
        assert_eq!(uncertain.status, NoteStatus::Uncertain);

        f.wallet.resolve(&uncertain.id()).await.unwrap();
        assert_eq!(live_amounts(&f.wallet), vec![3_000, 7_000]);
        assert!(f.wallet.store().data.notes.iter().all(|n| n.verified));
    }
}
