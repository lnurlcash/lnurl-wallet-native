//! The wallet end to end against a running lnurl-mint, the reference SERVICE
//! for the current draft. Opt-in: point `LNURL_MINT_URL` at a mint exposing
//! the dev-only `/_dev/issue`, `/_dev/invoice`, `/_dev/settle` and `/_dev/fail_payments` hooks
//! (lnurl-mint's test FakeNode behind its real server), then
//!
//! ```sh
//! LNURL_MINT_URL=http://127.0.0.1:8977 cargo test reference_mint -- --ignored --test-threads=1
//! ```

use std::time::Duration;

use serde_json::Value;

use crate::http::Http;
use crate::lud25;
use crate::store::{KdfParams, Note, NoteStatus, Store};
use crate::wallet::Wallet;

fn base() -> String {
    std::env::var("LNURL_MINT_URL").expect("set LNURL_MINT_URL to a dev lnurl-mint")
}

async fn get(url: &str) -> Value {
    serde_json::from_str(&reqwest::get(url).await.unwrap().text().await.unwrap()).unwrap()
}

async fn issue(amount_msat: u64) -> String {
    let body = get(&format!("{}/_dev/issue?amount={amount_msat}", base())).await;
    body["note"].as_str().unwrap().to_string()
}

/// A validly signed bolt11 for exactly `amount_msat` from some other node:
/// the mint refuses to melt into an invoice it issued itself.
async fn invoice(amount_msat: u64) -> String {
    let body = get(&format!("{}/_dev/invoice?amount={amount_msat}", base())).await;
    body["pr"].as_str().unwrap().to_string()
}

fn wallet() -> (Wallet, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let fast = KdfParams {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
    };
    let store = Store::create_with_params(&dir.path().join("w.json"), "reference", fast).unwrap();
    let wallet = Wallet::new(store, Http::new(Duration::from_secs(10)));
    wallet.set_seed(&crate::keys::generate_phrase()).unwrap();
    (wallet, dir)
}

fn only(wallet: &Wallet) -> Note {
    let store = wallet.store();
    assert_eq!(store.data.notes.len(), 1);
    store.data.notes[0].clone()
}

async fn check_until(wallet: &Wallet, id: &str, status: NoteStatus) {
    for _ in 0..50 {
        wallet.check(id).await.unwrap();
        if only(wallet).status == status {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never reached {status:?}: {:?}", only(wallet));
}

#[tokio::test]
#[ignore]
async fn receives_rotates_and_melts() {
    let (wallet, _dir) = wallet();
    let sent = issue(21_000).await;
    let message = wallet.receive(&sent, true).await.unwrap();
    assert!(message.contains("rotated"), "{message}");
    let note = only(&wallet);
    assert_eq!((note.amount_msat, note.status), (21_000, NoteStatus::Live));
    assert!(
        note.detail.is_none(),
        "certificates verified: {:?}",
        note.detail
    );
    let key = wallet
        .store()
        .data
        .mint_keys
        .values()
        .next()
        .unwrap()
        .clone();
    let cs1 = lnurlcash_core::note_signature(&note.url).expect("the rotated note is certified");
    assert!(lnurlcash_core::verify_note_signature(
        &note.k1(),
        "127.0.0.1",
        21_000,
        &cs1,
        &key
    ));
    assert!(
        wallet.receive(&sent, true).await.is_err(),
        "the sender's copy is dead"
    );

    wallet.rotate(&note.id()).await.unwrap();
    let note = only(&wallet);
    wallet
        .melt(&note.id(), &invoice(21_000).await)
        .await
        .unwrap();
    check_until(&wallet, &note.id(), NoteStatus::Spent).await;
}

#[tokio::test]
#[ignore]
async fn a_failed_melt_releases_the_note() {
    let (wallet, _dir) = wallet();
    wallet.receive(&issue(5_000).await, true).await.unwrap();
    let id = only(&wallet).id();
    get(&format!("{}/_dev/fail_payments?on=true", base())).await;
    // accepted: OK means in flight, and the payment then fails
    let result = wallet.melt(&id, &invoice(5_000).await).await;
    get(&format!("{}/_dev/fail_payments?on=false", base())).await;
    result.unwrap();
    check_until(&wallet, &id, NoteStatus::Live).await;
    wallet.rotate(&id).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn resolves_a_lost_rotate_by_p_lookup() {
    let (wallet, _dir) = wallet();
    wallet.receive(&issue(8_000).await, true).await.unwrap();
    let before = only(&wallet);

    // Rotate behind the wallet's back onto a key it journaled as pending,
    // exactly the state a rotate whose answer was lost leaves behind.
    let key = wallet.next_key_note("127.0.0.1", 0).unwrap();
    let fresh = key.k1.clone();
    let info = get(&before.url).await;
    let request = lnurlcash_core::protocol::rotate_request_with_hash(
        info["callback"].as_str().unwrap(),
        &before.k1(),
        &key.output,
    )
    .unwrap();
    assert_eq!(get(&request.url).await["status"], "OK");
    {
        let mut store = wallet.store();
        store.data.journal.push(crate::store::Mutation {
            id: "lost".into(),
            op: "rotate".into(),
            withdraw_link: lud25::withdraw_link_of(&before.url).unwrap(),
            inputs: vec![crate::store::JournalInput {
                id: before.id(),
                url: before.url.clone(),
                amount_msat: 8_000,
            }],
            outputs: vec![crate::store::JournalOutput {
                output: key.output.clone(),
                k1: Some(fresh.clone()),
                expected_msat: 8_000,
                recipient: None,
            }],
            split_msat: None,
            state: crate::store::JournalState::Pending,
            created_at: 0,
        });
        store.data.note_mut(&before.id()).unwrap().status = NoteStatus::Uncertain;
    }

    let message = wallet.resolve(&before.id()).await.unwrap();
    assert!(message.contains("did land"), "{message}");
    let note = only(&wallet);
    assert_eq!(
        (note.k1(), note.verified, note.amount_msat),
        (fresh, true, 8_000)
    );
}

fn address() -> String {
    format!("mint@{}", base().trim_start_matches("http://"))
}

#[tokio::test]
#[ignore]
async fn mints_rotates_and_restores_seed_keys() {
    let (wallet, _dir) = wallet();
    wallet.start_mint(&address(), 30_000).await.unwrap();
    let pending = wallet.store().data.pending_mints[0].clone();
    assert!(
        wallet.poll_mint(&pending.output).await.unwrap().is_none(),
        "unpaid"
    );
    get(&format!(
        "{}/_dev/settle?pr={}",
        base(),
        pending.pr.clone().unwrap()
    ))
    .await;
    let message = wallet
        .poll_mint(&pending.output)
        .await
        .unwrap()
        .expect("credited once paid");
    assert!(message.contains("Minted"), "{message}");
    let note = only(&wallet);
    assert!(note.k1().starts_with("ck1"));
    assert!(
        lnurlcash_core::note_signature(&note.url).is_some(),
        "certified"
    );

    // the real mint accepts the ck1 as a spend, and credits the next key
    wallet.rotate(&note.id()).await.unwrap();
    let rotated = only(&wallet);
    assert!(rotated.detail.is_none(), "{:?}", rotated.detail);
    assert!(
        lnurlcash_core::note_signature(&rotated.url).is_some(),
        "certified"
    );

    let dir = tempfile::tempdir().unwrap();
    let fast = KdfParams {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
    };
    let store = Store::create_with_params(&dir.path().join("r.json"), "reference", fast).unwrap();
    let restored = Wallet::new(store, Http::new(Duration::from_secs(10))).without_public_mints();
    restored.set_seed(&wallet.seed_phrase().unwrap()).unwrap();
    restored.trust_mint(&address()).await.unwrap();
    let message = restored.restore().await.unwrap();
    assert!(message.contains("found 1 note"), "{message}");
    assert_eq!(only(&restored).k1(), rotated.k1());
    assert_eq!(restored.store().data.counters["127.0.0.1"][0], 2);
}

fn origin() -> String {
    crate::wallet::origin_of(&base())
}

#[tokio::test]
#[ignore]
async fn splits_registers_and_transfers_internally() {
    let (alice, _a) = wallet();
    alice.receive(&issue(20_000).await, true).await.unwrap();

    // any amount: the real mint splits off exactly 7 sats, change comes back
    let id = alice.note_for_amount(&origin(), 7_000).await.unwrap();
    let mut amounts: Vec<u64> = alice
        .store()
        .data
        .notes
        .iter()
        .map(|n| n.amount_msat)
        .collect();
    amounts.sort();
    assert_eq!(
        alice
            .store()
            .data
            .notes
            .iter()
            .find(|n| n.id() == id)
            .unwrap()
            .amount_msat,
        7_000
    );
    // the dev mint charges no fee, so the change is the rest
    assert_eq!(amounts, vec![7_000, 13_000]);

    // bob registers a random username against his seed at the same mint
    let (bob, _b) = wallet();
    bob.trust_mint(&address()).await.unwrap();
    let username = format!("bob{}", hex::encode(rand::random::<[u8; 3]>()));
    bob.register_address(&origin(), &username).await.unwrap();

    // alice pays bob@mint: the mint's text/cpub turns it into a transfer
    let bob_address = format!("{username}@{}", base().trim_start_matches("http://"));
    let message = alice
        .pay(&origin(), &bob_address, Some(5_000))
        .await
        .unwrap();
    assert!(message.contains("inside the mint"), "{message}");

    let found = bob.check_addresses().await.unwrap();
    assert!(found.contains("5 sats"), "{found}");
    assert_eq!(only(&bob).amount_msat, 5_000);
    assert!(only(&bob).k1().starts_with("ck1"));

    bob.unregister_address(&origin(), &username).await.unwrap();
}
