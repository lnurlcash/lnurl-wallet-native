//! A minimal LUD-25 mint over raw TCP, for tests, speaking the current draft
//! (`luds/25.md`) through lnurlcash-core: notes filed by their output key
//! `Q`, spent by a hex preimage or a `ck1` bound to this mint's domain;
//! rotate, split and merge onto `p1`/`p2` with the draft's split and merge
//! fees; `?p=` lookups; `c`/`c2` certificates with a real key; minting
//! through a pay link whose comment names the output; and registered
//! Lightning Addresses that auto-mint to a branch and advertise it as
//! `text/cpub`. Plus hooks to misbehave the ways that cost wallets money.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use lnurlcash_core::recoverable::{
    decode_cx1, derive_note_pubkey, encode_cs1_with_amount, encode_cx1, Cx1,
    PURPOSE_LIGHTNING_ADDRESS, PURPOSE_WALLET,
};
use lnurlcash_core::{
    address_proof_digest, check_spend, decode_bolt11_amount_msat, decode_note, generate_note_secret,
};
use secp256k1::{schnorr, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// luds/25.md test vector 4's SERVICE key, and its public half.
const SIGNING_KEY: &str = "a8358061952ee158b42ffe1607c00adda3e63098247f837f08a4ef9492b4f798";
pub const KEY_A: &str = "035acdbd57663f858be6d61ec4bfcbc99492699010f1451e30a6550f26295e813d";
/// Some other valid key, for a mint that changes the one it presents.
pub const KEY_B: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
/// The domain a spend here must be signed for.
pub const DOMAIN: &str = "127.0.0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Live,
    Melting,
    Burned,
}

#[derive(Debug, Default)]
pub struct Mint {
    /// hex(Q) -> (amount, state)
    pub notes: HashMap<String, (u64, State)>,
    pub key: String,
    /// The draft's split/merge fee: taken from a split's change, refunded
    /// per extra input into a merge.
    pub base_fee_msat: u64,
    /// Apply the next N mutations, then drop the connection unanswered.
    pub drop_after_apply: u32,
    /// Drop the next N mutations unanswered WITHOUT applying them.
    pub drop_before_apply: u32,
    /// LUD-25 replay: answer a byte-identical retried mutation with OK.
    pub replay: bool,
    /// Mint invoices issued and not yet paid: hex(Q) -> amount.
    pub unpaid: HashMap<String, u64>,
    /// Payments to registered addresses not yet paid: username -> amounts.
    pub unpaid_to_address: Vec<(String, u64)>,
    /// username -> (branch, next index hint)
    pub usernames: HashMap<String, (Cx1, u32)>,
    mutations: HashSet<String>,
}

/// The draft's certificate: recoverable ECDSA over the Lightning signed
/// message `LNURLcash:<amount>:<hex(Q)>`, as `cs1`.
fn certify(q: &str, amount_msat: u64) -> String {
    let message = format!("LNURLcash:{amount_msat}:{q}");
    let inner =
        Sha256::digest([b"Lightning Signed Message:".as_slice(), message.as_bytes()].concat());
    let digest: [u8; 32] = Sha256::digest(inner).into();
    let key = SecretKey::from_slice(&hex::decode(SIGNING_KEY).unwrap()).unwrap();
    let (recovery, compact) = Secp256k1::signing_only()
        .sign_ecdsa_recoverable(&Message::from_digest(digest), &key)
        .serialize_compact();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&compact);
    signature[64] = recovery.to_i32() as u8;
    encode_cs1_with_amount(amount_msat, &signature)
}

/// hex(Q) a spend opens here, if it does.
fn spend_q(k1: &str) -> Option<String> {
    let check = check_spend(k1, DOMAIN)?;
    check.verdict.opens().then(|| hex::encode(check.output_key))
}

/// hex(Q) an output names: a `cp1<Q>`, or a hex `h` (the short form).
fn output_q(value: &str) -> Option<String> {
    decode_note(value).map(hex::encode)
}

/// An address proof by the branch's purpose-0 index-0 key.
fn proven(cx1: &Cx1, action: &str, username: &str, sig: &str) -> bool {
    let Ok(pk) = derive_note_pubkey(&cx1.pubkey_x_only, &cx1.chain_code, PURPOSE_WALLET, 0) else {
        return false;
    };
    let (Ok(key), Ok(digest)) = (
        XOnlyPublicKey::from_slice(&pk),
        address_proof_digest(action, DOMAIN, username),
    ) else {
        return false;
    };
    let Some(sig) = hex::decode(sig)
        .ok()
        .and_then(|s| schnorr::Signature::from_slice(&s).ok())
    else {
        return false;
    };
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &Message::from_digest(digest), &key)
        .is_ok()
}

#[derive(Clone)]
pub struct MockMint {
    pub base: String,
    pub state: Arc<Mutex<Mint>>,
}

impl MockMint {
    pub async fn start() -> MockMint {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(Mint {
            key: KEY_A.into(),
            ..Mint::default()
        }));
        let mint = MockMint {
            base: base.clone(),
            state: state.clone(),
        };
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let state = state.clone();
                let base = base.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let mut len = 0;
                    while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buf[len..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => len += n,
                        }
                    }
                    let head = String::from_utf8_lossy(&buf[..len]).to_string();
                    let mut parts = head.split_whitespace();
                    let method = parts.next().unwrap_or("GET").to_string();
                    let target = parts.next().unwrap_or("/").to_string();
                    let Some(body) = handle(&state, &base, &method, &target) else {
                        return; // dropped: the answer is lost
                    };
                    let body = body.to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        mint
    }

    /// Its own Lightning Address, for trusting and minting.
    pub fn address(&self) -> String {
        self.address_of("mint")
    }

    pub fn address_of(&self, username: &str) -> String {
        format!("{username}@{}", self.base.trim_start_matches("http://"))
    }

    /// Mint a bearer note directly and hand back its URL, as a sender would.
    pub fn issue(&self, amount_msat: u64) -> String {
        let k1 = generate_note_secret();
        let q = spend_q(&k1).unwrap();
        self.state
            .lock()
            .unwrap()
            .notes
            .insert(q, (amount_msat, State::Live));
        format!("{}/w?k1={k1}&amount={amount_msat}", self.base)
    }

    /// The state of the note a spend opens.
    pub fn state_of(&self, k1: &str) -> Option<State> {
        let q = spend_q(k1)?;
        self.state.lock().unwrap().notes.get(&q).map(|n| n.1)
    }

    /// What the mint holds live for purpose-2 keys of `username`'s branch.
    pub fn address_balance(&self, username: &str) -> u64 {
        let mint = self.state.lock().unwrap();
        let Some((cx1, _)) = mint.usernames.get(username) else {
            return 0;
        };
        (0..50)
            .filter_map(|i| {
                derive_note_pubkey(
                    &cx1.pubkey_x_only,
                    &cx1.chain_code,
                    PURPOSE_LIGHTNING_ADDRESS,
                    i,
                )
                .ok()
            })
            .filter_map(|q| mint.notes.get(&hex::encode(q)))
            .filter(|(_, state)| *state == State::Live)
            .map(|(amount, _)| amount)
            .sum()
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Mint) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    /// Settle (`true`) or fail every in-flight melt.
    pub fn finish_melts(&self, paid: bool) {
        for note in self.state.lock().unwrap().notes.values_mut() {
            if note.1 == State::Melting {
                note.1 = if paid { State::Burned } else { State::Live };
            }
        }
    }

    /// Pay every outstanding invoice: each mint invoice credits its note,
    /// each payment to a registered address auto-mints to its branch.
    pub fn pay_invoices(&self) {
        let mut mint = self.state.lock().unwrap();
        let unpaid: Vec<_> = mint.unpaid.drain().collect();
        for (q, amount) in unpaid {
            mint.notes.insert(q, (amount, State::Live));
        }
        let to_addresses = std::mem::take(&mut mint.unpaid_to_address);
        for (username, amount) in to_addresses {
            let (cx1, mut index) = mint.usernames[&username].clone();
            loop {
                let q = hex::encode(
                    derive_note_pubkey(
                        &cx1.pubkey_x_only,
                        &cx1.chain_code,
                        PURPOSE_LIGHTNING_ADDRESS,
                        index,
                    )
                    .unwrap(),
                );
                index += 1;
                if let std::collections::hash_map::Entry::Vacant(slot) = mint.notes.entry(q) {
                    slot.insert((amount, State::Live));
                    break;
                }
            }
            mint.usernames.get_mut(&username).unwrap().1 = index;
        }
    }
}

fn params(target: &str) -> (String, Vec<(String, String)>) {
    let url = reqwest::Url::parse(&format!("http://x{target}")).unwrap();
    let pairs = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    (url.path().to_string(), pairs)
}

fn error(reason: &str) -> Value {
    json!({"status": "ERROR", "reason": reason})
}

fn handle(state: &Mutex<Mint>, base: &str, method: &str, target: &str) -> Option<Value> {
    let (path, query) = params(target);
    let get = |key: &str| query.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    let all = |key: &str| -> Vec<String> {
        query
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect()
    };
    let mut mint = state.lock().unwrap();
    let withdraw = |amount: u64, key: &str| {
        json!({
            "tag": "withdrawRequest",
            "callback": format!("{base}/cb"),
            "maxWithdrawable": amount,
            "minWithdrawable": amount,
            "defaultDescription": "LNURLcash note",
            "mintPubkey": key,
        })
    };

    if let Some(username) = path.strip_prefix("/p/") {
        let username = username.to_string();
        let sig = get("sig").unwrap_or_default();
        return Some(match method {
            "POST" => {
                let Some(cx1) = get("cx1").as_deref().and_then(decode_cx1) else {
                    return Some(error("Invalid cx1."));
                };
                // a fresh claim proves the new branch, an overwrite the old one
                let prover = mint
                    .usernames
                    .get(&username)
                    .map(|(c, _)| c.clone())
                    .unwrap_or(cx1.clone());
                if !proven(&prover, "register", &username, &sig) {
                    return Some(error("Invalid ownership signature."));
                }
                mint.usernames.insert(username, (cx1, 0));
                json!({"status": "OK"})
            }
            "DELETE" => match mint.usernames.get(&username) {
                Some((cx1, _)) if proven(cx1, "unregister", &username, &sig) => {
                    mint.usernames.remove(&username);
                    json!({"status": "OK"})
                }
                Some(_) => error("Invalid ownership signature."),
                None => error("Unknown user."),
            },
            _ => error("not found"),
        });
    }

    match path.as_str() {
        "/w" => {
            if let Some(p) = get("p") {
                let q = output_q(&p)?;
                return Some(match mint.notes.get(&q) {
                    Some((amount, State::Live)) => withdraw(*amount, &mint.key),
                    _ => error("Unknown note."),
                });
            }
            let k1 = get("k1")?;
            let Some(q) = spend_q(&k1) else {
                return Some(error("Invalid spend."));
            };
            Some(match mint.notes.get(&q) {
                Some((amount, State::Live)) => {
                    let mut body = withdraw(*amount, &mint.key);
                    body["k1"] = json!(k1);
                    body["c"] = json!(certify(&q, *amount));
                    body
                }
                Some((_, State::Melting)) => error("pending"),
                Some((_, State::Burned)) => error("Note already spent."),
                None => error("Unknown note."),
            })
        }
        "/cb" => {
            let spends: Option<Vec<String>> = all("k1").iter().map(|k| spend_q(k)).collect();
            let Some(inputs) = spends.filter(|s| !s.is_empty()) else {
                return Some(error("Invalid or already spent k1."));
            };
            if mint.drop_before_apply > 0 {
                mint.drop_before_apply -= 1;
                return None;
            }
            let answer = if let Some(pr) = get("pr") {
                let q = inputs[0].clone();
                match mint.notes.get(&q).copied() {
                    Some((amount, State::Live))
                        if decode_bolt11_amount_msat(&pr) == Some(amount) =>
                    {
                        mint.notes.insert(q, (amount, State::Melting));
                        json!({"status": "OK"})
                    }
                    Some((_, State::Live)) => error("Invoice amount does not match the note."),
                    Some((_, State::Melting)) => error("pending"),
                    _ => error("Invalid or already spent k1."),
                }
            } else {
                mutate(&mut mint, &inputs, get("amount"), get("p1"), get("p2"))
            };
            if mint.drop_after_apply > 0 {
                mint.drop_after_apply -= 1;
                return None;
            }
            Some(answer)
        }
        p if p.starts_with("/.well-known/lnurlp/") => {
            let username = p.trim_start_matches("/.well-known/lnurlp/").to_string();
            let mut metadata = vec![json!(["text/plain", "test"])];
            // like lnurl-mint: a registered username auto-mints to its
            // branch, so it takes no comment - but still names withdrawLink
            let (callback, comment_allowed) = match mint.usernames.get(&username) {
                Some((cx1, hint)) => {
                    let cx1 = encode_cx1(&cx1.pubkey_x_only, &cx1.chain_code);
                    metadata.push(json!(["text/cpub", format!("{cx1}:{hint}")]));
                    (format!("{base}/invoice?user={username}"), Value::Null)
                }
                None => (format!("{base}/invoice"), json!(64)),
            };
            Some(json!({
                "tag": "payRequest",
                "callback": callback,
                "minSendable": 1000,
                "maxSendable": 100_000_000,
                "metadata": Value::Array(metadata).to_string(),
                "withdrawLink": format!("{base}/w"),
                "commentAllowed": comment_allowed,
            }))
        }
        "/invoice" => {
            let amount: u64 = get("amount")?.parse().ok()?;
            if let Some(user) = get("user") {
                mint.unpaid_to_address.push((user, amount));
            } else if let Some(comment) = get("comment") {
                // a comment names the note this payment mints; none is a plain
                // payment, which is what a melt to this address is
                let Some(q) = output_q(&comment) else {
                    return Some(error("Missing or malformed comment."));
                };
                if mint.notes.contains_key(&q) {
                    return Some(error("already in use"));
                }
                mint.unpaid.insert(q, amount);
            }
            // a fake bolt11 of the right amount: its prefix is all anyone reads
            Some(json!({"pr": format!("lnbcrt{}n1pqqqqqq", amount / 100), "routes": []}))
        }
        _ => Some(error("not found")),
    }
}

/// Rotate, split or merge, as the draft has a SERVICE do it: all inputs
/// live or nothing happens, outputs never reused, a retried request
/// replayed, and the split/merge fee applied.
fn mutate(
    mint: &mut Mint,
    inputs: &[String],
    amount: Option<String>,
    p1: Option<String>,
    p2: Option<String>,
) -> Value {
    let Some(p1) = p1 else {
        return error("missing p1");
    };
    let fingerprint = format!("{inputs:?}|{p1}|{p2:?}|{amount:?}");
    let Some(out1) = output_q(&p1) else {
        return error("malformed p1");
    };
    let out2 = match (&amount, &p2) {
        (Some(_), Some(p2)) => match output_q(p2) {
            Some(q) => Some(q),
            None => return error("malformed p2"),
        },
        (Some(_), None) => return error("missing p2"),
        _ => None,
    };
    let certificates = |mint: &Mint| {
        let mut body = json!({"status": "OK", "c": certify(&out1, mint.notes[&out1].0)});
        if let Some(q) = &out2 {
            body["c2"] = json!(certify(q, mint.notes[q].0));
        }
        body
    };
    if mint.replay && mint.mutations.contains(&fingerprint) {
        return certificates(mint);
    }
    let mut total = 0u64;
    for q in inputs {
        match mint.notes.get(q) {
            Some((value, State::Live)) => total += value,
            Some((_, State::Melting)) => return error("pending"),
            _ => return error("Invalid or already spent k1."),
        }
    }
    if [Some(&out1), out2.as_ref()]
        .into_iter()
        .flatten()
        .any(|q| mint.notes.contains_key(q))
    {
        return error("already in use");
    }
    let credits = match (amount.map(|a| a.parse::<u64>()), &out2) {
        (Some(Ok(first)), Some(change_q)) => {
            let fee = mint.base_fee_msat;
            if first == 0 || first > total || total - first < fee {
                return error("insufficient value");
            }
            vec![
                (out1.clone(), first),
                (change_q.clone(), total - first - fee),
            ]
        }
        (Some(_), _) => return error("bad amount"),
        (None, _) => {
            let refund = mint.base_fee_msat * (inputs.len() as u64 - 1);
            vec![(out1.clone(), total + refund)]
        }
    };
    for q in inputs {
        mint.notes.get_mut(q).unwrap().1 = State::Burned;
    }
    for (q, value) in credits {
        mint.notes.insert(q, (value, State::Live));
    }
    mint.mutations.insert(fingerprint);
    certificates(mint)
}
