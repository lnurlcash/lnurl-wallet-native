//! The seed phrase, and the key-path notes it recovers (luds/25.md, "Seed &
//! derivation").
//!
//! ```text
//! branch  = m/139'/d1/d2/d3/d4        per mint, from HMAC(m/139'/0, domain)
//! t       = tagged_hash("LNURLcash/derive", P || chaincode || ser32(purpose) || ser32(i))
//! pk_i    = x(lift_x(P) + t·G)        the note's Q, sent as cp1<Q>
//! ck1     = Q || schnorr(sk_i, sighash(domain, Q), aux = 0)
//! ```
//!
//! Every note this wallet creates - by minting or rotating - is such a key,
//! and its spend is a deterministic function of seed, mint, purpose and
//! index. That is what makes the seed a backup: a restore re-derives each
//! index and asks the mint about it by `?p=`.
//!
//! Everything here is lnurlcash-core's (0.2.0 derives with the spec's
//! `purpose`); this module only binds it to the wallet's seed phrase. The
//! spec's own test vectors pin it below.

use anyhow::{anyhow, Result};
use lnurlcash_core::cash::{derive_cash_domain_node, derive_cash_root};
use lnurlcash_core::recoverable::{
    cash_node_to_cx1, derive_note_secret_key, encode_ck1, encode_cp1, encode_cx1,
    sign_note_ownership,
};
pub use lnurlcash_core::recoverable::{
    PURPOSE_CHANGE, PURPOSE_LIGHTNING_ADDRESS as PURPOSE_ADDRESS, PURPOSE_WALLET,
};
use secp256k1::{Secp256k1, SecretKey};
use zeroize::Zeroizing;

pub const PURPOSES: [u32; 3] = [PURPOSE_WALLET, PURPOSE_CHANGE, PURPOSE_ADDRESS];

/// Twelve fresh words, from 128 bits of OS randomness.
pub fn generate_phrase() -> String {
    let mut entropy = Zeroizing::new([0u8; 16]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, entropy.as_mut());
    bip39::Mnemonic::from_entropy(entropy.as_ref())
        .expect("16 bytes is a valid entropy length")
        .to_string()
}

/// The phrase in canonical form (lowercase, single spaces), if it is a
/// valid BIP39 mnemonic with a correct checksum.
pub fn normalize_phrase(phrase: &str) -> Result<String> {
    let words = phrase
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    bip39::Mnemonic::parse_normalized(&words)
        .map(|m| m.to_string())
        .map_err(|e| anyhow!("that isn't a valid seed phrase: {e}"))
}

/// The 64-byte BIP39 seed (no passphrase).
pub fn seed_of(phrase: &str) -> Result<Zeroizing<[u8; 64]>> {
    let mnemonic = bip39::Mnemonic::parse_normalized(phrase)
        .map_err(|e| anyhow!("invalid seed phrase: {e}"))?;
    Ok(Zeroizing::new(mnemonic.to_seed("")))
}

/// One mint's branch, `m/139'/d1/d2/d3/d4`.
pub struct Branch {
    key: Zeroizing<[u8; 32]>,
    chain_code: [u8; 32],
}

impl Branch {
    pub fn derive(seed: &[u8], domain: &str) -> Result<Branch> {
        let root = derive_cash_root(seed)?;
        let node = derive_cash_domain_node(&root, &domain.to_ascii_lowercase())?;
        Ok(Branch {
            key: Zeroizing::new(node.private_key),
            chain_code: node.chain_code,
        })
    }

    /// `(sk_i, pk_i)` for one purpose and index. `None` for the ~2^-128
    /// case of an unusable tweak: skip to the next index.
    pub fn note_key(&self, purpose: u32, index: u32) -> Option<(SecretKey, [u8; 32])> {
        let sk = derive_note_secret_key(&self.key, &self.chain_code, purpose, index).ok()?;
        let sk = SecretKey::from_slice(&sk).ok()?;
        let q = sk.x_only_public_key(&Secp256k1::new()).0.serialize();
        Some((sk, q))
    }

    /// The watch-only export a mint derives Lightning Address notes from.
    pub fn cx1(&self) -> Result<String> {
        let node = lnurlcash_core::cash::CashNode {
            private_key: *self.key,
            chain_code: self.chain_code,
        };
        let cx1 = cash_node_to_cx1(&node)?;
        Ok(encode_cx1(&cx1.pubkey_x_only, &cx1.chain_code))
    }

    /// Purpose-0 index-0: the key a mint checks address proofs against.
    pub fn identity_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        let (sk, _) = self.note_key(PURPOSE_WALLET, 0)?;
        Some(Zeroizing::new(sk.secret_bytes()))
    }
}

/// A derived note, as the wire wants it.
#[derive(Debug, Clone)]
pub struct KeyNote {
    /// `ck1`: the spend, and so the bearer secret.
    pub k1: String,
    /// `cp1<Q>`: what the mint is told to credit.
    pub output: String,
}

/// The key-path spend of `sk` at `domain`: `Q || sig`, deterministic.
pub fn ck1(sk: &SecretKey, domain: &str) -> Option<String> {
    sign_note_ownership(&sk.secret_bytes(), domain)
        .ok()
        .map(|payload| encode_ck1(&payload))
}

pub fn key_note(seed: &[u8], domain: &str, purpose: u32, index: u32) -> Option<KeyNote> {
    let branch = Branch::derive(seed, domain).ok()?;
    let (sk, q) = branch.note_key(purpose, index)?;
    Some(KeyNote {
        k1: ck1(&sk, domain)?,
        output: encode_cp1(&q),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(seed_hex: &str, domain: &str, cases: &[(u32, u32, &str, &str)]) {
        let seed = hex::decode(seed_hex).unwrap();
        let branch = Branch::derive(&seed, domain).unwrap();
        for (purpose, index, pk, sk) in cases {
            let (got_sk, got_pk) = branch.note_key(*purpose, *index).unwrap();
            assert_eq!(
                hex::encode(got_pk),
                *pk,
                "pk purpose {purpose} index {index}"
            );
            assert_eq!(
                hex::encode(got_sk.secret_bytes()),
                *sk,
                "sk purpose {purpose} index {index}"
            );
        }
    }

    #[test]
    fn matches_vector_1_odd_branch() {
        check(
            "000102030405060708090a0b0c0d0e0f",
            "mint.example",
            &[
                (
                    0,
                    0,
                    "690ac33892c64aa53874b0066ab1332f0ef45cb7c0e017eae0828916f52aa99f",
                    "3616b02290a133da73e758a54dbff1bf6439b4067a820cb51ca873fa4a13a96a",
                ),
                (
                    0,
                    1,
                    "3e76b56c1a90bc64c4bf594be91a3cb8861a150232da92705cff6ee3714bb384",
                    "9566123d096bdb261538ecb053bef6c0cc0bdc0e3440834fced083b68f3c626b",
                ),
                (
                    0,
                    5,
                    "c64ed8f1cd0f4d23aba8ddd739d9ae7e1a7ba2719cb54437384498fbc73788b3",
                    "113b74ee7a712650b9d2b24a05ec397e50c81e684162a8d299b1f3d125d25389",
                ),
                (
                    1,
                    0,
                    "e9a2d71a45a4a5a22d3378bdd761f0b3b2622b6a939d24c779668379352d8274",
                    "55c4e56313646e78da474015034856d75cd38aa8e11c1fa5f67cb9e6673be305",
                ),
                (
                    2,
                    0,
                    "acff3482453b4671e410d2158fd93ab7d4c3e8c1b9554ce1190deb021fd2cd4c",
                    "845e8f836a4cf64e9c03dab9d20bda0d3032d6b5ee7c2fa3014ef9d8f501faa8",
                ),
            ],
        );
    }

    #[test]
    fn matches_vector_2_even_branch() {
        check(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "cash.example.com",
            &[
                (0, 0, "01fee34e378bf66de6afa1bfa6e30f5c89551fd92bc1b089dca93c52b7ab61bc", "a7852f4209cb741a251bd6f50fd8cf8a45e0824860193386b6d3d80246664a48"),
                (0, 2, "2517f8221468e33cb7aafdffde313950446da0cf4d790c9b758b373dc67a5686", "6c156d11237d3bee51847b97f1a9b4ed84771a731d4ec603cc0629cd76ec7da0"),
            ],
        );
    }

    #[test]
    fn signs_vector_3_ck1_deterministically() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let note = key_note(&seed, "mint.example", 0, 0).unwrap();
        assert_eq!(note.k1, "ck1dy9vxwyjce922wr5kqrx4vfn9u80gh9hcrsp06hqs2y3daf24x0lcdy378rtefeae4mt8r7xk75z4mc0r7n8yykwkltlvndug8ytlem7pkmqwa3yhughhtdktmlqg30rs2kf7nx4stm6tnpkd3awk3vq6smm20wz");
        assert_eq!(
            note.output,
            "cp1dy9vxwyjce922wr5kqrx4vfn9u80gh9hcrsp06hqs2y3daf24x0sxpcl6z"
        );
        assert_eq!(
            crate::lud25::note_id_of_url(&format!("https://mint.example/w?k1={}", note.k1))
                .as_deref(),
            Some("690ac33892c64aa53874b0066ab1332f0ef45cb7c0e017eae0828916f52aa99f")
        );
    }

    #[test]
    fn exports_vector_1s_branch() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let branch = Branch::derive(&seed, "mint.example").unwrap();
        assert_eq!(
            branch.cx1().unwrap(),
            "cx1k7pa9ycdcpf6ju0sryz5efp70jw72rs8d80gwtw3mh096zl5e8g6hywvzxh28902dd3zj2npgl63aaq4p6l2qnn52ymmdpceugu0jpqes280t"
        );
    }

    #[test]
    fn phrases_round_trip() {
        let phrase = generate_phrase();
        assert_eq!(phrase.split(' ').count(), 12);
        assert_eq!(
            normalize_phrase(&format!("  {}  ", phrase.to_uppercase())).unwrap(),
            phrase
        );
        assert!(normalize_phrase("abandon abandon abandon").is_err());
    }
}
