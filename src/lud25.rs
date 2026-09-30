//! The few LUD-25 pieces the wallet needs on top of lnurlcash-core, which
//! since 0.2.0 implements the current draft (`luds/25.md`): unified taproot
//! notes, `p1`/`p2`, `c`/`c2`, `?p=`, and derivation purposes.
//!
//! What stays here is wallet policy rather than protocol: a pasted note only
//! counts if its spend actually opens it at its own mint's domain, and the
//! internal-transfer hint (`text/cpub`) the pinned core does not parse yet.

use lnurlcash_core::recoverable::{decode_cx1, Cx1};
use lnurlcash_core::{check_spend, note_k1, resolve_lnurl_input, spend_domain_of};

/// The domain a note's spend is bound to: its URL's host, lowercased.
pub fn domain_of(url: &str) -> Option<String> {
    spend_domain_of(url)
}

/// The note's id, `hex(Q)`, if its spend opens it at its own domain. `None`
/// for a malformed k1, or a `ck1` signed for some other mint.
pub fn note_id_of_url(url: &str) -> Option<String> {
    let check = check_spend(&note_k1(url)?, &domain_of(url)?)?;
    check.verdict.opens().then(|| hex::encode(check.output_key))
}

/// Any pasted note form (lnurlw://, bech32 LNURL, https) down to a note URL,
/// if its k1 is a spend at that URL's own domain.
pub fn resolve_note_input(value: &str) -> Option<String> {
    let url = resolve_lnurl_input(value)?;
    note_id_of_url(&url).map(|_| url)
}

/// The withdraw link a note hangs off: its URL without the note in it.
pub fn withdraw_link_of(url: &str) -> Option<String> {
    let mut parsed = reqwest::Url::parse(&lnurlcash_core::from_lud17(url)).ok()?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| !matches!(k.as_ref(), "k1" | "amount" | "c" | "sig" | "p" | "h"))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    parsed.set_query(None);
    if !pairs.is_empty() {
        parsed.query_pairs_mut().extend_pairs(&pairs);
    }
    Some(parsed.to_string())
}

/// LUD-25 "Internal transfer": a registered username's payRequest metadata
/// carries `["text/cpub", "cx1<...>:<i>"]`, the payee's branch and its
/// best-known next unused purpose-2 index. `i` is only a hint.
pub fn parse_cpub(metadata: &str) -> Option<(Cx1, u32)> {
    let entries: Vec<serde_json::Value> = serde_json::from_str(metadata).ok()?;
    entries.iter().find_map(|entry| {
        let entry = entry.as_array()?;
        if entry.first()?.as_str()? != "text/cpub" {
            return None;
        }
        let (cx1, index) = entry.get(1)?.as_str()?.rsplit_once(':')?;
        Some((decode_cx1(cx1)?, index.parse().ok()?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // luds/25.md, test vector 3: a ck1 for mint.example
    const CK1: &str = "ck1dy9vxwyjce922wr5kqrx4vfn9u80gh9hcrsp06hqs2y3daf24x0lcdy378rtefeae4mt8r7xk75z4mc0r7n8yykwkltlvndug8ytlem7pkmqwa3yhughhtdktmlqg30rs2kf7nx4stm6tnpkd3awk3vq6smm20wz";
    const PK0: &str = "690ac33892c64aa53874b0066ab1332f0ef45cb7c0e017eae0828916f52aa99f";

    #[test]
    fn a_key_path_note_counts_only_at_its_own_mint() {
        let url = format!("lnurlw://mint.example/w?k1={CK1}");
        assert_eq!(
            note_id_of_url(&format!("https://mint.example/w?k1={CK1}")).as_deref(),
            Some(PK0)
        );
        assert!(resolve_note_input(&url).is_some());
        assert!(resolve_note_input(&url.replace("mint.example", "evil.example")).is_none());
    }

    #[test]
    fn a_bearer_note_is_keyed_by_its_taproot_q() {
        // test vector 5
        let url = "https://mint.example/w?k1=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert_eq!(
            note_id_of_url(url).as_deref(),
            Some("d18b619687343df2fc7a47e1daf25260b909bb563fb4b4b11e59e2bd64880982")
        );
    }

    #[test]
    fn strips_a_note_down_to_its_withdraw_link() {
        assert_eq!(
            withdraw_link_of(&format!("lnurlw://mint.example/w?k1={CK1}&amount=5&c=cs1x")).unwrap(),
            "https://mint.example/w"
        );
    }

    #[test]
    fn reads_the_internal_transfer_hint() {
        // test vector 1's branch
        let cx1 = "cx1k7pa9ycdcpf6ju0sryz5efp70jw72rs8d80gwtw3mh096zl5e8g6hywvzxh28902dd3zj2npgl63aaq4p6l2qnn52ymmdpceugu0jpqes280t";
        let metadata = format!(r#"[["text/plain","x"],["text/cpub","{cx1}:7"]]"#);
        let (branch, index) = parse_cpub(&metadata).unwrap();
        assert_eq!(index, 7);
        assert_eq!(
            hex::encode(branch.pubkey_x_only),
            "b783d2930dc053a971f019054ca43e7c9de50e0769de872dd1ddde5d0bf4c9d1"
        );
        assert!(parse_cpub(r#"[["text/plain","x"]]"#).is_none());
    }
}
