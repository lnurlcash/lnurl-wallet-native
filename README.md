# LNURLwallet (native)

A desktop wallet for **LNURLcash** bearer notes
([LUD-25 draft](https://github.com/lnurl/luds/blob/lnurlcash/25.md)), in Rust
with [egui](https://github.com/emilk/egui). It is a native counterpart to the
web [lnurl-wallet](https://github.com/lnurlcash/lnurl-wallet). The protocol comes
from [lnurlcash-core](https://github.com/lnurlcash/lnurlcash-core).

- **Seed phrase**: 12 BIP39 words, set up on first unlock (generate, or
  restore). Every note the wallet mints or rotates is a key derived from
  them (LUD-25 "Seed & derivation": one branch per mint, then a key per
  purpose and index), so the words alone bring your notes back.
- **Mints**: the public mints from
  [awesome-lnurlcash](https://github.com/lnurlcash/awesome-lnurlcash) are
  one click from trusted, and any other mint can be trusted by its Lightning
  Address. Receiving and minting only happen at trusted mints; a note from
  anywhere else asks first.
- **Mint**: pick a mint and an amount, and pay the invoice from any Lightning
  wallet. The invoice commits to your next seed key (`comment=cp1<Q>`), and
  the wallet polls the mint until the note appears.
- **Receive**: paste an `lnurlw://` link, a bech32 LNURL or a note URL. The
  wallet checks the note with its mint, verifies its certificate, and
  **rotates it onto a seed key straight away**, because the sender still
  knows its secret.
- **Check / Rotate**: ask the mint what a note is worth, or move it onto the
  next seed key.
- **Pay any amount**: to a BOLT-11 invoice, a Lightning Address or LNURL-pay
  link, or a `cx1`. The wallet splits or merges the notes at the chosen mint
  down to exactly that amount, keeps the change, and melts the result.
- **Internal transfer**: a Lightning Address registered at the *same* mint
  you pay from is paid inside the mint - the notes go straight onto the
  payee's next key, with no Lightning payment and no routing fee.
- **Send an amount**: make a note of exactly that amount and show it as a QR
  code or copyable link, then mark it as given away. *Check* shows when the
  recipient has claimed it; until then, *Take back* rotates it home again.
- **Merge**: combine every note held at one mint into one.
- **Lightning Address**: register `you@<mint>` against your seed at any
  trusted mint. Every payment to it mints a note to your seed, which the
  wallet picks up automatically, and wallets at that mint can pay you by
  internal transfer.
- **Restore**: scan every trusted and public mint for the keys your seed
  derives, 20 unknown indices past the last one found per purpose.

Not in this version: file backups, camera scanning, fiat display, auto-lock.

## Spec version

This wallet follows the current draft in `luds/25.md` (unified taproot notes
and derivation purposes, as of 2026-09-25), through
[lnurlcash-core](https://github.com/lnurlcash/lnurlcash-core) 0.2.0, which
implements it. [`src/keys.rs`](src/keys.rs) pins the derivation and the
key-path spend to the draft's test vectors 1-3, and
[`src/lud25.rs`](src/lud25.rs) holds the few wallet-side rules on top: a
pasted note only counts if its spend opens it at its own mint's domain, and
the `text/cpub` internal-transfer hint, which the core does not parse yet.

One known gap between the core and the reference mint: lnurl-mint's
registered Lightning Addresses advertise `withdrawLink` without
`commentAllowed` (they auto-mint, so take no comment), and core 0.2.0 refuses
that payRequest outright. The wallet reads past that one refusal when paying,
since paying needs no comment.

## Safety

Every one of these rules has a test:

- **Persist before disclose.** A seed key's index is reserved and saved
  before the key is derived. Every rotate, split, merge and transfer is
  written to a journal in the encrypted wallet file - inputs, outputs, our
  spends for them - *before* its request is built. The wallet never deletes
  a journal entry; it only marks it done or failed. A mint's key is saved
  before its invoice is even requested. An index the mint reports as
  `already in use` is skipped, never reused.
- **A lost answer is not a failure.** If a mutation's answer never arrives,
  it is re-sent once unchanged; LUD-25 requires the mint to replay its
  original success. If the outcome is still unknown, its inputs turn
  *uncertain*. **Resolve** reads the journal and asks the mint about the new
  outputs by `?p=`, which exposes nothing spendable, then about the inputs,
  which the mint already knows. Whatever landed is adopted; whatever didn't
  leaves the inputs as they were.
- **A melt's OK means in flight, not spent.** The note stays *melting* until
  the mint reports it burned. A failed payment makes it live again.
- **Mint keys are pinned** to scheme, host and port on first contact. A mint
  that later presents a different key is refused until you unpin it.
- **Encrypted at rest.** The file, seed phrase included, is sealed with a
  key stretched from your password (argon2id, 64 MiB) using
  XChaCha20-Poly1305, and every save replaces it atomically. Lose the
  password and the seed phrase still restores your notes; lose both and
  they're gone.

The wallet lives at the platform data directory
(`~/.local/share/lnurl-wallet-native/wallet.json` on Linux), or wherever
`LNURL_WALLET_FILE` points.

## Build and run

```sh
make build   # optimized binary at target/release/lnurl-wallet-native
make run     # build, then start it
make dev     # unoptimized build, quicker to compile
make test    # unit tests
make lint    # rustfmt check + clippy, warnings as errors
```

## Tests

The unit tests drive the wallet against an in-process mock mint that speaks
the current draft: split and merge with the draft's fees, registered
addresses that auto-mint and advertise `text/cpub`, and hooks that drop a
connection before or after applying a mutation, replay a retried request,
settle or fail a melt, and change the key the mint presents.

The end-to-end tests run against the real
[lnurl-mint](https://github.com/lnurlcash/lnurl-mint) server, backed by its
own test suite's fake Lightning node (needs a checkout next to this repo, and
[uv](https://docs.astral.sh/uv/)):

```sh
make reference-mint   # terminal 1; LNURL_MINT_DIR=... if it lives elsewhere
make e2e              # terminal 2
```

## CI and releases

[CI](.github/workflows/ci.yml) runs on every push to `main` and every pull
request: `make lint`, `make test` and `make build` on Linux, build and test
on macOS and Windows, and `make e2e` against lnurl-mint's `main`.

To release, push a version tag - there is nothing to bump:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The version comes from the tag. `Cargo.toml` carries a `0.0.0-dev`
placeholder, and [`scripts/set-version.sh`](scripts/set-version.sh) stamps the
tag's version into `Cargo.toml` and `Cargo.lock` just before each release
build; the app shows it on the unlock screen and with `--version`.
[The release workflow](.github/workflows/release.yml) reruns CI, builds for Linux (x86_64, arm64),
macOS (Apple silicon, Intel) and Windows, and publishes a GitHub Release with
generated notes, one archive per platform and a `.sha256` file. The binaries
are not code-signed.

## License

MIT
