# bsv-middleware-core

The runtime-free rules of BSV BRC-103/104 authentication and BRC-29 payment verification: what a server must
compute and decide, with no transport, no store, no clock and no network of its own. A host crate adapts these
rules to its runtime; `bsv-middleware-cloudflare` (0.4.0 and later) is the Cloudflare Workers host.

## Install

```toml
bsv-middleware-core = "0.2.2"
```

The SDK floor is bsv-rs 0.4.5; no API change in the core or adapter 0.5.2.
A script declining under a work or memory bound is payer-side `Unverifiable` with
`SpendRefused`, naming the decline and input (400 `ERR_PAYMENT_INVALID` in the adapter).
The crates set no bound themselves. The SDK's `MerklePath` refuses a lone hashed leaf
at a nonzero offset; the payment refusal is payer-side and names the offset.
LOW's tower, the relay's door, Zanaadu's door and wallet-infra should follow
[the re-pin migration](CHANGELOG.md).

## What it decides

**A payment check answers in six words, never a boolean:**

```rust
pub enum PaymentVerdict {
    Verified { satoshis: u64 },
    Underpaid { paid: u64, required: u64 },
    WrongScript { expected: String, actual: String },
    NoHeaderService,
    RootMismatch { height: u32, root: String },
    Unverifiable { reason: UnverifiableReason },
}
```

**A BEEF of any size.** A valid payment is never refused for its size or its counts (the owner's ruling of
2026-10-09): the payment is read once through the streaming reader of bsv-rs 0.4 (0.4.5 at least;
`transaction::verify_stream`), one element in hand, the scripts run; a refusal of the bytes names the offset and the
reader's kind. No bound lives here.

`verify_brc29_payment` runs, in order: the service gate (`None` is `NoHeaderService`, fail closed, before the bytes
are read); the reader (a valid BEEF whose unproven transactions spend the parent outputs it carries; invalid bytes
are `Unverifiable` with `InvalidBeef { offset, kind, .. }`, a refused spend `SpendRefused { txid, input, .. }`, at
the soonest fault in stream order); the subject's output (`WrongScript`, then `Underpaid`); a proof's presence (none
is `Unverifiable` with `NoProof { txid }`, the transaction whose proof is absent); then SPV through the header
service, each distinct root lowest height first: a root that differs from its header is `RootMismatch`; a root the
service could not answer makes the verdict `Unverifiable` with `HeaderLookupFailed { height, .. }`, a refusal (fail
closed, by the rule adopted 2026-10-08: an unchecked root is not evidence); every root matched is `Verified`.
`verify_brc29_payment_verified` answers the same with the subject's txid (`VerifiedPayment { satoshis, txid }`).

`UnverifiableReason` splits the class (the no-root ruling of 2026-10-09): `is_server_side()` is true for
`HeaderLookupFailed` alone (the host's 5xx with the quote kept; the same payment retried later) and false for every
other reason (the payer's: the host's 4xx, no fields, another payment). `PaymentFault` (an `Err`) is the host's own
fault alone: the server's key does not derive. A payer's bytes never produce an `Err`.

Only `Verified` serves (`is_verified`; every other word `is_refused`). `verify_brc29_payment_structural_only` is
the named opt-out: the reader's structure with no script run, the output, the proof's presence, and the roots NOT
asked; a payment that passes is `Unverifiable` with `RootsUnchecked { satoshis, roots }` so the skip is visible; a
host that serves on that answer does so because its caller named the opt-out, never through the full check.

**The header service is a trait.** No URL lives in the core.

```rust
pub trait HeaderService {
    fn merkle_root(&self, height: u32)
        -> impl Future<Output = Result<Option<MerkleRoot>, ServiceError>>;
}
```

`Ok(Some(root))` is the header at that height, `Ok(None)` means not indexed yet, `Err` means the service could not
answer. A host implements it over whatever it has: an HTTP header service, a service binding, a cached header store,
a fixture (`LookupFn` wraps a closure).

**The stores are traits.** `PaymentNonceStore` (scoped single-use values: a BRC-104 per-request nonce under its
session, a BRC-29 derivation prefix under `PAYMENT_NONCE_SCOPE`) and `ClaimStore` (an atomic claim by key, for a
host's own payment flow or a refund idempotency key). Both fail closed by contract: a storage fault is an error,
never a fresh claim. `MemoryStore` implements both for tests and single-process hosts.

## What else is here

- `brc29`: BRC-29 derivation (`expected_locking_script`, the sender's side, the derivation-prefix HMAC nonce)
  and the pays-us-correctly check (`verify_payment_output`).
- `spv`: the per-root decision (`decide_root`, pinned by a table) and the loop over a proof's roots
  (`check_roots`: the first mismatch decides, the lowest unanswered height is the `HeaderLookupFailed` height).
- `brc104`: BRC-104 header names, the signed request and response payloads, the header pairs a message is sent as.
- `auth`: BRC-103 message build and verify over a `SessionBinding`: sign, verify against the SESSION's identity
  (the header is a claim), the handshake's `InitialResponse`, the signed general message that carries a response.
- `session_lane`: the MAC'd session lane (one handshake, then no wallet calls per request), pure.
- `refund` (feature `refund`): the refund key derivation and the `createAction` template signer.
- `types`: `AuthContext`, `PaymentContext`, `BsvPayment`.

## What is not here, by design

No HTTP request type, no fetch, no KV, no Durable Object, no SQL, no clock read, no logging. Every function takes
what it needs as data and answers with data; the host owns every side effect and every policy decision.

The one runtime-shaped thing in the dependency tree is the SDK's own: `bsv-rs`'s `auth` feature (the BRC-103
message types and the HMAC nonce) brings `tokio`'s sync and time primitives transitively. This crate uses none of
them, declares no executor, and its tests run on `tokio`'s current-thread runtime as a dev-dependency only.

## Conformance

`tests/conformance_brc29.rs` runs the implementation-neutral BRC-29 payment vectors
(`conformance/brc29-payment-vectors.json`, 22 cases, the stack review repository's owned file) through
`verify_brc29_payment` with a stub service, reading the file the way a second implementation does: from JSON only,
and checks the outcome as well as the word: only `Verified` serves; `spv-lookup-error` is refused as `Unverifiable`
with `fields.height` (the ruling of 2026-10-08, the server's side); `spv-no-root` and `spv-incomplete-beef` are
refused as `Unverifiable` with no fields (the ruling of 2026-10-09, the payer's side, the refusal naming the absent
transaction, nothing asked of the service). The copy under this crate's `conformance/` is shipped in the package so
the published crate runs the vectors on its own; the repository root's copy is pinned to the owner's bytes by
digest, and this copy byte-identical to it, by the Workers adapter's runner.

## Build

```bash
cargo test -p bsv-middleware-core --all-features
cargo clippy -p bsv-middleware-core --all-features --all-targets -- -D warnings
```

## License

MIT OR Apache-2.0.
