# bsv-middleware-cloudflare

BSV authentication and payment middleware for Cloudflare Workers. Rust compiled to WASM.

Port of [`auth-express-middleware`](https://github.com/bitcoin-sv/auth-express-middleware) and [`payment-express-middleware`](https://github.com/bitcoin-sv/payment-express-middleware) for the Cloudflare Workers runtime. Implements BRC-103/104 mutual identity auth and BRC-29 direct payments, with session and payment state persisted in Cloudflare KV. Error codes, HTTP statuses, and header names match the Express versions.

## What it provides

- **`process_auth`** / **`process_auth_with_storage`** - BRC-103/104 mutual identity handshake, session verification, certificate exchange, and per-request replay protection (each `x-bsv-auth-nonce` is single-use per session). Returns the authenticated identity key, a reusable session handle, and the raw request body. Every authentication refusal is a 401 response from the middleware itself (0.4.1), with CORS, unsigned; an `Err` is a fault (storage, the server's key, the transport).
- **`process_payment_with_storage`** - BRC-29 payment verification. Emits `402 Payment Required` with derivation prefix, accepts `x-bsv-payment` header, reads output 0 of the payment and refuses it (`400 ERR_INVALID_PAYMENT`, the quote kept) unless it pays this server's BRC-29 derived key at least the price (0.3.8; 400 since 0.4.0), internalizes via a remote wallet storage endpoint, gates on the wallet's `accepted` flag, and enforces single-use derivation prefixes. `satoshis_paid` is the amount read from the output. (`process_payment` remains as a deprecated stateless variant.)
- **`sign_json_response`** - signs outbound JSON responses so BRC-103/104 clients (e.g. `AuthFetch`) can verify server identity and message integrity. Equivalent to Express's `res.json` hijacking, but explicit.
- **`WorkerStorageClient`** - WASM-compatible RPC client for a wallet storage server (e.g. `storage.babbage.systems`), used by `process_payment` and optional refund flows.
- **Optional `refund` feature** - BRC-41 refund transaction builder for partial-refund scenarios (e.g. AI agents that pre-charge and refund on failure). Not present in the Express reference.
- **`verify_brc29_payment`** / **`verify_brc29_payment_output`** (0.3.6) - checks, before anything is internalized, that a BRC-29 payment output pays *this* server's derived key at least the quoted amount inside a structurally complete BEEF, with merkle roots checked against a header service you run (required: no service, no verdict; `verify_brc29_payment_structural_only` is the named opt-out without SPV). For callers with their own payment flow; the stock middleware runs `verify_brc29_payment_output` itself (0.3.8).
- **Optional `d1-claims` feature** (0.3.6) - `claim_payment_nonce` / `release_payment_nonce`: an atomic, globally consistent single-use claim on a payment nonce in a D1 table, for callers outside the stock middleware or on the eventually-consistent KV backend.

## Shape (0.4.0): the core and the adapter

Since 0.4.0 the rules live in a runtime-free crate, [`bsv-middleware-core`](core/README.md) (this repository,
`core/`), and this crate is the Cloudflare Workers adapter over it:

| the core (`bsv-middleware-core`, no runtime) | this crate (`bsv-middleware-cloudflare`, Workers) |
|---|---|
| BRC-103 message build and verify over a `SessionBinding` (sign, verify against the SESSION's identity, the handshake replies, response signing) | reading a `worker::Request` into those messages, the session records, the replay guard, the HTTP answers, CORS |
| BRC-29 derivation, the output check, the streaming reader's validity and spends (bsv-rs 0.4.0, the scripts run), the proof's presence and the SPV decision, answered in six words (`PaymentVerdict`: `Verified`, `Underpaid`, `WrongScript`, `NoHeaderService`, `RootMismatch`, `Unverifiable { reason }`) | `verify_brc29_payment` and friends with their 0.3 signatures, `PaymentVerifyError`, and `accept_verdict`, the one visible match from the words to it |
| the `HeaderService` trait (no URL type in the core; `None` fails closed) | `UrlHeaderService`: Workers `fetch` to a ChainTracks-compatible base URL behind the 0.3.6 configuration gate |
| the `PaymentNonceStore` and `ClaimStore` traits | KV, Durable Object and D1 implementations (`SessionNonceStore`, `D1ClaimStore`) |
| the session lane's rules, the refund key derivation and the template signer, the context types | the lane's door and store, `issue_refund` over the storage client |

**Every 0.3 public item keeps its name, path and signature** (re-exported from the core where the type moved);
adopters upgrade by bumping the version. The core is reachable as `bsv_middleware_cloudflare::core` for code that
wants the words or the traits directly.

## Why Cloudflare Workers

Workers are request-scoped and have no in-process memory, so a direct port of the Express middleware isn't possible. Adaptations:

- **Sessions in Cloudflare KV** (`KvSessionStorage`) - configurable TTL, keyed by session nonce plus an identity index for lookups.
- **Payments in Cloudflare KV** (`KvPaymentStorage`) - duplicate-txid detection, unspent tracking, derivation prefix lifecycle.
- **No `res.json` hijacking** - Workers can't intercept response construction. Call `sign_json_response(&body, status, &[], &session)` explicitly before returning.
- **Remote wallet instead of local wallet object** - Workers can't host a `WalletInterface`, so `WorkerStorageClient` speaks JSON-RPC to a storage server over HTTP, authenticated by BRC-103/104.
- **Async everywhere** - KV reads, HTTP calls, and auth verification are all `async`, matching the Workers runtime.

Error codes, HTTP statuses, and all `x-bsv-auth-*` / `x-bsv-payment-*` header names are identical to the Express versions. Clients that talk to Express middleware will talk to this middleware unchanged.

## Install

```toml
bsv-middleware-cloudflare = "0.7.0"
# Runtime-free hosts:
bsv-middleware-core = "0.4.0"
```

Both crates require bsv-rs 0.7.0 or later in 0.7.x (caret). Work limits are optional, default `None`.
A local evaluator decline names the resource and input as payer-side `Unverifiable` (`SpendRefused`),
400 `ERR_PAYMENT_INVALID` in the adapter. A lone hashed leaf at a nonzero offset is refused by the
SDK's `MerklePath`, with a payer-side refusal naming the offset. See [the migration](CHANGELOG.md).

## Sources, multipart payments and work budgets

Core callers add `work_limit: None` to `verify_brc29_payment` and
`verify_brc29_payment_verified`. `verify_brc29_payment_stream` takes an
`AsyncByteSource`; `SliceSource` is the bounded-chunk slice wrapper.
Implement `HeaderService::mining_tip` for finality and coinbase maturity.
Missing context is a server-side `MiningContextUnavailable`, never a guessed verdict.

The adapter keeps its existing verify signatures with no budget. Read
`payment_work_limit(&env)?` once and pass it to `verify_brc29_payment_budgeted`
or `verify_brc29_payment_source`. `PAYMENT_WORK_LIMIT` is optional: absent or
blank means no bound, a positive decimal u64 bounds each unproven input,
and `0` or a non-number is `BadWorkLimit`, 500 `ERR_SERVER_MISCONFIGURED`.
The fleet uses `1000000` units per input; a one-input P2PKH witness needs 490.
A resource decline is payer-side, 400 `ERR_PAYMENT_INVALID`, with the quote kept.
The bound is per input, not per request. The Worker's configured CPU cap bounds
total request work (Paid defaults to 30 seconds); this release adds no request clock.

After authentication, use `split_multipart_payment(&req, body)` and feed
`payment.transaction()` to the source verifier with `payment.prefix()` and
`payment.suffix()`. The original multipart body moves into `PaymentPart`;
only the handler payload is copied out, and base64 decodes in 3 KB chunks.
The x402 helper switches above **8,192 bytes of payment JSON**, when multipart
is advertised. It sends an `x-bsv-payment` JSON part and an optional binary
`body` part. This is the helper's threshold, replacing the design's approximate
16 KB. The old `prepare_multipart_payment` remains available, deprecated.
BRC-104 authenticates the entire body before payment verification; its digest
path holds one body copy. Signed refusal payloads keep their existing shape.

`UrlHeaderService` uses `/findChainTipHeaderHex`, `/getChain`, and up to ten
`/findHeaderHexForBlockHash?hash=...` lookups to compute the tip's median time
past from its ancestry. Mainnet and testnet activation heights follow the SV
node's chain parameters. No candidate block time is guessed before CSV:
pre-CSV time locks decline without explicit context from a custom service.

Native release memory baseline on bsv-rs 0.5.0 (bytes):

| Unproven hops | BEEF body | Adapter/core payment path peak | SDK reader alone peak |
| --- | ---: | ---: | ---: |
| 16 | 16,001,286 | 7,080,245 | 6,984,599 |
| 64 | 64,004,742 | 7,109,677 | 7,012,711 |
| 128 | 128,009,350 | 7,114,117 | 7,012,711 |

All bodies verify. These are incremental native heap peaks above the caller's
already-owned body, not total Worker memory or a multipart runtime measurement.
Each hop has the same 1,000,005-byte unlocking script; the payment path receives
64 KiB chunks. All peaks are below 8 MB, and the largest body's peaks are within
0.5 percent of the smallest's (the test requires within 10 percent for both paths).
The release witness proves independence from body size at these points; its floor
is the largest transaction plus reader/index overhead. This replaces the design's
guessed below-4-MB bound under the captain's ruling. The prior lane measured the
64-hop SDK peak as 7,013,135 bytes; this witness samples before the validity assertion.
The 30 MB multipart `wrangler dev` WrongScript witness and adapter 0.5.2 control
are deferred to test-agent in the fleet wave.

## Quick start

```rust
use bsv_middleware_cloudflare::{
    process_auth, sign_json_response,
    middleware::auth::{AuthMiddlewareOptions, AuthResult, handle_cors_preflight},
};
use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    let opts = AuthMiddlewareOptions {
        server_private_key: env.secret("SERVER_PRIVATE_KEY")?.to_string(),
        allow_unauthenticated: false,
        session_ttl_seconds: 3600,
        ..Default::default()
    };

    let (auth, req, session, _body) = match process_auth(req, &env, &opts).await
        .map_err(|e| Error::from(e.to_string()))?
    {
        AuthResult::Authenticated { context, request, session, body } => (context, request, session, body),
        AuthResult::Response(resp) => return Ok(resp),
    };

    let body = serde_json::json!({ "identity": auth.identity_key });
    match session {
        Some(ref s) => sign_json_response(&body, 200, &[], s)
            .map_err(|e| Error::from(e.to_string())),
        None => Response::from_json(&body),
    }
}
```

See `examples/basic_server.rs` for auth + payment together.

## Cloudflare bindings

```toml
# wrangler.toml
[[kv_namespaces]]
binding = "AUTH_SESSIONS"
id = "<your-kv-id>"

[[kv_namespaces]]
binding = "PAYMENTS"           # only needed if you use the payment middleware
id = "<your-kv-id>"
```

Secret: `wrangler secret put SERVER_PRIVATE_KEY` (64-char hex secp256k1 private key).

## Features

| Feature | Default | Pulls in |
|---|---|---|
| `refund` | off | `bsv-middleware-core/refund` (`ripemd`) - enables `refund::issue_refund` for BRC-41 partial refunds |
| `d1-claims` | off | `worker/d1` - enables `payment_claims::{claim_payment_nonce, release_payment_nonce}` (atomic single-use payment-nonce claims on a D1 table) |

## Parity with Express middleware

All error codes, HTTP statuses, and header names match the Express versions:

| Concern | Express | Rust |
|---|---|---|
| Auth error codes | `UNAUTHORIZED`, `ERR_INVALID_AUTH`, `ERR_SESSION_NOT_FOUND` | identical |
| Payment error codes | `ERR_PAYMENT_REQUIRED`, `ERR_MALFORMED_PAYMENT`, `ERR_INVALID_DERIVATION_PREFIX`, `ERR_PAYMENT_FAILED` | identical |
| Headers | `x-bsv-auth-*`, `x-bsv-payment-*` | identical |
| HTTP statuses | 400 / 401 / 402 / 500 | identical, plus 503 `ERR_HEADER_SERVICE_UNAVAILABLE` when the header service cannot answer (the quote kept); a payment that cannot be verified for the payer's reason (invalid BEEF, a refused spend, no proof) is 400 `ERR_INVALID_PAYMENT` with the quote kept (0.5.0); every authentication refusal is a 401 `AuthResult::Response` (0.4.1), never an `Err` |

Known divergences (architectural, not bugs):
- **Response signing is explicit.** Callers invoke `sign_json_response` rather than relying on `res.json` interception.
- **Pluggable storage via `SessionStorage`.** Express lets you swap `SessionManager`; here the equivalent seam is the `SessionStorage` trait (`process_auth_with_storage` / `process_payment_with_storage`), with `KvSessionStorage` as the default backend.
- **No injectable logger.** Use `console_log!` / `console_error!` from the `worker` crate at call sites if needed.
- **Payment internalizes via HTTP to a wallet storage server**, not a local `WalletInterface`. Required for Workers (no local wallet possible).
- **No SPV on the middleware's own path.** `process_payment_with_storage` checks output 0's script and amount and nothing else about the transaction: no merkle proof is checked against a block header there. Whether the payment is real and confirmable is left to the wallet storage server's `internalizeAction`, which this crate does not verify. Run `verify_brc29_payment` (through a header service) before it when a proof must be checked.

Deliberate hardening divergences (the reference is weaker here; security audit findings #30/#44):
- **Auth replay protection.** The TS stack (`@bsv/sdk` `Peer.processGeneralMessage`) never records consumed per-request nonces, so a byte-identical signed request replays successfully there for the whole session TTL. This crate consumes each `(session nonce, x-bsv-auth-nonce)` pair and rejects duplicates with `401 ERR_REPLAYED_REQUEST`. See `middleware::auth` docs for the exact residual window under eventually-consistent KV.
- **Every authentication refusal is a 401 answer (0.4.1).** The reference answers `401 UNAUTHORIZED` only when no auth headers are present; a general message its SDK refuses (another identity's key over the session, a bad signature, a session that never completed its handshake) is swallowed by the `Peer` and never answered. Here each of those is `401 ERR_INVALID_AUTH` (`ERR_SESSION_NOT_FOUND` for an unknown session), from `process_auth*` as an `AuthResult::Response` with CORS, so `AuthFetch`-class clients re-handshake; an `Err` from `process_auth*` is a fault (storage, the server's key, the transport), the host's 500.
- **`accepted` gate.** `payment-express-middleware` calls `next()` even when `wallet.internalizeAction` returns `accepted: false`. Here a rejected payment returns `402` with a fresh challenge and never reaches the handler.
- **The paying output's script.** `payment-express-middleware` 2.1.9 reads output 0's satoshis and refuses below the price with `400 ERR_INVALID_PAYMENT`, and leaves the script to its wallet's signer. Here the storage server is not a signer, so output 0 must also pay this server's BRC-29 derived key; a short or misdirected payment gets the reference's `400 ERR_INVALID_PAYMENT` with the quote kept (no fresh challenge, the prefix not consumed), before the storage is called (0.3.8 answered 402 with a fresh challenge; 400 since 0.4.0).
- **Single-use payment derivation prefixes.** The reference's `verifyNonce` is a stateless HMAC; here each verified prefix is consumed (no expiry) via the `SessionStorage` nonce store, so a captured `X-BSV-Payment` header cannot be internalized twice.

## Consumers

Known production consumers using BRC-103/104 auth + dynamic pricing + optional refund:

- `bsv-messagebox-cloudflare` - BSV peer-to-peer messaging service (upcoming public release)
- Various agents (image gen, LLM inference) that pre-charge and refund on upstream failure

## License

Dual-licensed under MIT or Apache-2.0 at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## Session lane (0.3.4, opt-in)

One BRC-103/104 handshake per origin, then a LANE: `process_auth_lane(req, &env, &options, "AUTH_SESSION_STORE")`
serves calls that carry `x-low-session` (the lane id), `x-low-session-identity`, `x-low-session-n` (the client's
counter) and `x-low-session-mac` (`HMAC-SHA256(K, n ‖ "METHOD path?query" ‖ 0x00 ‖ sha256(body))`) with ZERO wallet
calls and one Durable Object round trip, and answers `LaneAuthResult::Laned { context, request, body, lane }`;
everything else is `LaneAuthResult::Reference(AuthResult)` or `LaneAuthResult::Offered { auth, offer }`, the unchanged
reference outcome. The client's FIRST BRC-104-signed general message carrying the explicit ask (`x-low-lane-ask`) on a
server with `options.session_lane = Some(..)` is answered `Offered`: the server attaches the offer to that message's
SIGNED reply as the `x-bsv-lane-offer` header (base64 JSON `{id, expiresAt, salt, ask}`, a header a reference client
ignores, exposed cross-origin); the unsigned handshake never mints. Both sides derive
`K = HMAC-SHA256(salt, label ‖ id ‖ clientMessageNonce ‖ serverSessionNonce)` from that message's own `x-bsv-auth-nonce`
and the server's session nonce. Seal a laned answer with
`seal_lane_response(&value, status, &lane)` (`x-low-session-n`, `x-low-session-mac`, `no-store`). Refusals are
401 `{status:"error", code:"ERR_SESSION_REFUSED", reason}` (`unknown-session` / `expired` / `replay` / `bad-mac` /
`malformed`; 503 `lane-unavailable` when the store cannot be asked). The KV backend keeps no lanes (never offers
one, answers a laned call 503 `lane-unsupported`). The pure rules live in `middleware::session_lane`; the MAC
vectors are `tests/fixtures/session_lane.vectors.json` (emitted by the module's own test, sha256-pinned; a client
pins the same bytes). Designed for the relay adopter: its lane, generalized to HTTP-only servers.

## Payment verification before internalize (0.3.6; the reader since 0.5.0)

`verify_brc29_payment(server_key, sender_identity_key, derivation_prefix, derivation_suffix, &tx_bytes, output_index, required_satoshis, header_url)`
proves, before any wallet call, that the payment *pays this server correctly* and is *real and confirmable*.
`verify_brc29_payment_verified(..)` (0.5.0) answers the same with the subject's txid beside the amount
(`VerifiedPayment { satoshis, txid }`), so a host records the payment without parsing the BEEF a second time.

**A BEEF of any size.** A valid payment is never refused for its size or its counts (the owner's ruling of
2026-10-09): the payment is read once through the streaming reader of bsv-rs 0.5 (0.5.0 at least), one element in
hand, and a refusal of the bytes names the offset and the reader's kind. This crate carries no limit, no count bound
and no 413.

The check runs, in order:

1. **Configuration**: `header_url` must name a header service (below), else `NoHeaderService` before the bytes are read.
2. **The bytes** (the core's reader, `bsv_middleware_core`): the BEEF is valid (V1, V2 or Atomic) and the scripts
   run: every unproven transaction's inputs name earlier transactions and spend them (each unlocking script is
   executed against the parent output the BEEF carries; no transaction creates value); an Atomic subject is the tip of
   its ancestry. Invalid bytes are `Unverifiable` with `InvalidBeef { offset, kind, .. }`, a refused spend
   `SpendRefused { txid, input, .. }`, at the soonest fault in stream order. 0.4.x checked the structure alone.
3. **Script + amount** (`verify_brc29_payment_output` runs this alone, offline): the subject's output's locking script
   equals the P2PKH script of the BRC-29 key derived from (server identity, sender identity, prefix, suffix) via
   `expected_brc29_locking_script`, and carries at least `required_satoshis`. One byte-compare rejects underpayment,
   zero-sat outputs, outputs paying any other key, a transaction built for another quote nonce, and a transaction built
   for another server.
4. **A proof is present**: no BUMP, or an ancestry that reaches no proof, is `Unverifiable` with `NoProof { txid }`
   (the transaction whose proof is absent). A transaction with no input is invalid bytes, refused by the reader in
   check 2 as `InvalidBeef { kind: "NoInputs", .. }` at its leading byte (bsv-rs 0.4.1; 0.4.0's reader read it as
   valid with no root and this check refused it). The payer's side either way (ruled 2026-10-09): the server never
   fetches a missing proof; the payer sends a proven BEEF.
5. **SPV**: each distinct merkle root, lowest height first, is checked against block headers from a
   ChainTracks-compatible service (`GET {header_url}/findHeaderHexForHeight?height=N`). Fail-closed both ways: a root
   the service cannot answer for (outage, timeout, HTTP error, height not yet indexed) is `Unverifiable` with
   `HeaderLookupFailed { height, .. }` (the server's own condition: 503-class, the quote kept, the client retries the
   same payment), and a root that differs from the header is `RootMismatch` (a fraud signal). 0.3.x accepted the first
   case with a logged warning; 0.4.0 fails closed, by the project's ruling of 2026-10-08: an unchecked root is not
   evidence.

> **Warning: a header service URL is required.** The crate ships no header service and never skips SPV silently.
> Pass the base URL of your own ChainTracks-compatible service as `header_url` (for example a ChainTracks deployment
> you run). `None`, `Some("")`, the `DEFAULT_CHAINTRACKS_URL` `.invalid` placeholder (in any case, with or without a
> trailing slash or dot), any other `.invalid` host, a value without an `http(s)://` scheme, or a value whose host the
> gate cannot classify as a real hostname (userinfo, percent-encoding, backslashes, whitespace, non-ASCII, a
> non-numeric port) is refused with `PaymentVerifyError::NoHeaderService` before any other check: fail-closed, never
> a silent skip. The host is normalised before the placeholder comparison, so no spelling of the placeholder reaches
> DNS and surfaces as a lookup error instead of as the misconfiguration it is. Adopters with no header service opt
> out of SPV *by name* with `verify_brc29_payment_structural_only(..)` (the reader's structure with no script run,
> the output, the proof's presence; no root check).

### What a host answers

Every `PaymentVerifyError` means reject without internalizing, no refund owed. `PaymentVerifyError::is_server_side()`
is the one predicate the table needs.

| `PaymentVerifyError` | status | code | the quote |
|---|---|---|---|
| `NoHeaderService` | 500 | `ERR_SERVER_MISCONFIGURED` | fix the deployment |
| `KeyDerivation` (the server's key) | 500 | the host's own | fix the deployment |
| `Unverifiable { reason }`, `is_server_side()` (`HeaderLookupFailed`) | 503 | `ERR_HEADER_SERVICE_UNAVAILABLE` | kept: retry the SAME payment once the service answers |
| `Unverifiable { reason }`, the payer's (`InvalidBeef`, `SpendRefused` including work or memory declines naming the input, `NoProof`, `OutputMissing`, `NoTransaction`, `MalformedTransaction`, the sender's `KeyDerivation`) | 400 | `ERR_PAYMENT_INVALID` | kept: send another payment |
| `Underpaid`, `WrongScript`, `RootMismatch` | 400 | `ERR_PAYMENT_INVALID` | kept |
| `Ok(satoshis)` | serve | | |

| `header_url` | result |
|---|---|
| `None`, `Some("")`, whitespace only | `Err(NoHeaderService)` |
| the `.invalid` placeholder (trailing slash or dot or not, any case), any `.invalid` host, no `http(s)://` scheme | `Err(NoHeaderService)` |
| userinfo, `%`, `\`, whitespace, control or non-ASCII characters, a non-numeric port, a label that is not a hostname | `Err(NoHeaderService)` |
| service unreachable, HTTP error, unparseable answer, height not indexed | `Err(Unverifiable { reason: HeaderLookupFailed { height, .. } })`, warning logged (fail-closed; 503-class at the host, the quote kept) |
| the header at that height carries a different root | `Err(RootMismatch)` (fail-closed) |
| the header carries the proof's root | `Ok(satoshis)` |

A host whose match on `PaymentVerifyError` has a `_` arm compiles unchanged on 0.5.0 but answers that arm's 400 for a
header outage; add the 503 arm by `is_server_side()`. The 0.3 variants `BadTransaction`, `MissingOutput` and
`BadBeef` are gone (0.5.0): a payer's bytes are an `Unverifiable` reason now, and a `_` arm takes them.

The check itself is the core's (`bsv-middleware-core`) and answers in six words; `accept_verdict` is this crate's one
visible match from them to the table above (`Verified` is the only `Ok(satoshis)`; every other word is the same-named
`Err`, `Unverifiable` included). Callers that want the words themselves use `verify_brc29_payment_verdict` with any
`HeaderService` (`UrlHeaderService::resolve(header_url)` is the gated URL one); none of the words but `Verified` may
be served on. The named opt-out `verify_brc29_payment_structural_only` is the one function that answers `Ok` with
roots unchecked, because its caller asked for exactly that by name.

With the `d1-claims` feature, `claim_payment_nonce(&db, nonce, agent)` is an atomic `INSERT OR IGNORE` on a D1
`payment_claims` table (schema in `PAYMENT_CLAIMS_SCHEMA`): `Ok(true)` won, `Ok(false)` already used, `Err` storage
fault. It is the single-use guard for callers that run their own payment flow and never reach the middleware's
`try_consume_nonce`, and a second, globally consistent guard for the stock middleware on KV. Using both is safe. Claim
after `verify_brc29_payment` succeeds and before internalizing; `release_payment_nonce` frees a claim after a
pre-internalize failure.

```toml
bsv-middleware-cloudflare = { version = "0.7.0", features = ["d1-claims"] }
```

## Session storage backends

- **KV (default)** - `process_auth(req, &env, &options)`: sessions and the per-request nonce replay guard in the `AUTH_SESSIONS` KV namespace (a read, and a read + write, per authenticated request).
- **Durable Objects (0.3.3, opt-in)** - `process_auth_do(req, &env, &options, "AUTH_SESSION_STORE")`: one `AuthSessionStore` object per session nonce holds the session record and the consumed nonces, so a request costs two same-colo object round trips and no KV write; KV stays the cold path (the identity → session index written at the handshake, a KV-minted session migrated on first sight, the BRC-29 payment nonce scope). Bind the class and add a migration:

```toml
[[durable_objects.bindings]]
name = "AUTH_SESSION_STORE"
class_name = "AuthSessionStore"

[[migrations]]
tag = "vN-auth-session-store"
new_classes = ["AuthSessionStore"]
```

and export the class from the worker crate: `pub use bsv_middleware_cloudflare::AuthSessionStore;`. Any other store implements `SessionStorage` and goes through `process_auth_with_storage`.

## Releases

Tags `core-v*` and `v*` publish `bsv-middleware-core` and `bsv-middleware-cloudflare` through crates.io trusted publishing (`.github/workflows/release.yml`); the trusted-publishing entries exist on crates.io for both crates (verified 2026-10-10: both tag shapes authenticate). Releases go out by the tags, `core-v*` first, then `v*` once the core version is on crates.io (the adapter's package step resolves the core from crates.io alone).

## Lint

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo clippy -p bsv-middleware-cloudflare --target wasm32-unknown-unknown --all-features -- -D warnings`.
Build docs with `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`.
Install `cargo-deny` with `cargo install cargo-deny --locked --version 0.19.0`, then run `cargo deny --manifest-path core/Cargo.toml check` and `cargo deny --manifest-path Cargo.toml check`.
`tools/ci/secrets_scan.sh origin/main` scans tracked files and the branch and working diffs for the estate's secret shapes, reporting paths only. Public test keys require a reviewed digest exception only if a shape matches; none are currently excluded.
The six existing CI contexts stay required. After merge, the captain adds `deny` and `secrets` to main's required contexts.
