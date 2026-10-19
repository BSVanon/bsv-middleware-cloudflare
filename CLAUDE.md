# bsv-middleware-cloudflare

BSV authentication and payment middleware for Cloudflare Workers. Rust compiled to WASM.
Port of `auth-express-middleware` (BRC-103/104) and `payment-express-middleware` (BRC-29),
adapted for the Workers runtime (KV for state, async everywhere, explicit response signing).

**Detailed module-level docs are in `src/CLAUDE.md`.** This file is a quick orientation.

Since 0.4.0 this is a two-crate workspace: `core/` is `bsv-middleware-core` (the runtime-free rules: no worker,
no fetch, no KV/DO/D1, no clock; 0.4.0), and the root crate is the Workers adapter over it (0.7.0). Every 0.3 public
item of the adapter keeps its name, path and signature; `src/api_surface_tests.rs` pins the fleet's call shapes.
Since 0.5.0 the payment is read through bsv-rs 0.4's streaming reader with the scripts run, and nothing is refused
for its size or its counts (the posture of 2026-10-09, "a BEEF of any size"): no limit, no 413, no `BeefLimits`.
Since 0.5.1 (core 0.2.1) the floor is bsv-rs 0.4.1: a raw transaction with no input is the reader's invalid bytes
(`InvalidBeef { kind: "NoInputs", .. }` at its leading byte, bsv-stack-lean #58/#59; the same change as
bsv-middleware-rs 0.4.1), and the core's own `NoProof` for that shape stays beneath the reader as defense in depth.
No behavior change for a host: payer-side, 400 either way; the 22 vectors are unchanged.

Current release: adapter 0.7.0 / core 0.4.0, both on `bsv-rs = "0.7.0"` (caret), Rust 1.88.
Hashing uses bsv-rs `primitives::hash::{sha256, sha256_hmac, Sha256}`; no direct sha2 or hmac.

## Build

```bash
cargo test --workspace --all-features                      # both crates, 22 conformance vectors in each
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo check --target wasm32-unknown-unknown --all-features # the adapter on its target
cargo clippy --target wasm32-unknown-unknown --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
worker-build --release           # WASM binary (only for the example server)
```

`.github/workflows/ci.yml` is the machine gate (fmt; clippy on both crates and the adapter on wasm32; the tests of
both; both conformance runners by name; rustdoc with warnings denied; the core's publish dry-run; the adapter
packaged once its core version is on crates.io, the manifests held `[patch]`-free). `release.yml` publishes on tags
`core-v*` (the core) and `v*` (the adapter) through crates.io trusted publishing, whose entries are the owner's to
add. Run the same gates locally before a push. `cargo package` / `cargo publish --dry-run` of the adapter resolve
the core from crates.io alone (a `[patch]` does not reach the packaged manifest), so they fail until the core
version is published: publish the core first, then the adapter.

## Layout

```
core/src/                — bsv-middleware-core (no runtime dependency)
├── verdict.rs          — PaymentVerdict (the six words), UnverifiableReason (is_server_side), VerifiedPayment,
│                         PaymentFault (the host's own fault alone)
├── header_service.rs   — HeaderService trait, MerkleRoot, ServiceError, LookupFn, NoService
├── brc29.rs            — derivation (expected / sender locking script, prefix HMAC nonce), verify_payment_output
├── spv.rs              — decide_root, check_roots (the roots come from the reader; the lowest unanswered height)
├── payment_verify.rs   — verify_brc29_payment / verify_brc29_payment_verified (ONE pass through bsv-rs 0.4's
│                         verify_stream with every root granted, a Tap judging the subject's output as the bytes
│                         pass, then the roots asked of the service), verify_brc29_payment_structural_only
├── store.rs            — PaymentNonceStore + ClaimStore traits, MemoryStore, PAYMENT_NONCE_SCOPE
├── brc104.rs           — auth_headers, HttpRequestData/HttpResponseData, payloads, varint, signable filters
├── auth.rs             — SessionBinding, sign/verify, identity binding, handshake replies, response signing
├── session_lane.rs     — the lane's rules (moved whole)
├── refund/             — refund_locking_script + signer (feature `refund`)
└── types.rs            — AuthContext, PaymentContext, BsvPayment
core/tests/conformance_brc29.rs — the owner's 22 vectors through the trait with a stub (22/22)

src/                     — bsv-middleware-cloudflare (the Workers adapter)
├── lib.rs              — crate entry, re-exports, init_panic_hook()
├── env.rs              — WorkerEnv: wraps Env for KV + secret access
├── error.rs            — AuthCloudflareError with Express-compatible codes
├── types.rs            — AuthContext, PaymentContext, StoredSession, StoredPayment
├── middleware/
│   ├── auth.rs         — process_auth[_with_storage](), sign_response(), sign_json_response(),
│   │                     per-request nonce replay protection, CORS helpers (signing and the
│   │                     handshake replies are the core's, over SessionBinding)
│   ├── session_lane.rs — re-export of the core's lane; session_lane_tests.rs keeps the suite
│   ├── payment.rs      — process_payment_with_storage() (the paying output judged from the
│   │                     core's words: payer-side Unverifiable 400, server-side 503, a fault 500;
│   │                     accepted gate, single-use prefixes), deprecated stateless
│   │                     process_payment(), 402 builder
│   └── multipart.rs    — BRC-105 multipart payment transport parsing
├── storage/
│   ├── session_storage.rs — SessionStorage trait (sessions + single-use nonce store);
│   │                     SessionNonceStore adapts any of them to the core's PaymentNonceStore
│   ├── kv_session.rs   — BRC-103/104 session persistence, identity index, nonce consumption
│   └── kv_payment.rs   — payment records, unspent tracking, derivation prefix lifecycle
├── client/
│   ├── json_rpc.rs     — JSON-RPC 2.0 types with tolerant deserialization
│   └── storage.rs      — WorkerStorageClient: auth'd RPC to a wallet storage server
├── transport/
│   └── cloudflare.rs   — CloudflareTransport: BRC-104 header extraction (payload build and
│                         header names are the core's brc104, re-exported)
├── payment_verify.rs   — the 0.3 verify_brc29_payment* functions over the core, plus
│                         verify_brc29_payment_verified (VerifiedPayment { satoshis, txid }); UrlHeaderService
│                         (the 0.3.6 URL gate + Workers fetch), PaymentVerifyError (is_server_side),
│                         accept_verdict (the one match from the six words; only Verified is Ok)
├── payment_claims.rs   — feature `d1-claims`: atomic single-use payment-nonce claim on D1; D1ClaimStore
├── refund/             — feature-gated BRC-41 refund builder (issue_refund); signer re-exported from the core
├── api_surface_tests.rs — the 0.3 surface pinned as call sites (cfg(test))
└── utils/
    └── cors.rs         — CorsConfig and preflight helpers
```

## Key patterns

- **The core decides, the adapter renders** (0.4.0; the reader since 0.5.0). The payment check answers in the
  core's six words (`PaymentVerdict`); `payment_verify::accept_verdict` is the ONE match from them to the 0.3
  `Result<u64, PaymentVerifyError>`; `Verified` is its only `Ok`. `Unverifiable { reason: UnverifiableReason }`
  is `Err(PaymentVerifyError::Unverifiable { reason })` there, and the reason splits the class:
  `is_server_side()` is true for `HeaderLookupFailed { height }` alone (a header service that could not answer:
  fail-closed since 0.4.0 by the ruling of 2026-10-08, 503 at the host with the quote kept, the same payment retried);
  every other reason is the payer's (`InvalidBeef { offset, kind }`, `SpendRefused { txid, input }`,
  `NoProof { txid }`, `OutputMissing`, `NoTransaction`, `MalformedTransaction`, the sender's `KeyDerivation`:
  400 with the quote kept, another payment; the no-root ruling of 2026-10-09: the server never fetches a missing
  proof). `PaymentFault` (an `Err`) is the host's own fault alone (the server's key, a byte source that failed):
  500; a payer's bytes never produce one. The named structural-only opt-out is the one function that serves with
  roots unchecked, by name (`RootsUnchecked { satoshis, roots }`), outside `accept_verdict`. `NoHeaderService` is a
  server fault (500 at the host, never a 503). Hosts: `NoHeaderService` 500 `ERR_SERVER_MISCONFIGURED`;
  `Unverifiable` server-side 503 `ERR_HEADER_SERVICE_UNAVAILABLE`; every other refusal 400 `ERR_PAYMENT_INVALID`.
  Code that wants the words uses `verify_brc29_payment_verdict` or `bsv_middleware_cloudflare::core` directly;
  `verify_brc29_payment_verified` hands back `VerifiedPayment { satoshis, txid }` so a host never re-parses the BEEF.
  The core's full check reads the bytes ONCE through bsv-rs 0.4's `verify_stream` (scripts run: every unproven
  transaction's inputs executed against the parent outputs the BEEF carries; an Atomic subject the tip of its
  ancestry), the roots granted to a `RootsAskedAfter` and asked of the async `HeaderService` afterwards, lowest
  height first; order: no service → the bytes (soonest fault) → the output (`WrongScript`, `Underpaid`) → a proof →
  the roots → `Verified`. The stack review repository's question of 2026-10-09 (are the inputs executed? is a
  no-input ancestry refused?) is answered yes since 0.2.0 (0.1.0 was `Beef::verify_valid`, structure alone).
  The middleware's own payment path (`middleware/payment.rs`, `judge_paying_output`) matches the words once more,
  into its decisions: `Verified` serves (`satoshis_paid` is the amount read); `Underpaid` / `WrongScript` 400
  `ERR_INVALID_PAYMENT` with the quote kept: no fresh challenge, the prefix not consumed, the wallet not called
  (0.4.0; 0.3.8 answered 402 with a fresh challenge); `RootMismatch` or a payer-side `Unverifiable` 400
  `ERR_INVALID_PAYMENT`, the quote kept; `NoHeaderService` or a `PaymentFault` 500 `ERR_SERVER_MISCONFIGURED`;
  a server-side `Unverifiable` 503 `ERR_HEADER_SERVICE_UNAVAILABLE` with the quote kept (the server's transient
  condition: nothing charged, prefix not consumed, no fresh challenge; the client retries the same payment later).
  Only `Verified` serves. This path runs the output check alone (output 0, script and amount): no reader, no SPV
  (no merkle proof is checked against a header here, and what the wallet storage server does on internalize is not
  verified by this crate); `verify_brc29_payment` is the caller's proof step, run before the middleware.
  `src/transport/cloudflare.rs` still reads the whole request body; 0.6.0 streams it through `verify_stream_async`.

- **Authentication refusals are 401 responses (0.4.1).** `process_auth*` never returns an `Err` for a refusal:
  identity not the session's, bad or missing signature, session not authenticated, unknown session, missing or
  replayed per-request nonce, malformed auth headers, a refused handshake message are all
  `Ok(AuthResult::Response(401))` with CORS, unsigned (`AuthRefusal` → `refusal_response`, the one renderer;
  `judge_general_message` is the Request/Response-free decision; `settle` renders the 401-class `Err`s raised
  below the door). An `Err` from `process_auth*` is a fault (storage, config, transport, SDK): the host's 500.
  Hosts and `AuthFetch`-class clients re-handshake on 401 only; 0.4.0's `Err` was rendered 500 by every host.
- **Raw body passthrough.** `process_auth` returns the original request bytes via
  `AuthResult::Authenticated { body }`. Workers consume the body stream during auth
  payload construction, so downstream handlers must use this `body` instead of
  re-reading the request.
- **Replay protection is a deliberate hardening divergence from the TS reference**
  (security audit findings #30/#44). The TS stack (`@bsv/sdk` `Peer.processGeneralMessage`,
  checked through v2.0.13) never records consumed per-request nonces; this crate
  consumes `(session_nonce, x-bsv-auth-nonce)` via `SessionStorage::try_consume_nonce`
  after signature verification and 401s reuse with `ERR_REPLAYED_REQUEST`. Payment
  derivation prefixes are likewise single-use: consumed (no expiry) *before*
  internalize, kept consumed on `accepted:false`, released best-effort on internalize
  *error* only. Residual window under eventually-consistent KV is documented in the
  `middleware/auth.rs` module docs and `KvSessionStorage::try_consume_nonce`.
- **`accepted` gate on internalize** (audit #44). `PaymentResult::Verified` implies the
  wallet affirmatively returned `accepted: true`; anything else 402s with a fresh
  challenge. The TS reference calls `next()` regardless of `accepted`.
- **`process_payment` is deprecated** (stateless — no single-use prefixes). Use
  `process_payment_with_storage`; the `SessionStorage` doubles as the nonce store.
- **Never update `peer_nonce` for General messages.** The TS SDK sets `peerNonce`
  once at handshake and treats the per-message nonce as random. Storing the
  per-message nonce breaks `yourNonce` verification and kills the AuthFetch promise.
  See nonce handling notes in `src/CLAUDE.md`.
- **`sign_json_response` over `sign_response`.** The former includes body bytes in
  the signed payload, matching Express's `res.json` hijacking behavior. Use it
  unless you already have a constructed `Response`.
- **`add_cors_headers` appends.** It uses `response.headers()` rather than
  `with_headers()` so it doesn't strip auth headers added by `sign_json_response`.
- **InitialResponse signing data = client nonce only.** The TS SDK's
  `Buffer.from(clientNonce + serverNonce, 'base64')` stops at the first `=` padding
  and effectively only decodes the client nonce. `WorkerStorageClient` matches.
- **Dual-license.** `MIT OR Apache-2.0`. Both LICENSE files live at the crate root.

## Error codes (Express parity)

| Status | Code | Variant |
|---|---|---|
| 400 | `ERR_MALFORMED_PAYMENT` / `ERR_INVALID_DERIVATION_PREFIX` / `ERR_PAYMENT_FAILED` / `ERR_INVALID_PAYMENT` (a short or misdirected output, `RootMismatch`, a payer-side `Unverifiable`: invalid BEEF, a refused spend, no proof; the quote kept) / `ERR_SERIALIZATION` | payment / serialization |
| 401 | `UNAUTHORIZED` / `ERR_INVALID_AUTH` / `ERR_SESSION_NOT_FOUND` / `ERR_REPLAYED_REQUEST`¹ | auth (every one an `AuthResult::Response` since 0.4.1, never an `Err`) |
| 402 | `ERR_PAYMENT_REQUIRED` / `ERR_PAYMENT_FAILED`¹ (wallet rejected, fresh challenge attached) | payment |
| 500 | `ERR_SERVER_MISCONFIGURED` (no auth first, `NoHeaderService`, a `PaymentFault`: the server's key) / `ERR_PAYMENT_INTERNAL` / `ERR_STORAGE` / `ERR_SDK` / `ERR_TRANSPORT` / `ERR_CONFIG` | payment / infra |
| 503 | `ERR_HEADER_SERVICE_UNAVAILABLE`¹ (a server-side `Unverifiable`: the header service could not answer at `fields.height`; quote kept, retry the same payment) | payment (rendered directly, no `AuthCloudflareError` variant) |

¹ Not in the Express reference — hardening additions (audit #30/#44; the 503 by the fail-closed ruling of 2026-10-08;
the payer-side 400 for a missing proof by the no-root ruling of 2026-10-09).

Full table with `From` conversions in `src/CLAUDE.md`.

## Headers (BRC-104 + BRC-29)

All headers match the Express middleware. See `transport::auth_headers` and
`middleware::payment::payment_headers` for constants.

Auth: `x-bsv-auth-version`, `x-bsv-auth-identity-key`, `x-bsv-auth-nonce`,
`x-bsv-auth-your-nonce`, `x-bsv-auth-initial-nonce`, `x-bsv-auth-signature`,
`x-bsv-auth-message-type`, `x-bsv-auth-request-id`, `x-bsv-auth-requested-certificates`.

Payment: `x-bsv-payment`, `x-bsv-payment-version`, `x-bsv-payment-satoshis-required`,
`x-bsv-payment-derivation-prefix`, `x-bsv-payment-satoshis-paid`, `x-bsv-payment-txid`,
`x-bsv-payment-transports` (BRC-105 negotiation).

## Reference code

| What | Where |
|---|---|
| Express auth middleware (reference) | `~/bsv/auth-express-middleware/` |
| Express payment middleware (reference) | `~/bsv/payment-express-middleware/` |
| BSV SDK (used for auth, wallet, transaction) | `~/bsv/bsv-rs/` (crates.io: `bsv-rs = "0.7.0"`) |
| Consumer example | `~/bsv/rust-message-box/` |
| Agent consumers | `~/bsv/agents/{banana-agent,claude-agent,...}` |

## The Durable Object session backend (0.3.3)

`storage/do_session.rs`: one `AuthSessionStore` object per session nonce holds the session record and the consumed per-request nonces (an atomic put-if-absent, no KV write per request); KV stays the cold path (the identity index, a KV-minted session migrated on first sight, the payment scope). Adopt with `process_auth_do(req, &env, &options, "AUTH_SESSION_STORE")`, a DO binding + migration in the worker's wrangler, and `pub use bsv_middleware_cloudflare::AuthSessionStore;` in the worker crate. The pure `SessionCell` and `route_scope` are unit-pinned.
