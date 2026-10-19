# bsv-middleware-cloudflare/src

> BSV blockchain authentication and payment middleware for Cloudflare Workers.

## Overview

This crate provides BRC-103/104 authentication and BRC-29 (Direct Payment) middleware for Cloudflare Workers. It enables building authenticated and paid APIs using BSV blockchain-based identity and micropayments. The implementation uses Cloudflare KV for session and payment storage, with built-in CORS support for browser clients.

This is a 1:1 port of the Express-based `auth-express-middleware` and `payment-express-middleware`, adapted for Cloudflare Workers. Error codes and response formats match the Express versions exactly.

Since 0.4.0 the rules live in `bsv-middleware-core` (`../core/`, no runtime dependency) and this crate is the Workers adapter over it: `worker::Request` in, the core's data through, HTTP out, plus the KV / Durable Object / D1 implementations of the core's traits and the URL-configured header service. M14 removes deprecated `process_payment` and changes the payment entry points to require `PaymentPrefixStore`; other retained items keep their paths. Items whose type moved are re-exported at their 0.3 paths (`types::{AuthContext, PaymentContext, BsvPayment}`, `transport::{auth_headers, HttpRequestData, HttpResponseData}`, `middleware::session_lane`, `refund::signer`, `middleware::payment::PAYMENT_NONCE_SCOPE`). `api_surface_tests.rs` pins the fleet's call shapes at compile time.

## Architecture

```
lib.rs                    # Crate entry point, re-exports, init_panic_hook()
├── env.rs               # Cloudflare environment helpers (WorkerEnv)
├── error.rs             # AuthCloudflareError enum with HTTP status codes
├── types.rs             # Core data structures and current_time_ms()
├── client/              # Storage server RPC client
│   ├── json_rpc.rs      # JSON-RPC 2.0 request/response types
│   └── storage.rs       # WorkerStorageClient with BRC-103/104 auth
├── middleware/          # Request processing middleware
│   ├── auth.rs          # BRC-103/104 authentication + replay protection + response signing + CORS
│   └── payment.rs       # BRC-29 payment verification (accepted gate, single-use prefixes) and 402 responses
├── storage/             # Pluggable persistence (default: Cloudflare KV)
│   ├── session_storage.rs # SessionStorage trait: sessions + single-use nonce store
│   ├── kv_session.rs    # Session storage with TTL + nonce consumption
│   └── kv_payment.rs    # Payment storage with duplicate detection
├── transport/           # HTTP transport layer
│   └── cloudflare.rs    # BRC-104 header handling + payload serialization
└── utils/               # Utilities
    └── cors.rs          # CorsConfig and CORS header helpers
```

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root with re-exports and `init_panic_hook()` for WASM error handling |
| `env.rs` | `WorkerEnv` wrapper for accessing Cloudflare secrets and KV bindings |
| `error.rs` | `AuthCloudflareError` enum with HTTP status codes, error codes, and JSON serialization |
| `types.rs` | Core types: `AuthContext`, `PaymentContext`, `BsvPayment`, `ErrorResponse`, `StoredSession`, `StoredPayment`, `current_time_ms()` |
| `client/mod.rs` | Re-exports `WorkerStorageClient`, `JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcError` |
| `client/json_rpc.rs` | JSON-RPC 2.0 types with tolerant deserialization (handles non-standard `{isError, name, message}` format from storage servers) |
| `client/storage.rs` | `WorkerStorageClient` - WASM-compatible storage client with BRC-103/104 auth handshake |
| `middleware/mod.rs` | Re-exports for auth and payment middleware |
| `middleware/auth.rs` | BRC-103/104 authentication (`process_auth` / `process_auth_with_storage`), every authentication refusal the middleware's own 401 `AuthResult::Response` (0.4.1: `AuthRefusal` rendered by `refusal_response`, the one place; `judge_general_message` is the `Request`/`Response`-free decision of the general path, `settle` renders the 401-class `Err`s raised below the door; an `Err` out of `process_auth*` is a fault), per-request nonce replay protection (401 `ERR_REPLAYED_REQUEST` on reuse), `sign_response()`, `sign_json_response()`, inline CORS (`add_cors_headers`, `handle_cors_preflight`), handshake handling (InitialRequest, CertificateRequest, CertificateResponse). `process_auth` returns raw body bytes via `AuthResult::Authenticated { body }` for General messages. |
| `middleware/payment.rs` | BRC-29 payment verification (`process_payment_with_storage` with `accepted` gate + single-use derivation prefixes; permanent txid bindings), the paying output judged from the core's words (`judge_paying_output`, the path's one match: `Verified` serves, `Underpaid` / `WrongScript` 400 with the quote kept (no fresh challenge, prefix not consumed, wallet not called), `RootMismatch` or a payer-side `Unverifiable` (invalid BEEF, a refused spend, no proof, unreadable bytes, no such output) 400 with the quote kept, `NoHeaderService` or a `PaymentFault` (the server's key) 500, a server-side `Unverifiable` (`is_server_side_unverifiable`) 503 `ERR_HEADER_SERVICE_UNAVAILABLE` with the quote kept (fail-closed; `HEADER_SERVICE_UNAVAILABLE`, `header_service_unavailable_description`)), 402 response generation, `payment_headers` module (incl. `TXID`), `PAYMENT_NONCE_SCOPE`, `payment_failed_response()`. Internally split into a request/`Response`-free decision core (`decide_payment` → `PaymentDecision`, with an internalize seam) so the money path executes under native `cargo test` (audit finding #62), plus thin wrappers that render decisions into the exact historical HTTP responses. |
| `api_surface_tests.rs` | `cfg(test)`: the 0.3 public surface pinned as call sites (the fleet's `verify_brc29_payment` gate, the context and session types, the re-exports, the `SessionBinding` conversions) |
| `payment_verify.rs` | The Workers adapter of the core's BRC-29 verification: the 0.3 functions with their signatures over `bsv_middleware_core::{brc29, spv, payment_verify}` (`expected_brc29_locking_script`; `verify_brc29_payment_output`, script + amount, sync, offline; `verify_brc29_payment`, the core's full check: the payment read ONCE through bsv-rs 0.4.0's streaming reader with the scripts run, the output, a proof's presence, then SPV through the header service named by `header_url`; `verify_brc29_payment_verified` (0.5.0), the same with the subject's txid, `VerifiedPayment { satoshis, txid }`; `verify_brc29_payment_structural_only`, the named opt-out with no script run and no SPV; `verify_brc29_payment_with_header_lookup`, a caller-supplied lookup with no URL gate, which drives `conformance/brc29-payment-vectors.json` via `tests/conformance_brc29.rs`); `UrlHeaderService`, the core's `HeaderService` over a ChainTracks-compatible base URL with Workers `fetch`, built only through the 0.3.6 gate `UrlHeaderService::resolve`: `None` / empty / the `.invalid` placeholder in any spelling (the host is normalised — lowercased, trailing dot stripped — before the comparison) / no `http(s)://` scheme / a host the gate cannot classify (userinfo, `%`, `\`, whitespace, non-ASCII, bad port) is `NoHeaderService`, fail-closed; once named, fail-closed on service errors too (`Unverifiable`, 503-class at the host, the quote kept; 0.3.x accepted with a warning) and on a root mismatch (the gate `resolve_header_service` and the core's per-root `decide_root` are pure and table-tested); `PaymentVerifyError` (the 0.3 type with 0.5.0's `Unverifiable { reason: UnverifiableReason }` and `is_server_side()`; `BadTransaction` / `MissingOutput` / `BadBeef` gone, a payer's bytes being `Unverifiable` reasons; `From<PaymentFault>` for the server's own faults); `accept_verdict`, the ONE visible match from the six words (`Verified` → `Ok(satoshis)`, the only `Ok`; every other word → the same-named `Err`, `Unverifiable` included, a server-side one logged); `verify_brc29_payment_structural_only` serves the core's `RootsUnchecked` by name, outside `accept_verdict`; `verify_brc29_payment_verdict` for callers that want the words themselves. Hosts: `NoHeaderService` 500, `is_server_side()` 503 with the quote kept, everything else 400. |
| `payment_claims.rs` | Feature `d1-claims`: `D1PrefixStore`, transaction-bound claims with a batched upsert/read, `PAYMENT_CLAIMS_SCHEMA` and one-time `PAYMENT_CLAIMS_MIGRATION`; fleet `payment_prefix_gate` takes explicit `FaultPosture`, with signed refusal left to the host; `D1ClaimStore` and the old nonce-named helpers are for idempotency keys only |
| `middleware/session_lane.rs` | `pub use bsv_middleware_core::session_lane::*` (the lane's rules moved whole in 0.4.0); `middleware/session_lane_tests.rs` keeps the adapter's copy of the suite and pins `tests/fixtures/session_lane.vectors.json` |
| `refund/mod.rs` | `issue_refund` (the storage-client flow); `signer` is `bsv_middleware_core::refund::signer` re-exported; the client's receiving key is `bsv_middleware_core::refund::refund_locking_script` |
| `storage/mod.rs` | Re-exports for storage trait + KV implementations |
| `storage/session_storage.rs` | `SessionStorage` trait: pluggable session persistence + single-use nonce consumption (`try_consume_nonce` / `release_nonce`); `SessionNonceStore(&storage)` adapts any of them to the core's `PaymentNonceStore`; `MemorySessionStorage` (`cfg(test)`, `pub(crate)`) is an atomic in-memory test double with consume/release fault injection, used by auth tests |
| `storage/kv_session.rs` | `KvSessionStorage` for BRC-103/104 session persistence with identity index and nonce-consumption records (read-then-write; see residual window note) |
| `storage/kv_payment.rs` | `KvPaymentStorage` for payment records with unspent/derivation tracking |
| `transport/mod.rs` | Re-exports for transport layer |
| `transport/cloudflare.rs` | `CloudflareTransport` for BRC-104 header extraction (incl. `content-type` media type) into the core's payloads (`bsv_middleware_core::brc104`: `auth_headers`, `HttpRequestData`, `HttpResponseData`, `build_request_payload`, `write_varint`, the signable-header filters, `message_to_headers`, re-exported here). `extract_auth_message()` returns `(AuthMessage, Vec<u8>)` with raw body passthrough. |
| `utils/mod.rs` | Re-exports for utility functions |
| `utils/cors.rs` | `CorsConfig`, `cors_headers()`, preflight handlers, response helpers |

## Key Exports

### Main Entry Points (from `lib.rs`)

| Export | Description |
|--------|-------------|
| `process_auth` | Main authentication middleware function (default KV storage from `AUTH_SESSIONS` binding) |
| `process_auth_with_storage` | Authentication middleware with a caller-supplied `SessionStorage` backend |
| `process_payment_with_storage` | Main payment middleware function: `accepted` gate + permanent derivation-prefix bindings via `PaymentPrefixStore` |
| `sign_response` | Sign a response for BRC-103/104 interop (required for authenticated clients) |
| `sign_json_response` | Sign a JSON response with body bytes included in signed payload (recommended over `sign_response`) |
| `WorkerStorageClient` | Storage server RPC client with BRC-103/104 authentication (re-exported from `client`) |
| `init_panic_hook` | Initialize WASM panic hook for better error messages |
| `verify_brc29_payment` / `verify_brc29_payment_verified` / `verify_brc29_payment_output` / `expected_brc29_locking_script` | Pre-internalize payment verification (`payment_verify`); the middleware's own flow runs `verify_brc29_payment_output` on output 0 before internalizing (0.3.8), the full `verify_brc29_payment` (the reader, the output, the proof, SPV) is for callers with their own payment flow; `_verified` adds the subject's txid |
| `claim_payment_nonce` / `release_payment_nonce` | Feature `d1-claims`: idempotency keys only on D1 (`payment_claims`), never derivation prefixes |

### Middleware Types

| Type | Description |
|------|-------------|
| `AuthMiddlewareOptions` | Config: `server_private_key`, `allow_unauthenticated`, `certificates_to_request`, `session_ttl_seconds`, `on_certificates_received` |
| `AuthResult` | Enum: `Authenticated { context, request, session, body }` or `Response(Response)`. `body` is the raw request body bytes (populated for General messages, empty for handshake/unauthenticated). |
| `AuthSession` | Session info for signing responses: `server_private_key`, `session_nonce`, `peer_nonce`, `peer_identity_key`, `request_id` |
| `PaymentMiddlewareOptions<F>` | Config: `server_private_key`, `calculate_price` function (`Fn(&Request) -> u64`), `storage_url` (defaults to mainnet). Constructors: `new()`, `with_storage_url()` |
| `PaymentResult` | Enum: `Free`, `Required(Response)`, `Verified(PaymentContext)`, `Failed(Response)`. `Verified` implies the wallet returned `accepted: true`; a rejected payment yields `Failed` with a 402 + fresh challenge. |

### Context Types

| Type | Description |
|------|-------------|
| `AuthContext` | Authenticated peer info: `identity_key: String`, `is_authenticated: bool`. Factory methods: `authenticated()`, `unauthenticated()` |
| `PaymentContext` | Payment info: `satoshis_paid: u64`, `accepted: bool`, `tx: Option<String>` (base64 transaction) |

### Storage Types

| Type | Description |
|------|-------------|
| `SessionStorage` | Trait: pluggable session persistence + single-use nonce store (`try_consume_nonce(scope, nonce, ttl)` / `release_nonce`). Implement with atomic put-if-absent where the backend supports it (e.g. Durable Object SQLite). |
| `KvSessionStorage` | Default `SessionStorage` backed by Cloudflare KV with TTL expiration, identity index, and nonce-consumption records |
| `KvPaymentStorage` | Payment storage with duplicate detection, unspent tracking, and derivation prefix management |
| `StoredSession` | Persisted session: `session_nonce`, `peer_identity_key`, `peer_nonce`, `is_authenticated`, `certificates_required`, `certificates_validated`, timestamps |
| `StoredPayment` | Persisted payment: `txid`, `vout`, `satoshis`, `sender_identity_key`, derivation info, `spent` flag |

### Transport Types

| Type | Description |
|------|-------------|
| `CloudflareTransport` | Static methods for BRC-104 header extraction, message construction, payload building, and `create_headers()` helper. `extract_auth_message()` returns `(AuthMessage, Vec<u8>)` where the second element is raw body bytes (populated for General messages, empty for handshake). |
| `HttpRequestData` | Deserialized request from General message payload: `request_id`, `method`, `path`, `search`, `headers`, `body`. Has `url()` method combining path + search. |
| `HttpResponseData` | HTTP response data for General message serialization: `request_id`, `status`, `headers`, `body` |
| `auth_headers` | Module with BRC-104 header name constants (including `INITIAL_NONCE`) |

### Client Types

| Type | Description |
|------|-------------|
| `WorkerStorageClient` | WASM-compatible RPC client for `storage.babbage.systems` with BRC-103/104 auth. Uses `worker::Fetch` for HTTP. Methods: `rpc_call()`, `make_available()`, `find_or_insert_user()`, `internalize_action()`, `list_outputs()` |
| `JsonRpcRequest` | JSON-RPC 2.0 request: `jsonrpc`, `method`, `params`, `id`. Factory: `new(id, method, params)` |
| `JsonRpcResponse` | JSON-RPC 2.0 response: `result`, `error`, `id` |
| `JsonRpcError` | JSON-RPC error with optional fields: `code`, `message`, `data`, `name`. Handles both standard and non-standard (storage server) error formats. Implements `Display`. |

`WorkerStorageClient` endpoints:
- `WorkerStorageClient::mainnet(wallet)` - connects to `https://storage.babbage.systems`
- `WorkerStorageClient::testnet(wallet)` - connects to `https://staging-storage.babbage.systems`
- `WorkerStorageClient::new(wallet, url)` - connects to custom endpoint

### Error Handling

| Type | Description |
|------|-------------|
| `AuthCloudflareError` | Error enum with variants for auth, payment, and infrastructure errors |
| `Result<T>` | Alias for `std::result::Result<T, AuthCloudflareError>` |

### Utility Types and Functions

| Export | Description |
|--------|-------------|
| `CorsConfig` | Configurable CORS settings: origins, methods, headers, expose headers, max age |
| `cors_headers()` | Create CORS headers with default config (from `utils::cors`) |
| `cors_headers_with_config()` | Create CORS headers with custom config (from `utils::cors`) |
| `handle_cors_preflight()` | Handle OPTIONS preflight with default CORS (from `utils::cors`) |
| `handle_cors_preflight_with_config()` | Handle OPTIONS preflight with custom CORS config |
| `add_cors_to_response()` | Add default CORS headers to existing response |
| `add_cors_to_response_with_config()` | Add custom CORS headers to existing response |
| `add_cors_headers()` | Inline CORS from `middleware::auth` (includes all BSV auth + payment headers, including `x-bsv-payment-txid`). Appends to existing response headers (does not replace). |
| `add_payment_headers()` | Add payment success headers (`x-bsv-payment-satoshis-paid`) to response |
| `payment_headers` | Module with BRC-29 payment header name constants (including `TXID`) |
| `payment_failed_response()` | Creates a 400 error response for payment failures with CORS |
| `ErrorResponse` | Serializable error body: `status`, `code`, `description` |

## Usage

### Authentication with Response Signing

```rust
use bsv_middleware_cloudflare::{
    process_auth, sign_json_response, AuthMiddlewareOptions, AuthResult,
    utils::handle_cors_preflight,
};
use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Handle CORS preflight
    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    let auth_options = AuthMiddlewareOptions {
        server_private_key: env.secret("SERVER_PRIVATE_KEY")?.to_string(),
        allow_unauthenticated: false,
        ..Default::default()
    };

    let (auth_context, req, session, _body) = match process_auth(req, &env, &auth_options).await
        .map_err(|e| Error::from(e.to_string()))?
    {
        AuthResult::Authenticated { context, request, session, body } => (context, request, session, body),
        AuthResult::Response(response) => return Ok(response),
    };

    // Build response data
    let data = serde_json::json!({
        "identity": auth_context.identity_key
    });

    // Sign the response before returning (recommended: includes body in signed payload)
    if let Some(ref session) = session {
        sign_json_response(&data, 200, &[], session)
            .map_err(|e| Error::from(e.to_string()))
    } else {
        Response::from_json(&data)
    }
}
```

### Adding Payment Verification

```rust
use bsv_middleware_cloudflare::{
    process_auth, process_payment_with_storage, sign_json_response,
    AuthMiddlewareOptions, KvPrefixStore, KvSessionStorage, PaymentMiddlewareOptions,
    AuthResult, PaymentResult,
};

// After authentication...
let payment_options = PaymentMiddlewareOptions::new(
    server_key,
    |req: &Request| {
        // Price function: return satoshis required for this request
        if req.path().starts_with("/premium") { 1000 } else { 100 }
    },
);

// KV retains G3; pass D1PrefixStore for exact M14 enforcement.
let session_storage = KvSessionStorage::new(env.kv("AUTH_SESSIONS")?, "auth", 3600);

match process_payment_with_storage(&req, &auth_context, &payment_options, &KvPrefixStore(&session_storage)).await
    .map_err(|e| Error::from(e.to_string()))?
{
    PaymentResult::Free => { /* No payment needed */ }
    PaymentResult::Verified(payment_ctx) => {
        // Wallet ACCEPTED the payment (accepted == true guaranteed).
        // payment_ctx.satoshis_paid, payment_ctx.tx
    }
    PaymentResult::Required(response) => return Ok(response), // 402
    PaymentResult::Failed(response) => return Ok(response),   // 400 bad/replayed, 402 rejected
}
```


### Environment Wrapper

```rust
use bsv_middleware_cloudflare::env::WorkerEnv;

let worker_env = WorkerEnv::new(&env);
let server_key = worker_env.get_server_private_key()?;
let auth_kv = worker_env.get_auth_sessions_kv()?;
let payments_kv = worker_env.get_payments_kv()?;
let environment = worker_env.get_environment(); // "production" default
```

### Storage Client

```rust
use bsv_middleware_cloudflare::WorkerStorageClient;
use bsv_sdk::wallet::ProtoWallet;

// Create client (performs BRC-103/104 handshake on first RPC call)
let wallet = ProtoWallet::from_private_key(&server_key)?;
let mut client = WorkerStorageClient::mainnet(wallet);

// Make authenticated RPC calls to storage server
let result = client.make_available().await?;
let user = client.find_or_insert_user(&identity_key).await?;
let internalized = client.internalize_action(auth_json, args_json).await?;
let outputs = client.list_outputs(auth_json, args_json).await?;
```

## Response Signing: `sign_response` vs `sign_json_response`

Two functions exist for signing responses. Prefer `sign_json_response` when possible.

| Function | Body in Signature | Use Case |
|----------|-------------------|----------|
| `sign_response(response, session)` | No (empty body in payload) | Legacy; when you already have a `Response` object |
| `sign_json_response(data, status, extra_headers, session)` | Yes (actual JSON bytes) | Recommended; matches Express `res.json()` hijacking behavior |

`sign_json_response` also filters `extra_headers` for signing: only `x-bsv-*` (excluding `x-bsv-auth-*`) and `authorization` headers are included in the signed payload, matching `SimplifiedFetchTransport` rules. All extra headers appear in the HTTP response regardless.

Note: `extract_signable_headers` in the transport layer also includes the `content-type` header (stripped to media type only, params like `; charset=utf-8` removed), matching TS SDK behavior.

## BRC Standards Implementation

### BRC-103/104

The authentication flow handles:
1. **Initial handshake** at `/.well-known/auth` - exchanges nonces and identity keys
2. **Certificate exchange** - CertificateRequest/CertificateResponse for identity verification (both directions)
3. **General requests** - signature verification using session nonces
4. **Response signing** - `sign_json_response()` / `sign_response()` signs outgoing responses for BRC-103/104 interop

Message types handled:
- `InitialRequest` / `InitialResponse` - session establishment
- `CertificateRequest` / `CertificateResponse` - certificate exchange (both directions)
- `General` - authenticated API requests (via headers) and signed responses

Key difference from Express: Express uses response hijacking (`res.send`/`res.json` interception). Workers cannot do this, so `sign_json_response()` (or `sign_response()`) must be called explicitly before returning responses to authenticated clients.

### BRC-29 (Direct Payment)

Payment flow (`process_payment_with_storage`):
1. Client makes request without payment
2. Server returns **402 Payment Required** with `derivation_prefix` and `satoshis_required`
3. Client constructs payment transaction, sends with `x-bsv-payment` header (JSON)
4. Server verifies derivation prefix via HMAC nonce, **reads output 0 through the core's output check and decides its word** (`400 ERR_INVALID_PAYMENT` with the quote kept, no fresh challenge, when the output is short or pays another key, when the transaction is unreadable or has no output 0, and for any payer-side `Unverifiable`; `500 ERR_SERVER_MISCONFIGURED` on `NoHeaderService` or a `PaymentFault`; `503 ERR_HEADER_SERVICE_UNAVAILABLE` with the quote kept on a server-side `Unverifiable`), **binds it permanently to the subject txid through PaymentPrefixStore** (`400 ERR_INVALID_DERIVATION_PREFIX` if already used), internalizes payment via `WorkerStorageClient::internalize_action()`, and **gates on `accepted: true`** (`402 ERR_PAYMENT_FAILED` with a fresh challenge if the wallet rejected), then returns success

Consumption ordering on the money path: prefix consumed **before** internalize; released (best-effort) only if internalize **errors** (so an honest client can retry the same payment); kept consumed on success or `accepted: false`.


Payment uses `ProtoWallet` for nonce creation/verification and `WorkerStorageClient` (connected to `storage.babbage.systems` by default) for transaction processing. The `storage_url` field on `PaymentMiddlewareOptions` controls the storage server endpoint.

### BRC-104 (HTTP Headers)

Auth headers (in `transport::auth_headers`):
- `x-bsv-auth-version` - Protocol version
- `x-bsv-auth-identity-key` - Sender's public key (66-char hex)
- `x-bsv-auth-nonce` / `x-bsv-auth-your-nonce` - Session nonces
- `x-bsv-auth-initial-nonce` - Initial handshake nonce
- `x-bsv-auth-signature` - Message signature (hex)
- `x-bsv-auth-message-type` - Message type string
- `x-bsv-auth-request-id` - 32-byte request correlation ID (base64)
- `x-bsv-auth-requested-certificates` - Certificate specification (JSON)

Payment headers (in `middleware::payment::payment_headers`):
- `x-bsv-payment` - Payment JSON (derivation info + base64 BEEF transaction)
- `x-bsv-payment-version` - Payment protocol version ("1.0")
- `x-bsv-payment-satoshis-required` - Amount required
- `x-bsv-payment-derivation-prefix` - Server-generated nonce for address derivation
- `x-bsv-payment-satoshis-paid` - Amount paid (response)
- `x-bsv-payment-txid` - Transaction ID of the accepted payment (response)

## Critical Implementation Notes

### Replay Protection (Hardening Divergence from the TS Reference)

The TS reference stack has **no** replay protection: `@bsv/sdk`
`Peer.processGeneralMessage` (checked at 1.10.3 and 2.0.13) verifies `yourNonce`
via stateless HMAC and binds `message.nonce` into the signature keyID, but never
records consumed nonces; `@bsv/payment-express-middleware` 1.2.3 likewise only
HMAC-checks the derivation prefix and even calls `next()` when
`internalizeAction` returns `accepted: false`. Per security audit findings
#30/#44, this crate diverges deliberately:

- **Auth:** after signature verification, `(session_nonce, x-bsv-auth-nonce)` is
  consumed via `SessionStorage::try_consume_nonce` with `ttl = session_ttl_seconds`;
  reuse → `401 ERR_REPLAYED_REQUEST`. General messages without a per-request
  nonce → `401 ERR_INVALID_AUTH`. Storage faults fail **closed** (an `Err`,
  never a refusal). Every authentication refusal is the middleware's own 401
  response (0.4.1), never an `Err`.
- **Payment (M14, BRC-105):** `PaymentPrefixStore` binds the first subject txid forever
  before any wallet call. Another txid gets 400 `ERR_INVALID_DERIVATION_PREFIX`,
  no fresh challenge, no internalize or refund. Held/served records refuse the
  same txid too. An internalize error releases only that txid's attempt; an
  identical retry can re-take it once. `accepted: false` keeps the prefix held.
  `process_payment` is removed; both storage entry points require a prefix store.

Auth KV still has concurrent and cross-edge replay windows. Payment
`KvPrefixStore` retains G3: no compare-and-swap, racing requests and about 60
seconds of propagation can admit competing transactions. `D1PrefixStore` is
exact. A DO auth backend does not change the payment backend. Run both
`PAYMENT_CLAIMS_MIGRATION` statements once before deploying over an existing
claims table; legacy NULL-txid rows remain closed. Never expire prefix rows.
Fleet doors use `payment_prefix_gate`: other txid 400 `ERR_PAYMENT_INVALID`,
same/unknown 409 `ERR_PAYMENT_REPLAYED`, closed faults 503
`ERR_PAYMENT_UNAVAILABLE` with `retryable: true`, `Retry-After: 5`, quote and
prefix kept, and no fresh challenge. Every host must pass `FaultPosture::Closed`
and forward `Refuse` headers through its signed-response helper. `Open` is
deprecated and returns `Fault` for one compatibility release only. Bodies never name either txid.

### Nonce Handling (TS SDK Compatibility)

**Never update `peer_nonce` after handshake for General messages.** The TS SDK sets `peerSession.peerNonce` once during handshake and never updates it for General messages. The per-message nonce in General messages is a random value (not HMAC-derived). Storing it as `peer_nonce` causes:
1. Response `yourNonce` mismatch -> client's `verifyNonce` fails
2. `processGeneralMessage` throws -> general message callbacks never fire
3. `AuthFetch` Promise never resolves -> 402 payment handling breaks
4. Signature `keyID` mismatch (uses `peer_nonce`, client expects handshake nonce)

### InitialResponse Signature Verification (TS SDK Compatibility)

The TS SDK computes signing data as `Buffer.from(clientNonce + serverNonce, 'base64')`, which due to Node.js `Buffer.from` stopping at the first `=` padding, only decodes the first nonce's raw bytes (32 bytes). The Rust client (`WorkerStorageClient`) matches this by using only the client's session nonce as signing data, not the concatenation of both nonces.

### Raw Body Passthrough

`process_auth` now returns raw request body bytes via `AuthResult::Authenticated { body }`. For General (authenticated) messages, this contains the original request body consumed during auth payload construction. For handshake and unauthenticated requests, this is empty (`vec![]`). This allows downstream handlers to access the body without re-reading the request (which would fail since Workers consume the body stream).

### CORS Headers (add_cors_headers)

The `add_cors_headers()` function in `middleware::auth` uses `response.headers()` to append to existing headers rather than creating new `Headers` and calling `with_headers()`. This is critical because `with_headers()` replaces all existing headers, which would strip auth headers added by `sign_json_response`.

## Error Handling

`AuthCloudflareError` provides:
- `status_code()` - HTTP status (400, 401, 402, 500)
- `error_code()` - Machine-readable code matching Express middleware exactly
- `to_json()` - JSON response body with `{ status, code, description }`

Error variants and their codes (matching Express middleware):

| Variant | Status | Code | Category |
|---------|--------|------|----------|
| `Unauthorized` | 401 | `UNAUTHORIZED` | Auth |
| `InvalidAuthentication(String)` | 401 | `ERR_INVALID_AUTH` | Auth |
| `SessionNotFound(String)` | 401 | `ERR_SESSION_NOT_FOUND` | Auth |
| `ServerMisconfigured` | 500 | `ERR_SERVER_MISCONFIGURED` | Payment |
| `PaymentInternal(String)` | 500 | `ERR_PAYMENT_INTERNAL` | Payment |
| `PaymentRequired { satoshis, derivation_prefix }` | 402 | `ERR_PAYMENT_REQUIRED` | Payment |
| `MalformedPayment(String)` | 400 | `ERR_MALFORMED_PAYMENT` | Payment |
| `InvalidDerivationPrefix` | 400 | `ERR_INVALID_DERIVATION_PREFIX` | Payment |
| `PaymentFailed(String)` | 400 | `ERR_PAYMENT_FAILED` | Payment |
| `InvalidPayment(String)` | 400 | `ERR_INVALID_PAYMENT` | Payment |
| `KvError(String)` | 500 | `ERR_STORAGE` | Infra |
| `SdkError(String)` | 500 | `ERR_SDK` | Infra |
| `TransportError(String)` | 500 | `ERR_TRANSPORT` | Infra |
| `ConfigError(String)` | 500 | `ERR_CONFIG` | Infra |
| `SerializationError(String)` | 400 | `ERR_SERIALIZATION` | Infra |

Since 0.4.1 the three Auth variants never escape `process_auth*`: an authentication refusal is rendered by the middleware itself as a 401 `AuthResult::Response` (CORS, unsigned) carrying the variant's code (`UNAUTHORIZED` with the reference's `message` field; `ERR_INVALID_AUTH` for an identity that is not the session's, a missing or wrong signature, a session that never completed its handshake, a missing per-request nonce, headers that do not form a message, a refused handshake message; `ERR_SESSION_NOT_FOUND`; `ERR_REPLAYED_REQUEST`). An `Err` from `process_auth*` is a fault (the Infra and Config rows), the host's 500.

| Status | Code | Condition |
|---|---|---|
| 503 | `ERR_PAYMENT_UNAVAILABLE` | Claim-store fault; retryable, `Retry-After: 5`, quote and prefix kept, no fresh challenge |

Three payment-path answers are rendered directly by `middleware/payment.rs` without an `AuthCloudflareError` variant: `500 ERR_SERVER_MISCONFIGURED` for the core's `NoHeaderService` or a `PaymentFault` (the `ServerFault` decision) and `503 ERR_HEADER_SERVICE_UNAVAILABLE` for a server-side `Unverifiable` (the `HeaderServiceUnavailable` decision: fail-closed, the quote kept, retry the same payment). A `PaymentPrefixStore` fault is `PrefixStoreUnavailable { detail }`, rendered as 503 `ERR_PAYMENT_UNAVAILABLE` with `retryable: true` and `Retry-After: 5`, quote and prefix kept, no fresh challenge. Both signed and unsigned paths use the same wire body; detail is logged only. A payer-side `Unverifiable` is the `InvalidPayment` decision's `400 ERR_INVALID_PAYMENT`, the quote kept.

Automatic `From` conversions: `bsv_sdk::Error` -> `SdkError`, `worker::Error` -> `KvError`, `serde_json::Error` -> `SerializationError`, `bsv_middleware_core::AuthError` -> the same-named variant, message intact (`InvalidAuthentication`, `Config` -> `ConfigError`, `Sdk` -> `SdkError`, `Serialization` -> `SerializationError`).

Two wire-level codes are emitted directly as `ErrorResponse` bodies (no enum variant; not in the Express reference — hardening additions): `401 ERR_REPLAYED_REQUEST` (auth per-request nonce reuse; since 0.4.1 one of the `AuthRefusal` words, rendered by `refusal_response` with the rest) and `402 ERR_PAYMENT_FAILED` with fresh challenge headers (wallet returned `accepted: false`). The paying-output refusal (output 0 short or paying another key) is the reference's own `400 ERR_INVALID_PAYMENT`, emitted as a body with the quote kept: no challenge headers, the prefix not consumed (0.4.0; 0.3.8 answered 402 with a fresh challenge).

## Cloudflare Configuration

### Required KV Namespaces

Add to `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "AUTH_SESSIONS"
id = "your-kv-id-here"

[[kv_namespaces]]
binding = "PAYMENTS"
id = "your-payments-kv-id-here"
```

### Required Secrets

```bash
wrangler secret put SERVER_PRIVATE_KEY
# Enter 64-character hex secp256k1 private key
```

### Optional Environment Variables

- `ENVIRONMENT` - Runtime environment name (default: `"production"`)

## Storage Schema

### Session Keys (KvSessionStorage)

- `{prefix}:session:{session_nonce}` - Session JSON with TTL
- `{prefix}:identity:{identity_key}:{session_nonce}` - Index for identity lookups (value = session_nonce)
- `{prefix}:nonce:{scope}:{nonce}` - Consumed single-use nonce records. Auth: `scope = session_nonce`, TTL = session TTL (min 60s, KV floor). Payment via `KvPrefixStore`: `scope = payment-derivation-prefix`, no TTL, value `txid` or `released:txid` (legacy `1` is closed).

### Payment Keys (KvPaymentStorage)

- `{prefix}:payment:{txid}:{vout}` - Payment record JSON (no TTL)
- `{prefix}:unspent:{txid}:{vout}` - Unspent output index
- `{prefix}:derivation:{derivation_prefix}` - One-time derivation prefix with TTL

## Dependencies

- `bsv_middleware_core` - the rules (`../core/`): the six-word verdict, the header-service and store traits, BRC-29 derivation and verification, BRC-103/104 message build and verify, the session lane, the refund signer
- `bsv_sdk` (bsv-rs 0.7) - BSV primitives, wallet (`ProtoWallet`, `WalletInterface`), auth protocol, nonce utils; the streaming BEEF reader the core verifies payments through
- `worker` - Cloudflare Workers runtime (Request, Response, KV, Headers; `d1` only under the `d1-claims` feature)
- `serde` / `serde_json` - Serialization
- `thiserror` - Error derive macros
- `hex` - Hex encoding/decoding
- `js_sys` - JavaScript interop for `Date.now()`
- `rand` - Random number generation (used by client for request IDs)
- `getrandom` - Random nonce generation
- `console_error_panic_hook` - WASM panic handling (optional, gated on `wasm32`)

## Related

- `../Cargo.toml` - Crate dependencies and features
- `../../bsv-sdk/` - Core BSV SDK with auth protocol implementation
