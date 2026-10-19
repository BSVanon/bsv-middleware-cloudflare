# Middleware - BSV Authentication and Payment Processing

> Request/response processing middleware for BRC-103/104 authentication and BRC-29 payments in Cloudflare Workers

## Overview

This module provides two core middleware components for Cloudflare Workers:

1. **Authentication Middleware** (`auth.rs`) - Implements BRC-103/104 mutual authentication protocol
2. **Payment Middleware** (`payment.rs`) - Implements BRC-29 direct payment protocol for monetized endpoints

Both middleware functions are designed to be called sequentially in request handlers, with authentication running first to establish identity, followed by payment processing for paid resources.

## Public Exports (from `mod.rs`)

```rust
pub use auth::{process_auth, sign_json_response, sign_response, AuthMiddlewareOptions, AuthResult, AuthSession};
pub use payment::{process_payment_with_storage, PaymentMiddlewareOptions, PaymentResult, payment_headers};
```

## Middleware Details

### process_auth

- **Purpose:** Authenticates requests using BRC-103/104 protocol with cryptographic signatures
- **When:** First middleware in the pipeline; runs on every request
- **Input:** `Request`, `&Env`, `&AuthMiddlewareOptions`
- **Output:** `Result<AuthResult>` - either `Authenticated { context, request, session, body }` or `Response`
- **Errors:** every authentication refusal is a 401 `AuthResult::Response` with CORS, unsigned (0.4.1); an `Err(AuthCloudflareError)` is a fault (storage, config, transport, SDK)

**Authentication Flow:**

1. **Handshake detection** - Checks if request path ends with `/.well-known/auth`
2. **For handshake requests:**
   - Parses `AuthMessage` from JSON body
   - Handles `InitialRequest` → Creates session, returns `InitialResponse`
   - Handles `CertificateResponse` → Validates certificates, updates session
   - Handles `CertificateRequest` → Returns requested certificates
3. **For general requests with auth headers:**
   - Extracts `AuthMessage` from BRC-104 headers
   - Looks up session by identity key or nonce
   - Verifies message signature using `ProtoWallet` (the `Request`/`Response`-free `judge_general_message`: the session, the identity binding, the signature, the single-use nonce; a refusal is an `AuthRefusal` value the door renders 401)
   - Updates session last activity timestamp only (peer_nonce is NOT updated for General messages — it is set once during handshake to match TS SDK behavior)
   - Captures raw request body bytes before auth consumes the body stream
4. **For requests without auth headers:**
   - If `allow_unauthenticated: true` → Returns unauthenticated context (session is `None`, body is empty)
   - Otherwise → Returns 401 error response

**Configuration (`AuthMiddlewareOptions`):**

```rust
pub struct AuthMiddlewareOptions {
    pub server_private_key: String,           // 64-char hex private key
    pub allow_unauthenticated: bool,          // Allow requests without auth (default: false)
    pub certificates_to_request: Option<RequestedCertificateSet>,
    pub session_ttl_seconds: u64,             // Default: 3600 (1 hour)
    pub on_certificates_received: Option<Box<dyn Fn(String, Vec<VerifiableCertificate>) + Send + Sync>>,
}
```

**Return Type (`AuthResult`):**

```rust
pub enum AuthResult {
    Authenticated {
        context: AuthContext,           // Peer identity info
        request: Request,              // The request (body may be consumed for auth)
        session: Option<AuthSession>,  // Session info for sign_response(); None if unauthenticated
        body: Vec<u8>,                 // Raw request body bytes captured before auth consumed the body
    },
    Response(Response),  // Return directly to client (handshake, error, etc.)
}
```

The `body` field contains the original request body bytes. For General (authenticated) messages, `CloudflareTransport::extract_auth_message()` reads the body to extract auth data, so the raw bytes are captured and returned here for the application handler to use. For handshake and unauthenticated requests, `body` is empty.

**Session Info (`AuthSession`):**

```rust
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub server_private_key: String,   // Server's private key hex
    pub session_nonce: String,        // Server's session nonce
    pub peer_nonce: Option<String>,   // Peer's last known nonce
    pub peer_identity_key: String,    // Peer's identity key (hex)
    pub request_id: [u8; 32],        // Request ID from client's auth headers
}
```

Returned from `process_auth` inside `AuthResult::Authenticated` and passed to `sign_response()` or `sign_json_response()` to sign outgoing responses.

---

### sign_response

- **Purpose:** Signs an outgoing response with BRC-104 auth headers for mutual authentication
- **When:** After your handler produces a response, before returning to an authenticated client
- **Input:** `Response`, `&AuthSession`
- **Output:** `Result<Response>` - the response with BRC-104 auth headers added
- **Required:** Without signing, clients using AuthFetch will reject the response

**What it does:**

1. Builds a `General` `AuthMessage` from the response metadata (status, request ID)
2. Signs the message using the server's private key and session context
3. Adds BRC-104 headers (`x-bsv-auth-*`) and request ID header to the response
4. Wraps with CORS headers

**Limitation:** Uses an empty body in the signed payload because `worker::Response` doesn't expose body bytes. For correct body-inclusive signing, use `sign_json_response()` instead.

---

### sign_json_response (recommended)

- **Purpose:** Signs a JSON response with BRC-104 auth headers, including actual body bytes in the signed payload
- **When:** After your handler computes the response data, before constructing the `Response` — the recommended way to sign responses
- **Input:** `&T: Serialize` (response data), `u16` (status), `&[(String, String)]` (extra headers), `&AuthSession`
- **Output:** `Result<Response>` - a complete signed Response with JSON body, auth headers, extra headers, and CORS headers
- **Why:** Matches how Express hijacks `res.json()` to include actual body bytes in the signature

**What it does:**

1. Serializes the response data to JSON bytes
2. Filters `extra_headers` to signable ones (see header filtering rules below)
3. Builds `HttpResponseData` payload with actual body bytes (not empty like `sign_response`)
4. Creates and signs a `General` `AuthMessage` with the payload
5. Constructs a `Response` with JSON body, auth headers, all extra headers, and CORS headers

**Header filtering rules (matching SimplifiedFetchTransport):**

Only these headers are included in the signed payload:
- Headers starting with `x-bsv-` (but **not** `x-bsv-auth-*`)
- The `authorization` header
- Sorted alphabetically by lowercase key

All `extra_headers` are included in the HTTP response regardless of whether they are signed.

**Example:**

```rust
// Instead of:
let response = Response::from_json(&data)?;
let signed = sign_response(response, &session)?;

// Use (recommended):
let extra_headers = vec![
    ("x-bsv-payment-satoshis-paid".to_string(), "100".to_string()),
];
let signed = sign_json_response(&data, 200, &extra_headers, &session)?;
```

---

### process_payment_with_storage

- **Purpose:** Handles BRC-29 payment flow for monetized API endpoints
- **When:** After authentication; only for endpoints requiring payment
- **Input:** `&Request`, `&AuthContext`, `&PaymentMiddlewareOptions<F>`, `&impl PaymentPrefixStore`
- **Output:** `Result<PaymentResult>` indicating payment status
- **Errors:** Returns 400/402/500 responses or `AuthCloudflareError` variants

**Payment Flow:**

1. **Auth check** - Verifies auth middleware ran first; returns 500 `ERR_SERVER_MISCONFIGURED` if not
2. **Price calculation** - Calls user-provided `calculate_price(req)` function
3. **If price is 0** → Returns `PaymentResult::Free`
4. **If no `x-bsv-payment` header:**
   - Generates derivation prefix via stateless HMAC nonce (`create_nonce`)
   - Returns 402 with payment instructions (version, satoshis required, derivation prefix)
5. **If payment header present:**
   - Parses `BsvPayment` JSON from header
   - Verifies derivation prefix via stateless HMAC (`verify_nonce`) before claiming the txid
   - Decodes base64 transaction data
   - Checks output 0 and reads the subject txid, then claims through `PaymentPrefixStore`
   - M14: another txid gets 400 `ERR_INVALID_DERIVATION_PREFIX`, no fresh challenge, no internalize or refund
   - Held/served prefixes refuse their own txid too; release after an internalize error allows only that txid to retry
   - `accepted: false` keeps the binding held; all bindings persist without expiry
   - Creates a `WorkerStorageClient` (BRC-103/104 client to remote storage server)
   - Initializes connection: `make_available()` → `find_or_insert_user()`
   - Calls `internalize_action()` on the storage client to process payment
   - Returns `PaymentResult::Verified` on success, `PaymentResult::Failed` on error

`D1PrefixStore` is exact. `KvPrefixStore` retains G3: same-edge races and about
60 seconds of cross-edge propagation can admit competing transactions. DO auth
storage is separate. Run `PAYMENT_CLAIMS_MIGRATION` once on existing tables before
0.7.0; legacy rows remain closed. The stateless `process_payment` was removed.
Fleet `payment_prefix_gate` takes explicit `FaultPosture`: Closed gives retryable
503 `ERR_PAYMENT_LOCK_UNAVAILABLE`, quote kept; Open returns fault detail for the
door to log. Other txid gives 400 `ERR_PAYMENT_INVALID`, same/unknown 409
`ERR_PAYMENT_REPLAYED`. The host signs responses; bodies never include a txid.

**Configuration (`PaymentMiddlewareOptions<F>`):**

```rust
pub struct PaymentMiddlewareOptions<F> {
    pub server_private_key: String,   // Same as auth middleware; also used for BRC-103/104 auth to storage server
    pub calculate_price: F,           // Fn(&Request) -> u64 (satoshis)
    pub storage_url: String,          // Remote storage server URL (default: "https://storage.babbage.systems")
}
```

**Constructors:**

- `PaymentMiddlewareOptions::new(key, calc_price)` — Uses mainnet storage (`WorkerStorageClient::MAINNET_URL`)
- `PaymentMiddlewareOptions::with_storage_url(key, calc_price, url)` — Uses a custom storage server URL

**Return Type (`PaymentResult`):**

```rust
pub enum PaymentResult {
    Free,                         // No payment needed (price was 0)
    Required(Response),           // 402 response with payment instructions
    Verified(PaymentContext),     // Payment accepted
    Failed(Response),             // Payment verification failed or server misconfigured
}
```

**Payment Headers (BRC-29):**

| Header | Direction | Description |
|--------|-----------|-------------|
| `x-bsv-payment` | Request | JSON payment data from client |
| `x-bsv-payment-version` | Response | Protocol version ("1.0") |
| `x-bsv-payment-satoshis-required` | Response | Amount needed |
| `x-bsv-payment-derivation-prefix` | Response | Server-generated HMAC nonce |
| `x-bsv-payment-satoshis-paid` | Response | Amount paid (success) |
| `x-bsv-payment-txid` | Response | Transaction ID of accepted payment |

These constants are available via the `payment_headers` module.

**Helper Functions:**

- `add_payment_headers(response, &PaymentContext) -> Response` — Adds `x-bsv-payment-satoshis-paid` header to a success response
- `payment_failed_response(error) -> worker::Result<Response>` — Creates a 400 `ERR_PAYMENT_FAILED` response with CORS headers

## Pipeline Order

```
Request → 1. CORS Preflight Check (OPTIONS → handle_cors_preflight)
        → 2. process_auth()
             /.well-known/auth? → Handshake response
             Has auth headers?  → Verify signature, capture body bytes
             No headers?        → Allow (if configured) or 401
        → 3. process_payment_with_storage() (if endpoint paid)
             Price = 0?    → Free
             No payment?   → 402 Required
             Has payment?  → Verify transaction
        → 4. Application Handler (with AuthContext, PaymentContext, body bytes)
        → 5. sign_json_response() or sign_response() (signs for authed clients)
        → 6. Response + CORS Headers (add_cors_headers)
```

## CORS Support

All responses from middleware are wrapped with CORS headers via `add_cors_headers()`. This function appends CORS headers to the response's **existing** headers (using `response.headers()`) rather than replacing them, preserving any previously-set headers like auth signatures from `sign_json_response()`.

Headers added:
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Allow-Headers`: Content-Type, Authorization, all `x-bsv-auth-*` headers, `x-bsv-payment`
- `Access-Control-Expose-Headers`: All `x-bsv-auth-*` response headers, payment headers (including `x-bsv-payment-txid`)

`handle_cors_preflight()` returns 204 No Content with CORS headers for OPTIONS requests.

## Configuration

### Required Cloudflare KV Namespaces

| Binding Name | Used By | Purpose |
|--------------|---------|---------|
| `AUTH_SESSIONS` | `process_auth` | Stores authenticated sessions |

Payment middleware does **not** use KV — nonce verification is stateless via HMAC.

### Server Private Key

Both middleware functions require the server's private key (64-character hex string). This key is used for:
- Generating session nonces
- Signing authentication responses and outgoing responses
- Generating/verifying derivation prefixes for payments (HMAC-based)
- Authenticating to the remote storage server via BRC-103/104 (payment middleware)

Store this in a Cloudflare Worker secret and pass to both middleware options.

## Usage Example

```rust
use bsv_middleware_cloudflare::middleware::{
    process_auth, sign_json_response, sign_response, process_payment_with_storage,
    AuthMiddlewareOptions, PaymentMiddlewareOptions,
    AuthResult, PaymentResult,
};

#[worker::event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    // Handle CORS preflight
    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    let server_key = env.secret("SERVER_PRIVATE_KEY")?.to_string();

    // Configure and run auth middleware
    let auth_options = AuthMiddlewareOptions {
        server_private_key: server_key.clone(),
        allow_unauthenticated: false,
        session_ttl_seconds: 3600,
        ..Default::default()
    };

    let (auth_context, req, session, body) = match process_auth(req, &env, &auth_options).await? {
        AuthResult::Authenticated { context, request, session, body } => (context, request, session, body),
        AuthResult::Response(resp) => return Ok(resp),
    };

    // Configure and run payment middleware (for paid endpoints)
    let payment_options = PaymentMiddlewareOptions::new(
        server_key,
        |req: &Request| {
            if req.path().starts_with("/api/premium") { 1000 } else { 0 }
        },
    );

    let session_storage = bsv_middleware_cloudflare::KvSessionStorage::new(env.kv("AUTH_SESSIONS")?, "auth", 3600);
    let prefixes = bsv_middleware_cloudflare::KvPrefixStore(&session_storage);
    let payment_context = match process_payment_with_storage(&req, &auth_context, &payment_options, &prefixes).await? {
        PaymentResult::Free => None,
        PaymentResult::Required(resp) => return Ok(resp),
        PaymentResult::Verified(ctx) => Some(ctx),
        PaymentResult::Failed(resp) => return Ok(resp),
    };

    // Handle the request — use `body` bytes since the Request body was consumed by auth
    let data = handle_request(&body, auth_context, payment_context).await?;

    // Sign the response for authenticated clients (recommended: sign_json_response)
    if let Some(ref session) = session {
        let extra_headers = vec![]; // e.g., payment headers
        Ok(sign_json_response(&data, 200, &extra_headers, session)?)
    } else {
        Ok(Response::from_json(&data)?)
    }
}
```

## Error Responses

All error responses are JSON with this structure:

```json
{
    "status": "error",
    "code": "ERR_CODE",
    "description": "Human-readable message"
}
```

| Code | HTTP Status | Middleware | Condition |
|------|-------------|-----------|-----------|
| `UNAUTHORIZED` | 401 | auth | Request lacks auth headers when required (body field `message`, as the reference) |
| `ERR_SESSION_NOT_FOUND` | 401 | auth | No session for the nonce or identity named |
| `ERR_INVALID_AUTH` | 401 | auth | The header's identity is not the session's; the signature is missing or wrong; the session never completed its handshake; no per-request nonce; headers that do not form a message; a refused handshake message (0.4.1: a response, never an `Err`) |
| `ERR_REPLAYED_REQUEST` | 401 | auth | The per-request nonce was already used (hardening, not in the reference) |
| `ERR_SERVER_MISCONFIGURED` | 500 | payment | Payment middleware called without prior auth |
| `ERR_PAYMENT_REQUIRED` | 402 | payment | Payment needed for this resource |
| `ERR_MALFORMED_PAYMENT` | 400 | payment | Cannot parse payment JSON |
| `ERR_INVALID_DERIVATION_PREFIX` | 400 | payment | HMAC nonce verification failed |
| `ERR_PAYMENT_FAILED` | 400 | payment | Transaction internalization failed |

Since 0.4.1 no authentication refusal is raised as an `Err`: `process_auth*` renders each as the 401 above (`AuthRefusal` → `refusal_response`, the one place; `settle` catches the 401-class errors raised below the door, the transport's and the handshake path's). An `Err` from `process_auth*` is a fault the host renders 500.

## Key Types

### AuthContext

Passed to request handlers after successful authentication:

```rust
pub struct AuthContext {
    pub identity_key: String,    // Peer's 66-char compressed public key hex ("unknown" if unauthenticated)
    pub is_authenticated: bool,  // true for authenticated, false for unauthenticated
}
```

### PaymentContext

Passed to request handlers after successful payment:

```rust
pub struct PaymentContext {
    pub satoshis_paid: u64,      // Amount paid
    pub accepted: bool,          // Whether wallet accepted the payment
    pub tx: Option<String>,      // Base64-encoded transaction data
}
```

## Internal Functions (auth.rs)

| Function | Visibility | Purpose |
|----------|-----------|---------|
| `handle_handshake_request` | private | Routes handshake messages by type |
| `handle_initial_request` | private | Creates session, returns `InitialResponse` with signature |
| `handle_certificate_response` | private | Validates peer certificates, calls callback |
| `handle_certificate_request` | private | Returns server's certificates to peer |
| `sign_message` | private | Signs an `AuthMessage` using ProtoWallet (AUTH_PROTOCOL_ID, Counterparty security) |
| `verify_message_signature` | private | Verifies an `AuthMessage` signature |
| `filter_signable_headers` | private | Filters headers to signable subset for `sign_json_response` payload (x-bsv-* excluding x-bsv-auth-*, authorization) |
| `generate_random_nonce` | private | 32-byte random nonce, base64-encoded (for General messages) |
| `add_cors_headers` | **pub** | Appends CORS headers to existing response headers (preserves auth headers; also used by payment middleware) |
| `handle_cors_preflight` | **pub** | Returns 204 with CORS headers for OPTIONS requests |

## Internal Functions (payment.rs)

| Function | Visibility | Purpose |
|----------|-----------|---------|
| `add_payment_headers` | **pub** | Adds `x-bsv-payment-satoshis-paid` header to a success response |
| `payment_failed_response` | **pub** | Creates a 400 `ERR_PAYMENT_FAILED` response with CORS headers |
| `PaymentMiddlewareOptions::new` | **pub** | Constructor with mainnet storage URL |
| `PaymentMiddlewareOptions::with_storage_url` | **pub** | Constructor with custom storage URL |

**Payment Internalization Architecture:**

Payment processing uses `WorkerStorageClient` (from `../client/`) to talk to a remote storage server (e.g., `storage.babbage.systems`) over BRC-103/104. This mirrors how the TypeScript Express middleware uses a `WalletInterface` (typically a `WalletClient` connected to the storage server). The sequence per payment request is:

1. `WorkerStorageClient::new(wallet, storage_url)` — creates client with BRC-103/104 auth capability
2. `make_available()` — establishes BRC-103/104 session with storage server
3. `find_or_insert_user(identity_key)` — registers/looks up user, gets `userId`
4. `internalize_action(auth, args)` — processes payment transaction with `paymentRemittance` output

**Shared Constant:** Both modules use `ORIGINATOR = "bsv-middleware-cloudflare"` for HMAC nonce operations (`create_nonce`/`verify_nonce`) and SDK utility calls.

## Test Coverage

Both modules have comprehensive `#[cfg(test)]` suites:

- **auth.rs** (~500 lines): Message signing/verification roundtrips, tamper detection, wrong-key rejection, unsigned message rejection, nonce generation (base64 format, uniqueness), `AuthContext` construction, `AuthMiddlewareOptions` defaults, `AuthSession` construction, `StoredSession` camelCase serialization roundtrips, `filter_signable_headers` rules (x-bsv-* inclusion, auth header exclusion, authorization inclusion, key lowercasing, alphabetical sorting, standard header exclusion), `sign_json_response` payload byte layout verification; the 0.4.1 refusal suite over `judge_general_message` with the in-memory store (identity not the session's, bad or missing signature, session not authenticated, unknown session, missing nonce, replay: each a 401 refusal with its code, nothing consumed; a storage fault still an `Err`), the refusal table, and the structural pin that every door settles and the one renderer sets 401 + CORS
- **payment.rs** (~230 lines): HMAC nonce create/verify cycle (including different-key failure, tampered nonce failure, uniqueness), BRC-29 header constants, `BsvPayment` camelCase deserialization (including missing field and invalid JSON failure), `ErrorResponse` Express format matching, `PaymentContext` construction, `PaymentMiddlewareOptions` constructors (mainnet and custom storage URL)

## Related

- `../client/` - `WorkerStorageClient` for BRC-103/104 RPC to remote storage servers (used by payment middleware)
- `../transport/` - BRC-104 header extraction and serialization (`cloudflare.rs`)
- `../storage/` - KV storage for sessions (`kv_session.rs`)
- `../types.rs` - `AuthContext`, `PaymentContext`, `StoredSession`, `BsvPayment`, `ErrorResponse`
- `../error.rs` - `AuthCloudflareError` enum with all error types

## Protocol References

- **BRC-103/104**: Mutual authentication protocol using identity keys and signatures
- **BRC-29**: Direct payment protocol for HTTP APIs
- **BRC-104**: HTTP transport encoding for BRC-103 messages
