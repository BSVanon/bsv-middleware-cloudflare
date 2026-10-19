# Storage Module
> Cloudflare KV-backed storage implementations for BSV authentication and payments

## Overview

This module provides persistent storage implementations using Cloudflare KV (key-value store) for the BSV authentication middleware. It handles two primary concerns: session management for BRC-103/104 mutual authentication flows, and payment tracking for BRC-29 paid requests. Both implementations use key prefixing to support multiple isolated instances within a single KV namespace.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module exports; re-exports `KvSessionStorage` and `KvPaymentStorage` |
| `kv_session.rs` | Session storage for BRC-103/104 authenticated peers with TTL expiration |
| `kv_payment.rs` | Payment record storage for BRC-29 with spent/unspent tracking |

## Key Exports

### `KvSessionStorage`

Session manager for BRC-103/104 authentication state stored in Cloudflare KV.

```rust
pub struct KvSessionStorage {
    kv: KvStore,
    prefix: String,
    session_ttl_seconds: u64,
}
```

**Constructor:**
- `new(kv: KvStore, prefix: &str, session_ttl_seconds: u64)` - Creates storage with KV namespace, key prefix, and session TTL

**Methods:**
- `get_session(session_nonce: &str)` - Retrieves a session by its nonce
- `save_session(session: &StoredSession)` - Saves a session with automatic TTL and identity index
- `remove_session(session_nonce: &str)` - Removes a session and its identity index entry
- `update_session(session: &StoredSession)` - Updates an existing session (delegates to `save_session`)
- `has_session(session_nonce: &str)` - Checks if a session exists
- `get_session_by_identity(identity_key_hex: &str)` - Gets the most recently updated session for an identity
- `get_sessions_for_identity(identity_key_hex: &str)` - Gets all sessions for an identity key

**KV Key Schema:**
- Session data: `{prefix}:session:{session_nonce}`
- Identity index: `{prefix}:identity:{identity_key}:{session_nonce}`

### `KvPaymentStorage`

Payment storage for BRC-29 paid requests with spent/unspent tracking.

```rust
pub struct KvPaymentStorage {
    kv: KvStore,
    prefix: String,
}
```

**Constructor:**
- `new(kv: KvStore, prefix: &str)` - Creates storage with KV namespace and key prefix

**Methods:**
- `get_payment(txid: &str, vout: u32)` - Retrieves a payment by transaction ID and output index
- `payment_exists(txid: &str, vout: u32)` - Checks if a payment exists (for duplicate detection)
- `store_payment(payment: &StoredPayment)` - Stores a payment and marks it in the unspent index
- `mark_spent(txid: &str, vout: u32)` - Marks a payment as spent and removes from unspent index
- `store_derivation_prefix(derivation_prefix: &str, ttl_seconds: u64)` - Stores derivation prefix for nonce validation
- `consume_derivation_prefix(derivation_prefix: &str)` - Validates and removes a derivation prefix (one-time use)
- `get_total_from_identity(identity_key: &str)` - Calculates total satoshis received from an identity

**KV Key Schema:**
- Payment data: `{prefix}:payment:{txid}:{vout}`
- Unspent index: `{prefix}:unspent:{txid}:{vout}`
- Derivation prefix: `{prefix}:derivation:{derivation_prefix}`

## Data Types

Both storage implementations use types defined in `crate::types`:

### `StoredSession`

```rust
pub struct StoredSession {
    pub session_nonce: String,           // Server's session nonce
    pub peer_identity_key: String,       // Peer's public key (hex)
    pub peer_nonce: Option<String>,      // Peer's last known nonce
    pub is_authenticated: bool,          // Mutual auth completed
    pub certificates_required: bool,     // Certs required for session
    pub certificates_validated: bool,    // Certs have been validated
    pub created_at: u64,                 // Creation timestamp (ms)
    pub last_update: u64,                // Last activity timestamp (ms)
}
```

### `StoredPayment`

```rust
pub struct StoredPayment {
    pub txid: String,                    // Transaction ID
    pub vout: u32,                       // Output index
    pub satoshis: u64,                   // Amount paid
    pub sender_identity_key: String,     // Sender's public key (hex)
    pub derivation_prefix: String,       // BIP-32 derivation prefix
    pub derivation_suffix: String,       // BIP-32 derivation suffix
    pub created_at: u64,                 // Receipt timestamp (ms)
    pub spent: bool,                     // Whether output is spent
}
```

## Usage

### Session Storage Example

```rust
use worker::kv::KvStore;
use bsv_middleware_cloudflare::storage::KvSessionStorage;
use bsv_middleware_cloudflare::types::StoredSession;

// Initialize with 1 hour TTL
let storage = KvSessionStorage::new(kv, "myapp", 3600);

// Create and save a new session
let session = StoredSession::new(
    "server_nonce_abc123".to_string(),
    "02abc123...".to_string(), // peer identity key
);
storage.save_session(&session).await?;

// Retrieve by nonce
let session = storage.get_session("server_nonce_abc123").await?;

// Find session by identity
let session = storage.get_session_by_identity("02abc123...").await?;
```

### Payment Storage Example

```rust
use worker::kv::KvStore;
use bsv_middleware_cloudflare::storage::KvPaymentStorage;
use bsv_middleware_cloudflare::types::StoredPayment;

let storage = KvPaymentStorage::new(kv, "myapp");

// Store derivation prefix for later validation (5 minute TTL)
storage.store_derivation_prefix("1/2/3", 300).await?;

// When payment arrives, validate the derivation prefix
let valid = storage.consume_derivation_prefix("1/2/3").await?;
if !valid {
    return Err(AuthCloudflareError::InvalidDerivationPrefix);
}

// Check for duplicate payment
if storage.payment_exists(&txid, vout).await? {
    return Err(AuthCloudflareError::InvalidPayment("duplicate".into()));
}

// Store the payment
storage.store_payment(&payment).await?;

// Later, mark as spent
storage.mark_spent(&txid, vout).await?;
```

## Error Handling

All async methods return `Result<T>` where errors are `AuthCloudflareError`. KV-specific errors are wrapped as `AuthCloudflareError::KvError(String)`.

Common error scenarios:
- KV read/write failures produce `KvError`
- JSON serialization failures produce `SerializationError` (via `serde_json::Error` conversion)

## Performance Considerations

- **Identity lookups**: `get_sessions_for_identity` and `get_session_by_identity` use KV `list()` which may be slow for large numbers of sessions per identity
- **Total calculations**: `get_total_from_identity` iterates all payments and should not be used in hot paths; consider maintaining counters for production use
- **Key prefixes**: Use distinct prefixes per application/environment to isolate data within shared KV namespaces
- **TTL expiration**: Sessions auto-expire via KV TTL; derivation prefixes also use TTL for automatic cleanup

## Related

- `../types.rs` - Data structures (`StoredSession`, `StoredPayment`)
- `../error.rs` - Error types (`AuthCloudflareError`, `Result`)
- Cloudflare Workers KV documentation for underlying storage semantics

## Payment prefix storage (M14, adapter 0.7.0)

Payment entry points require `PaymentPrefixStore`, separate from auth sessions.
`D1PrefixStore` is exact: a prefix binds its first txid forever, and only that
txid can re-take a released attempt. Run `PAYMENT_CLAIMS_MIGRATION` once before
deploying against existing tables. `KvPrefixStore(&KvSessionStorage)` retains
G3: read/write races and cross-edge propagation (about 60 seconds); values are
`txid` or `released:txid`, never deleted or expired. Legacy `1` is closed.
The DO session backend no longer routes payment scope to KV. `ClaimStore` and
`claim_payment_nonce` are only for idempotency keys, never payment prefixes.
