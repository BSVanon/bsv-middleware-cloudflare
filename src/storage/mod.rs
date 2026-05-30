//! Storage implementations for BRC-103/104 authentication sessions.
//!
//! - `kv_session` / `KvSessionStorage` — backward-compatible KV-backed impl.
//! - `d1_session` / `D1SessionStorage` — D1-backed impl, ~250× more free-tier
//!   write headroom; recommended when the consumer already binds a D1 namespace.
//! - `kv_payment` / `KvPaymentStorage` — KV-backed payment storage.
//! - `session_storage` / `SessionStorage` — the pluggable trait both impls satisfy.

pub mod d1_session;
pub mod kv_payment;
pub mod kv_session;
pub mod session_storage;

pub use d1_session::D1SessionStorage;
pub use kv_payment::KvPaymentStorage;
pub use kv_session::KvSessionStorage;
pub use session_storage::SessionStorage;
