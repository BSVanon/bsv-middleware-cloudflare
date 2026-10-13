//! Pluggable session storage abstraction for BRC-103/104 authentication.
//!
//! The [`SessionStorage`] trait lets consumers back BRC-103/104 session state
//! with any store they like (Cloudflare KV, a Durable Object SQLite database,
//! an in-memory map for tests, etc.) instead of being locked into Cloudflare KV.
//!
//! The default implementation, [`KvSessionStorage`](crate::storage::KvSessionStorage),
//! is still used by the backward-compatible [`process_auth`](crate::process_auth)
//! entry point. Consumers wanting a different backend implement this trait and
//! call [`process_auth_with_storage`](crate::process_auth_with_storage).
//!
//! The method set is exactly what the middleware requires: session lookup and
//! persistence for the auth middleware
//! ([`process_auth_with_storage`](crate::process_auth_with_storage) and its
//! handshake helpers), plus single-use nonce consumption shared by the auth
//! replay protection and the payment middleware
//! ([`process_payment_with_storage`](crate::process_payment_with_storage)).

use crate::error::Result;
use crate::types::StoredSession;
use async_trait::async_trait;

/// Pluggable backing store for BRC-103/104 authentication sessions.
///
/// Implementations must be `Send + Sync` so they can be shared across the
/// async middleware. All methods return the crate's [`Result`] type.
///
/// This trait captures exactly the operations the auth middleware performs:
/// looking up a session by nonce or by peer identity key, persisting a new
/// session during the handshake, and updating an existing session after a
/// verified message.
#[async_trait(?Send)]
pub trait SessionStorage {
    /// Retrieves a session by its (server) session nonce.
    async fn get_session(&self, session_nonce: &str) -> Result<Option<StoredSession>>;

    /// Finds an existing session for a peer identity key.
    ///
    /// Returns the most recently updated session if several exist.
    async fn get_session_by_identity(
        &self,
        identity_key_hex: &str,
    ) -> Result<Option<StoredSession>>;

    /// Persists a freshly created session (used during the handshake).
    ///
    /// Implementations should apply a TTL-based expiration where supported.
    async fn save_session(&self, session: &StoredSession) -> Result<()>;

    /// Updates an existing session (e.g. touch timestamp, mark certificates
    /// validated).
    async fn update_session(&self, session: &StoredSession) -> Result<()>;

    /// Records `nonce` (within `scope`) as consumed, once.
    ///
    /// Returns `Ok(true)` if the nonce had not been recorded before (first
    /// use — proceed), `Ok(false)` if it was already recorded (replay —
    /// reject). Storage failures must be surfaced as `Err` so callers can
    /// fail closed; silently returning `Ok(true)` on a storage fault would
    /// disable replay protection.
    ///
    /// Used for two kinds of single-use values:
    /// - **BRC-104 per-request nonces** (`x-bsv-auth-nonce` on General
    ///   messages), scoped by the server session nonce, with
    ///   `ttl_seconds = Some(session TTL)`.
    /// - **BRC-29 payment derivation prefixes**, scoped by
    ///   [`PAYMENT_NONCE_SCOPE`](crate::middleware::payment::PAYMENT_NONCE_SCOPE),
    ///   with `ttl_seconds = None` (the prefix HMAC never expires, so the
    ///   consumption record must not either).
    ///
    /// # Consistency requirements
    ///
    /// Implementations should use an **atomic put-if-absent** where the
    /// backend supports it (e.g. `INSERT OR IGNORE` + row-count in a Durable
    /// Object SQLite database) — that yields exact at-most-once semantics.
    ///
    /// The reference TS middleware stack (`@bsv/auth-express-middleware`
    /// 1.2.3 / `@bsv/sdk` `Peer.processGeneralMessage`, and
    /// `@bsv/payment-express-middleware` 1.2.3 `verifyNonce`) performs **no**
    /// consumption tracking at all — this method is a deliberate hardening
    /// divergence (security audit findings #30/#44).
    ///
    /// Backends without an atomic primitive (Cloudflare KV) may implement
    /// this as read-then-write; see
    /// [`KvSessionStorage`](crate::storage::KvSessionStorage) for the precise
    /// residual replay window that leaves.
    ///
    /// `ttl_seconds`: `Some(t)` = the record may expire after `t` seconds;
    /// `None` = retain indefinitely. Implementations may retain records
    /// longer than requested (never shorter, except backend-imposed minimums
    /// such as Cloudflare KV's 60-second TTL floor, which implementations
    /// must clamp *up* to).
    async fn try_consume_nonce(
        &self,
        scope: &str,
        nonce: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<bool>;

    /// Best-effort release of a previously consumed nonce.
    ///
    /// The payment middleware calls this when `internalizeAction` fails with
    /// a transport/wallet **error** (as opposed to an explicit
    /// `accepted: false` rejection): the payment was not processed, so the
    /// honest client must be able to retry the same payment. Releasing never
    /// grants replay value — a released nonce still has to pass full
    /// verification and wallet internalization again to be of any use.
    async fn release_nonce(&self, scope: &str, nonce: &str) -> Result<()>;

    /// The hot path's two questions — "is this session live?" and "has this
    /// request nonce been seen?" — in ONE storage round trip, for a backend
    /// that can answer both from one place (the Durable Object backend).
    /// The default says "not supported" (`None`) and the
    /// middleware falls back to `get_session` then `try_consume_nonce`, in
    /// that order, so a backend that does not override this is byte-for-byte
    /// unchanged. An override consumes the request nonce BEFORE the signature
    /// is verified: harmless (an unverifiable request's nonce is nobody
    /// else's) and it never weakens the replay refusal. `Some((None, _))` =
    /// no such live session (nothing consumed).
    async fn get_session_and_consume(
        &self,
        _session_nonce: &str,
        _request_nonce: &str,
        _ttl_seconds: Option<u64>,
    ) -> Result<Option<(Option<StoredSession>, bool)>> {
        Ok(None)
    }

    /// Session lane (0.3.4, `middleware::session_lane`): store a freshly
    /// minted lane under its id. `Ok(false)` = this backend keeps no lanes
    /// (the KV default): the handshake then offers none.
    async fn lane_put(&self, _lane: &LaneRecord) -> Result<bool> {
        Ok(false)
    }

    /// Session lane: verify one laned call against the stored lane (the
    /// counter window, the MAC, the idle refresh), answering the verdict and,
    /// on success, the lane's key so the caller can seal its answer.
    /// `Ok(None)` = this backend keeps no lanes.
    async fn lane_verify(&self, _ask: &LaneVerifyAsk) -> Result<Option<LaneVerdict>> {
        Ok(None)
    }
}

pub use crate::middleware::session_lane::LaneRecord;

/// Any [`SessionStorage`] as the core's
/// [`PaymentNonceStore`](bsv_middleware_core::PaymentNonceStore): the
/// trait's `try_consume_nonce` / `release_nonce`, with a storage fault as a
/// [`StoreError`](bsv_middleware_core::StoreError). For code written against
/// the core's traits (the fleet's own payment flows) over this crate's
/// backends: `SessionNonceStore(&storage)`.
pub struct SessionNonceStore<'a, S: ?Sized>(pub &'a S);

impl<S: SessionStorage + ?Sized> bsv_middleware_core::PaymentNonceStore
    for SessionNonceStore<'_, S>
{
    async fn try_consume(
        &self,
        scope: &str,
        nonce: &str,
        ttl_seconds: Option<u64>,
    ) -> std::result::Result<bool, bsv_middleware_core::StoreError> {
        self.0
            .try_consume_nonce(scope, nonce, ttl_seconds)
            .await
            .map_err(|e| bsv_middleware_core::StoreError::new(e.to_string()))
    }

    async fn release(
        &self,
        scope: &str,
        nonce: &str,
    ) -> std::result::Result<(), bsv_middleware_core::StoreError> {
        self.0
            .release_nonce(scope, nonce)
            .await
            .map_err(|e| bsv_middleware_core::StoreError::new(e.to_string()))
    }
}

/// One laned call, as the door read it (the body already digested).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaneVerifyAsk {
    pub id: String,
    pub identity: String,
    // bounded: the counter is refused above MAX_SAFE_COUNTER at the header (parse_lane_headers)
    pub h: u64,
    pub method: String,
    pub path_and_query: String,
    pub body_sha256: String,
    pub mac: String,
}

/// The store's answer to a `lane_verify`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaneVerdict {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// In-memory [`SessionStorage`] test double, shared by the trait-contract
/// tests below and the payment middleware's executed money-path tests
/// (`middleware::payment` — audit finding #62).
///
/// `try_consume_nonce` here is genuinely atomic (single-threaded map
/// insert), i.e. the semantics a Durable Object SQLite implementation
/// provides in production. Fault injection (`fail_consume`/`fail_release`)
/// exercises the fail-closed and release-failure branches.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemorySessionStorage {
    sessions: std::cell::RefCell<std::collections::HashMap<String, StoredSession>>,
    nonces: std::cell::RefCell<std::collections::HashSet<String>>,
    fail_consume: std::cell::Cell<bool>,
    fail_release: std::cell::Cell<bool>,
}

#[cfg(test)]
impl MemorySessionStorage {
    fn nonce_key(scope: &str, nonce: &str) -> String {
        format!("{}:{}", scope, nonce)
    }

    /// Make `try_consume_nonce` fail with a storage error (fail-closed path).
    pub(crate) fn fail_consume(&self, fail: bool) {
        self.fail_consume.set(fail);
    }

    /// Make `release_nonce` fail with a storage error (best-effort path).
    pub(crate) fn fail_release(&self, fail: bool) {
        self.fail_release.set(fail);
    }

    /// Whether `nonce` is currently recorded as consumed under `scope`.
    pub(crate) fn is_consumed(&self, scope: &str, nonce: &str) -> bool {
        self.nonces
            .borrow()
            .contains(&Self::nonce_key(scope, nonce))
    }

    /// Number of consumed-nonce records (all scopes).
    pub(crate) fn consumed_count(&self) -> usize {
        self.nonces.borrow().len()
    }
}

#[cfg(test)]
#[async_trait(?Send)]
impl SessionStorage for MemorySessionStorage {
    async fn get_session(&self, session_nonce: &str) -> Result<Option<StoredSession>> {
        Ok(self.sessions.borrow().get(session_nonce).cloned())
    }

    async fn get_session_by_identity(
        &self,
        identity_key_hex: &str,
    ) -> Result<Option<StoredSession>> {
        Ok(self
            .sessions
            .borrow()
            .values()
            .filter(|s| s.peer_identity_key == identity_key_hex)
            .max_by_key(|s| s.last_update)
            .cloned())
    }

    async fn save_session(&self, session: &StoredSession) -> Result<()> {
        self.sessions
            .borrow_mut()
            .insert(session.session_nonce.clone(), session.clone());
        Ok(())
    }

    async fn update_session(&self, session: &StoredSession) -> Result<()> {
        self.save_session(session).await
    }

    async fn try_consume_nonce(
        &self,
        scope: &str,
        nonce: &str,
        _ttl_seconds: Option<u64>,
    ) -> Result<bool> {
        if self.fail_consume.get() {
            return Err(crate::error::AuthCloudflareError::KvError(
                "injected consume fault".to_string(),
            ));
        }
        // HashSet::insert returns true only when the value was absent —
        // atomic put-if-absent.
        Ok(self
            .nonces
            .borrow_mut()
            .insert(Self::nonce_key(scope, nonce)))
    }

    async fn release_nonce(&self, scope: &str, nonce: &str) -> Result<()> {
        if self.fail_release.get() {
            return Err(crate::error::AuthCloudflareError::KvError(
                "injected release fault".to_string(),
            ));
        }
        self.nonces
            .borrow_mut()
            .remove(&Self::nonce_key(scope, nonce));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend that does not override the combined hot-path
    /// call answers "not supported", and the middleware keeps its two-step
    /// order (`get_session`, then `try_consume_nonce`) for it.
    #[test]
    fn the_combined_hot_path_call_is_unsupported_by_default() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let store = MemorySessionStorage::default();
        let r = rt
            .block_on(store.get_session_and_consume("s", "r", Some(60)))
            .unwrap();
        assert!(r.is_none());
    }

    /// Compile-time check: the trait must stay object safe so middleware can
    /// take `&dyn SessionStorage`.
    fn _assert_object_safe(_storage: &dyn SessionStorage) {}

    #[tokio::test]
    async fn test_consume_nonce_first_use_is_fresh() {
        let storage = MemorySessionStorage::default();
        let fresh = storage
            .try_consume_nonce("session-a", "nonce-1", Some(3600))
            .await
            .unwrap();
        assert!(fresh, "first consumption must report fresh");
    }

    #[tokio::test]
    async fn test_consume_nonce_second_use_is_replay() {
        let storage = MemorySessionStorage::default();
        storage
            .try_consume_nonce("session-a", "nonce-1", Some(3600))
            .await
            .unwrap();
        let second = storage
            .try_consume_nonce("session-a", "nonce-1", Some(3600))
            .await
            .unwrap();
        assert!(!second, "byte-identical replay must be rejected");
    }

    #[tokio::test]
    async fn test_consume_nonce_is_scoped() {
        let storage = MemorySessionStorage::default();
        storage
            .try_consume_nonce("session-a", "nonce-1", Some(3600))
            .await
            .unwrap();
        let other_scope = storage
            .try_consume_nonce("session-b", "nonce-1", Some(3600))
            .await
            .unwrap();
        assert!(
            other_scope,
            "same nonce under a different scope is independent"
        );
    }

    #[tokio::test]
    async fn test_release_nonce_allows_reuse() {
        let storage = MemorySessionStorage::default();
        storage
            .try_consume_nonce("payment", "prefix-1", None)
            .await
            .unwrap();
        storage.release_nonce("payment", "prefix-1").await.unwrap();
        let again = storage
            .try_consume_nonce("payment", "prefix-1", None)
            .await
            .unwrap();
        assert!(again, "released nonce must be consumable again");
    }

    /// The core's nonce-store trait over a `SessionStorage`: the same
    /// consume-once rule, and a storage fault is the core's `StoreError`
    /// (never `Ok(true)`).
    #[tokio::test]
    async fn test_session_storage_is_the_cores_nonce_store() {
        use bsv_middleware_core::PaymentNonceStore;
        let storage = MemorySessionStorage::default();
        let store = SessionNonceStore(&storage);
        assert!(store
            .try_consume(bsv_middleware_core::PAYMENT_NONCE_SCOPE, "p", None)
            .await
            .unwrap());
        assert!(!store
            .try_consume(bsv_middleware_core::PAYMENT_NONCE_SCOPE, "p", None)
            .await
            .unwrap());
        assert!(storage.is_consumed(bsv_middleware_core::PAYMENT_NONCE_SCOPE, "p"));
        store
            .release(bsv_middleware_core::PAYMENT_NONCE_SCOPE, "p")
            .await
            .unwrap();
        assert!(!storage.is_consumed(bsv_middleware_core::PAYMENT_NONCE_SCOPE, "p"));
        storage.fail_consume(true);
        let err = store.try_consume("s", "n", Some(1)).await.unwrap_err();
        assert!(err.reason().contains("injected consume fault"), "{err}");
        storage.fail_release(true);
        assert!(store.release("s", "n").await.is_err());
    }

    #[tokio::test]
    async fn test_release_unknown_nonce_is_noop() {
        let storage = MemorySessionStorage::default();
        // Must not error on releasing a nonce that was never consumed.
        storage.release_nonce("payment", "unknown").await.unwrap();
    }
}
