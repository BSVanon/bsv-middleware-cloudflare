//! KV-backed session storage for BRC-103/104 authentication.

use crate::error::{AuthCloudflareError, Result};
use crate::storage::session_storage::SessionStorage;
use crate::types::StoredSession;
use async_trait::async_trait;
use worker::kv::KvStore;

/// Attempts (1 initial + retries) for a KV op on the hot auth path before giving
/// up. Bounded so a genuinely-down KV fails fast (≤ ~150 ms of added backoff)
/// rather than hanging the request.
const KV_ATTEMPTS: u32 = 3;

/// Classify a KV failure as a *transient* infra blip that is safe to retry.
///
/// The auth hot path (`get_session`, `try_consume_nonce`) does a KV READ and,
/// for the replay guard, a KV WRITE on **every** authenticated request. Under a
/// request burst these intermittently fail with a transient fault — a generic
/// "network connection lost" / "storage … reset" / "internal error", or a
/// namespace/account throttle (429) — that succeeds on an immediate retry. This
/// is the KV analogue of the D1 cold-start blip the consuming relay already
/// retries around its `/listMessages` reads; without it a single transient KV
/// fault surfaces as a fatal 500 on an idempotent poll (incident
/// `INCIDENT-listmessages-500-2026-07-23`).
///
/// Deliberately conservative: it matches only infra/throttle markers, never a
/// logical outcome. A "consumed" nonce is `Ok(false)` (never an `Err`) and a
/// missing session is `Ok(None)`, so this classifier can never turn a real
/// replay/absence into a retry.
fn is_transient_kv_error(e: &AuthCloudflareError) -> bool {
    let s = e.to_string().to_ascii_lowercase();
    const TRANSIENT_MARKERS: [&str; 10] = [
        "network connection lost",
        "storage",
        "reset",
        "internal error",
        "connection",
        "timed out",
        "429",
        "too many requests",
        "rate limit",
        "please try again",
    ];
    TRANSIENT_MARKERS.iter().any(|m| s.contains(m))
}

/// Pure retry policy: given the zero-based `attempt` that just failed and its
/// error, return `Some(backoff)` to retry, or `None` to give up and propagate.
/// Extracted as a pure fn so the bounded-and-transient-only policy is
/// unit-testable without a live KV or JS runtime.
fn kv_retry_backoff(attempt: u32, err: &AuthCloudflareError) -> Option<std::time::Duration> {
    if attempt + 1 >= KV_ATTEMPTS {
        return None;
    }
    if !is_transient_kv_error(err) {
        return None;
    }
    // 50 ms, 100 ms — a transient KV blip clears well within this, and total
    // added latency on a genuine outage stays bounded (< 150 ms) before failing.
    Some(std::time::Duration::from_millis(50u64 << attempt))
}

/// Back off between retries. On the Worker (wasm) this is a real `setTimeout`-
/// backed `worker::Delay`; on the host test target it is a no-op (Delay needs a
/// JS event loop), which lets the retry runner be driven under `#[tokio::test]`.
#[cfg(target_arch = "wasm32")]
async fn kv_backoff_sleep(d: std::time::Duration) {
    worker::Delay::from(d).await;
}
#[cfg(not(target_arch = "wasm32"))]
async fn kv_backoff_sleep(_d: std::time::Duration) {}

/// Run an idempotent KV op `op` with a bounded, transient-only retry
/// (`kv_retry_backoff`). Returns on the first success; retries a transient blip
/// up to `KV_ATTEMPTS`; on a non-transient error (or once the bound is hit)
/// propagates the original error unchanged.
async fn with_kv_read_retry<T, F, Fut>(mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut attempt = 0u32;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => match kv_retry_backoff(attempt, &e) {
                Some(backoff) => {
                    kv_backoff_sleep(backoff).await;
                    attempt += 1;
                }
                None => return Err(e),
            },
        }
    }
}

/// Session manager backed by Cloudflare KV.
///
/// This stores session state for BRC-103/104 authenticated peers in Cloudflare KV,
/// with automatic TTL expiration.
pub struct KvSessionStorage {
    kv: KvStore,
    prefix: String,
    session_ttl_seconds: u64,
}

impl KvSessionStorage {
    /// Creates a new KV session storage.
    ///
    /// # Arguments
    ///
    /// * `kv` - The Cloudflare KV namespace
    /// * `prefix` - Prefix for all keys (to allow multiple instances)
    /// * `session_ttl_seconds` - TTL for sessions in seconds
    pub fn new(kv: KvStore, prefix: &str, session_ttl_seconds: u64) -> Self {
        Self {
            kv,
            prefix: prefix.to_string(),
            session_ttl_seconds,
        }
    }

    /// Constructs the KV key for a session by its nonce.
    fn session_key(&self, session_nonce: &str) -> String {
        format!("{}:session:{}", self.prefix, session_nonce)
    }

    /// Constructs the KV key for the identity -> session index.
    fn identity_key(&self, identity_key: &str, session_nonce: &str) -> String {
        format!(
            "{}:identity:{}:{}",
            self.prefix, identity_key, session_nonce
        )
    }

    /// Constructs the KV key for a consumed single-use nonce.
    fn nonce_key(&self, scope: &str, nonce: &str) -> String {
        format!("{}:nonce:{}:{}", self.prefix, scope, nonce)
    }

    /// Gets a session by its nonce.
    ///
    /// Bounded transient retry (`with_kv_read_retry`): a session lookup runs on
    /// EVERY authenticated request, so a transient KV blip under a request burst
    /// would otherwise surface as a fatal 500 on an idempotent read. Retrying an
    /// idempotent GET only ever turns a blip into the correct answer — a missing
    /// session stays `Ok(None)`, never an `Err`.
    pub async fn get_session(&self, session_nonce: &str) -> Result<Option<StoredSession>> {
        let key = self.session_key(session_nonce);
        with_kv_read_retry(|| async {
            self.kv
                .get(&key)
                .json::<StoredSession>()
                .await
                .map_err(|e| AuthCloudflareError::KvError(e.to_string()))
        })
        .await
    }

    /// Saves a session to KV.
    ///
    /// Also creates an index entry by identity key for lookups.
    pub async fn save_session(&self, session: &StoredSession) -> Result<()> {
        let session_key = self.session_key(&session.session_nonce);
        let json = serde_json::to_string(session)?;

        // Store by session nonce
        self.kv
            .put(&session_key, &json)
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?
            .expiration_ttl(self.session_ttl_seconds)
            .execute()
            .await
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?;

        // Also index by identity key for lookups
        let identity_key = self.identity_key(&session.peer_identity_key, &session.session_nonce);
        self.kv
            .put(&identity_key, &session.session_nonce)
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?
            .expiration_ttl(self.session_ttl_seconds)
            .execute()
            .await
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?;

        Ok(())
    }

    /// Removes a session from KV.
    pub async fn remove_session(&self, session_nonce: &str) -> Result<()> {
        // Get session first to find identity key
        if let Some(session) = self.get_session(session_nonce).await? {
            let identity_key = self.identity_key(&session.peer_identity_key, session_nonce);
            let _ = self.kv.delete(&identity_key).await;
        }

        let session_key = self.session_key(session_nonce);
        self.kv
            .delete(&session_key)
            .await
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?;

        Ok(())
    }

    /// Gets all sessions for a given identity key.
    ///
    /// Note: This uses KV list which may be slow for large numbers of sessions.
    pub async fn get_sessions_for_identity(
        &self,
        identity_key_hex: &str,
    ) -> Result<Vec<StoredSession>> {
        // List all session nonces for this identity. Bounded transient retry:
        // this is the identity-index read on the auth hot path (used when a
        // General message omits `your_nonce`); an idempotent LIST that blips
        // under burst must self-heal in-request, not 500.
        let prefix = format!("{}:identity:{}:", self.prefix, identity_key_hex);
        let list = with_kv_read_retry(|| async {
            self.kv
                .list()
                .prefix(prefix.clone())
                .execute()
                .await
                .map_err(|e| AuthCloudflareError::KvError(e.to_string()))
        })
        .await?;

        let mut sessions = Vec::new();
        for key in list.keys {
            if let Ok(Some(nonce)) = self.kv.get(&key.name).text().await {
                if let Ok(Some(session)) = self.get_session(&nonce).await {
                    sessions.push(session);
                }
            }
        }

        Ok(sessions)
    }

    /// Updates an existing session.
    pub async fn update_session(&self, session: &StoredSession) -> Result<()> {
        self.save_session(session).await
    }

    /// Checks if a session exists.
    pub async fn has_session(&self, session_nonce: &str) -> Result<bool> {
        Ok(self.get_session(session_nonce).await?.is_some())
    }

    /// Gets a session by identity key (returns the most recent one if multiple exist).
    pub async fn get_session_by_identity(
        &self,
        identity_key_hex: &str,
    ) -> Result<Option<StoredSession>> {
        let sessions = self.get_sessions_for_identity(identity_key_hex).await?;
        // Return the most recently updated session
        Ok(sessions.into_iter().max_by_key(|s| s.last_update))
    }

    /// Records a single-use nonce as consumed (see
    /// [`SessionStorage::try_consume_nonce`] for the contract).
    ///
    /// # Residual replay window (Cloudflare KV)
    ///
    /// Cloudflare KV has **no atomic put-if-absent / compare-and-swap**, and
    /// writes propagate to other edge locations eventually (up to ~60
    /// seconds). This read-then-write implementation therefore gives:
    ///
    /// - **Deterministic rejection** of a replay that reaches the *same*
    ///   Cloudflare location after the original write completed, and of any
    ///   replay anywhere after KV propagation (≤ ~60 s).
    /// - **Residual window**: a replay may be accepted at most once per
    ///   *other* edge location within the KV propagation window (~60 s of
    ///   the original request), and concurrent in-flight duplicates at the
    ///   same location can race the read-then-write (sub-second).
    ///
    /// This is the strongest guarantee KV can express. For exact
    /// at-most-once semantics, back the middleware with a strongly
    /// consistent [`SessionStorage`] (e.g. Durable Object SQLite with
    /// `INSERT OR IGNORE`) via
    /// [`process_auth_with_storage`](crate::process_auth_with_storage). Payments
    /// require a separate `PaymentPrefixStore`.
    pub async fn try_consume_nonce(
        &self,
        scope: &str,
        nonce: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<bool> {
        let key = self.nonce_key(scope, nonce);

        // Read first: if the nonce is already recorded, this is a replay.
        //
        // Bounded transient retry on BOTH the read and the write below: this
        // runs on every authenticated request and is the KV op most exposed to
        // a burst blip. Both halves are idempotent under retry — the GET is a
        // pure read, and the PUT writes the same `"1"` sentinel every time — so
        // a transient fault self-heals in-request instead of failing closed with
        // a fatal 500. A genuine replay is still caught: it is `Ok(Some)` on the
        // FIRST read (never an `Err`), so it never enters the retry branch, and
        // a non-transient error still fails closed (propagated unchanged).
        let existing = with_kv_read_retry(|| async {
            self.kv
                .get(&key)
                .text()
                .await
                .map_err(|e| AuthCloudflareError::KvError(e.to_string()))
        })
        .await?;
        if existing.is_some() {
            return Ok(false);
        }

        // Record consumption. Cloudflare KV enforces a 60-second minimum
        // expiration TTL — clamp up, never down (retaining a nonce longer
        // than requested is safe; shorter is not).
        with_kv_read_retry(|| async {
            let put = self
                .kv
                .put(&key, "1")
                .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?;
            let put = match ttl_seconds {
                Some(ttl) => put.expiration_ttl(ttl.max(60)),
                None => put,
            };
            put.execute()
                .await
                .map_err(|e| AuthCloudflareError::KvError(e.to_string()))
        })
        .await?;

        Ok(true)
    }

    /// Releases a consumed nonce (see [`SessionStorage::release_nonce`]).
    pub async fn release_nonce(&self, scope: &str, nonce: &str) -> Result<()> {
        let key = self.nonce_key(scope, nonce);
        self.kv
            .delete(&key)
            .await
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))
    }
}

/// `SessionStorage` impl delegates to the inherent KV methods, so existing
/// consumers that call the inherent methods directly keep working unchanged
/// while new consumers can program against the trait.
#[async_trait(?Send)]
impl SessionStorage for KvSessionStorage {
    async fn get_session(&self, session_nonce: &str) -> Result<Option<StoredSession>> {
        KvSessionStorage::get_session(self, session_nonce).await
    }

    async fn get_session_by_identity(
        &self,
        identity_key_hex: &str,
    ) -> Result<Option<StoredSession>> {
        KvSessionStorage::get_session_by_identity(self, identity_key_hex).await
    }

    async fn save_session(&self, session: &StoredSession) -> Result<()> {
        KvSessionStorage::save_session(self, session).await
    }

    async fn update_session(&self, session: &StoredSession) -> Result<()> {
        KvSessionStorage::update_session(self, session).await
    }

    async fn try_consume_nonce(
        &self,
        scope: &str,
        nonce: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<bool> {
        KvSessionStorage::try_consume_nonce(self, scope, nonce, ttl_seconds).await
    }

    async fn release_nonce(&self, scope: &str, nonce: &str) -> Result<()> {
        KvSessionStorage::release_nonce(self, scope, nonce).await
    }
}

#[cfg(test)]
mod kv_retry_tests {
    use super::*;
    use std::cell::Cell;

    fn transient() -> AuthCloudflareError {
        AuthCloudflareError::KvError("KV GET failed: Network connection lost.".into())
    }
    fn throttle() -> AuthCloudflareError {
        AuthCloudflareError::KvError("429 Too Many Requests".into())
    }
    // A non-transient error: a config/logic fault that must fail closed.
    fn permanent() -> AuthCloudflareError {
        AuthCloudflareError::ConfigError("bad key".into())
    }

    #[test]
    fn classifier_matches_transient_and_throttle_only() {
        assert!(is_transient_kv_error(&transient()));
        assert!(is_transient_kv_error(&throttle()));
        assert!(is_transient_kv_error(&AuthCloudflareError::KvError(
            "storage caught an exception; object was reset".into()
        )));
        assert!(is_transient_kv_error(&AuthCloudflareError::KvError(
            "internal error, please try again".into()
        )));
        // A logical config/auth fault is never retried.
        assert!(!is_transient_kv_error(&permanent()));
    }

    #[test]
    fn backoff_is_bounded_and_transient_only() {
        assert_eq!(
            kv_retry_backoff(0, &transient()),
            Some(std::time::Duration::from_millis(50))
        );
        assert_eq!(
            kv_retry_backoff(1, &throttle()),
            Some(std::time::Duration::from_millis(100))
        );
        // Bound reached → give up (no unbounded loop).
        assert_eq!(kv_retry_backoff(KV_ATTEMPTS - 1, &transient()), None);
        // Non-transient → never retried, even on the first attempt (fail closed).
        assert_eq!(kv_retry_backoff(0, &permanent()), None);
    }

    // Unit-level analogue of "a burst KV blip self-heals to success in-request".
    #[tokio::test]
    async fn read_recovers_after_one_transient_failure() {
        let calls = Cell::new(0u32);
        let out: Result<i64> = with_kv_read_retry(|| {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n == 1 {
                    Err(transient())
                } else {
                    Ok(7_i64)
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), 7);
        assert_eq!(calls.get(), 2, "failed once, succeeded on the retry");
    }

    #[tokio::test]
    async fn read_gives_up_after_bound_on_persistent_transient() {
        let calls = Cell::new(0u32);
        let out: Result<i64> = with_kv_read_retry(|| {
            calls.set(calls.get() + 1);
            async move { Err::<i64, _>(transient()) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls.get(), KV_ATTEMPTS, "bounded, no unbounded loop");
    }

    #[tokio::test]
    async fn read_does_not_retry_non_transient_error() {
        let calls = Cell::new(0u32);
        let out: Result<i64> = with_kv_read_retry(|| {
            calls.set(calls.get() + 1);
            async move { Err::<i64, _>(permanent()) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(
            calls.get(),
            1,
            "fail closed immediately on a non-transient error"
        );
    }
}

/// A permanent payment-prefix binding over the session store's KV namespace.
///
/// G3 residual window: KV has no compare-and-swap. Concurrent requests at one
/// edge, or requests at different edges before propagation (about 60 seconds),
/// can both win and overwrite bindings. Use `D1PrefixStore` (feature `d1-claims`)
/// for exact M14 enforcement. After a release, edge-cached reads can still
/// refuse the same txid as a replay for about 60 seconds. Values are `txid` or
/// `released:txid`, never deleted or expired; the legacy `1` sentinel refuses reuse as `PrefixClaim::Unknown`.
pub struct KvPrefixStore<'a>(pub &'a KvSessionStorage);

use bsv_middleware_core::{PaymentPrefixStore, PrefixClaim, StoreError};

fn judge_prefix_value(value: Option<&str>, txid: &str) -> PrefixClaim {
    match value {
        None => PrefixClaim::Won,
        Some("1") => PrefixClaim::Unknown,
        Some(value) => match value.strip_prefix("released:") {
            Some(bound) if bound == txid => PrefixClaim::Won,
            Some(_) => PrefixClaim::OtherTransaction,
            None if value == txid => PrefixClaim::SameTransaction,
            None => PrefixClaim::OtherTransaction,
        },
    }
}

impl PaymentPrefixStore for KvPrefixStore<'_> {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        _agent: &str,
    ) -> std::result::Result<PrefixClaim, StoreError> {
        #[allow(deprecated)]
        let key = self
            .0
            .nonce_key(bsv_middleware_core::PAYMENT_NONCE_SCOPE, prefix);
        let value = with_kv_read_retry(|| async {
            self.0
                .kv
                .get(&key)
                .text()
                .await
                .map_err(|e| AuthCloudflareError::KvError(e.to_string()))
        })
        .await
        .map_err(|e| StoreError::new(e.to_string()))?;
        let claim = judge_prefix_value(value.as_deref(), txid);
        if claim == PrefixClaim::Won {
            with_kv_read_retry(|| async {
                self.0
                    .kv
                    .put(&key, txid)
                    .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?
                    .execute()
                    .await
                    .map_err(|e| AuthCloudflareError::KvError(e.to_string()))
            })
            .await
            .map_err(|e| StoreError::new(e.to_string()))?;
        }
        Ok(claim)
    }

    async fn release_prefix(
        &self,
        prefix: &str,
        txid: &str,
    ) -> std::result::Result<(), StoreError> {
        #[allow(deprecated)]
        let key = self
            .0
            .nonce_key(bsv_middleware_core::PAYMENT_NONCE_SCOPE, prefix);
        let value = with_kv_read_retry(|| async {
            self.0
                .kv
                .get(&key)
                .text()
                .await
                .map_err(|e| AuthCloudflareError::KvError(e.to_string()))
        })
        .await
        .map_err(|e| StoreError::new(e.to_string()))?;
        if value.as_deref() == Some(txid) {
            with_kv_read_retry(|| async {
                self.0
                    .kv
                    .put(&key, format!("released:{txid}"))
                    .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?
                    .execute()
                    .await
                    .map_err(|e| AuthCloudflareError::KvError(e.to_string()))
            })
            .await
            .map_err(|e| StoreError::new(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;

    #[test]
    fn the_kv_prefix_encoding() {
        assert_eq!(judge_prefix_value(None, "a"), PrefixClaim::Won);
        assert_eq!(judge_prefix_value(Some("1"), "a"), PrefixClaim::Unknown);
        assert_eq!(
            judge_prefix_value(Some("a"), "a"),
            PrefixClaim::SameTransaction
        );
        assert_eq!(
            judge_prefix_value(Some("a"), "b"),
            PrefixClaim::OtherTransaction
        );
        assert_eq!(
            judge_prefix_value(Some("released:a"), "a"),
            PrefixClaim::Won
        );
        assert_eq!(
            judge_prefix_value(Some("released:a"), "b"),
            PrefixClaim::OtherTransaction
        );
    }
}
