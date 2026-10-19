//! The single-use stores as traits: a host implements them over its own
//! backend (a KV namespace, a Durable Object, a SQL table, a map in a test).
//!
//! Request nonces, idempotency keys and payment prefixes have separate contracts.
//! [`PaymentNonceStore`] holds BRC-104 request nonces; [`ClaimStore`] holds
//! idempotency keys (never derivation prefixes). [`PaymentPrefixStore`] binds
//! a derivation prefix permanently to its first transaction (M14, BRC-105).
//! All fail closed: a storage fault is `Err`, never a successful claim.

use std::fmt;
use std::future::Future;

/// Legacy KV namespace for payment derivation prefixes.
#[deprecated(since = "0.4.0", note = "use PaymentPrefixStore for payment prefixes")]
pub const PAYMENT_NONCE_SCOPE: &str = "payment-derivation-prefix";

/// A storage fault. The store could not say whether the value was fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(String);

impl StoreError {
    /// A storage fault with its reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    /// The reason.
    pub fn reason(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

/// A store of BRC-104 request nonces, scoped by session.
/// Never use this trait for payment derivation prefixes.
pub trait PaymentNonceStore {
    /// Records `nonce` (within `scope`) as consumed, once.
    ///
    /// `Ok(true)`: first use, proceed. `Ok(false)`: already recorded, a
    /// replay, reject. `Err`: the store could not answer; the caller fails
    /// closed. `ttl_seconds = None` retains the record indefinitely.
    fn try_consume(
        &self,
        scope: &str,
        nonce: &str,
        ttl_seconds: Option<u64>,
    ) -> impl Future<Output = Result<bool, StoreError>>;

    /// Best-effort release of a consumed value, so an honest client can
    /// retry after a step that failed before taking effect. Releasing never
    /// grants replay value: the value still has to pass every check again.
    fn release(&self, scope: &str, nonce: &str) -> impl Future<Output = Result<(), StoreError>>;
}

/// An atomic idempotency claim keyed by one string, such as a refund-once key.
/// Never use this trait for payment derivation prefixes.
pub trait ClaimStore {
    /// Claim `key` for `agent` (recorded for diagnostics only).
    ///
    /// `Ok(true)`: this call won the claim. `Ok(false)`: already claimed, a
    /// concurrent or sequential duplicate. `Err`: storage fault.
    fn claim(&self, key: &str, agent: &str) -> impl Future<Output = Result<bool, StoreError>>;

    /// Release a claim (best-effort), so the same key can be claimed again.
    fn release(&self, key: &str) -> impl Future<Output = Result<(), StoreError>>;
}

/// The result of claiming a permanently transaction-bound payment prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixClaim {
    /// Fresh binding, or the bound transaction re-taking its released attempt.
    Won,
    /// The bound transaction already holds or has served this prefix.
    SameTransaction,
    /// Another transaction bound this prefix first, even if released.
    OtherTransaction,
    /// A legacy consumed record with no transaction binding. Refuse reuse.
    Unknown,
}

/// A permanent binding from a BRC-29 derivation prefix to its first subject txid.
///
/// Claim atomically before any wallet call. Only the bound txid can re-take a
/// released record. Held and served records refuse even that txid. Records
/// never expire. Storage faults are `Err`; callers must fail closed.
pub trait PaymentPrefixStore {
    /// Claim `prefix` for `txid`; `agent` is diagnostic metadata only.
    fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> impl Future<Output = Result<PrefixClaim, StoreError>>;

    /// Release only this txid's attempt after an internalize error. Retain
    /// the binding forever; a different txid must never become eligible.
    fn release_prefix(
        &self,
        prefix: &str,
        txid: &str,
    ) -> impl Future<Output = Result<(), StoreError>>;
}

/// An in-memory [`PaymentPrefixStore`], [`PaymentNonceStore`] and [`ClaimStore`].
/// Prefixes use a map of `(txid, released)`; other keys use a `HashSet`
/// insert, which is a genuine put-if-absent on one thread. For tests and
/// single-process hosts; a fault can be injected to exercise fail-closed
/// paths.
#[derive(Default)]
pub struct MemoryStore {
    seen: std::cell::RefCell<std::collections::HashSet<String>>,
    prefixes: std::cell::RefCell<std::collections::HashMap<String, (String, bool)>>,
    fail: std::cell::Cell<bool>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every call fail with a storage fault (or stop doing so).
    pub fn fail(&self, fail: bool) {
        self.fail.set(fail);
    }

    /// Whether `nonce` under `scope` is recorded as consumed.
    pub fn is_consumed(&self, scope: &str, nonce: &str) -> bool {
        self.seen.borrow().contains(&format!("{scope}:{nonce}"))
    }

    /// The number of recorded values, all scopes and claims.
    pub fn len(&self) -> usize {
        self.seen.borrow().len() + self.prefixes.borrow().len()
    }

    /// Whether nothing is recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn put_if_absent(&self, key: String) -> Result<bool, StoreError> {
        if self.fail.get() {
            return Err(StoreError::new("injected store fault"));
        }
        Ok(self.seen.borrow_mut().insert(key))
    }

    fn remove(&self, key: &str) -> Result<(), StoreError> {
        if self.fail.get() {
            return Err(StoreError::new("injected store fault"));
        }
        self.seen.borrow_mut().remove(key);
        Ok(())
    }
}

impl PaymentNonceStore for MemoryStore {
    fn try_consume(
        &self,
        scope: &str,
        nonce: &str,
        _ttl_seconds: Option<u64>,
    ) -> impl Future<Output = Result<bool, StoreError>> {
        std::future::ready(self.put_if_absent(format!("{scope}:{nonce}")))
    }

    fn release(&self, scope: &str, nonce: &str) -> impl Future<Output = Result<(), StoreError>> {
        std::future::ready(self.remove(&format!("{scope}:{nonce}")))
    }
}

impl ClaimStore for MemoryStore {
    fn claim(&self, key: &str, _agent: &str) -> impl Future<Output = Result<bool, StoreError>> {
        std::future::ready(self.put_if_absent(format!("claim:{key}")))
    }

    fn release(&self, key: &str) -> impl Future<Output = Result<(), StoreError>> {
        std::future::ready(self.remove(&format!("claim:{key}")))
    }
}

impl PaymentPrefixStore for MemoryStore {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        _agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        if self.fail.get() {
            return Err(StoreError::new("injected store fault"));
        }
        let mut prefixes = self.prefixes.borrow_mut();
        match prefixes.get_mut(prefix) {
            None => {
                prefixes.insert(prefix.to_string(), (txid.to_string(), false));
                Ok(PrefixClaim::Won)
            }
            Some((bound, _)) if bound != txid => Ok(PrefixClaim::OtherTransaction),
            Some((_, released)) if *released => {
                *released = false;
                Ok(PrefixClaim::Won)
            }
            Some(_) => Ok(PrefixClaim::SameTransaction),
        }
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        if self.fail.get() {
            return Err(StoreError::new("injected store fault"));
        }
        if let Some((bound, released)) = self.prefixes.borrow_mut().get_mut(prefix) {
            if bound == txid {
                *released = true;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_nonce_is_consumed_once_per_scope_and_released_on_request() {
        let store = MemoryStore::new();
        assert!(store.try_consume("s", "n", Some(60)).await.unwrap());
        assert!(!store.try_consume("s", "n", Some(60)).await.unwrap());
        assert!(store.try_consume("t", "n", None).await.unwrap(), "scoped");
        assert!(store.is_consumed("s", "n"));
        PaymentNonceStore::release(&store, "s", "n").await.unwrap();
        assert!(!store.is_consumed("s", "n"));
        assert!(store.try_consume("s", "n", None).await.unwrap());
        PaymentNonceStore::release(&store, "s", "never")
            .await
            .unwrap();
        assert_eq!(store.len(), 2);
    }

    #[tokio::test]
    async fn a_claim_is_won_once_and_a_fault_is_never_a_win() {
        let store = MemoryStore::new();
        assert!(store.is_empty());
        assert!(store.claim("prefix-1", "agent-a").await.unwrap());
        assert!(!store.claim("prefix-1", "agent-b").await.unwrap());
        ClaimStore::release(&store, "prefix-1").await.unwrap();
        assert!(store.claim("prefix-1", "agent-b").await.unwrap());
        store.fail(true);
        assert!(store.claim("prefix-2", "a").await.is_err());
        assert!(store.try_consume("s", "n", None).await.is_err());
        assert!(ClaimStore::release(&store, "prefix-1").await.is_err());
        store.fail(false);
        assert!(store.claim("prefix-2", "a").await.unwrap());
    }

    #[tokio::test]
    async fn a_prefix_binds_its_first_txid() {
        let store = MemoryStore::new();
        assert_eq!(
            store.claim_prefix("p", "a", "agent").await.unwrap(),
            PrefixClaim::Won
        );
        assert_eq!(
            store.claim_prefix("p", "a", "agent").await.unwrap(),
            PrefixClaim::SameTransaction
        );
        assert_eq!(
            store.claim_prefix("p", "b", "agent").await.unwrap(),
            PrefixClaim::OtherTransaction
        );
        store.fail(true);
        assert!(store.claim_prefix("fresh", "b", "agent").await.is_err());
        assert!(store.release_prefix("p", "a").await.is_err());
    }

    #[tokio::test]
    async fn a_released_prefix_is_retaken_by_its_own_txid_only() {
        let store = MemoryStore::new();
        assert_eq!(
            store.claim_prefix("p", "a", "agent").await.unwrap(),
            PrefixClaim::Won
        );
        store.release_prefix("p", "b").await.unwrap();
        assert_eq!(
            store.claim_prefix("p", "a", "agent").await.unwrap(),
            PrefixClaim::SameTransaction
        );
        store.release_prefix("p", "a").await.unwrap();
        assert_eq!(
            store.claim_prefix("p", "b", "agent").await.unwrap(),
            PrefixClaim::OtherTransaction
        );
        assert_eq!(
            store.claim_prefix("p", "a", "agent").await.unwrap(),
            PrefixClaim::Won
        );
        assert_eq!(
            store.claim_prefix("p", "a", "agent").await.unwrap(),
            PrefixClaim::SameTransaction
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    #[allow(deprecated)]
    fn store_error_names_its_reason() {
        let e = StoreError::new("kv 429");
        assert_eq!(e.reason(), "kv 429");
        assert_eq!(e.to_string(), "kv 429");
        assert_eq!(PAYMENT_NONCE_SCOPE, "payment-derivation-prefix");
    }
}
