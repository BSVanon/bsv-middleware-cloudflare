//! D1-backed session storage for BRC-103/104 authentication.
//!
//! Implements the [`SessionStorage`] trait against a Cloudflare D1 (SQLite)
//! database. Designed for workers that already provision a D1 binding for
//! their primary data store; sessions ride along inside the same DB so the
//! KV `AUTH_SESSIONS` namespace isn't required at all.
//!
//! ## Why D1 instead of KV for sessions
//!
//! Cloudflare Workers KV's free tier caps **writes** at 1,000/day. The
//! BRC-103/104 middleware's per-message `update_session` (in `auth.rs`)
//! does two KV writes per authenticated request (session record + identity
//! index), so an authenticated wallet doing 250 requests/day saturates the
//! free tier — the user's "50% of daily KV limit" alert at SendBSV-Wallet on
//! 2026-05-29 was exactly this shape.
//!
//! D1's free tier allows ~100k writes/day, ~250× the headroom, and the
//! storage server already binds a D1 namespace, so this swap removes the
//! KV write hot-path entirely without expanding the infrastructure surface.
//!
//! ## Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS auth_sessions (
//!   session_nonce      TEXT PRIMARY KEY,
//!   peer_identity_key  TEXT NOT NULL,
//!   session_json       TEXT NOT NULL,
//!   last_update_ms     INTEGER NOT NULL,
//!   expires_at_ms      INTEGER NOT NULL
//! );
//! CREATE INDEX IF NOT EXISTS idx_auth_sessions_identity ON auth_sessions(peer_identity_key);
//! CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at_ms);
//! ```
//!
//! The full `StoredSession` rides in `session_json` so this schema doesn't
//! drift if the struct gains fields. `last_update_ms` is duplicated out of
//! the JSON for fast eviction sweeps; `expires_at_ms` is the TTL frontier
//! the consumer sets at create-time (last_update + session_ttl_seconds).
//! Reads use the primary-key path; identity lookups use the index.

use crate::error::{AuthCloudflareError, Result};
use crate::storage::session_storage::SessionStorage;
use crate::types::StoredSession;
use async_trait::async_trait;
use worker::D1Database;

/// Session storage backed by a Cloudflare D1 database.
///
/// Construct one per request — `D1Database` is cheap to obtain via
/// `env.d1(binding_name)?` and the wrapper itself holds no state beyond
/// the borrowed handle and config.
pub struct D1SessionStorage<'a> {
    db: &'a D1Database,
    session_ttl_seconds: u64,
}

impl<'a> D1SessionStorage<'a> {
    /// Creates a new D1-backed session storage.
    ///
    /// `session_ttl_seconds` is used to compute `expires_at_ms` on writes.
    /// Reads filter out rows whose `expires_at_ms` is in the past.
    pub fn new(db: &'a D1Database, session_ttl_seconds: u64) -> Self {
        Self {
            db,
            session_ttl_seconds,
        }
    }

    /// Returns the current time in milliseconds since epoch.
    fn now_ms() -> u64 {
        worker::Date::now().as_millis()
    }

    fn expires_at_ms(&self, base_ms: u64) -> u64 {
        base_ms + self.session_ttl_seconds * 1000
    }
}

#[async_trait(?Send)]
impl<'a> SessionStorage for D1SessionStorage<'a> {
    async fn get_session(&self, session_nonce: &str) -> Result<Option<StoredSession>> {
        // D1's bind layer converts JS Number → SQLite INTEGER. Passing i64
        // via `JsValue::from(i64)` produces a BigInt, which D1 rejects with
        // "D1_TYPE_ERROR: Type 'bigint' not supported". Routing the millisecond
        // timestamps through f64 keeps them within Number's safe-integer range
        // (2^53 ≫ any plausible ms-epoch this century) and matches the pattern
        // the storage server's `d1::QVal::Int → JsValue::from_f64` uses.
        let now_ms_f64 = Self::now_ms() as f64;
        let stmt = self
            .db
            .prepare(
                "SELECT session_json FROM auth_sessions \
                 WHERE session_nonce = ? AND expires_at_ms > ? LIMIT 1",
            )
            .bind(&[session_nonce.into(), now_ms_f64.into()])
            .map_err(|e| AuthCloudflareError::KvError(format!("D1 bind get_session: {e}")))?;

        let row: Option<serde_json::Value> = stmt
            .first(None)
            .await
            .map_err(|e| AuthCloudflareError::KvError(format!("D1 get_session: {e}")))?;

        match row {
            Some(value) => {
                let json_str = value
                    .get("session_json")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AuthCloudflareError::KvError(
                            "D1 get_session: session_json column missing/non-string".into(),
                        )
                    })?;
                let session: StoredSession = serde_json::from_str(json_str)
                    .map_err(|e| AuthCloudflareError::KvError(format!("D1 session JSON: {e}")))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn get_session_by_identity(
        &self,
        identity_key_hex: &str,
    ) -> Result<Option<StoredSession>> {
        // See `get_session` for the f64-bind rationale.
        let now_ms_f64 = Self::now_ms() as f64;
        // Pick the most recently touched session for this identity.
        let stmt = self
            .db
            .prepare(
                "SELECT session_json FROM auth_sessions \
                 WHERE peer_identity_key = ? AND expires_at_ms > ? \
                 ORDER BY last_update_ms DESC LIMIT 1",
            )
            .bind(&[identity_key_hex.into(), now_ms_f64.into()])
            .map_err(|e| {
                AuthCloudflareError::KvError(format!("D1 bind get_session_by_identity: {e}"))
            })?;

        let row: Option<serde_json::Value> = stmt
            .first(None)
            .await
            .map_err(|e| {
                AuthCloudflareError::KvError(format!("D1 get_session_by_identity: {e}"))
            })?;

        match row {
            Some(value) => {
                let json_str = value
                    .get("session_json")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AuthCloudflareError::KvError(
                            "D1 get_session_by_identity: session_json missing/non-string".into(),
                        )
                    })?;
                let session: StoredSession = serde_json::from_str(json_str)
                    .map_err(|e| AuthCloudflareError::KvError(format!("D1 session JSON: {e}")))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn save_session(&self, session: &StoredSession) -> Result<()> {
        let json = serde_json::to_string(session)
            .map_err(|e| AuthCloudflareError::KvError(format!("D1 save_session json: {e}")))?;
        // f64 conversion avoids D1's bigint-not-supported error. See `get_session`.
        let last_update = session.last_update as f64;
        let expires_at = self.expires_at_ms(session.last_update) as f64;

        let stmt = self
            .db
            .prepare(
                "INSERT INTO auth_sessions \
                   (session_nonce, peer_identity_key, session_json, last_update_ms, expires_at_ms) \
                 VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT(session_nonce) DO UPDATE SET \
                   peer_identity_key = excluded.peer_identity_key, \
                   session_json      = excluded.session_json, \
                   last_update_ms    = excluded.last_update_ms, \
                   expires_at_ms     = excluded.expires_at_ms",
            )
            .bind(&[
                session.session_nonce.as_str().into(),
                session.peer_identity_key.as_str().into(),
                json.as_str().into(),
                last_update.into(),
                expires_at.into(),
            ])
            .map_err(|e| AuthCloudflareError::KvError(format!("D1 bind save_session: {e}")))?;

        stmt.run()
            .await
            .map_err(|e| AuthCloudflareError::KvError(format!("D1 save_session: {e}")))?;
        Ok(())
    }

    async fn update_session(&self, session: &StoredSession) -> Result<()> {
        // ON CONFLICT path in save_session is idempotent — reuse it. D1
        // semantics: an UPSERT keyed by session_nonce.
        self.save_session(session).await
    }
}
