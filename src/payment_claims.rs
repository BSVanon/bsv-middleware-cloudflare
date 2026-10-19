//! Exact M14 payment-prefix bindings and separate idempotency claims on D1.
//!
//! Use [`D1PrefixStore`] with the stock middleware, or [`payment_prefix_gate`]
//! before any wallet call in a custom door. Bindings never expire. The upsert
//! and classification read run in one D1 batch transaction. Before deploying
//! 0.7.0, run both [`PAYMENT_CLAIMS_MIGRATION`] statements ONCE on existing
//! tables. Legacy rows remain closed (`PrefixClaim::Unknown`). Refund keys
//! keep their delete-on-release behavior through [`D1ClaimStore`].
//!
//! Fleet wire table (the host signs the returned body with BRC-104):
//!
//! | Claim | Result |
//! |---|---|
//! | Won | Proceed |
//! | SameTransaction / Unknown | 409 ERR_PAYMENT_REPLAYED |
//! | OtherTransaction | 400 ERR_PAYMENT_INVALID, no internalize or refund |
//! | Fault, Closed | 503 ERR_PAYMENT_LOCK_UNAVAILABLE, retryable, quote kept |
//! | Fault, Open | Fault detail for the host to log and retain its behavior |
//! No refusal body includes a txid or internal fault detail.

use bsv_middleware_core::{PaymentPrefixStore, PrefixClaim, StoreError};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::D1Database;
use worker::Env;

/// The `payment_claims` table, as one statement for a D1 migration.
pub const PAYMENT_CLAIMS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS payment_claims (\
    nonce TEXT PRIMARY KEY, agent TEXT, created_at INTEGER, \
    txid TEXT, released INTEGER NOT NULL DEFAULT 0\
)";

/// Run each statement ONCE on a pre-M14 table before deploying adapter 0.7.0.
pub const PAYMENT_CLAIMS_MIGRATION: &[&str] = &[
    "ALTER TABLE payment_claims ADD COLUMN txid TEXT",
    "ALTER TABLE payment_claims ADD COLUMN released INTEGER NOT NULL DEFAULT 0",
];

const CLAIM_SQL: &str =
    "INSERT OR IGNORE INTO payment_claims (nonce, agent, created_at) VALUES (?, ?, unixepoch())";
const RELEASE_SQL: &str = "DELETE FROM payment_claims WHERE nonce = ? AND txid IS NULL";
const PREFIX_CLAIM_SQL: &str = "INSERT INTO payment_claims (nonce, agent, created_at, txid, released) VALUES (?1, ?2, unixepoch(), ?3, 0) \
    ON CONFLICT(nonce) DO UPDATE SET released = 0 \
    WHERE payment_claims.txid = excluded.txid AND payment_claims.released = 1";
const PREFIX_READ_SQL: &str = "SELECT txid FROM payment_claims WHERE nonce = ?1";
const PREFIX_RELEASE_SQL: &str =
    "UPDATE payment_claims SET released = 1 WHERE nonce = ?1 AND txid = ?2";

/// `INSERT OR IGNORE` reports a changed row only when the insert took; a
/// missing row count is treated as NOT won (never fail open on the money path).
fn claim_won(changes: Option<usize>) -> bool {
    changes.unwrap_or(0) > 0
}

/// Atomically claim an idempotency key (for example, a refund-once key).
/// Never use this helper for a payment derivation prefix.
///
/// - `Ok(true)`: this call won the claim (fresh); proceed.
/// - `Ok(false)`: the nonce was already claimed (concurrent or sequential
///   replay); reject without serving.
/// - `Err(_)`: storage fault; the caller decides fail-open vs fail-closed.
///
/// `agent` is recorded for diagnostics only.
pub async fn claim_payment_nonce(
    db: &D1Database,
    nonce: &str,
    agent: &str,
) -> std::result::Result<bool, String> {
    let stmt = db
        .prepare(CLAIM_SQL)
        .bind(&[JsValue::from_str(nonce), JsValue::from_str(agent)])
        .map_err(|e| format!("claim bind: {}", e))?;
    let res = stmt.run().await.map_err(|e| format!("claim run: {}", e))?;
    let changes = res
        .meta()
        .map_err(|e| format!("claim meta: {}", e))?
        .and_then(|m| m.changes);
    Ok(claim_won(changes))
}

/// Release an idempotency key best-effort. Never releases a bound payment prefix.
pub async fn release_payment_nonce(db: &D1Database, nonce: &str) {
    if let Ok(stmt) = db.prepare(RELEASE_SQL).bind(&[JsValue::from_str(nonce)]) {
        let _ = stmt.run().await;
    }
}

/// A D1 `payment_claims` table as the core's
/// [`ClaimStore`](bsv_middleware_core::ClaimStore): [`claim_payment_nonce`]
/// and [`release_payment_nonce`] behind the trait, for code written against
/// the core. A storage fault is a [`StoreError`].
pub struct D1ClaimStore<'a>(pub &'a D1Database);

impl bsv_middleware_core::ClaimStore for D1ClaimStore<'_> {
    async fn claim(
        &self,
        key: &str,
        agent: &str,
    ) -> std::result::Result<bool, bsv_middleware_core::StoreError> {
        claim_payment_nonce(self.0, key, agent)
            .await
            .map_err(bsv_middleware_core::StoreError::new)
    }

    async fn release(&self, key: &str) -> std::result::Result<(), bsv_middleware_core::StoreError> {
        release_payment_nonce(self.0, key).await;
        Ok(())
    }
}

/// Exact, permanent M14 bindings on a D1 `payment_claims` table.
pub struct D1PrefixStore<'a>(pub &'a D1Database);

#[derive(Deserialize)]
struct PrefixRow {
    txid: Option<String>,
}

fn classify_prefix(
    changes: Option<usize>,
    row: Option<PrefixRow>,
    txid: &str,
) -> Result<PrefixClaim, String> {
    if changes == Some(1) {
        return Ok(PrefixClaim::Won);
    }
    match row {
        Some(PrefixRow { txid: Some(bound) }) if bound == txid => Ok(PrefixClaim::SameTransaction),
        Some(PrefixRow { txid: Some(_) }) => Ok(PrefixClaim::OtherTransaction),
        Some(PrefixRow { txid: None }) => Ok(PrefixClaim::Unknown),
        None => Err("prefix claim batch returned no binding".into()),
    }
}

/// Claim a prefix with one atomic upsert and its read in the same D1 batch.
/// A missing change count never grants a win; a missing row is a fault.
pub async fn claim_payment_prefix(
    db: &D1Database,
    prefix: &str,
    txid: &str,
    agent: &str,
) -> Result<PrefixClaim, String> {
    let claim = db
        .prepare(PREFIX_CLAIM_SQL)
        .bind(&[prefix.into(), agent.into(), txid.into()])
        .map_err(|e| e.to_string())?;
    let read = db
        .prepare(PREFIX_READ_SQL)
        .bind(&[prefix.into()])
        .map_err(|e| e.to_string())?;
    let results = db
        .batch(vec![claim, read])
        .await
        .map_err(|e| e.to_string())?;
    if results.len() != 2 {
        return Err("prefix claim batch returned incomplete results".into());
    }
    if results.iter().any(|result| !result.success()) {
        return Err("prefix claim batch failed".into());
    }
    let changes = results[0]
        .meta()
        .map_err(|e| e.to_string())?
        .and_then(|m| m.changes);
    let row = results[1]
        .results::<PrefixRow>()
        .map_err(|e| e.to_string())?
        .into_iter()
        .next();
    classify_prefix(changes, row, txid)
}

impl PaymentPrefixStore for D1PrefixStore<'_> {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        claim_payment_prefix(self.0, prefix, txid, agent)
            .await
            .map_err(StoreError::new)
    }
    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        self.0
            .prepare(PREFIX_RELEASE_SQL)
            .bind(&[prefix.into(), txid.into()])
            .map_err(|e| StoreError::new(e.to_string()))?
            .run()
            .await
            .map_err(|e| StoreError::new(e.to_string()))?;
        Ok(())
    }
}

/// The door's chosen behavior when its claim ledger cannot answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPosture {
    /// Return the fault to the door, which logs and keeps its existing policy.
    Open,
    /// Refuse with a retryable 503, retaining the quote.
    Closed,
}

/// A custom door's pre-wallet prefix decision. The host signs refusal bodies.
#[derive(Debug, PartialEq)]
pub enum PrefixGate {
    /// The claim was won; wallet processing may begin.
    Proceed,
    /// Return this status and body without a wallet call or refund.
    Refuse {
        status: u16,
        body: serde_json::Value,
    },
    /// Open posture only: the door must log this detail and apply its policy.
    Fault { detail: String },
}

fn prefix_gate_answer(claim: Result<PrefixClaim, String>, posture: FaultPosture) -> PrefixGate {
    let (status, code, description, retryable) = match claim {
        Ok(PrefixClaim::Won) => return PrefixGate::Proceed,
        Ok(PrefixClaim::SameTransaction | PrefixClaim::Unknown) => (409, "ERR_PAYMENT_REPLAYED", "This payment derivation prefix was already claimed.", false),
        Ok(PrefixClaim::OtherTransaction) => (400, "ERR_PAYMENT_INVALID", "Payment rejected: this derivation prefix was already used by another transaction (BRC-105: each prefix pays once). Nothing was internalized; get a fresh quote.", false),
        Err(detail) if posture == FaultPosture::Open => return PrefixGate::Fault { detail },
        Err(_) => (503, "ERR_PAYMENT_LOCK_UNAVAILABLE", "The payment claim ledger is unavailable. Nothing was internalized; the quote is still valid. Retry the same payment.", true),
    };
    let mut body =
        serde_json::json!({ "status": "error", "code": code, "description": description });
    if retryable {
        body["retryable"] = true.into();
    }
    PrefixGate::Refuse { status, body }
}

/// Claim through `CLAIMS` before any storage handshake, internalize or handler.
/// Missing bindings and D1 faults follow the door's explicit `posture`.
pub async fn payment_prefix_gate(
    env: &Env,
    prefix: &str,
    txid: &str,
    agent: &str,
    posture: FaultPosture,
) -> PrefixGate {
    let result = match env.d1("CLAIMS") {
        Ok(db) => claim_payment_prefix(&db, prefix, txid, agent).await,
        Err(e) => Err(e.to_string()),
    };
    prefix_gate_answer(result, posture)
}

/// Release this transaction's attempt, preserving its permanent binding.
/// Logs a missing binding or release fault; never deletes a record.
pub async fn release_payment_prefix(env: &Env, prefix: &str, txid: &str) {
    let result = match env.d1("CLAIMS") {
        Ok(db) => D1PrefixStore(&db).release_prefix(prefix, txid).await,
        Err(e) => Err(StoreError::new(e.to_string())),
    };
    if let Err(e) = result {
        worker::console_warn!("payment prefix release failed: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_is_won_only_by_an_inserted_row() {
        assert!(claim_won(Some(1)));
        assert!(!claim_won(Some(0)), "ignored insert = already claimed");
        assert!(!claim_won(None), "no row count = not won (fail closed)");
    }

    #[test]
    fn test_statements_target_the_documented_table() {
        assert!(PAYMENT_CLAIMS_SCHEMA.contains("payment_claims"));
        assert!(PAYMENT_CLAIMS_SCHEMA.contains("nonce TEXT PRIMARY KEY"));
        assert!(CLAIM_SQL.starts_with("INSERT OR IGNORE INTO payment_claims"));
        assert!(RELEASE_SQL.starts_with("DELETE FROM payment_claims"));
    }
    #[test]
    fn the_claims_sql_on_sqlite() {
        use rusqlite::{Connection, OptionalExtension};
        fn claim(db: &mut Connection, prefix: &str, txid: &str) -> PrefixClaim {
            let batch = db.transaction().unwrap();
            let changes = batch
                .execute(PREFIX_CLAIM_SQL, [prefix, "agent", txid])
                .unwrap();
            let row = batch
                .query_row(PREFIX_READ_SQL, [prefix], |row| {
                    Ok(PrefixRow { txid: row.get(0)? })
                })
                .optional()
                .unwrap();
            let result = classify_prefix(Some(changes), row, txid).unwrap();
            batch.commit().unwrap();
            result
        }
        fn exercise(db: &mut Connection) {
            assert_eq!(claim(db, "p", "a"), PrefixClaim::Won);
            assert_eq!(claim(db, "p", "a"), PrefixClaim::SameTransaction);
            assert_eq!(claim(db, "p", "b"), PrefixClaim::OtherTransaction);
            assert_eq!(db.execute(PREFIX_RELEASE_SQL, ["p", "b"]).unwrap(), 0);
            assert_eq!(claim(db, "p", "a"), PrefixClaim::SameTransaction);
            assert_eq!(db.execute(PREFIX_RELEASE_SQL, ["p", "a"]).unwrap(), 1);
            assert_eq!(claim(db, "p", "b"), PrefixClaim::OtherTransaction);
            assert_eq!(db.execute(RELEASE_SQL, ["p"]).unwrap(), 0);
            assert_eq!(claim(db, "p", "a"), PrefixClaim::Won);
            assert_eq!(claim(db, "p", "a"), PrefixClaim::SameTransaction);
            assert_eq!(db.execute(CLAIM_SQL, ["refund:key", "agent"]).unwrap(), 1);
            assert_eq!(db.execute(RELEASE_SQL, ["refund:key"]).unwrap(), 1);
            assert_eq!(db.execute(CLAIM_SQL, ["refund:key", "agent"]).unwrap(), 1);
        }
        let mut fresh = Connection::open_in_memory().unwrap();
        fresh.execute_batch(PAYMENT_CLAIMS_SCHEMA).unwrap();
        exercise(&mut fresh);
        let mut migrated = Connection::open_in_memory().unwrap();
        migrated.execute_batch("CREATE TABLE payment_claims (nonce TEXT PRIMARY KEY, agent TEXT, created_at INTEGER)").unwrap();
        migrated
            .execute(CLAIM_SQL, ["legacy", "old-agent"])
            .unwrap();
        for sql in PAYMENT_CLAIMS_MIGRATION {
            migrated.execute_batch(sql).unwrap();
        }
        assert_eq!(claim(&mut migrated, "legacy", "a"), PrefixClaim::Unknown);
        assert_eq!(
            migrated
                .execute(PREFIX_RELEASE_SQL, ["legacy", "a"])
                .unwrap(),
            0
        );
        assert_eq!(claim(&mut migrated, "legacy", "b"), PrefixClaim::Unknown);
        exercise(&mut migrated);
        assert_eq!(
            classify_prefix(
                None,
                Some(PrefixRow {
                    txid: Some("a".into())
                }),
                "a"
            )
            .unwrap(),
            PrefixClaim::SameTransaction
        );
        assert!(classify_prefix(None, None, "a").is_err());
    }

    #[test]
    fn payment_prefix_gate_answers() {
        assert_eq!(
            prefix_gate_answer(Ok(PrefixClaim::Won), FaultPosture::Closed),
            PrefixGate::Proceed
        );
        for (claim, status, code) in [
            (
                Ok(PrefixClaim::SameTransaction),
                409,
                "ERR_PAYMENT_REPLAYED",
            ),
            (Ok(PrefixClaim::Unknown), 409, "ERR_PAYMENT_REPLAYED"),
            (
                Ok(PrefixClaim::OtherTransaction),
                400,
                "ERR_PAYMENT_INVALID",
            ),
            (
                Err("private-txid-and-fault-detail".into()),
                503,
                "ERR_PAYMENT_LOCK_UNAVAILABLE",
            ),
        ] {
            let PrefixGate::Refuse {
                status: actual,
                body,
            } = prefix_gate_answer(claim, FaultPosture::Closed)
            else {
                panic!("expected refusal")
            };
            assert_eq!(actual, status);
            assert_eq!(body["code"], code);
            assert!(!body.to_string().contains("txid"));
            assert!(!body.to_string().contains("private"));
            assert!(body.get("transaction").is_none());
            if status == 503 {
                assert_eq!(body["retryable"], true);
                assert!(body["description"]
                    .as_str()
                    .unwrap()
                    .contains("quote is still valid"));
            }
        }
        assert_eq!(
            prefix_gate_answer(Err("detail".into()), FaultPosture::Open),
            PrefixGate::Fault {
                detail: "detail".into()
            }
        );
    }
}
