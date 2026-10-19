//! BRC-29 Payment middleware for Cloudflare Workers.
//!
//! This is a 1:1 port of payment-express-middleware, adapted for Cloudflare Workers.
//! It implements the same payment flow:
//! 1. Requires auth middleware to run first (checks auth_context)
//! 2. Calculates request price via user-provided function
//! 3. If price = 0: free pass
//! 4. If no x-bsv-payment header: returns 402 with derivation prefix (nonce)
//! 5. If payment header present: verifies nonce, reads the paying output and
//!    compares it with the price, internalizes payment via storage server
//!
//! Payment internalization uses `WorkerStorageClient` to talk to a remote storage
//! server (e.g. `storage.babbage.systems`) over BRC-103/104, matching how the TypeScript
//! Express middleware uses a `WalletInterface` (which is a remote wallet client).

use crate::client::WorkerStorageClient;
use crate::error::{AuthCloudflareError, Result};
use crate::middleware::auth::{add_cors_headers, sign_json_response, AuthSession};
use crate::types::{AuthContext, BsvPayment, ErrorResponse, PaymentContext};
#[cfg(test)]
use bsv_middleware_core::UnverifiableReason;
use bsv_middleware_core::{payment_subject_txid, PaymentPrefixStore, PrefixClaim};
use bsv_middleware_core::{verify_payment_output, PaymentFault, PaymentVerdict};
use bsv_sdk::auth::utils::{create_nonce, verify_nonce};
use bsv_sdk::primitives::{from_base64, PrivateKey};
use bsv_sdk::wallet::ProtoWallet;
use worker::{Headers, Request, Response};

/// Payment header names (BRC-29).
pub mod payment_headers {
    /// Payment data (JSON).
    pub const PAYMENT: &str = "x-bsv-payment";
    /// Payment protocol version.
    pub const VERSION: &str = "x-bsv-payment-version";
    /// Amount required in satoshis.
    pub const SATOSHIS_REQUIRED: &str = "x-bsv-payment-satoshis-required";
    /// Derivation prefix for payment address.
    pub const DERIVATION_PREFIX: &str = "x-bsv-payment-derivation-prefix";
    /// Amount paid in satoshis (response header).
    pub const SATOSHIS_PAID: &str = "x-bsv-payment-satoshis-paid";
    /// Transaction ID of the accepted payment (response header).
    pub const TXID: &str = "x-bsv-payment-txid";
    /// Supported payment transports (BRC-105 negotiation).
    pub const TRANSPORTS: &str = "x-bsv-payment-transports";
}

const PAYMENT_VERSION: &str = "1.0";
const ORIGINATOR: &str = "bsv-auth-cloudflare";

/// Legacy KV namespace. Payment replay protection uses [`PaymentPrefixStore`].
#[allow(deprecated)]
pub use bsv_middleware_core::store::PAYMENT_NONCE_SCOPE;

/// The output of the payment transaction that is internalized (and read).
const PAYMENT_OUTPUT_INDEX: usize = 0;

/// Options for payment middleware.
///
/// Mirrors payment-express-middleware's `PaymentMiddlewareOptions`:
/// - `server_private_key` for nonce operations (HMAC-based derivation prefix)
/// - `calculate_price` to determine per-request pricing
/// - `storage_url` for the remote storage server that handles `internalizeAction`
///
/// In the TypeScript middleware, a `WalletInterface` is passed in — typically a
/// `WalletClient` connected to `storage.babbage.systems`. Here, we use
/// `WorkerStorageClient` (created internally from the server key + storage URL)
/// to achieve the same thing.
pub struct PaymentMiddlewareOptions<F> {
    /// Server's private key (64-char hex). Used for:
    /// - Creating `ProtoWallet` for nonce operations (create_nonce/verify_nonce)
    /// - Authenticating to the storage server via BRC-103/104
    pub server_private_key: String,
    /// Function to calculate price for a request (in satoshis).
    /// Return 0 for free requests.
    /// Express equivalent: `calculateRequestPrice`
    pub calculate_price: F,
    /// URL of the storage server for payment internalization.
    /// Defaults to `WorkerStorageClient::MAINNET_URL` (<https://storage.babbage.systems>).
    pub storage_url: String,
    /// BRC-100 labels attached to every payment internalize.
    /// Real-wallet label permission is granted PER LABEL, which makes labels
    /// load-bearing, not decoration — production servers use small frozen
    /// vocabularies (e.g. "beacon read-fee"). `None` omits the key from the
    /// wire entirely (bit-compatible with the pre-labels behavior).
    pub labels: Option<Vec<String>>,
}

impl<F> PaymentMiddlewareOptions<F> {
    /// Creates new payment middleware options with mainnet storage.
    pub fn new(server_private_key: String, calculate_price: F) -> Self {
        Self {
            server_private_key,
            calculate_price,
            storage_url: WorkerStorageClient::MAINNET_URL.to_string(),
            labels: None,
        }
    }

    /// Creates new payment middleware options with a custom storage URL.
    pub fn with_storage_url(
        server_private_key: String,
        calculate_price: F,
        storage_url: String,
    ) -> Self {
        Self {
            server_private_key,
            calculate_price,
            storage_url,
            labels: None,
        }
    }

    /// Attach BRC-100 labels to every payment internalize (builder-style).
    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels = Some(labels);
        self
    }
}

/// Result of payment processing.
pub enum PaymentResult {
    /// No payment needed (price was 0).
    /// Express equivalent: `req.payment = { satoshisPaid: 0 }`, then `next()`
    Free,
    /// Payment required - return this 402 response.
    /// Express equivalent: `res.status(402).set({...}).json({...})`
    Required(Response),
    /// Payment verified successfully.
    /// Express equivalent: `req.payment = { satoshisPaid, accepted, tx }`, then `next()`
    Verified(PaymentContext),
    /// Payment verification failed - return this error response.
    Failed(Response),
}

/// Process payment for a request, with single-use derivation prefixes.
///
/// This is a port of payment-express-middleware's `createPaymentMiddleware`
/// with deliberate hardening divergences from the TS reference
/// (`@bsv/payment-express-middleware` 1.2.3), per audit finding #44:
///
/// 1. **`accepted` gate.** The reference destructures `accepted` from
///    `wallet.internalizeAction(...)` and calls `next()` regardless of its
///    value (index.ts:100-124). Here, `accepted != true` returns a **402**
///    ([`PaymentResult::Failed`]) carrying a fresh payment challenge —
///    a rejected payment never reaches the handler.
/// 2. **Single-use derivation prefix.** The reference's `verifyNonce` is a
///    stateless HMAC check — a captured `X-BSV-Payment` header can be
///    internalized repeatedly (bounded only by the upstream wallet's
///    duplicate handling). Here, each verified prefix is consumed through
///    [`PaymentPrefixStore::claim_prefix`] bound to its first subject txid
///    with **no expiry** (the HMAC itself never expires); a reused prefix is
///    rejected with `400 ERR_INVALID_DERIVATION_PREFIX` before touching the
///    wallet.
/// 3. **The paying output is read.** Like the reference (2.1.9's
///    `parseAtomicPayment` reads output 0's satoshis and refuses below the
///    price), output 0 is read and compared with the price before
///    internalizing; unlike it, the output must also be locked to the
///    server's BRC-29 key, because the storage server checks neither (the
///    reference leaves the script to its wallet's signer, which is not on
///    this path). The check is the core's
///    (`bsv_middleware_core::verify_payment_output`), answered in its words
///    and decided here in one match (`judge_paying_output`): a short or
///    misdirected payment (`Underpaid`, `WrongScript`) is refused with 400
///    `ERR_INVALID_PAYMENT`, as the reference does, and the quote is kept:
///    no fresh challenge, the prefix not consumed, the wallet not called,
///    so the client corrects the payment and retries under the same prefix
///    (0.4.0; 0.3.8 answered 402 with a fresh challenge). An unreadable
///    payment, a proof contradicting a block header, or a payment that
///    cannot be verified for a reason that is the payer's (`Unverifiable`
///    with a payer-side reason: invalid BEEF bytes, a refused spend, no
///    proof, no such output; the no-root ruling of 2026-10-09) is 400 as
///    well, the quote kept; a server that cannot judge (`NoHeaderService`,
///    or the server's own key not deriving: a `PaymentFault`) 500; a root
///    the header service could not check (`Unverifiable` with a server-side
///    reason) is refused with 503 `ERR_HEADER_SERVICE_UNAVAILABLE` and the
///    quote kept (fail-closed, 0.4.0: nothing is served on an unchecked
///    root; the client retries the same payment later). `satoshis_paid` is
///    the amount read, not the price.
///
///    This path runs no SPV of its own: output 0's script and amount are
///    checked here, and nothing on this path checks the transaction's
///    merkle proof against a block header. Whether the payment is real and
///    confirmable is left to the wallet storage server when it
///    internalizes the transaction, which this crate does not verify. A
///    caller that wants the proof checked through a header service before
///    internalize runs
///    [`verify_brc29_payment`](crate::payment_verify::verify_brc29_payment)
///    first.
///
/// Consumption ordering (money path):
/// - The prefix is consumed **before** `internalizeAction`, so concurrent
///   duplicates cannot both reach the wallet (subject to the storage
///   backend's consistency; see [`crate::KvPrefixStore`] for
///   the KV residual window).
/// - If `internalizeAction` fails with an **error**, the prefix is released
///   (best-effort) only to the same txid, retaining its binding forever.
/// - If the wallet returns **`accepted: false`** or the call succeeds, the
///   prefix stays consumed; the client must obtain a fresh 402 challenge.
///
/// **IMPORTANT**: Auth middleware MUST run before this. The `auth_context`
/// parameter must come from successful authentication. If `auth_context` is
/// not properly authenticated, this returns ERR_SERVER_MISCONFIGURED
/// (matching Express behavior when `req.auth.identityKey` is missing).
pub async fn process_payment_with_storage<F, S>(
    req: &Request,
    auth_context: &AuthContext,
    options: &PaymentMiddlewareOptions<F>,
    prefixes: &S,
) -> Result<PaymentResult>
where
    F: Fn(&Request) -> u64,
    S: PaymentPrefixStore + ?Sized,
{
    process_payment_inner(req, auth_context, options, prefixes).await
}

/// [`process_payment_with_storage`] with BRC-104-signed responses.
///
/// Identical decision flow, but every response this middleware builds —
/// the 402 challenges AND the failure responses — is signed against
/// `session` via [`sign_json_response`], the shape AuthFetch-class clients
/// expect. Production servers previously hand-rolled this composition
/// caller-side; pass the [`AuthSession`] from `process_auth` and the crate
/// carries it.
pub async fn process_payment_with_storage_signed<F, S>(
    req: &Request,
    auth_context: &AuthContext,
    options: &PaymentMiddlewareOptions<F>,
    prefixes: &S,
    session: &AuthSession,
) -> Result<PaymentResult>
where
    F: Fn(&Request) -> u64,
    S: PaymentPrefixStore + ?Sized,
{
    let payment_header = req.headers().get(payment_headers::PAYMENT).ok().flatten();
    let decision = decide_payment(
        auth_context,
        || (options.calculate_price)(req),
        payment_header,
        &options.server_private_key,
        prefixes,
        |derivation_prefix, derivation_suffix, tx_bytes| async move {
            internalize_payment(
                options,
                auth_context,
                &derivation_prefix,
                &derivation_suffix,
                tx_bytes,
            )
            .await
        },
    )
    .await?;
    decision_into_result_signed(decision, session)
}

/// Shared implementation with mandatory transaction-bound prefix protection.
///
/// Thin `worker::Request`/`Response` shell: extracts the price closure and
/// `x-bsv-payment` header from the request, delegates every money-path
/// decision to [`decide_payment`] (request-free, so `cargo test` executes
/// it natively), then renders the returned [`PaymentDecision`] into the
/// exact HTTP responses this function historically built inline.
async fn process_payment_inner<F, S>(
    req: &Request,
    auth_context: &AuthContext,
    options: &PaymentMiddlewareOptions<F>,
    prefixes: &S,
) -> Result<PaymentResult>
where
    F: Fn(&Request) -> u64,
    S: PaymentPrefixStore + ?Sized,
{
    let payment_header = req.headers().get(payment_headers::PAYMENT).ok().flatten();
    let decision = decide_payment(
        auth_context,
        || (options.calculate_price)(req),
        payment_header,
        &options.server_private_key,
        prefixes,
        |derivation_prefix, derivation_suffix, tx_bytes| async move {
            internalize_payment(
                options,
                auth_context,
                &derivation_prefix,
                &derivation_suffix,
                tx_bytes,
            )
            .await
        },
    )
    .await?;
    decision_into_result(decision)
}

/// Pure-data outcome of the payment decision core ([`decide_payment`]).
///
/// Each variant maps 1:1 onto a [`PaymentResult`] (see
/// [`decision_into_result`]); the split exists so the money path can be
/// executed under native `cargo test` — `worker::Response`/`Headers` wrap
/// `web_sys` types that only function on a live Workers runtime.
#[derive(Debug, PartialEq, Eq)]
enum PaymentDecision {
    /// Auth middleware didn't run first → 500 `ERR_SERVER_MISCONFIGURED`
    /// ([`PaymentResult::Failed`]).
    Misconfigured,
    /// Price was 0 → [`PaymentResult::Free`].
    Free,
    /// No `x-bsv-payment` header → 402 `ERR_PAYMENT_REQUIRED` challenge
    /// ([`PaymentResult::Required`]).
    Challenge {
        price: u64,
        derivation_prefix: String,
    },
    /// Header is not valid JSON → 400 `ERR_MALFORMED_PAYMENT`
    /// ([`PaymentResult::Failed`]).
    MalformedHeader,
    /// Derivation prefix failed HMAC verification → 400
    /// `ERR_INVALID_DERIVATION_PREFIX` ([`PaymentResult::Failed`]).
    InvalidPrefix,
    /// Derivation prefix was already consumed (single-use enforcement,
    /// audit #44) → 400 `ERR_INVALID_DERIVATION_PREFIX` "(already used)"
    /// ([`PaymentResult::Failed`]).
    ReplayedPrefix,
    /// Another transaction already bound this prefix. 400, no fresh challenge.
    PrefixUsedByAnotherTransaction,
    /// Claim store fault: retryable 503, quote kept, no wallet call.
    PrefixStoreUnavailable { detail: String },
    /// Wallet did not affirmatively accept (`accepted != true`) → 402
    /// `ERR_PAYMENT_FAILED` with a fresh challenge; the old prefix stays
    /// consumed ([`PaymentResult::Failed`]).
    WalletRejected { price: u64, fresh_prefix: String },
    /// `internalizeAction` errored (payment NOT processed; prefix released
    /// best-effort) → 400 `ERR_PAYMENT_FAILED` ([`PaymentResult::Failed`]).
    InternalizeError { description: String },
    /// The paying output carries less than the price or is not locked to
    /// the server's BRC-29 key → 400 `ERR_INVALID_PAYMENT`, the quote kept:
    /// no fresh challenge, the prefix never consumed, the wallet never
    /// called ([`PaymentResult::Failed`]). The client corrects the payment
    /// and retries under the same prefix.
    NotCovered { description: String },
    /// The payment transaction cannot be read, has no output 0, carries a
    /// proof that contradicts a block header, or cannot be verified for a
    /// reason that is the payer's (invalid BEEF bytes, a refused spend, no
    /// proof) → 400 `ERR_INVALID_PAYMENT`, the quote kept; the prefix is not
    /// consumed ([`PaymentResult::Failed`]).
    InvalidPayment { description: String },
    /// The server cannot judge the payment (the core answered
    /// `NoHeaderService`, or the server's own key does not derive: a
    /// `PaymentFault`) → 500 `ERR_SERVER_MISCONFIGURED`: the server's own
    /// fault, never a client error; the prefix is not consumed
    /// ([`PaymentResult::Failed`]).
    ServerFault { description: String },
    /// The header service could not answer for a merkle root (the core
    /// answered `Unverifiable`) → 503 `ERR_HEADER_SERVICE_UNAVAILABLE`, the
    /// quote kept: a transient server-side condition, nothing served on an
    /// unchecked root (fail-closed), no fresh challenge, the prefix not
    /// consumed, the wallet not called; the client retries the same payment
    /// later ([`PaymentResult::Failed`]).
    HeaderServiceUnavailable { description: String },
    /// Wallet accepted → [`PaymentResult::Verified`]; `satoshis_paid` is
    /// read from the paying output.
    Verified { satoshis_paid: u64, tx: String },
}

/// What this path does with the core's answer on the paying output.
#[derive(Debug, PartialEq, Eq)]
enum OutputJudgement {
    /// Serve; `satoshis_paid` is the amount the output carries.
    Covered { satoshis_paid: u64 },
    /// 400 `ERR_INVALID_PAYMENT`, the quote kept: no fresh challenge, the
    /// prefix not consumed, the wallet never called.
    NotCovered { description: String },
    /// 400 `ERR_INVALID_PAYMENT`, the quote kept; the prefix is kept.
    Invalid { description: String },
    /// 500 `ERR_SERVER_MISCONFIGURED`: the server's own; the prefix is kept.
    ServerFault { description: String },
    /// 503 `ERR_HEADER_SERVICE_UNAVAILABLE`, the quote kept: the root could
    /// not be checked, so nothing is served (fail-closed); the client
    /// retries the same payment once the service answers.
    HeaderServiceUnavailable { description: String },
}

/// The wire pair for a root the header service could not check: a 503, the
/// server's transient condition, distinct from the 500 of a server that has
/// no header service at all and from the 400s of a payment that is wrong.
const HEADER_SERVICE_UNAVAILABLE: (u16, &str) = (503, "ERR_HEADER_SERVICE_UNAVAILABLE");

/// The one match on this path from the core's words (and faults) to what
/// the middleware answers:
///
/// | the core says | this path answers |
/// |---|---|
/// | `Verified { satoshis }` | serve; `satoshis_paid = satoshis` |
/// | `Underpaid` / `WrongScript` | 400, the quote kept: no fresh challenge, prefix not consumed, wallet not called |
/// | `NoHeaderService` | 500: the server's own fault |
/// | `RootMismatch` | 400: a proof that contradicts a block header is a fraud signal, refused |
/// | `Unverifiable`, `reason.is_server_side()` | 503 `ERR_HEADER_SERVICE_UNAVAILABLE`, the quote kept: refused, fail-closed (0.4.0); the client retries the same payment later |
/// | `Unverifiable`, the payer's reason | 400, the quote kept: unreadable bytes, no such output, a sender key that does not derive, invalid BEEF, a refused spend, no proof (0.5.0; the no-root ruling of 2026-10-09) |
/// | a `PaymentFault` | 500: the server's own key does not derive (0.5.0; a payer's bytes are never a fault) |
///
/// Only `Verified` serves. The output check ([`verify_payment_output`])
/// answers `Verified`, `Underpaid`, `WrongScript`, a payer-side
/// `Unverifiable` or the server's fault; the SPV words are the path's
/// standing answer should the check grow a proof step.
fn judge_paying_output(
    answer: std::result::Result<PaymentVerdict, PaymentFault>,
) -> OutputJudgement {
    match answer {
        Ok(PaymentVerdict::Verified { satoshis }) => OutputJudgement::Covered {
            satoshis_paid: satoshis,
        },
        Ok(verdict @ (PaymentVerdict::Underpaid { .. } | PaymentVerdict::WrongScript { .. })) => {
            OutputJudgement::NotCovered {
                description: verdict.to_string(),
            }
        }
        Ok(verdict @ PaymentVerdict::NoHeaderService) => OutputJudgement::ServerFault {
            description: verdict.to_string(),
        },
        Ok(verdict @ PaymentVerdict::RootMismatch { .. }) => OutputJudgement::Invalid {
            description: verdict.to_string(),
        },
        // A root that could not be checked is not evidence: refused, as the
        // server's transient condition (503) with the quote kept, never
        // served and never blamed on the client (fail-closed, 0.4.0).
        Ok(verdict @ PaymentVerdict::Unverifiable { .. })
            if verdict.is_server_side_unverifiable() =>
        {
            OutputJudgement::HeaderServiceUnavailable {
                description: verdict.to_string(),
            }
        }
        // The payer's: unreadable bytes, no such output, a sender key that
        // does not derive, invalid BEEF, a refused spend, no proof. 400 with
        // the quote kept (0.5.0; the no-root ruling of 2026-10-09).
        Ok(verdict @ PaymentVerdict::Unverifiable { .. }) => OutputJudgement::Invalid {
            description: verdict.to_string(),
        },
        // A fault is the server's own (its key does not derive): never the
        // payer's bytes since 0.5.0.
        Err(fault) => OutputJudgement::ServerFault {
            description: fault.to_string(),
        },
    }
}

/// Request/`Response`-free core of BRC-29 payment processing.
///
/// Owns every ordering decision on the money path — auth gate → price →
/// challenge → header parse → HMAC verify → base64 decode → **consume
/// prefix** → internalize → **accepted gate / release** — over plain data,
/// so the whole path executes under native `cargo test` (audit finding #29's
/// lesson: handler logic must be executed by tests, not just its pure
/// helpers).
///
/// Parameters that exist purely as seams:
/// - `calculate_price` is lazy so the Express ordering is preserved
///   exactly: the reference errors on a missing `req.auth` *before*
///   calling `calculateRequestPrice`.
/// - `internalize` abstracts the wallet-communication phase
///   ([`internalize_payment`] in production, whose `WorkerStorageClient`
///   HTTP transport cannot run off-Workers). It receives
///   `(derivation_prefix, derivation_suffix, tx_bytes)` and returns the
///   wallet's `internalizeAction` JSON.
async fn decide_payment<P, S, I, Fut>(
    auth_context: &AuthContext,
    calculate_price: P,
    payment_header: Option<String>,
    server_private_key: &str,
    prefixes: &S,
    internalize: I,
) -> Result<PaymentDecision>
where
    P: FnOnce() -> u64,
    S: PaymentPrefixStore + ?Sized,
    I: FnOnce(String, String, Vec<u8>) -> Fut,
    Fut: core::future::Future<Output = Result<serde_json::Value>>,
{
    // Step 1: Verify auth middleware ran first (matches Express check for req.auth.identityKey)
    if !auth_context.is_authenticated || auth_context.identity_key == "unknown" {
        return Ok(PaymentDecision::Misconfigured);
    }

    // Step 2: Calculate price
    let price = calculate_price();

    // Step 3: If price is 0, proceed immediately (matches Express: `req.payment = { satoshisPaid: 0 }`)
    if price == 0 {
        return Ok(PaymentDecision::Free);
    }

    // Create wallet for nonce operations
    let private_key = PrivateKey::from_hex(server_private_key).map_err(|e| {
        AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
    })?;
    let wallet = ProtoWallet::new(Some(private_key));

    // Step 4: Check for payment header
    let Some(payment_json) = payment_header else {
        // No payment provided - generate nonce and return 402
        // Matches Express: `const derivationPrefix = await createNonce(wallet)`
        let derivation_prefix = create_nonce(&wallet, None, ORIGINATOR).await?;
        return Ok(PaymentDecision::Challenge {
            price,
            derivation_prefix,
        });
    };

    // Payment provided - parse and verify
    // Step 5: Parse payment JSON
    // Express: `paymentData = JSON.parse(String(bsvPaymentHeader))`
    let payment: BsvPayment = match serde_json::from_str(&payment_json) {
        Ok(p) => p,
        // Express catches parse error and returns ERR_MALFORMED_PAYMENT
        Err(_) => return Ok(PaymentDecision::MalformedHeader),
    };

    // Step 6: Verify derivation prefix (nonce)
    // Express: `const valid = await verifyNonce(paymentData.derivationPrefix, wallet)`
    let nonce_valid = verify_nonce(&payment.derivation_prefix, &wallet, None, ORIGINATOR)
        .await
        .unwrap_or_default();

    if !nonce_valid {
        // Express: returns ERR_INVALID_DERIVATION_PREFIX
        return Ok(PaymentDecision::InvalidPrefix);
    }

    // Decode the transaction BEFORE consuming the prefix — a
    // malformed payload must not burn the client's derivation prefix.
    let tx_bytes = from_base64(&payment.transaction).map_err(|_| {
        AuthCloudflareError::MalformedPayment("Invalid base64 transaction data".to_string())
    })?;

    // Step 6a: read the output that will be internalized and compare it
    // with the price before anyone is asked to record it. The storage
    // server checks neither the amount nor the script, so this is the only
    // check on the path. The core answers in its words; `judge_paying_output`
    // is this path's one match over them. Before consumption: a refusal
    // here is deterministic, so it must not burn the prefix, and the quote
    // stays whole (no fresh challenge) for the corrected retry.
    let satoshis_paid = match judge_paying_output(verify_payment_output(
        server_private_key,
        &auth_context.identity_key,
        &payment.derivation_prefix,
        &payment.derivation_suffix,
        &tx_bytes,
        PAYMENT_OUTPUT_INDEX,
        price,
    )) {
        OutputJudgement::Covered { satoshis_paid } => satoshis_paid,
        OutputJudgement::NotCovered { description } => {
            return Ok(PaymentDecision::NotCovered { description })
        }
        OutputJudgement::Invalid { description } => {
            return Ok(PaymentDecision::InvalidPayment { description })
        }
        OutputJudgement::ServerFault { description } => {
            return Ok(PaymentDecision::ServerFault { description })
        }
        OutputJudgement::HeaderServiceUnavailable { description } => {
            return Ok(PaymentDecision::HeaderServiceUnavailable { description })
        }
    };

    // M14: bind the subject before any wallet call. No expiry; faults fail closed.
    let txid = match payment_subject_txid(&tx_bytes) {
        Ok(txid) => txid,
        Err(reason) => {
            return Ok(PaymentDecision::InvalidPayment {
                description: reason.to_string(),
            })
        }
    };
    match prefixes
        .claim_prefix(&payment.derivation_prefix, &txid, ORIGINATOR)
        .await
    {
        Err(e) => {
            return Ok(PaymentDecision::PrefixStoreUnavailable {
                detail: e.to_string(),
            })
        }
        Ok(PrefixClaim::Won) => {}
        Ok(PrefixClaim::SameTransaction | PrefixClaim::Unknown) => {
            return Ok(PaymentDecision::ReplayedPrefix)
        }
        Ok(PrefixClaim::OtherTransaction) => {
            return Ok(PaymentDecision::PrefixUsedByAnotherTransaction)
        }
    }

    // Step 7: internalize the payment (see `internalize_payment`).
    // The whole wallet-communication phase maps to the reference's
    // try/catch around `wallet.internalizeAction(...)`.
    let internalize_result = internalize(
        payment.derivation_prefix.clone(),
        payment.derivation_suffix.clone(),
        tx_bytes,
    )
    .await;

    match internalize_result {
        Ok(result) => {
            // Gate on the wallet's `accepted` flag (hardening
            // divergence — audit #44). The TS reference
            // (payment-express-middleware 1.2.3, index.ts:100-124)
            // passes `accepted` through to `req.payment` and calls
            // `next()` even when the wallet rejected the payment.
            // Here a rejected payment returns 402 with a FRESH
            // challenge (the old prefix stays consumed).
            // A missing/non-boolean `accepted` field counts as
            // rejected — never fail open on the money path.
            if !internalize_accepted(&result) {
                let fresh_prefix = create_nonce(&wallet, None, ORIGINATOR).await?;
                return Ok(PaymentDecision::WalletRejected {
                    price,
                    fresh_prefix,
                });
            }

            // Success - matches Express: req.payment = { satoshisPaid, accepted, tx }
            Ok(PaymentDecision::Verified {
                satoshis_paid,
                tx: payment.transaction,
            })
        }
        Err(e) => {
            // Retain the binding even on an ambiguous wallet error: only this
            // transaction may retry, subject to the wallet's duplicate handling.
            if let Err(release_err) = prefixes
                .release_prefix(&payment.derivation_prefix, &txid)
                .await
            {
                warn_log(&format!("payment prefix release failed: {release_err}"));
            }

            // Express: catch(err) => res.status(400).json({ code: err.code ?? 'ERR_PAYMENT_FAILED', description: err.message ?? 'Payment failed.' })
            Ok(PaymentDecision::InternalizeError {
                description: e.to_string(),
            })
        }
    }
}

/// Renders a [`PaymentDecision`] into the [`PaymentResult`] (and its HTTP
/// `Response` bodies/headers) that `process_payment_inner` historically
/// built inline. Wire bytes are unchanged: identical JSON constructors,
/// identical header sets, identical statuses, identical CORS wrapping.
fn decision_into_result(decision: PaymentDecision) -> Result<PaymentResult> {
    match decision {
        PaymentDecision::Misconfigured => failed_json_response(
            500,
            "ERR_SERVER_MISCONFIGURED",
            "The payment middleware must be executed after the Auth middleware.",
        ),
        PaymentDecision::Free => Ok(PaymentResult::Free),
        PaymentDecision::Challenge {
            price,
            derivation_prefix,
        } => {
            // Build 402 response with payment headers
            // Matches Express response exactly
            let body = serde_json::json!({
                "status": "error",
                "code": "ERR_PAYMENT_REQUIRED",
                "satoshisRequired": price,
                "description": "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
            });

            let response = Response::from_json(&body)
                .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
                .with_status(402)
                .with_headers(challenge_headers(price, &derivation_prefix));

            Ok(PaymentResult::Required(add_cors_headers(response)))
        }
        PaymentDecision::MalformedHeader => failed_json_response(
            400,
            "ERR_MALFORMED_PAYMENT",
            "The X-BSV-Payment header is not valid JSON.",
        ),
        PaymentDecision::InvalidPrefix => failed_json_response(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The X-BSV-Payment-Derivation-Prefix header is not valid.",
        ),
        PaymentDecision::ReplayedPrefix => failed_json_response(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The X-BSV-Payment-Derivation-Prefix header is not valid (already used).",
        ),
        PaymentDecision::PrefixUsedByAnotherTransaction => failed_json_response(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The derivation prefix was already used by another transaction (BRC-105: each prefix pays once). Nothing was internalized; request a fresh challenge.",
        ),
        PaymentDecision::PrefixStoreUnavailable { detail } => {
            warn_log(&format!("payment prefix store unavailable: {detail}"));
            let (status, body, headers) = payment_unavailable_response();
            let response = Response::from_json(&body)?.with_status(status);
            for (name, value) in headers {
                response.headers().set(&name, &value)?;
            }
            Ok(PaymentResult::Failed(add_cors_headers(response)))
        }
        PaymentDecision::WalletRejected {
            price,
            fresh_prefix,
        } => {
            let response = Response::from_json(&ErrorResponse::new(
                "ERR_PAYMENT_FAILED",
                "The BSV payment was not accepted by the wallet. A fresh payment challenge is provided in the response headers.",
            ))
            .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
            .with_status(402)
            .with_headers(challenge_headers(price, &fresh_prefix));
            Ok(PaymentResult::Failed(add_cors_headers(response)))
        }
        PaymentDecision::InternalizeError { description } => {
            failed_json_response(400, "ERR_PAYMENT_FAILED", &description)
        }
        PaymentDecision::NotCovered { description } => {
            let text = not_covered_description(&description);
            failed_json_response(400, "ERR_INVALID_PAYMENT", &text)
        }
        PaymentDecision::InvalidPayment { description } => {
            failed_json_response(400, "ERR_INVALID_PAYMENT", &description)
        }
        PaymentDecision::ServerFault { description } => {
            failed_json_response(500, "ERR_SERVER_MISCONFIGURED", &description)
        }
        PaymentDecision::HeaderServiceUnavailable { description } => {
            let (status, code) = HEADER_SERVICE_UNAVAILABLE;
            failed_json_response(
                status,
                code,
                &header_service_unavailable_description(&description),
            )
        }
        PaymentDecision::Verified { satoshis_paid, tx } => {
            Ok(PaymentResult::Verified(PaymentContext {
                satoshis_paid,
                accepted: true,
                tx: Some(tx),
            }))
        }
    }
}

/// [`decision_into_result`] with every built response BRC-104-signed
/// against the caller's [`AuthSession`]. Free/Verified variants carry no
/// response and pass through untouched.
fn decision_into_result_signed(
    decision: PaymentDecision,
    session: &AuthSession,
) -> Result<PaymentResult> {
    let signed_failed = |status: u16, code: &str, description: &str| -> Result<PaymentResult> {
        let response =
            sign_json_response(&ErrorResponse::new(code, description), status, &[], session)?;
        Ok(PaymentResult::Failed(response))
    };
    match decision {
        PaymentDecision::Misconfigured => signed_failed(
            500,
            "ERR_SERVER_MISCONFIGURED",
            "The payment middleware must be executed after the Auth middleware.",
        ),
        PaymentDecision::Free => Ok(PaymentResult::Free),
        PaymentDecision::Challenge {
            price,
            derivation_prefix,
        } => {
            let body = serde_json::json!({
                "status": "error",
                "code": "ERR_PAYMENT_REQUIRED",
                "satoshisRequired": price,
                "description": "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
            });
            let response = sign_json_response(
                &body,
                402,
                &challenge_header_pairs(price, &derivation_prefix),
                session,
            )?;
            Ok(PaymentResult::Required(response))
        }
        PaymentDecision::MalformedHeader => signed_failed(
            400,
            "ERR_MALFORMED_PAYMENT",
            "The X-BSV-Payment header is not valid JSON.",
        ),
        PaymentDecision::InvalidPrefix => signed_failed(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The X-BSV-Payment-Derivation-Prefix header is not valid.",
        ),
        PaymentDecision::ReplayedPrefix => signed_failed(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The X-BSV-Payment-Derivation-Prefix header is not valid (already used).",
        ),
        PaymentDecision::PrefixUsedByAnotherTransaction => signed_failed(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The derivation prefix was already used by another transaction (BRC-105: each prefix pays once). Nothing was internalized; request a fresh challenge.",
        ),
        PaymentDecision::PrefixStoreUnavailable { detail } => {
            warn_log(&format!("payment prefix store unavailable: {detail}"));
            let (status, body, headers) = payment_unavailable_response();
            Ok(PaymentResult::Failed(sign_json_response(&body, status, &headers, session)?))
        }
        PaymentDecision::WalletRejected {
            price,
            fresh_prefix,
        } => {
            let response = sign_json_response(
                &ErrorResponse::new(
                    "ERR_PAYMENT_FAILED",
                    "The BSV payment was not accepted by the wallet. A fresh payment challenge is provided in the response headers.",
                ),
                402,
                &challenge_header_pairs(price, &fresh_prefix),
                session,
            )?;
            Ok(PaymentResult::Failed(response))
        }
        PaymentDecision::InternalizeError { description } => {
            signed_failed(400, "ERR_PAYMENT_FAILED", &description)
        }
        PaymentDecision::NotCovered { description } => {
            let text = not_covered_description(&description);
            signed_failed(400, "ERR_INVALID_PAYMENT", &text)
        }
        PaymentDecision::InvalidPayment { description } => {
            signed_failed(400, "ERR_INVALID_PAYMENT", &description)
        }
        PaymentDecision::ServerFault { description } => {
            signed_failed(500, "ERR_SERVER_MISCONFIGURED", &description)
        }
        PaymentDecision::HeaderServiceUnavailable { description } => {
            let (status, code) = HEADER_SERVICE_UNAVAILABLE;
            signed_failed(
                status,
                code,
                &header_service_unavailable_description(&description),
            )
        }
        PaymentDecision::Verified { satoshis_paid, tx } => {
            Ok(PaymentResult::Verified(PaymentContext {
                satoshis_paid,
                accepted: true,
                tx: Some(tx),
            }))
        }
    }
}

/// Shared wire response for stock and fleet claim-store failures.
pub(crate) fn payment_unavailable_response() -> (u16, serde_json::Value, Vec<(String, String)>) {
    (
        503,
        serde_json::json!({
            "status": "error",
            "code": "ERR_PAYMENT_UNAVAILABLE",
            "description": "Payment processing is temporarily unavailable. Retry the same payment.",
            "retryable": true
        }),
        vec![("Retry-After".into(), "5".into())],
    )
}

/// The 503 body description for a root the header service could not check:
/// nothing was charged, the quote stands, the client retries the SAME
/// payment later (not a corrected one: the payment may well be right).
fn header_service_unavailable_description(detail: &str) -> String {
    format!(
        "{detail}. The server could not check the payment's proof against a block header, so it was not accepted; nothing was charged and the challenge is unchanged. Retry the same payment later under the same derivation prefix."
    )
}

/// The 400 body description for a payment that does not cover the price:
/// the quote stands, so the client is told to retry under the same prefix.
fn not_covered_description(detail: &str) -> String {
    format!(
        "The BSV payment does not pay the required amount to the server ({detail}). The payment challenge is unchanged: correct the payment and retry with the same derivation prefix."
    )
}

/// [`challenge_headers`] as owned pairs — the shape [`sign_json_response`]
/// takes (and signs: `x-bsv-payment-*` headers are in the signable set).
fn challenge_header_pairs(price: u64, derivation_prefix: &str) -> Vec<(String, String)> {
    vec![
        (
            payment_headers::VERSION.to_string(),
            PAYMENT_VERSION.to_string(),
        ),
        (
            payment_headers::SATOSHIS_REQUIRED.to_string(),
            price.to_string(),
        ),
        (
            payment_headers::DERIVATION_PREFIX.to_string(),
            derivation_prefix.to_string(),
        ),
        (
            payment_headers::TRANSPORTS.to_string(),
            "header,multipart".to_string(),
        ),
    ]
}

/// The BRC-29 payment-challenge header set (402 responses, both the
/// no-payment challenge and the wallet-rejected fresh challenge).
fn challenge_headers(price: u64, derivation_prefix: &str) -> Headers {
    let h = Headers::new();
    let _ = h.set(payment_headers::VERSION, PAYMENT_VERSION);
    let _ = h.set(payment_headers::SATOSHIS_REQUIRED, &price.to_string());
    let _ = h.set(payment_headers::DERIVATION_PREFIX, derivation_prefix);
    let _ = h.set(payment_headers::TRANSPORTS, "header,multipart");
    h
}

/// `PaymentResult::Failed` with the standard `ErrorResponse` JSON body.
fn failed_json_response(status: u16, code: &str, description: &str) -> Result<PaymentResult> {
    let response = Response::from_json(&ErrorResponse::new(code, description))
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_status(status);
    Ok(PaymentResult::Failed(add_cors_headers(response)))
}

/// Warn on the Workers console; no-op under native `cargo test` (the
/// `console_*` macros call wasm-bindgen imports that panic off-WASM, and
/// the decision core executes natively in tests).
fn warn_log(message: &str) {
    #[cfg(target_arch = "wasm32")]
    worker::console_warn!("{}", message);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = message;
}

/// Wallet-communication phase of payment processing.
///
/// Creates a BRC-103/104 session with the storage server on first RPC call.
/// Sequence: makeAvailable → findOrInsertUser → internalizeAction (matches
/// wallet-toolbox StorageClient initialization pattern). Any failure here is
/// the equivalent of the TS reference's `catch` around
/// `wallet.internalizeAction(...)` and maps to a 400 `ERR_PAYMENT_FAILED`
/// (after releasing the consumed prefix).
///
/// The server identity is derived from `options.server_private_key` — the
/// same key the decision core's nonce wallet uses.
async fn internalize_payment<F>(
    options: &PaymentMiddlewareOptions<F>,
    auth_context: &AuthContext,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: Vec<u8>,
) -> Result<serde_json::Value> {
    let storage_wallet = ProtoWallet::new(Some(
        PrivateKey::from_hex(&options.server_private_key).map_err(|e| {
            AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
        })?,
    ));
    let server_identity = storage_wallet.identity_key().to_hex();
    let mut storage_client = WorkerStorageClient::new(storage_wallet, &options.storage_url);

    // Initialize connection and register user
    storage_client.make_available().await?;
    let user_result: serde_json::Value =
        storage_client.find_or_insert_user(&server_identity).await?;
    let user_id = user_result.get("userId").and_then(|v| v.as_i64());

    let auth_json = serde_json::json!({
        "identityKey": server_identity,
        "userId": user_id
    });
    // Express equivalent:
    //   const { accepted } = await wallet.internalizeAction({
    //     tx: Utils.toArray(paymentData.transaction, 'base64'),
    //     outputs: [{ paymentRemittance: { derivationPrefix, derivationSuffix, senderIdentityKey }, outputIndex: 0, protocol: 'wallet payment' }],
    //     description: 'Payment for request'
    //   })
    let args_json = internalize_args(
        &tx_bytes,
        derivation_prefix,
        derivation_suffix,
        &auth_context.identity_key,
        options.labels.as_ref(),
    );

    storage_client
        .internalize_action(auth_json, args_json)
        .await
}

/// The `internalizeAction` args for a verified payment — pure so the wire
/// shape (incl. the labels key) is unit-testable. Labels ride top-level
/// (the shape wallet storage persists and `listActions({labels})` filters
/// on); `None` omits the key entirely (bit-compatible pre-labels shape).
fn internalize_args(
    tx_bytes: &[u8],
    derivation_prefix: &str,
    derivation_suffix: &str,
    sender_identity_key: &str,
    labels: Option<&Vec<String>>,
) -> serde_json::Value {
    let mut args = serde_json::json!({
        "tx": tx_bytes,
        "outputs": [{
            "outputIndex": PAYMENT_OUTPUT_INDEX,
            "protocol": "wallet payment",
            "paymentRemittance": {
                "derivationPrefix": derivation_prefix,
                "derivationSuffix": derivation_suffix,
                "senderIdentityKey": sender_identity_key
            },
            "insertionRemittance": null
        }],
        "description": "Payment for request"
    });
    if let Some(labels) = labels {
        args["labels"] = serde_json::json!(labels);
    }
    args
}

/// Whether an `internalizeAction` response affirmatively accepted the payment.
///
/// Only a literal `"accepted": true` counts; missing or non-boolean values
/// are treated as rejected (never fail open on the money path). The TS
/// reference performs no such gate at all — see
/// [`process_payment_with_storage`] for the divergence note.
fn internalize_accepted(result: &serde_json::Value) -> bool {
    result
        .get("accepted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Add payment success headers to response.
///
/// Express equivalent: `res.set({ 'x-bsv-payment-satoshis-paid': String(requestPrice) })`
pub fn add_payment_headers(response: Response, payment: &PaymentContext) -> Response {
    let headers = Headers::new();
    let _ = headers.set(
        payment_headers::SATOSHIS_PAID,
        &payment.satoshis_paid.to_string(),
    );
    response.with_headers(headers)
}

/// Creates a payment failed response.
pub fn payment_failed_response(error: &str) -> worker::Result<Response> {
    let response =
        Response::from_json(&ErrorResponse::new("ERR_PAYMENT_FAILED", error))?.with_status(400);
    Ok(add_cors_headers(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_sdk::primitives::PrivateKey;

    const TEST_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    // ===========================================
    // Labels hook + internalize args wire shape
    // ===========================================

    #[test]
    fn internalize_args_without_labels_omits_the_key_entirely() {
        let args = internalize_args(&[1u8, 2, 3], "prefix-b64", "suffix-b64", "02abc", None);
        assert!(
            args.get("labels").is_none(),
            "labels key must be absent, not null"
        );
        let pr = &args["outputs"][0]["paymentRemittance"];
        assert_eq!(pr["derivationPrefix"], "prefix-b64");
        assert_eq!(pr["derivationSuffix"], "suffix-b64");
        assert_eq!(pr["senderIdentityKey"], "02abc");
        assert_eq!(args["outputs"][0]["protocol"], "wallet payment");
        assert_eq!(args["description"], "Payment for request");
    }

    #[test]
    fn internalize_args_with_labels_rides_them_top_level() {
        let labels = vec!["beacon read-fee".to_string()];
        let args = internalize_args(&[1u8], "p", "s", "02abc", Some(&labels));
        assert_eq!(args["labels"], serde_json::json!(["beacon read-fee"]));
    }

    #[test]
    fn with_labels_builder_sets_labels_and_defaults_are_none() {
        let opts = PaymentMiddlewareOptions::new("key".to_string(), |_req: &Request| 1u64);
        assert!(
            opts.labels.is_none(),
            "labels default to None (pre-labels wire shape)"
        );
        let opts = opts.with_labels(vec!["beacon donation".to_string()]);
        assert_eq!(
            opts.labels.as_deref(),
            Some(&["beacon donation".to_string()][..])
        );
    }

    // ===========================================
    // Payment header constant tests
    // ===========================================

    #[test]
    fn test_payment_header_constants() {
        // Verify header names match BRC-29 spec exactly
        assert_eq!(payment_headers::PAYMENT, "x-bsv-payment");
        assert_eq!(payment_headers::VERSION, "x-bsv-payment-version");
        assert_eq!(
            payment_headers::SATOSHIS_REQUIRED,
            "x-bsv-payment-satoshis-required"
        );
        assert_eq!(
            payment_headers::DERIVATION_PREFIX,
            "x-bsv-payment-derivation-prefix"
        );
        assert_eq!(
            payment_headers::SATOSHIS_PAID,
            "x-bsv-payment-satoshis-paid"
        );
    }

    #[test]
    fn test_payment_version() {
        assert_eq!(PAYMENT_VERSION, "1.0");
    }

    // ===========================================
    // HMAC nonce tests (stateless derivation prefix)
    // ===========================================

    #[tokio::test]
    async fn test_create_and_verify_nonce() {
        let pk = PrivateKey::from_hex(TEST_KEY_HEX).unwrap();
        let wallet = ProtoWallet::new(Some(pk));

        // Create a nonce (derivation prefix)
        let nonce = create_nonce(&wallet, None, ORIGINATOR).await.unwrap();
        assert!(!nonce.is_empty(), "Nonce should not be empty");

        // Verify the nonce - should succeed
        let valid = verify_nonce(&nonce, &wallet, None, ORIGINATOR)
            .await
            .unwrap();
        assert!(valid, "Valid nonce should verify");
    }

    #[tokio::test]
    async fn test_nonce_verification_fails_for_different_key() {
        let pk1 = PrivateKey::from_hex(TEST_KEY_HEX).unwrap();
        let wallet1 = ProtoWallet::new(Some(pk1));

        let pk2 = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let wallet2 = ProtoWallet::new(Some(pk2));

        // Create with wallet1
        let nonce = create_nonce(&wallet1, None, ORIGINATOR).await.unwrap();

        // Verify with wallet2 - should fail
        let valid = verify_nonce(&nonce, &wallet2, None, ORIGINATOR)
            .await
            .unwrap();
        assert!(!valid, "Nonce created with different key should not verify");
    }

    #[tokio::test]
    async fn test_nonce_verification_fails_for_tampered_nonce() {
        let pk = PrivateKey::from_hex(TEST_KEY_HEX).unwrap();
        let wallet = ProtoWallet::new(Some(pk));

        let nonce = create_nonce(&wallet, None, ORIGINATOR).await.unwrap();

        // Tamper with the nonce — with a byte that DIFFERS from the original's
        // first (a fixed "x" equalled the original one run in sixty-four: the
        // 2026-09-14 flake, "zero flakiness is a bug").
        let first = nonce.as_bytes()[0] as char;
        let tampered = format!("{}{}", if first == 'x' { 'y' } else { 'x' }, &nonce[1..]);

        let valid = verify_nonce(&tampered, &wallet, None, ORIGINATOR)
            .await
            .unwrap_or(false);
        assert!(!valid, "Tampered nonce should not verify");
    }

    #[tokio::test]
    async fn test_nonce_uniqueness() {
        let pk = PrivateKey::from_hex(TEST_KEY_HEX).unwrap();
        let wallet = ProtoWallet::new(Some(pk));

        let nonce1 = create_nonce(&wallet, None, ORIGINATOR).await.unwrap();
        let nonce2 = create_nonce(&wallet, None, ORIGINATOR).await.unwrap();

        assert_ne!(nonce1, nonce2, "Each nonce should be unique");

        // Both should still verify
        let valid1 = verify_nonce(&nonce1, &wallet, None, ORIGINATOR)
            .await
            .unwrap();
        let valid2 = verify_nonce(&nonce2, &wallet, None, ORIGINATOR)
            .await
            .unwrap();
        assert!(valid1 && valid2, "Both nonces should verify");
    }

    // ===========================================
    // accepted-gate tests (audit #44)
    // ===========================================
    // The TS reference (payment-express-middleware 1.2.3) proceeds to next()
    // regardless of `accepted`. We gate: only a literal `accepted: true`
    // counts, and anything else is a rejected payment.

    #[test]
    fn test_internalize_accepted_true() {
        let result = serde_json::json!({ "accepted": true, "satoshisPaid": 100 });
        assert!(internalize_accepted(&result));
    }

    #[test]
    fn test_internalize_accepted_false_is_rejected() {
        let result = serde_json::json!({ "accepted": false });
        assert!(
            !internalize_accepted(&result),
            "accepted=false must NOT be treated as success (audit #44)"
        );
    }

    #[test]
    fn test_internalize_accepted_missing_is_rejected() {
        let result = serde_json::json!({ "satoshisPaid": 100 });
        assert!(
            !internalize_accepted(&result),
            "missing accepted field must fail closed"
        );
    }

    #[test]
    fn test_internalize_accepted_non_bool_is_rejected() {
        for v in [
            serde_json::json!({ "accepted": "true" }),
            serde_json::json!({ "accepted": 1 }),
            serde_json::json!({ "accepted": null }),
        ] {
            assert!(
                !internalize_accepted(&v),
                "non-boolean accepted must fail closed: {v}"
            );
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_payment_nonce_scope_constant() {
        // Consumed derivation prefixes are recorded under this scope in the
        // SessionStorage nonce store; changing it orphans consumption records.
        assert_eq!(PAYMENT_NONCE_SCOPE, "payment-derivation-prefix");
    }

    // ===========================================
    // BsvPayment deserialization tests
    // ===========================================

    #[test]
    fn test_bsv_payment_deserialization() {
        let json = r#"{
            "derivationPrefix": "test-prefix",
            "derivationSuffix": "test-suffix",
            "transaction": "AQAAAA=="
        }"#;

        let payment: BsvPayment = serde_json::from_str(json).unwrap();
        assert_eq!(payment.derivation_prefix, "test-prefix");
        assert_eq!(payment.derivation_suffix, "test-suffix");
        assert_eq!(payment.transaction, "AQAAAA==");
    }

    #[test]
    fn test_bsv_payment_camel_case() {
        // Verify camelCase deserialization matches Express's JSON.parse()
        let json = r#"{"derivationPrefix":"p","derivationSuffix":"s","transaction":"dHg="}"#;
        let payment: BsvPayment = serde_json::from_str(json).unwrap();
        assert_eq!(payment.derivation_prefix, "p");
        assert_eq!(payment.derivation_suffix, "s");
        assert_eq!(payment.transaction, "dHg=");
    }

    #[test]
    fn test_bsv_payment_missing_field_fails() {
        let json = r#"{"derivationPrefix":"p","derivationSuffix":"s"}"#;
        let result: std::result::Result<BsvPayment, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Missing transaction field should fail");
    }

    #[test]
    fn test_bsv_payment_invalid_json_fails() {
        let result: std::result::Result<BsvPayment, _> = serde_json::from_str("not json");
        assert!(result.is_err(), "Invalid JSON should fail");
    }

    // ===========================================
    // PaymentContext tests
    // ===========================================

    #[test]
    fn test_payment_context_with_tx() {
        let ctx = PaymentContext {
            satoshis_paid: 500,
            accepted: true,
            tx: Some("base64tx".to_string()),
        };
        assert_eq!(ctx.satoshis_paid, 500);
        assert!(ctx.accepted);
        assert_eq!(ctx.tx.as_deref(), Some("base64tx"));
    }

    #[test]
    fn test_payment_context_free() {
        let ctx = PaymentContext {
            satoshis_paid: 0,
            accepted: true,
            tx: None,
        };
        assert_eq!(ctx.satoshis_paid, 0);
        assert!(ctx.tx.is_none());
    }

    // ===========================================
    // ErrorResponse tests
    // ===========================================

    #[test]
    fn test_error_response_serialization() {
        let err = ErrorResponse::new("ERR_PAYMENT_REQUIRED", "Payment needed");
        let json = serde_json::to_string(&err).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["code"], "ERR_PAYMENT_REQUIRED");
        assert_eq!(parsed["description"], "Payment needed");
    }

    #[test]
    fn test_error_response_matches_express_format() {
        // Express returns: { status: 'error', code: '...', description: '...' }
        let err = ErrorResponse::new("ERR_MALFORMED_PAYMENT", "Bad JSON");
        let json = serde_json::to_string(&err).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Must have exactly these fields (matching Express)
        assert!(parsed.get("status").is_some());
        assert!(parsed.get("code").is_some());
        assert!(parsed.get("description").is_some());
    }

    // ===========================================
    // PaymentMiddlewareOptions tests
    // ===========================================

    #[test]
    fn test_payment_middleware_options_construction() {
        let opts = PaymentMiddlewareOptions::new("key".to_string(), |_req: &Request| 100u64);
        assert_eq!(opts.server_private_key, "key");
        assert_eq!(opts.storage_url, WorkerStorageClient::MAINNET_URL);
    }

    #[test]
    fn test_payment_middleware_options_custom_storage_url() {
        let opts = PaymentMiddlewareOptions::with_storage_url(
            "key".to_string(),
            |_req: &Request| 100u64,
            "https://custom-storage.example.com".to_string(),
        );
        assert_eq!(opts.storage_url, "https://custom-storage.example.com");
    }

    // ===========================================
    // Executed money-path tests (audit finding #62)
    // ===========================================
    // `decide_payment` is the whole payment decision path over plain data
    // (no worker::Request/Response, which only exist on a live Workers
    // runtime), so these tests EXECUTE the ordering that matters on the
    // money path — consume-before-internalize, replay rejection, release
    // on wallet error, keep-consumed on wallet rejection, fail-closed on
    // storage faults — instead of only covering pure helpers (#29 lesson).

    // ===========================================
    // The six words on the paying output
    // ===========================================
    //
    // `judge_paying_output` is this path's one match over the core's
    // answer. The output check gives three of the six words today; the
    // table pins all six (and the faults), so the path's answer to a proof
    // step is settled before one exists.
    mod judge {
        use super::*;

        fn covered(judgement: OutputJudgement) -> u64 {
            match judgement {
                OutputJudgement::Covered { satoshis_paid } => satoshis_paid,
                other => panic!("expected Covered, got {other:?}"),
            }
        }

        #[test]
        fn verified_serves_the_amount_read() {
            let j = judge_paying_output(Ok(PaymentVerdict::Verified { satoshis: 501 }));
            assert_eq!(covered(j), 501);
        }

        #[test]
        fn underpaid_and_wrong_script_are_refused_with_the_quote_kept() {
            let j = judge_paying_output(Ok(PaymentVerdict::Underpaid {
                paid: 499,
                required: 500,
            }));
            assert!(
                matches!(&j, OutputJudgement::NotCovered { description }
                    if description.contains("carries 499 satoshis but 500 are required")),
                "{j:?}"
            );
            let j = judge_paying_output(Ok(PaymentVerdict::WrongScript {
                expected: "aa".into(),
                actual: "bb".into(),
            }));
            assert!(
                matches!(&j, OutputJudgement::NotCovered { description }
                    if description.contains("does not pay this server's BRC-29 derived key")),
                "{j:?}"
            );
        }

        #[test]
        fn no_header_service_is_the_servers_own_fault() {
            let j = judge_paying_output(Ok(PaymentVerdict::NoHeaderService));
            assert!(
                matches!(&j, OutputJudgement::ServerFault { description }
                    if description.contains("header service")),
                "{j:?}"
            );
        }

        #[test]
        fn root_mismatch_is_refused_without_a_fresh_challenge() {
            let j = judge_paying_output(Ok(PaymentVerdict::RootMismatch {
                height: 42,
                root: "ab".into(),
            }));
            assert!(
                matches!(&j, OutputJudgement::Invalid { description }
                    if description.contains("height 42")),
                "{j:?}"
            );
        }

        /// Fail-closed (0.4.0): a root the header service could not check
        /// is never served. It is the server's transient condition, so the
        /// answer is a 503 of its own (not the 500 of a missing service, not
        /// a 400 blaming the client), the quote kept for a retry of the same
        /// payment.
        #[test]
        fn unverifiable_is_refused_as_header_service_unavailable_with_the_quote_kept() {
            let j = judge_paying_output(Ok(PaymentVerdict::Unverifiable {
                reason: UnverifiableReason::HeaderLookupFailed {
                    height: 7,
                    reason: "HTTP 503".into(),
                },
            }));
            assert!(
                matches!(&j, OutputJudgement::HeaderServiceUnavailable { description }
                    if description.contains("HTTP 503") && description.contains("height 7")),
                "{j:?}"
            );
            assert_eq!(
                HEADER_SERVICE_UNAVAILABLE,
                (503, "ERR_HEADER_SERVICE_UNAVAILABLE")
            );
            let body = header_service_unavailable_description("detail");
            assert!(
                body.starts_with("detail.")
                    && body.contains("nothing was charged")
                    && body.contains("same derivation prefix"),
                "{body}"
            );
        }

        /// The payer's side of `Unverifiable` (0.5.0, the no-root ruling of
        /// 2026-10-09): unreadable bytes, no such output, invalid BEEF, a
        /// refused spend, no proof. A 400 with the quote kept, never the 503
        /// of the server's own outage.
        #[test]
        fn payer_side_unverifiable_is_an_invalid_payment_with_the_quote_kept() {
            for reason in [
                UnverifiableReason::MalformedTransaction("x".into()),
                UnverifiableReason::OutputMissing {
                    output_index: 0,
                    output_count: 0,
                },
                UnverifiableReason::KeyDerivation("sender".into()),
                UnverifiableReason::InvalidBeef {
                    offset: 12,
                    kind: "InputNamesNoElement".into(),
                    reason: "x".into(),
                },
                UnverifiableReason::SpendRefused {
                    offset: 40,
                    txid: "ab".into(),
                    input: Some(0),
                    why: "Script".into(),
                },
                UnverifiableReason::NoProof { txid: "ab".into() },
                UnverifiableReason::NoTransaction,
            ] {
                let verdict = PaymentVerdict::Unverifiable { reason };
                let text = verdict.to_string();
                let j = judge_paying_output(Ok(verdict));
                assert!(
                    matches!(&j, OutputJudgement::Invalid { description } if *description == text),
                    "{j:?}"
                );
            }
        }

        /// A fault is the server's own (0.5.0): its key does not derive.
        #[test]
        fn every_fault_is_the_servers_own() {
            for fault in [
                PaymentFault::KeyDerivation("x".into()),
                PaymentFault::Source("x".into()),
            ] {
                let text = fault.to_string();
                let j = judge_paying_output(Err(fault));
                assert!(
                    matches!(&j, OutputJudgement::ServerFault { description } if *description == text),
                    "{j:?}"
                );
            }
        }
    }

    mod decide {
        use super::*;
        use bsv_middleware_core::{MemoryStore, StoreError};

        #[derive(Default)]
        struct TestPrefixes {
            inner: MemoryStore,
            held: std::cell::RefCell<std::collections::HashSet<String>>,
            fail_release: std::cell::Cell<bool>,
        }
        impl TestPrefixes {
            fn is_consumed(&self, prefix: &str) -> bool {
                self.held.borrow().contains(prefix)
            }
            fn consumed_count(&self) -> usize {
                self.held.borrow().len()
            }
            fn fail_consume(&self, fail: bool) {
                self.inner.fail(fail);
            }
            fn fail_release(&self, fail: bool) {
                self.fail_release.set(fail);
            }
        }
        impl PaymentPrefixStore for TestPrefixes {
            async fn claim_prefix(
                &self,
                prefix: &str,
                txid: &str,
                agent: &str,
            ) -> std::result::Result<PrefixClaim, StoreError> {
                let result = self.inner.claim_prefix(prefix, txid, agent).await?;
                if result == PrefixClaim::Won {
                    self.held.borrow_mut().insert(prefix.to_string());
                }
                Ok(result)
            }
            async fn release_prefix(
                &self,
                prefix: &str,
                txid: &str,
            ) -> std::result::Result<(), StoreError> {
                if self.fail_release.get() {
                    return Err(StoreError::new("release fault"));
                }
                self.inner.release_prefix(prefix, txid).await?;
                self.held.borrow_mut().remove(prefix);
                Ok(())
            }
        }
        use crate::types::AuthContext;

        /// The paying client's identity key: 2·G, a point on the curve
        /// (the BRC-29 derivation needs one).
        const CLIENT_IDENTITY: &str =
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        const PRICE: u64 = 500;

        fn server_wallet() -> ProtoWallet {
            ProtoWallet::new(Some(PrivateKey::from_hex(TEST_KEY_HEX).unwrap()))
        }

        fn auth() -> AuthContext {
            AuthContext::authenticated(CLIENT_IDENTITY.to_string())
        }

        /// A server-issued 402 challenge prefix, exactly as `Challenge`
        /// (and the deployed 402 builders) would hand to a client.
        async fn issued_prefix() -> String {
            create_nonce(&server_wallet(), None, ORIGINATOR)
                .await
                .unwrap()
        }

        /// A payment of exactly the price to the server's derived key.
        fn header_for(prefix: &str) -> Option<String> {
            header_paying(prefix, &[(PRICE, derived_script(prefix))])
        }

        fn other_transaction(prefix: &str) -> Option<String> {
            header_paying(prefix, &[(PRICE + 1, derived_script(prefix))])
        }

        #[tokio::test]
        async fn a_prefix_reused_with_a_new_transaction_is_refused_before_the_wallet() {
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let first = header_for(&prefix);
            let second = other_transaction(&prefix);
            let txid = |header: &Option<String>| {
                let payment: BsvPayment = serde_json::from_str(header.as_ref().unwrap()).unwrap();
                payment_subject_txid(&from_base64(&payment.transaction).unwrap()).unwrap()
            };
            assert_ne!(txid(&first), txid(&second));
            let calls = std::cell::Cell::new(0);
            let wallet = |_, _, _| {
                calls.set(calls.get() + 1);
                async { Ok(serde_json::json!({ "accepted": true })) }
            };
            let first = decide_payment(&auth(), || PRICE, first, TEST_KEY_HEX, &store, wallet)
                .await
                .unwrap();
            assert!(matches!(first, PaymentDecision::Verified { .. }));
            let second = decide_payment(&auth(), || PRICE, second, TEST_KEY_HEX, &store, wallet)
                .await
                .unwrap();
            assert_eq!(second, PaymentDecision::PrefixUsedByAnotherTransaction);
            assert_eq!(calls.get(), 1);
        }

        fn exact_payment_b64(prefix: &str) -> String {
            crafted_payment_b64(&[(PRICE, derived_script(prefix))])
        }

        /// Internalizer for paths that must reject BEFORE the wallet.
        async fn wallet_unreachable(
            _prefix: String,
            _suffix: String,
            _tx: Vec<u8>,
        ) -> Result<serde_json::Value> {
            panic!("internalizeAction must not be reached on this path");
        }

        async fn wallet_accepts(
            _prefix: String,
            _suffix: String,
            _tx: Vec<u8>,
        ) -> Result<serde_json::Value> {
            Ok(serde_json::json!({ "accepted": true }))
        }

        async fn wallet_rejects(
            _prefix: String,
            _suffix: String,
            _tx: Vec<u8>,
        ) -> Result<serde_json::Value> {
            Ok(serde_json::json!({ "accepted": false }))
        }

        async fn wallet_errors(
            _prefix: String,
            _suffix: String,
            _tx: Vec<u8>,
        ) -> Result<serde_json::Value> {
            Err(AuthCloudflareError::TransportError("wallet down".into()))
        }

        #[tokio::test]
        async fn misconfigured_auth_rejects_before_price_calculation() {
            // Express errors on missing req.auth BEFORE calling
            // calculateRequestPrice — the panicking closure pins the order.
            for ctx in [
                AuthContext::unauthenticated(),
                AuthContext {
                    identity_key: "unknown".to_string(),
                    is_authenticated: true,
                },
            ] {
                let decision = decide_payment(
                    &ctx,
                    || -> u64 { panic!("price must not be calculated without auth") },
                    None,
                    TEST_KEY_HEX,
                    &TestPrefixes::default(),
                    wallet_unreachable,
                )
                .await
                .unwrap();
                assert_eq!(decision, PaymentDecision::Misconfigured);
            }
        }

        #[tokio::test]
        async fn price_zero_is_free_before_header_inspection() {
            // Express short-circuits on requestPrice === 0 before ever
            // reading x-bsv-payment — even a garbage header passes.
            let store = TestPrefixes::default();
            let decision = decide_payment(
                &auth(),
                || 0,
                Some("garbage, never parsed".to_string()),
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(decision, PaymentDecision::Free);
            assert_eq!(store.consumed_count(), 0);
        }

        #[tokio::test]
        async fn missing_header_yields_verifiable_challenge() {
            let store = TestPrefixes::default();
            let decision = decide_payment(
                &auth(),
                || PRICE,
                None,
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap();
            match decision {
                PaymentDecision::Challenge {
                    price,
                    derivation_prefix,
                } => {
                    assert_eq!(price, PRICE);
                    let valid =
                        verify_nonce(&derivation_prefix, &server_wallet(), None, ORIGINATOR)
                            .await
                            .unwrap();
                    assert!(valid, "issued challenge prefix must verify");
                }
                other => panic!("expected Challenge, got {other:?}"),
            }
            // Challenges are consumed at redemption, not issuance.
            assert_eq!(store.consumed_count(), 0);
        }

        #[tokio::test]
        async fn malformed_header_rejected_without_store_writes() {
            let store = TestPrefixes::default();
            let decision = decide_payment(
                &auth(),
                || PRICE,
                Some("not json".to_string()),
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(decision, PaymentDecision::MalformedHeader);
            assert_eq!(store.consumed_count(), 0);
        }

        #[tokio::test]
        async fn foreign_prefix_fails_hmac_before_store_and_wallet() {
            let store = TestPrefixes::default();
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for("bm90LWEtcmVhbC1ub25jZQ=="),
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(decision, PaymentDecision::InvalidPrefix);
            assert_eq!(store.consumed_count(), 0);
        }

        #[tokio::test]
        async fn bad_base64_tx_errs_without_burning_the_prefix() {
            // Decode happens BEFORE consumption: a malformed payload must
            // not burn the client's one-shot derivation prefix.
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let header = serde_json::json!({
                "derivationPrefix": prefix,
                "derivationSuffix": "c3VmZml4",
                "transaction": "!!!not-base64!!!",
            })
            .to_string();
            let err = decide_payment(
                &auth(),
                || PRICE,
                Some(header),
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, AuthCloudflareError::MalformedPayment(_)),
                "expected MalformedPayment, got {err:?}"
            );
            assert!(
                !store.is_consumed(&prefix),
                "prefix must survive a malformed transaction payload"
            );
        }

        #[tokio::test]
        async fn prefix_is_consumed_before_the_wallet_is_called() {
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let wallet_called = std::cell::Cell::new(false);
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                &store,
                |seen_prefix: String, seen_suffix: String, tx: Vec<u8>| {
                    wallet_called.set(true);
                    assert_eq!(seen_prefix, prefix);
                    assert_eq!(seen_suffix, "c3VmZml4");
                    assert_eq!(
                        tx,
                        from_base64(&exact_payment_b64(&prefix)).unwrap(),
                        "decoded base64 of the payment"
                    );
                    assert!(
                        store.is_consumed(&prefix),
                        "prefix must already be consumed when internalize runs \
                         (concurrent duplicates must not both reach the wallet)"
                    );
                    async { Ok(serde_json::json!({ "accepted": true })) }
                },
            )
            .await
            .unwrap();
            assert!(wallet_called.get(), "accepting path must reach the wallet");
            assert_eq!(
                decision,
                PaymentDecision::Verified {
                    satoshis_paid: PRICE,
                    tx: exact_payment_b64(&prefix)
                }
            );
        }

        #[tokio::test]
        async fn redeemed_header_replay_is_rejected_before_the_wallet() {
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let first = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                &store,
                wallet_accepts,
            )
            .await
            .unwrap();
            assert!(matches!(first, PaymentDecision::Verified { .. }));

            // Byte-identical replay of the captured X-BSV-Payment header:
            // rejected pre-wallet (the shim's stateless path deferred this
            // to the upstream wallet's duplicate handling — issue #44).
            let replay = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(replay, PaymentDecision::ReplayedPrefix);
        }

        #[tokio::test]
        async fn wallet_rejection_keeps_prefix_consumed_and_issues_fresh_challenge() {
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                &store,
                wallet_rejects,
            )
            .await
            .unwrap();
            match decision {
                PaymentDecision::WalletRejected {
                    price,
                    fresh_prefix,
                } => {
                    assert_eq!(price, PRICE);
                    assert_ne!(fresh_prefix, prefix, "challenge must be fresh");
                    let valid = verify_nonce(&fresh_prefix, &server_wallet(), None, ORIGINATOR)
                        .await
                        .unwrap();
                    assert!(valid, "fresh challenge prefix must verify");
                }
                other => panic!("expected WalletRejected, got {other:?}"),
            }
            assert!(
                store.is_consumed(&prefix),
                "a wallet-REJECTED payment's prefix stays consumed"
            );

            // Retrying the rejected payment replays a consumed prefix.
            let retry = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(retry, PaymentDecision::ReplayedPrefix);
            let other = decide_payment(
                &auth(),
                || PRICE,
                other_transaction(&prefix),
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(other, PaymentDecision::PrefixUsedByAnotherTransaction);
        }

        #[tokio::test]
        async fn missing_accepted_field_fails_closed_end_to_end() {
            // internalize_accepted's fail-closed contract, executed through
            // the full decision path: no `accepted: true`, no Verified.
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                &store,
                |_p: String, _s: String, _t: Vec<u8>| async {
                    Ok(serde_json::json!({ "satoshisPaid": PRICE }))
                },
            )
            .await
            .unwrap();
            assert!(matches!(decision, PaymentDecision::WalletRejected { .. }));
        }

        #[tokio::test]
        async fn an_internalize_error_releases_the_prefix_to_its_own_transaction_only() {
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let calls = std::cell::Cell::new(0);
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                &store,
                |p, s, t| {
                    calls.set(calls.get() + 1);
                    wallet_errors(p, s, t)
                },
            )
            .await
            .unwrap();
            match decision {
                PaymentDecision::InternalizeError { description } => {
                    assert!(
                        description.contains("wallet down"),
                        "error detail must flow to the 400 body: {description}"
                    );
                }
                other => panic!("expected InternalizeError, got {other:?}"),
            }
            assert!(
                !store.is_consumed(&prefix),
                "prefix released after a wallet ERROR (payment not processed)"
            );

            let other = decide_payment(
                &auth(),
                || PRICE,
                other_transaction(&prefix),
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(other, PaymentDecision::PrefixUsedByAnotherTransaction);
            assert_eq!(
                calls.get(),
                1,
                "refused transaction never reaches the wallet"
            );

            // The honest client retries the SAME real payment and succeeds.
            let retry = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                &store,
                |p, s, t| {
                    calls.set(calls.get() + 1);
                    wallet_accepts(p, s, t)
                },
            )
            .await
            .unwrap();
            assert!(matches!(retry, PaymentDecision::Verified { .. }));
            assert_eq!(calls.get(), 2);
        }

        #[tokio::test]
        async fn release_failure_is_best_effort_error_still_reported() {
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            store.fail_release(true);
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                &store,
                wallet_errors,
            )
            .await
            .unwrap();
            assert!(matches!(decision, PaymentDecision::InternalizeError { .. }));
            assert!(
                store.is_consumed(&prefix),
                "when release fails the prefix stays consumed (client must re-challenge)"
            );
        }

        #[tokio::test]
        async fn store_fault_during_consume_fails_closed() {
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let header = header_for(&prefix);
            let calls = std::cell::Cell::new(0);
            store.fail_consume(true);
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header.clone(),
                TEST_KEY_HEX,
                &store,
                |_, _, _| {
                    calls.set(calls.get() + 1);
                    async { Ok(serde_json::json!({"accepted": true})) }
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                decision,
                PaymentDecision::PrefixStoreUnavailable { .. }
            ));
            let (status, body, headers) = payment_unavailable_response();
            assert_eq!(status, 503);
            assert_eq!(
                body,
                serde_json::json!({
                    "status": "error", "code": "ERR_PAYMENT_UNAVAILABLE",
                    "description": "Payment processing is temporarily unavailable. Retry the same payment.",
                    "retryable": true
                })
            );
            assert_eq!(headers, vec![("Retry-After".into(), "5".into())]);
            assert_eq!(calls.get(), 0);
            assert!(!store.is_consumed(&prefix));
            store.fail_consume(false);
            let retry = decide_payment(
                &auth(),
                || PRICE,
                header,
                TEST_KEY_HEX,
                &store,
                |_, _, _| {
                    calls.set(calls.get() + 1);
                    async { Ok(serde_json::json!({"accepted": true})) }
                },
            )
            .await
            .unwrap();
            assert!(matches!(retry, PaymentDecision::Verified { .. }));
            assert_eq!(calls.get(), 1);
            assert!(store.is_consumed(&prefix));
        }

        // ---- P0-3b: the paying output is compared with the price ----
        //
        // Ported from the P0-3 finding onto the
        // session-lane line, where the check is the crate's own
        // `verify_brc29_payment_output`. Crafted payments only: one input
        // from a crafted parent, never signed, never broadcast; the wallet
        // is a stub that accepts anything well-formed (what the storage
        // servers do, per that report).

        use bsv_sdk::primitives::{to_base64, PublicKey};
        use bsv_sdk::script::LockingScript;
        use bsv_sdk::transaction::{Transaction, TransactionInput, TransactionOutput};
        use bsv_sdk::wallet::{Counterparty, GetPublicKeyArgs, Protocol, SecurityLevel};
        use std::sync::atomic::{AtomicUsize, Ordering};

        const SUFFIX: &str = "c3VmZml4";

        fn p2pkh(hash: &[u8; 20]) -> Vec<u8> {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(hash);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        }

        /// The server's BRC-29 key for (prefix, SUFFIX, the client),
        /// derived here with the SDK, independent of the code under test.
        fn derived_script(prefix: &str) -> Vec<u8> {
            let derived = server_wallet()
                .get_public_key(GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(Protocol::new(SecurityLevel::Counterparty, "3241645161d8")),
                    key_id: Some(format!("{prefix} {SUFFIX}")),
                    counterparty: Some(Counterparty::Other(
                        PublicKey::from_hex(CLIENT_IDENTITY).unwrap(),
                    )),
                    for_self: Some(true),
                })
                .unwrap();
            p2pkh(&PublicKey::from_hex(&derived.public_key).unwrap().hash160())
        }

        /// An Atomic BEEF (the shape a BRC-100 wallet's `createAction`
        /// hands the client) whose subject spends a crafted parent.
        fn crafted_payment_b64(outputs: &[(u64, Vec<u8>)]) -> String {
            let mut parent = Transaction::new();
            parent
                .add_output(TransactionOutput::new(
                    10_000,
                    LockingScript::from_binary(&p2pkh(&[7u8; 20])).unwrap(),
                ))
                .unwrap();
            let mut tx = Transaction::new();
            tx.add_input(TransactionInput::with_source_transaction(parent, 0))
                .unwrap();
            for (satoshis, script) in outputs {
                tx.add_output(TransactionOutput::new(
                    *satoshis,
                    LockingScript::from_binary(script).unwrap(),
                ))
                .unwrap();
            }
            to_base64(&tx.to_atomic_beef(true).unwrap())
        }

        fn header_paying(prefix: &str, outputs: &[(u64, Vec<u8>)]) -> Option<String> {
            Some(
                serde_json::json!({
                    "derivationPrefix": prefix,
                    "derivationSuffix": SUFFIX,
                    "transaction": crafted_payment_b64(outputs),
                })
                .to_string(),
            )
        }

        /// Runs the decision core for one crafted payment against a stub
        /// wallet that accepts; returns the decision and the wallet calls.
        async fn decide_crafted(
            outputs: impl FnOnce(&str) -> Vec<(u64, Vec<u8>)>,
        ) -> (PaymentDecision, usize) {
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let calls = AtomicUsize::new(0);
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_paying(&prefix, &outputs(&prefix)),
                TEST_KEY_HEX,
                &store,
                |_prefix: String, _suffix: String, _tx: Vec<u8>| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(serde_json::json!({ "accepted": true })) }
                },
            )
            .await
            .unwrap();
            (decision, calls.load(Ordering::SeqCst))
        }

        fn satoshis_paid(decision: PaymentDecision) -> u64 {
            match decision_into_result(decision) {
                Ok(PaymentResult::Verified(ctx)) => ctx.satoshis_paid,
                _ => panic!("expected a verified payment"),
            }
        }

        /// A refusal that keeps the quote: the decision carries the reason
        /// and no fresh prefix (none is minted), so the client retries under
        /// the prefix it already holds.
        fn assert_refused_quote_kept(decision: PaymentDecision, detail: &str) {
            match decision {
                PaymentDecision::NotCovered { description } => {
                    assert!(description.contains(detail), "{description}");
                }
                other => panic!("expected NotCovered, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn p0_3b_exact_price_is_served_and_records_the_price() {
            let (decision, calls) = decide_crafted(|p| vec![(PRICE, derived_script(p))]).await;
            assert_eq!(calls, 1);
            assert_eq!(satoshis_paid(decision), PRICE);
        }

        #[tokio::test]
        async fn p0_3b_one_satoshi_under_is_refused_before_the_wallet() {
            let (decision, calls) = decide_crafted(|p| vec![(PRICE - 1, derived_script(p))]).await;
            assert!(
                !matches!(decision, PaymentDecision::Verified { .. }),
                "an underpaid payment was served: {decision:?}"
            );
            assert_eq!(
                calls, 0,
                "the wallet was asked to internalize an underpaid payment"
            );
            assert_refused_quote_kept(decision, "carries 499 satoshis but 500 are required");
        }

        #[tokio::test]
        async fn p0_3b_one_satoshi_over_records_the_real_amount() {
            let (decision, calls) = decide_crafted(|p| vec![(PRICE + 1, derived_script(p))]).await;
            assert_eq!(calls, 1);
            assert_eq!(satoshis_paid(decision), PRICE + 1);
        }

        #[tokio::test]
        async fn p0_3b_output_at_another_script_is_refused_before_the_wallet() {
            let (decision, calls) = decide_crafted(|_| vec![(PRICE, p2pkh(&[9u8; 20]))]).await;
            assert!(
                !matches!(decision, PaymentDecision::Verified { .. }),
                "a payment to another script was served: {decision:?}"
            );
            assert_eq!(
                calls, 0,
                "the wallet was asked to internalize a payment to another script"
            );
            assert_refused_quote_kept(decision, "does not pay this server's BRC-29 derived key");
        }

        #[tokio::test]
        async fn p0_3b_derived_output_at_index_1_does_not_pay_output_0() {
            // Output 0 is what is internalized; paying the derived key at
            // index 1 while output 0 pays someone else is refused.
            let (decision, calls) =
                decide_crafted(|p| vec![(PRICE, p2pkh(&[9u8; 20])), (PRICE, derived_script(p))])
                    .await;
            assert_eq!(calls, 0);
            assert_refused_quote_kept(decision, "does not pay this server's BRC-29 derived key");
        }

        #[tokio::test]
        async fn p0_3b_unreadable_transaction_is_invalid_and_keeps_the_prefix() {
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let header = serde_json::json!({
                "derivationPrefix": prefix,
                "derivationSuffix": SUFFIX,
                "transaction": "AQIDBA==",
            })
            .to_string();
            let decision = decide_payment(
                &auth(),
                || PRICE,
                Some(header),
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert!(
                matches!(decision, PaymentDecision::InvalidPayment { .. }),
                "{decision:?}"
            );
            assert!(!store.is_consumed(&prefix));
        }

        #[tokio::test]
        async fn p0_3b_a_refused_payment_keeps_the_prefix_for_a_correct_retry() {
            let store = TestPrefixes::default();
            let prefix = issued_prefix().await;
            let short = decide_payment(
                &auth(),
                || PRICE,
                header_paying(&prefix, &[(PRICE - 1, derived_script(&prefix))]),
                TEST_KEY_HEX,
                &store,
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert!(
                matches!(short, PaymentDecision::NotCovered { .. }),
                "{short:?}"
            );
            assert!(!store.is_consumed(&prefix));
            let paid = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                &store,
                wallet_accepts,
            )
            .await
            .unwrap();
            assert_eq!(
                paid,
                PaymentDecision::Verified {
                    satoshis_paid: PRICE,
                    tx: exact_payment_b64(&prefix)
                }
            );
        }
    }
}
