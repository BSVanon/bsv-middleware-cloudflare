//! # BSV Auth Cloudflare
//!
//! Authentication and payment middleware for Cloudflare Workers using BSV blockchain.
//!
//! This crate provides BRC-103/104 authentication and BRC-29 payment middleware for
//! Cloudflare Workers, allowing you to build authenticated and paid APIs with
//! BSV blockchain-based identity and payments.
//!
//! ## Shape (0.4.0)
//!
//! The rules (BRC-103/104 message build and verify, BRC-29 derivation and
//! payment verification, the SPV decision through a header-service trait,
//! the single-use store traits, the session lane, refund signing) are
//! [`bsv_middleware_core`], re-exported here as [`core`]. This crate is the
//! Workers adapter: `worker::Request` in, the core's data through, HTTP out;
//! KV, Durable Object and D1 implementations of the core's traits; the
//! URL-configured header service; CORS. Every 0.3 item keeps its name, path
//! and signature.
//!
//! ## Features
//!
//! - **BRC-103/104 Mutual Authentication**: Cryptographic authentication using BSV keys
//! - **BRC-29 Payment Verification**: Accept BSV payments for API access
//! - **Replay Protection**: per-request auth nonces and payment derivation
//!   prefixes are single-use via the pluggable [`SessionStorage`] nonce store
//!   (a hardening divergence from the TS reference middleware — see
//!   [`middleware::auth`] for the precise residual window under Cloudflare KV)
//! - **Payment verification before internalize**: [`verify_brc29_payment`]
//!   checks that a BRC-29 payment output pays this server's derived key the
//!   quoted amount inside a complete BEEF proof, merkle roots against your own
//!   header service (required: no service, no verdict;
//!   [`verify_brc29_payment_structural_only`] is the named opt-out without
//!   SPV), for callers running their own payment flow
//! - **Atomic payment-nonce claims on D1** (feature `d1-claims`):
//!   `claim_payment_nonce` / `release_payment_nonce`, a globally
//!   consistent put-if-absent for callers outside the stock middleware
//! - **Cloudflare KV Storage**: Session and payment storage in Cloudflare KV
//! - **CORS Handling**: Built-in CORS support for browser clients
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use bsv_middleware_cloudflare::{
//!     middleware::{AuthMiddlewareOptions, PaymentMiddlewareOptions, process_auth, process_payment_with_storage, AuthResult, PaymentResult},
//!     KvSessionStorage,
//!     utils::handle_cors_preflight,
//! };
//! use worker::*;
//!
//! #[event(fetch)]
//! pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
//!     // Handle CORS preflight
//!     if req.method() == Method::Options {
//!         return handle_cors_preflight();
//!     }
//!
//!     // Get server key from secrets
//!     let server_key = env.secret("SERVER_PRIVATE_KEY")?.to_string();
//!
//!     // Process authentication
//!     let auth_options = AuthMiddlewareOptions {
//!         server_private_key: server_key.clone(),
//!         allow_unauthenticated: false,
//!         ..Default::default()
//!     };
//!
//!     let auth_result = process_auth(req, &env, &auth_options).await
//!         .map_err(|e| Error::from(e.to_string()))?;
//!
//!     let (auth_context, req, _session, _body) = match auth_result {
//!         AuthResult::Authenticated { context, request, session, body } => (context, request, session, body),
//!         AuthResult::Response(response) => return Ok(response),
//!     };
//!
//!     // Process payment (if needed). The session storage doubles as the
//!     // single-use nonce store that makes payment derivation prefixes
//!     // one-shot (replay protection).
//!     let payment_options = PaymentMiddlewareOptions::new(
//!         server_key,
//!         |_req| 100, // 100 satoshis per request
//!     );
//!     let session_storage = KvSessionStorage::new(env.kv("AUTH_SESSIONS")?, "auth", 3600);
//!
//!     let payment_result = process_payment_with_storage(&req, &auth_context, &payment_options, &session_storage).await
//!         .map_err(|e| Error::from(e.to_string()))?;
//!
//!     match payment_result {
//!         PaymentResult::Free | PaymentResult::Verified(_) => {}
//!         PaymentResult::Required(response) => return Ok(response),
//!         PaymentResult::Failed(response) => return Ok(response),
//!     };
//!
//!     // Handle your business logic here...
//!     Response::from_json(&serde_json::json!({
//!         "message": "Hello!",
//!         "identity": auth_context.identity_key,
//!     }))
//! }
//! ```
//!
//! ## Configuration
//!
//! ### Wrangler Configuration
//!
//! Add the following to your `wrangler.toml`:
//!
//! ```toml
//! [[kv_namespaces]]
//! binding = "AUTH_SESSIONS"
//! id = "your-kv-id-here"
//!
//! [[kv_namespaces]]
//! binding = "PAYMENTS"
//! id = "your-payments-kv-id-here"
//! ```
//!
//! ### Secrets
//!
//! Set the server private key secret:
//!
//! ```bash
//! wrangler secret put SERVER_PRIVATE_KEY
//! ```
//!
//! The secret should be a 64-character hexadecimal string representing a
//! secp256k1 private key.
//!
//! ## BRC Standards
//!
//! This crate implements:
//! - **BRC-103**: Peer-to-peer mutual authentication
//! - **BRC-29**: Direct payment protocol
//! - **BRC-104**: HTTP headers for authenticated requests

pub mod client;
pub mod env;
pub mod error;
pub mod middleware;
#[cfg(feature = "d1-claims")]
pub mod payment_claims;
pub mod payment_verify;
#[cfg(feature = "refund")]
pub mod refund;
pub mod storage;
pub mod transport;
pub mod types;
pub mod utils;

#[cfg(test)]
mod api_surface_tests;

// Re-exports for convenient access
/// The runtime-free rules this crate adapts: `bsv_middleware_core`, as a
/// module, so an adopter can reach the words and the traits without a second
/// dependency line (`bsv_middleware_cloudflare::core::PaymentVerdict`).
pub use bsv_middleware_core as core;
pub use bsv_middleware_core::{
    HeaderService, PaymentFault, PaymentVerdict, UnverifiableReason, VerifiedPayment,
};
pub use client::{ClientSessionSnapshot, WorkerStorageClient};
pub use env::payment_work_limit;
pub use error::{AuthCloudflareError, Result};
pub use middleware::auth::{
    add_cors_headers, add_lane_cors_headers, mint_attested_lane, process_auth, process_auth_do,
    process_auth_lane, process_auth_lane_with_storage, process_auth_with_storage,
    request_presents_lane, seal_lane_response, seal_lane_response_text, sign_json_response,
    sign_response, AuthMiddlewareOptions, AuthResult, AuthSession, LaneAuth, LaneAuthResult,
    SessionLaneOptions,
};
#[allow(deprecated)]
pub use middleware::multipart::{
    prepare_multipart_payment, split_multipart_payment, MultipartPayment, PaymentPart,
};
#[allow(deprecated)] // re-exported for backward compatibility
pub use middleware::payment::process_payment;
pub use middleware::payment::{
    add_payment_headers, payment_headers, process_payment_with_storage,
    process_payment_with_storage_signed, PaymentMiddlewareOptions, PaymentResult,
    PAYMENT_NONCE_SCOPE,
};
pub use middleware::session_lane;
#[cfg(feature = "d1-claims")]
pub use payment_claims::{claim_payment_nonce, release_payment_nonce, PAYMENT_CLAIMS_SCHEMA};
pub use payment_verify::{
    accept_verdict, expected_brc29_locking_script, verify_brc29_payment,
    verify_brc29_payment_budgeted, verify_brc29_payment_output, verify_brc29_payment_source,
    verify_brc29_payment_structural_only, verify_brc29_payment_verdict,
    verify_brc29_payment_verified, verify_brc29_payment_with_header_lookup, PaymentVerifyError,
    UrlHeaderService, DEFAULT_CHAINTRACKS_URL,
};
pub use storage::do_session::{AuthSessionStore, DoSessionStorage};
pub use storage::{
    KvPaymentStorage, KvSessionStorage, LaneVerdict, LaneVerifyAsk, SessionNonceStore,
    SessionStorage,
};
pub use transport::{auth_headers, CloudflareTransport, HttpRequestData, HttpResponseData};
pub use types::{AuthContext, BsvPayment, PaymentContext};

/// Initialize the panic hook for better error messages in WASM.
///
/// Call this at the start of your worker to get better panic messages.
pub fn init_panic_hook() {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}
