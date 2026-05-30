//! # BSV Auth Cloudflare
//!
//! Authentication and payment middleware for Cloudflare Workers using BSV blockchain.
//!
//! This crate provides BRC-103/104 authentication and BRC-29 payment middleware for
//! Cloudflare Workers, allowing you to build authenticated and paid APIs with
//! BSV blockchain-based identity and payments.
//!
//! ## Features
//!
//! - **BRC-103/104 Mutual Authentication**: Cryptographic authentication using BSV keys
//! - **BRC-29 Payment Verification**: Accept BSV payments for API access
//! - **Cloudflare KV Storage**: Session and payment storage in Cloudflare KV
//! - **CORS Handling**: Built-in CORS support for browser clients
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use bsv_middleware_cloudflare::{
//!     middleware::{AuthMiddlewareOptions, PaymentMiddlewareOptions, process_auth, process_payment, AuthResult, PaymentResult},
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
//!     // Process payment (if needed)
//!     let payment_options = PaymentMiddlewareOptions::new(
//!         server_key,
//!         |_req| 100, // 100 satoshis per request
//!     );
//!
//!     let payment_result = process_payment(&req, &auth_context, &payment_options).await
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
#[cfg(feature = "refund")]
pub mod refund;
pub mod storage;
pub mod transport;
pub mod types;
pub mod utils;

// Re-exports for convenient access
pub use client::WorkerStorageClient;
pub use error::{AuthCloudflareError, Result};
pub use middleware::auth::{
    add_cors_headers, process_auth, process_auth_with_storage, sign_json_response, sign_response,
    AuthMiddlewareOptions, AuthResult, AuthSession,
};
pub use middleware::multipart::prepare_multipart_payment;
pub use middleware::payment::{
    add_payment_headers, payment_headers, process_payment, PaymentMiddlewareOptions, PaymentResult,
};
pub use storage::{D1SessionStorage, KvPaymentStorage, KvSessionStorage, SessionStorage};
pub use transport::{auth_headers, CloudflareTransport, HttpRequestData, HttpResponseData};
pub use types::{AuthContext, BsvPayment, PaymentContext};

/// Initialize the panic hook for better error messages in WASM.
///
/// Call this at the start of your worker to get better panic messages.
pub fn init_panic_hook() {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}
