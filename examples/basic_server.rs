//! Basic BSV auth + payment example for Cloudflare Workers.
//!
//! Matches the pattern used by production consumers (rust-message-box,
//! banana-agent, claude-agent): a single top-level `process_auth` call,
//! then dispatch to handlers with the `AuthSession` threaded through.
//! Each handler's terminal call is `sign_json_response(&body, status, &[], session)`.
//!
//! Endpoints:
//! - GET  /                     → health check (no auth)
//! - POST /.well-known/auth     → handled implicitly by `process_auth` (handshake)
//! - POST /protected            → auth only, echoes identity
//! - POST /paid                 → auth + BRC-29 payment (100 sats)
//!
//! ## Setup
//!
//! 1. Create KV namespaces:
//!    ```bash
//!    wrangler kv:namespace create AUTH_SESSIONS
//!    wrangler kv:namespace create PAYMENTS
//!    ```
//!
//! 2. Update wrangler.toml with the KV IDs.
//!
//! 3. Set the server private key:
//!    ```bash
//!    wrangler secret put SERVER_PRIVATE_KEY
//!    ```
//!
//! 4. Deploy: `npm run deploy`

use bsv_middleware_cloudflare::{
    add_cors_headers, init_panic_hook,
    middleware::{
        auth::handle_cors_preflight, process_auth, process_payment_with_storage,
        sign_json_response, AuthMiddlewareOptions, AuthResult, AuthSession,
        PaymentMiddlewareOptions, PaymentResult,
    },
    storage::{KvPrefixStore, KvSessionStorage},
    types::AuthContext,
};
use serde_json::json;
use worker::*;

// Stub main for cargo check — the actual entry point is #[event(fetch)] below.
fn main() {}

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    init_panic_hook();

    // CORS preflight (before auth)
    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    // Public: health check (before auth)
    if req.method() == Method::Get && req.path() == "/" {
        let resp = Response::from_json(&json!({ "status": "ok" }))?;
        return Ok(add_cors_headers(resp));
    }

    // Auth middleware — one pass for the whole request lifecycle.
    let server_key = env.secret("SERVER_PRIVATE_KEY")?.to_string();
    let auth_options = AuthMiddlewareOptions {
        server_private_key: server_key.clone(),
        allow_unauthenticated: false,
        session_ttl_seconds: 3600,
        ..Default::default()
    };

    let auth_result = process_auth(req, &env, &auth_options)
        .await
        .map_err(|e| Error::from(e.to_string()))?;

    // `process_auth` returns `Response(resp)` for handshake replies and auth
    // failures. For authenticated General requests it returns the peer's
    // identity, the rebuilt request, the session for signing responses, and
    // the raw body bytes (since the Worker's request body stream was consumed).
    let (auth_context, req, session, _body) = match auth_result {
        AuthResult::Authenticated {
            context,
            request,
            session,
            body,
        } => (context, request, session, body),
        AuthResult::Response(resp) => return Ok(resp),
    };

    // `session` is always Some for authenticated routes (allow_unauthenticated: false).
    let session = session.expect("session present on authenticated route");

    // Dispatch.
    match (req.method(), req.path().as_str()) {
        (Method::Post, "/protected") => handle_protected(&auth_context, &session).await,
        (Method::Post, "/paid") => {
            handle_paid(req, &env, &auth_context, &session, &server_key).await
        }
        _ => {
            let body = json!({
                "status": "error",
                "code": "ERR_NOT_FOUND",
                "description": "Not Found",
            });
            sign_json_response(&body, 404, &[], &session).map_err(|e| Error::from(e.to_string()))
        }
    }
}

/// Auth-only endpoint. Echoes the caller's identity key.
async fn handle_protected(auth: &AuthContext, session: &AuthSession) -> Result<Response> {
    let body = json!({
        "message": "You are authenticated.",
        "identity": auth.identity_key,
    });
    sign_json_response(&body, 200, &[], session).map_err(|e| Error::from(e.to_string()))
}

/// Auth + BRC-29 payment (100 sats flat).
async fn handle_paid(
    req: Request,
    env: &Env,
    auth: &AuthContext,
    session: &AuthSession,
    server_key: &str,
) -> Result<Response> {
    let payment_options =
        PaymentMiddlewareOptions::new(server_key.to_string(), |_req: &Request| 100u64);

    // KV retains the G3 race/propagation window. Production hosts that need
    // exact M14 enforcement should enable d1-claims and pass D1PrefixStore.
    let session_storage = KvSessionStorage::new(env.kv("AUTH_SESSIONS")?, "auth", 3600);

    let payment_prefixes = KvPrefixStore(&session_storage);
    let payment_ctx =
        match process_payment_with_storage(&req, auth, &payment_options, &payment_prefixes)
            .await
            .map_err(|e| Error::from(e.to_string()))?
        {
            PaymentResult::Free => None,
            // `Verified` now implies the wallet ACCEPTED the payment
            // (accepted == false returns `Failed` with a 402).
            PaymentResult::Verified(ctx) => Some(ctx),
            PaymentResult::Required(resp) => return Ok(resp), // 402 with derivation prefix
            PaymentResult::Failed(resp) => return Ok(resp),   // 400/402 bad or rejected payment
        };

    let body = json!({
        "message": "Paid endpoint.",
        "identity": auth.identity_key,
        "payment": payment_ctx.as_ref().map(|p| json!({
            "satoshis_paid": p.satoshis_paid,
            "tx": p.tx,
        })),
    });

    let extra_headers: Vec<(String, String)> = payment_ctx
        .map(|p| {
            vec![(
                "x-bsv-payment-satoshis-paid".to_string(),
                p.satoshis_paid.to_string(),
            )]
        })
        .unwrap_or_default();

    sign_json_response(&body, 200, &extra_headers, session).map_err(|e| Error::from(e.to_string()))
}
