//! BRC-103/104 Authentication middleware for Cloudflare Workers.
//!
//! This is a 1:1 port of auth-express-middleware, adapted for Cloudflare Workers.
//! It implements BRC-103/104 mutual authentication via BRC-104 HTTP headers.
//!
//! ## Key differences from Express:
//! - Express uses response hijacking (intercepting res.send/json). Workers can't do this.
//! - Instead, we provide `sign_response()` which users call before returning a response.
//! - Express uses in-memory SessionManager. Workers use KV for persistence.
//! - Express delegates all protocol logic to `Peer`. We implement it directly (same logic).
//!
//! ## Usage:
//! ```rust,ignore
//! let auth_result = process_auth(req, &env, &options).await?;
//! let (ctx, req, session, body) = match auth_result {
//!     AuthResult::Authenticated { context, request, session, body } => (context, request, session, body),
//!     AuthResult::Response(resp) => return Ok(resp),
//! };
//!
//! // Your handler
//! let response = handle_request(req, &ctx).await?;
//!
//! // Sign the response before returning (required for BRC-103/104 interop)
//! let signed = sign_response(response, &session)?;
//! Ok(signed)
//! ```

use crate::error::{AuthCloudflareError, Result};
use crate::storage::{KvSessionStorage, SessionStorage};
use crate::transport::{auth_headers, CloudflareTransport, HttpResponseData};
use crate::types::{AuthContext, ErrorResponse, StoredSession};
use bsv_sdk::auth::types::{AuthMessage, MessageType, RequestedCertificateSet, AUTH_PROTOCOL_ID};
use bsv_sdk::auth::utils::create_nonce;
use bsv_sdk::auth::VerifiableCertificate;
use bsv_sdk::primitives::PrivateKey;
use bsv_sdk::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel,
    VerifySignatureArgs,
};
use serde::Serialize;
use worker::{Env, Headers, Request, Response};

/// Options for creating auth middleware.
pub struct AuthMiddlewareOptions {
    /// Server's private key (64-char hex).
    pub server_private_key: String,
    /// Whether to allow unauthenticated requests through.
    /// Express: `allowUnauthenticated`
    pub allow_unauthenticated: bool,
    /// Certificates to request from peers.
    pub certificates_to_request: Option<RequestedCertificateSet>,
    /// Session TTL in seconds (default: 3600 = 1 hour).
    pub session_ttl_seconds: u64,
    /// Minimum seconds between persistent `update_session` writes per session.
    /// Per-message touches inside this window are skipped — the in-memory
    /// session still reflects the new activity for the rest of the request,
    /// but the durable store is only written when `now - last_update >=
    /// session_touch_debounce_seconds`.
    ///
    /// Default `30` keeps a heavily-trafficked session's write rate at
    /// ≤ 2/min, which on Cloudflare KV's 1k-writes/day free tier means a
    /// single wallet can sustain hours of activity without running quota.
    /// Set to `0` to restore the pre-debounce behavior of writing on every
    /// authenticated request.
    pub session_touch_debounce_seconds: u64,
    /// Callback when certificates are received.
    #[allow(clippy::type_complexity)]
    pub on_certificates_received:
        Option<Box<dyn Fn(String, Vec<VerifiableCertificate>) + Send + Sync>>,
}

impl Default for AuthMiddlewareOptions {
    fn default() -> Self {
        Self {
            server_private_key: String::new(),
            allow_unauthenticated: false,
            certificates_to_request: None,
            session_ttl_seconds: 3600,
            session_touch_debounce_seconds: 30,
            on_certificates_received: None,
        }
    }
}

/// Returns the current time in milliseconds since epoch, using
/// Cloudflare Workers' `Date::now`. Matches the unit `StoredSession::touch`
/// writes into `last_update` (via `crate::types::current_time_ms`), so
/// arithmetic between the two is direct.
fn current_time_ms_for_touch() -> u64 {
    crate::types::current_time_ms()
}

/// Session info needed for signing responses.
/// Returned from `process_auth` so the user can call `sign_response`.
#[derive(Debug, Clone)]
pub struct AuthSession {
    /// Server's private key hex.
    pub server_private_key: String,
    /// Server's session nonce.
    pub session_nonce: String,
    /// Peer's last known nonce.
    pub peer_nonce: Option<String>,
    /// Peer's identity key (hex).
    pub peer_identity_key: String,
    /// Request ID from the client's auth headers (32 bytes).
    pub request_id: [u8; 32],
}

/// Result of auth middleware processing.
pub enum AuthResult {
    /// Request is authenticated - proceed with the authenticated context.
    Authenticated {
        /// Authentication context with peer identity.
        context: AuthContext,
        /// The request (potentially with body consumed for auth).
        request: Request,
        /// Session info needed for signing responses.
        /// For unauthenticated requests (allowUnauthenticated=true), this is None.
        session: Option<AuthSession>,
        /// Raw request body bytes, captured before auth consumed the body.
        /// For General messages this contains the original body; for handshake
        /// and unauthenticated requests this is empty.
        body: Vec<u8>,
    },
    /// Authentication processing produced a response - return it to the client.
    /// This happens for handshake requests and error responses.
    Response(Response),
}

const ORIGINATOR: &str = "bsv-auth-cloudflare";

/// Process authentication for a Cloudflare Worker request.
///
/// This is a 1:1 port of auth-express-middleware's `createAuthMiddleware`.
///
/// ## Flow:
/// 1. Handshake requests (`/.well-known/auth`) → processes handshake, returns Response
/// 2. Authenticated requests (with auth headers) → verifies signature, returns Authenticated
/// 3. Unauthenticated requests → returns 401 or allows through if configured
pub async fn process_auth(
    req: Request,
    env: &Env,
    options: &AuthMiddlewareOptions,
) -> Result<AuthResult> {
    // Backward-compatible wrapper: build the default Cloudflare KV-backed
    // session storage from the `AUTH_SESSIONS` binding, then delegate to the
    // storage-generic implementation.
    let kv = env.kv("AUTH_SESSIONS").map_err(|e| {
        AuthCloudflareError::ConfigError(format!("AUTH_SESSIONS KV not bound: {}", e))
    })?;
    let session_storage = KvSessionStorage::new(kv, "auth", options.session_ttl_seconds);

    process_auth_with_storage(req, &session_storage, options).await
}

/// Process authentication for a Cloudflare Worker request using a caller-supplied
/// [`SessionStorage`] backend.
///
/// This is the real implementation behind [`process_auth`]. Use it directly when
/// you want to back BRC-103/104 sessions with a store other than the default
/// Cloudflare KV namespace — for example a Durable Object SQLite database, which
/// avoids the isolate-instability problems that arise when auth sessions live in
/// KV / entrypoint isolates.
///
/// The BRC-103/104 wire format and signature verification are identical to
/// [`process_auth`]; only the session backing store differs.
///
/// ## Flow:
/// 1. Handshake requests (`/.well-known/auth`) → processes handshake, returns Response
/// 2. Authenticated requests (with auth headers) → verifies signature, returns Authenticated
/// 3. Unauthenticated requests → returns 401 or allows through if configured
pub async fn process_auth_with_storage<S: SessionStorage + ?Sized>(
    mut req: Request,
    session_storage: &S,
    options: &AuthMiddlewareOptions,
) -> Result<AuthResult> {
    // Create wallet from server private key
    let private_key = PrivateKey::from_hex(&options.server_private_key).map_err(|e| {
        AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
    })?;
    let wallet = ProtoWallet::new(Some(private_key));

    // Check if this is a handshake request
    if CloudflareTransport::is_handshake_request(&req) {
        return handle_handshake_request(req, &wallet, session_storage, options).await;
    }

    // Check for auth headers
    if !CloudflareTransport::has_auth_headers(&req) {
        if options.allow_unauthenticated {
            // Express: req.auth = { identityKey: 'unknown' }
            return Ok(AuthResult::Authenticated {
                context: AuthContext::unauthenticated(),
                request: req,
                session: None,
                body: vec![],
            });
        } else {
            // TS Express middleware wire format:
            //   { status: "error", code: "UNAUTHORIZED", message: "Mutual-authentication failed!" }
            // Field is `message` (not `description`) — verified against live
            // TS server at messagebox.babbage.systems. Handler-layer errors
            // (ERR_MESSAGEBOX_REQUIRED etc.) use `description`; middleware-
            // layer auth errors use `message`. Mirror exactly.
            let body = serde_json::json!({
                "status": "error",
                "code": "UNAUTHORIZED",
                "message": "Mutual-authentication failed!",
            });
            let response = Response::from_json(&body)
                .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
                .with_status(401);
            return Ok(AuthResult::Response(add_cors_headers(response)));
        }
    }

    // Extract request ID before consuming body
    let request_id = CloudflareTransport::get_request_id(&req).unwrap_or([0u8; 32]);

    // Extract auth message from request (also returns raw body bytes)
    let (auth_message, request_body) = CloudflareTransport::extract_auth_message(&mut req).await?;

    // Get session by peer's identity key or nonce
    let identity_key_hex = auth_message.identity_key.to_hex();
    let session_nonce = auth_message
        .your_nonce
        .as_ref()
        .or(auth_message.nonce.as_ref());

    let session = if let Some(nonce) = session_nonce {
        session_storage.get_session(nonce).await?
    } else {
        session_storage
            .get_session_by_identity(&identity_key_hex)
            .await?
    };

    let session = match session {
        Some(s) => s,
        None => {
            let response = Response::from_json(&ErrorResponse::new(
                "ERR_SESSION_NOT_FOUND",
                "No authenticated session found",
            ))
            .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
            .with_status(401);
            return Ok(AuthResult::Response(add_cors_headers(response)));
        }
    };

    if !session.is_authenticated {
        return Err(AuthCloudflareError::InvalidAuthentication(
            "Session not authenticated".into(),
        ));
    }

    // Verify signature
    let is_valid = verify_message_signature(&wallet, &auth_message, &session)?;
    if !is_valid {
        return Err(AuthCloudflareError::InvalidAuthentication(
            "Invalid message signature".into(),
        ));
    }

    // Update session last activity (but NOT peer_nonce).
    // In the TS SDK, peerSession.peerNonce is set ONCE during handshake and
    // NEVER updated for General messages. The client's per-message nonce is a
    // random value (not wallet-derived). If we store it as peer_nonce:
    //   1. Response yourNonce = random nonce → client's verifyNonce fails
    //   2. processGeneralMessage throws → general message callbacks never fire
    //   3. AuthFetch Promise never resolves → 402 payment handling breaks
    //   4. Signature keyID mismatch (uses peer_nonce, client expects handshake nonce)
    //
    // Debounce: only persist the touch when the on-disk `last_update` is older
    // than `session_touch_debounce_seconds` (default 30s). The previous behavior
    // was a write per authenticated request — on Cloudflare KV's free tier
    // (1k writes/day) a wallet doing storage-sync hit 50% by 250 requests/day.
    // The session's TTL is still set to `session_ttl_seconds` at handshake; if
    // a session goes idle long enough that the next request is past TTL, the
    // session is rotated through the handshake path anyway, so skipping the
    // intra-window touch can't strand a session before its real expiration.
    let needs_touch = {
        let debounce_ms = options.session_touch_debounce_seconds.saturating_mul(1000);
        let now_ms = current_time_ms_for_touch();
        now_ms.saturating_sub(session.last_update) >= debounce_ms
    };
    if needs_touch {
        let mut updated_session = session.clone();
        updated_session.touch();
        session_storage.update_session(&updated_session).await?;
    }

    // Build session info for response signing.
    // peer_nonce = the client's HANDSHAKE nonce (from session), not the per-message random nonce.
    let auth_session = AuthSession {
        server_private_key: options.server_private_key.clone(),
        session_nonce: session.session_nonce.clone(),
        peer_nonce: session.peer_nonce.clone(),
        peer_identity_key: session.peer_identity_key.clone(),
        request_id,
    };

    Ok(AuthResult::Authenticated {
        context: AuthContext::authenticated(session.peer_identity_key),
        request: req,
        session: Some(auth_session),
        body: request_body,
    })
}

/// Sign a response for BRC-103/104 interop.
///
/// This creates a signed General message from the response, matching how
/// auth-express-middleware signs responses via `peer.toPeer(payload, identityKey)`.
///
/// Call this before returning any response to an authenticated client.
/// Without signing, clients using AuthFetch will reject the response.
///
/// # Arguments
/// * `response` - The response from your handler
/// * `session` - The AuthSession from process_auth
///
/// # Returns
/// The response with BRC-104 auth headers added (including signature)
pub fn sign_response(response: Response, session: &AuthSession) -> Result<Response> {
    let private_key = PrivateKey::from_hex(&session.server_private_key).map_err(|e| {
        AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
    })?;
    let wallet = ProtoWallet::new(Some(private_key));

    // Get server's identity key
    let identity_result = wallet.get_public_key(GetPublicKeyArgs {
        identity_key: true,
        protocol_id: None,
        key_id: None,
        counterparty: None,
        for_self: None,
    })?;
    let identity_key = bsv_sdk::primitives::PublicKey::from_hex(&identity_result.public_key)?;

    // Build response payload (matching Express's buildResponsePayload)
    let status = response.status_code();

    // Extract body from response
    // Note: worker::Response doesn't have a way to get body bytes easily,
    // so we need to handle this at the caller level or use a workaround.
    // For now, we build the payload with the status and headers but empty body,
    // which matches most API responses that are JSON.
    let response_data = HttpResponseData {
        request_id: session.request_id,
        status,
        headers: vec![], // Response headers are handled separately
        body: vec![],    // Body is sent in the HTTP response directly
    };

    let payload = response_data.to_payload();

    // Create a General AuthMessage with the payload
    let nonce = generate_random_nonce();

    let mut msg = AuthMessage::new(MessageType::General, identity_key);
    msg.nonce = Some(nonce);
    msg.your_nonce = session.peer_nonce.clone();
    msg.payload = Some(payload);

    // Sign the message
    let stored_session = StoredSession {
        session_nonce: session.session_nonce.clone(),
        peer_identity_key: session.peer_identity_key.clone(),
        peer_nonce: session.peer_nonce.clone(),
        is_authenticated: true,
        certificates_required: false,
        certificates_validated: false,
        created_at: 0,
        last_update: 0,
    };
    sign_message(&wallet, &mut msg, &stored_session)?;

    // Add auth headers to the response
    let auth_header_pairs = CloudflareTransport::message_to_headers(&msg);

    // Also add the request ID header
    let request_id_b64 = bsv_sdk::primitives::to_base64(&session.request_id);

    let headers = Headers::new();
    for (key, value) in &auth_header_pairs {
        let _ = headers.set(key, value);
    }
    let _ = headers.set(auth_headers::REQUEST_ID, &request_id_b64);

    Ok(add_cors_headers(response.with_headers(headers)))
}

/// Signs a JSON response with BRC-104 auth headers.
///
/// Unlike `sign_response()`, this function takes the response data BEFORE
/// constructing the Response object, ensuring the actual body bytes are
/// included in the signed payload (matching how Express hijacks `res.json()`).
///
/// This is the recommended way to sign responses for authenticated clients.
///
/// # Header filtering rules (matching SimplifiedFetchTransport)
///
/// Only headers matching these rules are included in the signed payload:
/// - Headers starting with `x-bsv-` (but NOT `x-bsv-auth-*`)
/// - The `authorization` header
/// - Sorted alphabetically by lowercase key
///
/// All `extra_headers` are included in the HTTP response regardless of
/// whether they are signed.
///
/// # Arguments
/// * `data` - The response body to serialize as JSON
/// * `status` - HTTP status code
/// * `extra_headers` - Additional headers to include in the response (e.g., payment headers)
/// * `session` - The AuthSession from process_auth
///
/// # Returns
/// A signed Response with JSON body, auth headers, extra headers, and CORS headers
pub fn sign_json_response<T: Serialize>(
    data: &T,
    status: u16,
    extra_headers: &[(String, String)],
    session: &AuthSession,
) -> Result<Response> {
    // Step 1: Serialize body to JSON bytes
    let json_bytes = serde_json::to_vec(data)
        .map_err(|e| AuthCloudflareError::SerializationError(e.to_string()))?;

    // Step 2: Filter extra_headers to signable ones
    let signable_headers = filter_signable_headers(extra_headers);

    // Step 3: Build response payload with actual body bytes
    let response_data = HttpResponseData {
        request_id: session.request_id,
        status,
        headers: signable_headers,
        body: json_bytes.clone(),
    };
    let payload = response_data.to_payload();

    // Step 4: Create wallet and get identity key
    let private_key = PrivateKey::from_hex(&session.server_private_key).map_err(|e| {
        AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
    })?;
    let wallet = ProtoWallet::new(Some(private_key));

    let identity_result = wallet.get_public_key(GetPublicKeyArgs {
        identity_key: true,
        protocol_id: None,
        key_id: None,
        counterparty: None,
        for_self: None,
    })?;
    let identity_key = bsv_sdk::primitives::PublicKey::from_hex(&identity_result.public_key)?;

    // Step 5: Create and sign a General AuthMessage
    let nonce = generate_random_nonce();

    let mut msg = AuthMessage::new(MessageType::General, identity_key);
    msg.nonce = Some(nonce);
    msg.your_nonce = session.peer_nonce.clone();
    msg.payload = Some(payload);

    let stored_session = StoredSession {
        session_nonce: session.session_nonce.clone(),
        peer_identity_key: session.peer_identity_key.clone(),
        peer_nonce: session.peer_nonce.clone(),
        is_authenticated: true,
        certificates_required: false,
        certificates_validated: false,
        created_at: 0,
        last_update: 0,
    };
    sign_message(&wallet, &mut msg, &stored_session)?;

    // Step 6: Build the Response
    let auth_header_pairs = CloudflareTransport::message_to_headers(&msg);
    let request_id_b64 = bsv_sdk::primitives::to_base64(&session.request_id);

    let headers = Headers::new();
    // Content-Type
    let _ = headers.set("content-type", "application/json");
    // Auth headers
    for (key, value) in &auth_header_pairs {
        let _ = headers.set(key, value);
    }
    // Request ID
    let _ = headers.set(auth_headers::REQUEST_ID, &request_id_b64);
    // All extra headers (not just signable ones)
    for (key, value) in extra_headers {
        let _ = headers.set(key, value);
    }

    let response = Response::from_bytes(json_bytes)
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_status(status)
        .with_headers(headers);

    Ok(add_cors_headers(response))
}

/// Filters headers to only those that are signed in the response payload.
///
/// Rules (matching SimplifiedFetchTransport):
/// - Include: headers starting with `x-bsv-` (but NOT `x-bsv-auth-*`)
/// - Include: `authorization` header
/// - Exclude: all `x-bsv-auth-*` headers
/// - Sort: alphabetically by lowercase key
fn filter_signable_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut signable: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(key, value)| {
            let lower = key.to_lowercase();
            if lower.starts_with("x-bsv-auth-") {
                // Exclude all x-bsv-auth-* headers
                None
            } else if lower.starts_with("x-bsv-") || lower == "authorization" {
                Some((lower, value.clone()))
            } else {
                None
            }
        })
        .collect();
    signable.sort_by(|a, b| a.0.cmp(&b.0));
    signable
}

/// Handle a handshake request to /.well-known/auth
async fn handle_handshake_request<S: SessionStorage + ?Sized>(
    mut req: Request,
    wallet: &ProtoWallet,
    session_storage: &S,
    options: &AuthMiddlewareOptions,
) -> Result<AuthResult> {
    // Parse the handshake message from body
    let body = req
        .text()
        .await
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?;

    let message: AuthMessage = serde_json::from_str(&body).map_err(|e| {
        AuthCloudflareError::InvalidAuthentication(format!("Invalid auth message: {}", e))
    })?;

    match message.message_type {
        MessageType::InitialRequest => {
            handle_initial_request(message, wallet, session_storage, options).await
        }
        MessageType::CertificateResponse => {
            handle_certificate_response(message, wallet, session_storage, options).await
        }
        MessageType::CertificateRequest => {
            handle_certificate_request(message, wallet, session_storage, options).await
        }
        _ => Err(AuthCloudflareError::InvalidAuthentication(format!(
            "Unexpected message type for handshake: {}",
            message.message_type
        ))),
    }
}

/// Handle an InitialRequest message.
///
/// This matches the Peer's `process_initial_request`:
/// 1. Creates session nonce
/// 2. Creates session
/// 3. Sends InitialResponse with signature
async fn handle_initial_request<S: SessionStorage + ?Sized>(
    message: AuthMessage,
    wallet: &ProtoWallet,
    session_storage: &S,
    options: &AuthMiddlewareOptions,
) -> Result<AuthResult> {
    let peer_identity_key = message.identity_key.to_hex();

    // Get our identity key
    let my_identity_result = wallet.get_public_key(GetPublicKeyArgs {
        identity_key: true,
        protocol_id: None,
        key_id: None,
        counterparty: None,
        for_self: None,
    })?;
    let my_identity_key = bsv_sdk::primitives::PublicKey::from_hex(&my_identity_result.public_key)?;

    // Create our session nonce (matches Peer: create_nonce with counterparty=Self)
    let session_nonce = create_nonce(wallet, None, ORIGINATOR).await?;

    // Get the peer's nonce (initial_nonce from the InitialRequest)
    let peer_nonce = message.initial_nonce.clone().or(message.nonce.clone());

    // Create and save session
    let mut session = StoredSession::new(session_nonce.clone(), peer_identity_key.clone());
    session.peer_nonce = peer_nonce.clone();
    session.is_authenticated = true;

    // Check if certificates are required
    if options.certificates_to_request.is_some() {
        session.certificates_required = true;
    }

    session_storage.save_session(&session).await?;

    // Build InitialResponse (matches Peer's process_initial_request)
    // InitialResponse fields:
    //   nonce = our session nonce (same as initial_nonce)
    //   initial_nonce = our session nonce
    //   your_nonce = peer's nonce (echoed back)
    //   signature = signature over (your_nonce || initial_nonce)
    let mut response_msg = AuthMessage::new(MessageType::InitialResponse, my_identity_key);
    response_msg.nonce = Some(session_nonce.clone());
    response_msg.initial_nonce = Some(session_nonce.clone());
    response_msg.your_nonce = peer_nonce;

    // Request certificates if configured
    if options.certificates_to_request.is_some() {
        response_msg.requested_certificates = options.certificates_to_request.clone();
    }

    // Sign the response (InitialResponse signing uses its own fields for key_id)
    sign_message(wallet, &mut response_msg, &session)?;

    // Build response with auth headers
    let auth_headers = CloudflareTransport::message_to_headers(&response_msg);
    let headers = Headers::new();
    for (key, value) in &auth_headers {
        let _ = headers.set(key, value);
    }

    let response = Response::from_json(&response_msg)
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_headers(headers);

    Ok(AuthResult::Response(add_cors_headers(response)))
}

/// Handle a CertificateResponse message.
///
/// Matches Peer's `process_certificate_response`:
/// 1. Verifies the signature
/// 2. Validates certificates
/// 3. Updates session
/// 4. Calls callback
async fn handle_certificate_response<S: SessionStorage + ?Sized>(
    message: AuthMessage,
    wallet: &ProtoWallet,
    session_storage: &S,
    options: &AuthMiddlewareOptions,
) -> Result<AuthResult> {
    let peer_identity_key = message.identity_key.to_hex();

    // Find existing session
    let session = session_storage
        .get_session_by_identity(&peer_identity_key)
        .await?
        .ok_or_else(|| AuthCloudflareError::SessionNotFound(peer_identity_key.clone()))?;

    // Verify signature
    let is_valid = verify_message_signature(wallet, &message, &session)?;
    if !is_valid {
        return Err(AuthCloudflareError::InvalidAuthentication(
            "Invalid certificate response signature".into(),
        ));
    }

    // Validate certificates if we have requirements
    if let Some(ref certs) = message.certificates {
        // Verify certificates match our requirements
        if let Some(ref _requested) = options.certificates_to_request {
            // Use SDK's certificate validation
            bsv_sdk::auth::utils::validate_certificates(
                wallet,
                &message,
                options.certificates_to_request.as_ref(),
                ORIGINATOR,
            )
            .await
            .map_err(|e| {
                AuthCloudflareError::InvalidAuthentication(format!(
                    "Certificate validation failed: {}",
                    e
                ))
            })?;
        }

        // Call callback if provided
        if let Some(ref callback) = options.on_certificates_received {
            callback(peer_identity_key.clone(), certs.clone());
        }
    } else {
        // Express: responds with 400 { status: 'No certificates provided' }
        let response = Response::from_json(&serde_json::json!({
            "status": "No certificates provided"
        }))
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_status(400);
        return Ok(AuthResult::Response(add_cors_headers(response)));
    }

    // Update session
    let mut updated_session = session;
    updated_session.certificates_validated = true;
    updated_session.touch();
    session_storage.update_session(&updated_session).await?;

    // Return success response
    let response = Response::from_json(&serde_json::json!({
        "status": "ok",
        "message": "Certificates received"
    }))
    .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?;

    Ok(AuthResult::Response(add_cors_headers(response)))
}

/// Handle a CertificateRequest message.
///
/// Matches Peer's `process_certificate_request`:
/// Returns certificates from the server's wallet.
async fn handle_certificate_request<S: SessionStorage + ?Sized>(
    message: AuthMessage,
    wallet: &ProtoWallet,
    session_storage: &S,
    _options: &AuthMiddlewareOptions,
) -> Result<AuthResult> {
    let peer_identity_key = message.identity_key.to_hex();

    // Find existing session
    let session = session_storage
        .get_session_by_identity(&peer_identity_key)
        .await?
        .ok_or_else(|| AuthCloudflareError::SessionNotFound(peer_identity_key.clone()))?;

    // Verify signature
    let is_valid = verify_message_signature(wallet, &message, &session)?;
    if !is_valid {
        return Err(AuthCloudflareError::InvalidAuthentication(
            "Invalid certificate request signature".into(),
        ));
    }

    // Get requested certificates from our wallet
    let certificates = if let Some(ref requested) = message.requested_certificates {
        let peer_key = bsv_sdk::primitives::PublicKey::from_hex(&peer_identity_key)?;
        bsv_sdk::auth::utils::get_verifiable_certificates(wallet, requested, &peer_key, ORIGINATOR)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Build CertificateResponse
    let my_identity_result = wallet.get_public_key(GetPublicKeyArgs {
        identity_key: true,
        protocol_id: None,
        key_id: None,
        counterparty: None,
        for_self: None,
    })?;
    let my_identity_key = bsv_sdk::primitives::PublicKey::from_hex(&my_identity_result.public_key)?;

    let mut response_msg = AuthMessage::new(MessageType::CertificateResponse, my_identity_key);
    response_msg.nonce = Some(generate_random_nonce());
    response_msg.your_nonce = session.peer_nonce.clone();
    response_msg.certificates = Some(certificates);

    sign_message(wallet, &mut response_msg, &session)?;

    let auth_headers = CloudflareTransport::message_to_headers(&response_msg);
    let headers = Headers::new();
    for (key, value) in &auth_headers {
        let _ = headers.set(key, value);
    }

    let response = Response::from_json(&response_msg)
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_headers(headers);

    Ok(AuthResult::Response(add_cors_headers(response)))
}

/// Sign an auth message using ProtoWallet.
///
/// Matches Peer's `sign_message`:
/// - Protocol: AUTH_PROTOCOL_ID ("auth message signature")
/// - Security level: Counterparty (2)
/// - Key ID: "{nonce} {peer_session_nonce}" (from AuthMessage::get_key_id)
/// - Counterparty: peer's identity key
fn sign_message(
    wallet: &ProtoWallet,
    message: &mut AuthMessage,
    session: &StoredSession,
) -> Result<()> {
    let data = message.signing_data();
    let key_id = message.get_key_id(session.peer_nonce.as_deref());
    let peer_key = bsv_sdk::primitives::PublicKey::from_hex(&session.peer_identity_key)?;

    let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);

    let result = wallet.create_signature(CreateSignatureArgs {
        data: Some(data),
        hash_to_directly_sign: None,
        protocol_id: protocol,
        key_id,
        counterparty: Some(Counterparty::Other(peer_key)),
    })?;

    message.signature = Some(result.signature);
    Ok(())
}

/// Verify an auth message signature.
///
/// Matches Peer's `verify_message_signature`:
/// - Uses the message's signing_data() as the data
/// - Key ID: "{nonce} {server_session_nonce}"
/// - Counterparty: message sender's identity key
fn verify_message_signature(
    wallet: &ProtoWallet,
    message: &AuthMessage,
    session: &StoredSession,
) -> Result<bool> {
    let signature = message
        .signature
        .as_ref()
        .ok_or_else(|| AuthCloudflareError::InvalidAuthentication("Message not signed".into()))?;

    let data = message.signing_data();
    let key_id = message.get_key_id(Some(session.session_nonce.as_str()));

    let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);

    let result = wallet.verify_signature(VerifySignatureArgs {
        data: Some(data),
        hash_to_directly_verify: None,
        signature: signature.clone(),
        protocol_id: protocol,
        key_id,
        counterparty: Some(Counterparty::Other(message.identity_key.clone())),
        for_self: None,
    });

    match result {
        Ok(r) => Ok(r.valid),
        Err(_) => Ok(false),
    }
}

/// Generate a random nonce (32 bytes, base64 encoded).
/// Used for General message nonces (not session nonces which use HMAC).
fn generate_random_nonce() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    bsv_sdk::primitives::to_base64(&bytes)
}

/// Add CORS headers to a response.
///
/// Includes all BSV auth and payment headers in Access-Control headers.
pub fn add_cors_headers(response: Response) -> Response {
    // IMPORTANT: Use response.headers() to get the EXISTING headers and add CORS to them.
    // Previously this created Headers::new() (empty) and called response.with_headers(),
    // which REPLACED all existing headers (including auth headers from sign_json_response).
    let headers = response.headers();
    let _ = headers.set("Access-Control-Allow-Origin", "*");
    let _ = headers.set(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, OPTIONS",
    );
    let _ = headers.set(
        "Access-Control-Allow-Headers",
        &format!(
            "Content-Type, Authorization, {}, {}, {}, {}, {}, {}, {}, {}, x-bsv-payment",
            auth_headers::VERSION,
            auth_headers::IDENTITY_KEY,
            auth_headers::NONCE,
            auth_headers::YOUR_NONCE,
            auth_headers::SIGNATURE,
            auth_headers::MESSAGE_TYPE,
            auth_headers::REQUEST_ID,
            auth_headers::REQUESTED_CERTIFICATES
        ),
    );
    let _ = headers.set(
        "Access-Control-Expose-Headers",
        &format!(
            "{}, {}, {}, {}, {}, {}, {}, x-bsv-payment-satoshis-paid, x-bsv-payment-version, x-bsv-payment-satoshis-required, x-bsv-payment-derivation-prefix, x-bsv-payment-txid",
            auth_headers::VERSION,
            auth_headers::IDENTITY_KEY,
            auth_headers::NONCE,
            auth_headers::YOUR_NONCE,
            auth_headers::SIGNATURE,
            auth_headers::MESSAGE_TYPE,
            auth_headers::REQUEST_ID
        ),
    );

    response
}

/// Handle CORS preflight request.
pub fn handle_cors_preflight() -> worker::Result<Response> {
    let response = Response::empty()?.with_status(204);
    Ok(add_cors_headers(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_sdk::primitives::PrivateKey;

    // Helper to create a test wallet
    fn test_wallet(hex: &str) -> ProtoWallet {
        let pk = PrivateKey::from_hex(hex).unwrap();
        ProtoWallet::new(Some(pk))
    }

    fn test_key(hex: &str) -> bsv_sdk::primitives::PublicKey {
        PrivateKey::from_hex(hex).unwrap().public_key()
    }

    // Known test keys
    const SERVER_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const CLIENT_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    // ===========================================
    // Message signing and verification tests
    // ===========================================

    #[test]
    fn test_sign_and_verify_initial_response() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let server_pk = test_key(SERVER_KEY_HEX);
        let client_pk = test_key(CLIENT_KEY_HEX);

        // Create an InitialResponse (as the server would)
        let mut msg = AuthMessage::new(MessageType::InitialResponse, server_pk.clone());
        msg.nonce = Some("server-nonce-1".to_string());
        msg.initial_nonce = Some("server-nonce-1".to_string());
        msg.your_nonce = Some("client-nonce-1".to_string());

        let session = StoredSession {
            session_nonce: "server-nonce-1".to_string(),
            peer_identity_key: client_pk.to_hex(),
            peer_nonce: Some("client-nonce-1".to_string()),
            is_authenticated: false,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };

        // Sign the message
        sign_message(&server_wallet, &mut msg, &session).unwrap();
        assert!(msg.signature.is_some(), "Message should be signed");

        // Verify the signature (from the client's perspective)
        // The client (verifier) uses the server's session_nonce as the key_id component
        let client_wallet = test_wallet(CLIENT_KEY_HEX);
        let verify_session = StoredSession {
            session_nonce: "server-nonce-1".to_string(),
            peer_identity_key: server_pk.to_hex(),
            peer_nonce: Some("server-nonce-1".to_string()),
            is_authenticated: false,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };
        let is_valid = verify_message_signature(&client_wallet, &msg, &verify_session).unwrap();
        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn test_sign_and_verify_general_message() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let server_pk = test_key(SERVER_KEY_HEX);
        let client_pk = test_key(CLIENT_KEY_HEX);

        let mut msg = AuthMessage::new(MessageType::General, server_pk.clone());
        msg.nonce = Some("new-nonce".to_string());
        msg.your_nonce = Some("client-nonce".to_string());
        msg.payload = Some(vec![1, 2, 3, 4, 5]);

        let session = StoredSession {
            session_nonce: "server-session-nonce".to_string(),
            peer_identity_key: client_pk.to_hex(),
            peer_nonce: Some("client-nonce".to_string()),
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };

        sign_message(&server_wallet, &mut msg, &session).unwrap();
        assert!(msg.signature.is_some());

        // Verify from client's perspective
        // The client's session_nonce must equal what the server used as peer_nonce in sign_message
        // because get_key_id uses the counterparty's nonce and both sides must derive the same key
        let client_wallet = test_wallet(CLIENT_KEY_HEX);
        let client_session = StoredSession {
            session_nonce: "client-nonce".to_string(), // matches signing session's peer_nonce
            peer_identity_key: server_pk.to_hex(),
            peer_nonce: Some("server-session-nonce".to_string()),
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };
        let valid = verify_message_signature(&client_wallet, &msg, &client_session).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_tampered_message_fails() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let server_pk = test_key(SERVER_KEY_HEX);
        let client_pk = test_key(CLIENT_KEY_HEX);

        let mut msg = AuthMessage::new(MessageType::General, server_pk.clone());
        msg.nonce = Some("nonce-1".to_string());
        msg.your_nonce = Some("nonce-2".to_string());
        msg.payload = Some(vec![1, 2, 3]);

        let session = StoredSession {
            session_nonce: "session-nonce".to_string(),
            peer_identity_key: client_pk.to_hex(),
            peer_nonce: Some("nonce-2".to_string()),
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };

        sign_message(&server_wallet, &mut msg, &session).unwrap();

        // Tamper with the payload
        msg.payload = Some(vec![9, 9, 9]);

        let client_wallet = test_wallet(CLIENT_KEY_HEX);
        let verify_session = StoredSession {
            session_nonce: "session-nonce".to_string(),
            peer_identity_key: server_pk.to_hex(),
            peer_nonce: None,
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };
        let valid = verify_message_signature(&client_wallet, &msg, &verify_session).unwrap();
        assert!(!valid, "Tampered message should not verify");
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let server_pk = test_key(SERVER_KEY_HEX);
        let client_pk = test_key(CLIENT_KEY_HEX);

        let mut msg = AuthMessage::new(MessageType::General, server_pk.clone());
        msg.nonce = Some("n1".to_string());
        msg.payload = Some(vec![1]);

        let session = StoredSession {
            session_nonce: "sn".to_string(),
            peer_identity_key: client_pk.to_hex(),
            peer_nonce: None,
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };

        sign_message(&server_wallet, &mut msg, &session).unwrap();

        // Try to verify with a different key (third party)
        let third_key_hex = "0000000000000000000000000000000000000000000000000000000000000003";
        let third_wallet = test_wallet(third_key_hex);
        let third_session = StoredSession {
            session_nonce: "sn".to_string(),
            peer_identity_key: server_pk.to_hex(),
            peer_nonce: None,
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };
        let valid = verify_message_signature(&third_wallet, &msg, &third_session).unwrap();
        assert!(!valid, "Verification with wrong key should fail");
    }

    #[test]
    fn test_verify_unsigned_message_fails() {
        let wallet = test_wallet(SERVER_KEY_HEX);
        let server_pk = test_key(SERVER_KEY_HEX);
        let client_pk = test_key(CLIENT_KEY_HEX);

        let msg = AuthMessage::new(MessageType::General, client_pk);
        // No signature set

        let session = StoredSession {
            session_nonce: "sn".to_string(),
            peer_identity_key: server_pk.to_hex(),
            peer_nonce: None,
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };

        let result = verify_message_signature(&wallet, &msg, &session);
        assert!(result.is_err(), "Unsigned message should return error");
    }

    // ===========================================
    // Random nonce generation tests
    // ===========================================

    #[test]
    fn test_generate_random_nonce_is_base64() {
        let nonce = generate_random_nonce();
        // 32 bytes base64 encoded = 44 chars (with padding)
        assert!(!nonce.is_empty());
        // Should be valid base64
        let decoded = bsv_sdk::primitives::from_base64(&nonce);
        assert!(decoded.is_ok(), "Nonce should be valid base64");
        assert_eq!(
            decoded.unwrap().len(),
            32,
            "Nonce should be 32 bytes decoded"
        );
    }

    #[test]
    fn test_generate_random_nonce_uniqueness() {
        let nonce1 = generate_random_nonce();
        let nonce2 = generate_random_nonce();
        assert_ne!(nonce1, nonce2, "Two random nonces should differ");
    }

    // ===========================================
    // AuthContext tests
    // ===========================================

    #[test]
    fn test_auth_context_authenticated() {
        let ctx = AuthContext::authenticated("02abc123".to_string());
        assert_eq!(ctx.identity_key, "02abc123");
        assert!(ctx.is_authenticated);
    }

    #[test]
    fn test_auth_context_unauthenticated() {
        let ctx = AuthContext::unauthenticated();
        assert_eq!(ctx.identity_key, "unknown");
        assert!(!ctx.is_authenticated);
    }

    // ===========================================
    // AuthMiddlewareOptions default tests
    // ===========================================

    #[test]
    fn test_auth_middleware_options_defaults() {
        let opts = AuthMiddlewareOptions::default();
        assert!(opts.server_private_key.is_empty());
        assert!(!opts.allow_unauthenticated);
        assert!(opts.certificates_to_request.is_none());
        assert_eq!(opts.session_ttl_seconds, 3600);
        assert!(opts.on_certificates_received.is_none());
    }

    // ===========================================
    // AuthSession tests
    // ===========================================

    #[test]
    fn test_auth_session_construction() {
        let session = AuthSession {
            server_private_key: SERVER_KEY_HEX.to_string(),
            session_nonce: "test-nonce".to_string(),
            peer_nonce: Some("peer-nonce".to_string()),
            peer_identity_key: "02abc".to_string(),
            request_id: [42u8; 32],
        };
        assert_eq!(session.session_nonce, "test-nonce");
        assert_eq!(session.peer_nonce.as_deref(), Some("peer-nonce"));
        assert_eq!(session.request_id, [42u8; 32]);
    }

    // ===========================================
    // StoredSession tests
    // ===========================================

    #[test]
    fn test_stored_session_serialization_roundtrip() {
        let session = StoredSession {
            session_nonce: "nonce-abc".to_string(),
            peer_identity_key: "02deadbeef".to_string(),
            peer_nonce: Some("peer-nonce".to_string()),
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: true,
            created_at: 1000,
            last_update: 2000,
        };

        let json = serde_json::to_string(&session).unwrap();
        let deserialized: StoredSession = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.session_nonce, "nonce-abc");
        assert_eq!(deserialized.peer_identity_key, "02deadbeef");
        assert_eq!(deserialized.peer_nonce.as_deref(), Some("peer-nonce"));
        assert!(deserialized.is_authenticated);
        assert!(!deserialized.certificates_required);
        assert!(deserialized.certificates_validated);
        assert_eq!(deserialized.created_at, 1000);
        assert_eq!(deserialized.last_update, 2000);
    }

    #[test]
    fn test_stored_session_camel_case_serialization() {
        // Express uses camelCase for session fields - verify our serde config matches
        let session = StoredSession {
            session_nonce: "test".to_string(),
            peer_identity_key: "key".to_string(),
            peer_nonce: None,
            is_authenticated: false,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };

        let json = serde_json::to_string(&session).unwrap();
        assert!(
            json.contains("sessionNonce"),
            "Should use camelCase: {}",
            json
        );
        assert!(
            json.contains("peerIdentityKey"),
            "Should use camelCase: {}",
            json
        );
        assert!(
            json.contains("isAuthenticated"),
            "Should use camelCase: {}",
            json
        );
        assert!(json.contains("createdAt"), "Should use camelCase: {}", json);
        assert!(
            json.contains("lastUpdate"),
            "Should use camelCase: {}",
            json
        );
    }

    // ===========================================
    // filter_signable_headers tests
    // ===========================================

    #[test]
    fn test_filter_signable_headers_includes_x_bsv_non_auth() {
        let headers = vec![
            ("x-bsv-payment-version".to_string(), "1.0".to_string()),
            (
                "x-bsv-payment-satoshis-required".to_string(),
                "10".to_string(),
            ),
            (
                "x-bsv-payment-derivation-prefix".to_string(),
                "nonce123".to_string(),
            ),
        ];
        let result = filter_signable_headers(&headers);
        assert_eq!(result.len(), 3);
        // Should be sorted alphabetically
        assert_eq!(result[0].0, "x-bsv-payment-derivation-prefix");
        assert_eq!(result[1].0, "x-bsv-payment-satoshis-required");
        assert_eq!(result[2].0, "x-bsv-payment-version");
    }

    #[test]
    fn test_filter_signable_headers_excludes_auth_headers() {
        let headers = vec![
            ("x-bsv-auth-version".to_string(), "0.1".to_string()),
            ("x-bsv-auth-identity-key".to_string(), "02abc".to_string()),
            ("x-bsv-payment-version".to_string(), "1.0".to_string()),
        ];
        let result = filter_signable_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "x-bsv-payment-version");
    }

    #[test]
    fn test_filter_signable_headers_includes_authorization() {
        let headers = vec![
            ("Authorization".to_string(), "Bearer token".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let result = filter_signable_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "authorization");
        assert_eq!(result[0].1, "Bearer token");
    }

    #[test]
    fn test_filter_signable_headers_lowercases_keys() {
        let headers = vec![("X-BSV-Payment-Version".to_string(), "1.0".to_string())];
        let result = filter_signable_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "x-bsv-payment-version");
    }

    #[test]
    fn test_filter_signable_headers_sorts_alphabetically() {
        let headers = vec![
            ("x-bsv-z-header".to_string(), "z".to_string()),
            ("x-bsv-a-header".to_string(), "a".to_string()),
            ("x-bsv-m-header".to_string(), "m".to_string()),
        ];
        let result = filter_signable_headers(&headers);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "x-bsv-a-header");
        assert_eq!(result[1].0, "x-bsv-m-header");
        assert_eq!(result[2].0, "x-bsv-z-header");
    }

    #[test]
    fn test_filter_signable_headers_excludes_standard_headers() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("cache-control".to_string(), "no-cache".to_string()),
            ("x-custom-header".to_string(), "value".to_string()),
        ];
        let result = filter_signable_headers(&headers);
        assert_eq!(result.len(), 0);
    }

    // ===========================================
    // sign_json_response payload tests
    // ===========================================

    #[test]
    fn test_sign_json_response_includes_body_in_payload() {
        // Verify that the response payload format includes body bytes,
        // unlike sign_response which uses empty body.
        let body = serde_json::json!({"message": "hello"});
        let json_bytes = serde_json::to_vec(&body).unwrap();

        let response_data = HttpResponseData {
            request_id: [0u8; 32],
            status: 200,
            headers: vec![],
            body: json_bytes.clone(),
        };
        let payload = response_data.to_payload();

        // The payload should contain the body bytes (not -1 empty marker)
        // After request_id (32) + status varint (1 for 200) + header count varint (1 for 0)
        // = offset 34, then body length varint + body bytes
        let body_start = 34; // 32 + 1 (200) + 1 (0 headers)
                             // Body length should be a varint, not -1 (0xFF...)
        assert_ne!(payload[body_start], 0xFF, "Body should not be empty marker");

        // The actual JSON bytes should appear in the payload
        let payload_contains_body = payload
            .windows(json_bytes.len())
            .any(|w| w == json_bytes.as_slice());
        assert!(
            payload_contains_body,
            "Payload should contain the JSON body bytes"
        );
    }

    #[test]
    fn test_sign_json_response_payload_matches_expected_format() {
        // Verify exact payload byte layout for a known input
        let body = serde_json::json!({"ok": true});
        let json_bytes = serde_json::to_vec(&body).unwrap();
        let request_id = [1u8; 32];

        let headers = vec![("x-bsv-payment-satoshis-paid".to_string(), "10".to_string())];

        let response_data = HttpResponseData {
            request_id,
            status: 200,
            headers: headers.clone(),
            body: json_bytes.clone(),
        };
        let payload = response_data.to_payload();

        // Verify structure:
        // [32 bytes request_id]
        assert_eq!(&payload[0..32], &[1u8; 32]);

        // [status varint: 200 = single byte]
        assert_eq!(payload[32], 200);

        // [header_count varint: 1]
        assert_eq!(payload[33], 1);

        // [key_len varint][key bytes][val_len varint][val bytes]
        let key = b"x-bsv-payment-satoshis-paid";
        assert_eq!(payload[34], key.len() as u8);
        assert_eq!(&payload[35..35 + key.len()], key);
        let val = b"10";
        let val_offset = 35 + key.len();
        assert_eq!(payload[val_offset], val.len() as u8);
        assert_eq!(&payload[val_offset + 1..val_offset + 1 + val.len()], val);

        // [body_len varint][body bytes]
        let body_offset = val_offset + 1 + val.len();
        assert_eq!(payload[body_offset], json_bytes.len() as u8);
        assert_eq!(
            &payload[body_offset + 1..body_offset + 1 + json_bytes.len()],
            json_bytes.as_slice()
        );
    }
}
