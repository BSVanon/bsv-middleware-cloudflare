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
//! - **Replay protection (hardening divergence):** the TS reference
//!   (`@bsv/sdk` `Peer.processGeneralMessage`, verified through v2.0.13)
//!   never records consumed per-request nonces, so a byte-identical signed
//!   request replays successfully there for the whole session lifetime. This
//!   crate consumes `(session_nonce, x-bsv-auth-nonce)` through
//!   [`SessionStorage::try_consume_nonce`] after signature verification and
//!   rejects duplicates with `401 ERR_REPLAYED_REQUEST`.
//!
//! ## Residual replay window (precise statement)
//!
//! With the default Cloudflare-KV-backed storage ([`KvSessionStorage`]):
//! 1. A replay arriving at the **same Cloudflare location** after the
//!    original nonce write completed is always rejected; concurrent
//!    in-flight duplicates at that location can race the KV read-then-write
//!    (sub-second window, no atomic put-if-absent in KV).
//! 2. A replay arriving at a **different location** may succeed at most once
//!    per location until the KV write propagates (≤ ~60 seconds after the
//!    original request).
//! 3. Nonce records expire after `session_ttl_seconds`. A session kept alive
//!    past that by the sliding liveness refresh can therefore accept a
//!    replay of a request **older than `session_ttl_seconds`** — i.e. replay
//!    of a captured request is rejected for at least the full session TTL,
//!    and forever unless the victim's session is still alive when the record
//!    lapses.
//!
//! A strongly consistent `SessionStorage` implementation (Durable Object
//! SQLite put-if-absent) eliminates windows 1 and 2 entirely; retaining
//! nonce records for the whole session lifetime eliminates window 3.
//!
//! ## Refusals are the middleware's own 401 (0.4.1)
//!
//! Every authentication refusal `process_auth*` decides is an
//! `Ok(AuthResult::Response(..))`: status 401, the body
//! `{"status":"error","code":..,"description":..}` (the reference's `message`
//! field for `UNAUTHORIZED`), the CORS headers, unsigned (there is no session
//! to sign with). The codes: `UNAUTHORIZED` (no auth headers),
//! `ERR_SESSION_NOT_FOUND` (no session for the nonce or identity named),
//! `ERR_INVALID_AUTH` (the header's identity is not the session's; the
//! signature is missing or wrong; the session never completed its handshake;
//! a general message without its per-request nonce; headers that do not form
//! a BRC-103 message; a handshake message refused), `ERR_REPLAYED_REQUEST`
//! (the per-request nonce already used). `Err` is a fault only: storage, the
//! server's own key, the transport, the SDK. 0.4.0 raised three of the
//! refusals as `Err(AuthCloudflareError::InvalidAuthentication(..))`, which
//! every host rendered as a generic 500, and the clients that re-handshake
//! on 401 only (`AuthFetch` among them) never recovered a stale session.
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
use crate::types::{current_time_ms, AuthContext, ErrorResponse, StoredSession};
use bsv_middleware_core::auth as core_auth;
use bsv_middleware_core::brc104::signable_response_headers;
use bsv_middleware_core::SessionBinding;
use bsv_sdk::auth::types::{AuthMessage, MessageType, RequestedCertificateSet};
use bsv_sdk::auth::VerifiableCertificate;
use bsv_sdk::primitives::PrivateKey;
use bsv_sdk::wallet::ProtoWallet;
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
    /// Callback when certificates are received.
    #[allow(clippy::type_complexity)]
    pub on_certificates_received:
        Option<Box<dyn Fn(String, Vec<VerifiableCertificate>) + Send + Sync>>,
    /// Session lane (0.3.4, `middleware::session_lane`): when set, the client's
    /// FIRST BRC-104-signed general message carrying the explicit ask
    /// (`x-low-lane-ask`) is answered with a lane offer (the unsigned handshake
    /// never mints), and `process_auth_lane*` serves laned calls. `None`
    /// (the default) = the reference behaviour byte-for-byte.
    pub session_lane: Option<SessionLaneOptions>,
}

impl Default for AuthMiddlewareOptions {
    fn default() -> Self {
        Self {
            server_private_key: String::new(),
            allow_unauthenticated: false,
            certificates_to_request: None,
            session_ttl_seconds: 3600,
            on_certificates_received: None,
            session_lane: None,
        }
    }
}

/// The session lane's knobs (`AuthMiddlewareOptions::session_lane`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLaneOptions {
    /// The domain separator inside `K`'s derivation; every server on one label
    /// shares the vectors. Default `session_lane::DEFAULT_LABEL`.
    pub label: Vec<u8>,
    /// The idle window a verified call refreshes. Default `session_lane::LANE_IDLE_MS`.
    pub idle_ms: u64,
}

impl Default for SessionLaneOptions {
    fn default() -> Self {
        Self {
            label: lane::DEFAULT_LABEL.to_vec(),
            idle_ms: lane::LANE_IDLE_MS,
        }
    }
}

/// A verified laned call: what the door needs to bind the caller and to seal
/// its answer (`seal_lane_response`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneAuth {
    pub id: String,
    /// The lane's identity (66 hex, lowercase) — the handshake's peer.
    pub identity: String,
    /// `K`, hex — the answer is sealed under it.
    pub key: String,
    /// The request's counter — the answer carries the same `h`.
    pub h: u64,
}

/// `process_auth_lane*`'s answer. `Reference` wraps the unchanged reference
/// outcome (a handshake reply, a BRC-104 verified request, a refusal) so an
/// adopter's existing `match` on [`AuthResult`] keeps working.
pub enum LaneAuthResult {
    /// The request rode the lane: verified by the store, the body captured.
    Laned {
        context: AuthContext,
        request: Request,
        body: Vec<u8>,
        lane: LaneAuth,
    },
    /// The reference outcome (`Authenticated`, always) PLUS a freshly minted
    /// lane offer the adopter must attach to its SIGNED answer as the
    /// `session_lane::LANE_OFFER_HEADER` extra header (a signable `x-bsv-`
    /// header: the reference signs it, the client's verification covers it).
    /// Minted only for a BRC-104-authenticated general message that carried
    /// the ask, under the VERIFIED identity — never on the handshake.
    Offered {
        auth: AuthResult,
        offer: lane::LaneOffer,
    },
    Reference(AuthResult),
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

/// The three fields the BRC-103 signatures are keyed on, for the core's
/// sign and verify functions.
impl From<&AuthSession> for SessionBinding {
    fn from(session: &AuthSession) -> Self {
        SessionBinding::new(
            session.session_nonce.clone(),
            session.peer_identity_key.clone(),
            session.peer_nonce.clone(),
        )
    }
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
    /// This happens for handshake requests and error responses: every
    /// authentication refusal is one of these, a 401 (0.4.1); an `Err` from
    /// `process_auth*` is a fault (storage, the server's key, the transport).
    Response(Response),
}

const ORIGINATOR: &str = "bsv-auth-cloudflare";

use crate::middleware::session_lane as lane;
use crate::storage::session_storage::LaneVerifyAsk;

/// Why the door refused a request: rendered by [`refusal_response`] as the
/// middleware's own 401 (0.4.1). Before, three of these were an `Err` every
/// host rendered as a generic 500, and the clients that re-handshake on 401
/// only (`AuthFetch` among them) never recovered a stale session. A fault
/// (storage, the server's own key, the transport, the SDK) is never one of
/// these: it stays `Err`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthRefusal {
    /// No BRC-104 auth headers and `allow_unauthenticated` is off →
    /// `UNAUTHORIZED` (the reference's body: the `message` field).
    NoAuthHeaders,
    /// The request is not a BRC-103 message for this server: the transport
    /// could not read one from the headers (the identity key missing or not
    /// a key, an unknown message type), a handshake body that does not
    /// parse, a certificate message whose signature or certificates fail →
    /// `ERR_INVALID_AUTH`, the reason as the description.
    InvalidMessage(String),
    /// No session for the nonce (or identity) named → `ERR_SESSION_NOT_FOUND`.
    SessionNotFound,
    /// The session exists but its handshake never completed → `ERR_INVALID_AUTH`.
    SessionNotAuthenticated,
    /// The identity in the header is not the session's (the 2026-09-14
    /// delta-verify NEW-1) → `ERR_INVALID_AUTH`.
    IdentityNotSessions,
    /// The signature is missing or does not verify under the session's
    /// identity → `ERR_INVALID_AUTH`.
    InvalidSignature(String),
    /// A general message without `x-bsv-auth-nonce` → `ERR_INVALID_AUTH`.
    MissingNonce,
    /// The per-request nonce was already consumed for this session (audit
    /// #30) → `ERR_REPLAYED_REQUEST`.
    Replayed,
}

impl AuthRefusal {
    /// Every refusal is a 401.
    const STATUS: u16 = 401;

    /// The wire code (the reference's where it has one; `ERR_REPLAYED_REQUEST`
    /// is this crate's).
    fn code(&self) -> &'static str {
        match self {
            Self::NoAuthHeaders => "UNAUTHORIZED",
            Self::SessionNotFound => "ERR_SESSION_NOT_FOUND",
            Self::Replayed => "ERR_REPLAYED_REQUEST",
            Self::InvalidMessage(_)
            | Self::SessionNotAuthenticated
            | Self::IdentityNotSessions
            | Self::InvalidSignature(_)
            | Self::MissingNonce => "ERR_INVALID_AUTH",
        }
    }

    /// The body's text (the 0.3 wire texts where a 401 already existed).
    fn description(&self) -> String {
        match self {
            Self::NoAuthHeaders => "Mutual-authentication failed!".into(),
            Self::InvalidMessage(reason) | Self::InvalidSignature(reason) => reason.clone(),
            Self::SessionNotFound => "No authenticated session found".into(),
            Self::SessionNotAuthenticated => "Session not authenticated".into(),
            Self::IdentityNotSessions => "Message identity key is not the session's".into(),
            Self::MissingNonce => {
                "General message is missing the per-request nonce (x-bsv-auth-nonce).".into()
            }
            Self::Replayed => "The request nonce has already been used (replay rejected).".into(),
        }
    }

    /// An error raised below the door: the 401 class (what
    /// `AuthCloudflareError::status_code` has called 401 since 0.1) is a
    /// refusal; anything else is a fault and stays an `Err`.
    fn from_fault(e: AuthCloudflareError) -> std::result::Result<Self, AuthCloudflareError> {
        match e {
            AuthCloudflareError::Unauthorized => Ok(Self::NoAuthHeaders),
            AuthCloudflareError::InvalidAuthentication(reason) => Ok(Self::InvalidMessage(reason)),
            AuthCloudflareError::SessionNotFound(_) => Ok(Self::SessionNotFound),
            fault => Err(fault),
        }
    }
}

/// What the door decided about a general message, free of `Request` and
/// `Response` so the whole path runs under native `cargo test`.
#[derive(Debug)]
enum GeneralJudgement {
    /// Verified over its session (the per-request nonce consumed, the
    /// liveness touched): the session the answer is signed for.
    Accepted(StoredSession),
    /// Refused: the door answers 401 and serves nothing.
    Refused(AuthRefusal),
}

/// The 0.4.1 rule at the door: a refusal raised below it as an `Err` of the
/// 401 class becomes the middleware's own 401 answer; a fault stays `Err`.
fn settle(outcome: Result<AuthResult>) -> Result<AuthResult> {
    match outcome {
        Err(e) => {
            let refusal = AuthRefusal::from_fault(e)?;
            Ok(AuthResult::Response(refusal_response(&refusal)?))
        }
        ok => ok,
    }
}

/// Render a refusal as the middleware's own answer: 401, the wire body, the
/// CORS headers, unsigned (there is no session to sign with, as the 0.3 401s
/// already were). The ONE place a refusal becomes a `Response`.
fn refusal_response(refusal: &AuthRefusal) -> Result<Response> {
    let response = match refusal {
        // TS Express middleware wire format:
        //   { status: "error", code: "UNAUTHORIZED", message: "Mutual-authentication failed!" }
        // Field is `message` (not `description`) — verified against a live
        // TS server. Handler-layer errors use `description`; middleware-
        // layer auth errors use `message`. Mirror exactly.
        AuthRefusal::NoAuthHeaders => Response::from_json(&serde_json::json!({
            "status": "error",
            "code": refusal.code(),
            "message": refusal.description(),
        })),
        _ => Response::from_json(&ErrorResponse::new(refusal.code(), refusal.description())),
    }
    .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
    .with_status(AuthRefusal::STATUS);
    Ok(add_cors_headers(response))
}

/// Process authentication for a Cloudflare Worker request.
///
/// This is a 1:1 port of auth-express-middleware's `createAuthMiddleware`.
///
/// ## Flow:
/// 1. Handshake requests (`/.well-known/auth`) → processes handshake, returns Response
/// 2. Authenticated requests (with auth headers) → verifies signature, returns Authenticated
/// 3. Unauthenticated requests → returns 401 or allows through if configured
/// 4. A refused request → a 401 `AuthResult::Response` (0.4.1); `Err` is a fault only
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

/// `process_auth` over the Durable Object session backend: the
/// session record and the replay guard live in one object per session nonce
/// (`AuthSessionStore`, bound as `do_binding`), KV the cold path. See
/// `storage::do_session`.
pub async fn process_auth_do(
    req: Request,
    env: &Env,
    options: &AuthMiddlewareOptions,
    do_binding: &str,
) -> Result<AuthResult> {
    let storage =
        crate::storage::DoSessionStorage::from_env(env, do_binding, options.session_ttl_seconds)?;
    process_auth_with_storage(req, &storage, options).await
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
/// 4. A refused request → a 401 `AuthResult::Response` (0.4.1); `Err` is a fault only
pub async fn process_auth_with_storage<S: SessionStorage + ?Sized>(
    req: Request,
    session_storage: &S,
    options: &AuthMiddlewareOptions,
) -> Result<AuthResult> {
    settle(authenticate(req, session_storage, options).await)
}

/// The reference flow over the store, before the door settles it: the
/// general path's own refusals are already answers (`judge_general_message`);
/// a refusal raised below the door as an `Err` of the 401 class (the transport
/// could not read a BRC-103 message from the headers; a handshake message
/// refused) is rendered by [`settle`]; a fault stays `Err`.
async fn authenticate<S: SessionStorage + ?Sized>(
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
            return Ok(AuthResult::Response(refusal_response(
                &AuthRefusal::NoAuthHeaders,
            )?));
        }
    }

    // Extract request ID before consuming body
    let request_id = CloudflareTransport::get_request_id(&req).unwrap_or([0u8; 32]);

    // Extract auth message from request (also returns raw body bytes)
    let (auth_message, request_body, digest) =
        CloudflareTransport::extract_auth_message_digest(&mut req).await?;

    // The door's judgement of the general message (Request/Response-free,
    // so the whole path runs under native `cargo test`): a refusal is the
    // middleware's own 401, never an `Err` (0.4.1).
    let now_ms = current_time_ms();
    let session = match judge_general_message_digest(
        &wallet,
        &auth_message,
        session_storage,
        options,
        now_ms,
        digest,
    )
    .await?
    {
        GeneralJudgement::Accepted(session) => session,
        GeneralJudgement::Refused(refusal) => {
            return Ok(AuthResult::Response(refusal_response(&refusal)?));
        }
    };

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

/// Judge a general message over the store: the session it names, its
/// identity binding (NEW-1), its signature under the SESSION's identity, its
/// per-request nonce (single-use, audit #30), then the liveness touch. Every
/// refusal is a value ([`AuthRefusal`], rendered 401 by the door); `Err` is a
/// storage or SDK fault only. Free of `Request`, `Response` and the clock
/// (`now_ms` is the caller's), so the whole path executes under native
/// `cargo test` (as the payment path's `decide_payment` does, audit finding
/// #62).
async fn judge_general_message_digest<S: SessionStorage + ?Sized>(
    wallet: &ProtoWallet,
    message: &AuthMessage,
    session_storage: &S,
    options: &AuthMiddlewareOptions,
    now_ms: u64,
    digest: Option<[u8; 32]>,
) -> Result<GeneralJudgement> {
    use GeneralJudgement::Refused;

    // Get session by peer's identity key or nonce
    let identity_key_hex = message.identity_key.to_hex();
    let session_nonce = message.your_nonce.as_ref().or(message.nonce.as_ref());

    // The combined hot path: a backend that answers "is this session live?" and "has
    // this request nonce been seen?" from ONE place (the Durable Object
    // backend) answers both in one round trip here; every other backend says
    // "unsupported" and takes the two-step path below, unchanged. The nonce
    // is then consumed before the signature check — harmless (an
    // unverifiable request's nonce is nobody else's) and never weaker.
    let request_nonce_opt = message.nonce.as_deref().filter(|n| !n.is_empty());
    let mut combined_fresh: Option<bool> = None;
    let session = if let Some(nonce) = session_nonce {
        match request_nonce_opt {
            Some(rn) => match session_storage
                .get_session_and_consume(nonce, rn, Some(options.session_ttl_seconds))
                .await?
            {
                Some((s, fresh)) => {
                    combined_fresh = Some(fresh);
                    s
                }
                None => session_storage.get_session(nonce).await?,
            },
            None => session_storage.get_session(nonce).await?,
        }
    } else {
        session_storage
            .get_session_by_identity(&identity_key_hex)
            .await?
    };

    let Some(session) = session else {
        return Ok(Refused(AuthRefusal::SessionNotFound));
    };

    if !session.is_authenticated {
        return Ok(Refused(AuthRefusal::SessionNotAuthenticated));
    }

    // The signed identity IS the session's: a general message naming another
    // identity over this session is refused by name before its signature is
    // judged (the reference verifies with `peerSession.peerIdentityKey`; the
    // header is a claim — the 2026-09-14 delta-verify NEW-1).
    if !core_auth::message_identity_is_sessions(message, &SessionBinding::from(&session)) {
        return Ok(Refused(AuthRefusal::IdentityNotSessions));
    }

    // Verify signature: `false` and the core's "not a message for this
    // session" (unsigned) are refusals; a fault below stays an `Err`.
    let signature_valid = match digest {
        Some(digest) => core_auth::verify_message_digest(
            wallet,
            message,
            &SessionBinding::from(&session),
            digest,
        )
        .map_err(AuthCloudflareError::from),
        None => verify_message_signature(wallet, message, &session),
    };
    match signature_valid {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Refused(AuthRefusal::InvalidSignature(
                "Invalid message signature".into(),
            )))
        }
        Err(AuthCloudflareError::InvalidAuthentication(reason)) => {
            return Ok(Refused(AuthRefusal::InvalidSignature(reason)))
        }
        Err(fault) => return Err(fault),
    }

    // Replay protection (audit finding #30): consume the per-request
    // nonce so a byte-identical replay of a signed request is rejected.
    //
    // Reference behavior: the TS stack (@bsv/auth-express-middleware 1.2.3 →
    // @bsv/sdk Peer.processGeneralMessage, verified through v2.0.13) checks
    // only that yourNonce is a server-created HMAC nonce (verifyNonce) and
    // binds message.nonce into the signature keyID
    // (`${message.nonce} ${peerSession.sessionNonce}`) — it never RECORDS a
    // consumed nonce, so replays re-execute there too. This check is a
    // deliberate hardening divergence from the reference.
    //
    // The per-request nonce (x-bsv-auth-nonce) is the right dedup key: it is
    // key-derivation input for the signature, so an attacker cannot alter it
    // without invalidating the signature. Scope = the server session nonce
    // (unique per session), so identical client nonces across sessions don't
    // collide.
    //
    // Placement: after signature verification (unauthenticated garbage must
    // not write to the nonce store) and before ANY side effect (liveness
    // touch, handler execution).
    //
    // TTL: the nonce record lives `session_ttl_seconds`. See the module docs
    // for the exact residual-replay window this leaves under KV and under
    // sliding session renewal.
    let request_nonce = match message.nonce.as_deref() {
        Some(n) if !n.is_empty() => n,
        // Honest BRC-104 clients always send x-bsv-auth-nonce on General
        // messages (SimplifiedFetchTransport sets it unconditionally).
        // Without it replay protection is impossible — reject.
        _ => return Ok(Refused(AuthRefusal::MissingNonce)),
    };

    // Fail closed on storage errors (`?`): a nonce-store outage must not
    // silently disable replay protection. Each nonce key is unique, so this
    // write cannot hit Cloudflare KV's ~1-write/sec/key limit the way the
    // (shared-key) liveness touch could.
    let nonce_fresh = match combined_fresh {
        Some(fresh) => fresh, // consumed in the one-round-trip read above (W-D)
        None => {
            session_storage
                .try_consume_nonce(
                    &session.session_nonce,
                    request_nonce,
                    Some(options.session_ttl_seconds),
                )
                .await?
        }
    };
    if !nonce_fresh {
        return Ok(Refused(AuthRefusal::Replayed));
    }

    // Update session last activity (but NOT peer_nonce).
    // In the TS SDK, peerSession.peerNonce is set ONCE during handshake and
    // NEVER updated for General messages. The client's per-message nonce is a
    // random value (not wallet-derived). If we store it as peer_nonce:
    //   1. Response yourNonce = random nonce → client's verifyNonce fails
    //   2. processGeneralMessage throws → general message callbacks never fire
    //   3. AuthFetch Promise never resolves → 402 payment handling breaks
    //   4. Signature keyID mismatch (uses peer_nonce, client expects handshake nonce)
    // Liveness touch — a sliding-window TTL refresh ONLY. The auth signature was
    // already verified above, so this write is NOT part of authentication and
    // must never fail an authenticated request. Two guards keep it from
    // hammering one Cloudflare KV key past the ~1-write/sec/key limit (which
    // returns 429 — previously surfacing as a 500 on every polled General
    // request, e.g. message-box `/listMessages` backfill):
    //   (a) LAZY — only refresh once past the half-TTL mark, so writes to a
    //       session key are spaced ~ttl/2 apart (hours) regardless of request
    //       rate, while the sliding window still never lapses under activity;
    //   (b) BEST-EFFORT — a write failure (KV 429, transient KV error) is logged
    //       and ignored; the session's existing TTL is still valid, so the
    //       request proceeds authenticated.
    let refresh_after_ms = options.session_ttl_seconds.saturating_mul(1000) / 2;
    if now_ms.saturating_sub(session.last_update) >= refresh_after_ms {
        let mut updated_session = session.clone();
        updated_session.last_update = now_ms;
        if let Err(e) = session_storage.update_session(&updated_session).await {
            worker::console_warn!("BRC-31 session liveness touch skipped (non-fatal): {e:?}");
        }
    }

    Ok(GeneralJudgement::Accepted(session))
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

    // A signed General message over the payload (the core: a fresh random
    // nonce, your_nonce = the peer's HANDSHAKE nonce, signed for the session).
    let msg =
        core_auth::sign_http_response(&wallet, &SessionBinding::from(session), &response_data)?;

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

    // Step 4: Create wallet
    let private_key = PrivateKey::from_hex(&session.server_private_key).map_err(|e| {
        AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
    })?;
    let wallet = ProtoWallet::new(Some(private_key));

    // Step 5: Create and sign a General AuthMessage over the payload (the
    // core: a fresh random nonce, your_nonce = the peer's HANDSHAKE nonce).
    let msg =
        core_auth::sign_http_response(&wallet, &SessionBinding::from(session), &response_data)?;

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
    signable_response_headers(headers)
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

    // Create our session nonce (matches Peer: create_nonce with counterparty=Self)
    let session_nonce = core_auth::create_session_nonce(wallet, ORIGINATOR).await?;

    // Get the peer's nonce (initial_nonce from the InitialRequest)
    let peer_nonce = message.initial_nonce.clone().or(message.nonce.clone());

    // Create and save session
    let mut session = StoredSession::new(session_nonce, peer_identity_key);
    session.peer_nonce = peer_nonce;
    session.is_authenticated = true;

    // Check if certificates are required
    if options.certificates_to_request.is_some() {
        session.certificates_required = true;
    }

    session_storage.save_session(&session).await?;

    // Build and sign the InitialResponse (the core, matching Peer's
    // process_initial_request):
    //   nonce = our session nonce (same as initial_nonce)
    //   initial_nonce = our session nonce
    //   your_nonce = peer's nonce (echoed back)
    //   requested_certificates = ours, if configured
    //   signature = signature over (your_nonce || initial_nonce)
    let response_msg = core_auth::build_initial_response(
        wallet,
        &SessionBinding::from(&session),
        options.certificates_to_request.clone(),
    )?;

    // Build response with auth headers
    let auth_headers = CloudflareTransport::message_to_headers(&response_msg);
    let headers = Headers::new();
    for (key, value) in &auth_headers {
        let _ = headers.set(key, value);
    }

    // Session lane (0.3.4): the InitialResponse NEVER offers a lane. The
    // initialRequest is unsigned — its identity is a claim (the 2026-09-14
    // gate HIGH-1: a stranger could mint a lane under any identity) — so the
    // offer rides the answer to the client's FIRST BRC-104-SIGNED general
    // message instead (`process_auth_lane_with_storage`, `LaneAuthResult::Offered`).
    let response = Response::from_json(&response_msg)
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_headers(headers);
    Ok(AuthResult::Response(add_cors_headers(response)))
}

/// Mint a lane for a proven handshake and store it; `None` when the store
/// keeps no lanes or the mint could not be stored (the reference reply stands:
/// a lane is never owed).
async fn mint_lane_offer<S: SessionStorage + ?Sized>(
    session_storage: &S,
    lane_opts: &SessionLaneOptions,
    peer_identity_key: &str,
    client_nonce: &str,
    server_nonce: &str,
    ask: &str,
) -> Option<lane::LaneOffer> {
    let mut random = [0u8; 64];
    if let Err(e) = getrandom::getrandom(&mut random) {
        worker::console_warn!("session lane: no randomness ({e}); the reference reply stands");
        return None;
    }
    let (record, offer) = lane::LaneRecord::mint(
        &lane_opts.label,
        &lane::Handshake {
            identity: peer_identity_key,
            client_nonce,
            server_nonce,
        },
        &random,
        current_time_ms(),
        lane_opts.idle_ms,
        ask,
    );
    match session_storage.lane_put(&record).await {
        Ok(true) => Some(offer),
        Ok(false) => None,
        Err(e) => {
            worker::console_warn!(
                "session lane: the store refused the mint ({e:?}); the reference reply stands"
            );
            None
        }
    }
}

/// The attested mint (2026-09-14): mint a lane for an identity a first-party
/// AUTHORITY has proven (the relay's hub mirror, asked by the door through its
/// service binding) — the same `LaneRecord::mint` as the signed-read mint, the
/// same label, idle window and lifetime; only the proof differs, and the door
/// owns that proof. `client_nonce` is the client's fresh nonce from the attest
/// body, `server_nonce` the door's fresh nonce it answers alongside the offer
/// (the client derives K from both exactly as for a signed-read mint). `None`
/// when the store keeps no lanes or the mint could not be stored.
pub async fn mint_attested_lane<S: SessionStorage + ?Sized>(
    session_storage: &S,
    lane_opts: &SessionLaneOptions,
    proven_identity_key: &str,
    client_nonce: &str,
    server_nonce: &str,
    ask: &str,
) -> Option<lane::LaneOffer> {
    mint_lane_offer(
        session_storage,
        lane_opts,
        proven_identity_key,
        client_nonce,
        server_nonce,
        ask,
    )
    .await
}

/// `process_auth_lane` over the Durable Object session backend: a laned
/// request (the `x-low-session*` headers) is verified by the lane's object and
/// answered `Laned`; an AUTHENTICATED general message carrying `x-low-lane-ask`
/// earns an offer (`Offered`, attached by the adopter to its signed answer);
/// everything else takes [`process_auth_do`]'s path unchanged.
pub async fn process_auth_lane(
    req: Request,
    env: &Env,
    options: &AuthMiddlewareOptions,
    do_binding: &str,
) -> Result<LaneAuthResult> {
    let storage =
        crate::storage::DoSessionStorage::from_env(env, do_binding, options.session_ttl_seconds)?;
    process_auth_lane_with_storage(req, &storage, options).await
}

/// [`process_auth_lane`] over a caller-supplied store. A store that keeps no
/// lanes (the KV default) answers a laned call 503 `lane-unsupported` (the
/// client falls back to the reference path) and never offers one.
pub async fn process_auth_lane_with_storage<S: SessionStorage + ?Sized>(
    mut req: Request,
    session_storage: &S,
    options: &AuthMiddlewareOptions,
) -> Result<LaneAuthResult> {
    let (parsed, ask_header, client_nonce_header) = {
        let headers = req.headers();
        let get = |name: &str| headers.get(name).ok().flatten();
        (
            lane::parse_lane_headers(
                get(lane::SESSION_HEADER).as_deref(),
                get(lane::SESSION_IDENTITY_HEADER).as_deref(),
                get(lane::SESSION_COUNTER_HEADER).as_deref(),
                get(lane::SESSION_MAC_HEADER).as_deref(),
            ),
            get(lane::LANE_ASK_HEADER),
            // The asking general message's OWN nonce (the reference verifies
            // it inside the signed payload): the client-side half of K.
            get(auth_headers::NONCE).filter(|n| !n.trim().is_empty()),
        )
    };
    let laned = match parsed {
        Err(r) => {
            return Ok(LaneAuthResult::Reference(AuthResult::Response(
                lane_refusal_response(r.as_str(), 401)?,
            )))
        }
        Ok(None) => None,
        Ok(Some(l)) => Some(l),
    };
    if let Some(lr) = laned {
        let method = req.method().as_ref().to_ascii_uppercase();
        let url = req
            .url()
            .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?;
        let path_and_query = lane::path_and_query(url.path(), url.query());
        let body = req
            .bytes()
            .await
            .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?;
        let ask = LaneVerifyAsk {
            id: lr.id.clone(),
            identity: lr.identity.clone(),
            h: lr.h,
            method,
            path_and_query,
            body_sha256: hex::encode(lane::body_digest(&body)),
            mac: lr.mac.clone(),
        };
        let verdict = match session_storage.lane_verify(&ask).await {
            Ok(Some(v)) => v,
            Ok(None) => {
                return Ok(LaneAuthResult::Reference(AuthResult::Response(
                    lane_refusal_response("lane-unsupported", 503)?,
                )))
            }
            Err(e) => {
                worker::console_warn!("session lane: the store could not be asked ({e:?})");
                return Ok(LaneAuthResult::Reference(AuthResult::Response(
                    lane_refusal_response("lane-unavailable", 503)?,
                )));
            }
        };
        if !verdict.ok {
            return Ok(LaneAuthResult::Reference(AuthResult::Response(
                lane_refusal_response(verdict.reason.as_deref().unwrap_or("unknown-session"), 401)?,
            )));
        }
        let identity = verdict.identity.unwrap_or(lr.identity).to_ascii_lowercase();
        let key = verdict.key.unwrap_or_default();
        return Ok(LaneAuthResult::Laned {
            context: AuthContext::authenticated(identity.clone()),
            request: req,
            body,
            lane: LaneAuth {
                id: lr.id,
                identity,
                key,
                h: lr.h,
            },
        });
    }
    if CloudflareTransport::is_handshake_request(&req) {
        let private_key = PrivateKey::from_hex(&options.server_private_key).map_err(|e| {
            AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
        })?;
        let wallet = ProtoWallet::new(Some(private_key));
        return Ok(LaneAuthResult::Reference(settle(
            handle_handshake_request(req, &wallet, session_storage, options).await,
        )?));
    }
    // The reference path judges the general message (the BRC-104 signature
    // over the payload, the session, the per-request nonce). Only a request it
    // AUTHENTICATED can earn a lane: the ask + the request's own nonce + the
    // session's server nonce mint one under the VERIFIED identity, and the
    // offer rides the adopter's signed answer (`x-bsv-lane-offer`).
    let auth = process_auth_with_storage(req, session_storage, options).await?;
    let ask = lane::parse_ask(ask_header.as_deref());
    if let (Some(lane_opts), Some(ask), Some(client_nonce)) =
        (options.session_lane.as_ref(), ask, client_nonce_header)
    {
        if let AuthResult::Authenticated {
            context,
            session: Some(session),
            ..
        } = &auth
        {
            if let Some(offer) = mint_lane_offer(
                session_storage,
                lane_opts,
                &context.identity_key,
                &client_nonce,
                &session.session_nonce,
                &ask,
            )
            .await
            {
                return Ok(LaneAuthResult::Offered { auth, offer });
            }
        }
    }
    Ok(LaneAuthResult::Reference(auth))
}

/// Whether a request presents the lane (the `x-low-session` header) — the
/// adopter's front door counts it as an auth ATTEMPT (never silently anonymous)
/// without reading a header itself.
pub fn request_presents_lane(req: &Request) -> bool {
    req.headers()
        .get(lane::SESSION_HEADER)
        .ok()
        .flatten()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// The lane's refusal: 401 `ERR_SESSION_REFUSED {reason}` (503 when the store
/// could not be asked: the client falls back rather than reads "refused").
fn lane_refusal_response(reason: &str, status: u16) -> Result<Response> {
    let body = serde_json::json!({
        "status": "error",
        "code": lane::HTTP_REFUSED_CODE,
        "reason": reason,
        "description": format!("session lane refused: {reason}"),
    });
    let resp = Response::from_json(&body)
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_status(status);
    let _ = resp.headers().set("Cache-Control", "no-store");
    Ok(add_lane_cors_headers(add_cors_headers(resp)))
}

/// Seal a laned answer: the body as JSON text, `x-low-session-n` = the request's
/// `h`, `x-low-session-mac` over it under `K`, `no-store`, the CORS lists.
pub fn seal_lane_response<T: Serialize>(
    data: &T,
    status: u16,
    auth: &LaneAuth,
) -> Result<Response> {
    let text = serde_json::to_string(data)
        .map_err(|e| AuthCloudflareError::SerializationError(e.to_string()))?;
    seal_lane_response_text(text, status, auth)
}

/// [`seal_lane_response`] for a body already serialized: the exact bytes sent
/// are the bytes MAC'd.
pub fn seal_lane_response_text(text: String, status: u16, auth: &LaneAuth) -> Result<Response> {
    let mac = lane::response_mac(&auth.key, auth.h, &text).ok_or_else(|| {
        AuthCloudflareError::ConfigError("session lane: the key is not hex".into())
    })?;
    let resp = Response::from_bytes(text.into_bytes())
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_status(status);
    let headers = resp.headers();
    let _ = headers.set("Content-Type", "application/json");
    let _ = headers.set("Cache-Control", "no-store");
    let _ = headers.set(lane::SESSION_COUNTER_HEADER, &auth.h.to_string());
    let _ = headers.set(lane::SESSION_MAC_HEADER, &mac);
    Ok(add_lane_cors_headers(add_cors_headers(resp)))
}

/// Append the lane's headers to the reference CORS lists (allowed on the
/// request, exposed on the answer). Idempotent.
pub fn add_lane_cors_headers(response: Response) -> Response {
    let headers = response.headers();
    let allow = headers
        .get("Access-Control-Allow-Headers")
        .ok()
        .flatten()
        .unwrap_or_default();
    if !allow.contains(lane::SESSION_HEADER) {
        let _ = headers.set(
            "Access-Control-Allow-Headers",
            &format!(
                "{}, {}, {}, {}, {}, {}",
                allow,
                lane::SESSION_HEADER,
                lane::SESSION_IDENTITY_HEADER,
                lane::SESSION_COUNTER_HEADER,
                lane::SESSION_MAC_HEADER,
                lane::LANE_ASK_HEADER
            ),
        );
    }
    let expose = headers
        .get("Access-Control-Expose-Headers")
        .ok()
        .flatten()
        .unwrap_or_default();
    if !expose.contains(lane::SESSION_MAC_HEADER) {
        let _ = headers.set(
            "Access-Control-Expose-Headers",
            &format!(
                "{}, {}, {}, {}, Retry-After",
                expose,
                lane::SESSION_COUNTER_HEADER,
                lane::SESSION_MAC_HEADER,
                lane::LANE_OFFER_HEADER
            ),
        );
    }
    response
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

    // Build and sign the CertificateResponse (the core).
    let response_msg = core_auth::build_certificate_response(
        wallet,
        &SessionBinding::from(&session),
        certificates,
    )?;

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

/// Verify an auth message signature
/// (`bsv_middleware_core::auth::verify_message_signature`): the counterparty
/// is the SESSION's peer identity, never the message header's.
fn verify_message_signature(
    wallet: &ProtoWallet,
    message: &AuthMessage,
    session: &StoredSession,
) -> Result<bool> {
    Ok(core_auth::verify_message_signature(
        wallet,
        message,
        &SessionBinding::from(session),
    )?)
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
            "{}, {}, {}, {}, {}, {}, {}, x-bsv-payment-satoshis-paid, x-bsv-payment-version, x-bsv-payment-satoshis-required, x-bsv-payment-derivation-prefix, x-bsv-payment-txid, {}, Retry-After",
            auth_headers::VERSION,
            auth_headers::IDENTITY_KEY,
            auth_headers::NONCE,
            auth_headers::YOUR_NONCE,
            auth_headers::SIGNATURE,
            auth_headers::MESSAGE_TYPE,
            auth_headers::REQUEST_ID,
            // The lane offer rides a SIGNED response header; a cross-origin
            // fetch only sees EXPOSED headers, and the SDK rebuilds the signed
            // payload from what it sees — unexposed, the offer is invisible AND
            // the answer's signature never verifies (the 2026-09-14
            // delta-verify NEW-2).
            lane::LANE_OFFER_HEADER
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
    async fn judge_general_message<S: SessionStorage + ?Sized>(
        wallet: &ProtoWallet,
        message: &AuthMessage,
        session_storage: &S,
        options: &AuthMiddlewareOptions,
        now_ms: u64,
    ) -> Result<GeneralJudgement> {
        judge_general_message_digest(wallet, message, session_storage, options, now_ms, None).await
    }

    use super::*;
    use bsv_sdk::primitives::PrivateKey;

    /// Sign an auth message (`bsv_middleware_core::auth::sign_message` over
    /// the session's binding), as the 0.3 tests called it; production paths
    /// build their messages through the core directly.
    fn sign_message(
        wallet: &ProtoWallet,
        message: &mut AuthMessage,
        session: &StoredSession,
    ) -> Result<()> {
        Ok(core_auth::sign_message(
            wallet,
            message,
            &SessionBinding::from(session),
        )?)
    }

    /// A random per-message nonce (`bsv_middleware_core::auth::generate_random_nonce`).
    fn generate_random_nonce() -> String {
        core_auth::generate_random_nonce()
    }

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

    /// The 2026-09-14 gate HIGH-1, pinned at the source: the handshake path
    /// (`handle_initial_request`, the unsigned initialRequest) contains NO mint,
    /// and the only mint site sits inside the `AuthResult::Authenticated` arm
    /// of `process_auth_lane_with_storage` — a lane binds a PROVEN identity.
    #[test]
    fn the_lane_mints_only_for_an_authenticated_general_message_never_on_the_handshake() {
        // The crate's own source up to its tests (this pin's own literals excluded).
        let whole = include_str!("auth.rs");
        let src = &whole[..whole.find("#[cfg(test)]").unwrap()];
        let initial = &src[src.find("async fn handle_initial_request").unwrap()
            ..src.find("/// Mint a lane for a proven").unwrap()];
        assert!(
            !initial.contains("mint_lane_offer("),
            "the handshake path must not mint"
        );
        assert!(
            initial.contains("NEVER offers a lane"),
            "the handshake path states why"
        );
        let lane_fn = &src[src
            .find("pub async fn process_auth_lane_with_storage")
            .unwrap()
            ..src.find("pub fn request_presents_lane").unwrap()];
        assert_eq!(
            lane_fn.matches("mint_lane_offer(").count(),
            1,
            "exactly one mint site"
        );
        let mint_at = lane_fn.find("mint_lane_offer(").unwrap();
        let auth_arm = lane_fn.find("if let AuthResult::Authenticated {").unwrap();
        assert!(
            auth_arm < mint_at,
            "the mint sits inside the Authenticated arm"
        );
        assert!(
            lane_fn[..mint_at]
                .contains("process_auth_with_storage(req, session_storage, options).await?"),
            "the reference path judges the message BEFORE any mint"
        );
        assert_eq!(
            src.matches("mint_lane_offer(").count(),
            2,
            "exactly two CALL sites: the Authenticated arm and the step-4 attested wrapper (the definition carries generics before its paren)"
        );
        let wrapper = &src[src.find("pub async fn mint_attested_lane").unwrap()..];
        let wrapper = &wrapper[..wrapper.find("\n}\n").unwrap()];
        assert!(
            wrapper.contains("mint_lane_offer(") && !wrapper.contains("process_auth"),
            "the attested wrapper mints only; the door owns the proof"
        );
    }

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

    /// The 2026-09-14 delta-verify NEW-1: a general message is verified against
    /// the SESSION's identity (the reference's `peerSession.peerIdentityKey`),
    /// never the header's. Before this pin the header identity was the
    /// counterparty, so ANY wallet's honest signature verified under a session
    /// another identity's UNSIGNED initialRequest opened, and the context
    /// reported the victim.
    #[test]
    fn a_general_message_is_verified_against_the_session_s_identity_not_the_header_s() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let server_pk = test_key(SERVER_KEY_HEX);
        let victim_pk = test_key(CLIENT_KEY_HEX);
        let attacker_hex = "0000000000000000000000000000000000000000000000000000000000000003";
        let attacker_wallet = test_wallet(attacker_hex);
        let attacker_pk = test_key(attacker_hex);

        // The attacker names ITS OWN key in the header, rides the victim's
        // session nonce and signs honestly for its own key.
        let mut msg = AuthMessage::new(MessageType::General, attacker_pk.clone());
        msg.nonce = Some("attacker-nonce".to_string());
        msg.your_nonce = Some("victim-session-nonce".to_string());
        msg.payload = Some(vec![9, 9, 9]);
        let attacker_view = StoredSession {
            session_nonce: "attacker-nonce".to_string(),
            peer_identity_key: server_pk.to_hex(),
            peer_nonce: Some("victim-session-nonce".to_string()),
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };
        sign_message(&attacker_wallet, &mut msg, &attacker_view).unwrap();

        // The server's session: opened by an unsigned initialRequest CLAIMING the victim.
        let victim_session = StoredSession {
            session_nonce: "victim-session-nonce".to_string(),
            peer_identity_key: victim_pk.to_hex(),
            peer_nonce: Some("attacker-nonce".to_string()),
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        };
        assert!(
            !verify_message_signature(&server_wallet, &msg, &victim_session).unwrap(),
            "another key's signature over a session claiming the victim must NOT verify"
        );
        // The honest control: the same message over the session ITS identity opened.
        let own_session = StoredSession {
            peer_identity_key: attacker_pk.to_hex(),
            ..victim_session.clone()
        };
        assert!(verify_message_signature(&server_wallet, &msg, &own_session).unwrap());
        // A session whose identity is not a key verifies nothing (never a panic).
        let junk = StoredSession {
            peer_identity_key: "not-a-key".to_string(),
            ..victim_session
        };
        assert!(!verify_message_signature(&server_wallet, &msg, &junk).unwrap());
    }

    /// Structural: the general path refuses a header identity that is not the
    /// session's BEFORE the signature is judged, and the verify's counterparty
    /// is the session's identity (NEW-1); the lane offer header is EXPOSED by
    /// both CORS emitters (NEW-2: a cross-origin fetch sees exposed headers
    /// only, and the SDK rebuilds the signed payload from what it sees).
    #[test]
    fn the_general_path_binds_the_identity_and_the_offer_header_is_exposed() {
        let whole = include_str!("auth.rs");
        let src = &whole[..whole.find("#[cfg(test)]").unwrap()];
        let general = &src[src.find("pub async fn process_auth_with_storage").unwrap()..];
        let bind = general
            .find("core_auth::message_identity_is_sessions(")
            .expect("the identity binding");
        let verify = general
            .find("verify_message_signature(wallet, message, &session)")
            .expect("the verify call");
        assert!(bind < verify, "the binding precedes the signature check");
        // The verify is the core's, over the SESSION's binding (the core pins
        // its own counterparty: `bsv_middleware_core::auth` tests).
        let verify_fn = &src[src.find("fn verify_message_signature(").unwrap()..];
        let verify_fn = &verify_fn[..verify_fn.find("\n}\n").unwrap()];
        assert!(
            verify_fn.contains("core_auth::verify_message_signature(")
                && verify_fn.contains("SessionBinding::from(session)")
                && !verify_fn.contains("message.identity_key"),
            "the counterparty is the session's identity, never the header's"
        );
        for emitter in ["pub fn add_cors_headers(", "pub fn add_lane_cors_headers("] {
            let body = &src[src.find(emitter).unwrap()..];
            let body = &body[..body.find("\n}\n").unwrap()];
            let expose = body.find("Access-Control-Expose-Headers").expect(emitter);
            assert!(
                body[expose..].contains("lane::LANE_OFFER_HEADER"),
                "{emitter} exposes the lane offer header"
            );
            assert!(
                body[expose..].contains("Retry-After"),
                "{emitter} exposes the payment retry delay"
            );
        }
    }
    // ===========================================
    // 0.4.1: an authentication refusal is the door's own 401, never an Err
    // ===========================================

    use crate::storage::session_storage::MemorySessionStorage;

    const SERVER_SESSION_NONCE: &str = "server-session-nonce";
    const CLIENT_HANDSHAKE_NONCE: &str = "client-handshake-nonce";
    const OTHER_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000003";

    /// The server's record of the session `client_hex`'s handshake opened.
    fn session_for(client_hex: &str, authenticated: bool) -> StoredSession {
        StoredSession {
            session_nonce: SERVER_SESSION_NONCE.to_string(),
            peer_identity_key: test_key(client_hex).to_hex(),
            peer_nonce: Some(CLIENT_HANDSHAKE_NONCE.to_string()),
            is_authenticated: authenticated,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        }
    }

    /// A general message over the server's session: `claimed_hex` in the
    /// header, signed by `signer_hex` (honest when they are the same key).
    fn general_message(claimed_hex: &str, signer_hex: &str, nonce: &str) -> AuthMessage {
        let mut msg = AuthMessage::new(MessageType::General, test_key(claimed_hex));
        msg.nonce = Some(nonce.to_string());
        msg.your_nonce = Some(SERVER_SESSION_NONCE.to_string());
        msg.payload = Some(vec![1, 2, 3]);
        // The signer's view of the session: the server is its peer, the
        // server's session nonce its peer's nonce.
        let signer_view = StoredSession {
            session_nonce: CLIENT_HANDSHAKE_NONCE.to_string(),
            peer_identity_key: test_key(SERVER_KEY_HEX).to_hex(),
            peer_nonce: Some(SERVER_SESSION_NONCE.to_string()),
            ..session_for(claimed_hex, true)
        };
        sign_message(&test_wallet(signer_hex), &mut msg, &signer_view).unwrap();
        msg
    }

    fn door() -> AuthMiddlewareOptions {
        AuthMiddlewareOptions {
            server_private_key: SERVER_KEY_HEX.to_string(),
            ..Default::default()
        }
    }

    async fn store_with(session: StoredSession) -> MemorySessionStorage {
        let store = MemorySessionStorage::default();
        store.save_session(&session).await.unwrap();
        store
    }

    /// The door's judgement at `NOW_MS` (past the half-TTL mark of a session
    /// last touched at 0, so an accepted message also exercises the touch).
    const NOW_MS: u64 = 3_600_000;

    async fn judge(store: &MemorySessionStorage, msg: &AuthMessage) -> Result<GeneralJudgement> {
        judge_general_message(&test_wallet(SERVER_KEY_HEX), msg, store, &door(), NOW_MS).await
    }

    fn refused(judgement: Result<GeneralJudgement>) -> AuthRefusal {
        match judgement {
            Ok(GeneralJudgement::Refused(refusal)) => refusal,
            Ok(GeneralJudgement::Accepted(s)) => panic!("served {s:?}, expected a refusal"),
            Err(e) => panic!("an Err ({e:?}), expected a refusal"),
        }
    }

    #[tokio::test]
    async fn an_honest_general_message_is_accepted_and_its_nonce_consumed() {
        let store = store_with(session_for(CLIENT_KEY_HEX, true)).await;
        let msg = general_message(CLIENT_KEY_HEX, CLIENT_KEY_HEX, "nonce-1");
        match judge(&store, &msg).await.unwrap() {
            GeneralJudgement::Accepted(session) => {
                assert_eq!(session.peer_identity_key, test_key(CLIENT_KEY_HEX).to_hex());
            }
            GeneralJudgement::Refused(r) => panic!("refused: {r:?}"),
        }
        assert!(store.is_consumed(SERVER_SESSION_NONCE, "nonce-1"));
        // The liveness touch (past the half-TTL mark) wrote the caller's clock.
        let touched = store
            .get_session(SERVER_SESSION_NONCE)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(touched.last_update, NOW_MS);
    }

    /// The live gap (2026-10-08): a general message naming another identity
    /// over the session was `Err(InvalidAuthentication)`, a 500 at every host.
    #[tokio::test]
    async fn a_message_naming_another_identity_is_refused_401_not_err() {
        let store = store_with(session_for(CLIENT_KEY_HEX, true)).await;
        // The attacker names its own key and signs honestly for it.
        let msg = general_message(OTHER_KEY_HEX, OTHER_KEY_HEX, "nonce-1");
        let refusal = refused(judge(&store, &msg).await);
        assert_eq!(refusal, AuthRefusal::IdentityNotSessions);
        assert_eq!(refusal.code(), "ERR_INVALID_AUTH");
        assert_eq!(
            refusal.description(),
            "Message identity key is not the session's"
        );
        assert_eq!(
            store.consumed_count(),
            0,
            "nothing consumed, nothing served"
        );
    }

    #[tokio::test]
    async fn a_bad_or_missing_signature_is_refused_401_not_err() {
        let store = store_with(session_for(CLIENT_KEY_HEX, true)).await;
        // Another key's signature under the session's identity.
        let forged = general_message(CLIENT_KEY_HEX, OTHER_KEY_HEX, "nonce-1");
        let refusal = refused(judge(&store, &forged).await);
        assert!(
            matches!(refusal, AuthRefusal::InvalidSignature(_)),
            "{refusal:?}"
        );
        assert_eq!(refusal.code(), "ERR_INVALID_AUTH");
        assert_eq!(refusal.description(), "Invalid message signature");
        // A tampered payload.
        let mut tampered = general_message(CLIENT_KEY_HEX, CLIENT_KEY_HEX, "nonce-2");
        tampered.payload = Some(vec![9, 9, 9]);
        assert!(matches!(
            refused(judge(&store, &tampered).await),
            AuthRefusal::InvalidSignature(_)
        ));
        // No signature at all (the core's "Message not signed" was an Err too).
        let mut unsigned = general_message(CLIENT_KEY_HEX, CLIENT_KEY_HEX, "nonce-3");
        unsigned.signature = None;
        let refusal = refused(judge(&store, &unsigned).await);
        assert_eq!(
            refusal,
            AuthRefusal::InvalidSignature("Message not signed".into())
        );
        assert_eq!(
            store.consumed_count(),
            0,
            "nothing consumed, nothing served"
        );
    }

    #[tokio::test]
    async fn a_session_whose_handshake_never_completed_is_refused_401_not_err() {
        let store = store_with(session_for(CLIENT_KEY_HEX, false)).await;
        let msg = general_message(CLIENT_KEY_HEX, CLIENT_KEY_HEX, "nonce-1");
        let refusal = refused(judge(&store, &msg).await);
        assert_eq!(refusal, AuthRefusal::SessionNotAuthenticated);
        assert_eq!(refusal.code(), "ERR_INVALID_AUTH");
        assert_eq!(store.consumed_count(), 0);
    }

    #[tokio::test]
    async fn an_unknown_session_is_refused_session_not_found() {
        let store = MemorySessionStorage::default();
        let msg = general_message(CLIENT_KEY_HEX, CLIENT_KEY_HEX, "nonce-1");
        let refusal = refused(judge(&store, &msg).await);
        assert_eq!(refusal, AuthRefusal::SessionNotFound);
        assert_eq!(refusal.code(), "ERR_SESSION_NOT_FOUND");
        assert_eq!(refusal.description(), "No authenticated session found");
    }

    #[tokio::test]
    async fn a_general_message_without_a_per_request_nonce_is_refused() {
        let store = store_with(session_for(CLIENT_KEY_HEX, true)).await;
        let msg = general_message(CLIENT_KEY_HEX, CLIENT_KEY_HEX, "");
        let refusal = refused(judge(&store, &msg).await);
        assert_eq!(refusal, AuthRefusal::MissingNonce);
        assert_eq!(refusal.code(), "ERR_INVALID_AUTH");
        assert_eq!(store.consumed_count(), 0);
    }

    #[tokio::test]
    async fn a_replayed_nonce_is_refused_replayed_request() {
        let store = store_with(session_for(CLIENT_KEY_HEX, true)).await;
        let msg = general_message(CLIENT_KEY_HEX, CLIENT_KEY_HEX, "nonce-1");
        assert!(matches!(
            judge(&store, &msg).await.unwrap(),
            GeneralJudgement::Accepted(_)
        ));
        let refusal = refused(judge(&store, &msg).await);
        assert_eq!(refusal, AuthRefusal::Replayed);
        assert_eq!(refusal.code(), "ERR_REPLAYED_REQUEST");
        assert_eq!(store.consumed_count(), 1);
    }

    /// The compatibility proof: a storage fault is still an `Err` (the host's
    /// 500), never dressed as a refusal; replay protection fails closed.
    #[tokio::test]
    async fn a_storage_fault_is_still_an_err_never_a_refusal() {
        let store = store_with(session_for(CLIENT_KEY_HEX, true)).await;
        store.fail_consume(true);
        let msg = general_message(CLIENT_KEY_HEX, CLIENT_KEY_HEX, "nonce-1");
        let err = judge(&store, &msg).await.unwrap_err();
        assert!(matches!(err, AuthCloudflareError::KvError(_)), "{err:?}");
        assert_eq!(err.status_code(), 500);
    }

    /// Every refusal is a 401 with the code the reference (or the 0.3 wire)
    /// gave it, and the door settles exactly the 401-class errors raised
    /// below it: the class `AuthCloudflareError::status_code` has declared.
    #[test]
    fn every_refusal_is_a_401_with_its_code_and_only_the_401_class_settles() {
        let table = [
            (
                AuthRefusal::NoAuthHeaders,
                "UNAUTHORIZED",
                "Mutual-authentication failed!",
            ),
            (
                AuthRefusal::InvalidMessage("Missing identity key header".into()),
                "ERR_INVALID_AUTH",
                "Missing identity key header",
            ),
            (
                AuthRefusal::SessionNotFound,
                "ERR_SESSION_NOT_FOUND",
                "No authenticated session found",
            ),
            (
                AuthRefusal::SessionNotAuthenticated,
                "ERR_INVALID_AUTH",
                "Session not authenticated",
            ),
            (
                AuthRefusal::IdentityNotSessions,
                "ERR_INVALID_AUTH",
                "Message identity key is not the session's",
            ),
            (
                AuthRefusal::InvalidSignature("Invalid message signature".into()),
                "ERR_INVALID_AUTH",
                "Invalid message signature",
            ),
            (
                AuthRefusal::MissingNonce,
                "ERR_INVALID_AUTH",
                "General message is missing the per-request nonce (x-bsv-auth-nonce).",
            ),
            (
                AuthRefusal::Replayed,
                "ERR_REPLAYED_REQUEST",
                "The request nonce has already been used (replay rejected).",
            ),
        ];
        assert_eq!(AuthRefusal::STATUS, 401);
        for (refusal, code, description) in table {
            assert_eq!(refusal.code(), code, "{refusal:?}");
            assert_eq!(refusal.description(), description, "{refusal:?}");
        }
        let errors = vec![
            AuthCloudflareError::Unauthorized,
            AuthCloudflareError::InvalidAuthentication("Invalid identity key: x".into()),
            AuthCloudflareError::SessionNotFound("02ab".into()),
            AuthCloudflareError::KvError("kv".into()),
            AuthCloudflareError::SdkError("sdk".into()),
            AuthCloudflareError::TransportError("body".into()),
            AuthCloudflareError::ConfigError("key".into()),
            AuthCloudflareError::SerializationError("json".into()),
            AuthCloudflareError::ServerMisconfigured,
            AuthCloudflareError::PaymentFailed("x".into()),
        ];
        for e in errors {
            let is_refusal = e.status_code() == 401;
            let shown = format!("{e:?}");
            match AuthRefusal::from_fault(e) {
                Ok(r) => assert!(is_refusal, "{shown} settled as {r:?}"),
                Err(fault) => assert!(!is_refusal, "{shown} stayed Err({fault:?})"),
            }
        }
        assert_eq!(
            AuthRefusal::from_fault(AuthCloudflareError::InvalidAuthentication(
                "Invalid identity key: x".into()
            ))
            .unwrap(),
            AuthRefusal::InvalidMessage("Invalid identity key: x".into())
        );
        assert_eq!(
            AuthRefusal::from_fault(AuthCloudflareError::SessionNotFound("02ab".into())).unwrap(),
            AuthRefusal::SessionNotFound
        );
        assert_eq!(
            AuthRefusal::from_fault(AuthCloudflareError::Unauthorized).unwrap(),
            AuthRefusal::NoAuthHeaders
        );
    }

    /// Structural: every door answers through `settle` (the general path, and
    /// the lane's handshake call), the ONE renderer sets 401 and appends CORS,
    /// and no refusal is raised as an `Err` inside the general path.
    #[test]
    fn every_refusal_leaves_the_door_as_a_401_response_with_cors() {
        fn body_of<'a>(src: &'a str, name: &str) -> &'a str {
            let from = &src[src.find(name).unwrap_or_else(|| panic!("{name}"))..];
            &from[..from.find("\n}\n").unwrap()]
        }
        let whole = include_str!("auth.rs");
        let src = &whole[..whole.find("#[cfg(test)]").unwrap()];
        let door = body_of(src, "pub async fn process_auth_with_storage");
        assert!(
            door.contains("settle(authenticate(req, session_storage, options).await)"),
            "the door settles"
        );
        let lane = body_of(src, "pub async fn process_auth_lane_with_storage");
        let handshake = lane
            .find("handle_handshake_request(req, &wallet, session_storage, options).await")
            .unwrap();
        assert!(
            lane[..handshake].trim_end().ends_with("settle("),
            "the lane's handshake call settles"
        );
        let render = body_of(src, "fn refusal_response(");
        assert!(
            render.contains(".with_status(AuthRefusal::STATUS)")
                && render.contains("add_cors_headers(response)"),
            "one renderer: 401 + CORS"
        );
        assert_eq!(
            src.matches(".with_status(401)").count(),
            0,
            "no 401 is built by hand outside the renderer"
        );
        for path in ["async fn judge_general_message", "async fn authenticate"] {
            let body = body_of(src, path);
            assert!(
                !body.contains("return Err(AuthCloudflareError::"),
                "{path} raises no refusal as an Err"
            );
            assert!(
                !body.contains("AuthCloudflareError::InvalidAuthentication(\n")
                    && !body.contains("AuthCloudflareError::SessionNotFound("),
                "{path} builds no 401-class error"
            );
        }
        let settle_fn = body_of(src, "fn settle(");
        assert!(
            settle_fn.contains("AuthRefusal::from_fault(e)?")
                && settle_fn.contains("refusal_response(&refusal)?")
        );
    }
    #[tokio::test]
    async fn digest_authenticates_without_a_payload_copy_and_keeps_replay_protection() {
        use bsv_sdk::primitives::hash::sha256;
        let store = store_with(session_for(CLIENT_KEY_HEX, true)).await;
        let mut message = general_message(CLIENT_KEY_HEX, CLIENT_KEY_HEX, "digest-nonce");
        let digest: [u8; 32] = sha256(&message.signing_data());
        message.payload = None;
        let wallet = test_wallet(SERVER_KEY_HEX);
        let answer =
            judge_general_message_digest(&wallet, &message, &store, &door(), NOW_MS, Some(digest))
                .await
                .unwrap();
        assert!(matches!(answer, GeneralJudgement::Accepted(_)));
        let replay =
            judge_general_message_digest(&wallet, &message, &store, &door(), NOW_MS, Some(digest))
                .await;
        assert!(matches!(refused(replay), AuthRefusal::Replayed));
        let clean = store_with(session_for(CLIENT_KEY_HEX, true)).await;
        let mut bad = digest;
        bad[0] ^= 1;
        let answer =
            judge_general_message_digest(&wallet, &message, &clean, &door(), NOW_MS, Some(bad))
                .await;
        assert!(matches!(refused(answer), AuthRefusal::InvalidSignature(_)));
        assert_eq!(clean.consumed_count(), 0);
    }
}
