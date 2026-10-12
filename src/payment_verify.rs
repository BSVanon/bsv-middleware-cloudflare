//! BRC-29 payment verification before internalize: the Workers adapter over
//! `bsv_middleware_core`.
//!
//! The rules live in the core: the pays-us-correctly check
//! ([`bsv_middleware_core::brc29`]), the streaming reader's validity and
//! spends, the proof's presence and the SPV decision
//! ([`bsv_middleware_core::payment_verify`], [`bsv_middleware_core::spv`]),
//! and the six-word verdict ([`PaymentVerdict`]). This module keeps what is
//! bound to this runtime and to the 0.3 API:
//!
//! - [`UrlHeaderService`]: the core's [`HeaderService`] over a
//!   ChainTracks-compatible base URL fetched with Workers `fetch`, behind the
//!   0.3.6 configuration gate (below);
//! - [`PaymentVerifyError`], the 0.3 error type, and [`accept_verdict`], the
//!   one visible match that maps the core's words onto it;
//! - the 0.3 functions, name for name and signature for signature, and
//!   [`verify_brc29_payment_verified`] (0.5.0), which hands back the
//!   subject's txid beside the amount.
//!
//! ## A payment of any size (0.5.0)
//!
//! The payment is read ONCE through the streaming reader of bsv-rs 0.4 (0.4.1 at least)
//! (`transaction::verify_stream`), the scripts run: every unproven
//! transaction's inputs are executed against the parent outputs the BEEF
//! carries, and an Atomic subject is held to its rule. A valid payment is
//! never refused for its size or its counts; a refusal of the bytes names
//! the offset and the reader's kind. This crate carries no limit, no count
//! bound and no 413 (the posture of 2026-10-09, "a BEEF of any size").
//!
//! ## What the words map to (0.5.0)
//!
//! | core | adapter | a host answers |
//! |---|---|---|
//! | `Verified { satoshis }` | `Ok(satoshis)` | serve |
//! | `NoHeaderService` | `Err(NoHeaderService)` | 500 `ERR_SERVER_MISCONFIGURED`: a misconfiguration, fix the deployment |
//! | `Unverifiable { reason }`, `reason.is_server_side()` (`HeaderLookupFailed`) | `Err(Unverifiable { reason })`, warning logged | 503 `ERR_HEADER_SERVICE_UNAVAILABLE`, the quote kept: retry the SAME payment later |
//! | `Unverifiable { reason }`, the payer's (`InvalidBeef`, `SpendRefused`, `NoProof`, `OutputMissing`, `NoTransaction`, `MalformedTransaction`, `KeyDerivation` of the sender's key) | `Err(Unverifiable { reason })` | 400 `ERR_PAYMENT_INVALID`, the quote kept: send another payment |
//! | `Underpaid { paid, required }` | `Err(Underpaid { satoshis: paid, required })` | 400 `ERR_PAYMENT_INVALID`, the quote kept |
//! | `WrongScript { expected, actual }` | `Err(WrongScript { expected, actual })` | 400 `ERR_PAYMENT_INVALID`, the quote kept |
//! | `RootMismatch { height, root }` | `Err(RootMismatch { height, root })` | 400 `ERR_PAYMENT_INVALID`: a fraud signal |
//! | `PaymentFault::KeyDerivation` (the SERVER's key) | `Err(KeyDerivation)` | 500: the host's own fault |
//!
//! [`PaymentVerifyError::is_server_side`] is the one predicate a host needs
//! for the 503 row: `true` for `Unverifiable` with a server-side reason and
//! for nothing else (`NoHeaderService` is a misconfiguration, 500, not a
//! transient 503).
//!
//! **A header lookup the service cannot answer fails closed (0.4.0).** Once
//! a header service is named, a lookup it cannot answer (unreachable, HTTP
//! error, unparseable body, height not yet indexed) leaves the root
//! unchecked, and an unchecked root is not evidence: the core answers
//! `Unverifiable` with `HeaderLookupFailed { height }` (the lowest such
//! height) and [`accept_verdict`] refuses it. 0.3.x accepted that case with a
//! logged warning; the rule adopted on 2026-10-08 ended that. The refusal is
//! the server's condition, not the client's fault: render it 503-class, keep
//! the quote, and let the client retry the same payment once the service
//! answers.
//!
//! **A missing proof is the payer's (0.5.0, ruled 2026-10-09).** A BEEF that
//! carries no BUMP, a transaction whose input names a parent the BEEF does
//! not carry, a transaction with no input (invalid bytes to the reader since
//! bsv-rs 0.4.1, `InvalidBeef` with the kind `NoInputs` at its leading byte;
//! 0.5.0 on 0.4.0 refused that shape as `NoProof`): the server never
//! fetches a missing proof; the refusal names the transaction whose proof is
//! absent, and the host answers 400 with the quote kept. A spend the script
//! interpreter refuses (`SpendRefused`) is the payer's too. Hosts that want
//! the words themselves call the core (or [`verify_brc29_payment_verdict`])
//! and match them; none of the six may be served on but `Verified`, except
//! the named opt-out's own `Unverifiable` through
//! [`verify_brc29_payment_structural_only`].
//!
//! ## Header service: required
//!
//! This crate ships **no** header service of its own, and it never skips SPV
//! silently. `header_url` must name your own ChainTracks-compatible service
//! (for example a ChainTracks deployment you run). `None`, an empty string,
//! [`DEFAULT_CHAINTRACKS_URL`], any other `.invalid` host, a value without
//! an `http://` / `https://` scheme, or a value whose host the gate cannot
//! classify as a real hostname is refused with
//! [`PaymentVerifyError::NoHeaderService`] BEFORE anything else is checked, so
//! a misconfigured deployment rejects every payment loudly instead of
//! accepting unverified ones. The host is normalised (lowercased, trailing
//! dot stripped) before the placeholder comparison, and spellings that would
//! need a URL parser to decode or rewrite (percent-encoding, backslashes,
//! userinfo, whitespace, non-ASCII) are refused rather than guessed at, so
//! no spelling of the placeholder reaches DNS and surfaces as a lookup error
//! instead of as the misconfiguration it is. Adopters that
//! truly have no header service opt out *by name* with
//! [`verify_brc29_payment_structural_only`].
//!
//! | `header_url` | outcome |
//! |---|---|
//! | `None`, `Some("")`, whitespace only | `Err(NoHeaderService)` |
//! | the `.invalid` placeholder (trailing slash or dot or not, any case), any `.invalid` host | `Err(NoHeaderService)` |
//! | no `http://` / `https://` scheme, no host | `Err(NoHeaderService)` |
//! | userinfo (`@`), `%`, `\`, whitespace, control or non-ASCII characters, a non-numeric port, a label that is not a hostname | `Err(NoHeaderService)` |
//! | service unreachable, HTTP error, unparseable answer, height not indexed | `Err(Unverifiable { reason: HeaderLookupFailed { height, .. } })`, warning logged (fail-closed; 503-class, the quote kept) |
//! | the header at that height carries a different root | `Err(RootMismatch)` (fail-closed) |
//! | the header carries the proof's root | `Ok(satoshis)` |
//!
//! The configuration gate (`resolve_header_service`) is a pure function,
//! pinned by table tests; the per-root decision is the core's
//! (`bsv_middleware_core::spv::decide_root`), pinned there.
//!
//! ## Relation to the payment middleware
//!
//! [`process_payment_with_storage`](crate::process_payment_with_storage)
//! verifies the derivation-prefix HMAC, runs the core's output check
//! (`bsv_middleware_core::verify_payment_output`: script and amount, 0.3.8)
//! on output 0 and decides its words in one match of its own
//! (`middleware::payment`; a server-side `Unverifiable` there is `503
//! ERR_HEADER_SERVICE_UNAVAILABLE` with the quote kept, a payer-side one
//! `400 ERR_INVALID_PAYMENT` with the quote kept), consumes the prefix
//! once, and hands the transaction to the wallet storage
//! server. The storage server's
//! `internalizeAction` checks neither the script nor the amount (the
//! reference keeps the script check in its signer, which is not on this
//! path), so the middleware's check is the only one on it. The middleware
//! does not run the reader or SPV. The full [`verify_brc29_payment`] is
//! for callers that run their **own** payment flow (a custom 402 handler, a
//! pre-charge + refund model, a non-wallet settlement path) and want, locally
//! and before any remote call, an output that pays this server's derived key,
//! carrying at least the quoted satoshis, inside a valid, spendable, proven
//! BEEF.

use std::future::Future;

use bsv_middleware_core::{
    HeaderService, LookupFn, MerkleRoot, PaymentFault, PaymentVerdict, ServiceError,
    UnverifiableReason, VerifiedPayment,
};
use serde::Deserialize;

/// Placeholder header-service base URL: **never a working default.**
///
/// `.invalid` is a reserved top-level domain (RFC 2606) that never resolves.
/// [`verify_brc29_payment`] refuses this value, and every other `.invalid`
/// host, with [`PaymentVerifyError::NoHeaderService`]; the constant exists so
/// a configuration that was never filled in reads as such. Point `header_url`
/// at your own service, one that answers
/// `GET {base}/findHeaderHexForHeight?height={h}` with
/// `{"status":"success","value":{"merkleRoot":"<hex>", ...}}`.
pub const DEFAULT_CHAINTRACKS_URL: &str = "https://chaintracks.invalid";

/// Errors from BRC-29 payment verification.
///
/// Every variant means: reject without internalizing, and no refund is owed
/// (no funds were accepted). Most are the payer's, a 400-class answer with
/// the quote kept. Two are the SERVER's own: [`NoHeaderService`](Self::NoHeaderService)
/// (no usable `header_url`) and a [`KeyDerivation`](Self::KeyDerivation)
/// error naming the server key, which are 500-class (fix the deployment).
/// One is the server's transient condition: [`Unverifiable`](Self::Unverifiable)
/// with a server-side reason ([`is_server_side`](Self::is_server_side)), the
/// header service could not answer, 503-class: nothing charged, the quote
/// kept, the client retries the same payment later.
///
/// Since 0.4.0 this is the adapter's rendering of the core's
/// [`PaymentVerdict`] and [`PaymentFault`] (see the module docs for the
/// mapping). 0.5.0 (breaking): `Unverifiable` carries the core's
/// [`UnverifiableReason`] in place of `{ satoshis, reason: String }`, and the
/// 0.3 variants `BadTransaction`, `MissingOutput` and `BadBeef` are gone: a
/// payer's bytes are an `Unverifiable` reason now (`MalformedTransaction`,
/// `OutputMissing`, `InvalidBeef`, `SpendRefused`, `NoProof`), every one of
/// them payer-side. A host's match: `NoHeaderService` and the server's
/// `KeyDerivation` 500 (the host's own, as is `Source`), `Unverifiable` with
/// `is_server_side()` 503, everything else 400 (the payer's, quote kept).
#[derive(Debug)]
pub enum PaymentVerifyError {
    /// The output's locking script does not pay the server's derived key.
    WrongScript { expected: String, actual: String },
    /// The output pays the right key but less than the quoted price.
    Underpaid { satoshis: u64, required: u64 },
    /// The SERVER's key does not derive (an invalid server private key, or a
    /// derivation the wallet refused): the host's own fault, 500-class.
    /// Through [`expected_brc29_locking_script`] (the bare helper) either
    /// key's failure is this error; through the verifiers a sender key that
    /// does not derive is `Unverifiable` with
    /// [`UnverifiableReason::KeyDerivation`], the payer's.
    KeyDerivation(String),
    /// A merkle root in the proof does NOT match the block header at that
    /// height: a fraud signal, never an outage.
    RootMismatch { height: u32, root: String },
    /// No usable header service was configured (`header_url` was `None`,
    /// empty, the `.invalid` placeholder, or not an `http(s)://` URL), so SPV
    /// cannot run. Fail-closed: a deployment misconfiguration, never a silent
    /// skip. Pass your own header service, or opt out of SPV by name with
    /// [`verify_brc29_payment_structural_only`].
    NoHeaderService,
    /// The payment cannot be verified; `reason` says what and whose side.
    /// Server-side ([`UnverifiableReason::is_server_side`], the header
    /// service could not answer at `HeaderLookupFailed.height`): fail-closed
    /// since 0.4.0, 503-class (`ERR_HEADER_SERVICE_UNAVAILABLE`), the quote
    /// kept, the client retries the same payment once the service answers.
    /// Payer-side (invalid BEEF bytes, a spend the interpreter refused, no
    /// proof, no such output, no transaction, a sender key that does not
    /// derive): 400-class, the quote kept, the client sends another payment.
    Unverifiable { reason: UnverifiableReason },
    /// The payment's byte source failed while it was being read: never for
    /// bytes in hand (the 0.5.0 functions take a slice); the arm a host that
    /// streams a body will meet.
    Source(String),
}

impl PaymentVerifyError {
    /// `true` when the server, not the payment, is why the payment was
    /// refused for the moment: [`Unverifiable`](Self::Unverifiable) with a
    /// server-side reason (the header service could not answer). Render it
    /// 503 with the quote kept. `false` for every other variant,
    /// [`NoHeaderService`](Self::NoHeaderService) included: that one is a
    /// misconfiguration, the host's 500, not a transient condition.
    pub fn is_server_side(&self) -> bool {
        matches!(self, PaymentVerifyError::Unverifiable { reason } if reason.is_server_side())
    }
}

impl std::fmt::Display for PaymentVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentVerifyError::WrongScript { expected, actual } => write!(
                f,
                "Payment output does not pay this server's BRC-29 derived key (expected script {}, got {})",
                expected, actual
            ),
            PaymentVerifyError::Underpaid {
                satoshis,
                required,
            } => write!(
                f,
                "Payment output carries {} satoshis but {} are required",
                satoshis, required
            ),
            PaymentVerifyError::KeyDerivation(msg) => {
                write!(f, "Key derivation failed: {}", msg)
            }
            PaymentVerifyError::RootMismatch { height, root } => write!(
                f,
                "Payment merkle root {} at height {} does not match the block header",
                root, height
            ),
            PaymentVerifyError::NoHeaderService => write!(
                f,
                "No header service configured for SPV: pass your own ChainTracks-compatible base URL as header_url, or opt out by name with verify_brc29_payment_structural_only"
            ),
            PaymentVerifyError::Unverifiable { reason } if reason.is_server_side() => write!(
                f,
                "Payment not verified: {}. Refused until the header service answers; nothing was charged and the quote is unchanged, retry the same payment",
                reason
            ),
            PaymentVerifyError::Unverifiable { reason } => {
                write!(f, "Payment not verified: {}", reason)
            }
            PaymentVerifyError::Source(msg) => {
                write!(f, "The payment's byte source failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for PaymentVerifyError {}

/// The core's faults, variant for variant: the host's own.
impl From<PaymentFault> for PaymentVerifyError {
    fn from(fault: PaymentFault) -> Self {
        match fault {
            PaymentFault::KeyDerivation(m) => PaymentVerifyError::KeyDerivation(m),
            PaymentFault::Source(m) => PaymentVerifyError::Source(m),
            // `PaymentFault` is non-exhaustive: a fault the core adds later is
            // still the host's own, rendered by its text.
            other => PaymentVerifyError::KeyDerivation(other.to_string()),
        }
    }
}

/// The one visible match that collapses the core's words to this adapter's
/// 0.3 result: `Verified` is `Ok(satoshis)`, the only `Ok`; every other word
/// is the same-named `Err`. `Unverifiable` is
/// [`PaymentVerifyError::Unverifiable`] with the reason, logged as a warning
/// when it is the server's side (a root that could not be checked is
/// refused, **fail-closed**, 0.4.0; the host renders it 503-class with the
/// quote kept) and as the payer's refusal otherwise (400-class). No path
/// through this function serves with a root unchecked; the named opt-out
/// [`verify_brc29_payment_structural_only`] does not use it for its own
/// `Unverifiable`.
pub fn accept_verdict(verdict: PaymentVerdict) -> std::result::Result<u64, PaymentVerifyError> {
    match verdict {
        PaymentVerdict::Verified { satoshis } => Ok(satoshis),
        PaymentVerdict::Unverifiable { reason } => {
            if reason.is_server_side() {
                warn_log(&format!(
                    "[payment_verify] SPV refused, root unchecked (not served): {}",
                    reason
                ));
            }
            Err(PaymentVerifyError::Unverifiable { reason })
        }
        PaymentVerdict::Underpaid { paid, required } => Err(PaymentVerifyError::Underpaid {
            satoshis: paid,
            required,
        }),
        PaymentVerdict::WrongScript { expected, actual } => {
            Err(PaymentVerifyError::WrongScript { expected, actual })
        }
        PaymentVerdict::NoHeaderService => Err(PaymentVerifyError::NoHeaderService),
        PaymentVerdict::RootMismatch { height, root } => {
            Err(PaymentVerifyError::RootMismatch { height, root })
        }
    }
}

// ─── Header-service configuration (pure) ────────────────────────────

/// The normalised host of an `http://` / `https://` base URL, or `None` when
/// the value cannot be classified as such a URL naming a real host.
///
/// This is deliberately stricter than a WHATWG URL parse. The gate compares
/// the host against the `.invalid` placeholder, so any spelling that a URL
/// parser would decode or rewrite into a different host than this function
/// sees could slip past that comparison and surface at lookup time as a
/// service error (`Unverifiable`, a retryable 503) instead of the
/// misconfiguration it is (`NoHeaderService`, a 500 to fix) (a trailing-dot
/// FQDN, a percent-encoded dot, a backslash before an `@`).
/// The rule is therefore: normalise what can be normalised, refuse what
/// would need decoding, and never guess. After the scheme:
///
/// - the authority is the text up to the first `/`, `?` or `#`;
/// - the whole value must be free of `\`, whitespace and control characters;
/// - the authority must be ASCII and carry no `@` (userinfo: the Fetch
///   standard rejects URL credentials, so an `@` can only be a trick) and
///   no `%` (the gate does not decode, so it accepts nothing that needs it);
/// - the host is either a bracketed IPv6 literal that `Ipv6Addr` parses, or
///   dot-separated labels of ASCII letters, digits and hyphens (no hyphen at
///   a label's ends), with one optional trailing dot (the FQDN marker);
/// - an optional `:port` is a run of decimal digits that fits in 16 bits.
///
/// The host comes back lowercased, without the port, with the trailing dot
/// stripped and an IPv6 literal unbracketed, so the `.invalid` test sees one
/// spelling of each host.
fn header_service_host(base: &str) -> Option<String> {
    if base
        .chars()
        .any(|c| c == '\\' || c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let (scheme, rest) = base.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || !authority.is_ascii() || authority.contains(['@', '%']) {
        return None;
    }
    let (host, port_suffix) = match authority.strip_prefix('[') {
        Some(after_bracket) => {
            let (literal, after) = after_bracket.split_once(']')?;
            literal.parse::<std::net::Ipv6Addr>().ok()?;
            (literal, after)
        }
        None => authority.split_at(authority.find(':').unwrap_or(authority.len())),
    };
    match port_suffix.strip_prefix(':') {
        Some(port) => {
            if port.is_empty()
                || !port.bytes().all(|b| b.is_ascii_digit())
                || port.parse::<u16>().is_err()
            {
                return None;
            }
        }
        None if port_suffix.is_empty() => {}
        None => return None,
    }
    let host = host.to_ascii_lowercase();
    if authority.starts_with('[') {
        return Some(host);
    }
    let name = host.strip_suffix('.').unwrap_or(&host);
    let label_ok = |label: &str| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if name.is_empty() || !name.split('.').all(label_ok) {
        return None;
    }
    Some(name.to_string())
}

/// The pure configuration gate: the base URL SPV will query, or
/// [`PaymentVerifyError::NoHeaderService`].
///
/// Trims surrounding whitespace and trailing slashes, then refuses `None`,
/// the empty string, anything [`header_service_host`] cannot classify as an
/// `http://` / `https://` URL naming a real host (no scheme, no host,
/// userinfo, percent-encoding, backslashes, whitespace, a port that is not a
/// number, labels that are not a hostname), and any host that normalises
/// (lowercased, trailing dot stripped) to the reserved `.invalid` TLD, which
/// covers [`DEFAULT_CHAINTRACKS_URL`] in any case, with or without a trailing
/// slash or dot. The normalisation runs BEFORE the placeholder comparison, so
/// no spelling of the placeholder reaches DNS. A real but wrong host is NOT
/// caught here: that surfaces as a service error at lookup time and is
/// refused as `Unverifiable` (see the module docs).
fn resolve_header_service(
    header_url: Option<&str>,
) -> std::result::Result<&str, PaymentVerifyError> {
    let base = header_url
        .map(str::trim)
        .unwrap_or("")
        .trim_end_matches('/');
    if base.is_empty() {
        return Err(PaymentVerifyError::NoHeaderService);
    }
    let host = header_service_host(base).ok_or(PaymentVerifyError::NoHeaderService)?;
    if host == "invalid" || host.ends_with(".invalid") {
        return Err(PaymentVerifyError::NoHeaderService);
    }
    Ok(base)
}

// ─── The URL-configured header service ──────────────────────────────

/// `{"status":"success","value":{...}}`
#[derive(Deserialize)]
struct ChainTracksApiResponse {
    status: String,
    value: Option<ChainTracksHeader>,
}

/// Handles both camelCase (`merkleRoot`) and lowercase (`merkleroot`) forms.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChainTracksHeader {
    merkle_root: Option<String>,
    merkleroot: Option<String>,
}

/// Pure half of the header lookup: the merkle root carried by a
/// `findHeaderHexForHeight` response body, or why it cannot be read.
fn parse_header_response(body: &str, height: u32) -> std::result::Result<String, String> {
    let api: ChainTracksApiResponse =
        serde_json::from_str(body).map_err(|e| format!("parse response: {}", e))?;
    if api.status != "success" {
        return Err(format!(
            "header service status '{}' at height {}",
            api.status, height
        ));
    }
    let header = api
        .value
        .ok_or_else(|| format!("no header at height {}", height))?;
    header
        .merkle_root
        .or(header.merkleroot)
        .ok_or_else(|| "response missing merkleRoot".to_string())
}

/// The network half of the header lookup: the merkle root the header service
/// reports for the block at `height`, or why it could not answer.
async fn fetch_header_root(base_url: &str, height: u32) -> std::result::Result<String, String> {
    let base = base_url.trim_end_matches('/');
    let url = format!("{}/findHeaderHexForHeight?height={}", base, height);
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get);
    let request =
        worker::Request::new_with_init(&url, &init).map_err(|e| format!("request build: {}", e))?;
    let mut response = worker::Fetch::Request(request)
        .send()
        .await
        .map_err(|e| format!("fetch height {}: {}", height, e))?;
    let status = response.status_code();
    if status >= 400 {
        return Err(format!(
            "header service HTTP {} at height {}",
            status, height
        ));
    }
    let body = response
        .text()
        .await
        .map_err(|e| format!("read response: {}", e))?;
    parse_header_response(&body, height)
}

/// The core's [`HeaderService`] over a ChainTracks-compatible base URL,
/// fetched with Workers `fetch`: `GET {base}/findHeaderHexForHeight?height={h}`.
///
/// Built only through [`UrlHeaderService::resolve`], which is the 0.3.6
/// configuration gate: a value the gate refuses (see the module docs) is
/// `Err(NoHeaderService)`, so no unclassifiable URL ever becomes a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlHeaderService {
    base_url: String,
}

impl UrlHeaderService {
    /// The gate: a header service for `header_url`, or
    /// [`PaymentVerifyError::NoHeaderService`] for every shape of "no
    /// service" (`None`, blank, the `.invalid` placeholder in any spelling, no
    /// `http(s)://` scheme, a host the gate cannot classify).
    pub fn resolve(header_url: Option<&str>) -> std::result::Result<Self, PaymentVerifyError> {
        let base = resolve_header_service(header_url)?;
        Ok(Self {
            base_url: base.to_string(),
        })
    }

    /// The base URL SPV queries: trimmed, without trailing slashes.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl HeaderService for UrlHeaderService {
    async fn merkle_root(
        &self,
        height: u32,
    ) -> std::result::Result<Option<MerkleRoot>, ServiceError> {
        fetch_header_root(&self.base_url, height)
            .await
            .map(|root| Some(MerkleRoot::new(root)))
            .map_err(ServiceError::new)
    }
}

/// Logs through the Workers console on wasm32; a no-op under native tests.
fn warn_log(message: &str) {
    #[cfg(target_arch = "wasm32")]
    worker::console_warn!("{}", message);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = message;
}

// ─── The 0.3 functions over the core ────────────────────────────────

/// Compute the P2PKH locking script (hex) the sender must have paid for a
/// BRC-29 payment to (`server_key`, `sender_identity_key`, prefix, suffix)
/// (`bsv_middleware_core::brc29::expected_locking_script`). A bare helper
/// with no verdict to answer in: either key that does not parse is
/// [`PaymentVerifyError::KeyDerivation`] here.
pub fn expected_brc29_locking_script(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
) -> std::result::Result<String, PaymentVerifyError> {
    Ok(bsv_middleware_core::expected_locking_script(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
    )?)
}

/// Verify that output `output_index` of the BEEF-encoded payment transaction
/// pays the server's BRC-29 derived key at least `required_satoshis`
/// (`bsv_middleware_core::brc29::verify_payment_output`, rendered through
/// [`accept_verdict`]): the output check alone, offline, no reader, no proof,
/// no header service. Bytes that are no BEEF, a BEEF without the named
/// output and a sender key that does not derive are payer-side
/// `Unverifiable` errors.
///
/// Call this AFTER nonce/quote verification and BEFORE `internalizeAction`.
/// Returns the actual satoshis carried by the output on success.
pub fn verify_brc29_payment_output(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
) -> std::result::Result<u64, PaymentVerifyError> {
    accept_verdict(bsv_middleware_core::verify_payment_output(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
    )?)
}

/// The core's verdict on a payment through `service`
/// (`bsv_middleware_core::verify_brc29_payment`), for hosts that render the
/// words themselves instead of taking this adapter's [`accept_verdict`]
/// rendering. No word is accepted on the host's behalf: `Unverifiable` is
/// always a refusal (503-class when `reason.is_server_side()`, the quote
/// kept; 400-class otherwise). `None` is `NoHeaderService`.
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment_verdict<H: HeaderService + ?Sized>(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
    service: Option<&H>,
) -> std::result::Result<PaymentVerdict, PaymentVerifyError> {
    Ok(bsv_middleware_core::verify_brc29_payment(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
        service,
    )
    .await?)
}

/// [`verify_brc29_payment`] with the header lookup supplied by the caller
/// instead of a `header_url`: the reader, the output, the proof, then SPV
/// through `lookup`.
///
/// `lookup(height)` is your header service: `Ok(merkle_root_hex)` for the
/// block at `height` (compared case-insensitively; a different root is
/// [`PaymentVerifyError::RootMismatch`], fail-closed) or `Err(reason)` when it
/// cannot answer ([`PaymentVerifyError::Unverifiable`] with
/// `HeaderLookupFailed`, fail-closed as well: the payment is refused with
/// the reason, 503-class at the host, the quote kept). There is no
/// configuration gate here, since there is no URL to check; a lookup that
/// always errors refuses every proven payment, so a host with no header
/// service must opt out by name with
/// [`verify_brc29_payment_structural_only`] instead. For a service binding,
/// a cached header store, or a conformance runner
/// (`conformance/brc29-payment-vectors.json`) that answers from a fixture.
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment_with_header_lookup<F, Fut>(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
    lookup: F,
) -> std::result::Result<u64, PaymentVerifyError>
where
    F: Fn(u32) -> Fut,
    Fut: Future<Output = std::result::Result<String, String>>,
{
    let service = LookupFn(|height| {
        let answer = lookup(height);
        async move {
            answer
                .await
                .map(|root| Some(MerkleRoot::new(root)))
                .map_err(ServiceError::new)
        }
    });
    let verdict = verify_brc29_payment_verdict(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
        Some(&service),
    )
    .await?;
    accept_verdict(verdict)
}

/// Full pre-service payment verification: pays-us-correctly **and**
/// real-and-confirmable. Call this AFTER nonce/quote verification and BEFORE
/// `internalizeAction`; on `Ok` the payment is safe to internalize and serve,
/// on `Err` reject without serving (no funds accepted, so no refund is owed).
///
/// Runs, in order (the core's
/// [`verify_brc29_payment`](bsv_middleware_core::verify_brc29_payment)):
///   0. configuration gate: `header_url` must name a header service (below).
///   1. the bytes are a valid BEEF by the streaming reader, the scripts run
///      (every unproven transaction spends the parent outputs the BEEF
///      carries; an Atomic subject is the tip of its ancestry);
///   2. the subject's output `output_index` pays the server's derived key at
///      least `required_satoshis` (script before amount);
///   3. a proof is present (no BUMP, or an unproven transaction with no
///      input, is `NoProof`: the payer's);
///   4. each merkle root, lowest height first, matches the block header the
///      service answers.
///
/// **`header_url` is required.** Pass the base URL of your own
/// ChainTracks-compatible header service (for example a ChainTracks deployment
/// you run). `None`, `Some("")`, [`DEFAULT_CHAINTRACKS_URL`], any `.invalid`
/// host (in any case, with or without a trailing dot), a value without an
/// `http(s)://` scheme, or a value whose host cannot be classified as a real
/// hostname (userinfo, percent-encoding, backslashes, whitespace) returns
/// [`PaymentVerifyError::NoHeaderService`] before any other check: fail-closed,
/// never a silent skip. Once a service is named, a lookup it cannot answer
/// (unreachable, HTTP error, unparseable answer, height not indexed) is
/// [`PaymentVerifyError::Unverifiable`] with a server-side reason:
/// fail-closed since 0.4.0, refused with the reason, for the host to answer
/// 503-class with the quote kept so the client retries once the service
/// answers; a root that differs from the header is
/// [`PaymentVerifyError::RootMismatch`]. Adopters with no header service opt
/// out of SPV by name with [`verify_brc29_payment_structural_only`].
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
    header_url: Option<&str>,
) -> std::result::Result<u64, PaymentVerifyError> {
    verify_brc29_payment_verified(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
        header_url,
    )
    .await
    .map(|verified| verified.satoshis)
}

/// [`verify_brc29_payment`] with the subject's txid beside the amount
/// ([`VerifiedPayment`]): the txid the reader hashed while the bytes passed,
/// so a host records and internalizes without parsing the BEEF a second
/// time. Same arguments, same gate, same refusals.
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment_verified(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
    header_url: Option<&str>,
) -> std::result::Result<VerifiedPayment, PaymentVerifyError> {
    // 0. No header service, no verdict: the gate classifies the URL, and the
    //    core refuses `None` before any other work, so a misconfigured
    //    deployment never looks like one that verifies.
    let service = UrlHeaderService::resolve(header_url).ok();
    match bsv_middleware_core::verify_brc29_payment_verified(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
        service.as_ref(),
    )
    .await?
    {
        Ok(verified) => Ok(verified),
        // The core's refusal side never carries `Verified`; `accept_verdict`
        // renders the five refusal words.
        Err(word) => {
            Err(accept_verdict(word).expect_err("the core's refusal side never carries Verified"))
        }
    }
}

/// [`verify_brc29_payment`] **without SPV**: the BEEF's structure by the
/// streaming reader (no script is run), the output, the proof's presence;
/// the merkle roots in the proof are NOT checked against block headers.
///
/// **Opt-in, by name, for adopters that have no header service.** Prefer
/// [`verify_brc29_payment`] with your own header service: a structurally
/// valid BEEF only proves its merkle paths compute *some* root, so a forged
/// parent transaction with a made-up proof passes this function and is caught
/// only by whatever your broadcast or internalize step does later. Callers
/// that serve before those steps are exposed to that forgery.
///
/// This is the ONE function in this crate that answers `Ok` with merkle
/// roots unchecked, and only because the caller named it: the core answers
/// the skip as `Unverifiable` with
/// [`UnverifiableReason::RootsUnchecked`] so it stays visible in the word,
/// and this function (not [`accept_verdict`], which refuses that word) serves
/// it with a warning logged. Every other word is [`accept_verdict`]'s
/// same-named `Err`: invalid bytes, a wrong or short output and a missing
/// proof are refused here as well.
pub fn verify_brc29_payment_structural_only(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
) -> std::result::Result<u64, PaymentVerifyError> {
    match bsv_middleware_core::verify_brc29_payment_structural_only(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
    )? {
        // The skip the caller asked for by name: served, and said so.
        PaymentVerdict::Unverifiable {
            reason: UnverifiableReason::RootsUnchecked { satoshis, roots },
        } => {
            warn_log(&format!(
                "[payment_verify] structural-only (named opt-out): serving {} satoshis with {} merkle root(s) unchecked",
                satoshis, roots
            ));
            Ok(satoshis)
        }
        verdict => accept_verdict(verdict),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_middleware_core::BRC29_PROTOCOL_ID;
    use bsv_sdk::primitives::hash::hash160;
    use bsv_sdk::primitives::{PrivateKey, PublicKey};
    use bsv_sdk::script::{LockingScript, UnlockingScript};
    use bsv_sdk::transaction::{
        Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    };
    use bsv_sdk::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};
    use std::cell::RefCell;

    const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    /// A real-looking (non-`.invalid`) base URL for tests that must never
    /// reach the network: they fail before SPV, or inject their lookup.
    const HEADERS_URL: &str = "https://headers.example";

    /// Block height of the one-leaf proof in [`beef_with_proven_payment`].
    const PROOF_HEIGHT: u32 = 850_000;
    const OP_TRUE: &[u8] = &[0x51];

    fn sender_identity() -> String {
        let sender_priv = PrivateKey::from_hex(SENDER_KEY).unwrap();
        ProtoWallet::new(Some(sender_priv)).identity_key().to_hex()
    }

    fn payment_tx(script_hex: &str, satoshis: u64) -> Transaction {
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput {
            source_txid: Some("11".repeat(32)),
            source_output_index: 0,
            ..Default::default()
        })
        .unwrap();
        tx.add_output(TransactionOutput {
            satoshis: Some(satoshis),
            locking_script: LockingScript::from_hex(script_hex).unwrap(),
            change: false,
        })
        .unwrap();
        tx
    }

    /// A BEEF holding ONE transaction that spends an output this BEEF does not
    /// carry and pays `satoshis` to `script_hex`. `from_beef` resolves it (the
    /// output is readable), while the reader refuses it (its input names an
    /// element the BEEF does not carry).
    fn beef_with_unproven_payment(script_hex: &str, satoshis: u64) -> Vec<u8> {
        let mut beef = Beef::new();
        beef.merge_transaction(payment_tx(script_hex, satoshis));
        beef.to_binary()
    }

    /// A BEEF holding ONE transaction proven by a one-leaf BUMP at
    /// `PROOF_HEIGHT` (a block of one transaction, whose merkle root IS the
    /// txid), paying `satoshis` to `script_hex`. The reader accepts it and
    /// reports exactly one root, so SPV can be driven by an injected lookup.
    /// Returns the bytes and the txid (= the root the lookup must answer).
    fn beef_with_proven_payment(script_hex: &str, satoshis: u64) -> (Vec<u8>, String) {
        let tx = payment_tx(script_hex, satoshis);
        let txid = tx.id();
        let bump = MerklePath::new(
            PROOF_HEIGHT,
            vec![vec![MerklePathLeaf::new_txid(0, txid.clone())]],
        )
        .unwrap();
        let mut beef = Beef::new();
        beef.merge_bump(bump);
        beef.merge_transaction(tx);
        (beef.to_binary(), txid)
    }

    /// A transaction with no input paying `outputs` (satoshis, script bytes).
    fn rootless(outputs: &[(u64, Vec<u8>)]) -> Transaction {
        let mut tx = Transaction::new();
        for (satoshis, script) in outputs {
            tx.add_output(TransactionOutput::new(
                *satoshis,
                LockingScript::from_binary(script).unwrap(),
            ))
            .unwrap();
        }
        tx
    }

    /// A transaction spending `parent:0` with an EMPTY unlocking script.
    fn spending(parent: &Transaction, outputs: &[(u64, Vec<u8>)]) -> Transaction {
        let mut tx = rootless(outputs);
        let mut input = TransactionInput::new(parent.id(), 0);
        input.unlocking_script = Some(UnlockingScript::new());
        tx.inputs.push(input);
        tx
    }

    /// A BEEF of `txs` in order, the first proven at `PROOF_HEIGHT` when
    /// `proven`; the bytes and the first txid (the root).
    fn beef_of(txs: &[&Transaction], proven: bool) -> (Vec<u8>, String) {
        let mut beef = Beef::new();
        let root = txs[0].id();
        let bump = proven.then(|| {
            beef.merge_bump(
                MerklePath::new(
                    PROOF_HEIGHT,
                    vec![vec![MerklePathLeaf::new_txid(0, root.clone())]],
                )
                .unwrap(),
            )
        });
        for (i, tx) in txs.iter().enumerate() {
            beef.merge_raw_tx(tx.to_binary(), bump.filter(|_| i == 0));
        }
        (beef.to_binary(), root)
    }

    fn p2pkh(hash: &[u8; 20]) -> Vec<u8> {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(hash);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    fn our_script() -> String {
        expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefix", "suffix").unwrap()
    }

    /// The full verification of `beef` with the header service replaced by
    /// `answer` (the same answer at every height); also returns the heights
    /// the lookup was asked for.
    async fn verify_with(
        beef: &[u8],
        answer: std::result::Result<String, String>,
    ) -> (std::result::Result<u64, PaymentVerifyError>, Vec<u32>) {
        let asked = RefCell::new(Vec::new());
        let result = verify_brc29_payment_with_header_lookup(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            beef,
            0,
            1000,
            |height| {
                asked.borrow_mut().push(height);
                let answer = answer.clone();
                async move { answer }
            },
        )
        .await;
        (result, asked.into_inner())
    }

    /// The full verification of a correct, proven 1000-sat payment.
    async fn verify_proven_with(
        answer: std::result::Result<String, String>,
    ) -> (std::result::Result<u64, PaymentVerifyError>, Vec<u32>) {
        let (beef, _) = beef_with_proven_payment(&our_script(), 1000);
        verify_with(&beef, answer).await
    }

    fn reason_of(err: &PaymentVerifyError) -> &UnverifiableReason {
        match err {
            PaymentVerifyError::Unverifiable { reason } => reason,
            other => panic!("expected Unverifiable, got {other:?}"),
        }
    }

    /// The script the SENDER computes (their wallet, for_self=false toward the
    /// server) must equal the script the SERVER expects (for_self=true).
    #[test]
    fn test_sender_and_server_derive_same_script() {
        let server_priv = PrivateKey::from_hex(SERVER_KEY).unwrap();
        let server_identity = ProtoWallet::new(Some(server_priv)).identity_key().to_hex();

        let prefix = "dGVzdC1wcmVmaXg=";
        let suffix = "dGVzdC1zdWZmaXg=";

        // Sender-side derivation of the server's receiving key
        let sender_wallet = ProtoWallet::new(Some(PrivateKey::from_hex(SENDER_KEY).unwrap()));
        let derived = sender_wallet
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(Protocol::new(
                    SecurityLevel::Counterparty,
                    BRC29_PROTOCOL_ID,
                )),
                key_id: Some(format!("{} {}", prefix, suffix)),
                counterparty: Some(Counterparty::Other(
                    PublicKey::from_hex(&server_identity).unwrap(),
                )),
                for_self: Some(false),
            })
            .unwrap();
        let pkh = hash160(&hex::decode(&derived.public_key).unwrap());
        let sender_script = format!("76a914{}88ac", hex::encode(pkh));

        // Server-side expectation
        let server_script =
            expected_brc29_locking_script(SERVER_KEY, &sender_identity(), prefix, suffix).unwrap();

        assert_eq!(sender_script, server_script);
    }

    #[test]
    fn test_different_nonce_changes_script() {
        let a = expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefixA", "suffix")
            .unwrap();
        let b = expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefixB", "suffix")
            .unwrap();
        assert_ne!(
            a, b,
            "different derivation prefixes must produce different scripts"
        );
    }

    #[test]
    fn test_different_server_changes_script() {
        let a = expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefix", "suffix")
            .unwrap();
        let b = expected_brc29_locking_script(SENDER_KEY, &sender_identity(), "prefix", "suffix")
            .unwrap();
        assert_ne!(a, b, "different server keys must produce different scripts");
    }

    /// The bare helper reports either key as `KeyDerivation`; through the
    /// verifiers the server's key stays `KeyDerivation` (the host's 500) and
    /// the sender's is a payer-side `Unverifiable` (400).
    #[test]
    fn test_invalid_keys_are_key_derivation_errors_and_the_verifier_splits_the_sides() {
        let bad_server =
            expected_brc29_locking_script("zz", &sender_identity(), "prefix", "suffix")
                .unwrap_err();
        assert!(matches!(bad_server, PaymentVerifyError::KeyDerivation(_)));
        let bad_sender =
            expected_brc29_locking_script(SERVER_KEY, "not-a-pubkey", "prefix", "suffix")
                .unwrap_err();
        assert!(matches!(bad_sender, PaymentVerifyError::KeyDerivation(_)));

        let (beef, _) = beef_with_proven_payment(&our_script(), 1000);
        let err = verify_brc29_payment_output(
            "zz",
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::KeyDerivation(_)), "{err}");
        assert!(
            !err.is_server_side(),
            "a misconfiguration, not a transient 503"
        );
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            "not-a-pubkey",
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap_err();
        assert!(
            matches!(reason_of(&err), UnverifiableReason::KeyDerivation(_)),
            "{err}"
        );
        assert!(!err.is_server_side());
    }

    /// Bytes that are no BEEF are the payer's `MalformedTransaction` through
    /// the output check: never a fault, never server-side.
    #[test]
    fn test_bad_tx_bytes_are_a_payer_side_refusal() {
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
        )
        .unwrap_err();
        assert!(
            matches!(reason_of(&err), UnverifiableReason::MalformedTransaction(_)),
            "{err}"
        );
        assert!(!err.is_server_side());
    }

    #[test]
    fn test_output_check_accepts_exact_and_over_payment() {
        let script = our_script();
        for paid in [1000u64, 1001, 50_000] {
            let beef = beef_with_unproven_payment(&script, paid);
            let sats = verify_brc29_payment_output(
                SERVER_KEY,
                &sender_identity(),
                "prefix",
                "suffix",
                &beef,
                0,
                1000,
            )
            .unwrap();
            assert_eq!(sats, paid);
        }
    }

    #[test]
    fn test_underpaid_output_rejected() {
        let beef = beef_with_unproven_payment(&our_script(), 999);
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaymentVerifyError::Underpaid {
                satoshis: 999,
                required: 1000
            }
        ));
    }

    #[test]
    fn test_output_for_another_nonce_or_server_rejected() {
        let other_nonce =
            expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "stale", "suffix")
                .unwrap();
        let beef = beef_with_unproven_payment(&other_nonce, 5000);
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::WrongScript { .. }));

        let other_server =
            expected_brc29_locking_script(SENDER_KEY, &sender_identity(), "prefix", "suffix")
                .unwrap();
        let beef = beef_with_unproven_payment(&other_server, 5000);
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::WrongScript { .. }));
    }

    /// No output at the named index is the payer's `OutputMissing`.
    #[test]
    fn test_missing_output_index_is_payer_side() {
        let beef = beef_with_unproven_payment(&our_script(), 1000);
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            3,
            1000,
        )
        .unwrap_err();
        assert_eq!(
            *reason_of(&err),
            UnverifiableReason::OutputMissing {
                output_index: 3,
                output_count: 1
            }
        );
    }

    /// The full check: a transaction that pays us correctly but whose BEEF
    /// does not carry the parent its input names is refused by the reader
    /// as invalid bytes (`InputNamesNoElement`, naming the absent
    /// transaction), never reaching the header service, so a bare,
    /// unconfirmable payment cannot buy service. The payer's side.
    #[tokio::test]
    async fn test_unproven_beef_fails_full_verification() {
        let beef = beef_with_unproven_payment(&our_script(), 1000);
        let (err, asked) = verify_with(&beef, Ok("00".repeat(32))).await;
        let err = err.unwrap_err();
        match reason_of(&err) {
            UnverifiableReason::InvalidBeef { kind, reason, .. } => {
                assert_eq!(kind, "InputNamesNoElement");
                assert!(reason.contains(&"11".repeat(32)), "{reason}");
            }
            other => panic!("expected InvalidBeef, got {other:?}"),
        }
        assert!(!err.is_server_side());
        assert!(err.to_string().contains(&"11".repeat(32)), "{err}");
        assert!(asked.is_empty());
    }

    /// Garbage bytes are refused by the reader at offset 0 without a lookup.
    #[tokio::test]
    async fn test_full_verification_bad_bytes_rejected_offline() {
        let err = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
            Some(HEADERS_URL),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                reason_of(&err),
                UnverifiableReason::InvalidBeef { offset: 0, kind, .. } if kind == "BadVersion"
            ),
            "{err}"
        );
    }

    /// The scripts run (0.5.0): a payment spending a proven parent locked to
    /// a key, with no signature, is `SpendRefused`; the lookup is not asked.
    /// 0.4.x checked the structure alone and served it.
    #[tokio::test]
    async fn test_unsigned_spend_is_refused_by_the_reader() {
        let parent = spending(&rootless(&[(1, vec![0x52])]), &[(1000, p2pkh(&[7u8; 20]))]);
        let subject = spending(&parent, &[(1000, hex::decode(our_script()).unwrap())]);
        let (beef, root) = beef_of(&[&parent, &subject], true);
        let (err, asked) = verify_with(&beef, Ok(root)).await;
        let err = err.unwrap_err();
        assert!(
            matches!(
                reason_of(&err),
                UnverifiableReason::SpendRefused { txid, input: Some(0), .. } if *txid == subject.id()
            ),
            "{err}"
        );
        assert!(!err.is_server_side());
        assert!(asked.is_empty());

        // Spendable (the parent is OP_TRUE): verified, one lookup.
        let parent = spending(&rootless(&[(1, vec![0x52])]), &[(1000, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(1000, hex::decode(our_script()).unwrap())]);
        let (beef, root) = beef_of(&[&parent, &subject], true);
        let (ok, asked) = verify_with(&beef, Ok(root)).await;
        assert_eq!(ok.unwrap(), 1000);
        assert_eq!(asked, vec![PROOF_HEIGHT]);
    }

    /// No proof is the payer's (ruled 2026-10-09). An unproven transaction
    /// with no input is invalid bytes to the reader since bsv-rs 0.4.1
    /// (bsv-stack-lean #58): `InvalidBeef { kind: "NoInputs" }` at the
    /// transaction's leading byte (7: the version, the two counts, the
    /// has-BUMP byte), the offset in the words, no lookup. 0.5.0 on 0.4.0
    /// refused the same bytes as the door's own `NoProof { txid: parent }`;
    /// that rule stays beneath the reader's in the core, and the word's
    /// class (the payer's, the txid in its words) is pinned in the
    /// `accept_verdict` table below.
    #[tokio::test]
    async fn test_no_proof_is_the_payers_side() {
        let parent = rootless(&[(1000, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(1000, hex::decode(our_script()).unwrap())]);
        let (beef, _) = beef_of(&[&parent, &subject], false);
        let (err, asked) = verify_with(&beef, Ok("00".repeat(32))).await;
        let err = err.unwrap_err();
        assert_eq!(
            *reason_of(&err),
            UnverifiableReason::InvalidBeef {
                offset: 7,
                kind: "NoInputs".into(),
                reason: "invalid BEEF at byte 7: NoInputs".into()
            }
        );
        assert!(!err.is_server_side());
        let shown = err.to_string();
        assert!(
            shown.contains("offset 7") && shown.contains("NoInputs"),
            "{shown}"
        );
        assert!(asked.is_empty());
    }

    /// The witness of bsv-stack-lean #58 (the captain ran it on 0.4.0 and
    /// 0.4.1, 2026-10-09): a parent with no input beside a proven stranger
    /// whose BUMP is the only proof in the BEEF, the subject paying us out
    /// of that parent, the stranger's root the header's. Refused, never
    /// served, the payer's side, and the stranger's root is never asked of
    /// the header service. On 0.4.0 the core's tap refused it as `NoProof`
    /// naming the parent; on 0.4.1 the reader refuses it as `NoInputs` at
    /// the parent's leading byte, which is what this asserts.
    #[tokio::test]
    async fn witness_no_input_parent_beside_a_proven_stranger_is_refused() {
        let stranger = spending(&rootless(&[(1, vec![0x52])]), &[(1, vec![0x51])]);
        let parent = rootless(&[(1000, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(1000, hex::decode(our_script()).unwrap())]);
        let (beef, root) = beef_of(&[&stranger, &parent, &subject], true);
        let (result, asked) = verify_with(&beef, Ok(root)).await;
        let err = result.unwrap_err();
        println!("witness (adapter): {err}");
        assert!(
            matches!(reason_of(&err), UnverifiableReason::InvalidBeef { kind, .. } if kind == "NoInputs"),
            "{err:?}"
        );
        assert!(!err.is_server_side(), "the payer's side");
        assert!(asked.is_empty(), "the stranger's root is never asked");
    }

    #[test]
    fn test_default_header_url_is_a_reserved_placeholder_and_is_refused() {
        assert!(DEFAULT_CHAINTRACKS_URL.ends_with(".invalid"));
        assert!(matches!(
            resolve_header_service(Some(DEFAULT_CHAINTRACKS_URL)),
            Err(PaymentVerifyError::NoHeaderService)
        ));
    }

    /// The configuration gate, as a table: every shape of "no header service"
    /// is `NoHeaderService` (never a lookup error, never a skip), including the
    /// placeholder spellings a URL parser would have decoded or rewritten
    /// into the placeholder after our comparison (the re-review's R1: a
    /// trailing-dot FQDN, a percent-encoded dot, a backslash before an `@`)
    /// and every host form the gate declines to classify; a real base URL
    /// comes back trimmed, without trailing slashes.
    #[test]
    fn test_resolve_header_service_table() {
        let refused: &[Option<&str>] = &[
            // nothing
            None,
            Some(""),
            Some("   "),
            Some("/"),
            // the placeholder, in every spelling
            Some(DEFAULT_CHAINTRACKS_URL),
            Some("https://chaintracks.invalid/"),
            Some("HTTPS://CHAINTRACKS.INVALID"),
            Some("http://CHAINTRACKS.INVALID:443/"),
            Some("HTTPS://Chaintracks.Invalid///"),
            Some("https://invalid"),
            Some("https://invalid."),
            // R1: trailing-dot FQDN, with and without a path
            Some("https://chaintracks.invalid."),
            Some("https://chaintracks.invalid./"),
            Some("https://chaintracks.invalid./v1"),
            Some("HTTPS://CHAINTRACKS.INVALID.:8443/"),
            Some("https://chaintracks.invalid.."),
            // R1: percent-encoding (a URL parser decodes it to the placeholder)
            Some("https://chaintracks%2Einvalid"),
            Some("https://chaintracks%2einvalid/"),
            Some("https://chaintracks.invalid%2F"),
            Some("https://%63haintracks.invalid"),
            // R1: backslash parser differential (WHATWG reads `\` as `/`,
            // so the fetch would have gone to the placeholder)
            Some("https://chaintracks.invalid\\@real.example"),
            Some("https://real.example\\@chaintracks.invalid"),
            Some("https://chaintracks.invalid\\real.example"),
            Some("https:\\\\chaintracks.invalid"),
            Some("https://headers.example\\v1"),
            // userinfo, on the placeholder and on a real host alike
            Some("https://user@chaintracks.invalid"),
            Some("https://user:pw@headers.invalid:8443/v1/"),
            Some("https://user:pw@CHAINTRACKS.invalid:8443/x"),
            Some("https://chaintracks.invalid@real.example"),
            Some("https://user:pw@headers.example"),
            Some("https://@headers.example"),
            Some("https://@"),
            // whitespace and control characters inside the value
            Some("https://chain tracks.invalid"),
            Some("https://chaintracks.invalid\t"),
            Some("https://chaintracks.invalid\n/"),
            Some("https://headers.example/v1 /x"),
            Some("https://headers.example\u{0}"),
            Some("https://headers\u{a0}.example"),
            Some("\0\u{ff}garbage"),
            // non-ASCII (an IDNA mapping could fold it onto the placeholder)
            Some("https://chaintracks\u{ff0e}invalid"),
            Some("https://h\u{e9}aders.example"),
            // no scheme, the wrong scheme, no host
            Some("headers.example"),
            Some("ftp://headers.example"),
            Some("https:/headers.example"),
            Some("https:///headers.example"),
            Some("https://"),
            Some("https://:443"),
            Some("https://[]"),
            Some("https://[::1"),
            Some("https://[::1]x"),
            Some("https://[zz::1]"),
            Some("https://[fe80::1%25eth0]"),
            // a port that is not a port
            Some("https://headers.example:"),
            Some("https://headers.example:abc"),
            Some("https://headers.example:+80"),
            Some("https://headers.example:99999"),
            Some("https://chaintracks.invalid:"),
            // labels that are not a hostname
            Some("https://-headers.example"),
            Some("https://headers-.example"),
            Some("https://headers..example"),
            Some("https://.headers.example"),
            Some("https://headers_svc.example"),
            Some("https://."),
        ];
        for url in refused {
            assert!(
                matches!(
                    resolve_header_service(*url),
                    Err(PaymentVerifyError::NoHeaderService)
                ),
                "{url:?} must be refused as NoHeaderService"
            );
        }

        let accepted = [
            ("https://headers.example", "https://headers.example"),
            ("https://headers.example/", "https://headers.example"),
            (
                "  https://headers.example/v1//  ",
                "https://headers.example/v1",
            ),
            ("HTTPS://Headers.Example", "HTTPS://Headers.Example"),
            ("https://headers.example.", "https://headers.example."),
            (
                "https://headers.example.:8443/v1",
                "https://headers.example.:8443/v1",
            ),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("http://localhost:3000/", "http://localhost:3000"),
            ("https://[::1]:8080/", "https://[::1]:8080"),
            ("https://[::ffff:10.0.0.1]", "https://[::ffff:10.0.0.1]"),
            ("https://invalid.example", "https://invalid.example"),
            (
                "https://chaintracks.invalid.example.com",
                "https://chaintracks.invalid.example.com",
            ),
            (
                "https://xn--hders-kva.example",
                "https://xn--hders-kva.example",
            ),
            (
                "https://headers.example/v1?x=1",
                "https://headers.example/v1?x=1",
            ),
        ];
        for (url, base) in accepted {
            assert_eq!(resolve_header_service(Some(url)).unwrap(), base, "{url:?}");
        }
    }

    /// The host classifier normalises BEFORE the gate compares: case,
    /// port, trailing dot, brackets and path all fold away, so every spelling
    /// of one host is one string, and the forms it will not classify are
    /// `None` rather than a guess.
    #[test]
    fn test_header_service_host_normalises_before_comparison() {
        let normalised = [
            ("https://chaintracks.invalid", "chaintracks.invalid"),
            ("HTTPS://CHAINTRACKS.INVALID.:8443/x", "chaintracks.invalid"),
            ("http://chaintracks.invalid./", "chaintracks.invalid"),
            ("https://Headers.Example.", "headers.example"),
            ("https://headers.example:443/v1", "headers.example"),
            ("https://[::1]:8080", "::1"),
            ("https://[FE80::1]", "fe80::1"),
            ("http://127.0.0.1", "127.0.0.1"),
            ("https://invalid.", "invalid"),
        ];
        for (url, host) in normalised {
            assert_eq!(header_service_host(url).as_deref(), Some(host), "{url:?}");
        }
        for url in [
            "https://chaintracks%2Einvalid",
            "https://chaintracks.invalid\\@real.example",
            "https://user@headers.example",
            "https://headers.example:",
            "https://headers..example",
            "https://headers.example..",
            "ftp://headers.example",
            "https://",
        ] {
            assert_eq!(header_service_host(url), None, "{url:?}");
        }
    }

    #[test]
    fn test_resource_decline_stays_payer_side_in_the_adapter() {
        for bound in ["work", "memory"] {
            let error = accept_verdict(PaymentVerdict::Unverifiable {
                reason: UnverifiableReason::SpendRefused {
                    offset: 42,
                    txid: "ab".into(),
                    input: Some(3),
                    why: format!("script declined under a {bound} resource bound"),
                },
            })
            .unwrap_err();
            assert!(matches!(error, PaymentVerifyError::Unverifiable { .. }));
            assert!(!error.is_server_side());
            let text = error.to_string();
            assert!(
                text.contains("input 3") && text.contains(bound) && text.contains("declined"),
                "{text}"
            );
            assert!(!text.contains("retry the same payment"), "{text}");
        }
    }

    /// The one visible match, as a table: every core word lands on its 0.3
    /// result; `Verified` is the only `Ok`, and every `Unverifiable` is
    /// refused (fail-closed) as the same-named `Err` carrying the reason, so
    /// no host serves on a root that was not checked or a proof that is
    /// absent. `is_server_side` is true for the header lookup alone.
    #[test]
    fn test_accept_verdict_table() {
        assert_eq!(
            accept_verdict(PaymentVerdict::Verified { satoshis: 7 }).unwrap(),
            7
        );
        let refused = accept_verdict(PaymentVerdict::Unverifiable {
            reason: UnverifiableReason::HeaderLookupFailed {
                height: 9,
                reason: "HTTP 503".into(),
            },
        })
        .unwrap_err();
        assert!(
            refused.is_server_side(),
            "fail-closed, the server's side: {refused:?}"
        );
        let text = refused.to_string();
        assert!(
            text.contains("not verified")
                && text.contains("height 9")
                && text.contains("HTTP 503")
                && text.contains("retry the same payment"),
            "{text}"
        );
        let payer = accept_verdict(PaymentVerdict::Unverifiable {
            reason: UnverifiableReason::NoProof { txid: "ab".into() },
        })
        .unwrap_err();
        assert!(!payer.is_server_side(), "{payer:?}");
        assert!(payer.to_string().contains("ab"), "{payer}");
        let opted = accept_verdict(PaymentVerdict::Unverifiable {
            reason: UnverifiableReason::RootsUnchecked {
                satoshis: 5,
                roots: 1,
            },
        });
        assert!(
            opted.is_err(),
            "accept_verdict never serves the opt-out's word; only the named function does"
        );
        assert!(matches!(
            accept_verdict(PaymentVerdict::Underpaid {
                paid: 5,
                required: 10
            }),
            Err(PaymentVerifyError::Underpaid {
                satoshis: 5,
                required: 10
            })
        ));
        assert!(matches!(
            accept_verdict(PaymentVerdict::WrongScript {
                expected: "a".into(),
                actual: "b".into()
            }),
            Err(PaymentVerifyError::WrongScript { expected, actual }) if expected == "a" && actual == "b"
        ));
        assert!(matches!(
            accept_verdict(PaymentVerdict::NoHeaderService),
            Err(PaymentVerifyError::NoHeaderService)
        ));
        assert!(
            !PaymentVerifyError::NoHeaderService.is_server_side(),
            "a misconfiguration is the host's 500, not a 503"
        );
        assert!(matches!(
            accept_verdict(PaymentVerdict::RootMismatch {
                height: 4,
                root: "r".into()
            }),
            Err(PaymentVerifyError::RootMismatch { height: 4, root }) if root == "r"
        ));
    }

    /// The core's faults land on the same-named errors, message intact.
    #[test]
    fn test_fault_mapping_table() {
        let faults = [
            PaymentFault::KeyDerivation("k".into()),
            PaymentFault::Source("s".into()),
        ];
        for fault in faults {
            let text = fault.to_string();
            let err = PaymentVerifyError::from(fault.clone());
            let same_variant = match (&fault, &err) {
                (PaymentFault::KeyDerivation(a), PaymentVerifyError::KeyDerivation(b)) => a == b,
                (PaymentFault::Source(a), PaymentVerifyError::Source(b)) => a == b,
                _ => false,
            };
            assert!(same_variant, "{fault:?} -> {err:?}");
            assert!(!err.is_server_side());
            let _ = text;
        }
    }

    /// The URL service is built only through the gate, and keeps the trimmed
    /// base the gate resolved.
    #[test]
    fn test_url_header_service_is_gated() {
        let service = UrlHeaderService::resolve(Some("  https://headers.example/v1/ ")).unwrap();
        assert_eq!(service.base_url(), "https://headers.example/v1");
        assert!(matches!(
            UrlHeaderService::resolve(Some(DEFAULT_CHAINTRACKS_URL)),
            Err(PaymentVerifyError::NoHeaderService)
        ));
        assert!(matches!(
            UrlHeaderService::resolve(None),
            Err(PaymentVerifyError::NoHeaderService)
        ));
    }

    /// End to end on a correct, proven payment with the header service
    /// injected: the lookup is asked exactly once, at the proof's height; a
    /// matching header accepts, a different one is `RootMismatch` naming the
    /// height and root, and a service error is refused as `Unverifiable`
    /// with `HeaderLookupFailed` at that height (fail-closed, server-side).
    #[tokio::test]
    async fn test_full_verification_spv_outcomes_table() {
        let (_, txid) = beef_with_proven_payment(&our_script(), 1000);

        let (ok, asked) = verify_proven_with(Ok(txid.clone())).await;
        assert_eq!(ok.unwrap(), 1000);
        assert_eq!(asked, vec![PROOF_HEIGHT]);

        let (ok, _) = verify_proven_with(Ok(txid.to_ascii_uppercase())).await;
        assert_eq!(ok.unwrap(), 1000, "root compare is case-insensitive");

        let (err, asked) = verify_proven_with(Ok("00".repeat(32))).await;
        let err = err.unwrap_err();
        assert!(
            matches!(&err, PaymentVerifyError::RootMismatch { height, root }
                if *height == PROOF_HEIGHT && *root == txid),
            "{err}"
        );
        assert_eq!(asked, vec![PROOF_HEIGHT]);

        let (refused, asked) = verify_proven_with(Err("fetch height: timeout".to_string())).await;
        let refused = refused.unwrap_err();
        assert_eq!(
            *reason_of(&refused),
            UnverifiableReason::HeaderLookupFailed {
                height: PROOF_HEIGHT,
                reason: "fetch height: timeout".into()
            },
            "a service error fails closed on the server's side"
        );
        assert!(refused.is_server_side());
        assert_eq!(asked, vec![PROOF_HEIGHT]);
    }

    /// The txid form refuses through the same gate; the txid itself is the
    /// core's (pinned there), carried through unchanged.
    #[tokio::test]
    async fn test_verified_form_shares_the_gate() {
        let (beef, _) = beef_with_proven_payment(&our_script(), 1000);
        let err = verify_brc29_payment_verified(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::NoHeaderService));
        let _: fn(VerifiedPayment) -> (u64, String) = |v| (v.satoshis, v.txid);
    }

    /// The named opt-out is the one function that serves with roots
    /// unchecked, and it says so in its log, not in its result. Every other
    /// refusal still refuses through it: a short output, invalid bytes (a
    /// parent the BEEF does not carry, a transaction with no input, garbage).
    #[test]
    fn test_structural_only_is_the_named_opt_out_and_serves_by_name() {
        let (proven, _) = beef_with_proven_payment(&our_script(), 1000);
        let served = verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &proven,
            0,
            1000,
        )
        .unwrap();
        assert_eq!(served, 1000, "opted out of SPV by name");

        let (short, _) = beef_with_proven_payment(&our_script(), 999);
        let err = verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &short,
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::Underpaid { .. }), "{err}");

        let unproven = beef_with_unproven_payment(&our_script(), 1000);
        let err = verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &unproven,
            0,
            1000,
        )
        .unwrap_err();
        assert!(
            matches!(reason_of(&err), UnverifiableReason::InvalidBeef { kind, .. } if kind == "InputNamesNoElement"),
            "{err}"
        );

        // A parent with no input: invalid bytes to the reader (bsv-rs 0.4.1,
        // `NoInputs` at its leading byte), refused even by name. 0.4.0's
        // reader read it as valid with no root and the door's `NoProof`
        // refused it.
        let parent = rootless(&[(1000, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(1000, hex::decode(our_script()).unwrap())]);
        let (no_input, _) = beef_of(&[&parent, &subject], false);
        let err = verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &no_input,
            0,
            1000,
        )
        .unwrap_err();
        assert!(
            matches!(reason_of(&err), UnverifiableReason::InvalidBeef { offset: 7, kind, .. } if kind == "NoInputs"),
            "a transaction with no input is invalid bytes, even by name: {err}"
        );

        let err = verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
        )
        .unwrap_err();
        assert!(
            matches!(reason_of(&err), UnverifiableReason::InvalidBeef { kind, .. } if kind == "BadVersion"),
            "{err}"
        );
    }

    /// `verify_brc29_payment` with no usable header service is
    /// `NoHeaderService` for a payment that would otherwise pass: never `Ok`,
    /// never a skipped root check. The gate runs before the bytes are read,
    /// so garbage bytes under a missing service are also `NoHeaderService`.
    #[tokio::test]
    async fn test_full_verification_without_header_service_fails_closed() {
        let (beef, _) = beef_with_proven_payment(&our_script(), 1000);
        let no_service: [Option<&str>; 7] = [
            None,
            Some(""),
            Some("  "),
            Some(DEFAULT_CHAINTRACKS_URL),
            Some("https://chaintracks.invalid/"),
            Some("https://headers.invalid"),
            Some("headers.example"),
        ];
        for header_url in no_service {
            let err = verify_brc29_payment(
                SERVER_KEY,
                &sender_identity(),
                "prefix",
                "suffix",
                &beef,
                0,
                1000,
                header_url,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, PaymentVerifyError::NoHeaderService),
                "{header_url:?}: {err}"
            );
        }

        let err = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, PaymentVerifyError::NoHeaderService),
            "the gate runs first: {err}"
        );
    }

    #[test]
    fn test_parse_header_response_accepts_both_root_spellings() {
        let camel = r#"{"status":"success","value":{"merkleRoot":"AbCd"}}"#;
        assert_eq!(parse_header_response(camel, 7).unwrap(), "AbCd");
        let lower = r#"{"status":"success","value":{"merkleroot":"ef01"}}"#;
        assert_eq!(parse_header_response(lower, 7).unwrap(), "ef01");
    }

    #[test]
    fn test_parse_header_response_errors_are_service_errors() {
        let not_success = r#"{"status":"error","value":null}"#;
        assert!(parse_header_response(not_success, 7)
            .unwrap_err()
            .contains("status 'error'"));
        let no_value = r#"{"status":"success"}"#;
        assert!(parse_header_response(no_value, 7)
            .unwrap_err()
            .contains("no header at height 7"));
        let no_root = r#"{"status":"success","value":{"height":7}}"#;
        assert!(parse_header_response(no_root, 7)
            .unwrap_err()
            .contains("missing merkleRoot"));
        assert!(parse_header_response("not json", 7)
            .unwrap_err()
            .contains("parse response"));
    }

    #[test]
    fn test_error_display_names_the_fault() {
        let s = PaymentVerifyError::Underpaid {
            satoshis: 5,
            required: 10,
        }
        .to_string();
        assert!(
            s.contains("5 satoshis") && s.contains("10 are required"),
            "{s}"
        );
        let s = PaymentVerifyError::RootMismatch {
            height: 42,
            root: "ab".into(),
        }
        .to_string();
        assert!(s.contains("height 42"), "{s}");
        let s = PaymentVerifyError::NoHeaderService.to_string();
        assert!(
            s.contains("header service") && s.contains("structural_only"),
            "{s}"
        );
        let s = PaymentVerifyError::Unverifiable {
            reason: UnverifiableReason::SpendRefused {
                offset: 40,
                txid: "cd".into(),
                input: Some(0),
                why: "Script(\"x\")".into(),
            },
        }
        .to_string();
        assert!(
            s.contains("transaction cd") && !s.contains("retry the same payment"),
            "a payer-side refusal does not invite the same payment again: {s}"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(PaymentVerifyError::Source("x".into()));
        assert!(boxed.to_string().contains("source"));
    }
}
