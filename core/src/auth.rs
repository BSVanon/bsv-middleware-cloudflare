//! BRC-103 message build and verify: the server's half of the mutual
//! authentication, as pure functions over an [`AuthMessage`] and the session
//! it rides on. Nonces are data the host stores; the clock, the store and
//! the transport are the host's.
//!
//! The identity a general message claims in its header is a CLAIM; the
//! session's identity is the fact. [`verify_message_signature`] verifies
//! against the session's peer identity (the reference verifies with
//! `peerSession.peerIdentityKey`), and
//! [`message_identity_is_sessions`] refuses a message naming another
//! identity before its signature is judged.

use std::fmt;

use bsv_sdk::auth::types::{AuthMessage, MessageType, RequestedCertificateSet, AUTH_PROTOCOL_ID};
use bsv_sdk::auth::utils::create_nonce;
use bsv_sdk::auth::VerifiableCertificate;
use bsv_sdk::primitives::PublicKey;
use bsv_sdk::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel,
    VerifySignatureArgs,
};

use crate::brc104::HttpResponseData;

/// What a BRC-103 session binds: the server's session nonce, the peer's
/// identity, and the peer's handshake nonce. The host's stored session
/// carries more (timestamps, certificate state); these three are what the
/// signatures are keyed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// The server's session nonce (the HMAC nonce minted at the handshake).
    pub session_nonce: String,
    /// The peer's identity public key (hex).
    pub peer_identity_key: String,
    /// The peer's handshake nonce. Set ONCE at the handshake and never
    /// updated for general messages: the per-message nonce is random, and
    /// storing it here breaks the reference client's `yourNonce` check.
    pub peer_nonce: Option<String>,
}

impl SessionBinding {
    /// A binding from its three parts.
    pub fn new(
        session_nonce: impl Into<String>,
        peer_identity_key: impl Into<String>,
        peer_nonce: Option<String>,
    ) -> Self {
        Self {
            session_nonce: session_nonce.into(),
            peer_identity_key: peer_identity_key.into(),
            peer_nonce,
        }
    }
}

/// Why a message could not be signed or verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The message is not a valid BRC-103 message for this session.
    InvalidAuthentication(String),
    /// The server's own key is not usable.
    Config(String),
    /// The SDK refused (a key that does not parse, a signature it cannot build).
    Sdk(String),
    /// A value could not be serialized.
    Serialization(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidAuthentication(m) => write!(f, "Invalid authentication: {}", m),
            AuthError::Config(m) => write!(f, "Configuration error: {}", m),
            AuthError::Sdk(m) => write!(f, "SDK error: {}", m),
            AuthError::Serialization(m) => write!(f, "Serialization error: {}", m),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<bsv_sdk::Error> for AuthError {
    fn from(e: bsv_sdk::Error) -> Self {
        AuthError::Sdk(e.to_string())
    }
}

/// The auth protocol: security level 2 (counterparty), `AUTH_PROTOCOL_ID`.
fn auth_protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID)
}

/// Sign an auth message with the server's wallet.
///
/// Matches the reference `Peer.signMessage`:
/// - Protocol: `AUTH_PROTOCOL_ID` ("auth message signature")
/// - Security level: Counterparty (2)
/// - Key ID: `"{nonce} {peer_session_nonce}"` (from `AuthMessage::get_key_id`)
/// - Counterparty: the peer's identity key
pub fn sign_message(
    wallet: &ProtoWallet,
    message: &mut AuthMessage,
    session: &SessionBinding,
) -> Result<(), AuthError> {
    let data = message.signing_data();
    let key_id = message.get_key_id(session.peer_nonce.as_deref());
    let peer_key = PublicKey::from_hex(&session.peer_identity_key)?;

    let result = wallet.create_signature(CreateSignatureArgs {
        data: Some(data),
        hash_to_directly_sign: None,
        protocol_id: auth_protocol(),
        key_id,
        counterparty: Some(Counterparty::Other(peer_key)),
    })?;

    message.signature = Some(result.signature);
    Ok(())
}

/// Verify an auth message's signature against the session it rides on.
///
/// Matches the reference `Peer.verifyMessageSignature`:
/// - the message's `signing_data()` is the data
/// - Key ID: `"{nonce} {server_session_nonce}"`
/// - Counterparty: the SESSION's peer identity, never the message header's.
///   The header is a claim; with the header as the counterparty ANY wallet's
///   honest signature verified under a session another identity's unsigned
///   initialRequest opened.
///
/// `Ok(false)` for a signature that does not verify, a session whose
/// identity is not a key, or an SDK refusal; `Err` only for an unsigned
/// message.
pub fn verify_message_signature(
    wallet: &ProtoWallet,
    message: &AuthMessage,
    session: &SessionBinding,
) -> Result<bool, AuthError> {
    let signature = message
        .signature
        .as_ref()
        .ok_or_else(|| AuthError::InvalidAuthentication("Message not signed".into()))?;

    let data = message.signing_data();
    let key_id = message.get_key_id(Some(session.session_nonce.as_str()));
    let Ok(session_identity) = PublicKey::from_hex(&session.peer_identity_key) else {
        return Ok(false); // a session whose identity is not a key verifies nothing
    };

    let result = wallet.verify_signature(VerifySignatureArgs {
        data: Some(data),
        hash_to_directly_verify: None,
        signature: signature.clone(),
        protocol_id: auth_protocol(),
        key_id,
        counterparty: Some(Counterparty::Other(session_identity)),
        for_self: None,
    });

    match result {
        Ok(r) => Ok(r.valid),
        Err(_) => Ok(false),
    }
}

/// Verify an already hashed message using the session's identity binding.
/// The caller must hash exactly `message.signing_data()`; General HTTP messages
/// use [`crate::brc104::request_payload_digest`].
pub fn verify_message_digest(
    wallet: &ProtoWallet,
    message: &AuthMessage,
    session: &SessionBinding,
    digest: [u8; 32],
) -> Result<bool, AuthError> {
    let signature = message
        .signature
        .as_ref()
        .ok_or_else(|| AuthError::InvalidAuthentication("Message not signed".into()))?;

    let key_id = message.get_key_id(Some(session.session_nonce.as_str()));
    let Ok(session_identity) = PublicKey::from_hex(&session.peer_identity_key) else {
        return Ok(false); // a session whose identity is not a key verifies nothing
    };

    let result = wallet.verify_signature(VerifySignatureArgs {
        data: None,
        hash_to_directly_verify: Some(digest),
        signature: signature.clone(),
        protocol_id: auth_protocol(),
        key_id,
        counterparty: Some(Counterparty::Other(session_identity)),
        for_self: None,
    });

    match result {
        Ok(r) => Ok(r.valid),
        Err(_) => Ok(false),
    }
}

/// Whether the identity a message claims in its header IS the session's
/// (case-insensitive hex). A general message naming another identity over
/// this session is refused by name before its signature is judged.
pub fn message_identity_is_sessions(message: &AuthMessage, session: &SessionBinding) -> bool {
    message
        .identity_key
        .to_hex()
        .eq_ignore_ascii_case(&session.peer_identity_key)
}

/// A random nonce (32 bytes, base64), for general messages. Session nonces
/// are HMAC nonces instead ([`create_session_nonce`]).
pub fn generate_random_nonce() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    bsv_sdk::primitives::to_base64(&bytes)
}

/// The server's identity key, from its wallet.
pub fn server_identity_key(wallet: &ProtoWallet) -> Result<PublicKey, AuthError> {
    let identity_result = wallet.get_public_key(GetPublicKeyArgs {
        identity_key: true,
        protocol_id: None,
        key_id: None,
        counterparty: None,
        for_self: None,
    })?;
    Ok(PublicKey::from_hex(&identity_result.public_key)?)
}

/// The server's session nonce for a new session: an HMAC nonce under
/// `originator` the server can later recognise as its own (the reference
/// `Peer`'s `createNonce` with counterparty self).
pub async fn create_session_nonce(
    wallet: &ProtoWallet,
    originator: &str,
) -> Result<String, AuthError> {
    Ok(create_nonce(wallet, None, originator).await?)
}

/// The signed `InitialResponse` to a peer's `InitialRequest`, for a session
/// the host has just created: `nonce` = `initial_nonce` = the session nonce,
/// `your_nonce` = the peer's nonce echoed back, `requested_certificates` if
/// the server asks for any, signed over the peer's nonce.
pub fn build_initial_response(
    wallet: &ProtoWallet,
    session: &SessionBinding,
    requested_certificates: Option<RequestedCertificateSet>,
) -> Result<AuthMessage, AuthError> {
    let mut response = AuthMessage::new(MessageType::InitialResponse, server_identity_key(wallet)?);
    response.nonce = Some(session.session_nonce.clone());
    response.initial_nonce = Some(session.session_nonce.clone());
    response.your_nonce = session.peer_nonce.clone();
    response.requested_certificates = requested_certificates;
    sign_message(wallet, &mut response, session)?;
    Ok(response)
}

/// A signed `General` message over `payload` for this session: a fresh
/// random nonce, `your_nonce` = the peer's HANDSHAKE nonce (never a
/// per-message one), signed.
pub fn sign_general_message(
    wallet: &ProtoWallet,
    session: &SessionBinding,
    payload: Vec<u8>,
) -> Result<AuthMessage, AuthError> {
    let mut message = AuthMessage::new(MessageType::General, server_identity_key(wallet)?);
    message.nonce = Some(generate_random_nonce());
    message.your_nonce = session.peer_nonce.clone();
    message.payload = Some(payload);
    sign_message(wallet, &mut message, session)?;
    Ok(message)
}

/// The signed general message that carries an HTTP response: the response's
/// BRC-104 payload ([`HttpResponseData::to_payload`]) signed for the session.
pub fn sign_http_response(
    wallet: &ProtoWallet,
    session: &SessionBinding,
    response: &HttpResponseData,
) -> Result<AuthMessage, AuthError> {
    sign_general_message(wallet, session, response.to_payload())
}

/// The signed `CertificateResponse` carrying `certificates` for this session.
pub fn build_certificate_response(
    wallet: &ProtoWallet,
    session: &SessionBinding,
    certificates: Vec<VerifiableCertificate>,
) -> Result<AuthMessage, AuthError> {
    let mut response = AuthMessage::new(
        MessageType::CertificateResponse,
        server_identity_key(wallet)?,
    );
    response.nonce = Some(generate_random_nonce());
    response.your_nonce = session.peer_nonce.clone();
    response.certificates = Some(certificates);
    sign_message(wallet, &mut response, session)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_sdk::primitives::PrivateKey;

    fn test_wallet(hex: &str) -> ProtoWallet {
        ProtoWallet::new(Some(PrivateKey::from_hex(hex).unwrap()))
    }

    fn test_key(hex: &str) -> PublicKey {
        PrivateKey::from_hex(hex).unwrap().public_key()
    }

    const SERVER_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const CLIENT_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const OTHER_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000003";

    /// The CLIENT's view of the session: its own nonce is the session nonce
    /// (the server signed with it as `peer_nonce`), the server is the peer,
    /// and the server's nonce is the peer nonce.
    fn client_side(own_nonce: &str, server_nonce: &str) -> SessionBinding {
        SessionBinding::new(
            own_nonce,
            test_key(SERVER_KEY_HEX).to_hex(),
            Some(server_nonce.to_string()),
        )
    }

    #[test]
    fn test_sign_and_verify_initial_response() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let client_pk = test_key(CLIENT_KEY_HEX);

        let session = SessionBinding::new(
            "server-nonce-1",
            client_pk.to_hex(),
            Some("client-nonce-1".to_string()),
        );
        let msg = build_initial_response(&server_wallet, &session, None).unwrap();
        assert_eq!(msg.message_type, MessageType::InitialResponse);
        assert_eq!(msg.nonce.as_deref(), Some("server-nonce-1"));
        assert_eq!(msg.initial_nonce.as_deref(), Some("server-nonce-1"));
        assert_eq!(msg.your_nonce.as_deref(), Some("client-nonce-1"));
        assert!(msg.signature.is_some(), "Message should be signed");
        assert!(msg.requested_certificates.is_none());

        // The client verifies with the server's session nonce as the key_id component.
        let client_wallet = test_wallet(CLIENT_KEY_HEX);
        let is_valid = verify_message_signature(
            &client_wallet,
            &msg,
            &client_side("client-nonce-1", "server-nonce-1"),
        )
        .unwrap();
        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn test_initial_response_carries_requested_certificates() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let session = SessionBinding::new("s", test_key(CLIENT_KEY_HEX).to_hex(), Some("c".into()));
        let requested = RequestedCertificateSet::default();
        let msg =
            build_initial_response(&server_wallet, &session, Some(requested.clone())).unwrap();
        assert!(msg.requested_certificates.is_some());
    }

    #[test]
    fn test_sign_and_verify_general_message() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let session = SessionBinding::new(
            "server-session-nonce",
            test_key(CLIENT_KEY_HEX).to_hex(),
            Some("client-nonce".to_string()),
        );
        let msg = sign_general_message(&server_wallet, &session, vec![1, 2, 3, 4, 5]).unwrap();
        assert_eq!(msg.message_type, MessageType::General);
        assert_eq!(msg.your_nonce.as_deref(), Some("client-nonce"));
        assert!(msg.nonce.is_some());
        assert_eq!(msg.payload, Some(vec![1, 2, 3, 4, 5]));

        let client_wallet = test_wallet(CLIENT_KEY_HEX);
        assert!(verify_message_signature(
            &client_wallet,
            &msg,
            &client_side("client-nonce", "server-session-nonce")
        )
        .unwrap());
    }

    #[test]
    fn test_tampered_payload_fails_verification() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let session = SessionBinding::new(
            "s-nonce",
            test_key(CLIENT_KEY_HEX).to_hex(),
            Some("c".into()),
        );
        let mut msg = sign_general_message(&server_wallet, &session, b"original".to_vec()).unwrap();
        msg.payload = Some(b"tampered".to_vec());
        let client_wallet = test_wallet(CLIENT_KEY_HEX);
        assert!(
            !verify_message_signature(&client_wallet, &msg, &client_side("c", "s-nonce")).unwrap()
        );
    }

    #[test]
    fn test_wrong_session_nonce_fails_verification() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let session = SessionBinding::new(
            "s-nonce",
            test_key(CLIENT_KEY_HEX).to_hex(),
            Some("c".into()),
        );
        let msg = sign_general_message(&server_wallet, &session, b"x".to_vec()).unwrap();
        let client_wallet = test_wallet(CLIENT_KEY_HEX);
        assert!(
            verify_message_signature(&client_wallet, &msg, &client_side("c", "s-nonce")).unwrap()
        );
        assert!(!verify_message_signature(
            &client_wallet,
            &msg,
            &client_side("other-nonce", "s-nonce")
        )
        .unwrap());
    }

    /// The session's identity is the counterparty, never the header's: a
    /// message honestly signed by ANOTHER wallet, over a session opened for
    /// the client, does not verify, and its header is refused by name.
    #[test]
    fn test_another_identitys_honest_signature_is_refused_under_this_session() {
        let other_wallet = test_wallet(OTHER_KEY_HEX);
        let server_pk = test_key(SERVER_KEY_HEX);
        // The other wallet signs a general message toward the server.
        let other_session =
            SessionBinding::new("s-nonce", server_pk.to_hex(), Some("s-nonce".into()));
        let msg = sign_general_message(&other_wallet, &other_session, b"hi".to_vec()).unwrap();

        // The server's session binds the CLIENT's identity.
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let server_session =
            SessionBinding::new("s-nonce", test_key(CLIENT_KEY_HEX).to_hex(), None);
        assert!(!message_identity_is_sessions(&msg, &server_session));
        assert!(!verify_message_signature(&server_wallet, &msg, &server_session).unwrap());

        // And a session that does bind the other identity verifies it.
        let bound = SessionBinding::new("s-nonce", test_key(OTHER_KEY_HEX).to_hex(), None);
        assert!(message_identity_is_sessions(&msg, &bound));
        assert!(verify_message_signature(&server_wallet, &msg, &bound).unwrap());
    }

    #[test]
    fn test_identity_match_is_case_insensitive() {
        let msg = AuthMessage::new(MessageType::General, test_key(CLIENT_KEY_HEX));
        let upper = SessionBinding::new(
            "s",
            test_key(CLIENT_KEY_HEX).to_hex().to_ascii_uppercase(),
            None,
        );
        assert!(message_identity_is_sessions(&msg, &upper));
        let other = SessionBinding::new("s", test_key(OTHER_KEY_HEX).to_hex(), None);
        assert!(!message_identity_is_sessions(&msg, &other));
    }

    #[test]
    fn test_unsigned_message_is_an_error_and_bad_session_identity_is_false() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let msg = AuthMessage::new(MessageType::General, test_key(CLIENT_KEY_HEX));
        let session = SessionBinding::new("s", test_key(CLIENT_KEY_HEX).to_hex(), None);
        let err = verify_message_signature(&server_wallet, &msg, &session).unwrap_err();
        assert_eq!(
            err,
            AuthError::InvalidAuthentication("Message not signed".into())
        );
        assert!(err.to_string().contains("Message not signed"));

        let mut signed = msg;
        signed.signature = Some(vec![1, 2, 3]);
        let not_a_key = SessionBinding::new("s", "not-a-key", None);
        assert_eq!(
            verify_message_signature(&server_wallet, &signed, &not_a_key),
            Ok(false)
        );
        assert!(matches!(
            sign_message(&server_wallet, &mut signed, &not_a_key),
            Err(AuthError::Sdk(_))
        ));
    }

    #[test]
    fn test_random_nonces_differ_and_decode_to_32_bytes() {
        let a = generate_random_nonce();
        let b = generate_random_nonce();
        assert_ne!(a, b);
        assert_eq!(bsv_sdk::primitives::from_base64(&a).unwrap().len(), 32);
    }

    #[test]
    fn test_server_identity_key_is_the_wallets() {
        let wallet = test_wallet(SERVER_KEY_HEX);
        assert_eq!(
            server_identity_key(&wallet).unwrap(),
            test_key(SERVER_KEY_HEX)
        );
    }

    #[tokio::test]
    async fn test_session_nonce_is_an_hmac_nonce_the_server_recognises() {
        let wallet = test_wallet(SERVER_KEY_HEX);
        let nonce = create_session_nonce(&wallet, "core-test").await.unwrap();
        assert!(
            bsv_sdk::auth::utils::verify_nonce(&nonce, &wallet, None, "core-test")
                .await
                .unwrap()
        );
        assert!(!bsv_sdk::auth::utils::verify_nonce(
            &nonce,
            &test_wallet(OTHER_KEY_HEX),
            None,
            "core-test"
        )
        .await
        .unwrap_or_default());
    }

    #[test]
    fn test_http_response_signature_covers_the_body() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let session = SessionBinding::new(
            "s-nonce",
            test_key(CLIENT_KEY_HEX).to_hex(),
            Some("c".into()),
        );
        let data = HttpResponseData {
            request_id: [9; 32],
            status: 200,
            headers: vec![("x-bsv-a".into(), "1".into())],
            body: b"{\"ok\":true}".to_vec(),
        };
        let msg = sign_http_response(&server_wallet, &session, &data).unwrap();
        assert_eq!(msg.payload.as_deref(), Some(data.to_payload().as_slice()));
        let client_wallet = test_wallet(CLIENT_KEY_HEX);
        assert!(
            verify_message_signature(&client_wallet, &msg, &client_side("c", "s-nonce")).unwrap()
        );
        let mut other = data.clone();
        other.body = b"{\"ok\":false}".to_vec();
        let mut forged = msg.clone();
        forged.payload = Some(other.to_payload());
        assert!(
            !verify_message_signature(&client_wallet, &forged, &client_side("c", "s-nonce"))
                .unwrap()
        );
    }

    #[test]
    fn test_certificate_response_is_signed_for_the_session() {
        let server_wallet = test_wallet(SERVER_KEY_HEX);
        let session = SessionBinding::new(
            "s-nonce",
            test_key(CLIENT_KEY_HEX).to_hex(),
            Some("c".into()),
        );
        let msg = build_certificate_response(&server_wallet, &session, vec![]).unwrap();
        assert_eq!(msg.message_type, MessageType::CertificateResponse);
        assert_eq!(msg.certificates.as_ref().map(Vec::len), Some(0));
        assert_eq!(msg.your_nonce.as_deref(), Some("c"));
        let client_wallet = test_wallet(CLIENT_KEY_HEX);
        assert!(
            verify_message_signature(&client_wallet, &msg, &client_side("c", "s-nonce")).unwrap()
        );
    }

    /// Structural pin: the verify's counterparty is the SESSION's identity
    /// (`peerSession.peerIdentityKey` in the reference), never the message
    /// header's, and the identity binding compares the header to the session.
    #[test]
    fn the_verify_counterparty_is_the_sessions_identity_never_the_headers() {
        let whole = include_str!("auth.rs");
        let src = &whole[..whole.find("#[cfg(test)]").unwrap()];
        let verify_fn = &src[src.find("pub fn verify_message_signature(").unwrap()..];
        let verify_fn = &verify_fn[..verify_fn.find("\n}\n").unwrap()];
        assert!(
            verify_fn.contains("PublicKey::from_hex(&session.peer_identity_key)")
                && verify_fn.contains("Counterparty::Other(session_identity)")
                && !verify_fn.contains("message.identity_key"),
            "the counterparty is the session's identity, never the header's"
        );
        let bind_fn = &src[src.find("pub fn message_identity_is_sessions(").unwrap()..];
        let bind_fn = &bind_fn[..bind_fn.find("\n}\n").unwrap()];
        assert!(
            bind_fn.contains("message")
                && bind_fn.contains(".identity_key")
                && bind_fn.contains("eq_ignore_ascii_case(&session.peer_identity_key)"),
            "the binding compares the header's claim to the session's fact"
        );
    }

    #[test]
    fn test_auth_error_display_and_sdk_conversion() {
        assert!(AuthError::Config("bad key".into())
            .to_string()
            .contains("Configuration error: bad key"));
        assert!(AuthError::Serialization("x".into())
            .to_string()
            .starts_with("Serialization error"));
        let e: AuthError = PublicKey::from_hex("zz").unwrap_err().into();
        assert!(matches!(e, AuthError::Sdk(_)));
        assert!(e.to_string().starts_with("SDK error"));
        let boxed: Box<dyn std::error::Error> = Box::new(e);
        assert!(!boxed.to_string().is_empty());
    }
    #[test]
    fn direct_digest_verifies_identically_and_rejects_tampering() {
        use bsv_sdk::primitives::hash::sha256;
        let server = test_wallet(SERVER_KEY_HEX);
        let client = test_wallet(CLIENT_KEY_HEX);
        let binding = SessionBinding::new(
            "s-nonce",
            test_key(CLIENT_KEY_HEX).to_hex(),
            Some("c".into()),
        );
        let message =
            sign_general_message(&server, &binding, b"authenticated multipart body".to_vec())
                .unwrap();
        let digest: [u8; 32] = sha256(&message.signing_data());
        let verify_binding = client_side("c", "s-nonce");
        assert!(verify_message_signature(&client, &message, &verify_binding).unwrap());
        let mut without_payload = message;
        without_payload.payload = None;
        assert!(verify_message_digest(&client, &without_payload, &verify_binding, digest).unwrap());
        let mut bad = digest;
        bad[0] ^= 1;
        assert!(!verify_message_digest(&client, &without_payload, &verify_binding, bad).unwrap());
    }
}
