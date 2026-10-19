//! The 0.3 public surface, pinned as call sites (0.4.0, the core extract):
//! every item the fleet calls keeps its name, path and signature. These
//! tests do nothing at run time beyond constructing values; their value is
//! that they COMPILE: a renamed item, a moved path or a changed signature
//! fails the build here before it fails an adopter's.

use crate::middleware::AuthSession;
use crate::types::{AuthContext, BsvPayment, PaymentContext};
use crate::{
    expected_brc29_locking_script, verify_brc29_payment, verify_brc29_payment_output,
    verify_brc29_payment_structural_only, verify_brc29_payment_verified,
    verify_brc29_payment_with_header_lookup, PaymentVerifyError, UnverifiableReason,
    VerifiedPayment,
};

const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// The fleet's payment-verification gate, as written in the agents: the
/// URL form with `Some(url.as_str())`, the output form, the structural
/// opt-out, the derived script, and the two-arm match on the error.
#[tokio::test]
async fn the_fleet_payment_verify_call_sites_compile_unchanged() {
    let header_service: Result<String, PaymentVerifyError> =
        Err(PaymentVerifyError::NoHeaderService);
    let tx: Vec<u8> = vec![0u8; 16];
    let answer: Result<u64, PaymentVerifyError> = match header_service {
        Ok(url) => {
            verify_brc29_payment(
                KEY,
                "02",
                "prefix",
                "suffix",
                &tx,
                0,
                1000,
                Some(url.as_str()),
            )
            .await
        }
        Err(e) => Err(e),
    };
    let render = |err: PaymentVerifyError| match err {
        PaymentVerifyError::NoHeaderService => (500u16, "ERR_SERVER_MISCONFIGURED"),
        _ => (400u16, "ERR_PAYMENT_INVALID"),
    };
    assert_eq!(
        render(answer.unwrap_err()),
        (500, "ERR_SERVER_MISCONFIGURED")
    );
    // 0.4.0 added `Unverifiable` (refused: fail-closed); 0.5.0 gives it the
    // core's reason and `is_server_side()`. The fleet's two-arm match above
    // compiles unchanged because of its `_` arm, and that arm answers the
    // client's 400 for a header outage; the hosts' change is the three-arm
    // form below: 500 misconfigured, 503 the server's transient condition
    // (the quote kept, the same payment retried), 400 everything else.
    let outage = || PaymentVerifyError::Unverifiable {
        reason: UnverifiableReason::HeaderLookupFailed {
            height: 850_000,
            reason: "header service HTTP 503".into(),
        },
    };
    assert_eq!(
        render(outage()),
        (400, "ERR_PAYMENT_INVALID"),
        "what a two-arm host answers; the 503 arm is the hosts' change"
    );
    let render_three = |err: PaymentVerifyError| match err {
        PaymentVerifyError::NoHeaderService => (500u16, "ERR_SERVER_MISCONFIGURED"),
        e if e.is_server_side() => (503u16, "ERR_HEADER_SERVICE_UNAVAILABLE"),
        _ => (400u16, "ERR_PAYMENT_INVALID"),
    };
    assert_eq!(
        render_three(outage()),
        (503, "ERR_HEADER_SERVICE_UNAVAILABLE")
    );
    assert_eq!(
        render_three(PaymentVerifyError::Unverifiable {
            reason: UnverifiableReason::NoProof { txid: "ab".into() },
        }),
        (400, "ERR_PAYMENT_INVALID"),
        "a missing proof is the payer's (ruled 2026-10-09)"
    );
    assert_eq!(
        render_three(PaymentVerifyError::NoHeaderService),
        (500, "ERR_SERVER_MISCONFIGURED")
    );

    let output: Result<u64, PaymentVerifyError> =
        verify_brc29_payment_output(KEY, "02", "prefix", "suffix", &tx, 0, 1000);
    assert!(output.is_err());
    let structural: Result<u64, PaymentVerifyError> =
        verify_brc29_payment_structural_only(KEY, "02", "prefix", "suffix", &tx, 0, 1000);
    assert!(structural.is_err());
    let script: Result<String, PaymentVerifyError> =
        expected_brc29_locking_script(KEY, "02", "prefix", "suffix");
    assert!(matches!(script, Err(PaymentVerifyError::KeyDerivation(_))));
    // 0.5.0: the same gate, the amount and the subject's txid together.
    let with_txid: Result<VerifiedPayment, PaymentVerifyError> =
        verify_brc29_payment_verified(KEY, "02", "prefix", "suffix", &tx, 0, 1000, None).await;
    assert!(matches!(
        with_txid,
        Err(PaymentVerifyError::NoHeaderService)
    ));
    let looked_up: Result<u64, PaymentVerifyError> = verify_brc29_payment_with_header_lookup(
        KEY,
        "02",
        "prefix",
        "suffix",
        &tx,
        0,
        1000,
        |_height: u32| async { Err::<String, String>("no fixture".to_string()) },
    )
    .await;
    assert!(looked_up.is_err());
}

/// The context and session types at their 0.3 paths, with their 0.3 fields.
#[test]
fn the_auth_and_payment_types_keep_their_paths_and_fields() {
    let context: AuthContext = AuthContext::authenticated("02ab".to_string());
    let _: &str = &context.identity_key;
    let _: bool = context.is_authenticated;
    assert!(!AuthContext::unauthenticated().is_authenticated);

    let session = AuthSession {
        server_private_key: KEY.to_string(),
        session_nonce: "s".to_string(),
        peer_nonce: Some("p".to_string()),
        peer_identity_key: "02ab".to_string(),
        request_id: [0u8; 32],
    };
    let signed = crate::sign_json_response(&serde_json::json!({"ok": true}), 200, &[], &session);
    // Building a worker Response needs the Workers runtime; the call shape is
    // what this test pins, and it is checked at compile time.
    drop(signed);

    let payment: BsvPayment = serde_json::from_str(
        r#"{"derivationPrefix":"p","derivationSuffix":"s","transaction":"dHg="}"#,
    )
    .unwrap();
    let _: (&str, &str, &str) = (
        &payment.derivation_prefix,
        &payment.derivation_suffix,
        &payment.transaction,
    );
    let paid = PaymentContext {
        satoshis_paid: 1,
        accepted: true,
        tx: Some(payment.transaction.clone()),
    };
    assert_eq!(paid.satoshis_paid, 1);

    #[cfg(feature = "refund")]
    {
        let info = crate::refund::RefundInfo {
            transaction: String::new(),
            derivation_prefix: String::new(),
            derivation_suffix: String::new(),
            sender_identity_key: String::new(),
            satoshis: 0,
            txid: String::new(),
        };
        let _: &str = &info.txid;
        let err: crate::refund::RefundError = crate::refund::RefundError::Signing("x".into());
        assert!(err.to_string().contains("Signing"));
        let _ = crate::refund::signer::compute_txid;
        let _ = crate::refund::signer::hash160;
    }
}

/// The transport and lane re-exports are the core's items at the 0.3 paths.
#[test]
#[allow(deprecated)]
fn the_transport_and_lane_re_exports_are_the_cores() {
    use crate::transport::{auth_headers, CloudflareTransport, HttpResponseData};
    use bsv_sdk::auth::types::{AuthMessage, MessageType};
    use bsv_sdk::primitives::PrivateKey;

    assert_eq!(
        auth_headers::NONCE,
        bsv_middleware_core::auth_headers::NONCE
    );
    assert_eq!(
        crate::middleware::session_lane::SESSION_HEADER,
        bsv_middleware_core::session_lane::SESSION_HEADER
    );
    assert_eq!(
        crate::middleware::payment::PAYMENT_NONCE_SCOPE,
        bsv_middleware_core::PAYMENT_NONCE_SCOPE
    );
    let mut msg = AuthMessage::new(
        MessageType::General,
        PrivateKey::from_hex(KEY).unwrap().public_key(),
    );
    msg.nonce = Some("n".to_string());
    assert_eq!(
        CloudflareTransport::message_to_headers(&msg),
        bsv_middleware_core::brc104::message_to_headers(&msg)
    );
    let data = HttpResponseData {
        request_id: [1u8; 32],
        status: 200,
        headers: vec![],
        body: vec![],
    };
    assert_eq!(data.to_payload().len(), 43);
}

/// The session binding the core signs over carries exactly the three fields
/// of the adapter's session types, whichever one it is built from.
#[test]
fn the_session_binding_carries_the_three_fields() {
    use bsv_middleware_core::SessionBinding;
    let stored = crate::types::StoredSession {
        session_nonce: "s".into(),
        peer_identity_key: "02ab".into(),
        peer_nonce: Some("p".into()),
        is_authenticated: true,
        certificates_required: false,
        certificates_validated: false,
        created_at: 1,
        last_update: 2,
    };
    let session = AuthSession {
        server_private_key: KEY.into(),
        session_nonce: "s".into(),
        peer_nonce: Some("p".into()),
        peer_identity_key: "02ab".into(),
        request_id: [0u8; 32],
    };
    let expected = SessionBinding::new("s", "02ab", Some("p".into()));
    assert_eq!(SessionBinding::from(&stored), expected);
    assert_eq!(SessionBinding::from(&session), expected);
}
