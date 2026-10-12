//! Bytes captured from main 27d0669 before replacing the primitive implementations.
#![cfg(feature = "refund")]
use bsv_middleware_core::{brc104, refund::signer};
use bsv_sdk::{
    primitives::PrivateKey,
    wallet::{Counterparty, KeyDeriverApi, ProtoWallet, Protocol, SecurityLevel},
};

#[test]
fn primitives_golden() {
    let wallet = ProtoWallet::new(Some(PrivateKey::from_hex(&format!("{:064x}", 1)).unwrap()));
    let key = wallet
        .key_deriver()
        .derive_private_key(
            &Protocol::new(SecurityLevel::Counterparty, "3241645161d8"),
            "golden-prefix golden-input",
            &Counterparty::Self_,
        )
        .unwrap();
    let locking = format!(
        "76a914{}88ac",
        hex::encode(signer::hash160(&key.public_key().to_compressed()))
    );
    let mut cases = Vec::new();
    for length in [0, 1, 252, 253, 65535, 65536] {
        let script = format!("51{}", "00".repeat(length));
        let template = serde_json::json!({
            "version": 2, "lockTime": 17, "derivationPrefix": "golden-prefix",
            "inputs": [{"sourceTxid": "ab".repeat(32), "sourceVout": 3,
                "sourceSatoshis": 100000, "sourceLockingScript": locking,
                "derivationPrefix": "golden-prefix", "derivationSuffix": "golden-input"}],
            "outputs": [{"satoshis": 90000, "lockingScript": script},
                {"satoshis": 9999, "derivationSuffix": "golden-change"}]
        });
        let signed = signer::sign_create_action_template(&wallet, &template).unwrap();
        let frame = brc104::build_request_payload(
            &[42; 32],
            "POST",
            "/golden",
            "?a=1",
            &[("x-bsv-test".into(), "value".into())],
            &vec![0x5a; length],
        );
        cases.push(
            serde_json::json!({"length": length, "signed": hex::encode(&signed),
            "txid": signer::compute_txid(&signed), "frame": hex::encode(frame)}),
        );
    }
    let varints: Vec<_> = [
        -2,
        -1,
        0,
        1,
        252,
        253,
        65535,
        65536,
        4294967295,
        4294967296,
        i64::MAX,
    ]
    .into_iter()
    .map(|n| serde_json::json!({"value": n, "bytes": hex::encode(brc104::write_varint(n))}))
    .collect();
    let actual = serde_json::json!({"cases": cases, "varints": varints});
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/primitives_golden.json")).unwrap();
    assert_eq!(actual, expected);
}
