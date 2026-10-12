//! BRC-29 payment-verification conformance: every case of
//! `conformance/brc29-payment-vectors.json` through the core's
//! [`verify_brc29_payment`] with the header service replaced by a stub that
//! answers from the case's `header_service.lookup`.
//!
//! The file is owned by the stack review repository (bsv-stack-lean, 22
//! cases since 2026-10-09). This crate ships its own copy under
//! `core/conformance/` so the published package runs the file on its own;
//! the Workers adapter's runner (`tests/conformance_brc29.rs` at the
//! repository root) pins the two copies byte-identical and the root copy to
//! the owner's by digest. This runner reads it the way a second
//! implementation does: from JSON only, comparing `expected.word` and
//! `expected.fields`. The six words are the core's [`PaymentVerdict`].
//! `Unverifiable` emits `fields.height` when its reason is the server's (the
//! lowest height the service could not answer for: `spv-lookup-error`, the
//! ruling of 2026-10-08) and no fields when it is the payer's (the no-root
//! class: `spv-no-root`, `spv-incomplete-beef`, ruled 2026-10-09); this
//! runner also holds those two to the payer's side and to a refusal that
//! names the absent transaction. `config` cases carry the adapter's URL
//! gate's refusal: the core has no URL, so a refused configuration is
//! `None` service.

use std::cell::RefCell;

use bsv_middleware_core::brc29::{expected_locking_script, sender_locking_script};
use bsv_middleware_core::{
    verify_brc29_payment, verify_payment_output, LookupFn, MerkleRoot, NoService, PaymentFault,
    PaymentVerdict, ServiceError, UnverifiableReason,
};
use bsv_sdk::primitives::PrivateKey;
use bsv_sdk::transaction::Transaction;
use serde_json::{json, Value};

/// This crate's copy of the vector file (inside the package, so the
/// published tarball runs it); the adapter pins it equal to the root copy.
const VECTORS: &str = include_str!("../conformance/brc29-payment-vectors.json");
const CASES: usize = 22;
const NO_ROOT_CASES: [&str; 2] = ["spv-no-root", "spv-incomplete-beef"];

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string in {v}"))
}

fn u(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not an integer in {v}"))
}

/// The header lookup a case describes: `answer: "root"` answers
/// `merkle_root` at `height` (and nothing else), `answer: "error"` fails;
/// a `null` lookup (the no-root cases) is never asked, and errors if it is.
fn lookup_answer(lookup: &Value, height: u32) -> Result<Option<MerkleRoot>, ServiceError> {
    if lookup.is_null() {
        return Err(ServiceError::new(format!(
            "the header service was asked at height {height}"
        )));
    }
    match s(lookup, "answer") {
        "root" if u(lookup, "height") == u64::from(height) => {
            Ok(Some(MerkleRoot::new(s(lookup, "merkle_root"))))
        }
        "root" => Ok(None),
        "error" => Err(ServiceError::new(s(lookup, "reason"))),
        other => panic!("unknown lookup answer {other:?}"),
    }
}

/// The conformance word and fields for a core answer.
fn word_of(answer: &Result<PaymentVerdict, PaymentFault>) -> (String, Value) {
    match answer {
        Ok(PaymentVerdict::Verified { satoshis }) => {
            ("Verified".into(), json!({ "satoshis": satoshis }))
        }
        Ok(PaymentVerdict::Unverifiable { reason }) => match reason {
            UnverifiableReason::HeaderLookupFailed { height, .. } => {
                ("Unverifiable".into(), json!({ "height": height }))
            }
            _ => ("Unverifiable".into(), json!({})),
        },
        Ok(PaymentVerdict::Underpaid { paid, required }) => (
            "Underpaid".into(),
            json!({ "paid": paid, "required": required }),
        ),
        Ok(PaymentVerdict::WrongScript { expected, actual }) => (
            "WrongScript".into(),
            json!({ "expected_script": expected, "actual_script": actual }),
        ),
        Ok(PaymentVerdict::NoHeaderService) => ("NoHeaderService".into(), json!({})),
        Ok(PaymentVerdict::RootMismatch { height, root }) => (
            "RootMismatch".into(),
            json!({ "height": height, "merkle_root": root }),
        ),
        Err(fault) => (format!("Fault({fault:?})"), json!({})),
    }
}

/// Run one case: `stage: "config"` is a configuration the adapter's gate
/// refused, so the core sees no service; every other stage runs through a
/// stub service answering from the case's lookup. Returns the answer and
/// the heights the stub was asked for.
async fn run_case(case: &Value) -> (Result<PaymentVerdict, PaymentFault>, Vec<u32>) {
    let tx = hex::decode(s(&case["transaction"], "beef_hex")).unwrap();
    let server_key = s(case, "server_private_key");
    let sender = s(case, "sender_identity_key");
    let prefix = s(case, "derivation_prefix");
    let suffix = s(case, "derivation_suffix");
    let index = u(case, "output_index") as usize;
    let required = u(case, "required_satoshis");

    if s(case, "stage") == "config" {
        let answer = verify_brc29_payment(
            server_key,
            sender,
            prefix,
            suffix,
            &tx,
            index,
            required,
            None::<&NoService>,
            None,
        )
        .await;
        return (answer, Vec::new());
    }

    let asked = RefCell::new(Vec::new());
    let lookup = &case["header_service"]["lookup"];
    let service = LookupFn(|height| {
        asked.borrow_mut().push(height);
        let answer = lookup_answer(lookup, height);
        async move { answer }
    });
    let answer = verify_brc29_payment(
        server_key,
        sender,
        prefix,
        suffix,
        &tx,
        index,
        required,
        Some(&service),
        None,
    )
    .await;
    let primary_asked = asked.borrow().clone();
    struct Chunks<'a> {
        bytes: &'a [u8],
        n: usize,
    }
    impl bsv_middleware_core::AsyncByteSource for Chunks<'_> {
        async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            if self.bytes.is_empty() {
                return Ok(None);
            }
            let n = self.n.min(self.bytes.len());
            let out = self.bytes[..n].to_vec();
            self.bytes = &self.bytes[n..];
            Ok(Some(out))
        }
    }
    for n in [1, 7] {
        for limit in [None, Some(1_000_000)] {
            let result = bsv_middleware_core::verify_brc29_payment_stream(
                server_key,
                sender,
                prefix,
                suffix,
                &mut Chunks { bytes: &tx, n },
                index,
                required,
                Some(&service),
                limit,
            )
            .await;
            let word = result.map(|v| match v {
                Ok(v) => PaymentVerdict::Verified {
                    satoshis: v.satoshis,
                },
                Err(v) => v,
            });
            assert_eq!(
                word_of(&word),
                word_of(&answer),
                "chunk {n}, limit {limit:?}"
            );
        }
    }
    (answer, primary_asked)
}

/// Every txid a case's BEEF names: the subject's, and each input's source
/// up the linked ancestry.
fn txids_named(tx: &Transaction, out: &mut Vec<String>) {
    out.push(tx.id());
    for input in &tx.inputs {
        if let Some(source) = &input.source_txid {
            out.push(source.clone());
        }
        if let Some(parent) = &input.source_transaction {
            txids_named(parent, out);
        }
    }
}

/// The checks every case gets that do not depend on the verdict: the
/// identity and script derivations from BOTH sides, and that the listed
/// outputs are the outputs of the BEEF's subject transaction.
fn check_case_is_self_consistent(case: &Value, name: &str) -> Transaction {
    let server = PrivateKey::from_hex(s(case, "server_private_key")).unwrap();
    assert_eq!(
        server.public_key().to_hex(),
        s(case, "server_identity_key"),
        "{name}: server_identity_key"
    );
    let expected = expected_locking_script(
        s(case, "server_private_key"),
        s(case, "sender_identity_key"),
        s(case, "derivation_prefix"),
        s(case, "derivation_suffix"),
    )
    .unwrap();
    assert_eq!(
        expected,
        s(case, "expected_locking_script"),
        "{name}: expected_locking_script"
    );
    let sender_side = sender_locking_script(
        s(case, "sender_private_key"),
        s(case, "server_identity_key"),
        s(case, "derivation_prefix"),
        s(case, "derivation_suffix"),
    )
    .unwrap();
    assert_eq!(
        sender_side, expected,
        "{name}: the sender derives the same script (BRC-42)"
    );
    let txv = &case["transaction"];
    let tx = Transaction::from_beef(&hex::decode(s(txv, "beef_hex")).unwrap(), None).unwrap();
    assert_eq!(tx.id(), s(txv, "txid"), "{name}: txid");
    let listed = txv["outputs"].as_array().unwrap();
    assert_eq!(tx.outputs.len(), listed.len(), "{name}: output count");
    for (out, want) in tx.outputs.iter().zip(listed) {
        assert_eq!(out.satoshis.unwrap_or(0), u(want, "satoshis"), "{name}");
        assert_eq!(
            out.locking_script.to_hex(),
            s(want, "locking_script"),
            "{name}"
        );
    }
    tx
}

#[tokio::test]
async fn every_brc29_vector_gives_its_word_through_the_trait() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(doc["schema"], "brc29-payment-vectors/1");
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), CASES, "the 22 vectors");
    let words = doc["words"].as_object().unwrap();
    assert_eq!(words.len(), 6, "six words");

    let mut mismatches = Vec::new();
    let mut table = Vec::new();
    for case in cases {
        let name = s(case, "name");
        let subject = check_case_is_self_consistent(case, name);

        let (answer, asked) = run_case(case).await;
        let (word, fields) = word_of(&answer);
        table.push(format!("{name}: {word} {fields}"));
        let expected = &case["expected"];
        if word != s(expected, "word") || fields != expected["fields"] {
            mismatches.push(format!(
                "{name}: intended {} {}, core gave {word} {fields}",
                expected["word"], expected["fields"]
            ));
        }
        // The outcome, not only the spelling: `Verified` is the one word
        // that serves; every other word, `Unverifiable` included, is refused.
        if let Ok(verdict) = &answer {
            let serves = s(expected, "word") == "Verified";
            if verdict.is_verified() != serves || verdict.is_refused() == serves {
                mismatches.push(format!(
                    "{name}: {} must {} but the core's predicates say verified={} refused={}",
                    expected["word"],
                    if serves { "serve" } else { "refuse" },
                    verdict.is_verified(),
                    verdict.is_refused()
                ));
            }
        }
        if !case["requires_merkle_lookup"].as_bool().unwrap() {
            assert!(
                asked.is_empty() || word == "Verified",
                "{name}: a refusal that does not need a lookup must not ask for one"
            );
        } else {
            let proof_height = u(&case["transaction"]["proof"], "height") as u32;
            assert_eq!(
                asked,
                vec![proof_height],
                "{name}: asked once, at the proof's height"
            );
        }
        // The no-root class (ruled 2026-10-09): the payer's side, no fields,
        // the refusal names a transaction of the case (the one whose proof
        // is absent), the service never asked.
        if NO_ROOT_CASES.contains(&name) {
            let verdict = answer.as_ref().unwrap();
            assert!(
                !verdict.is_server_side_unverifiable(),
                "{name}: the payer's side: {verdict:?}"
            );
            let PaymentVerdict::Unverifiable { reason } = verdict else {
                panic!("{name}: expected Unverifiable, got {verdict:?}");
            };
            assert!(!reason.is_server_side());
            let shown = verdict.to_string();
            let mut named = Vec::new();
            txids_named(&subject, &mut named);
            assert!(
                named.iter().any(|txid| shown.contains(txid)),
                "{name}: the refusal must name a transaction of the case: {shown}"
            );
            assert!(asked.is_empty(), "{name}: nothing asked of the service");
        }

        // The pays-us-correctly check alone must give the same word on every
        // `stage: "output"` case.
        if s(case, "stage") == "output" {
            let tx = hex::decode(s(&case["transaction"], "beef_hex")).unwrap();
            let pure = verify_payment_output(
                s(case, "server_private_key"),
                s(case, "sender_identity_key"),
                s(case, "derivation_prefix"),
                s(case, "derivation_suffix"),
                &tx,
                u(case, "output_index") as usize,
                u(case, "required_satoshis"),
            );
            let (pure_word, pure_fields) = word_of(&pure);
            if pure_word != word || pure_fields != fields {
                mismatches.push(format!(
                    "{name}: output-only check gave {pure_word} {pure_fields}, full gave {word} {fields}"
                ));
            }
        }
    }
    eprintln!(
        "conformance table ({} cases):\n{}",
        table.len(),
        table.join("\n")
    );
    assert!(
        mismatches.is_empty(),
        "conformance mismatches:\n{}",
        mismatches.join("\n")
    );
}

/// The file's six words are the core's six, under the core's spellings.
#[test]
fn the_vector_words_are_the_cores_words() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let mut file_words: Vec<&str> = doc["words"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    file_words.sort_unstable();
    let mut core_words = [
        PaymentVerdict::Verified { satoshis: 0 }.word(),
        PaymentVerdict::Underpaid {
            paid: 0,
            required: 0,
        }
        .word(),
        PaymentVerdict::WrongScript {
            expected: String::new(),
            actual: String::new(),
        }
        .word(),
        PaymentVerdict::NoHeaderService.word(),
        PaymentVerdict::RootMismatch {
            height: 0,
            root: String::new(),
        }
        .word(),
        PaymentVerdict::Unverifiable {
            reason: UnverifiableReason::NoTransaction,
        }
        .word(),
    ];
    core_words.sort_unstable();
    assert_eq!(file_words, core_words);
}

/// The rulings the file records: `spv-lookup-error` (2026-10-08, the
/// server's side, `fields.height`) and the two no-root cases (2026-10-09,
/// the payer's side, no fields) expect `Unverifiable`; each case agrees
/// with its ruling. A second implementation reads the same list.
#[test]
fn the_ruled_cases_are_unverifiable() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let rulings = doc["rulings"].as_array().expect("a rulings list");
    let cases = doc["cases"].as_array().unwrap();
    let mut ruled = Vec::new();
    for ruling in rulings {
        assert_eq!(s(ruling, "word"), "Unverifiable");
        let case = cases
            .iter()
            .find(|c| s(c, "name") == s(ruling, "case"))
            .unwrap_or_else(|| panic!("the ruled case {}", ruling["case"]));
        assert_eq!(s(&case["expected"], "word"), "Unverifiable");
        ruled.push((s(ruling, "date"), s(ruling, "case")));
    }
    assert_eq!(
        ruled,
        [
            ("2026-10-08", "spv-lookup-error"),
            ("2026-10-09", "spv-no-root"),
            ("2026-10-09", "spv-incomplete-beef"),
        ]
    );
    let lookup_error = cases
        .iter()
        .find(|c| s(c, "name") == "spv-lookup-error")
        .unwrap();
    assert_eq!(
        s(&lookup_error["header_service"]["lookup"], "answer"),
        "error"
    );
    assert_eq!(
        lookup_error["expected"]["fields"],
        json!({ "height": 850_000 })
    );
    for name in NO_ROOT_CASES {
        let case = cases.iter().find(|c| s(c, "name") == name).unwrap();
        assert_eq!(case["expected"]["fields"], json!({}), "{name}: no fields");
        assert!(case["header_service"]["lookup"].is_null());
        assert!(case["crate_result"].is_null(), "{name}: the owner's case");
    }
}

#[tokio::test]
async fn failing_non_send_source_is_a_host_fault() {
    struct Broken(std::rc::Rc<()>);
    impl bsv_middleware_core::AsyncByteSource for Broken {
        async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            let _ = &self.0;
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "test source disconnected",
            ))
        }
    }
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| s(c, "name") == "exact-amount")
        .unwrap();
    let service = LookupFn(|_| std::future::ready(Ok(Some(MerkleRoot::new("unused")))));
    let result = bsv_middleware_core::verify_brc29_payment_stream(
        s(case, "server_private_key"),
        s(case, "sender_identity_key"),
        s(case, "derivation_prefix"),
        s(case, "derivation_suffix"),
        &mut Broken(std::rc::Rc::new(())),
        0,
        1000,
        Some(&service),
        Some(1_000_000),
    )
    .await;
    assert!(
        matches!(result,Err(PaymentFault::Source(message)) if message.contains("test source disconnected"))
    );
}
