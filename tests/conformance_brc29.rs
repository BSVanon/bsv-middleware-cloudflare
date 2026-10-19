//! BRC-29 payment-verification conformance: runs every case of
//! `conformance/brc29-payment-vectors.json` through the crate's public API.
//!
//! The vector file is OWNED by the stack review repository (bsv-stack-lean,
//! `conformance/brc29-payment-vectors.json`, 22 cases since 2026-10-09); the
//! copy here is its bytes unchanged (the `producer` line included) and is
//! pinned by digest below, the same sha every implementation pins. Twenty of its cases are synthetic payments this
//! crate's producer (`build_cases`, fixed inputs) regenerates, and
//! `the_twenty_synthetic_cases_regenerate_from_the_producer` holds the
//! file's cases to the regenerated ones field for field (the owner's own
//! `note` and `crate_result` texts aside). The two no-root cases of
//! 2026-10-09 and the `rulings` list are the owner's bytes alone, never
//! retyped here. The runner below reads the file the way a second
//! implementation would: from JSON only, never from the producer's tables;
//! `expected` is the judge, `crate_result` is informational.
//!
//! The core (`core/`, the `bsv-middleware-core` package) ships its own copy
//! under `core/conformance/` so its published tarball runs the vectors
//! without this repository; `the_cores_copy_of_the_vectors_is_byte_identical`
//! pins the two copies equal, so the root copy stays canonical.
//!
//! The six words are the core's. `Unverifiable` emits `fields.height` (the
//! lowest height the header service could not answer for) when its reason
//! is the server's, and no fields when it is the payer's (the no-root class,
//! ruled 2026-10-09: `spv-no-root`, `spv-incomplete-beef`); the runner also
//! holds those two to the payer's side and to a refusal that names the
//! absent transaction.
//!
//! To take a new owned file: copy its bytes over both copies unchanged,
//! update `VECTORS_SHA256`, and run this file.

use std::cell::RefCell;

use bsv_middleware_cloudflare::{
    expected_brc29_locking_script, verify_brc29_payment, verify_brc29_payment_output,
    verify_brc29_payment_with_header_lookup, PaymentVerifyError, UnverifiableReason,
};
use bsv_sdk::primitives::hash::hash160;
use bsv_sdk::primitives::hash::sha256;
use bsv_sdk::primitives::PrivateKey;
use bsv_sdk::script::LockingScript;
use bsv_sdk::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::{json, Value};

const PINNED: &str = include_str!("../conformance/brc29-payment-vectors.json");
/// SHA-256 of the pinned copy: the owner's file (blob `8eede32d` of the
/// stack review repository), byte for byte.
const VECTORS_SHA256: &str = "836579ad73e20ca0e259a6c7cce5b55d85095cf290f74458937aeb39c9b5253c";
/// The core's copy of the file (`core/conformance/`), shipped inside the
/// `bsv-middleware-core` package. It sits next to this manifest only in the
/// repository: the sub-package is not part of this crate's own tarball.
const CORE_COPY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/core/conformance/brc29-payment-vectors.json"
);
const CASES: usize = 22;
const SYNTHETIC_CASES: usize = 20;
const NO_ROOT_CASES: [&str; 2] = ["spv-no-root", "spv-incomplete-beef"];

// ─── The runner (reads JSON only) ───────────────────────────────────

/// What a case's crate call returned, plus the heights the lookup was asked.
struct Outcome {
    result: Result<u64, PaymentVerifyError>,
    asked: Vec<u32>,
}

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
/// `merkle_root` at `height` (and nothing else), `answer: "error"` fails.
/// A `null` lookup (the no-root cases) is a service that is never asked:
/// it errors should it be.
fn lookup_answer(lookup: &Value, height: u32) -> Result<String, String> {
    if lookup.is_null() {
        return Err(format!("the header service was asked at height {height}"));
    }
    match s(lookup, "answer") {
        "root" if u(lookup, "height") == u64::from(height) => {
            Ok(s(lookup, "merkle_root").to_string())
        }
        "root" => Err(format!("no header at height {height}")),
        "error" => Err(s(lookup, "reason").to_string()),
        other => panic!("unknown lookup answer {other:?}"),
    }
}

/// Run one case: `stage: "config"` through `verify_brc29_payment` with the
/// case's `header_url` (the gate refuses before any network work), every
/// other stage through `verify_brc29_payment_with_header_lookup` with the
/// case's lookup.
async fn run_case(case: &Value) -> Outcome {
    let tx = hex::decode(s(&case["transaction"], "beef_hex")).unwrap();
    let server_key = s(case, "server_private_key");
    let sender = s(case, "sender_identity_key");
    let prefix = s(case, "derivation_prefix");
    let suffix = s(case, "derivation_suffix");
    let index = u(case, "output_index") as usize;
    let required = u(case, "required_satoshis");
    let service = &case["header_service"];

    if s(case, "stage") == "config" {
        let result = verify_brc29_payment(
            server_key,
            sender,
            prefix,
            suffix,
            &tx,
            index,
            required,
            service["url"].as_str(),
        )
        .await;
        return Outcome {
            result,
            asked: Vec::new(),
        };
    }

    let asked = RefCell::new(Vec::new());
    let lookup = &service["lookup"];
    let result = verify_brc29_payment_with_header_lookup(
        server_key,
        sender,
        prefix,
        suffix,
        &tx,
        index,
        required,
        |height| {
            asked.borrow_mut().push(height);
            let answer = lookup_answer(lookup, height);
            async move { answer }
        },
    )
    .await;
    Outcome {
        result,
        asked: asked.into_inner(),
    }
}

/// The conformance word for an outcome. `Ok` is `Verified` and nothing
/// else: since 0.4.0 the crate serves on no other word. `Unverifiable` is an
/// `Err` (fail-closed, the ruling of 2026-10-08) whose fields are the
/// lowest height the service could not answer for when the reason is the
/// server's, and nothing when it is the payer's (ruled 2026-10-09).
fn word_of(outcome: &Outcome) -> (String, Value) {
    match &outcome.result {
        Ok(sats) => ("Verified".into(), json!({ "satoshis": sats })),
        Err(PaymentVerifyError::Unverifiable { reason }) => match reason {
            UnverifiableReason::HeaderLookupFailed { height, .. } => {
                ("Unverifiable".into(), json!({ "height": height }))
            }
            _ => ("Unverifiable".into(), json!({})),
        },
        Err(PaymentVerifyError::Underpaid { satoshis, required }) => (
            "Underpaid".into(),
            json!({ "paid": satoshis, "required": required }),
        ),
        Err(PaymentVerifyError::WrongScript { expected, actual }) => (
            "WrongScript".into(),
            json!({ "expected_script": expected, "actual_script": actual }),
        ),
        Err(PaymentVerifyError::NoHeaderService) => ("NoHeaderService".into(), json!({})),
        Err(PaymentVerifyError::RootMismatch { height, root }) => (
            "RootMismatch".into(),
            json!({ "height": height, "merkle_root": root }),
        ),
        Err(other) => (format!("Unmapped({other:?})"), json!({})),
    }
}

fn crate_result_of(result: &Result<u64, PaymentVerifyError>) -> String {
    match result {
        Ok(sats) => format!("Ok({sats})"),
        Err(e) => format!("Err({e:?})"),
    }
}

/// Every txid a case's BEEF names: the subject's, and each input's source
/// up the linked ancestry (so the one the BEEF does not carry is among
/// them).
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
/// identity and script derivations, and that the listed outputs are the
/// outputs of the BEEF's subject transaction.
fn check_case_is_self_consistent(case: &Value, name: &str) -> Transaction {
    let server = PrivateKey::from_hex(s(case, "server_private_key")).unwrap();
    assert_eq!(
        server.public_key().to_hex(),
        s(case, "server_identity_key"),
        "{name}: server_identity_key"
    );
    assert_eq!(
        expected_brc29_locking_script(
            s(case, "server_private_key"),
            s(case, "sender_identity_key"),
            s(case, "derivation_prefix"),
            s(case, "derivation_suffix"),
        )
        .unwrap(),
        s(case, "expected_locking_script"),
        "{name}: expected_locking_script"
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
async fn every_brc29_vector_gives_its_word() {
    let doc: Value = serde_json::from_str(PINNED).unwrap();
    assert_eq!(doc["schema"], "brc29-payment-vectors/1");
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), CASES, "the 22 vectors");

    let mut mismatches = Vec::new();
    let mut table = Vec::new();
    for case in cases {
        let name = s(case, "name");
        let subject = check_case_is_self_consistent(case, name);

        let outcome = run_case(case).await;
        let (word, fields) = word_of(&outcome);
        table.push(format!("{name}: {word} {fields}"));
        let expected = &case["expected"];
        if word != s(expected, "word") || fields != expected["fields"] {
            mismatches.push(format!(
                "{name}: intended {} {}, crate gave {word} {fields}",
                expected["word"], expected["fields"]
            ));
        }
        // The outcome, not only the spelling: `Verified` is the one word
        // the 0.3 API answers `Ok`; every other word, `Unverifiable`
        // included, is an `Err` (refused).
        let serves = s(expected, "word") == "Verified";
        if outcome.result.is_ok() != serves {
            mismatches.push(format!(
                "{name}: {} must {}, crate gave {}",
                expected["word"],
                if serves { "serve (Ok)" } else { "refuse (Err)" },
                crate_result_of(&outcome.result)
            ));
        }
        // `crate_result` is what some producer once answered: informational,
        // never the judge (the owner's file carries older shapes).
        if let Some(recorded) = case["crate_result"].as_str() {
            let got = crate_result_of(&outcome.result);
            if got != recorded {
                eprintln!(
                    "{name}: crate_result recorded {recorded:?}, now {got:?} (informational)"
                );
            }
        }
        if !case["requires_merkle_lookup"].as_bool().unwrap() {
            assert!(
                outcome.asked.is_empty() || word == "Verified",
                "{name}: a refusal that does not need a lookup must not ask for one"
            );
        }
        // The no-root class (ruled 2026-10-09): the payer's side, no fields,
        // the refusal names the transaction whose proof is absent, and the
        // header service is never asked.
        if NO_ROOT_CASES.contains(&name) {
            let err = outcome
                .result
                .as_ref()
                .err()
                .unwrap_or_else(|| panic!("{name}: refused"));
            assert!(
                !err.is_server_side(),
                "{name}: the payer's side, never the server's: {err}"
            );
            let shown = err.to_string();
            let mut named = Vec::new();
            txids_named(&subject, &mut named);
            assert!(
                named.iter().any(|txid| shown.contains(txid)),
                "{name}: the refusal must name a transaction of the case: {shown}"
            );
            assert!(
                outcome.asked.is_empty(),
                "{name}: nothing asked of the service"
            );
        }

        // A pure implementation (no header service) runs the script + amount
        // check alone on every `stage: "output"` case and must get the same
        // word.
        if s(case, "stage") == "output" {
            let tx = hex::decode(s(&case["transaction"], "beef_hex")).unwrap();
            let pure = verify_brc29_payment_output(
                s(case, "server_private_key"),
                s(case, "sender_identity_key"),
                s(case, "derivation_prefix"),
                s(case, "derivation_suffix"),
                &tx,
                u(case, "output_index") as usize,
                u(case, "required_satoshis"),
            );
            let (pure_word, pure_fields) = word_of(&Outcome {
                result: pure,
                asked: Vec::new(),
            });
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

/// The rulings the file records, as the owner's `rulings` list: the
/// lookup-error case (2026-10-08) and the two no-root cases (2026-10-09)
/// expect `Unverifiable`, each case agrees with its ruling, and the glossary
/// has the six words under the core's spellings.
#[test]
fn the_ruled_cases_are_unverifiable() {
    let doc: Value = serde_json::from_str(PINNED).unwrap();
    let rulings = doc["rulings"].as_array().expect("a rulings list");
    assert_eq!(rulings.len(), 3);
    let cases = doc["cases"].as_array().unwrap();
    let mut ruled = Vec::new();
    for ruling in rulings {
        for key in ["date", "case", "word", "by", "why"] {
            assert!(ruling[key].is_string(), "a ruling carries {key}");
        }
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
    let words = doc["words"].as_object().unwrap();
    let mut spelled: Vec<&str> = words.keys().map(String::as_str).collect();
    spelled.sort_unstable();
    assert_eq!(
        spelled,
        [
            "NoHeaderService",
            "RootMismatch",
            "Underpaid",
            "Unverifiable",
            "Verified",
            "WrongScript"
        ]
    );
}

/// The pinned copy is the owner's file byte for byte (the `producer` line
/// included: sha256 836579ad…, the sha bsv-middleware-rs 0.4.0 pins too), by
/// digest. A new owned file is a reviewed diff here.
#[test]
fn brc29_vectors_are_the_owned_bytes() {
    let digest = hex::encode(sha256(PINNED.as_bytes()));
    assert_eq!(
        digest, VECTORS_SHA256,
        "conformance/brc29-payment-vectors.json is not the pinned owned file. It is a CROSS-REPO \
         agreement: take the owner's bytes unchanged, update VECTORS_SHA256, and copy \
         the file to every implementation that runs it."
    );
    let doc: Value = serde_json::from_str(PINNED).unwrap();
    assert_eq!(
        s(&doc, "producer"),
        "bsv-middleware-cloudflare 0.3.6 tests/conformance_brc29.rs build_vectors (fixed synthetic inputs; regenerate, never retype)",
        "the producer line is the owner's (the 0.3.6 producer first generated the twenty synthetic cases); it is not rewritten per release, so every implementation pins one sha"
    );
}

/// The core's copy is the root copy, byte for byte. Outside the repository
/// (this crate's own packaged tarball) the core sub-package is not shipped
/// and there is no second copy to compare; inside it, a missing copy is a
/// defect.
#[test]
fn the_cores_copy_of_the_vectors_is_byte_identical() {
    match std::fs::read_to_string(CORE_COPY_PATH) {
        Ok(core_copy) => assert!(
            core_copy == PINNED,
            "core/conformance/brc29-payment-vectors.json differs from the root copy. The root copy \
             is canonical: copy it over the core's."
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let core_manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/core/Cargo.toml");
            assert!(
                !std::path::Path::new(core_manifest).exists(),
                "core/ is present but its conformance copy is missing: {e}"
            );
            eprintln!("core/ is not part of this package; no second copy to compare");
        }
        Err(e) => panic!("cannot read {CORE_COPY_PATH}: {e}"),
    }
}

/// The producer's check (the former emit mode): the twenty synthetic cases
/// regenerate from the fixed inputs and equal the file's, field for field,
/// the owner's own `note` and `crate_result` texts aside; the top-level
/// `words`, `derivation`, `schema` and `description` equal the producer's
/// too. The two owned cases and the `rulings` are not produced here and are
/// not compared: they are the owner's bytes. (The file cannot be emitted
/// byte-identically from here: the owner's copy carries its own key order
/// and texts on the ruled case, so the emit became this check.)
#[tokio::test]
async fn the_twenty_synthetic_cases_regenerate_from_the_producer() {
    let doc: Value = serde_json::from_str(PINNED).unwrap();
    let file_cases = doc["cases"].as_array().unwrap();
    let produced = build_cases().await;
    assert_eq!(produced.len(), SYNTHETIC_CASES);
    assert_eq!(file_cases.len(), SYNTHETIC_CASES + NO_ROOT_CASES.len());

    let mut drift = Vec::new();
    for ours in &produced {
        let name = s(ours, "name");
        let Some(theirs) = file_cases.iter().find(|c| s(c, "name") == name) else {
            drift.push(format!("{name}: produced here, not in the file"));
            continue;
        };
        for (key, value) in ours.as_object().unwrap() {
            if key == "crate_result" || key == "note" {
                continue;
            }
            if theirs[key] != *value {
                drift.push(format!(
                    "{name}.{key}: file {}, produced {value}",
                    theirs[key]
                ));
            }
        }
        if theirs["crate_result"] != ours["crate_result"] {
            eprintln!(
                "{name}: crate_result in the file {}, this crate's {} (informational)",
                theirs["crate_result"], ours["crate_result"]
            );
        }
    }
    for owned in NO_ROOT_CASES {
        assert!(
            file_cases.iter().any(|c| s(c, "name") == owned),
            "the owned case {owned} is in the file"
        );
        assert!(
            produced.iter().all(|c| s(c, "name") != owned),
            "{owned} is the owner's, never produced here"
        );
    }
    assert_eq!(doc["schema"], producer_header()["schema"]);
    assert_eq!(doc["description"], producer_header()["description"]);
    assert_eq!(doc["words"], producer_header()["words"]);
    assert_eq!(doc["derivation"], producer_header()["derivation"]);
    assert!(
        drift.is_empty(),
        "the file's synthetic cases drifted from the producer:\n{}",
        drift.join("\n")
    );
}

// ─── The producer (fixed synthetic inputs) ──────────────────────────

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const OTHER_SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";
/// base64("brc29-conformance-prefix")
const PREFIX: &str = "YnJjMjktY29uZm9ybWFuY2UtcHJlZml4";
/// base64("brc29-conformance-suffix")
const SUFFIX: &str = "YnJjMjktY29uZm9ybWFuY2Utc3VmZml4";
/// base64("brc29-conformance-stale-prefix"), a prefix from an older quote.
const STALE_PREFIX: &str = "YnJjMjktY29uZm9ybWFuY2Utc3RhbGUtcHJlZml4";
/// RFC 2606 reserved name: never a real service.
const HEADERS_URL: &str = "https://headers.example";
const PROOF_HEIGHT: u32 = 850_000;
const PRICE: u64 = 1000;

fn identity(private_hex: &str) -> String {
    PrivateKey::from_hex(private_hex)
        .unwrap()
        .public_key()
        .to_hex()
}

fn p2pkh_of_pubkey(pubkey_hex: &str) -> String {
    format!(
        "76a914{}88ac",
        hex::encode(hash160(&hex::decode(pubkey_hex).unwrap()))
    )
}

fn script(server: &str, sender_identity: &str, prefix: &str) -> String {
    expected_brc29_locking_script(server, sender_identity, prefix, SUFFIX).unwrap()
}

/// A BEEF holding ONE transaction with `outputs`, proven by a one-leaf BUMP
/// at `PROOF_HEIGHT` (a block of one transaction: the merkle root IS the
/// txid). Returns the bytes and the txid.
fn proven_beef(outputs: &[(String, u64)]) -> (Vec<u8>, String) {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput {
        source_txid: Some("11".repeat(32)),
        source_output_index: 0,
        ..Default::default()
    })
    .unwrap();
    for (script_hex, sats) in outputs {
        tx.add_output(TransactionOutput {
            satoshis: Some(*sats),
            locking_script: LockingScript::from_hex(script_hex).unwrap(),
            change: false,
        })
        .unwrap();
    }
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

#[derive(Clone, Copy)]
enum Lookup {
    /// The service answers the proof's own root (upper-cased if `true`).
    ProofRoot(bool),
    /// The service answers a different root at the proof's height.
    OtherRoot,
    /// The service cannot answer.
    Error,
}

struct CaseDef {
    name: &'static str,
    description: &'static str,
    stage: &'static str,
    sender_private_key: &'static str,
    /// `None`: the sender's own identity; `Some(key)` overrides it (pay-yourself).
    sender_identity_override: Option<&'static str>,
    outputs: Vec<(String, u64)>,
    output_index: u64,
    header_url: Option<&'static str>,
    lookup: Lookup,
    word: &'static str,
    note: &'static str,
}

fn case_defs() -> Vec<CaseDef> {
    let sender = identity(SENDER_KEY);
    let ours = script(SERVER_KEY, &sender, PREFIX);
    let base = |name, description, outputs: Vec<(String, u64)>, word, note| CaseDef {
        name,
        description,
        stage: "output",
        sender_private_key: SENDER_KEY,
        sender_identity_override: None,
        outputs,
        output_index: 0,
        header_url: Some(HEADERS_URL),
        lookup: Lookup::ProofRoot(false),
        word,
        note,
    };

    let mut defs = vec![
        base(
            "exact-amount",
            "Output 0 pays the derived key exactly the price.",
            vec![(ours.clone(), PRICE)],
            "Verified",
            "",
        ),
        base(
            "one-sat-under",
            "Output 0 pays the derived key one satoshi below the price.",
            vec![(ours.clone(), PRICE - 1)],
            "Underpaid",
            "",
        ),
        base(
            "one-sat-over",
            "Output 0 pays the derived key one satoshi above the price; overpayment is accepted and the paid amount reported.",
            vec![(ours.clone(), PRICE + 1)],
            "Verified",
            "",
        ),
        base(
            "zero-sat-output",
            "Output 0 carries the derived key's script but zero satoshis.",
            vec![(ours.clone(), 0)],
            "Underpaid",
            "",
        ),
        base(
            "wrong-script-another-server",
            "Output 0 pays the key a DIFFERENT server would derive for the same sender, prefix and suffix (one payment replayed across servers).",
            vec![(script(OTHER_SERVER_KEY, &sender, PREFIX), 5000)],
            "WrongScript",
            "",
        ),
        base(
            "wrong-script-stale-prefix",
            "Output 0 pays this server's key for an older quote's derivation prefix (a paid transaction replayed against a fresh quote).",
            vec![(script(SERVER_KEY, &sender, STALE_PREFIX), 5000)],
            "WrongScript",
            "",
        ),
        base(
            "wrong-script-pays-sender",
            "Output 0 pays the sender's own identity key (P2PKH of sender_identity_key): the client keeps the funds.",
            vec![(p2pkh_of_pubkey(&sender), 5000)],
            "WrongScript",
            "",
        ),
        base(
            "first-output-underpays-second-would-pay",
            "Reference rule: the payment is output 0 only. Output 0 pays the derived key one sat under the price, output 1 pays it in full; refused.",
            vec![(ours.clone(), PRICE - 1), (ours.clone(), PRICE)],
            "Underpaid",
            "The express payment middleware internalizes outputIndex 0 only; an implementation must not search later outputs for one that pays.",
        ),
        base(
            "first-output-is-change-second-would-pay",
            "Reference rule: output 0 is change back to the sender, output 1 pays the derived key in full; refused.",
            vec![(p2pkh_of_pubkey(&sender), 5000), (ours.clone(), PRICE)],
            "WrongScript",
            "Same rule as first-output-underpays-second-would-pay, script side.",
        ),
    ];

    // Pay-yourself: the sender IS the server (same identity key).
    let server_id = identity(SERVER_KEY);
    defs.push(CaseDef {
        sender_private_key: SERVER_KEY,
        sender_identity_override: Some(SERVER_KEY),
        ..base(
            "pay-yourself-sender-is-server",
            "The sender identity key is the server's own identity key and output 0 pays the key derived for that (server, server, prefix, suffix) tuple.",
            vec![(script(SERVER_KEY, &server_id, PREFIX), PRICE)],
            "Verified",
            "The verifier does not refuse sender == server: BRC-42 with the counterparty set to one's own key is well defined, the output pays a key the server can spend, so it is a real payment. Refusing self-payment is a policy above the verifier.",
        )
    });

    // No header service: the gate refuses before any other check, for a
    // payment that would otherwise verify.
    for (name, url, what) in [
        ("no-header-service-none", None, "header_url absent (null)."),
        ("no-header-service-blank", Some(""), "header_url is the empty string."),
        (
            "no-header-service-placeholder",
            Some("https://chaintracks.invalid"),
            "header_url is the reserved .invalid placeholder.",
        ),
        (
            "no-header-service-trailing-dot",
            Some("https://chaintracks.invalid."),
            "The placeholder as a trailing-dot FQDN.",
        ),
        (
            "no-header-service-percent-encoded",
            Some("https://chaintracks%2Einvalid"),
            "The placeholder with a percent-encoded dot (a URL parser would decode it).",
        ),
        (
            "no-header-service-backslash-userinfo",
            Some("https://real.example\\@chaintracks.invalid"),
            "A backslash before userinfo: a WHATWG parser reads the host as real.example, a naive split as chaintracks.invalid. Refused rather than guessed.",
        ),
    ] {
        defs.push(CaseDef {
            stage: "config",
            header_url: url,
            ..base(
                name,
                what,
                vec![(ours.clone(), PRICE)],
                "NoHeaderService",
                "Fail-closed: a deployment misconfiguration, refused before the script, amount or proof is looked at.",
            )
        });
    }

    // SPV: the payment is correct; only the header service's answer varies.
    for (name, lookup, word, what, note) in [
        (
            "spv-root-match",
            Lookup::ProofRoot(false),
            "Verified",
            "The header service answers the proof's merkle root at the proof's height.",
            "",
        ),
        (
            "spv-root-match-uppercase",
            Lookup::ProofRoot(true),
            "Verified",
            "The header service answers the proof's root in upper-case hex.",
            "Roots compare case-insensitively.",
        ),
        (
            "spv-root-mismatch",
            Lookup::OtherRoot,
            "RootMismatch",
            "The header service answers a DIFFERENT merkle root at the proof's height.",
            "Fail-closed: a mismatch is a fraud signal, not an outage.",
        ),
        (
            "spv-lookup-error",
            Lookup::Error,
            "Unverifiable",
            "The header service cannot answer (HTTP 503).",
            "Fail closed (ruled 2026-10-08): the header service errored at height 850000, so the root was not checked and the payment is refused as Unverifiable; fields.height names the height to re-ask (the first erroring root in height order).",
        ),
    ] {
        defs.push(CaseDef {
            stage: "spv",
            lookup,
            ..base(name, what, vec![(ours.clone(), PRICE)], word, note)
        });
    }
    defs
}

fn expected_fields(word: &str, def: &CaseDef, expected_script: &str, root: &str) -> Value {
    let out = &def.outputs[def.output_index as usize];
    match word {
        "Verified" => json!({ "satoshis": out.1 }),
        "Unverifiable" => json!({ "height": PROOF_HEIGHT }),
        "Underpaid" => json!({ "paid": out.1, "required": PRICE }),
        "WrongScript" => json!({ "expected_script": expected_script, "actual_script": out.0 }),
        "NoHeaderService" => json!({}),
        "RootMismatch" => json!({ "height": PROOF_HEIGHT, "merkle_root": root }),
        other => panic!("unknown word {other}"),
    }
}

/// The twenty synthetic cases, each with this crate's answer as
/// `crate_result`.
async fn build_cases() -> Vec<Value> {
    let mut cases = Vec::new();
    for def in case_defs() {
        let sender_identity = identity(def.sender_identity_override.unwrap_or(SENDER_KEY));
        let expected_script = script(SERVER_KEY, &sender_identity, PREFIX);
        let (beef, txid) = proven_beef(&def.outputs);
        let lookup = match (def.stage, def.lookup) {
            ("config", _) => Value::Null,
            (_, Lookup::ProofRoot(upper)) => json!({
                "answer": "root",
                "height": PROOF_HEIGHT,
                "merkle_root": if upper { txid.to_ascii_uppercase() } else { txid.clone() },
            }),
            (_, Lookup::OtherRoot) => json!({
                "answer": "root",
                "height": PROOF_HEIGHT,
                "merkle_root": "00".repeat(32),
            }),
            (_, Lookup::Error) => json!({
                "answer": "error",
                "reason": format!("header service HTTP 503 at height {PROOF_HEIGHT}"),
            }),
        };
        let mut case = json!({
            "name": def.name,
            "description": def.description,
            "stage": def.stage,
            "requires_merkle_lookup": def.stage == "spv",
            "server_private_key": SERVER_KEY,
            "server_identity_key": identity(SERVER_KEY),
            "sender_private_key": def.sender_private_key,
            "sender_identity_key": sender_identity,
            "derivation_prefix": PREFIX,
            "derivation_suffix": SUFFIX,
            "expected_locking_script": expected_script,
            "transaction": {
                "beef_hex": hex::encode(&beef),
                "txid": txid,
                "proof": { "height": PROOF_HEIGHT, "merkle_root": txid },
                "outputs": def.outputs.iter().map(|(script, sats)| json!({
                    "satoshis": sats,
                    "locking_script": script,
                })).collect::<Vec<_>>(),
            },
            "output_index": def.output_index,
            "required_satoshis": PRICE,
            "header_service": { "url": def.header_url, "lookup": lookup },
            "expected": {
                "word": def.word,
                "fields": expected_fields(def.word, &def, &expected_script, &txid),
            },
            "crate_result": "",
        });
        if !def.note.is_empty() {
            case["note"] = json!(def.note);
        }
        let outcome = run_case(&case).await;
        case["crate_result"] = json!(crate_result_of(&outcome.result));
        cases.push(case);
    }
    cases
}

/// The document's head as this producer states it; the owner's file must
/// agree (the `producer` line aside, which names the version).
fn producer_header() -> Value {
    json!({
        "schema": "brc29-payment-vectors/1",
        "description": "BRC-29 payment verification before internalize: does output `output_index` of the payment transaction pay the server's BRC-29 derived key at least `required_satoshis`, and does its merkle proof tie to a block header? See conformance/README.md.",
        "words": {
            "Verified": "Accept. fields.satoshis = the output's satoshis.",
            "Unverifiable": "Refuse: a merkle root could not be checked (fail-closed): the header service errored at fields.height (the first such height in height order), or the BEEF carries no proof at all (no fields).",
            "Underpaid": "Refuse: the output pays the derived key less than required. fields.paid, fields.required.",
            "WrongScript": "Refuse: the output's locking script is not the expected one. fields.expected_script, fields.actual_script.",
            "NoHeaderService": "Refuse before any other check: no usable header service is configured (fail-closed misconfiguration).",
            "RootMismatch": "Refuse: the header at the proof's height carries a different merkle root (fail-closed fraud signal). fields.height, fields.merkle_root (the proof's root)."
        },
        "derivation": {
            "brc": "BRC-29 over BRC-42/BRC-43",
            "protocol_id": [2, "3241645161d8"],
            "key_id": "<derivation_prefix> <derivation_suffix>",
            "server_side": "child public key for (server_private_key, counterparty = sender_identity_key, for_self = true)",
            "sender_side": "child public key for (sender_private_key, counterparty = server_identity_key, for_self = false); equal by BRC-42",
            "locking_script": "P2PKH: 76a914 <hash160(compressed child pubkey)> 88ac"
        },
    })
}
