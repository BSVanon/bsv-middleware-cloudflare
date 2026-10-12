// Adapted from the L2-budget scratch harness: the work budget on the core's
// payment path. Phantom outpoints, throwaway keys, nothing broadcast.
use std::collections::HashMap;
use std::sync::Arc;

use bsv_middleware_core::brc29::expected_locking_script;
use bsv_middleware_core::{LookupFn, MerkleRoot, PaymentFault, PaymentVerdict, VerifiedPayment};
use bsv_sdk::primitives::bsv::sighash::{
    build_sighash_preimage_original, SighashParams, TxInput, TxOutput, TxSighashCache, SIGHASH_ALL,
    SIGHASH_CHRONICLE, SIGHASH_FORKID,
};
use bsv_sdk::primitives::bsv::tx_signature::TransactionSignature;
use bsv_sdk::primitives::{sha256d, to_hex, PrivateKey, Writer};
use bsv_sdk::script::Script;
use serde_json::Value;

const VECTORS: &str = include_str!("../../conformance/brc29-payment-vectors.json");

#[derive(Clone)]
struct Payment {
    server_key: String,
    sender: String,
    prefix: String,
    suffix: String,
    beef: Vec<u8>,
    output_index: usize,
    required: u64,
    roots: HashMap<u32, String>,
}

async fn run(
    p: &Payment,
    limit: Option<u64>,
) -> Result<Result<VerifiedPayment, PaymentVerdict>, PaymentFault> {
    let service = LookupFn(|height| {
        let answer = p.roots.get(&height).cloned().map(MerkleRoot::new);
        async move { Ok(answer) }
    });
    bsv_middleware_core::verify_brc29_payment_verified(
        &p.server_key,
        &p.sender,
        &p.prefix,
        &p.suffix,
        &p.beef,
        p.output_index,
        p.required,
        Some(&service),
        limit,
    )
    .await
    .inspect(|answer| {
        if let Err(word) = answer {
            let error = bsv_middleware_cloudflare::accept_verdict(word.clone()).unwrap_err();
            assert_eq!(error.is_server_side(), word.is_server_side_unverifiable());
            assert_eq!(
                error.response_class().0,
                if word.is_server_side_unverifiable() {
                    503
                } else {
                    400
                }
            );
        }
    })
}

async fn verifies(p: &Payment, limit: Option<u64>) -> bool {
    matches!(run(p, limit).await, Ok(Ok(_)))
}

/// The smallest work limit that still answers Verified (None must verify).
async fn smallest_limit(p: &Payment) -> u64 {
    assert!(verifies(p, None).await, "verifies unbounded");
    if verifies(p, Some(0)).await {
        return 0;
    }
    let mut hi = 1u64;
    while !verifies(p, Some(hi)).await {
        hi *= 2;
        assert!(hi < 1 << 50);
    }
    let mut lo = hi / 2;
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if verifies(p, Some(mid)).await {
            hi = mid
        } else {
            lo = mid
        }
    }
    hi
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap()
}

fn vector_payment(case: &Value) -> Payment {
    let lookup = &case["header_service"]["lookup"];
    let mut roots = HashMap::new();
    if !lookup.is_null() && s(lookup, "answer") == "root" {
        roots.insert(
            lookup["height"].as_u64().unwrap() as u32,
            s(lookup, "merkle_root").to_string(),
        );
    }
    Payment {
        server_key: s(case, "server_private_key").into(),
        sender: s(case, "sender_identity_key").into(),
        prefix: s(case, "derivation_prefix").into(),
        suffix: s(case, "derivation_suffix").into(),
        beef: hex::decode(s(&case["transaction"], "beef_hex")).unwrap(),
        output_index: case["output_index"].as_u64().unwrap() as usize,
        required: case["required_satoshis"].as_u64().unwrap(),
        roots,
    }
}

/// The keys and derivation of the `exact-amount` vector (the derived script is theirs).
fn derivation() -> (String, String, String, String, Vec<u8>) {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| s(c, "name") == "exact-amount")
        .unwrap();
    let script = expected_locking_script(
        s(case, "server_private_key"),
        s(case, "sender_identity_key"),
        s(case, "derivation_prefix"),
        s(case, "derivation_suffix"),
    )
    .unwrap();
    (
        s(case, "server_private_key").into(),
        s(case, "sender_identity_key").into(),
        s(case, "derivation_prefix").into(),
        s(case, "derivation_suffix").into(),
        hex::decode(script).unwrap(),
    )
}

fn p2pkh(pubkey: &[u8]) -> Vec<u8> {
    let mut lock = Script::new();
    lock.write_opcode(0x76)
        .write_opcode(0xa9)
        .write_bin(&bsv_sdk::primitives::hash160(pubkey))
        .write_opcode(0x88)
        .write_opcode(0xac);
    lock.to_binary()
}

fn serialize(
    version: i32,
    inputs: &[TxInput],
    unlocks: &[Vec<u8>],
    outputs: &[TxOutput],
    locktime: u32,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_i32_le(version).write_var_int(inputs.len() as u64);
    for (i, input) in inputs.iter().enumerate() {
        w.write_bytes(&input.txid)
            .write_u32_le(input.output_index)
            .write_var_bytes(&unlocks[i])
            .write_u32_le(input.sequence);
    }
    w.write_var_int(outputs.len() as u64);
    for out in outputs {
        w.write_u64_le(out.satoshis).write_var_bytes(&out.script);
    }
    w.write_u32_le(locktime);
    w.into_bytes()
}

/// A proven parent with `k` P2PKH outputs at the root of `hops` unproven
/// transactions, each spending all `k` outputs of the one before (FORKID
/// signatures, the wallet's), the last paying output 0 to the derived script.
fn honest(k: usize, hops: usize) -> Payment {
    const REQUIRED: u64 = 1000;
    let (server_key, sender, prefix, suffix, derived) = derivation();
    let key = PrivateKey::from_hex(&format!("{:064x}", 7)).unwrap();
    let pubkey = key.public_key().to_compressed();
    let lock = p2pkh(&pubkey);
    let scope = SIGHASH_ALL | SIGHASH_FORKID;
    // The proven parent: one phantom input, k P2PKH outputs of 1000 + k sats.
    let parent_outputs: Vec<TxOutput> = (0..k)
        .map(|_| TxOutput {
            satoshis: 100_000,
            script: lock.clone(),
        })
        .collect();
    let parent = serialize(
        2,
        &[TxInput {
            txid: [0xaa; 32],
            output_index: 0,
            script: vec![],
            sequence: u32::MAX,
        }],
        &[vec![]],
        &parent_outputs,
        0,
    );
    let root = sha256d(&parent);
    let mut prev_txid = root;
    let mut prev_outputs = parent_outputs;
    let mut unproven = Vec::new();
    for hop in 0..hops {
        let last = hop + 1 == hops;
        let inputs: Vec<TxInput> = (0..prev_outputs.len())
            .map(|i| TxInput {
                txid: prev_txid,
                output_index: i as u32,
                script: vec![],
                sequence: u32::MAX,
            })
            .collect();
        let outputs: Vec<TxOutput> = if last {
            vec![
                TxOutput {
                    satoshis: REQUIRED,
                    script: derived.clone(),
                },
                TxOutput {
                    satoshis: 1,
                    script: lock.clone(),
                },
            ]
        } else {
            (0..k)
                .map(|_| TxOutput {
                    satoshis: 100_000 - 1 - hop as u64,
                    script: lock.clone(),
                })
                .collect()
        };
        let cache = Arc::new(TxSighashCache::new(2, inputs.clone(), outputs.clone(), 0));
        let unlocks: Vec<Vec<u8>> = (0..inputs.len())
            .map(|i| {
                let digest =
                    cache.sighash_dispatched_for_signing(i, &lock, prev_outputs[i].satoshis, scope);
                let sig = TransactionSignature::new(key.sign(&digest).unwrap(), scope)
                    .to_checksig_format();
                let mut u = Script::new();
                u.write_bin(&sig).write_bin(&pubkey);
                u.to_binary()
            })
            .collect();
        let raw = serialize(2, &inputs, &unlocks, &outputs, 0);
        prev_txid = sha256d(&raw);
        prev_outputs = outputs;
        unproven.push(raw);
    }
    let beef = beef(&parent, &unproven, 800_000, &root);
    let mut shown = root;
    shown.reverse();
    Payment {
        server_key,
        sender,
        prefix,
        suffix,
        beef,
        output_index: 0,
        required: REQUIRED,
        roots: HashMap::from([(800_000, to_hex(&shown))]),
    }
}

fn beef(parent: &[u8], unproven: &[Vec<u8>], height: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32_le(0xefbe_0002)
        .write_var_int(1)
        .write_var_int(height)
        .write_bytes(&[1, 1, 0, 2])
        .write_bytes(root)
        .write_var_int(1 + unproven.len() as u64)
        .write_bytes(&[1, 0])
        .write_bytes(parent);
    for raw in unproven {
        w.write_u8(0).write_bytes(raw);
    }
    w.into_bytes()
}

/// The 0.4.5 witness body (`tests/script_work_budget.rs`): one input, `n`
/// original-digest checks over a 1 MB subject; here output 0 pays the derived
/// script for the quoted amount so the body is a payment in every other respect.
fn hostile(n: usize) -> (Payment, u64) {
    const REQUIRED: u64 = 1000;
    let (server_key, sender, prefix, suffix, derived) = derivation();
    let scope = SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_CHRONICLE;
    let key = PrivateKey::from_hex(&format!("{:064x}", 42)).unwrap();
    let pubkey = key.public_key().to_compressed();
    let mut lock = Script::new();
    for _ in 0..n {
        lock.write_opcode(0x76)
            .write_bin(&pubkey)
            .write_opcode(0xad);
    }
    lock.write_opcode(0x75).write_opcode(0x51);
    let locking = lock.to_binary();
    let parent = serialize(
        2,
        &[TxInput {
            txid: [0xaa; 32],
            output_index: 0,
            script: vec![],
            sequence: u32::MAX,
        }],
        &[vec![]],
        &[TxOutput {
            satoshis: REQUIRED + 100,
            script: locking.clone(),
        }],
        0,
    );
    let root = sha256d(&parent);
    let inputs = vec![TxInput {
        txid: root,
        output_index: 0,
        script: vec![],
        sequence: u32::MAX,
    }];
    let outputs = vec![
        TxOutput {
            satoshis: REQUIRED,
            script: derived,
        },
        TxOutput {
            satoshis: 1,
            script: vec![0; 1_000_000 - 64],
        },
    ];
    let params = SighashParams {
        version: 2,
        inputs: &inputs,
        outputs: &outputs,
        locktime: 0,
        input_index: 0,
        subscript: &locking,
        satoshis: REQUIRED + 100,
        scope,
    };
    let work =
        (build_sighash_preimage_original(&params).len() as u64 + 32) * n as u64 + 3 * n as u64 + 3;
    let cache = TxSighashCache::new(2, inputs.clone(), outputs.clone(), 0);
    let digest = cache.sighash_dispatched_for_signing(0, &locking, REQUIRED + 100, scope);
    let sig = TransactionSignature::new(key.sign(&digest).unwrap(), scope).to_checksig_format();
    let mut unlock = Script::new();
    unlock.write_bin(&sig);
    let raw = serialize(2, &inputs, &[unlock.to_binary()], &outputs, 0);
    let beef = beef(&parent, &[raw], 800_000, &root);
    let mut shown = root;
    shown.reverse();
    (
        Payment {
            server_key,
            sender,
            prefix,
            suffix,
            beef,
            output_index: 0,
            required: REQUIRED,
            roots: HashMap::from([(800_000, to_hex(&shown))]),
        },
        work,
    )
}

#[tokio::test]
async fn vectors_keep_their_words_with_default_and_fleet_budget() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    for case in doc["cases"].as_array().unwrap() {
        if s(case, "stage") == "config" {
            continue;
        }
        let p = vector_payment(case);
        for limit in [None, Some(1_000_000)] {
            let word = match run(&p, limit).await.unwrap() {
                Ok(_) => "Verified",
                Err(ref word) => word.word(),
            };
            assert_eq!(word, s(&case["expected"], "word"));
        }
    }
}

#[tokio::test]
async fn honest_p2pkh_verifies_at_490_and_declines_at_489() {
    let p = honest(1, 1);
    assert_eq!(smallest_limit(&p).await, 490);
    assert!(verifies(&p, Some(490)).await);
    let refused = run(&p, Some(489)).await.unwrap().unwrap_err();
    assert!(!refused.is_server_side_unverifiable());
    assert!(refused.to_string().contains("work resource bound"));
}

#[tokio::test]
async fn hostile_body_declines_at_one_million() {
    let (p, _) = hostile(10_000);
    let mut best = std::time::Duration::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        let word = run(&p, Some(1_000_000)).await.unwrap().unwrap_err();
        best = best.min(start.elapsed());
        assert!(!word.is_server_side_unverifiable());
        let reason = word.to_string();
        assert!(
            reason.contains("work resource bound") && reason.contains("work_spent: Some(4)"),
            "{reason}"
        );
    }
    println!(
        "HOSTILE bytes={} limit=1000000 decline_ms_best_of_3={:.3}",
        p.beef.len(),
        best.as_secs_f64() * 1000.0
    );
    // Timing is measured in release on the reporting host, not asserted on shared CI.
}

#[tokio::test]
#[ignore = "release control: 10,000 original-digest checks take minutes"]
async fn hostile_body_default_has_no_budget_and_verifies() {
    let (p, _) = hostile(10_000);
    assert!(verifies(&p, None).await);
}

struct TipService<'a> {
    payment: &'a Payment,
    tip: Option<bsv_middleware_core::ChainTip>,
}
impl bsv_middleware_core::HeaderService for TipService<'_> {
    async fn merkle_root(
        &self,
        height: u32,
    ) -> Result<Option<MerkleRoot>, bsv_middleware_core::ServiceError> {
        Ok(self
            .payment
            .roots
            .get(&height)
            .cloned()
            .map(MerkleRoot::new))
    }
    async fn mining_tip(
        &self,
    ) -> Result<Option<bsv_middleware_core::ChainTip>, bsv_middleware_core::ServiceError> {
        Ok(self.tip)
    }
}

async fn refusal(
    p: &Payment,
    tip: Option<bsv_middleware_core::ChainTip>,
    name: &str,
    server: bool,
) {
    let service = TipService { payment: p, tip };
    let word = bsv_middleware_core::verify_brc29_payment_verified(
        &p.server_key,
        &p.sender,
        &p.prefix,
        &p.suffix,
        &p.beef,
        0,
        p.required,
        Some(&service),
        None,
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(word.to_string().contains(name), "{name}: {word}");
    assert_eq!(word.is_server_side_unverifiable(), server, "{word}");
    let error = bsv_middleware_cloudflare::accept_verdict(word).unwrap_err();
    assert_eq!(error.response_class().0, if server { 503 } else { 400 });
}

#[tokio::test]
async fn mining_refusals_reach_the_correct_class() {
    use bsv_middleware_core::ChainTip;
    let tip = Some(ChainTip {
        height: 800_050,
        median_time_past: 1_700_000_000,
        genesis_height: 620_538,
        csv_height: 419_328,
        next_block_time: None,
    });
    let mut p = honest(1, 1);
    let derived = derivation().4;
    let ordinary = TxInput {
        txid: [0xaa; 32],
        output_index: 0,
        script: vec![],
        sequence: u32::MAX,
    };
    let null = TxInput {
        txid: [0; 32],
        output_index: u32::MAX,
        script: vec![],
        sequence: u32::MAX,
    };
    let output = TxOutput {
        satoshis: 1000,
        script: derived.clone(),
    };
    let parent = serialize(
        2,
        std::slice::from_ref(&ordinary),
        &[vec![]],
        std::slice::from_ref(&output),
        0,
    );
    let root = sha256d(&parent);
    let spending = TxInput {
        txid: root,
        output_index: 0,
        script: vec![],
        sequence: u32::MAX,
    };
    let mut shaped = |inputs: &[TxInput], outputs: &[TxOutput], locktime| {
        let raw = serialize(2, inputs, &vec![vec![]; inputs.len()], outputs, locktime);
        p.beef = beef(&parent, &[raw], 800_000, &root);
        p.roots = HashMap::from([(800_000, {
            let mut shown = root;
            shown.reverse();
            to_hex(&shown)
        })]);
        p.clone()
    };
    refusal(
        &shaped(
            std::slice::from_ref(&null),
            std::slice::from_ref(&output),
            0,
        ),
        tip,
        "UnprovenCoinbase",
        false,
    )
    .await;
    refusal(
        &shaped(&[spending.clone(), null], std::slice::from_ref(&output), 0),
        tip,
        "NullOutpoint",
        false,
    )
    .await;
    refusal(
        &shaped(
            &[spending.clone(), spending.clone()],
            std::slice::from_ref(&output),
            0,
        ),
        tip,
        "DuplicateInput",
        false,
    )
    .await;
    refusal(
        &shaped(
            std::slice::from_ref(&spending),
            &[TxOutput {
                satoshis: 2_100_000_000_000_001,
                script: derived.clone(),
            }],
            0,
        ),
        tip,
        "ValueOutOfRange",
        false,
    )
    .await;
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend([1; 20]);
    p2sh.push(0x87);
    refusal(
        &shaped(
            std::slice::from_ref(&spending),
            &[TxOutput {
                satoshis: 1000,
                script: p2sh,
            }],
            0,
        ),
        tip,
        "P2shOutput",
        false,
    )
    .await;
    let mut locked = spending.clone();
    locked.sequence = 0;
    let time_locked = shaped(
        std::slice::from_ref(&locked),
        std::slice::from_ref(&output),
        800_051,
    );
    refusal(&time_locked, tip, "NonFinal", false).await;
    refusal(&time_locked, None, "Finality", true).await;
    let coinbase = serialize(
        2,
        &[TxInput {
            txid: [0; 32],
            output_index: u32::MAX,
            script: vec![],
            sequence: u32::MAX,
        }],
        &[vec![1, 1]],
        std::slice::from_ref(&output),
        0,
    );
    let root = sha256d(&coinbase);
    let subject = serialize(
        2,
        &[TxInput {
            txid: root,
            output_index: 0,
            script: vec![],
            sequence: u32::MAX,
        }],
        &[vec![]],
        std::slice::from_ref(&output),
        0,
    );
    p.beef = beef(&coinbase, &[subject], 800_000, &root);
    p.roots = HashMap::from([(800_000, {
        let mut shown = root;
        shown.reverse();
        to_hex(&shown)
    })]);
    refusal(&p, tip, "PrematureCoinbase", false).await;
    refusal(&p, None, "CoinbaseMaturity", true).await;
    // Each proven output is in MoneyRange; spending both makes the input total exceed it.
    let rich = TxOutput {
        satoshis: 2_100_000_000_000_000,
        script: vec![0x51],
    };
    let parent = serialize(
        2,
        &[ordinary],
        &[vec![]],
        &[
            rich.clone(),
            TxOutput {
                satoshis: 0,
                script: vec![0x51],
            },
        ],
        0,
    );
    let root = sha256d(&parent);
    let second = serialize(
        2,
        &[TxInput {
            txid: [0xbb; 32],
            output_index: 0,
            script: vec![],
            sequence: u32::MAX,
        }],
        &[vec![]],
        &[rich],
        0,
    );
    let second_root = sha256d(&second);
    let subject = serialize(
        2,
        &[
            TxInput {
                txid: root,
                output_index: 0,
                script: vec![],
                sequence: u32::MAX,
            },
            TxInput {
                txid: second_root,
                output_index: 0,
                script: vec![],
                sequence: u32::MAX,
            },
        ],
        &[vec![], vec![]],
        &[output],
        0,
    );
    // Two one-leaf BUMPs, two proven parents, one subject.
    let mut w = Writer::new();
    w.write_u32_le(0xefbe_0002).write_var_int(2);
    for r in [root, second_root] {
        w.write_var_int(800_000)
            .write_bytes(&[1, 1, 0, 2])
            .write_bytes(&r);
    }
    w.write_var_int(3)
        .write_bytes(&[1, 0])
        .write_bytes(&parent)
        .write_bytes(&[1, 1])
        .write_bytes(&second)
        .write_u8(0)
        .write_bytes(&subject);
    p.beef = w.into_bytes();
    refusal(&p, tip, "InputValueOutOfRange", false).await;
}
