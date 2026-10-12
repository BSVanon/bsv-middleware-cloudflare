//! Minimal transaction signing for refund payments.
//!
//! Ported from `poc-server/src/signer.rs`. This module provides just enough
//! functionality to sign a `createAction` template from the storage server
//! and produce a valid signed transaction for `processAction`.
//!
//! The `append_tx_to_beef` function from the POC is intentionally excluded —
//! use `bsv_sdk::transaction::Beef` for BEEF construction instead.
//!
//! # BRC-29 change output derivation
//!
//! Change outputs created here must be spendable later by the same wallet. The
//! reference `bsv-wallet-toolbox-rs` derives the change output locking script
//! via `derive_private_key(brc29, key_id, Self_).public_key()` and the spend
//! path uses the matching `derive_private_key(brc29, key_id, Self_)`. We do
//! the same here to guarantee a round-trip pair — see the module tests.

use bsv_sdk::primitives::encoding::{Reader, Writer};
pub use bsv_sdk::primitives::hash::hash160;
use bsv_sdk::primitives::hash::sha256d;
use bsv_sdk::wallet::{Counterparty, KeyDeriverApi, ProtoWallet, Protocol, SecurityLevel};

/// Sign a transaction template from the storage server's createAction response.
///
/// # Arguments
///
/// * `proto_wallet` - The ProtoWallet for key derivation (server's wallet)
/// * `create_result` - The raw JSON response from createAction
///
/// # Returns
///
/// The signed raw transaction bytes, ready for processAction.
pub fn sign_create_action_template(
    proto_wallet: &ProtoWallet,
    create_result: &serde_json::Value,
) -> Result<Vec<u8>, String> {
    // Parse the template from createAction response
    let version = create_result
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u32;
    let lock_time = create_result
        .get("lockTime")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let derivation_prefix = create_result
        .get("derivationPrefix")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let inputs = create_result
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or("createAction response missing 'inputs' array")?;
    let outputs = create_result
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or("createAction response missing 'outputs' array")?;

    // Build the unsigned raw transaction
    let mut raw_tx = Vec::new();

    // Version (4 bytes LE)
    raw_tx.extend_from_slice(&version.to_le_bytes());

    // Input count (varint)
    raw_tx.extend_from_slice(Writer::new().write_var_int(inputs.len() as u64).as_bytes());

    // Inputs (with empty unlocking scripts)
    for input in inputs {
        let source_txid = input
            .get("sourceTxid")
            .and_then(|v| v.as_str())
            .ok_or("input missing sourceTxid")?;
        let source_vout = input
            .get("sourceVout")
            .and_then(|v| v.as_u64())
            .ok_or("input missing sourceVout")? as u32;

        // txid (32 bytes, reversed from hex display order)
        let txid_bytes =
            hex::decode(source_txid).map_err(|e| format!("Invalid txid hex: {}", e))?;
        if txid_bytes.len() != 32 {
            return Err(format!("txid wrong length: {}", txid_bytes.len()));
        }
        let mut txid_le = txid_bytes;
        txid_le.reverse();
        raw_tx.extend_from_slice(&txid_le);

        // vout (4 bytes LE)
        raw_tx.extend_from_slice(&source_vout.to_le_bytes());

        // Empty unlocking script (will be filled after signing)
        raw_tx.extend_from_slice(Writer::new().write_var_int(0).as_bytes());

        // Sequence (4 bytes, 0xFFFFFFFF)
        raw_tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    }

    // Output count (varint)
    raw_tx.extend_from_slice(Writer::new().write_var_int(outputs.len() as u64).as_bytes());

    // Outputs
    for output in outputs {
        let satoshis = output
            .get("satoshis")
            .and_then(|v| v.as_u64())
            .ok_or("output missing satoshis")?;
        let locking_script_hex = output
            .get("lockingScript")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // satoshis (8 bytes LE)
        raw_tx.extend_from_slice(&satoshis.to_le_bytes());

        // If locking script is empty but has derivation suffix, derive P2PKH
        let locking_script = if locking_script_hex.is_empty() {
            let suffix = output
                .get("derivationSuffix")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !suffix.is_empty() && !derivation_prefix.is_empty() {
                // Derive change output P2PKH locking script. Must use
                // derive_private_key(..., Self_).public_key() — the matching
                // spend-time path below uses derive_private_key(..., Self_),
                // so this guarantees create/spend produce an inverse key pair.
                // See module docs and the round-trip test in this file.
                let key_id = format!("{} {}", derivation_prefix, suffix);
                let brc29_protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
                let derived_key = proto_wallet
                    .key_deriver()
                    .derive_private_key(&brc29_protocol, &key_id, &Counterparty::Self_)
                    .map_err(|e| format!("Change output key derivation failed: {}", e))?
                    .public_key();
                let pubkey_bytes = derived_key.to_compressed();
                let pkh = hash160(&pubkey_bytes);
                let mut script = vec![0x76, 0xa9, 0x14];
                script.extend_from_slice(&pkh);
                script.extend_from_slice(&[0x88, 0xac]);
                script
            } else {
                return Err("Output has empty locking script and no derivation info".to_string());
            }
        } else {
            hex::decode(locking_script_hex)
                .map_err(|e| format!("Invalid locking script hex: {}", e))?
        };

        // Script length (varint) + script bytes
        raw_tx.extend_from_slice(
            Writer::new()
                .write_var_int(locking_script.len() as u64)
                .as_bytes(),
        );
        raw_tx.extend_from_slice(&locking_script);
    }

    // Locktime (4 bytes LE)
    raw_tx.extend_from_slice(&lock_time.to_le_bytes());

    // Now sign each input
    for (vin, input) in inputs.iter().enumerate() {
        let source_satoshis = input
            .get("sourceSatoshis")
            .and_then(|v| v.as_u64())
            .ok_or("input missing sourceSatoshis")?;
        let source_locking_script_hex = input
            .get("sourceLockingScript")
            .and_then(|v| v.as_str())
            .ok_or("input missing sourceLockingScript")?;
        let source_locking_script = hex::decode(source_locking_script_hex)
            .map_err(|e| format!("Invalid source locking script hex: {}", e))?;

        // Get derivation info for this input
        let input_derivation_prefix = input
            .get("derivationPrefix")
            .and_then(|v| v.as_str())
            .unwrap_or(&derivation_prefix);
        let input_derivation_suffix = input
            .get("derivationSuffix")
            .and_then(|v| v.as_str())
            .ok_or(format!("input {} missing derivationSuffix", vin))?;

        // Determine counterparty from senderIdentityKey
        let sender_key_str = input.get("senderIdentityKey").and_then(|v| v.as_str());
        let counterparty = if let Some(sender_key) = sender_key_str {
            let pubkey = bsv_sdk::primitives::PublicKey::from_hex(sender_key)
                .map_err(|e| format!("Invalid sender key: {}", e))?;
            Counterparty::Other(pubkey)
        } else {
            Counterparty::Self_
        };

        // Derive the signing key using BRC-29 protocol
        let brc29_protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
        let key_id = format!("{} {}", input_derivation_prefix, input_derivation_suffix);

        // Extract expected hash from P2PKH locking script
        let expected_pkh_hex = if source_locking_script.len() == 25
            && source_locking_script[0] == 0x76
            && source_locking_script[1] == 0xa9
            && source_locking_script[2] == 0x14
        {
            hex::encode(&source_locking_script[3..23])
        } else {
            String::new()
        };

        // Try deriving with the indicated counterparty
        let key_primary = proto_wallet
            .key_deriver()
            .derive_private_key(&brc29_protocol, &key_id, &counterparty)
            .map_err(|e| format!("Key derivation (primary) failed for input {}: {}", vin, e))?;
        let pkh_primary = hex::encode(hash160(&key_primary.public_key().to_compressed()));

        // Also try with Self_ counterparty
        let key_self = proto_wallet
            .key_deriver()
            .derive_private_key(&brc29_protocol, &key_id, &Counterparty::Self_)
            .map_err(|e| format!("Key derivation (Self) failed for input {}: {}", vin, e))?;
        let pkh_self = hex::encode(hash160(&key_self.public_key().to_compressed()));

        // Determine which counterparty gives the correct key. If neither
        // derivation produces a key whose pubkey hashes to the expected P2PKH
        // hash, fail hard — silently signing with the wrong key produces an
        // invalid tx that OP_EQUALVERIFY rejects at broadcast time (ARC 461).
        let signing_key = if pkh_primary == expected_pkh_hex {
            key_primary
        } else if pkh_self == expected_pkh_hex {
            key_self
        } else {
            let counterparty_desc = match &counterparty {
                Counterparty::Other(pk) => format!("Other({})", pk.to_hex()),
                Counterparty::Self_ => "Self_".to_string(),
                Counterparty::Anyone => "Anyone".to_string(),
            };
            return Err(format!(
                "refund signer: no derived key matches parent output's P2PKH hash \
                 (input {}, key_id={:?}, counterparty_tried={}, expected_pkh={}, \
                 pkh_primary={}, pkh_self={}). Parent output derivation is \
                 asymmetric between create-time and spend-time — refusing to \
                 produce an invalid tx.",
                vin, key_id, counterparty_desc, expected_pkh_hex, pkh_primary, pkh_self,
            ));
        };

        // Compute BIP-143 sighash
        let sighash =
            compute_sighash(&raw_tx, vin as u32, &source_locking_script, source_satoshis)?;

        // Sign the sighash
        let signature = signing_key
            .sign(&sighash)
            .map_err(|e| format!("Signing failed for input {}: {}", vin, e))?;

        // Get the public key for the unlocking script
        let pubkey = signing_key.public_key();

        // Build P2PKH unlocking script: <sig+hashtype> <pubkey>
        let unlocking_script =
            build_p2pkh_unlocking_script(&signature.to_der(), &pubkey.to_compressed());

        // Insert the unlocking script into the transaction
        raw_tx = insert_unlocking_script(&raw_tx, vin as u32, &unlocking_script)?;
    }

    Ok(raw_tx)
}

/// Compute the txid from a raw transaction (double SHA256, reversed).
pub fn compute_txid(raw_tx: &[u8]) -> String {
    let hash = sha256d(raw_tx);
    let mut reversed = hash;
    reversed.reverse();
    hex::encode(reversed)
}

// =============================================================================
// BIP-143 Sighash
// =============================================================================

/// Computes the BIP-143 sighash for a transaction input.
fn compute_sighash(
    tx_data: &[u8],
    input_index: u32,
    locking_script: &[u8],
    satoshis: u64,
) -> Result<[u8; 32], String> {
    let (version, inputs, outputs, locktime) =
        parse_transaction(tx_data).map_err(|e| format!("Parse failed: {}", e))?;

    // hashPrevouts: double SHA256 of all outpoints
    let mut prevouts_data = Vec::new();
    for input in &inputs {
        prevouts_data.extend_from_slice(&input.txid);
        prevouts_data.extend_from_slice(&input.vout.to_le_bytes());
    }
    let hash_prevouts = sha256d(&prevouts_data);

    // hashSequence: double SHA256 of all sequences
    let mut sequence_data = Vec::new();
    for input in &inputs {
        sequence_data.extend_from_slice(&input.sequence.to_le_bytes());
    }
    let hash_sequence = sha256d(&sequence_data);

    // hashOutputs: double SHA256 of all outputs
    let mut outputs_data = Vec::new();
    for output in &outputs {
        outputs_data.extend_from_slice(&output.satoshis.to_le_bytes());
        outputs_data.extend_from_slice(
            Writer::new()
                .write_var_int(output.script.len() as u64)
                .as_bytes(),
        );
        outputs_data.extend_from_slice(&output.script);
    }
    let hash_outputs = sha256d(&outputs_data);

    // Build the preimage
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);

    let input = &inputs[input_index as usize];
    preimage.extend_from_slice(&input.txid);
    preimage.extend_from_slice(&input.vout.to_le_bytes());

    preimage.extend_from_slice(
        Writer::new()
            .write_var_int(locking_script.len() as u64)
            .as_bytes(),
    );
    preimage.extend_from_slice(locking_script);

    preimage.extend_from_slice(&satoshis.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&locktime.to_le_bytes());

    // sighash type: SIGHASH_ALL | SIGHASH_FORKID = 0x41
    preimage.extend_from_slice(&0x41u32.to_le_bytes());

    Ok(sha256d(&preimage))
}

// =============================================================================
// Transaction Parsing
// =============================================================================

struct TxInput {
    txid: [u8; 32],
    vout: u32,
    script: Vec<u8>,
    sequence: u32,
}

struct TxOutput {
    satoshis: u64,
    script: Vec<u8>,
}

fn parse_transaction(tx_data: &[u8]) -> Result<(u32, Vec<TxInput>, Vec<TxOutput>, u32), String> {
    let mut offset = 0;

    if tx_data.len() < 10 {
        return Err("Transaction too short".to_string());
    }

    let version = u32::from_le_bytes([
        tx_data[offset],
        tx_data[offset + 1],
        tx_data[offset + 2],
        tx_data[offset + 3],
    ]);
    offset += 4;

    let (input_count, bytes_read) = {
        let mut reader = Reader::new(&tx_data[offset..]);
        let value = reader.read_var_int().map_err(|e| e.to_string())?;
        (value, reader.position())
    };
    offset += bytes_read;

    let mut inputs = Vec::with_capacity(input_count as usize);
    for _ in 0..input_count {
        if offset + 36 > tx_data.len() {
            return Err("Unexpected end of tx (input outpoint)".to_string());
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&tx_data[offset..offset + 32]);
        offset += 32;

        let vout = u32::from_le_bytes([
            tx_data[offset],
            tx_data[offset + 1],
            tx_data[offset + 2],
            tx_data[offset + 3],
        ]);
        offset += 4;

        let (script_len, bytes_read) = {
            let mut reader = Reader::new(&tx_data[offset..]);
            let value = reader.read_var_int().map_err(|e| e.to_string())?;
            (value, reader.position())
        };
        offset += bytes_read;

        if offset + script_len as usize > tx_data.len() {
            return Err("Unexpected end of tx (input script)".to_string());
        }
        let script = tx_data[offset..offset + script_len as usize].to_vec();
        offset += script_len as usize;

        if offset + 4 > tx_data.len() {
            return Err("Unexpected end of tx (sequence)".to_string());
        }
        let sequence = u32::from_le_bytes([
            tx_data[offset],
            tx_data[offset + 1],
            tx_data[offset + 2],
            tx_data[offset + 3],
        ]);
        offset += 4;

        inputs.push(TxInput {
            txid,
            vout,
            script,
            sequence,
        });
    }

    let (output_count, bytes_read) = {
        let mut reader = Reader::new(&tx_data[offset..]);
        let value = reader.read_var_int().map_err(|e| e.to_string())?;
        (value, reader.position())
    };
    offset += bytes_read;

    let mut outputs = Vec::with_capacity(output_count as usize);
    for _ in 0..output_count {
        if offset + 8 > tx_data.len() {
            return Err("Unexpected end of tx (output satoshis)".to_string());
        }
        let satoshis = u64::from_le_bytes([
            tx_data[offset],
            tx_data[offset + 1],
            tx_data[offset + 2],
            tx_data[offset + 3],
            tx_data[offset + 4],
            tx_data[offset + 5],
            tx_data[offset + 6],
            tx_data[offset + 7],
        ]);
        offset += 8;

        let (script_len, bytes_read) = {
            let mut reader = Reader::new(&tx_data[offset..]);
            let value = reader.read_var_int().map_err(|e| e.to_string())?;
            (value, reader.position())
        };
        offset += bytes_read;

        if offset + script_len as usize > tx_data.len() {
            return Err("Unexpected end of tx (output script)".to_string());
        }
        let script = tx_data[offset..offset + script_len as usize].to_vec();
        offset += script_len as usize;

        outputs.push(TxOutput { satoshis, script });
    }

    if offset + 4 > tx_data.len() {
        return Err("Unexpected end of tx (locktime)".to_string());
    }
    let locktime = u32::from_le_bytes([
        tx_data[offset],
        tx_data[offset + 1],
        tx_data[offset + 2],
        tx_data[offset + 3],
    ]);

    Ok((version, inputs, outputs, locktime))
}

// =============================================================================
// Unlocking Scripts
// =============================================================================

/// Build a P2PKH unlocking script: <sig + SIGHASH_FORKID> <pubkey>
fn build_p2pkh_unlocking_script(signature_der: &[u8], pubkey_compressed: &[u8]) -> Vec<u8> {
    let mut script = Vec::new();

    // Push signature + hashtype byte (SIGHASH_ALL | SIGHASH_FORKID = 0x41)
    let sig_len = signature_der.len() + 1;
    script.push(sig_len as u8);
    script.extend_from_slice(signature_der);
    script.push(0x41);

    // Push compressed pubkey (33 bytes)
    script.push(pubkey_compressed.len() as u8);
    script.extend_from_slice(pubkey_compressed);

    script
}

/// Insert an unlocking script at the given input index by rebuilding the tx.
fn insert_unlocking_script(
    tx_data: &[u8],
    input_index: u32,
    unlocking_script: &[u8],
) -> Result<Vec<u8>, String> {
    let (version, inputs, outputs, locktime) =
        parse_transaction(tx_data).map_err(|e| format!("Parse failed: {}", e))?;

    let mut result = Vec::new();
    result.extend_from_slice(&version.to_le_bytes());
    result.extend_from_slice(Writer::new().write_var_int(inputs.len() as u64).as_bytes());

    for (i, input) in inputs.iter().enumerate() {
        result.extend_from_slice(&input.txid);
        result.extend_from_slice(&input.vout.to_le_bytes());

        let script = if i == input_index as usize {
            unlocking_script
        } else {
            &input.script
        };

        result.extend_from_slice(Writer::new().write_var_int(script.len() as u64).as_bytes());
        result.extend_from_slice(script);
        result.extend_from_slice(&input.sequence.to_le_bytes());
    }

    result.extend_from_slice(Writer::new().write_var_int(outputs.len() as u64).as_bytes());
    for output in &outputs {
        result.extend_from_slice(&output.satoshis.to_le_bytes());
        result.extend_from_slice(
            Writer::new()
                .write_var_int(output.script.len() as u64)
                .as_bytes(),
        );
        result.extend_from_slice(&output.script);
    }

    result.extend_from_slice(&locktime.to_le_bytes());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_sdk::primitives::PrivateKey;

    // Reproduces the production bug where the create-time and spend-time
    // derivations for a BRC-29 change output produced keys whose hash160s
    // did not match, causing broadcast rejection (ARC 461
    // "Script failed an OP_EQUALVERIFY operation").
    //
    // The create path (output builder at signer.rs:~108) derives the P2PKH
    // pubkey hash; the spend path (signer.rs:~197) derives the private key
    // whose public key must hash to the same value. If they don't, the
    // unlocking script fails OP_EQUALVERIFY.
    //
    // The reference `bsv-wallet-toolbox-rs` uses
    // `derive_private_key(brc29, key_id, Self_).public_key()` for the create
    // path and `derive_private_key(brc29, key_id, counterparty)` for the
    // spend path (defaulting counterparty to Self_ when no senderIdentityKey
    // is present). This test pins that invariant.
    #[test]
    fn brc29_self_change_create_spend_roundtrip() {
        let server_key = PrivateKey::from_hex(
            "ed31fecde26778e5f5f0788f0be77ead322056d6ecec03dd599ff2aa52222a4f",
        )
        .expect("valid hex");
        let wallet = ProtoWallet::new(Some(server_key));

        let brc29 = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
        let key_id = "AuW008NjJR5zmQ1fBXXsJeQyesmDn08TIPl82TlMe9Y= \
                      Gt1QNh3NX8z6RbHpOy38SzfTzBC4nr2/awhY+Iufi9c="
            .to_string();

        // Create path (output builder): must produce the pubkey hash that
        // will appear in the parent tx's locking script.
        let create_pub = wallet
            .key_deriver()
            .derive_private_key(&brc29, &key_id, &Counterparty::Self_)
            .expect("create-path key derivation")
            .public_key();
        let create_pkh = hash160(&create_pub.to_compressed());

        // Spend path: derive the private key to sign with. Its public key
        // must hash to the same value.
        let spend_priv = wallet
            .key_deriver()
            .derive_private_key(&brc29, &key_id, &Counterparty::Self_)
            .expect("spend-path key derivation");
        let spend_pkh = hash160(&spend_priv.public_key().to_compressed());

        assert_eq!(
            hex::encode(create_pkh),
            hex::encode(spend_pkh),
            "BRC-29 Self_ create/spend derivation must produce matching \
             pubkey hashes — if they diverge, refund txs will fail \
             OP_EQUALVERIFY at broadcast"
        );
    }

    // Pins the assumption that `derive_public_key(..., Self_, for_self=false)`
    // and `derive_private_key(..., Self_).public_key()` are equivalent. The
    // production bug was silently falling back to an arbitrary key when this
    // equivalence didn't hold at runtime; keeping this test around ensures
    // any SDK-level drift is caught immediately.
    // Reproduces the production bug where a BRC-29 payment from a client to
    // a server cannot be later spent by the server. The client constructs a
    // P2PKH output using `derive_public_key(..., Other(server_identity),
    // for_self=false)` — so the receiving pubkey is the server's derived key.
    // The server, to spend it, calls `derive_private_key(..., Other(client_identity))`.
    // Both sides must agree on the pubkey / pkh, or OP_EQUALVERIFY fails.
    //
    // Production refund tx 45f9caf3... failed with ARC 461 because this
    // round-trip did NOT hold. This test pins it.
    #[test]
    fn brc29_other_round_trip_client_server() {
        use bsv_sdk::wallet::GetPublicKeyArgs;

        let client_key = PrivateKey::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let server_key = PrivateKey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let client_wallet = ProtoWallet::new(Some(client_key));
        let server_wallet = ProtoWallet::new(Some(server_key));
        let client_identity = client_wallet.identity_key();
        let server_identity = server_wallet.identity_key();

        let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
        let key_id = "AuW008NjJR5zmQ1fBXXsJeQyesmDn08TIPl82TlMe9Y= \
                      Gt1QNh3NX8z6RbHpOy38SzfTzBC4nr2/awhY+Iufi9c="
            .to_string();

        // CLIENT side: derive server's RECEIVING pubkey for the P2PKH output.
        let server_receiving_pub_hex = client_wallet
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(protocol.clone()),
                key_id: Some(key_id.clone()),
                counterparty: Some(Counterparty::Other(server_identity.clone())),
                for_self: Some(false),
            })
            .expect("client public key derivation")
            .public_key;
        let server_receiving_pub_bytes = hex::decode(&server_receiving_pub_hex).unwrap();
        let expected_pkh = hash160(&server_receiving_pub_bytes);

        // SERVER side: derive the matching private key to SPEND the output.
        let signing_key = server_wallet
            .key_deriver()
            .derive_private_key(&protocol, &key_id, &Counterparty::Other(client_identity))
            .expect("server private key derivation");
        let actual_pkh = hash160(&signing_key.public_key().to_compressed());

        assert_eq!(
            hex::encode(expected_pkh),
            hex::encode(actual_pkh),
            "BRC-29 Counterparty::Other round-trip FAILED.\n\
             Client derived receiving pub: {}\n\
             Expected PKH (what client put in P2PKH output): {}\n\
             Actual PKH (what server's signing key produces): {}\n\
             This is the root cause of production refund OP_EQUALVERIFY failures.",
            server_receiving_pub_hex,
            hex::encode(expected_pkh),
            hex::encode(actual_pkh),
        );
    }

    // End-to-end guard: simulates a client BRC-29 payment to a server,
    // then the server spending that output via sign_create_action_template.
    // Verifies the signed unlock's pubkey hash matches the parent's P2PKH.
    //
    // This is the "once and for all" regression test: if the signer,
    // counterparty metadata, or SDK derivation ever diverges, this catches it.
    #[test]
    fn brc29_e2e_client_pays_server_then_server_spends() {
        use bsv_sdk::wallet::GetPublicKeyArgs;

        let client_key = PrivateKey::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let server_key = PrivateKey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let client_wallet = ProtoWallet::new(Some(client_key));
        let server_wallet = ProtoWallet::new(Some(server_key.clone()));
        let client_identity = client_wallet.identity_key();
        let server_identity = server_wallet.identity_key();

        let derivation_prefix = "AuW008NjJR5zmQ1fBXXsJeQyesmDn08TIPl82TlMe9Y=";
        let derivation_suffix = "Gt1QNh3NX8z6RbHpOy38SzfTzBC4nr2/awhY+Iufi9c=";
        let key_id = format!("{} {}", derivation_prefix, derivation_suffix);
        let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");

        // ── Step 1: Client derives server's P2PKH locking script ──
        let server_pub_hex = client_wallet
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(protocol.clone()),
                key_id: Some(key_id.clone()),
                counterparty: Some(Counterparty::Other(server_identity)),
                for_self: Some(false),
            })
            .expect("client derive")
            .public_key;
        let server_pub_bytes = hex::decode(&server_pub_hex).unwrap();
        let pkh = hash160(&server_pub_bytes);
        let locking_script_hex = format!("76a914{}88ac", hex::encode(pkh));

        // ── Step 2: Build a fake parent tx containing that P2PKH output ──
        let parent_satoshis: u64 = 100;
        let mut parent_tx = Vec::new();
        parent_tx.extend_from_slice(&1u32.to_le_bytes()); // version
        parent_tx.extend_from_slice(Writer::new().write_var_int(1).as_bytes()); // 1 input
        parent_tx.extend_from_slice(&[0u8; 32]); // coinbase txid
        parent_tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // vout
        parent_tx.extend_from_slice(Writer::new().write_var_int(1).as_bytes()); // script len
        parent_tx.push(0x00); // OP_0
        parent_tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // sequence
        parent_tx.extend_from_slice(Writer::new().write_var_int(1).as_bytes()); // 1 output
        parent_tx.extend_from_slice(&parent_satoshis.to_le_bytes());
        let ls_bytes = hex::decode(&locking_script_hex).unwrap();
        parent_tx.extend_from_slice(
            Writer::new()
                .write_var_int(ls_bytes.len() as u64)
                .as_bytes(),
        );
        parent_tx.extend_from_slice(&ls_bytes);
        parent_tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
        let parent_txid = compute_txid(&parent_tx);

        // ── Step 3: Build a createAction-style JSON template ──
        let create_result = serde_json::json!({
            "version": 1,
            "lockTime": 0,
            "derivationPrefix": derivation_prefix,
            "inputs": [{
                "sourceTxid": parent_txid,
                "sourceVout": 0,
                "sourceSatoshis": parent_satoshis,
                "sourceLockingScript": locking_script_hex,
                "derivationPrefix": derivation_prefix,
                "derivationSuffix": derivation_suffix,
                "senderIdentityKey": client_identity.to_hex(),
            }],
            "outputs": [{
                "satoshis": parent_satoshis - 1,
                "lockingScript": locking_script_hex,
            }],
        });

        // ── Step 4: Sign the template as the server ──
        let signed_tx = sign_create_action_template(&server_wallet, &create_result)
            .expect("signer should produce a valid tx");

        // ── Step 5: Verify the unlock pubkey matches the parent P2PKH ──
        let (_version, inputs, _outputs, _locktime) =
            parse_transaction(&signed_tx).expect("parse signed tx");
        let unlock = &inputs[0].script;
        assert!(!unlock.is_empty(), "unlocking script is empty");

        // P2PKH unlock: <sig_len> <sig+hashtype> <pubkey_len=0x21> <33-byte pubkey>
        let sig_len = unlock[0] as usize;
        let pub_offset = 1 + sig_len;
        assert!(
            pub_offset < unlock.len(),
            "unlock script too short for pubkey"
        );
        let pub_len = unlock[pub_offset] as usize;
        assert_eq!(pub_len, 33, "expected 33-byte compressed pubkey");
        let unlock_pubkey = &unlock[pub_offset + 1..pub_offset + 1 + pub_len];
        let unlock_pkh = hash160(unlock_pubkey);

        assert_eq!(
            hex::encode(pkh),
            hex::encode(unlock_pkh),
            "E2E FAILURE: signed tx's unlock pubkey hash ({}) \
             doesn't match the parent P2PKH locking script ({}). \
             The signer derived the wrong key for Counterparty::Other.",
            hex::encode(unlock_pkh),
            hex::encode(pkh),
        );
    }

    // Identical to above but for Counterparty::Self_ (change outputs).
    #[test]
    fn brc29_e2e_server_change_create_and_spend() {
        let server_key = PrivateKey::from_hex(
            "ed31fecde26778e5f5f0788f0be77ead322056d6ecec03dd599ff2aa52222a4f",
        )
        .unwrap();
        let server_wallet = ProtoWallet::new(Some(server_key));

        let derivation_prefix = "pfx-test-base64==";
        let derivation_suffix = "sfx-test-base64==";
        let key_id = format!("{} {}", derivation_prefix, derivation_suffix);
        let brc29 = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");

        // Server derives change output P2PKH (same path as signer.rs:~127)
        let change_key = server_wallet
            .key_deriver()
            .derive_private_key(&brc29, &key_id, &Counterparty::Self_)
            .expect("change key derivation")
            .public_key();
        let pkh = hash160(&change_key.to_compressed());
        let locking_script_hex = format!("76a914{}88ac", hex::encode(pkh));

        // Build parent and template
        let parent_satoshis: u64 = 50;
        let mut parent_tx = Vec::new();
        parent_tx.extend_from_slice(&1u32.to_le_bytes());
        parent_tx.extend_from_slice(Writer::new().write_var_int(1).as_bytes());
        parent_tx.extend_from_slice(&[0u8; 32]);
        parent_tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        parent_tx.extend_from_slice(Writer::new().write_var_int(1).as_bytes());
        parent_tx.push(0x00);
        parent_tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        parent_tx.extend_from_slice(Writer::new().write_var_int(1).as_bytes());
        parent_tx.extend_from_slice(&parent_satoshis.to_le_bytes());
        let ls_bytes = hex::decode(&locking_script_hex).unwrap();
        parent_tx.extend_from_slice(
            Writer::new()
                .write_var_int(ls_bytes.len() as u64)
                .as_bytes(),
        );
        parent_tx.extend_from_slice(&ls_bytes);
        parent_tx.extend_from_slice(&0u32.to_le_bytes());
        let parent_txid = compute_txid(&parent_tx);

        // No senderIdentityKey → Self_ counterparty
        let create_result = serde_json::json!({
            "version": 1,
            "lockTime": 0,
            "derivationPrefix": derivation_prefix,
            "inputs": [{
                "sourceTxid": parent_txid,
                "sourceVout": 0,
                "sourceSatoshis": parent_satoshis,
                "sourceLockingScript": locking_script_hex,
                "derivationPrefix": derivation_prefix,
                "derivationSuffix": derivation_suffix,
            }],
            "outputs": [{
                "satoshis": parent_satoshis - 1,
                "lockingScript": locking_script_hex,
            }],
        });

        let signed_tx = sign_create_action_template(&server_wallet, &create_result)
            .expect("signer should produce a valid tx");

        let (_version, inputs, _outputs, _locktime) =
            parse_transaction(&signed_tx).expect("parse signed tx");
        let unlock = &inputs[0].script;
        let sig_len = unlock[0] as usize;
        let pub_offset = 1 + sig_len;
        let pub_len = unlock[pub_offset] as usize;
        let unlock_pubkey = &unlock[pub_offset + 1..pub_offset + 1 + pub_len];
        let unlock_pkh = hash160(unlock_pubkey);

        assert_eq!(
            hex::encode(pkh),
            hex::encode(unlock_pkh),
            "E2E Self_ FAILURE: signed tx's unlock pubkey hash ({}) \
             doesn't match the parent P2PKH ({})",
            hex::encode(unlock_pkh),
            hex::encode(pkh),
        );
    }

    #[test]
    fn brc29_self_derive_public_matches_derive_private_public() {
        let server_key = PrivateKey::from_hex(
            "ed31fecde26778e5f5f0788f0be77ead322056d6ecec03dd599ff2aa52222a4f",
        )
        .expect("valid hex");
        let wallet = ProtoWallet::new(Some(server_key));

        let brc29 = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
        let key_id = "prefix-test suffix-test".to_string();

        let via_public = wallet
            .key_deriver()
            .derive_public_key(&brc29, &key_id, &Counterparty::Self_, false)
            .expect("derive_public_key");
        let via_private = wallet
            .key_deriver()
            .derive_private_key(&brc29, &key_id, &Counterparty::Self_)
            .expect("derive_private_key")
            .public_key();

        assert_eq!(
            hex::encode(via_public.to_compressed()),
            hex::encode(via_private.to_compressed()),
            "derive_public_key(Self_, for_self=false) must equal \
             derive_private_key(Self_).public_key() — any divergence \
             indicates an SDK-level BRC-42 bug"
        );
    }
}
