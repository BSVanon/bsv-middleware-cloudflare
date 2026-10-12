//! The words a BRC-29 payment check answers with: one enum, no booleans.
//! The rule behind it: a payment verifier answers in words, never a
//! boolean, fails closed without a header service, and never serves on a
//! root it could not check.
//!
//! A host collapses the words to "serve" or "refuse" in ONE visible match.
//! Only [`PaymentVerdict::Verified`] serves. [`PaymentVerdict::NoHeaderService`]
//! is the server's own fault and is answered as a 5xx, never as a client
//! error. [`PaymentVerdict::Unverifiable`] is a refusal too, and its
//! [`UnverifiableReason`] says whose side it is on
//! ([`UnverifiableReason::is_server_side`]): a header lookup the service
//! could not answer is the server's (a 5xx of its own, the quote kept, the
//! same payment retried later: the ruling of 2026-10-08); invalid bytes, a
//! spend the interpreter refuses, a missing output, a key that does not
//! derive and a proof that is absent are the payer's (a 4xx, no fields: the
//! ruling of 2026-10-09 on the no-root class). The core never serves on it,
//! and neither may a host.
//!
//! No word and no reason is a size or a count: a valid payment of any size
//! is read, and a refusal is for invalid bytes only, named by offset and
//! kind (the posture of 2026-10-09, "a BEEF of any size").

use std::fmt;

/// The verdict on one BRC-29 payment: the six words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentVerdict {
    /// The payment's bytes are a valid BEEF whose scripts run, the subject's
    /// output pays the server's derived key at least the quoted amount, and
    /// every merkle root in the proof matches the block header at its
    /// height. `satoshis` is the output's amount, which may exceed the price.
    Verified { satoshis: u64 },
    /// The output pays the derived key, but less than required.
    Underpaid { paid: u64, required: u64 },
    /// The output's locking script is not the one derived for this
    /// (server, sender, prefix, suffix) tuple: it pays another server, an
    /// older quote, or the sender itself. Both scripts in hex.
    WrongScript { expected: String, actual: String },
    /// No header service was supplied, so SPV cannot run. Fail closed: a
    /// deployment fault, refused BEFORE the bytes are read. Answer it as a
    /// 5xx server fault, never a 4xx client error.
    NoHeaderService,
    /// A merkle root in the proof differs from the block header at that
    /// height: a fraud signal, never an outage.
    RootMismatch { height: u32, root: String },
    /// The payment cannot be verified; the reason says what and whose side
    /// ([`UnverifiableReason::is_server_side`]). A refusal: a host fails
    /// closed on it. The server's side (a header the service could not
    /// answer for) is answered 5xx with the quote kept, since the payment
    /// may be good and only the check is missing; the payer's side (invalid
    /// bytes, a refused spend, no proof, a key that does not derive, a
    /// missing output) is answered 4xx with the quote kept, since the payer
    /// must send another payment. The one `Unverifiable` a host may serve on
    /// is [`UnverifiableReason::RootsUnchecked`], and only through the
    /// opt-out that names it
    /// ([`verify_brc29_payment_structural_only`](crate::verify_brc29_payment_structural_only)).
    Unverifiable { reason: UnverifiableReason },
}

/// Why a payment is [`PaymentVerdict::Unverifiable`].
///
/// No reason is a size or a count: a payment is refused for what its bytes
/// say, never for how many they are.
///
/// Non-exhaustive: a reason may be added in a minor release, so a match on
/// it carries a catch-all arm. The six words of [`PaymentVerdict`] are the
/// contract and stay exhaustive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnverifiableReason {
    /// Header context needed for finality or coinbase maturity was unavailable.
    /// The host must supply a tip; the same payment may be retried. Server-side.
    MiningContextUnavailable {
        /// Byte offset of the contextual check.
        offset: u64,
        /// Spending transaction in display hex.
        txid: String,
        /// Input if the check names one.
        input: Option<u32>,
        /// Finality or CoinbaseMaturity.
        check: String,
    },
    /// The BEEF's bytes are invalid: the stream offset of the byte and one
    /// of the streaming reader's kinds (bsv-rs 0.5.0 or later,
    /// `transaction::beef_stream::Kind`, as its name; `NoInputs`, since
    /// 0.4.1, for a raw transaction with no input, at its leading byte). The
    /// reading stopped there. The payer's side.
    InvalidBeef {
        /// The stream offset of the byte the refusal names.
        offset: u64,
        /// The kind, as the reader names it (`BadVersion`, `Truncated`,
        /// `InputNamesNoElement`, ...).
        kind: String,
        /// The reader's refusal with its data (txids in display hex).
        reason: String,
    },
    /// The BEEF's bytes are well formed up to `offset` and the script
    /// interpreter refused a spend of an unproven transaction: an input
    /// that does not unlock the parent output the BEEF carries, a parent
    /// output that is not there to spend, or a transaction worth more than
    /// its inputs, or a local evaluator decline under a work or memory
    /// resource bound (not a script validity judgment). The payer's side.
    SpendRefused {
        /// The offset of the input (or of the transaction, for the value
        /// rule).
        offset: u64,
        /// The spending transaction (display hex).
        txid: String,
        /// The input, when one input is named.
        input: Option<u32>,
        /// Why, as the reader says it.
        why: String,
    },
    /// The bytes are not a BEEF the output check can read (the offline
    /// output check, which reads the subject transaction). The payer's side.
    MalformedTransaction(String),
    /// The BEEF carries no raw transaction: nothing pays. The payer's side.
    NoTransaction,
    /// The subject transaction has no output at the index that is paid.
    /// The payer's side.
    OutputMissing {
        /// The index the payment names.
        output_index: u32,
        /// How many outputs the transaction has.
        output_count: usize,
    },
    /// The SENDER's identity key does not derive a BRC-29 key (it is not a
    /// public key). The payer's side. A SERVER key that does not derive is
    /// the host's own fault and is [`PaymentFault::KeyDerivation`], never
    /// this.
    KeyDerivation(String),
    /// The BEEF is valid and gives no root to check for `txid`: it carries
    /// no BUMP, so nothing is proven. The payer's side (the ruling of
    /// 2026-10-09): the server never fetches a missing proof; the payer
    /// sends a proven BEEF. A transaction with no input is invalid bytes to
    /// the reader (bsv-rs 0.4.1, [`InvalidBeef`](Self::InvalidBeef) with the
    /// kind `NoInputs` at its leading byte), refused before this word;
    /// 0.4.0's reader read it as valid with no root and this word refused it,
    /// and that rule stays beneath the reader's as defense in depth.
    NoProof {
        /// The transaction whose proof is absent (display hex): the
        /// subject; beneath the reader, an unproven transaction with no
        /// input.
        txid: String,
    },
    /// The header service could not answer for `height` (outage, timeout,
    /// HTTP error, unparseable body, height not yet indexed): the lowest
    /// such height. The SERVER's side: nothing charged, the quote kept, the
    /// same payment retried once the service answers.
    HeaderLookupFailed {
        /// The height asked for.
        height: u32,
        /// What the service said.
        reason: String,
    },
    /// The caller opted out of SPV by name
    /// ([`verify_brc29_payment_structural_only`](crate::verify_brc29_payment_structural_only)):
    /// the BEEF is valid and the output pays `satoshis`, and `roots` merkle
    /// roots were NOT checked against block headers, by choice. Neither
    /// side's fault; the one `Unverifiable` a host may serve on, and only
    /// because its caller named the opt-out.
    RootsUnchecked {
        /// The output's satoshis (at least the price).
        satoshis: u64,
        /// How many distinct roots went unchecked.
        roots: usize,
    },
}

impl UnverifiableReason {
    /// `true` when the server, not the payment, is why it cannot be
    /// verified: [`HeaderLookupFailed`](Self::HeaderLookupFailed) or missing mining context.
    /// A host answers a server-side reason 5xx with the quote kept (retry
    /// the same payment) and every other reason 4xx (send another payment).
    pub fn is_server_side(&self) -> bool {
        matches!(
            self,
            Self::HeaderLookupFailed { .. } | Self::MiningContextUnavailable { .. }
        )
    }
}

impl fmt::Display for UnverifiableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MiningContextUnavailable { offset, txid, input, check } => write!(f, "mining context unavailable for {check}: transaction {txid} at offset {offset}, input {input:?}; the host's header service must supply a mining tip"),
            Self::InvalidBeef {
                offset,
                kind,
                reason,
            } => write!(f, "BEEF is invalid at offset {offset} ({kind}): {reason}"),
            Self::SpendRefused {
                offset,
                txid,
                input,
                why,
            } => {
                write!(f, "transaction {txid} at offset {offset} ")?;
                if let Some(input) = input {
                    write!(f, "input {input} ")?;
                }
                write!(f, "does not spend: {why}")
            }
            Self::MalformedTransaction(e) => write!(f, "payment transaction unreadable: {e}"),
            Self::NoTransaction => write!(f, "BEEF carries no raw transaction: nothing pays"),
            Self::OutputMissing {
                output_index,
                output_count,
            } => write!(
                f,
                "payment transaction has no output at index {output_index} ({output_count} outputs present)"
            ),
            Self::KeyDerivation(e) => write!(f, "sender key does not derive a BRC-29 key: {e}"),
            Self::NoProof { txid } => write!(
                f,
                "no merkle proof for transaction {txid}: the BEEF gives no root to check (no BUMP, or an ancestry that reaches no proof); send a proven BEEF"
            ),
            Self::HeaderLookupFailed { height, reason } => write!(
                f,
                "the header service could not answer at height {height}: {reason}"
            ),
            Self::RootsUnchecked { satoshis, roots } => write!(
                f,
                "structural-only verification: {roots} merkle root(s) NOT checked against block headers (no SPV), by the caller's choice; the output carries {satoshis} satoshis"
            ),
        }
    }
}

/// A payment the full check verified: the amount read from the paying
/// output and the subject transaction's txid as the reader hashed it, so a
/// host internalizes and records without parsing the BEEF a second time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    /// Satoshis in the paying output (at least the price).
    pub satoshis: u64,
    /// The subject transaction's txid (display hex).
    pub txid: String,
}

impl PaymentVerdict {
    /// The word alone, for logs and conformance tables.
    pub fn word(&self) -> &'static str {
        match self {
            PaymentVerdict::Verified { .. } => "Verified",
            PaymentVerdict::Underpaid { .. } => "Underpaid",
            PaymentVerdict::WrongScript { .. } => "WrongScript",
            PaymentVerdict::NoHeaderService => "NoHeaderService",
            PaymentVerdict::RootMismatch { .. } => "RootMismatch",
            PaymentVerdict::Unverifiable { .. } => "Unverifiable",
        }
    }

    /// `true` only for [`Verified`](Self::Verified): the one word the core
    /// stands behind and the one word a host may serve on. Every other word
    /// is a refusal, [`Unverifiable`](Self::Unverifiable) included (fail
    /// closed, rule of 2026-10-08). This is the only accept predicate the
    /// core offers; there is no `is_accepted` that answers differently.
    pub fn is_verified(&self) -> bool {
        matches!(self, PaymentVerdict::Verified { .. })
    }

    /// `true` for every word but [`Verified`](Self::Verified): the payment
    /// is not served. [`Unverifiable`](Self::Unverifiable) is refused like
    /// the rest; what differs is only how a host renders it (a 5xx with the
    /// quote kept when the reason is the server's, a 4xx when it is the
    /// payer's).
    pub fn is_refused(&self) -> bool {
        !self.is_verified()
    }

    /// `true` for an [`Unverifiable`](Self::Unverifiable) whose reason is the
    /// server's ([`UnverifiableReason::is_server_side`]); `false` for every
    /// other word, [`NoHeaderService`](Self::NoHeaderService) included (a
    /// misconfiguration, the host's 500, not a transient condition).
    pub fn is_server_side_unverifiable(&self) -> bool {
        matches!(
            self,
            PaymentVerdict::Unverifiable { reason } if reason.is_server_side()
        )
    }
}

impl fmt::Display for PaymentVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaymentVerdict::Verified { satoshis } => {
                write!(f, "Verified: the output carries {} satoshis", satoshis)
            }
            PaymentVerdict::Underpaid { paid, required } => write!(
                f,
                "Payment output carries {} satoshis but {} are required",
                paid, required
            ),
            PaymentVerdict::WrongScript { expected, actual } => write!(
                f,
                "Payment output does not pay this server's BRC-29 derived key (expected script {}, got {})",
                expected, actual
            ),
            PaymentVerdict::NoHeaderService => write!(
                f,
                "No header service configured for SPV: pass one, or opt out by name with verify_brc29_payment_structural_only"
            ),
            PaymentVerdict::RootMismatch { height, root } => write!(
                f,
                "Payment merkle root {} at height {} does not match the block header",
                root, height
            ),
            PaymentVerdict::Unverifiable { reason } => {
                write!(f, "Payment not verified: {}", reason)
            }
        }
    }
}

/// The host's own fault while judging a payment: the input could not be
/// judged for a reason that is the server's, never the payer's. A payer's
/// bytes never produce one (they are an [`UnverifiableReason`]); a host
/// renders a fault as its own 500.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaymentFault {
    /// The SERVER's key does not derive: an invalid server private key or a
    /// derivation the wallet refused. Fix the deployment.
    KeyDerivation(String),
    /// The payment's byte source failed while it was being read. Never
    /// raised for bytes in hand (a slice cannot fail to be read); the arm a
    /// host that streams a body will meet. Says nothing about the payment
    /// and is never an acceptance.
    Source(String),
}

impl fmt::Display for PaymentFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaymentFault::KeyDerivation(msg) => {
                write!(f, "Server key derivation failed: {}", msg)
            }
            PaymentFault::Source(msg) => {
                write!(f, "The payment's byte source failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for PaymentFault {}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_failed() -> UnverifiableReason {
        UnverifiableReason::HeaderLookupFailed {
            height: 7,
            reason: "HTTP 503".into(),
        }
    }

    #[test]
    fn the_six_words_are_the_six_words() {
        let words = [
            PaymentVerdict::Verified { satoshis: 1 }.word(),
            PaymentVerdict::Underpaid {
                paid: 1,
                required: 2,
            }
            .word(),
            PaymentVerdict::WrongScript {
                expected: "a".into(),
                actual: "b".into(),
            }
            .word(),
            PaymentVerdict::NoHeaderService.word(),
            PaymentVerdict::RootMismatch {
                height: 1,
                root: "c".into(),
            }
            .word(),
            PaymentVerdict::Unverifiable {
                reason: lookup_failed(),
            }
            .word(),
        ];
        assert_eq!(
            words,
            [
                "Verified",
                "Underpaid",
                "WrongScript",
                "NoHeaderService",
                "RootMismatch",
                "Unverifiable"
            ]
        );
    }

    /// The one accept predicate: `Verified` alone. Every other word, every
    /// `Unverifiable` included, is refused: no helper in the core answers
    /// "accepted" for a root that was not checked.
    #[test]
    fn only_verified_is_verified_every_other_word_is_refused() {
        let verified = PaymentVerdict::Verified { satoshis: 5 };
        assert!(verified.is_verified());
        assert!(!verified.is_refused());
        let refused = [
            PaymentVerdict::Underpaid {
                paid: 4,
                required: 5,
            },
            PaymentVerdict::WrongScript {
                expected: "a".into(),
                actual: "b".into(),
            },
            PaymentVerdict::NoHeaderService,
            PaymentVerdict::RootMismatch {
                height: 1,
                root: "c".into(),
            },
            PaymentVerdict::Unverifiable {
                reason: lookup_failed(),
            },
            PaymentVerdict::Unverifiable {
                reason: UnverifiableReason::NoProof { txid: "ab".into() },
            },
            PaymentVerdict::Unverifiable {
                reason: UnverifiableReason::RootsUnchecked {
                    satoshis: 5,
                    roots: 1,
                },
            },
        ];
        for word in refused {
            assert!(!word.is_verified(), "{word:?}");
            assert!(word.is_refused(), "{word:?} is a refusal, fail closed");
        }
    }

    /// The side of each reason: a header the service could not answer for
    /// is the server's; everything else is the payer's (or the caller's
    /// named choice), 4xx at the host.
    #[test]
    fn only_a_header_lookup_failure_is_the_servers_side() {
        assert!(lookup_failed().is_server_side());
        assert!(PaymentVerdict::Unverifiable {
            reason: lookup_failed()
        }
        .is_server_side_unverifiable());
        let payers = [
            UnverifiableReason::InvalidBeef {
                offset: 12,
                kind: "InputNamesNoElement".into(),
                reason: "x".into(),
            },
            UnverifiableReason::SpendRefused {
                offset: 40,
                txid: "ab".into(),
                input: Some(0),
                why: "Script(..)".into(),
            },
            UnverifiableReason::MalformedTransaction("x".into()),
            UnverifiableReason::NoTransaction,
            UnverifiableReason::OutputMissing {
                output_index: 1,
                output_count: 1,
            },
            UnverifiableReason::KeyDerivation("x".into()),
            UnverifiableReason::NoProof { txid: "ab".into() },
            UnverifiableReason::RootsUnchecked {
                satoshis: 1,
                roots: 1,
            },
        ];
        for reason in payers {
            assert!(!reason.is_server_side(), "{reason:?}");
            assert!(!PaymentVerdict::Unverifiable { reason }.is_server_side_unverifiable());
        }
        assert!(
            !PaymentVerdict::NoHeaderService.is_server_side_unverifiable(),
            "a misconfiguration is the host's 500, not a transient 503"
        );
    }

    #[test]
    fn display_names_the_fact() {
        let s = PaymentVerdict::Underpaid {
            paid: 5,
            required: 10,
        }
        .to_string();
        assert!(
            s.contains("5 satoshis") && s.contains("10 are required"),
            "{s}"
        );
        let s = PaymentVerdict::RootMismatch {
            height: 42,
            root: "ab".into(),
        }
        .to_string();
        assert!(s.contains("height 42"), "{s}");
        let s = PaymentVerdict::NoHeaderService.to_string();
        assert!(
            s.contains("header service") && s.contains("structural_only"),
            "{s}"
        );
        let s = PaymentVerdict::Unverifiable {
            reason: lookup_failed(),
        }
        .to_string();
        assert!(s.contains("height 7") && s.contains("HTTP 503"), "{s}");
        let s = UnverifiableReason::InvalidBeef {
            offset: 12,
            kind: "InputNamesNoElement".into(),
            reason: "invalid BEEF at byte 12: InputNamesNoElement { txid: \"11\" }".into(),
        }
        .to_string();
        assert!(
            s.contains("offset 12") && s.contains("InputNamesNoElement") && s.contains("\"11\""),
            "{s}"
        );
        let s = UnverifiableReason::SpendRefused {
            offset: 40,
            txid: "ab".into(),
            input: Some(0),
            why: "Script(\"fail\")".into(),
        }
        .to_string();
        assert!(
            s.contains("transaction ab") && s.contains("input 0") && s.contains("fail"),
            "{s}"
        );
        let s = UnverifiableReason::NoProof { txid: "cd".into() }.to_string();
        assert!(s.contains("cd") && s.contains("no merkle proof"), "{s}");
        let s = UnverifiableReason::OutputMissing {
            output_index: 3,
            output_count: 1,
        }
        .to_string();
        assert!(s.contains("index 3") && s.contains("1 outputs"), "{s}");
        let s = UnverifiableReason::RootsUnchecked {
            satoshis: 7,
            roots: 2,
        }
        .to_string();
        assert!(
            s.contains("structural-only")
                && s.contains("2 merkle root")
                && s.contains("7 satoshis"),
            "{s}"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(PaymentFault::KeyDerivation("x".into()));
        assert!(boxed.to_string().contains("Server key"));
    }
}
