//! BRC-29 payment verification before internalize: pays-us-correctly
//! **and** real-and-confirmable, answered in the six words.
//!
//! # A payment of any size
//!
//! A valid payment is never refused for its size or its counts (the ruling
//! of 2026-10-09, "a BEEF of any size"). The payment is read ONCE through
//! the streaming reader of bsv-rs 0.5 (0.5.0 at least)
//! ([`bsv_sdk::transaction::verify_stream`]): the reader holds one element
//! of the BEEF and its index, never the BEEF; a tap beside it notes the
//! subject's output as the bytes pass. A refusal of the bytes names the
//! offset and one of the reader's twenty-four kinds
//! ([`UnverifiableReason::InvalidBeef`]), none of which is a size or a
//! count. The caller may set a local work bound per input. The primary API takes
//! an asynchronous byte source; slice APIs wrap it in bounded chunks.
//!
//! # Order of checks ([`verify_brc29_payment`])
//!
//! 0. a header service is configured, else
//!    [`NoHeaderService`](PaymentVerdict::NoHeaderService), before the bytes
//!    are read, so a deployment with no header service never looks like one
//!    that verifies; the server's key derives, else `Err(PaymentFault)`
//!    (the host's own fault); the sender's key derives, else
//!    [`Unverifiable`](PaymentVerdict::Unverifiable)
//!    ([`KeyDerivation`](UnverifiableReason::KeyDerivation), the payer's);
//! 1. the bytes are a valid BEEF (V1, V2 or Atomic) by the streaming
//!    reader, with the scripts run: the frame, every BUMP's own root, every
//!    unproven transaction's inputs naming earlier transactions and
//!    SPENDING them (the interpreter executes each unlocking script against
//!    the parent output the BEEF carries, and no transaction creates
//!    value), the Atomic subject the tip of its ancestry; else
//!    `Unverifiable` at the soonest fault in stream order
//!    ([`InvalidBeef`](UnverifiableReason::InvalidBeef),
//!    [`SpendRefused`](UnverifiableReason::SpendRefused));
//! 2. the subject (the Atomic BEEF's named transaction, else the last raw
//!    transaction) has output `output_index`, else `Unverifiable`
//!    ([`OutputMissing`](UnverifiableReason::OutputMissing)); the output's
//!    script equals the expected BRC-29 script, else
//!    [`WrongScript`](PaymentVerdict::WrongScript); its satoshis are at
//!    least the price, else [`Underpaid`](PaymentVerdict::Underpaid);
//! 3. the BEEF carries a proof (so every ancestry ends at a proven
//!    transaction: the reader holds every unproven transaction to an input,
//!    a transaction with no input being invalid bytes since bsv-rs 0.4.1,
//!    `InvalidBeef` with the kind `NoInputs`), else `Unverifiable`
//!    ([`NoProof`](UnverifiableReason::NoProof), naming the transaction
//!    whose proof is absent: the payer's side, ruled 2026-10-09; the server
//!    never fetches a missing proof);
//! 4. every merkle root the BUMPs compute, lowest height first, each
//!    distinct root once, is the [`HeaderService`]'s root at that height
//!    (case-insensitive hex): a different root is
//!    [`RootMismatch`](PaymentVerdict::RootMismatch); a lookup that cannot
//!    answer is `Unverifiable`
//!    ([`HeaderLookupFailed`](UnverifiableReason::HeaderLookupFailed) at the
//!    lowest such height: the server's side, fail closed, the quote kept;
//!    a mismatch at any height still wins over an outage at another);
//! 5. [`Verified`](PaymentVerdict::Verified), the amount read from the
//!    output ([`verify_brc29_payment_verified`] also hands back the subject's
//!    txid as the reader hashed it).
//!
//! The roots are asked AFTER the output is judged (no header is asked for a
//! payment the output already refuses), so the reader runs with every root
//! granted (`RootsAskedAfter`) and step 4 is where a root is held to a
//! header: nothing is `Verified` with a root unchecked.
//!
//! [`verify_brc29_payment_structural_only`] is the named opt-out: the
//! reader's structure alone (no script is run), the output, the proof's
//! presence; the roots are NOT asked, and the answer is `Unverifiable`
//! ([`RootsUnchecked`](UnverifiableReason::RootsUnchecked), carrying the
//! amount) so the skip stays visible in the word. That is the one
//! `Unverifiable` a host may serve on, and only because its caller named
//! the opt-out; through [`verify_brc29_payment`] the word is always a
//! refusal.

pub use bsv_sdk::transaction::beef_stream::AsyncByteSource;
use bsv_sdk::transaction::beef_stream::{AsyncStreamVerifier, ChainTip, MiningCheck};
use bsv_sdk::transaction::{ChainTracker, ChainTrackerError};
use std::io::Read;

use bsv_sdk::transaction::beef_stream::{display_hex, Hash32, SpendRefusal, Step};
use bsv_sdk::transaction::{
    verify_stream_structure, BeefDecoder, Element, Headers, Reason, Refusal, Verdict,
};

use crate::brc29::{derive_expected_script, judge_output};
use crate::header_service::HeaderService;
use crate::spv::{check_roots, RootsOutcome};
use crate::verdict::{PaymentFault, PaymentVerdict, UnverifiableReason, VerifiedPayment};

/// The reader's headers while the BEEF streams: every root is granted here
/// and held to the [`HeaderService`] afterwards, lowest height first, once
/// the output is judged. The reader's verdict hands the roots back; none is
/// accepted unasked.
struct RootsAskedAfter;

struct MiningContext(std::sync::Mutex<Option<ChainTip>>);

#[async_trait::async_trait]
impl ChainTracker for MiningContext {
    async fn is_valid_root_for_height(
        &self,
        _root: &str,
        _height: u32,
    ) -> Result<bool, ChainTrackerError> {
        Ok(true)
    }
    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        Err(ChainTrackerError::Other(
            "height alone is not mining context".into(),
        ))
    }
    async fn mining_tip(&self) -> Result<Option<ChainTip>, ChainTrackerError> {
        Ok(*self.0.lock().expect("mining context lock"))
    }
}

/// A borrowed byte slice, read in bounded chunks without copying the whole BEEF.
pub struct SliceSource<'a> {
    bytes: &'a [u8],
}
impl<'a> SliceSource<'a> {
    /// Read this slice as a source.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}
impl AsyncByteSource for SliceSource<'_> {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.bytes.is_empty() {
            return Ok(None);
        }
        let n = self.bytes.len().min(64 * 1024);
        let chunk = self.bytes[..n].to_vec();
        self.bytes = &self.bytes[n..];
        Ok(Some(chunk))
    }
}

impl Headers for RootsAskedAfter {
    fn carries(&self, _height: u64, _root: &Hash32) -> bool {
        true
    }
}

/// Full pre-service payment verification: pays-us-correctly **and**
/// real-and-confirmable, through `service`. See the module docs for the
/// order of checks. `None` is `NoHeaderService` (fail closed); a service
/// that cannot answer for a root is `Unverifiable` (fail closed as well:
/// the host refuses and keeps the quote). `Err` is the host's own fault
/// (its key does not derive); a payer's bytes never produce one.
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment<H: HeaderService + ?Sized>(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
    service: Option<&H>,
    work_limit: Option<u64>,
) -> Result<PaymentVerdict, PaymentFault> {
    Ok(
        match verify_brc29_payment_verified(
            server_key,
            sender_identity_key,
            derivation_prefix,
            derivation_suffix,
            tx_bytes,
            output_index,
            required_satoshis,
            service,
            work_limit,
        )
        .await?
        {
            Ok(VerifiedPayment { satoshis, .. }) => PaymentVerdict::Verified { satoshis },
            Err(word) => word,
        },
    )
}

/// [`verify_brc29_payment`] with the subject's txid beside the amount:
/// `Ok(Ok(verified))` serves (the one `Verified`, with the txid the reader
/// hashed, so a host records and internalizes without parsing the BEEF a
/// second time); `Ok(Err(word))` is a refusal in the core's words (never
/// `Verified`); `Err(fault)` is the host's own fault.
/// `work_limit` bounds each unproven input; `None` imposes no local budget.
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment_verified<H: HeaderService + ?Sized>(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
    service: Option<&H>,
    work_limit: Option<u64>,
) -> Result<Result<VerifiedPayment, PaymentVerdict>, PaymentFault> {
    verify_brc29_payment_stream(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        &mut SliceSource::new(tx_bytes),
        output_index,
        required_satoshis,
        service,
        work_limit,
    )
    .await
}

/// Verify a source with an optional local work bound per unproven input.
/// Source failures are host faults. Missing mining context is server-side,
/// never evidence that a payer's time lock or coinbase spend is invalid.
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment_stream<S: AsyncByteSource, H: HeaderService + ?Sized>(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    source: &mut S,
    output_index: usize,
    required_satoshis: u64,
    service: Option<&H>,
    work_limit: Option<u64>,
) -> Result<Result<VerifiedPayment, PaymentVerdict>, PaymentFault> {
    // 0. No header service, no verdict: refuse before the bytes are read.
    let Some(service) = service else {
        return Ok(Err(PaymentVerdict::NoHeaderService));
    };
    let expected = match derive_expected_script(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
    )? {
        Ok(script) => script,
        Err(reason) => return Ok(Err(PaymentVerdict::Unverifiable { reason })),
    };

    // 1 + 2. One pass over the bytes: the reader's validity (scripts run,
    //        every root granted for now) and the tap's output check.
    let mut tap = Tap::new(&expected, output_index, required_satoshis);
    let context = MiningContext(std::sync::Mutex::new(None));
    let mut reader = AsyncStreamVerifier::new(None);
    reader.set_work_limit(work_limit);
    let verdict = reader
        .run(
            &mut TeeSource {
                source,
                tap: &mut tap,
                service,
                context: &context,
                tip_read: false,
            },
            &context,
        )
        .await
        .map_err(|e| PaymentFault::Source(e.to_string()))?;
    let Settled {
        satoshis,
        txid,
        roots,
    } = match tap.settle(verdict) {
        Ok(settled) => settled,
        Err(word) => return Ok(Err(word)),
    };

    // 4. Each distinct root, lowest height first, held to a header.
    Ok(match check_roots(&roots, service).await {
        RootsOutcome::AllMatched => Ok(VerifiedPayment { satoshis, txid }),
        RootsOutcome::Mismatch { height, root } => {
            Err(PaymentVerdict::RootMismatch { height, root })
        }
        RootsOutcome::Unanswered { height, reason } => Err(PaymentVerdict::Unverifiable {
            reason: UnverifiableReason::HeaderLookupFailed { height, reason },
        }),
    })
}

/// [`verify_brc29_payment`] **without SPV**: the BEEF's structure by the
/// streaming reader (no script is run), the output, and that a proof is
/// present; the merkle roots are NOT checked against block headers.
///
/// **Opt-in, by name, for hosts that have no header service.** A
/// structurally valid BEEF only proves its merkle paths compute *some* root,
/// so a forged parent transaction with a made-up proof passes this function
/// and is caught only by whatever the host's broadcast or internalize step
/// does later. A payment that passes is therefore answered
/// [`Unverifiable`](PaymentVerdict::Unverifiable) with
/// [`RootsUnchecked`](UnverifiableReason::RootsUnchecked) (carrying the
/// amount and how many roots went unasked), never
/// [`Verified`](PaymentVerdict::Verified), so the skip is visible in the
/// word; a host that serves on this answer does so because its caller named
/// this function. Every other answer is the full check's own: invalid bytes,
/// a wrong or short output, a missing proof
/// ([`NoProof`](UnverifiableReason::NoProof): no BUMP at all is no payment
/// here either). `Err` is the host's own fault.
pub fn verify_brc29_payment_structural_only(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
) -> Result<PaymentVerdict, PaymentFault> {
    let expected = match derive_expected_script(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
    )? {
        Ok(script) => script,
        Err(reason) => return Ok(PaymentVerdict::Unverifiable { reason }),
    };
    let mut tap = Tap::new(&expected, output_index, required_satoshis);
    let verdict = verify_stream_structure(
        Tee {
            source: tx_bytes,
            tap: &mut tap,
        },
        RootsAskedAfter,
        None,
    )
    .map_err(|e| PaymentFault::Source(e.to_string()))?;
    Ok(match tap.settle(verdict) {
        Ok(Settled {
            satoshis, roots, ..
        }) => PaymentVerdict::Unverifiable {
            reason: UnverifiableReason::RootsUnchecked {
                satoshis,
                roots: roots.len(),
            },
        },
        Err(word) => word,
    })
}

/// What the reader and the tap settled on before any header is asked: the
/// output pays `satoshis`, the subject is `txid`, and `roots` are the
/// distinct `(height, root)` pairs to hold to headers, lowest height first.
struct Settled {
    satoshis: u64,
    txid: String,
    roots: Vec<(u32, String)>,
}

/// What the door notes of the bytes as they pass to the reader: the
/// subject's output, judged. One element in hand, nothing kept of the
/// others.
struct Tap<'p> {
    expected_script_hex: &'p str,
    output_index: usize,
    required_satoshis: u64,
    decoder: BeefDecoder,
    /// The frame's own fault, where the cutting stopped.
    refusal: Option<Refusal>,
    /// The output check of the subject: the Atomic BEEF's named transaction,
    /// else the last raw transaction read so far.
    paid: Option<Result<u64, PaymentVerdict>>,
    /// The subject whose output `paid` judged.
    subject: Option<Hash32>,
    /// The first unproven transaction with no input: nothing beneath it is
    /// proven. Defense in depth since bsv-rs 0.4.1, whose decoder refuses
    /// such a transaction as invalid bytes (`NoInputs`, at its leading byte)
    /// before this tap could note it; 0.4.0's reader read it as valid with
    /// no root, and this field was the refusal (`NoProof`, naming it).
    unanchored: Option<Hash32>,
    /// A BUMP claims a height no header service can be asked for.
    beyond_headers: Option<Refusal>,
    needs_context: bool,
}

impl<'p> Tap<'p> {
    fn new(expected_script_hex: &'p str, output_index: usize, required_satoshis: u64) -> Self {
        Self {
            expected_script_hex,
            output_index,
            required_satoshis,
            decoder: BeefDecoder::new(),
            refusal: None,
            paid: None,
            subject: None,
            unanchored: None,
            beyond_headers: None,
            needs_context: false,
        }
    }

    /// The next bytes of the source.
    fn feed(&mut self, mut input: &[u8]) {
        if self.refusal.is_some() {
            return;
        }
        loop {
            match self.decoder.next(&mut input) {
                Ok(Step::Element(element)) => self.note(&element),
                Ok(Step::NeedMore | Step::Done) => return,
                Err(refusal) => {
                    self.refusal = Some(refusal);
                    return;
                }
            }
        }
    }

    fn note(&mut self, element: &Element) {
        match element {
            Element::Bump(bump) => {
                if bump.block_height > u64::from(u32::MAX) && self.beyond_headers.is_none() {
                    self.beyond_headers = Some(Refusal {
                        offset: bump.offset,
                        reason: Reason::RootNotCarried {
                            height: bump.block_height,
                            root: bump.root,
                        },
                    });
                }
            }
            Element::Tx {
                txid,
                bump_index,
                body,
                ..
            } => {
                self.needs_context |= bump_index.is_none();
                if bump_index.is_none() && body.inputs.is_empty() && self.unanchored.is_none() {
                    self.unanchored = Some(*txid);
                }
                let subject = match self.decoder.subject() {
                    Some(named) => named == *txid && self.paid.is_none(),
                    None => true,
                };
                if subject {
                    let output = body
                        .outputs
                        .get(self.output_index)
                        .map(|o| (o.satoshis, &body.raw[o.script.clone()]));
                    self.paid = Some(judge_output(
                        self.expected_script_hex,
                        self.output_index,
                        body.outputs.len(),
                        output,
                        self.required_satoshis,
                    ));
                    self.subject = Some(*txid);
                }
            }
            Element::TxidOnly { .. } => {}
        }
    }

    /// Steps 1 to 3 over the reader's verdict: the words that need no
    /// header, or what to hold to headers.
    fn settle(self, verdict: Verdict) -> Result<Settled, PaymentVerdict> {
        let Tap {
            paid,
            subject,
            unanchored,
            beyond_headers,
            ..
        } = self;
        let unverifiable = |reason| PaymentVerdict::Unverifiable { reason };
        let roots = match verdict {
            Verdict::Valid { roots, .. } => roots,
            Verdict::Unverifiable {
                offset,
                txid,
                input,
                check,
            } => {
                let check = match check {
                    MiningCheck::Finality => "Finality",
                    MiningCheck::CoinbaseMaturity => "CoinbaseMaturity",
                };
                return Err(unverifiable(UnverifiableReason::MiningContextUnavailable {
                    offset,
                    txid: display_hex(&txid),
                    input,
                    check: check.into(),
                }));
            }
            Verdict::Invalid {
                offset,
                kind,
                reason,
            } => {
                return Err(unverifiable(UnverifiableReason::InvalidBeef {
                    offset,
                    kind: format!("{kind:?}"),
                    reason: describe_refusal(&Refusal { offset, reason }),
                }))
            }
            Verdict::SpendRefused {
                offset,
                txid,
                input,
                why,
            } => {
                return Err(unverifiable(UnverifiableReason::SpendRefused {
                    offset,
                    txid: display_hex(&txid),
                    input,
                    why: match why {
                        SpendRefusal::Resource(limit) => {
                            let bound = match limit.resource {
                                bsv_sdk::script::ScriptResource::Work => "work",
                                bsv_sdk::script::ScriptResource::Stack
                                | bsv_sdk::script::ScriptResource::AltStack
                                | bsv_sdk::script::ScriptResource::ElementSize => "memory",
                            };
                            format!("script declined under a {bound} resource bound: {limit:?}")
                        }
                        why @ (SpendRefusal::ParentIsTxidOnly
                        | SpendRefusal::OutputNotAvailable { .. }
                        | SpendRefusal::Script(_)
                        | SpendRefusal::CreatesValue
                        | SpendRefusal::InputValueOutOfRange
                        | SpendRefusal::P2shOutput { .. }
                        | SpendRefusal::NonFinal { .. }
                        | SpendRefusal::PrematureCoinbase { .. }) => format!("{why:?}"),
                    },
                }))
            }
        };
        let satoshis = match paid {
            None => return Err(unverifiable(UnverifiableReason::NoTransaction)),
            Some(Err(word)) => return Err(word),
            Some(Ok(satoshis)) => satoshis,
        };
        let txid = display_hex(&subject.expect("a judged output has its subject"));
        if let Some(unanchored) = unanchored {
            return Err(unverifiable(UnverifiableReason::NoProof {
                txid: display_hex(&unanchored),
            }));
        }
        if roots.is_empty() {
            return Err(unverifiable(UnverifiableReason::NoProof { txid }));
        }
        if let Some(refusal) = beyond_headers {
            return Err(unverifiable(invalid(refusal)));
        }
        // Each distinct root once, lowest height first. Two BUMPs that claim
        // one height with two roots are two questions, and one is a mismatch.
        // Every height fits a u32 here: a BUMP beyond that was refused above.
        let mut roots: Vec<(u32, String)> = roots
            .iter()
            .map(|(height, root)| (*height as u32, display_hex(root)))
            .collect();
        roots.sort_unstable();
        roots.dedup();
        Ok(Settled {
            satoshis,
            txid,
            roots,
        })
    }
}

/// The source, with each chunk the reader takes shown to the tap.
struct Tee<'t, 'p, R> {
    source: R,
    tap: &'t mut Tap<'p>,
}

impl<R: Read> Read for Tee<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.source.read(buf)?;
        self.tap.feed(&buf[..n]);
        Ok(n)
    }
}

struct TeeSource<'t, 'p, S, H: ?Sized> {
    source: &'t mut S,
    tap: &'t mut Tap<'p>,
    service: &'t H,
    context: &'t MiningContext,
    tip_read: bool,
}
impl<S: AsyncByteSource, H: HeaderService + ?Sized> AsyncByteSource for TeeSource<'_, '_, S, H> {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let chunk = self.source.next_chunk().await?;
        if let Some(bytes) = &chunk {
            self.tap.feed(bytes);
        }
        // The tap and reader cut the same elements. Acquire context once, only
        // when an unproven transaction is ready to be folded by the reader.
        if self.tap.needs_context && !self.tip_read {
            let tip = self.service.mining_tip().await.unwrap_or(None);
            *self.context.0.lock().expect("mining context lock") = tip;
            self.tip_read = true;
        }
        Ok(chunk)
    }
}

/// The reader's refusal as an [`UnverifiableReason::InvalidBeef`].
fn invalid(refusal: Refusal) -> UnverifiableReason {
    UnverifiableReason::InvalidBeef {
        offset: refusal.offset,
        kind: format!("{:?}", refusal.kind()),
        reason: describe_refusal(&refusal),
    }
}

/// The reader's refusal in words, its hashes in display hex (the reader's
/// own `Display` prints them as byte arrays).
fn describe_refusal(refusal: &Refusal) -> String {
    let data = match &refusal.reason {
        Reason::RootNotCarried { height, root } => {
            format!(
                "RootNotCarried {{ height: {height}, root: {} }}",
                display_hex(root)
            )
        }
        Reason::TxidNotInBump { index, txid } => {
            format!(
                "TxidNotInBump {{ index: {index}, txid: {} }}",
                display_hex(txid)
            )
        }
        Reason::InputNamesNoElement { txid } => {
            format!("InputNamesNoElement {{ txid: {} }}", display_hex(txid))
        }
        Reason::StubNotProven { txid } => {
            format!("StubNotProven {{ txid: {} }}", display_hex(txid))
        }
        Reason::SubjectMissing { subject } => {
            format!("SubjectMissing {{ subject: {} }}", display_hex(subject))
        }
        Reason::UnrelatedTransaction { txid } => {
            format!("UnrelatedTransaction {{ txid: {} }}", display_hex(txid))
        }
        reason @ (Reason::BadVersion { .. }
        | Reason::BadVarint
        | Reason::Truncated { .. }
        | Reason::BadFlag { .. }
        | Reason::TreeHeightOver64 { .. }
        | Reason::TreeHeightZero
        | Reason::OffsetOutsideTree { .. }
        | Reason::NoTxidAtLevelZero
        | Reason::MissingSibling { .. }
        | Reason::MismatchedNode { .. }
        | Reason::BumpIndexNamesNoBump { .. }
        | Reason::TrailingBytes
        | Reason::NoInputs
        | Reason::NoOutputs
        | Reason::UnprovenCoinbase
        | Reason::NullOutpoint
        | Reason::DuplicateInput
        | Reason::ValueOutOfRange) => format!("{reason:?}"),
    };
    format!("invalid BEEF at byte {}: {data}", refusal.offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brc29::test_support::*;
    use crate::header_service::{MerkleRoot, NoService, ServiceError};
    use bsv_sdk::transaction::beef_stream::{InputRef, OutputRef, TxBody};
    use bsv_sdk::transaction::{verify_stream, Beef, Kind, Transaction};
    use std::cell::RefCell;

    /// A header service answering `answer` at every height, recording the
    /// heights asked.
    struct Stub {
        answer: Result<Option<MerkleRoot>, ServiceError>,
        asked: RefCell<Vec<u32>>,
    }

    impl Stub {
        fn answering(answer: Result<Option<MerkleRoot>, ServiceError>) -> Self {
            Self {
                answer,
                asked: RefCell::new(Vec::new()),
            }
        }
        fn root(hex: &str) -> Self {
            Self::answering(Ok(Some(MerkleRoot::new(hex))))
        }
        fn asked(&self) -> Vec<u32> {
            self.asked.borrow().clone()
        }
    }

    impl HeaderService for Stub {
        async fn merkle_root(&self, height: u32) -> Result<Option<MerkleRoot>, ServiceError> {
            self.asked.borrow_mut().push(height);
            self.answer.clone()
        }
    }

    async fn full(beef: &[u8], service: &Stub) -> PaymentVerdict {
        verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            beef,
            0,
            1000,
            Some(service),
            None,
        )
        .await
        .unwrap()
    }

    fn structural(beef: &[u8]) -> PaymentVerdict {
        verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            beef,
            0,
            1000,
        )
        .unwrap()
    }

    fn reason_of(verdict: &PaymentVerdict) -> &UnverifiableReason {
        match verdict {
            PaymentVerdict::Unverifiable { reason } => reason,
            other => panic!("expected Unverifiable, got {other:?}"),
        }
    }

    /// A parent proven at `PROOF_HEIGHT`, locked to `lock`, paying `amount`;
    /// its root (= its txid).
    fn proven_parent(lock: Vec<u8>, amount: u64) -> Transaction {
        spending(&rootless(&[(1, vec![0x52])]), &[(amount, lock)])
    }

    /// `tx` as the decoder hands a raw transaction to the tap, built by
    /// hand (bsv-rs 0.4.1's decoder refuses one with no input before the
    /// tap sees it): the txid in wire order, the one output's `script`
    /// located in the raw bytes (the last field before the lock time). The
    /// tap counts the inputs and reads nothing of them.
    fn element_of(tx: &Transaction, script: &[u8], offset: u64) -> Element {
        let raw = tx.to_binary();
        let mut txid: Hash32 = hex::decode(tx.id()).unwrap().try_into().unwrap();
        txid.reverse();
        let end = raw.len() - 4;
        let located = end - script.len()..end;
        assert_eq!(
            &raw[located.clone()],
            script,
            "the script's place in the raw bytes"
        );
        let inputs = tx
            .inputs
            .iter()
            .map(|_| InputRef {
                at: 0,
                prev: [0u8; 32],
                vout: 0,
                script: 0..0,
                sequence: 0,
            })
            .collect();
        Element::Tx {
            offset,
            txid,
            bump_index: None,
            body: TxBody {
                raw,
                version: 1,
                inputs,
                outputs: vec![OutputRef {
                    at: 0,
                    satoshis: tx.outputs[0].satoshis.unwrap(),
                    script: located,
                }],
                lock_time: 0,
            },
        }
    }

    #[test]
    fn resource_declines_name_the_input_and_are_the_payers_side() {
        use bsv_sdk::script::{ScriptResource, ScriptResourceLimit};
        for resource in [
            ScriptResource::Work,
            ScriptResource::Stack,
            ScriptResource::AltStack,
            ScriptResource::ElementSize,
        ] {
            let limit = ScriptResourceLimit {
                resource,
                limit: 10,
                attempted: 11,
                work_spent: (resource == ScriptResource::Work).then_some(10),
            };
            let verdict = Tap::new("", 0, 0)
                .settle(Verdict::SpendRefused {
                    offset: 42,
                    txid: [7; 32],
                    input: Some(3),
                    why: SpendRefusal::Resource(limit),
                })
                .err()
                .unwrap();
            let reason = reason_of(&verdict);
            assert!(!reason.is_server_side());
            assert!(matches!(
                reason,
                UnverifiableReason::SpendRefused {
                    offset: 42,
                    input: Some(3),
                    ..
                }
            ));
            let text = reason.to_string();
            assert!(
                text.contains("input 3") && text.contains("script declined under a"),
                "{text}"
            );
            assert!(text.contains(&format!("{resource:?}")), "{text}");
            assert!(!text.contains("invalid"), "{text}");
        }
    }

    #[tokio::test]
    async fn lone_leaf_at_nonzero_offset_is_a_named_payer_refusal() {
        use bsv_sdk::transaction::{MerklePath, MerklePathLeaf};
        let parent = proven_parent(vec![0x51], 1000);
        let subject = spending(&parent, &[(1000, our_script_bytes())]);
        let (bytes, root) = beef_of(&[&parent, &subject], true);
        let mut beef = Beef::from_binary(&bytes).unwrap();
        let path = MerklePath {
            block_height: PROOF_HEIGHT,
            path: vec![vec![MerklePathLeaf::new_txid(1, root.clone())]],
        };
        let sdk_reason = path.compute_root(None).unwrap_err().to_string();
        assert!(sdk_reason.contains("0"), "{sdk_reason}");
        assert!(MerklePath::from_binary(&path.to_binary()).is_err());
        beef.bumps[0] = path;
        let headers = Stub::root(&root);
        let verdict = full(&beef.to_binary(), &headers).await;
        let reason = reason_of(&verdict);
        assert!(!reason.is_server_side());
        assert!(matches!(reason, UnverifiableReason::InvalidBeef { .. }));
        let text = reason.to_string();
        assert!(
            text.contains("offset") && text.contains("MissingSibling"),
            "{text}"
        );
        assert!(headers.asked().is_empty());
    }

    // ---- the stack-lean question: are the scripts run? ----

    /// The answer to the stack-lean question of 2026-10-09: an unproven
    /// transaction's inputs ARE executed against the parent outputs the
    /// BEEF carries. The parent is proven and locked to a key; the subject
    /// pays us correctly but offers no signature: `SpendRefused` naming the
    /// subject and its input, and no header is asked. 0.1.0 checked the
    /// structure alone (`Beef::verify_valid`) and answered `Verified` here.
    #[tokio::test]
    async fn an_unsigned_spend_of_a_proven_parent_is_spend_refused_and_asks_no_header() {
        let parent = proven_parent(p2pkh(&[7u8; 20]), 1000);
        let subject = spending(&parent, &[(1000, our_script_bytes())]);
        let (beef, root) = beef_of(&[&parent, &subject], true);
        let headers = Stub::root(&root);
        let verdict = full(&beef, &headers).await;
        match reason_of(&verdict) {
            UnverifiableReason::SpendRefused {
                txid, input, why, ..
            } => {
                assert_eq!(*txid, subject.id());
                assert_eq!(*input, Some(0));
                assert!(why.starts_with("Script("), "{why}");
                assert!(!reason_of(&verdict).is_server_side());
            }
            other => panic!("expected SpendRefused, got {other:?}"),
        }
        assert!(
            headers.asked().is_empty(),
            "no header asked for a refused spend"
        );
        let shown = verdict.to_string();
        assert!(
            shown.contains(&subject.id()) && shown.contains("input 0"),
            "{shown}"
        );
        // The structure alone (the named opt-out) does not run the script
        // and reads the output: that is why it is opt-in by name.
        assert!(
            matches!(
                reason_of(&structural(&beef)),
                UnverifiableReason::RootsUnchecked {
                    satoshis: 1000,
                    roots: 1
                }
            ),
            "{:?}",
            structural(&beef)
        );
    }

    /// The same chain, spendable: the parent is locked to `OP_TRUE`, the
    /// subject's empty unlock satisfies it, the root is the header's. The
    /// honest proven payment of an unproven subject under a proven parent is
    /// `Verified`, and the service is asked once, at the proof's height.
    #[tokio::test]
    async fn an_unproven_subject_under_a_proven_parent_is_verified_when_it_spends() {
        let parent = proven_parent(OP_TRUE.to_vec(), 1000);
        let subject = spending(&parent, &[(1000, our_script_bytes())]);
        let (beef, root) = beef_of(&[&parent, &subject], true);
        let headers = Stub::root(&root);
        assert_eq!(
            full(&beef, &headers).await,
            PaymentVerdict::Verified { satoshis: 1000 }
        );
        assert_eq!(headers.asked(), vec![PROOF_HEIGHT]);
        let verified = verify_brc29_payment_verified(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            Some(&headers),
            None,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            verified,
            VerifiedPayment {
                satoshis: 1000,
                txid: subject.id()
            },
            "the subject's txid as the reader hashed it"
        );
    }

    /// A transaction that creates value is refused by the reader's value
    /// rule: `SpendRefused` with no input named.
    #[tokio::test]
    async fn a_transaction_that_creates_value_is_spend_refused() {
        let parent = proven_parent(OP_TRUE.to_vec(), 999);
        let subject = spending(&parent, &[(1000, our_script_bytes())]);
        let (beef, root) = beef_of(&[&parent, &subject], true);
        let verdict = full(&beef, &Stub::root(&root)).await;
        assert!(
            matches!(
                reason_of(&verdict),
                UnverifiableReason::SpendRefused {
                    input: None,
                    why,
                    ..
                } if why == "CreatesValue"
            ),
            "{verdict:?}"
        );
    }

    // ---- the no-root class (ruled 2026-10-09): the payer's side ----

    /// What the reader itself says of an unproven transaction with no
    /// input: invalid bytes at the transaction's leading byte,
    /// `Kind::NoInputs` (bsv-rs 0.4.1, bsv-stack-lean #58; the rule is the
    /// node's). Red at 0.4.0, whose reader read it as `Valid` with no root
    /// and left the refusal to the core's `NoProof`: the witness of the
    /// bump. The leading byte is at 7: the version (4), the BUMP count (1),
    /// the transaction count (1), the transaction's has-BUMP byte (1).
    #[test]
    fn what_the_reader_says_of_a_no_input_unproven_transaction() {
        let (alone, _) = beef_of(&[&rootless(&[(1000, OP_TRUE.to_vec())])], false);
        let verdict = verify_stream(&alone[..], RootsAskedAfter, None).unwrap();
        assert_eq!(
            verdict,
            Verdict::Invalid {
                offset: 7,
                kind: Kind::NoInputs,
                reason: Reason::NoInputs
            },
            "bsv-rs 0.4.1: a transaction with no input is invalid bytes"
        );
    }

    /// An unproven transaction with no input is invalid bytes to the reader
    /// (bsv-rs 0.4.1): alone or under a paying subject, the payment is
    /// `Unverifiable` with `InvalidBeef { kind: "NoInputs" }` at the
    /// transaction's leading byte, the offset in the words, the payer's
    /// side, and no header is asked. 0.4.0's reader read the bytes as valid
    /// with no root and the core's own `NoProof` refused them; that rule
    /// stays beneath the reader's
    /// (`the_doors_no_proof_stands_beneath_the_reader`).
    #[tokio::test]
    async fn a_transaction_with_no_input_and_no_proof_anchors_nothing() {
        let parent = rootless(&[(1000, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(1000, our_script_bytes())]);
        let (alone, _) = beef_of(&[&rootless(&[(1000, our_script_bytes())])], false);
        let (under, _) = beef_of(&[&parent, &subject], false);

        let headers = Stub::root("00".repeat(32).as_str());
        for (shape, beef) in [("alone", &alone), ("under a subject", &under)] {
            let verdict = full(beef, &headers).await;
            assert_eq!(
                *reason_of(&verdict),
                UnverifiableReason::InvalidBeef {
                    offset: 7,
                    kind: "NoInputs".into(),
                    reason: "invalid BEEF at byte 7: NoInputs".into()
                },
                "{shape}: the transaction with no input, at its leading byte"
            );
            assert!(!reason_of(&verdict).is_server_side(), "the payer's side");
            let shown = verdict.to_string();
            assert!(
                shown.contains("offset 7") && shown.contains("NoInputs"),
                "{shown}"
            );
        }
        assert!(headers.asked().is_empty());

        // The named opt-out reads the same bytes: invalid, even by name.
        assert!(matches!(
            reason_of(&structural(&under)),
            UnverifiableReason::InvalidBeef { offset: 7, kind, .. } if kind == "NoInputs"
        ));
    }

    /// The witness of bsv-stack-lean #58 (the captain ran it on 0.4.0 and
    /// 0.4.1, 2026-10-09): a parent with no input beside a proven stranger
    /// whose BUMP is the only proof in the BEEF, the subject paying us out
    /// of that parent, the stranger's root the header's. Refused, never
    /// `Verified`, the payer's side, and the stranger's root is never asked
    /// of the header service. On 0.4.0 the core's tap refused it as
    /// `NoProof` naming the parent; on 0.4.1 the reader refuses it as
    /// `NoInputs` at the parent's leading byte, which is what this asserts.
    #[tokio::test]
    async fn witness_no_input_parent_beside_a_proven_stranger_is_refused() {
        let stranger = spending(&rootless(&[(1, vec![0x52])]), &[(1, vec![0x51])]);
        let parent = rootless(&[(1000, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(1000, our_script_bytes())]);
        let (beef, root) = beef_of(&[&stranger, &parent, &subject], true);
        let headers = Stub::root(&root);
        let verdict = full(&beef, &headers).await;
        println!("witness (core): {verdict}");
        assert_ne!(verdict, PaymentVerdict::Verified { satoshis: 1000 });
        assert!(
            matches!(reason_of(&verdict), UnverifiableReason::InvalidBeef { kind, .. } if kind == "NoInputs"),
            "{verdict:?}"
        );
        assert!(!reason_of(&verdict).is_server_side(), "the payer's side");
        assert!(
            headers.asked().is_empty(),
            "the stranger's root is never asked"
        );
        // The same bytes through the named opt-out: refused the same way.
        assert!(matches!(
            reason_of(&structural(&beef)),
            UnverifiableReason::InvalidBeef { kind, .. } if kind == "NoInputs"
        ));
    }

    /// The door's own rule, beneath the reader's. Were the reader to read a
    /// transaction with no input as valid with no root (bsv-rs 0.4.0's
    /// word), the tap refuses the payment `NoProof` naming that
    /// transaction; and a valid reading of a BEEF with no BUMP is `NoProof`
    /// naming the subject. Unreachable through bsv-rs 0.4.1's reader, which
    /// refuses the first shape as `NoInputs` (its decoder, before the tap
    /// sees the element) and the second as `InputNamesNoElement` or
    /// `StubNotProven` (every ancestry ends at a proven transaction or a
    /// proven txid-only entry, so a valid BEEF that pays carries a BUMP):
    /// kept as defense in depth and exercised here on the tap, the reader's
    /// word supplied.
    #[test]
    fn the_doors_no_proof_stands_beneath_the_reader() {
        let expected = our_script();
        let valid_no_root = || Verdict::Valid {
            subject: None,
            roots: vec![],
        };
        let refused = |settled: Result<Settled, PaymentVerdict>| settled.err().expect("refused");

        // A parent with no input under the subject, the elements built by
        // hand: the parent is named.
        let parent = rootless(&[(1000, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(1000, our_script_bytes())]);
        let mut tap = Tap::new(&expected, 0, 1000);
        tap.note(&element_of(&parent, OP_TRUE, 7));
        tap.note(&element_of(&subject, &our_script_bytes(), 40));
        assert_eq!(
            refused(tap.settle(valid_no_root())),
            PaymentVerdict::Unverifiable {
                reason: UnverifiableReason::NoProof { txid: parent.id() }
            }
        );

        // No BUMP at all, every transaction with an input, the bytes fed
        // through the tee as the reader's source: the subject is named.
        let parent = spending(&rootless(&[(1, vec![0x52])]), &[(1000, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(1000, our_script_bytes())]);
        let (no_bump, _) = beef_of(&[&parent, &subject], false);
        let mut tap = Tap::new(&expected, 0, 1000);
        let mut tee = Tee {
            source: &no_bump[..],
            tap: &mut tap,
        };
        std::io::copy(&mut tee, &mut std::io::sink()).unwrap();
        assert_eq!(
            refused(tap.settle(valid_no_root())),
            PaymentVerdict::Unverifiable {
                reason: UnverifiableReason::NoProof { txid: subject.id() }
            }
        );
        // The reader's own word for those bytes: the parent's input names a
        // transaction the BEEF does not carry.
        assert!(matches!(
            verify_stream(&no_bump[..], RootsAskedAfter, None).unwrap(),
            Verdict::Invalid {
                kind: Kind::InputNamesNoElement,
                ..
            }
        ));
    }

    /// The owned vector shapes of 2026-10-09. `spv-incomplete-beef`: the
    /// subject alone, its input naming a parent the BEEF does not carry.
    /// `spv-no-root`: the subject and its parent, neither proven, the
    /// parent's input naming a transaction the BEEF does not carry. The
    /// reader refuses both as invalid bytes (`InputNamesNoElement`), naming
    /// the transaction that is absent; the payer's side, no header asked.
    #[tokio::test]
    async fn the_no_root_vector_shapes_are_payer_side_and_name_the_absent_transaction() {
        let headers = Stub::root("00".repeat(32).as_str());
        // spv-incomplete-beef: `payment_tx` spends 11..11, which is not carried.
        let incomplete = beef_with_unproven_payment(&our_script(), 1000);
        let verdict = full(&incomplete, &headers).await;
        match reason_of(&verdict) {
            UnverifiableReason::InvalidBeef {
                offset,
                kind,
                reason,
            } => {
                assert_eq!(kind, "InputNamesNoElement");
                assert_eq!(
                    *offset, 12,
                    "the input's previous txid: 4 + 1 + 1 + 1 + 4 + 1"
                );
                assert!(reason.contains(&"11".repeat(32)), "{reason}");
            }
            other => panic!("expected InvalidBeef, got {other:?}"),
        }
        assert!(!reason_of(&verdict).is_server_side());
        assert!(verdict.to_string().contains(&"11".repeat(32)), "{verdict}");

        // spv-no-root: parent (spends 11..11) + subject (spends parent:0).
        let parent = payment_tx(&hex::encode(OP_TRUE), 1000);
        let subject = spending(&parent, &[(1000, our_script_bytes())]);
        let (no_root, _) = beef_of(&[&parent, &subject], false);
        let verdict = full(&no_root, &headers).await;
        assert!(
            matches!(
                reason_of(&verdict),
                UnverifiableReason::InvalidBeef { kind, reason, .. }
                    if kind == "InputNamesNoElement" && reason.contains(&"11".repeat(32))
            ),
            "{verdict:?}"
        );
        assert!(headers.asked().is_empty());
    }

    // ---- the service and the roots ----

    /// `verify_brc29_payment` with no service is `NoHeaderService` for a
    /// payment that would otherwise pass: never `Verified`, never a skipped
    /// root check. The gate runs before the bytes are read, so garbage
    /// bytes under a missing service are also `NoHeaderService` (the 0.3.x
    /// regression stays refused).
    #[tokio::test]
    async fn no_header_service_is_refused_before_the_bytes_are_read() {
        let (beef, _) = beef_with_proven_payment(&our_script(), 1000);
        for bytes in [&beef[..], &[0u8; 16][..], &b"garbage"[..]] {
            let verdict = verify_brc29_payment(
                SERVER_KEY,
                &sender_identity(),
                "prefix",
                "suffix",
                bytes,
                0,
                1000,
                None::<&NoService>,
                None,
            )
            .await
            .unwrap();
            assert_eq!(verdict, PaymentVerdict::NoHeaderService);
        }
        // `Some(&NoService)` by mistake: every lookup errors, so the root
        // goes unchecked and the verdict is a server-side `Unverifiable`,
        // never `Verified`.
        let verdict = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            Some(&NoService),
            None,
        )
        .await
        .unwrap();
        assert!(verdict.is_server_side_unverifiable(), "{verdict:?}");
    }

    /// End to end on a correct, proven payment (T1: an honest BEEF parses)
    /// with the header service stubbed: asked exactly once, at the proof's
    /// height; a matching header in either case is `Verified`, a different
    /// one is `RootMismatch` naming the height and root, and a service that
    /// cannot answer is `HeaderLookupFailed` at that height with the
    /// service's words: the server's side.
    #[tokio::test]
    async fn spv_outcomes_table() {
        let (beef, txid) = beef_with_proven_payment(&our_script(), 1000);

        let headers = Stub::root(&txid);
        assert_eq!(
            full(&beef, &headers).await,
            PaymentVerdict::Verified { satoshis: 1000 }
        );
        assert_eq!(headers.asked(), vec![PROOF_HEIGHT]);

        assert_eq!(
            full(&beef, &Stub::root(&txid.to_ascii_uppercase())).await,
            PaymentVerdict::Verified { satoshis: 1000 },
            "root compare is case-insensitive"
        );

        let headers = Stub::root("00".repeat(32).as_str());
        assert_eq!(
            full(&beef, &headers).await,
            PaymentVerdict::RootMismatch {
                height: PROOF_HEIGHT,
                root: txid.clone()
            }
        );
        assert_eq!(headers.asked(), vec![PROOF_HEIGHT]);

        let headers = Stub::answering(Err(ServiceError::new("fetch height: timeout")));
        let verdict = full(&beef, &headers).await;
        assert_eq!(
            verdict,
            PaymentVerdict::Unverifiable {
                reason: UnverifiableReason::HeaderLookupFailed {
                    height: PROOF_HEIGHT,
                    reason: "fetch height: timeout".into()
                }
            }
        );
        assert!(verdict.is_server_side_unverifiable());
        assert_eq!(headers.asked(), vec![PROOF_HEIGHT]);

        let verdict = full(&beef, &Stub::answering(Ok(None))).await;
        assert!(
            matches!(
                reason_of(&verdict),
                UnverifiableReason::HeaderLookupFailed {
                    height: PROOF_HEIGHT,
                    ..
                }
            ),
            "a height the service has not indexed is unanswered: {verdict:?}"
        );
    }

    /// A refusal of the output is answered before any header is asked, and
    /// the BEEF's own fault before the output is judged.
    #[tokio::test]
    async fn the_output_is_judged_before_any_lookup_and_the_bytes_before_the_output() {
        let (underpaid, root) = beef_with_proven_payment(&our_script(), 999);
        let headers = Stub::root(&root);
        assert_eq!(
            full(&underpaid, &headers).await,
            PaymentVerdict::Underpaid {
                paid: 999,
                required: 1000
            }
        );
        assert!(headers.asked().is_empty());

        let other = crate::brc29::expected_locking_script(
            SERVER_KEY,
            &sender_identity(),
            "stale",
            "suffix",
        )
        .unwrap();
        let (wrong, root) = beef_with_proven_payment(&other, 5000);
        let headers = Stub::root(&root);
        assert!(matches!(
            full(&wrong, &headers).await,
            PaymentVerdict::WrongScript { .. }
        ));
        assert!(headers.asked().is_empty());

        // The subject pays the wrong script AND names a parent the BEEF does
        // not carry: the reading stops at the invalid bytes.
        let orphan = spending(&rootless(&[(1, vec![0x52])]), &[(1000, vec![0x53])]);
        let (beef, _) = beef_of(&[&orphan], false);
        assert!(matches!(
            reason_of(&full(&beef, &headers).await),
            UnverifiableReason::InvalidBeef { kind, .. } if kind == "InputNamesNoElement"
        ));

        // Garbage leads with no BEEF version word.
        let verdict = full(&[0u8; 16], &headers).await;
        assert!(
            matches!(
                reason_of(&verdict),
                UnverifiableReason::InvalidBeef { offset: 0, kind, .. } if kind == "BadVersion"
            ),
            "{verdict:?}"
        );
        // A raw transaction is no BEEF either.
        let raw = payment_tx(&our_script(), 1000).to_binary();
        assert!(matches!(
            reason_of(&full(&raw, &headers).await),
            UnverifiableReason::InvalidBeef { offset: 0, kind, .. } if kind == "BadVersion"
        ));
        assert!(headers.asked().is_empty());
    }

    /// A BEEF with no transaction pays nothing; a subject without the named
    /// output is `OutputMissing`.
    #[tokio::test]
    async fn no_transaction_and_no_output_are_the_payers_side() {
        let headers = Stub::root("00".repeat(32).as_str());
        let empty = Beef::new().to_binary();
        assert_eq!(
            *reason_of(&full(&empty, &headers).await),
            UnverifiableReason::NoTransaction
        );
        let (beef, root) = beef_with_proven_payment(&our_script(), 1000);
        let verdict = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            2,
            1000,
            Some(&Stub::root(&root)),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            *reason_of(&verdict),
            UnverifiableReason::OutputMissing {
                output_index: 2,
                output_count: 1
            }
        );
    }

    /// The sender's key not deriving is the payer's; the server's is the
    /// host's own fault, before the bytes are read.
    #[tokio::test]
    async fn key_derivation_sides() {
        let (beef, root) = beef_with_proven_payment(&our_script(), 1000);
        let headers = Stub::root(&root);
        let verdict = verify_brc29_payment(
            SERVER_KEY,
            "not-a-key",
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            Some(&headers),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            reason_of(&verdict),
            UnverifiableReason::KeyDerivation(_)
        ));
        let fault = verify_brc29_payment(
            "zz",
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            Some(&headers),
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(fault, PaymentFault::KeyDerivation(_)), "{fault}");
        assert!(headers.asked().is_empty());
    }

    /// A BUMP at a height no header service can be asked for is the
    /// reader's own `RootNotCarried`, never asked at the height's low bits.
    #[tokio::test]
    async fn a_height_beyond_u32_is_a_root_not_carried() {
        let tx = payment_tx(&our_script(), 1000);
        let raw = tx.to_binary();
        let txid = bsv_sdk::primitives::sha256d(&raw);
        let height = u64::from(u32::MAX) + 1 + u64::from(PROOF_HEIGHT);
        let mut v = bsv_sdk::transaction::BEEF_V2.to_le_bytes().to_vec();
        v.push(1);
        v.push(0xFF);
        v.extend_from_slice(&height.to_le_bytes());
        v.extend_from_slice(&[1, 1, 0, 2]);
        v.extend_from_slice(&txid);
        v.extend_from_slice(&[1, 1, 0]);
        v.extend_from_slice(&raw);
        let headers = Stub::root(&tx.id());
        let verdict = full(&v, &headers).await;
        assert!(
            matches!(
                reason_of(&verdict),
                UnverifiableReason::InvalidBeef { offset: 5, kind, reason }
                    if *kind == format!("{:?}", Kind::RootNotCarried) && reason.contains(&height.to_string())
            ),
            "{verdict:?}"
        );
        assert!(headers.asked().is_empty());
    }

    /// The named opt-out keeps every offline check (the structure, the
    /// output, the proof's presence) and answers a proof with roots
    /// `RootsUnchecked`, by name, carrying the amount.
    #[test]
    fn structural_only_keeps_offline_checks_and_names_the_skip() {
        let (proven, _) = beef_with_proven_payment(&our_script(), 1000);
        assert_eq!(
            *reason_of(&structural(&proven)),
            UnverifiableReason::RootsUnchecked {
                satoshis: 1000,
                roots: 1
            }
        );
        let shown = structural(&proven).to_string();
        assert!(
            shown.contains("structural-only") && shown.contains("1 merkle root"),
            "{shown}"
        );

        let unproven = beef_with_unproven_payment(&our_script(), 1000);
        assert!(matches!(
            reason_of(&structural(&unproven)),
            UnverifiableReason::InvalidBeef { kind, .. } if kind == "InputNamesNoElement"
        ));

        let (underpaid, _) = beef_with_proven_payment(&our_script(), 999);
        assert!(matches!(
            structural(&underpaid),
            PaymentVerdict::Underpaid { .. }
        ));

        assert!(matches!(
            reason_of(&structural(&[0u8; 16])),
            UnverifiableReason::InvalidBeef { kind, .. } if kind == "BadVersion"
        ));
    }

    /// A deep honest chain: one proven parent and a few thousand unproven
    /// links, each spending the one before with its empty unlock against
    /// `OP_TRUE`, the last paying us. The reader runs every script and
    /// answers `Verified`; nothing is refused for the count (T1, "a BEEF
    /// of any size").
    #[tokio::test]
    async fn a_deep_honest_chain_is_verified_whole() {
        const LINKS: usize = 3_000;
        let mut txs: Vec<Transaction> = Vec::with_capacity(LINKS + 1);
        txs.push(proven_parent(OP_TRUE.to_vec(), 1000));
        for i in 0..LINKS {
            let lock = if i + 1 == LINKS {
                our_script_bytes()
            } else {
                OP_TRUE.to_vec()
            };
            let next = spending(&txs[i], &[(1000, lock)]);
            txs.push(next);
        }
        let refs: Vec<&Transaction> = txs.iter().collect();
        let (beef, root) = beef_of(&refs, true);
        let headers = Stub::root(&root);
        let verified = verify_brc29_payment_verified(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            Some(&headers),
            None,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(verified.satoshis, 1000);
        assert_eq!(verified.txid, txs[LINKS].id());
        assert_eq!(headers.asked(), vec![PROOF_HEIGHT]);
    }

    /// Two BUMPs at one height with two roots are two questions: the one
    /// the header does not carry is a mismatch, whichever is asked first.
    #[tokio::test]
    async fn two_roots_at_one_height_are_two_questions() {
        let (honest, honest_root) = beef_with_proven_payment(&our_script(), 1000);
        let mut beef = Beef::from_binary(&honest).unwrap();
        let forged = payment_tx(&hex::encode([0x53]), 5);
        beef.merge_bump(
            bsv_sdk::transaction::MerklePath::new(
                PROOF_HEIGHT,
                vec![vec![bsv_sdk::transaction::MerklePathLeaf::new_txid(
                    0,
                    forged.id(),
                )]],
            )
            .unwrap(),
        );
        // The forged stranger proven by its own BUMP, then the honest payment
        // last so it stays the subject.
        let subject = Transaction::from_beef(&honest, None).unwrap();
        let mut rebuilt = Beef::new();
        for bump in beef.bumps.clone() {
            rebuilt.merge_bump(bump);
        }
        rebuilt.merge_raw_tx(forged.to_binary(), Some(1));
        rebuilt.merge_raw_tx(subject.to_binary(), Some(0));
        let bytes = rebuilt.to_binary();
        let headers = Stub::root(&honest_root);
        let verdict = full(&bytes, &headers).await;
        assert_eq!(
            verdict,
            PaymentVerdict::RootMismatch {
                height: PROOF_HEIGHT,
                root: forged.id()
            },
            "the forged root at the honest height is held to the header"
        );
    }
}
