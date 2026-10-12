//! # bsv-middleware-core
//!
//! The runtime-free rules of BSV BRC-103/104 authentication and BRC-29
//! payment verification: what a server must compute and decide, with no
//! transport, no store, no clock and no network of its own. A host crate
//! (such as `bsv-middleware-cloudflare` for Workers) adapts these rules to
//! its runtime: it reads headers into these types, implements the traits
//! over its storage and its header service, and renders the words as HTTP.
//!
//! ## What is here
//!
//! - [`verdict`]: the six words a payment check answers with, as ONE enum
//!   ([`PaymentVerdict`]): `Verified`, `Underpaid`, `WrongScript`,
//!   `NoHeaderService`, `RootMismatch`, `Unverifiable`. Never a boolean.
//!   `Unverifiable` carries an [`UnverifiableReason`] that says whose side
//!   it is on (`is_server_side`); [`PaymentFault`] is the host's own fault
//!   alone. [`VerifiedPayment`] is the amount and the subject's txid.
//! - [`header_service`]: SPV's one seam, the [`HeaderService`] trait. No
//!   URL type lives here; `None` fails closed.
//! - [`brc29`]: BRC-29 derivation and the pays-us-correctly check
//!   ([`expected_locking_script`], [`verify_payment_output`]).
//! - [`spv`]: the per-root decision and the loop over a proof's roots.
//! - [`payment_verify`]: [`verify_brc29_payment`] (the full check through a
//!   service: the payment read ONCE through the streaming reader of bsv-rs
//!   0.4.0 with the scripts run, then the output, then each root asked),
//!   [`verify_brc29_payment_verified`] (the same, with the subject's txid)
//!   and [`verify_brc29_payment_structural_only`] (the named opt-out).
//! - [`store`]: the single-use stores as traits ([`PaymentNonceStore`],
//!   [`ClaimStore`]) and an in-memory implementation.
//! - [`brc104`]: BRC-104 header names, the signed request and response
//!   payloads, the header pairs a message is sent as.
//! - [`auth`]: BRC-103 message build and verify over a [`SessionBinding`]:
//!   sign, verify against the session's identity, the handshake's
//!   `InitialResponse`, the signed general message that carries a response.
//! - [`session_lane`]: the MAC'd session lane (one handshake, then no wallet
//!   calls per request), pure.
//! - `refund` (feature `refund`): the refund key derivation and the
//!   `createAction` template signer.
//! - [`types`]: the context a host attaches to a request.
//!
//! ## What is not here, by design
//!
//! No HTTP request type, no fetch, no KV, no Durable Object, no SQL, no
//! clock read, no logging. Every function takes what it needs as data and
//! answers with data; the host owns every side effect and renders the words
//! as HTTP. One rendering is fixed by rule, not by host policy: only
//! [`PaymentVerdict::Verified`] serves, and [`PaymentVerdict::Unverifiable`]
//! is a refusal (fail closed, 2026-10-08): a server-side reason (a header
//! the service could not answer for) is a 5xx with the quote kept, a
//! payer-side reason (invalid bytes, a refused spend, no proof) is a 4xx
//! (the no-root ruling of 2026-10-09).
//!
//! ## A BEEF of any size
//!
//! No count or size bound lives here (the posture of
//! 2026-10-09): a valid payment of any size is read, one element at a time,
//! and a refusal is for invalid bytes only, named by offset and kind.
//!
//! ## Conformance
//!
//! `tests/conformance_brc29.rs` runs the implementation-neutral BRC-29
//! payment vectors (this crate's `conformance/brc29-payment-vectors.json`,
//! a copy of the file the stack review repository owns, 22 cases, pinned
//! byte-identical to the repository root's copy by the Workers adapter)
//! through [`verify_brc29_payment`] with a stub service.

pub mod auth;
pub mod brc104;
pub mod brc29;
pub mod header_service;
pub mod payment_verify;
#[cfg(feature = "refund")]
pub mod refund;
pub mod session_lane;
pub mod spv;
pub mod store;
pub mod types;
pub mod verdict;

pub use auth::{AuthError, SessionBinding};
pub use brc104::{auth_headers, HttpRequestData, HttpResponseData};
pub use brc29::{expected_locking_script, verify_payment_output, BRC29_PROTOCOL_ID};
pub use header_service::{ChainTip, HeaderService, LookupFn, MerkleRoot, NoService, ServiceError};
pub use payment_verify::{
    verify_brc29_payment, verify_brc29_payment_stream, verify_brc29_payment_structural_only,
    verify_brc29_payment_verified, AsyncByteSource, SliceSource,
};
pub use spv::{check_roots, decide_root, RootDecision, RootsOutcome};
pub use store::{ClaimStore, MemoryStore, PaymentNonceStore, StoreError, PAYMENT_NONCE_SCOPE};
pub use types::{AuthContext, BsvPayment, PaymentContext};
pub use verdict::{PaymentFault, PaymentVerdict, UnverifiableReason, VerifiedPayment};
