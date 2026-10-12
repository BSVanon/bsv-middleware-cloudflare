# Changelog

All notable changes to `bsv-middleware-core`. Versions below 1.0 may change public API between minor versions;
patch versions are additive unless a line below says otherwise.

## 0.3.0 - 2026-10-12

The SDK floor in both crates is `bsv-rs = "0.5.0"` (caret). Core 0.3.0's
primary check is `verify_brc29_payment_stream` over `AsyncByteSource`, with
`work_limit: Option<u64>`; the two existing full slice functions are wrappers
and now require the trailing work limit. The structural-only opt-out is unchanged.
Adapter 0.6.0 preserves its six existing verify signatures with budget `None`,
and adds `verify_brc29_payment_budgeted`, `verify_brc29_payment_source`,
`payment_work_limit`, `split_multipart_payment`, `MultipartPayment` and `PaymentPart`.

The authenticated body stays in one owned buffer. BRC-104 hashes the exact
signed frame incrementally via `verify_message_digest`; multipart payment JSON
borrows the base64 span and decodes 3 KB chunks. The helper's threshold is
8,192 bytes of payment JSON, replacing the design's approximate 16 KB.
`prepare_multipart_payment` is retained and deprecated. Signed refusals keep
their existing wire shape.

`PAYMENT_WORK_LIMIT` is optional, default none. Absent or blank preserves the
unbounded path; a positive decimal u64 sets the budget per unproven input.
An input exceeding it is payer-side `SpendRefused`, 400 `ERR_PAYMENT_INVALID`,
with the quote kept. `0` and non-numbers are `BadWorkLimit { value }`, the
host's own 500 `ERR_SERVER_MISCONFIGURED`. The fleet selects 1,000,000 units;
the one-input P2PKH witness verifies at 490 and declines at 489. This is a
per-input bound; the Worker's CPU cap is the total request bound, with no
new request clock (Paid default 30 seconds).

The new SDK byte kinds (`UnprovenCoinbase`, `NullOutpoint`, `DuplicateInput`,
`ValueOutOfRange`) map to payer-side `InvalidBeef`. `InputValueOutOfRange`,
`P2shOutput`, `NonFinal` and `PrematureCoinbase` map to payer-side
`SpendRefused`. Missing `Finality` or `CoinbaseMaturity` evidence maps to
server-side `MiningContextUnavailable`: the host failed to supply a tip,
so it cannot claim the payer's transaction is invalid. Implement
`HeaderService::mining_tip` for contextual verdicts. `UrlHeaderService` queries
ChainTracks' `/findChainTipHeaderHex`, resolves the network through `/getChain`,
and follows up to ten parent headers by hash for median time past. It supports
mainnet and testnet; custom networks and pre-CSV candidate block time require
an explicit host service. SDK consumers extend exhaustive `Kind`, `Reason`,
`SpendRefusal`, `Stop`, `Verdict` matches and add `OutputRef.at` to literals.

Migration by host:

- Agents' 13 Workers: re-pin adapter 0.6.0/core 0.3.0 on bsv-rs 0.5.0.
  Paying doors read the var once, use the budgeted/source verifier, set
  `PAYMENT_WORK_LIMIT = "1000000"`, map `BadWorkLimit` to their signed 500,
  and switch multipart extraction to `split_multipart_payment`. The viewer
  has no payment door. Locks and manifests land in the fleet's separate wave.
- LOW's tower: re-pin core 0.3.0, add the trailing `None` or chosen budget
  to direct core calls, and supply `HeaderService::mining_tip`.
- The relay's door: re-pin adapter 0.6.0, extend the exhaustive error match
  with `BadWorkLimit` as signed 500; optionally select a budget and source API.
- Zanaadu's door: re-pin adapter 0.6.0, extend the exhaustive error match
  with `BadWorkLimit` as signed 500; optionally select a budget and source API.
- wallet-infra: update its exact adapter pin to 0.6.0, extend the error match
  with the host's 500 arm, and select a budget by its own honest ceiling.
- The template: re-pin adapter 0.6.0, use the budgeted/source verifier,
  add the `BadWorkLimit` 500 arm and `PAYMENT_WORK_LIMIT = "1000000"` example.

The 22 owned payment vectors remain byte-identical. Crate witnesses cover the
work decline, honest boundary, default unbounded control, multipart helper
shape, mining refusals and chunk independence. No vector was added to the owned file.


Native size witness: the 64,004,742-byte body verifies, but the core's
incremental peak is 7,109,677 bytes. The SDK reader alone uses 7,013,135 bytes.
The design's below-4-MB target is therefore not met on bsv-rs 0.5.0. The
ignored `stream_memory` test retains that assertion so the missed gate stays
visible; it requires a dependency change or an owner-approved revised bound.
No Cloudflare 30 MB multipart memory/control run has been made in this crate lane.


## 0.2.2 - 2026-10-12

The floor is `bsv-rs = "0.4.5"` (caret); no API change in either crate.
For every host that re-pins, including LOW's tower, the relay's door, Zanaadu's door and wallet-infra:
a payer whose script declines under a work or memory bound is answered as payer-side
`Unverifiable` with `SpendRefused`, naming the decline and input. In the adapter this is
400 `ERR_PAYMENT_INVALID` by name, never a server-side reason or 500. The crates set no
bound themselves: `work_limit` stays `None`, with no size or count limit.

The SDK's `MerklePath` now refuses a lone hashed leaf at a nonzero offset (`MissingSibling`).
The payment reader preserves this as a payer-side `InvalidBeef` refusal naming the offset;
the payer must obtain a valid proof, without rewriting its offset.

Hosts using SDK literals directly must add `work_limit: None` to `SpendParams` and
`TxSpendParams`, and `work_spent: None` to memory `ScriptResourceLimit` literals. Resource
byte fields are `u64`. Handle `ScriptResource::Work` and `SpendRefusal::Resource` as local
declines before interpreting validity. These crates had no such literals to migrate.
Choosing a payment-path work budget remains the owner's decision.

## 0.2.1 - 2026-10-10

bsv-rs 0.4.1 is the floor. A raw transaction with no input is invalid bytes to the streaming reader (bsv-stack-lean
#58, #59; the rule is the node's, cited by bsv-rs): `verify_stream`, `verify_stream_structure` and
`verify_stream_async` answer `Invalid { offset, kind: NoInputs, reason: NoInputs }` at the transaction's leading
byte, with or without a BUMP index, and `BeefDecoder` refuses the element when its last byte is read. Through
`verify_brc29_payment` and the named opt-out the word is `Unverifiable { reason: InvalidBeef { offset, kind:
"NoInputs", .. } }`, where 0.2.0 on bsv-rs 0.4.0 answered `NoProof { txid }` from the tap's own rule (the reader
read the bytes as valid with no root). That rule stays, beneath the reader's, as defense in depth: the tap's
`unanchored` field, named so in its doc. No behavior change for a host: the refusal class is unchanged (the payer's,
`is_server_side()` false), and nothing is asked of the header service. The same change as bsv-middleware-rs 0.4.1.
The 22 conformance vectors pass unchanged.

### Changed

- `Cargo.toml`: `bsv-rs = "0.4.1"`. A fresh resolve takes the newest 0.4.x (0.4.3 at this date, which also refuses a
  transaction with an input and no output, `NoOutputs`: the same class, `InvalidBeef`).
- `UnverifiableReason::NoProof`'s doc and `Display`: no BUMP, or an ancestry that reaches no proof; a transaction with
  no input is the reader's `InvalidBeef` with the kind `NoInputs`, refused before this word.

### Tests

- `what_the_reader_says_of_a_no_input_unproven_transaction` asserts `Invalid { offset: 7, kind: NoInputs, reason:
  NoInputs }` (the leading byte of the first transaction; red at 0.4.0, the witness of the bump) where it asserted
  `Valid { roots: [] }`; `a_transaction_with_no_input_and_no_proof_anchors_nothing` asserts `InvalidBeef { kind:
  "NoInputs" }` at offset 7, the offset in the words, alone and under a subject, through the full check and the named
  opt-out, where it asserted `NoProof`.
- `witness_no_input_parent_beside_a_proven_stranger_is_refused` (bsv-stack-lean #58): a parent with no input beside a
  proven stranger whose BUMP is the only proof in the BEEF, the subject paying out of that parent, the stranger's root
  the header's. Refused, never `Verified`, the payer's side, the stranger's root never asked. On 0.4.0 the tap
  refused it as `NoProof`; on 0.4.1 the reader refuses it as `NoInputs`.
- `the_doors_no_proof_stands_beneath_the_reader`: the tap's own rule, the reader's word supplied (`Valid`, no root):
  a parent with no input, the elements built by hand, is `NoProof` naming the parent; a BEEF with no BUMP fed through
  the tee is `NoProof` naming the subject. Both shapes are the reader's refusals at 0.4.1 (`NoInputs`,
  `InputNamesNoElement`), so the word is unreachable through it: kept as defense in depth.

## 0.2.0 - 2026-10-09

The payment door reads a BEEF of any size, and the scripts run. The posture, as a rule (the owner's ruling of
2026-10-09; the stack review repository's charter "a BEEF of any size"): a valid BEEF is never refused for its size
or its counts; a refusal is for invalid bytes only, and names them. This crate carries no bound and exports none.
Breaking: the verdict's shape and the SDK major.

### Changed (breaking)

- `verify_brc29_payment` reads the payment ONCE through the streaming reader of bsv-rs 0.4.0
  (`transaction::verify_stream`; every root is granted to a `Headers` that accepts them, so the roots can be asked of
  the async `HeaderService` afterwards): the frame, every BUMP's own root, every unproven transaction's inputs naming
  earlier transactions and SPENDING them (the interpreter executes each unlocking script against the parent output
  the BEEF carries; no transaction creates value), an Atomic subject the tip of its ancestry. 0.1.0 checked the
  structure alone (`Beef::verify_valid`) and answered `Verified` for an unsigned spend beside a proven stranger and
  for an ancestry with no input. Order of checks: no header service (before the bytes are read); the server's key
  derives (else `Err`); the sender's derives (else `Unverifiable`); the reader, at the soonest fault in stream order;
  the subject's output (`WrongScript`, then `Underpaid`); a proof exists; each distinct root, lowest height first;
  `Verified`. The output is judged before any header is asked, as before; the bytes are judged before the output
  (0.1.0 judged the output first: a payment with both a wrong output and an invalid BEEF was `WrongScript` or
  `Underpaid`, and is `Unverifiable` now).
- `PaymentVerdict::Unverifiable { reason: UnverifiableReason }` (was `{ satoshis: u64, reason: String }`). The
  reason splits the class (the no-root ruling of 2026-10-09): `is_server_side()` is true for
  `HeaderLookupFailed { height, reason }` alone (the lowest height the service could not answer for; the host's 5xx
  with the quote kept, the same payment retried); every other reason is the payer's (the host's 4xx, no fields, send
  another payment): `InvalidBeef { offset, kind, reason }` (the reader's refusal: the offset of the byte and one of
  its eighteen kinds, none a size or a count; txids in display hex), `SpendRefused { offset, txid, input, why }`,
  `MalformedTransaction`, `NoTransaction`, `OutputMissing { output_index, output_count }`, `KeyDerivation` (the
  SENDER's key), `NoProof { txid }` (the transaction whose proof is absent; the server never fetches a missing proof),
  and `RootsUnchecked { satoshis, roots }` (the named opt-out's own word, carrying the amount). `#[non_exhaustive]`:
  match it with a catch-all arm. `PaymentVerdict::is_server_side_unverifiable()` is the predicate on the verdict.
- `PaymentFault` is the host's own fault alone: `KeyDerivation` (the SERVER's key) and `Source` (a byte source that
  failed; never for a slice in hand). `BadTransaction`, `MissingOutput` and `BadBeef` are gone: a payer's bytes never
  produce an `Err`; they are an `UnverifiableReason`. `#[non_exhaustive]`.
- `verify_payment_output` (the offline output check): unreadable bytes, a missing output and a sender key that does
  not derive are `Ok(Unverifiable { .. })` now, never `Err`; the server's key alone is the `Err`.
- `verify_brc29_payment_structural_only`: the reader's structure (`verify_stream_structure`, no script run), the
  output, the proof's presence; a payment that passes is `Unverifiable { reason: RootsUnchecked { satoshis, roots } }`
  so the skip stays visible in the word. A BEEF with no root is `NoProof` here too (0.1.0 answered `Verified` for a
  proof with no root to check).
- `spv::beef_roots` is removed (the reader replaces it; nothing in the core parses a BEEF whole). `spv::check_roots`
  takes `&[(u32, String)]` (each distinct root once, lowest height first: two BUMPs at one height with two roots are
  two questions, and one is a mismatch) and answers `RootsOutcome::Unanswered { height, reason }` (the lowest
  unanswered height and the service's words; was `{ reasons: Vec<String> }`); `decide_root`'s `Unanswered` carries the
  service's words alone, the height beside it.
- `expected_locking_script` is unchanged in shape; either key's failure is still its `KeyDerivation` fault (a bare
  helper with no verdict to answer in); the verifiers split the sides.

### Added

- `verify_brc29_payment_verified(..) -> Result<Result<VerifiedPayment, PaymentVerdict>, PaymentFault>`: the same
  check, with the subject's txid as the reader hashed it (`VerifiedPayment { satoshis, txid }`), so a host records and
  internalizes without parsing the BEEF a second time. `Ok(Ok(..))` serves; `Ok(Err(word))` is a refusal, never
  `Verified`; `Err` is the host's own fault.
- `UnverifiableReason` (above), with `is_server_side()` and a `Display` that names the fact (offset, txid, height);
  `VerifiedPayment`; `spv::{check_roots, RootsOutcome}` re-exported at the root.

### Tests

- The witnesses, one fact each: an unsigned spend of a proven parent is `SpendRefused` naming the subject and its
  input, and no header is asked (the stack review repository's question of 2026-10-09, answered yes: the scripts
  run); the same chain spendable is `Verified`; a transaction that creates value is `SpendRefused`; what bsv-rs
  0.4.0's reader says of an unproven transaction with no input (`Valid`, no root) and the core's `NoProof` over it,
  alone, under a subject, or beside a proven stranger whose root is the header's; the owned no-root shapes
  (`spv-no-root`, `spv-incomplete-beef`) refused by the reader as `InputNamesNoElement` naming the absent
  transaction; the lookup error at the lowest height, the server's side; `None` service before the bytes are read;
  an honest proven payment; a BUMP at a height above `u32::MAX` (`RootNotCarried`, never asked at the low bits);
  two roots at one height; a deep honest chain of 3,000 links `Verified` whole, the scripts run at every link.
- `tests/conformance_brc29.rs`: the owner's 22 cases, 22 exact; `Unverifiable` emits `fields.height` on the
  server's side and no fields on the payer's; the two no-root cases held to the payer's side, to a refusal that names
  a transaction of the case, and to a service never asked.

### Dependencies

- `bsv-rs` 0.4 (was 0.3): the streaming BEEF reader (`transaction::beef_stream`). No `BeefLimits`, no size bound.
  (`{:?}` of a linked `Transaction` prints a source as its txid in 0.4.0; no log line or test of this crate prints
  one.)

### Upgrade

- A match on `PaymentVerdict::Unverifiable { satoshis, reason }` becomes `Unverifiable { reason }`; render it by
  `reason.is_server_side()`: true is the server's 5xx with the quote kept (retry the same payment), false the payer's
  4xx (send another payment). The amount is on `Verified` alone (or on `VerifiedPayment`).
- A match on `PaymentFault::{BadTransaction, MissingOutput, BadBeef}` has nothing left to match: those are
  `Unverifiable` reasons now. An `Err` is the host's own fault: render it 500.
- Nothing to delete for limits: this crate never had one.
- Next: 0.3.0 reads the payment from a byte source (`verify_stream_async` over an `AsyncByteSource`), so a host
  streams a request body through the same checks without holding it whole.

## 0.1.0 - 2026-10-08

The first release: the runtime-free rules extracted from `bsv-middleware-cloudflare` 0.3.8, which becomes a
Workers adapter over this crate in its 0.4.0.

### The six words

- `PaymentVerdict`: `Verified { satoshis }`, `Underpaid { paid, required }`, `WrongScript { expected, actual }`,
  `NoHeaderService`, `RootMismatch { height, root }`, `Unverifiable { satoshis, reason }`. One enum, no booleans.
  Only `Verified` serves (`is_verified`); every other word `is_refused`. `Unverifiable` (a root the service could
  not answer, or the named structural-only opt-out) is a refusal: the core never serves on it and a host fails closed
  on it, by the rule adopted on 2026-10-08 (a 5xx of the server's own, the quote kept). The structural-only opt-out
  is the one place a host may serve with roots unchecked, and only because its caller named it.
- `PaymentFault`: `BadTransaction`, `MissingOutput`, `KeyDerivation`, `BadBeef`. The input could not be judged.

### The seams

- `HeaderService`: `fn merkle_root(&self, height) -> impl Future<Output = Result<Option<MerkleRoot>, ServiceError>>`.
  No URL type in the core; `verify_brc29_payment(.., service: Option<&H>)` answers `NoHeaderService` for `None`
  before any other check. `LookupFn` wraps a closure; `NoService` is the type to name for `None`.
- `PaymentNonceStore` (scoped single-use values, `PAYMENT_NONCE_SCOPE`) and `ClaimStore` (an atomic claim by key),
  both fail-closed by contract (`StoreError`, never `Ok(true)`); `MemoryStore` implements both.

### The rules

- `brc29`: `expected_locking_script`, `sender_locking_script`, `verify_payment_output`, `create_derivation_prefix`,
  `verify_derivation_prefix`, `BRC29_PROTOCOL_ID`.
- `spv`: `decide_root` / `RootDecision`, `beef_roots`, `check_roots` / `RootsOutcome`.
- `payment_verify`: `verify_brc29_payment` (the full check through a service) and
  `verify_brc29_payment_structural_only` (the named opt-out; a proof with roots is `Unverifiable`, by name).
- `brc104`: `auth_headers`, `HttpRequestData`, `HttpResponseData`, `build_request_payload`, `write_varint`,
  `signable_request_headers`, `signable_response_headers`, `message_to_headers`.
- `auth`: `SessionBinding`, `AuthError`, `sign_message`, `verify_message_signature` (the counterparty is the
  session's identity, never the header's), `message_identity_is_sessions`, `generate_random_nonce`,
  `server_identity_key`, `create_session_nonce`, `build_initial_response`, `sign_general_message`,
  `sign_http_response`, `build_certificate_response`.
- `session_lane`: the MAC'd lane, moved whole from the adapter (0.3.4 / 0.3.5), with its vectors.
- `refund` (feature `refund`): `refund_locking_script`, `signer` (moved whole from the adapter).
- `types`: `AuthContext`, `PaymentContext`, `BsvPayment`.

### Conformance

- `tests/conformance_brc29.rs` runs `conformance/brc29-payment-vectors.json` (20 cases) through
  `verify_brc29_payment` with a stub service, and checks the outcome as well as the word (only `Verified` serves).
  `spv-lookup-error` expects `Unverifiable`, refused, as the file's `rulings` list records (2026-10-08). The file
  ships inside this package (a copy of the repository root's canonical file, which the Workers adapter produces and
  pins byte-identical to this one), so the published crate runs the vectors on its own.
- 89 unit tests with `refund` (82 without) + 3 conformance tests; the packaged crate runs all of them on its own.

### Known

- `HeaderService::merkle_root`, `PaymentNonceStore` and `ClaimStore` return `impl Future` without a `Send` bound,
  by design for wasm32. A host on a multi-threaded runtime must make its own implementations' futures `Send`; the
  verifier is generic over the service, so that works.
