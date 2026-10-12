# Changelog

All notable changes to `bsv-middleware-cloudflare`. Versions below 1.0 may change public API between minor versions;
patch versions are additive unless a line below says otherwise.

## Adapter 0.6.0 and core 0.3.0 - 2026-10-12

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


## Adapter 0.5.2 and core 0.2.2 - 2026-10-12

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

## 0.5.1 - 2026-10-10

bsv-rs 0.4.1 is the floor (the core is `bsv-middleware-core` 0.2.1, on the same floor). A raw transaction with no
input is invalid bytes to the streaming reader (bsv-stack-lean #58, #59; the rule is the node's, cited by bsv-rs):
`verify_stream`, `verify_stream_structure` and `verify_stream_async` answer `Invalid { offset, kind: NoInputs,
reason: NoInputs }` at the transaction's leading byte, with or without a BUMP index. Through this crate the word is
`PaymentVerifyError::Unverifiable { reason: InvalidBeef { offset, kind: "NoInputs", .. } }`, where 0.5.0 on bsv-rs
0.4.0 answered `NoProof { txid }` from the core's own tap. No behavior change for a host: the refusal class is
unchanged (the payer's, `is_server_side()` false, 400 `ERR_PAYMENT_INVALID` with the quote kept either way), and
nothing is asked of the header service. The same change as bsv-middleware-rs 0.4.1. The 22 conformance vectors
pass unchanged (the owner's bytes, sha256 `836579ad…`).

### Changed

- `Cargo.toml`: `bsv-rs = "0.4.1"`, `bsv-middleware-core = "0.2.1"`. A fresh resolve takes the newest 0.4.x (0.4.3 at
  this date, which also refuses a transaction with an input and no output, `NoOutputs`: the same class, `InvalidBeef`).
- `.github/workflows/release.yml`, `README.md` Releases: the crates.io trusted-publishing entries exist for both crates
  (verified 2026-10-10); releases go out by the tags, `core-v*` first, then `v*`. The release-hold sentences are gone.

### Tests

- `test_no_proof_is_the_payers_side` and `test_structural_only_is_the_named_opt_out_and_serves_by_name` assert the
  reader's word, `InvalidBeef { kind: "NoInputs" }` at offset 7 (the leading byte of the first transaction: the
  version, the two counts, the has-BUMP byte), the offset named in the `Display`, where they asserted `NoProof`.
- `witness_no_input_parent_beside_a_proven_stranger_is_refused` (bsv-stack-lean #58): a parent with no input beside a
  proven stranger whose BUMP is the only proof in the BEEF, the subject paying out of that parent, the stranger's root
  the header's. Refused, never served, the payer's side, the stranger's root never asked. On 0.4.0 the core's tap
  refused it as `NoProof`; on 0.4.1 the reader refuses it as `NoInputs`.
- `NoProof` keeps its class witness (payer-side, the txid in its words) in `test_accept_verdict_table`. Through the
  reader the word is unreachable at 0.4.1 (every ancestry must end at a proven transaction or a proven txid-only
  entry, so a valid BEEF that pays carries a BUMP); the core witnesses its own rule on the tap directly
  (`the_doors_no_proof_stands_beneath_the_reader`).

## 0.5.0 - 2026-10-09

The payment door reads a BEEF of any size, and the scripts run. The core is `bsv-middleware-core` 0.2.0; the SDK is
bsv-rs 0.4. The posture, as a rule (the owner's ruling of 2026-10-09; the stack review repository's charter "a BEEF
of any size"): a valid BEEF is never refused for its size or its counts; a refusal is for invalid bytes only, and
names them. This crate carries no limit, no count bound and no 413. Breaking: the verdict's shape and the SDK major;
every 0.3 function keeps its name, path and signature, and the fleet's call sites compile unchanged
(`src/api_surface_tests.rs`).

### Changed (breaking)

- `verify_brc29_payment`, `verify_brc29_payment_with_header_lookup`, `verify_brc29_payment_verdict`: the core's
  check reads the payment ONCE through the streaming reader of bsv-rs 0.4.0 with the scripts run (every unproven
  transaction's inputs executed against the parent outputs the BEEF carries; no transaction creates value; an Atomic
  subject the tip of its ancestry), then the subject's output, then a proof's presence, then each distinct root
  against the header service, lowest height first. 0.4.x checked the BEEF's structure alone and served an unsigned
  spend beside a proven stranger. Order: no header service (before the bytes are read); the bytes, at the soonest
  fault; the output (`WrongScript`, then `Underpaid`); a proof; the roots; `Ok(satoshis)`.
- `PaymentVerifyError::Unverifiable { reason: UnverifiableReason }` (was `{ satoshis, reason: String }`), the core's
  reason re-exported. `PaymentVerifyError::is_server_side()` is true for it when the reason is the server's
  (`HeaderLookupFailed { height, .. }`: the lowest height the service could not answer for) and false for every
  other variant, `NoHeaderService` included (a misconfiguration, 500, not a transient 503). The 0.3 variants
  `BadTransaction`, `MissingOutput` and `BadBeef` are gone: a payer's bytes are an `Unverifiable` reason now
  (`MalformedTransaction`, `OutputMissing`, `InvalidBeef { offset, kind, reason }`, `SpendRefused { offset, txid,
  input, why }`, `NoProof { txid }`, `NoTransaction`, the sender's `KeyDerivation`), every one of them payer-side.
  `Source(String)` is added for a byte source that fails (never for bytes in hand).
- The host's table (in the rustdoc of `PaymentVerifyError` and the README):

  | `PaymentVerifyError` | status | code |
  |---|---|---|
  | `NoHeaderService` | 500 | `ERR_SERVER_MISCONFIGURED` (fix the deployment) |
  | `KeyDerivation` (the server's key) | 500 | the host's own |
  | `Unverifiable`, `is_server_side()` | 503 | `ERR_HEADER_SERVICE_UNAVAILABLE`, the quote kept: retry the same payment later |
  | every other refusal (`Unverifiable` payer-side, `Underpaid`, `WrongScript`, `RootMismatch`) | 400 | `ERR_PAYMENT_INVALID`, the quote kept: send another payment |

- The middleware's own path (`process_payment_with_storage*`, `judge_paying_output`): `Unverifiable` with a
  server-side reason stays 503 `ERR_HEADER_SERVICE_UNAVAILABLE` with the quote kept; `Unverifiable` with a
  payer-side reason is 400 `ERR_INVALID_PAYMENT` with the quote kept (as `RootMismatch`; the no-root ruling of
  2026-10-09); a `PaymentFault` is 500 `ERR_SERVER_MISCONFIGURED` (0.4.x answered a fault 400, when faults were the
  payer's bytes; they are the server's own key now). What the path reads is unchanged: output 0, script and amount,
  through the core's output check; no reader, no SPV.
- `verify_brc29_payment_structural_only`: through the reader's structure (no script run), the output and the proof's
  presence; serves (`Ok(satoshis)`) by name on the core's `RootsUnchecked`; a BEEF with no root is refused (`NoProof`)
  here too (0.4.x served it).
- `verify_brc29_payment_output` (the output check alone): unreadable bytes and a missing output are payer-side
  `Unverifiable` errors (were `BadTransaction`, `MissingOutput`).

### Added

- `verify_brc29_payment_verified(.., header_url) -> Result<VerifiedPayment, PaymentVerifyError>`: the same gate and
  refusals as `verify_brc29_payment`, with the subject's txid beside the amount (`VerifiedPayment { satoshis, txid }`,
  the core's, hashed by the reader while the bytes passed), so a host records the payment without parsing the BEEF a
  second time. Re-exports `UnverifiableReason` and `VerifiedPayment` at the root.
- The machine gate: `.github/workflows/ci.yml` (on PR and push to `main`: `cargo fmt --check`, clippy on both crates
  and the adapter on `wasm32-unknown-unknown`, the tests of both, both conformance runners by name, rustdoc with
  warnings denied, `cargo publish --dry-run` of the core, the adapter packaged once its core version is on crates.io,
  the manifests held free of `[patch]`) and `release.yml` (tag `core-v*` publishes the core, `v*` the adapter, through crates.io trusted
  publishing after the gate passes; action SHAs pinned). The crates.io trusted-publishing entries are the owner's to
  add (crates.io → crate → Settings → Trusted Publishing: repository `Calhooon/bsv-middleware-cloudflare`, workflow
  `release.yml`); until they exist the captain publishes with a token under the release hold.

### Conformance

- `conformance/brc29-payment-vectors.json` (and the core's copy `core/conformance/`) is the stack review repository's
  owned file (22 cases; the two no-root cases of 2026-10-09, `spv-no-root` and `spv-incomplete-beef`, `Unverifiable`
  with no fields, the payer's side), its bytes unchanged (the `producer` line included), pinned by digest
  (sha256 `836579ad…`, the sha every implementation pins; bsv-middleware-rs 0.4.0 pins the same).
  `spv-lookup-error` emits `fields.height` (the declared `fields.satoshis` divergence of 0.4.x is withdrawn). Both
  runners pass 22 of 22; `crate_result` is informational, `expected` is the judge. The emit mode is a check now
  (`the_twenty_synthetic_cases_regenerate_from_the_producer`): the 20 synthetic cases regenerate from the producer's
  fixed inputs and are held to the file's field for field (the owner's `note` and `crate_result` texts aside); the
  owner's two cases and the `rulings` list are never produced here.

### Dependencies

- `bsv-middleware-core` 0.2.0; `bsv-rs` 0.4 (was 0.3; the streaming BEEF reader, no `BeefLimits`); `worker` 0.8
  (unchanged). (`{:?}` of a linked `Transaction` prints a source as its txid in bsv-rs 0.4.0; no log line or test of
  this crate prints one.)

### Upgrade

- Match `PaymentVerifyError::Unverifiable { reason }` and render by `is_server_side()`: a two-arm match with a `_`
  arm compiles unchanged and answers 400 for a header outage; the three-arm form (500 `NoHeaderService` / 503
  server-side `Unverifiable` with the quote kept / 400 everything else) is the hosts' change
  (`src/api_surface_tests.rs` shows it). The amount is on `Ok` alone (or on `VerifiedPayment`).
- Delete arms for `BadTransaction`, `MissingOutput`, `BadBeef`: a `_` arm takes their cases.
- No limit to delete: this crate never had one. `src/transport/cloudflare.rs` still reads the whole request body into
  memory before the middleware runs; nothing refuses it for its size.
- Next: 0.6.0 streams the request body through `verify_stream_async` (`AsyncByteSource`), so the body is never held
  whole.

## 0.4.1 - 2026-10-08

### Changed

- **Authentication refusals are 401 responses from the middleware itself, never an `Err`.** `process_auth`,
  `process_auth_with_storage`, `process_auth_do`, `process_auth_lane` and `process_auth_lane_with_storage` answer
  every refusal as `Ok(AuthResult::Response(..))`: status 401, the body
  `{"status":"error","code":"…","description":"…"}`, the CORS headers, unsigned (there is no session to sign with,
  as the existing 401s already were). The codes are the ones the crate has declared for them since 0.1
  (`AuthCloudflareError::status_code()` has always said 401): `UNAUTHORIZED` (no auth headers; the reference's
  body, its `message` field), `ERR_SESSION_NOT_FOUND` (no session for the nonce or identity named),
  `ERR_INVALID_AUTH` (the header's identity is not the session's; the signature is missing or does not verify; the
  session never completed its handshake; a general message without `x-bsv-auth-nonce`; headers that do not form a
  BRC-103 message; a handshake message refused: an unparseable body, a certificate message whose signature or
  certificates fail), `ERR_REPLAYED_REQUEST` (the per-request nonce already used). 0.4.0 raised four of these as
  `Err(AuthCloudflareError::InvalidAuthentication(..))` ("Message identity key is not the session's", "Invalid
  message signature", "Session not authenticated"), and the transport's header refusals and the handshake path's
  refusals likewise; every host rendered an `Err` as a generic 500, so the clients that re-handshake on 401 only
  (`AuthFetch`, and the paid-call helpers built on it) never recovered a stale session. `Err` from `process_auth*`
  now means a fault: storage (KV, Durable Object, D1), the server's own key, the transport, the SDK. No public item
  changed; a host's existing `match` compiles unchanged and sees the 401 on the `Response` arm it already has.
  (Reference note: the Express middleware answers 401 `UNAUTHORIZED` for a request without auth headers; a general
  message its SDK refuses is swallowed by the `Peer` and never answered. The 401 here is this crate's own rule, as
  the `ERR_REPLAYED_REQUEST` 401 was.)

### Behaviour

- Served requests, the handshake replies and response signing are byte-for-byte 0.4.0; the three 401 bodies that
  existed (`UNAUTHORIZED`, `ERR_SESSION_NOT_FOUND`, `ERR_REPLAYED_REQUEST`, and the missing-nonce
  `ERR_INVALID_AUTH`) are byte-for-byte too. The general path's decision is a `Request`/`Response`-free judgement
  inside `middleware::auth`, so it runs under native `cargo test`: each refusal pinned at 401 with its code and
  nothing consumed or served, a storage fault pinned as the `Err` it was.
- The core (`bsv-middleware-core`) is unchanged, 0.1.0.

## 0.4.0 - 2026-10-08

The core extract. The rules moved to a new runtime-free crate, `bsv-middleware-core` 0.1.0 (this repository,
`core/`); this crate is now the Cloudflare Workers adapter over it. Carries everything in 0.3.7, 0.3.8 and 0.3.9.
**One breaking change, for 0.3.9 adopters only:** `PaymentVerifyError::Unverifiable` carries `{ satoshis, reason }`
here where 0.3.9 carried `{ height, reason }`; a match written against 0.3.9's fields must change (a `_` arm compiles
unchanged). Every other 0.3 public item keeps its name, path and signature (re-exported from the core where the type
moved), and the fleet's call sites compile unchanged. Versions below 1.0 may change public API between minors.

### What moved to the core (re-exported here at the 0.3 paths)

- `types::{AuthContext, PaymentContext, BsvPayment}`.
- `transport::{auth_headers, HttpRequestData, HttpResponseData}`; the request payload builder, the varint
  writer, the signable-header filters and `message_to_headers` are `bsv_middleware_core::brc104`
  (`CloudflareTransport` delegates to them).
- `middleware::session_lane` (whole; the adapter keeps the suite and `tests/fixtures/session_lane.vectors.json`).
- `refund::signer` (whole); `issue_refund` derives the client's key through `bsv_middleware_core::refund`.
- The BRC-103 sign/verify, the identity binding, the `InitialResponse` and `CertificateResponse` builders and
  response signing (`bsv_middleware_core::auth`, over a `SessionBinding`); `process_auth*`, `sign_response` and
  `sign_json_response` call them and are byte-for-byte on the wire.
- BRC-29 derivation, the output check, BEEF completeness and the SPV decision
  (`bsv_middleware_core::{brc29, spv, payment_verify}`), answered in the six words (`PaymentVerdict`).
- `PAYMENT_NONCE_SCOPE` (`bsv_middleware_core::store`).

### Added

- `UrlHeaderService`: the core's `HeaderService` over a ChainTracks-compatible base URL (Workers `fetch`), built
  only through the 0.3.6 configuration gate (`UrlHeaderService::resolve`).
- `verify_brc29_payment_verdict`: the core's `PaymentVerdict` through any `HeaderService`, for callers that
  decide the words themselves.
- `accept_verdict`: the one visible match from the core's words to `PaymentVerifyError` / `Ok(satoshis)`.
- `PaymentVerifyError::Unverifiable { satoshis, reason }`: new on this line (0.3.9 introduced it on the 0.3 line as
  `{ height, reason }`; see Changed). A host's `_` arm compiles unchanged; that arm answers the client's 400 today, so
  hosts should add a 503 arm for it (the quote kept).
- `PaymentVerifyError: From<PaymentFault>`; `AuthCloudflareError: From<bsv_middleware_core::AuthError>`.
- `SessionNonceStore(&storage)`: any `SessionStorage` as the core's `PaymentNonceStore`; `D1ClaimStore(&db)`
  (feature `d1-claims`): the D1 table as the core's `ClaimStore`.
- `bsv_middleware_cloudflare::core` (the core crate as a module) and the top-level `HeaderService`,
  `PaymentVerdict`, `PaymentFault` re-exports.
- `core/tests/conformance_brc29.rs`: the core runs the 20 vectors of `conformance/brc29-payment-vectors.json` (0.3.7)
  through its `HeaderService` trait with a stub, from its own copy of the file (`core/conformance/`, shipped in the
  core's package); the adapter's runner re-pins the root file with the 0.4.0 producer line, writes both copies on
  `emit`, and pins the core's copy byte-identical to the root one.

### Changed

Against 0.3.9 (the last release on the 0.3 line), three behaviours differ and are intended:

- `Unverifiable` carries `{ satoshis, reason }` (0.3.9: `{ height, reason }`), matching the conformance vectors as the
  vectors' owner (bsv-stack-lean) keeps them: `spv-lookup-error` expects `fields: {satoshis}`; 0.3.9's file wrote
  `{height}` and retired the glossary entry `AcceptedUnverified`, this file keeps the entry as a retired alias.
- Root precedence: the core asks the header service about every root and a mismatch at any height wins over an
  unanswered root (`RootMismatch`, 400); 0.3.9 stopped at the lowest height that did not match, so a lookup error at
  a low height answered `Unverifiable` (503) even when a higher root was wrong. A lookup error cannot mask fraud here.
- Underpaid / WrongScript on the middleware's own payment path answer 400 `ERR_INVALID_PAYMENT` with the quote kept
  (0.3.8 and 0.3.9 answered 402 with a fresh challenge); reference parity with the Express payment middleware.

- **A header lookup the service cannot answer fails closed.** 0.3.x accepted a payment whose merkle root could not be
  checked (service unreachable, HTTP error, unparseable answer, height not yet indexed) with a logged warning; 0.4.0
  refuses it, by the project's ruling of 2026-10-08: a root that was not checked against a block header is not
  evidence. `accept_verdict`, and with it `verify_brc29_payment`, `verify_brc29_payment_with_header_lookup` and
  `verify_brc29_payment_verdict`'s callers that use it, answer `Err(PaymentVerifyError::Unverifiable { satoshis,
  reason })` where 0.3.x answered `Ok(satoshis)`, so no host serves on it by accident. On the middleware's own path
  (`process_payment_with_storage`, `process_payment_with_storage_signed`, the deprecated `process_payment`) the word
  is `503 ERR_HEADER_SERVICE_UNAVAILABLE` with the quote kept: a transient server-side condition (nothing charged, the
  prefix not consumed, no fresh challenge, the wallet not called; the client retries the same payment later),
  distinct from `500 ERR_SERVER_MISCONFIGURED` for `NoHeaderService` and from the 400s for a payment that is wrong
  (`Underpaid`, `WrongScript`, `RootMismatch`, a `PaymentFault`). The one function that still answers `Ok` with roots
  unchecked is the named opt-out `verify_brc29_payment_structural_only`, because its caller asked for that by name;
  it no longer goes through `accept_verdict` for that word. The conformance file's `spv-lookup-error` case expects
  `Unverifiable`, refused, and carries the ruling in its `rulings` list. Hosts that run their own payment flow
  through `verify_brc29_payment` should render the new variant 503-class (today a two-arm match answers 400).
- **A short or misdirected payment on the middleware's own path is refused with `400 ERR_INVALID_PAYMENT` and the
  quote is kept** (`process_payment_with_storage`, `process_payment_with_storage_signed`, the deprecated
  `process_payment`; the core's `Underpaid` / `WrongScript` on output 0). 0.3.8 answered `402 ERR_INVALID_PAYMENT`
  with a fresh challenge. Now: no fresh challenge, the derivation prefix not consumed, the wallet not called, and the
  body says the challenge is unchanged, so an honest client corrects the payment and retries under the same prefix.
  Why: the Express reference (`payment-express-middleware`) answers 400 for every refusal after the challenge and
  reserves 402 for "pay now"; a 402 re-arms automated payers (AuthFetch-class clients) into a second payment for the
  same request while the first sits un-internalized; one live quote per request keeps the single-use rule simple;
  and existing hosts built on this crate's `verify_brc29_payment` already answer 400 and keep the quote. `NoHeaderService` stays `500 ERR_SERVER_MISCONFIGURED`,
  `RootMismatch` and a `PaymentFault` `400 ERR_INVALID_PAYMENT`, `Unverifiable` `503 ERR_HEADER_SERVICE_UNAVAILABLE`
  (above). The words did not change; the HTTP rendering of three of them did, and one case's expected word
  (`spv-lookup-error`) changed with the ruling.

### Behaviour

- Unchanged on the wire, except the two refusals under Changed. The verdict mapping is documented in
  `payment_verify`: `Verified` is the only `Ok(satoshis)`; every other word is the same-named `Err`, `Unverifiable`
  included (**fail-closed**, with the reason logged).
- `verify_brc29_payment_structural_only` answers through the core's `Unverifiable` word when a proof carries
  roots and serves it with the warning logged, as 0.3.6 did: the named opt-out is the one place that may.
- **The middleware's own payment path decides from the core's words.** `process_payment_with_storage`,
  `process_payment_with_storage_signed` and the deprecated `process_payment` run the core's output check
  (`bsv_middleware_core::verify_payment_output`) on output 0 and match its `PaymentVerdict` once
  (`judge_paying_output`): `Verified` serves and records the amount read; `Underpaid` / `WrongScript` are
  `400 ERR_INVALID_PAYMENT` with the quote kept (the prefix not consumed, no fresh challenge, the wallet not called;
  see Changed); a `PaymentFault` or `RootMismatch` is `400 ERR_INVALID_PAYMENT`, the prefix kept; `NoHeaderService` is
  `500 ERR_SERVER_MISCONFIGURED` (the server's own fault, never a client error); `Unverifiable` is
  `503 ERR_HEADER_SERVICE_UNAVAILABLE`, the quote kept (refused, fail-closed; see Changed). Only `Verified` serves.
  The output check answers three of the six words today: this path
  runs no SPV (no merkle proof is checked against a header; what the wallet storage server does on
  `internalizeAction` is not verified by this crate, and `verify_brc29_payment` is the caller's proof step before
  the middleware); the other arms are the path's standing answer should the check grow a proof step. Every payment
  0.3.8 served is served, with the same `satoshis_paid`; the one wire answer that changed is the refusal under
  Changed.

### Tests

- 0.3.8 baseline: 212 unit + 2 conformance-file tests. 0.4.0: adapter 220 unit + 4 conformance-file tests (the
  runner, the pinned bytes, the core's copy, the ruling; the emitter is ignored); core 89 unit (82 without `refund`)
  + 3 conformance. 23 test paths moved from the adapter to the core, none lost. Both runners check the outcome as
  well as the word: only `Verified` serves.

### Known

- Error-code spelling: hosts that run their own payment flow through `verify_brc29_payment` have answered
  `ERR_PAYMENT_INVALID` for a refused payment; this crate and the Express reference spell it `ERR_INVALID_PAYMENT`.
  The Express spelling is the one to keep; aligning the hosts (or documenting the alias) is a later release.
- Hosts on a two-arm match (`NoHeaderService` → 500, `_` → 400) render the new `PaymentVerifyError::Unverifiable`
  as the client's 400 today; the intended answer is 503-class with the quote kept, so the client retries the same
  payment. The hosts' change, not this crate's.
- The conformance file's `words` glossary still spells `Unverifiable` by its retired name `AcceptedUnverified`, and
  the ruled case's `expected.fields` carry that word's `satoshis`; both are the file owner's to change in a reviewed
  diff. This crate's copy differs from the owner's in the `producer` line, the ruling's `why` (public wording) and,
  on the ruled case, `crate_result` and `note` (this crate's own answer, now a refusal).
- `HeaderService::merkle_root` and the core's store traits return `impl Future` without a `Send` bound, by design
  for wasm32. A host on a multi-threaded runtime needs its own implementations' futures to be `Send`; the verifier
  is generic over the service, so that works, but it is the host's obligation and the core README will say so
  before a native host adopts the trait.

### Removed from the dependency list

- `hmac` and `ripemd` (they moved with the lane and the signer; `sha2` stays for the Durable Object cell).

## 0.3.9 - 2026-10-08 (0.3 line, branch `release-0.3`, tag `v0.3.9`)

- Fails closed on a header-service lookup error: `verify_brc29_payment` (and the `_with_header_lookup` form) return
  `Err(PaymentVerifyError::Unverifiable { height, reason })` instead of accepting with a warning; the middleware's own
  payment path answers 503 `ERR_HEADER_SERVICE_UNAVAILABLE` with the quote kept (prefix not consumed, wallet not
  called). The owner's ruling of 2026-10-08. The conformance file's `spv-lookup-error` case expects `Unverifiable`.
- No other change: 0.3.8's 402-with-a-fresh-challenge on Underpaid / WrongScript stays on this line.

## 0.3.8 - 2026-10-08

### Fixed

- **The middleware's own payment flow reads the paying output** (P0-3b). `process_payment_with_storage`,
  `process_payment_with_storage_signed` and the deprecated `process_payment` now run `verify_brc29_payment_output` on
  output 0 before the derivation prefix is consumed and before `internalizeAction`. Until now nothing on this path
  compared the output with the price or checked that it pays this server's BRC-29 derived key; the storage server
  checks neither, so an underpaid payment, or one paying another key, was served. 0.3.7 shipped the conformance
  vectors without this wiring.

### Behaviour

- A payment whose output 0 carries less than the price, or is not locked to the server's derived key for (prefix,
  suffix, the authenticated identity), is refused with `402 ERR_INVALID_PAYMENT` and a fresh challenge; the storage
  is not called and the prefix is not consumed, so the client may retry it.
- An unreadable payment transaction, or one with no output 0, is refused with `400 ERR_INVALID_PAYMENT`; the prefix
  is not consumed.
- `PaymentContext::satoshis_paid` (and so `x-bsv-payment-satoshis-paid`) is the amount read from output 0, not the
  price: an overpayment records what was paid.
- The middleware does not run BEEF structure or SPV (`verify_brc29_payment` stays the caller's choice).
- Exact-price payers to the key derived from the same `server_private_key` see no change. A deployment whose payment
  key differs from the key its clients derive for will now be refused instead of recording outputs it cannot spend.

## 0.3.7 - 2026-10-08

### Added

- `verify_brc29_payment_with_header_lookup`: `verify_brc29_payment` with the header lookup supplied by the caller
  (`Fn(height) -> Future<Result<merkle_root, reason>>`) instead of a `header_url`; same fail-closed mismatch,
  fail-open service error (0.4.0 fails closed on it; see 0.4.0 Changed). For a service binding, a cached header
  store, or a conformance runner.
- `conformance/brc29-payment-vectors.json` + `conformance/README.md`: 20 implementation-neutral BRC-29 payment
  verification vectors (amount, script, first-output rule, pay-yourself, header-service gate, SPV), produced and run
  by `tests/conformance_brc29.rs`. A second implementation runs the same file. No behaviour or signature changes.

## 0.3.6 - 2026-10-08

### Added

- `payment_verify`: `expected_brc29_locking_script`, `verify_brc29_payment_output` (script + amount, sync) and
  `verify_brc29_payment` (adds BEEF structural completeness and SPV against a header service you run), for callers
  that run their own payment flow and want the pays-us-correctly and real-and-confirmable checks before
  `internalizeAction`.
- `verify_brc29_payment_structural_only`: the same offline checks with **no SPV**, for adopters that have no header
  service. Opt-in by name; a warning is logged whenever merkle roots go unchecked.
- `PaymentVerifyError::NoHeaderService`.
- Feature `d1-claims`: `claim_payment_nonce` / `release_payment_nonce`, an atomic single-use payment-nonce claim on a
  D1 table (`PAYMENT_CLAIMS_SCHEMA`), for callers outside the stock middleware or on the eventually-consistent KV
  backend.
- docs.rs builds with all features.

### Behaviour

- **A header service URL is required for `verify_brc29_payment`.** `header_url = None`, `Some("")`, the
  `DEFAULT_CHAINTRACKS_URL` `.invalid` placeholder (in any case, with or without a trailing slash or dot), any other
  `.invalid` host, a value without an `http(s)://` scheme, or a value whose host the gate cannot classify as a real
  hostname (userinfo, percent-encoding, backslashes, whitespace, non-ASCII, a non-numeric port) returns
  `Err(NoHeaderService)` before any other check. The host is normalised before the placeholder comparison, so no
  spelling of the placeholder slips through to DNS and fails open. SPV is never skipped
  silently. Once a service is named, a service error (unreachable, HTTP error, unparseable answer) still fails open
  with a logged warning (until 0.3.8; 0.4.0 fails closed on it, see 0.4.0 Changed), and a merkle root that differs
  from the block header still fails closed with `RootMismatch`.
- The configuration gate and the per-root SPV decision are pure functions with table tests (match, mismatch, lookup
  error, and every refused `header_url` shape); the header lookup is injected into the loop that runs them.

## 0.3.5 - 2026-09-20

Session-lane hardening; no new API.

- The lane's replay window rides across the Durable Object store as a decimal string, and a laned counter above
  `MAX_SAFE_COUNTER` (2^53 − 1) is refused by name instead of faulting the store.
- Every 64-bit field of the session cell and its body types documents its bound.

## 0.3.4 - 2026-09-14

- **Session lane (opt-in).** One BRC-103/104 handshake per origin, then MAC'd calls with no wallet calls and one
  Durable Object round trip: `process_auth_lane`, `LaneAuthResult`, `seal_lane_response` / `seal_lane_response_text`,
  `request_presents_lane`, the `x-bsv-lane-offer` header on the first signed general message that asks, and the pure
  rules in `middleware::session_lane`. The MAC vectors are `tests/fixtures/session_lane.vectors.json`, sha256-pinned.
- `mint_attested_lane`: a lane for an identity a first-party authority has proven, with the same record and lifetime
  as the signed-read mint.
- `sha2` is a plain dependency (the lane MACs); `ripemd` stays behind `refund`.

## 0.3.3 - 2026-09-09

- **Durable Object session backend (opt-in).** `process_auth_do`, `AuthSessionStore`, `DoSessionStorage`: one object
  per session nonce holds the session record and the consumed per-request nonces (an atomic put-if-absent, no KV
  write per request); KV stays the cold path.
- `SessionStorage::get_session_and_consume`: the hot path in one round trip, as an additive trait default
  ("unsupported") that every existing backend keeps.
