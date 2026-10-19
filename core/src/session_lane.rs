//! THE SESSION LANE (0.3.4; the relay adopter's lane, generalized to
//! HTTP-only servers).
//!
//! One BRC-103/104 handshake per origin and tab, then a LANE: when the client's
//! FIRST BRC-104-signed general message carries the explicit ask
//! (`x-low-lane-ask`), its SIGNED answer carries the offer header
//! (`x-bsv-lane-offer`, base64 JSON `{id, expiresAt, salt, ask}`, a header a
//! reference client ignores; the `InitialResponse` never offers — the
//! initialRequest is unsigned). Both sides derive one secret `K` from the
//! salt, the id, that message's own nonce (`x-bsv-auth-nonce`) and the
//! server's session nonce; `K` never crosses the wire. Every
//! later call carries `x-low-session` (the id), `x-low-session-identity`,
//! `x-low-session-n` (the client's counter `h`) and `x-low-session-mac` =
//! `HMAC-SHA256(K, h_le8 ‖ "METHOD path?query" ‖ 0x00 ‖ sha256(body))`; the
//! server verifies the MAC and the counter (a 64-deep window: parallel fetches
//! land in any order, each `h` accepted once), refreshes the idle window, and
//! seals its answer with `x-low-session-mac` = `HMAC-SHA256(K, h_le8 ‖
//! "response" ‖ 0x00 ‖ sha256(body))` under the request's own `h`. A refusal
//! names its reason; a request without the headers takes the reference path.
//! ZERO wallet calls per laned call: the MAC is computed in wasm here and in
//! JS there.
//!
//! Pure: no I/O, no clock reads (the caller passes `now_ms`), so every rule is
//! unit-pinned here; the store (`storage::do_session`) and the door
//! (`middleware::auth::process_auth_lane`) only wire it. The MAC vectors are
//! PRODUCED here (`emit_session_lane_vectors`) and pinned byte-for-byte by the
//! client (the relay adopter's copy of `session_lane.vectors.json`): the
//! artifact is shared, never the convention.
use bsv_sdk::primitives::hash::{sha256, sha256_hmac};
use serde::{Deserialize, Serialize};

/// The default domain separator inside `K`'s derivation. A server may pass its
/// own label (the relay keeps `low-relay-session/v1`); the vectors say which.
pub const DEFAULT_LABEL: &[u8] = b"low-session-lane/v1";
/// A lane expires this long after the last verified call.
pub const LANE_IDLE_MS: u64 = 60 * 60 * 1000;
/// The request headers of a laned call.
pub const SESSION_HEADER: &str = "x-low-session";
pub const SESSION_IDENTITY_HEADER: &str = "x-low-session-identity";
pub const SESSION_COUNTER_HEADER: &str = "x-low-session-n";
/// The largest counter a laned call may carry: `Number.MAX_SAFE_INTEGER`. Above
/// it a JSON number no longer survives the JavaScript side of the store's
/// boundary (0.3.5); a lane makes nowhere near 2^53 calls.
pub const MAX_SAFE_COUNTER: u64 = (1u64 << 53) - 1;
pub const SESSION_MAC_HEADER: &str = "x-low-session-mac";
/// The client's explicit ask, a header on its FIRST BRC-104-signed general
/// message (D10: only an explicit ask mints; the unsigned handshake never does).
pub const LANE_ASK_HEADER: &str = "x-low-lane-ask";
/// The OFFER's carrier: a header on the answer to the client's FIRST
/// BRC-104-SIGNED general message that carried the ask — base64 of the
/// offer's JSON. Named in the `x-bsv-` namespace (not `x-bsv-auth-`) on
/// purpose: the reference signs exactly those response headers, so the
/// offer rides under the server's identity signature and the client's own
/// verification covers it. The handshake's `InitialResponse` never offers:
/// the initialRequest is unsigned, its identity a claim (the 2026-09-14 gate
/// HIGH-1); a lane binds a PROVEN identity only.
pub const LANE_OFFER_HEADER: &str = "x-bsv-lane-offer";
/// A lane's absolute lifetime from its mint, refreshes or not (the idle
/// window is the short bound; this is the long one: a stolen K + id is
/// worthless past it whatever the traffic).
pub const LANE_MAX_LIFETIME_MS: u64 = 12 * 60 * 60 * 1000;
/// The event name a sealed answer is MAC'd under.
pub const HTTP_RESPONSE_EVENT: &str = "response";
/// The refusal's `code` (401), `reason` carries the word.
pub const HTTP_REFUSED_CODE: &str = "ERR_SESSION_REFUSED";
/// How many counters behind the highest accepted one are still accepted once.
pub const HTTP_REPLAY_WINDOW: u64 = 64;

/// The lane as the store holds it: keyed by `id`, one object per lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaneRecord {
    pub id: String,
    /// `K`, hex.
    pub key: String,
    /// The handshake's peer identity key (66 hex, lowercase).
    pub identity: String,
    // bounded: a millisecond stamp
    pub expires_at_ms: u64,
    /// The highest accepted `h`. Rides as a DECIMAL STRING since 0.3.5 like the
    /// mask below: the caller's counter is bounded at the header (`MAX_SAFE_COUNTER`)
    /// and the store's serializer accepts exactly up to that bound — the same
    /// constant on both sides, zero headroom — so the field does not depend on it.
    #[serde(with = "u64_as_string")]
    pub last_h: u64,
    /// Bit `k` set ⇔ `last_h - k` was accepted (k < 64). Rides as a DECIMAL
    /// STRING (0.3.5): the store persists the whole cell through
    /// the Durable Object's `storage().put`, whose serializer carries a `u64`
    /// as a JavaScript number and THROWS past 2^53. Bit 53 is set as soon as an
    /// accepted counter sits 53 above the one before it — the 54th of a dense
    /// run, or the SECOND call of a client whose counter skipped (aborted
    /// fetches, offline retries) — after which every verify of the lane fails
    /// at the put (relay 0.3.24's class, seen live on the hub mirror
    /// 2026-09-20). A number still reads: every row persisted before 0.3.5 is
    /// below 2^53 by construction (a larger one never stored). The untagged
    /// number-or-string shape needs a self-describing deserializer:
    /// serde-wasm-bindgen's `deserialize_any` reads both a JS number and a JS
    /// string (0.6.x), and a string is always representable. A row that fails
    /// to read is an EMPTY cell (`AuthSessionStore::load`): the lane is
    /// unknown, the door refuses by name and the client re-mints — lossy,
    /// never a grant.
    #[serde(default, with = "u64_as_string")]
    pub seen_mask: u64,
    /// When the lane was minted (ms); the absolute lifetime counts from here.
    /// A record without one (pre-lifetime) reads as minted at 0: expired.
    #[serde(default)]
    // bounded: a millisecond stamp
    pub minted_at_ms: u64,
}

/// `u64` ⇄ a decimal string on the wire (see `LaneRecord::seen_mask`); a number
/// is still read (the rows persisted before 0.3.5, all below 2^53 by
/// construction — anything larger never persisted). The same module as the
/// relay's (`rust-message-box` 0.3.24 `session_lane::u64_as_string`).
pub mod u64_as_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        v.to_string().serialize(s)
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(u64),
        Str(String),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        match NumOrStr::deserialize(d)? {
            NumOrStr::Num(n) => Ok(n),
            NumOrStr::Str(t) => t.parse::<u64>().map_err(serde::de::Error::custom),
        }
    }
}

/// What the SIGNED answer to the first general message carries when it asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneOffer {
    pub id: String,
    #[serde(rename = "expiresAt")]
    pub expires_at_ms: u64,
    pub salt: String,
    /// The ask this offer answers (the client binds its lane to its own ask).
    pub ask: String,
}

/// Why a laned call was refused — stable wire words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Refusal {
    UnknownSession,
    Expired,
    Replay,
    BadMac,
    Malformed,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::UnknownSession => "unknown-session",
            Refusal::Expired => "expired",
            Refusal::Replay => "replay",
            Refusal::BadMac => "bad-mac",
            Refusal::Malformed => "malformed",
        }
    }
}

/// `K = HMAC-SHA256(salt, label ‖ id ‖ clientNonce ‖ serverNonce)`.
pub fn derive_key(
    label: &[u8],
    salt: &[u8; 32],
    id: &[u8; 32],
    client_nonce: &str,
    server_nonce: &str,
) -> [u8; 32] {
    let mut data =
        Vec::with_capacity(label.len() + id.len() + client_nonce.len() + server_nonce.len());
    data.extend_from_slice(label);
    data.extend_from_slice(id);
    data.extend_from_slice(client_nonce.as_bytes());
    data.extend_from_slice(server_nonce.as_bytes());
    sha256_hmac(salt, &data)
}

/// `m = HMAC-SHA256(K, n as 8 bytes little-endian ‖ e ‖ 0x00 ‖ sha256(d))`.
pub fn frame_mac(key: &[u8; 32], n: u64, e: &str, d: &str) -> [u8; 32] {
    let digest: [u8; 32] = sha256(d.as_bytes());
    frame_mac_over_digest(key, n, e, &digest)
}

/// `frame_mac` with the body's sha256 already in hand (a request body read as bytes).
pub fn frame_mac_over_digest(key: &[u8; 32], n: u64, e: &str, digest: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(8 + e.len() + 1 + digest.len());
    data.extend_from_slice(&n.to_le_bytes());
    data.extend_from_slice(e.as_bytes());
    data.push(0);
    data.extend_from_slice(digest);
    sha256_hmac(key, &data)
}

/// The HTTP "event": `"METHOD path?query"` — the method upper-cased, the path
/// and query byte-for-byte.
pub fn http_event(method: &str, path_and_query: &str) -> String {
    format!("{} {}", method.to_ascii_uppercase(), path_and_query)
}

/// `path?query` from a URL's parts (the query only when non-empty).
pub fn path_and_query(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.to_string(),
    }
}

/// sha256 of a body's bytes.
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    sha256(body)
}

/// The seal on an answer: `HMAC(K, h ‖ "response" ‖ 0x00 ‖ sha256(body))`, hex.
pub fn response_mac(key_hex: &str, h: u64, body_text: &str) -> Option<String> {
    let key = hex32(key_hex)?;
    Some(hex::encode(frame_mac(
        &key,
        h,
        HTTP_RESPONSE_EVENT,
        body_text,
    )))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn hex32(h: &str) -> Option<[u8; 32]> {
    let v = hex::decode(h).ok()?;
    if v.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Some(a)
}

fn is_hex_of(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// What the VERIFIED general message contributes to a lane: the session's
/// identity, the message's own nonce (`x-bsv-auth-nonce`) and the server's
/// session nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake<'a> {
    pub identity: &'a str,
    pub client_nonce: &'a str,
    pub server_nonce: &'a str,
}

/// One laned HTTP call as the door read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCall<'a> {
    pub h: u64,
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub body_digest: &'a [u8; 32],
    pub mac_hex: &'a str,
}

impl LaneRecord {
    /// Mint a lane for a proven handshake: `random` = 64 fresh bytes (32 the
    /// id, 32 the salt), the nonces the handshake's own.
    pub fn mint(
        label: &[u8],
        handshake: &Handshake<'_>,
        random: &[u8; 64],
        now_ms: u64,
        idle_ms: u64,
        ask: &str,
    ) -> (LaneRecord, LaneOffer) {
        let mut id = [0u8; 32];
        id.copy_from_slice(&random[..32]);
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&random[32..]);
        let key = derive_key(
            label,
            &salt,
            &id,
            handshake.client_nonce,
            handshake.server_nonce,
        );
        let expires_at_ms = now_ms.saturating_add(idle_ms);
        let record = LaneRecord {
            id: hex::encode(id),
            key: hex::encode(key),
            identity: handshake.identity.trim().to_ascii_lowercase(),
            expires_at_ms,
            last_h: 0,
            seen_mask: 0,
            minted_at_ms: now_ms,
        };
        let offer = LaneOffer {
            id: record.id.clone(),
            expires_at_ms,
            salt: hex::encode(salt),
            ask: ask.to_string(),
        };
        (record, offer)
    }

    /// Within the idle window AND the absolute lifetime (the same two bars
    /// `verify_http` judges).
    pub fn is_live(&self, now_ms: u64) -> bool {
        now_ms <= self.expires_at_ms
            && now_ms < self.minted_at_ms.saturating_add(LANE_MAX_LIFETIME_MS)
    }

    /// Verify one laned call: the window, the MAC over the method, the path
    /// and query and the body's digest; on success the counter is recorded
    /// and the idle window refreshed.
    pub fn verify_http(
        &mut self,
        call: &HttpCall<'_>,
        now_ms: u64,
        idle_ms: u64,
    ) -> Result<(), Refusal> {
        let h = call.h;
        if now_ms > self.expires_at_ms
            || now_ms > self.minted_at_ms.saturating_add(LANE_MAX_LIFETIME_MS)
        {
            return Err(Refusal::Expired);
        }
        if h == 0 || !self.counter_is_fresh(h) {
            return Err(Refusal::Replay);
        }
        let Some(key) = hex32(&self.key) else {
            return Err(Refusal::UnknownSession);
        };
        let Some(m) = hex32(call.mac_hex) else {
            return Err(Refusal::Malformed);
        };
        let e = http_event(call.method, call.path_and_query);
        let expected = frame_mac_over_digest(&key, h, &e, call.body_digest);
        if !constant_time_eq(&expected, &m) {
            return Err(Refusal::BadMac);
        }
        self.accept_counter(h);
        self.expires_at_ms = now_ms.saturating_add(idle_ms);
        Ok(())
    }

    /// The seal for an answer to the call that carried `h`.
    pub fn seal_response(&self, h: u64, body_text: &str) -> Option<String> {
        response_mac(&self.key, h, body_text)
    }

    fn counter_is_fresh(&self, h: u64) -> bool {
        if h > self.last_h {
            return true;
        }
        let back = self.last_h - h;
        if back >= HTTP_REPLAY_WINDOW {
            return false;
        }
        self.seen_mask & (1u64 << back) == 0
    }

    fn accept_counter(&mut self, h: u64) {
        if h > self.last_h {
            let shift = h - self.last_h;
            self.seen_mask = if shift >= 64 {
                0
            } else {
                self.seen_mask << shift
            };
            self.seen_mask |= 1;
            self.last_h = h;
        } else {
            self.seen_mask |= 1u64 << (self.last_h - h);
        }
    }
}

/// The lane headers of one request, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneRequest {
    pub id: String,
    pub identity: String,
    pub h: u64,
    pub mac: String,
}

/// `Ok(None)`: no `x-low-session` header — the reference path. `Ok(Some)`:
/// every part present and well-formed. `Err(Malformed)`: the id is present but
/// a part is missing or malformed (a refusal, never a silent fall-through:
/// the client asked for the lane and must learn why it was not served).
pub fn parse_lane_headers(
    id: Option<&str>,
    identity: Option<&str>,
    h: Option<&str>,
    mac: Option<&str>,
) -> Result<Option<LaneRequest>, Refusal> {
    let Some(id) = id.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if !is_hex_of(id, 64) {
        return Err(Refusal::Malformed);
    }
    let identity = identity
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !is_hex_of(&identity, 66) {
        return Err(Refusal::Malformed);
    }
    let Some(h) = h.and_then(|v| v.trim().parse::<u64>().ok()) else {
        return Err(Refusal::Malformed);
    };
    // 0.3.5 (the review's MED): the counter rides to the store as
    // a JSON number (`req.json()` = JSON.parse + serde-wasm-bindgen), which
    // faults above 2^53 — a crafted header would turn into an uncaught store
    // fault (a 503 the client retries) instead of a refusal by name.
    if h > MAX_SAFE_COUNTER {
        return Err(Refusal::Malformed);
    }
    let mac = mac.map(str::trim).unwrap_or_default().to_ascii_lowercase();
    if !is_hex_of(&mac, 64) {
        return Err(Refusal::Malformed);
    }
    Ok(Some(LaneRequest {
        id: id.to_ascii_lowercase(),
        identity,
        h,
        mac,
    }))
}

/// The handshake's ask, when well-formed: 1..=64 visible ASCII characters.
pub fn parse_ask(header: Option<&str>) -> Option<String> {
    let a = header?.trim();
    if a.is_empty() || a.len() > 64 || !a.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    Some(a.to_string())
}

/// The offer as its header carries it: base64 (standard, padded) of the JSON.
pub fn offer_header_value(offer: &LaneOffer) -> String {
    let json = serde_json::to_string(offer).unwrap_or_default();
    bsv_sdk::primitives::to_base64(json.as_bytes())
}

/// The inverse of [`offer_header_value`]; `None` for anything malformed.
pub fn parse_offer_header(value: Option<&str>) -> Option<LaneOffer> {
    let raw = value?.trim();
    if raw.is_empty() || raw.len() > 1024 {
        return None;
    }
    let bytes = bsv_sdk::primitives::from_base64(raw).ok()?;
    let offer: LaneOffer = serde_json::from_slice(&bytes).ok()?;
    let hex64 = |v: &str| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex64(&offer.id) || !hex64(&offer.salt) || offer.ask.is_empty() {
        return None;
    }
    Some(offer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CLIENT_NONCE: &str = "Y2xpZW50LW5vbmNlLWJhc2U2NA==";
    const SERVER_NONCE: &str = "c2VydmVyLW5vbmNlLWJhc2U2NA==";
    const ASK: &str = "a1b2c3d4e5f60718";

    fn fixed_random() -> [u8; 64] {
        let mut r = [0u8; 64];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        r
    }

    fn handshake() -> Handshake<'static> {
        Handshake {
            identity: IDENTITY,
            client_nonce: CLIENT_NONCE,
            server_nonce: SERVER_NONCE,
        }
    }

    fn minted() -> (LaneRecord, LaneOffer) {
        LaneRecord::mint(
            DEFAULT_LABEL,
            &handshake(),
            &fixed_random(),
            1_000,
            LANE_IDLE_MS,
            ASK,
        )
    }

    /// `verify_http` with the call's parts spelled out (the pins read better).
    fn verify(
        l: &mut LaneRecord,
        h: u64,
        method: &str,
        path: &str,
        digest: &[u8; 32],
        mac: &str,
        now_ms: u64,
    ) -> Result<(), Refusal> {
        l.verify_http(
            &HttpCall {
                h,
                method,
                path_and_query: path,
                body_digest: digest,
                mac_hex: mac,
            },
            now_ms,
            LANE_IDLE_MS,
        )
    }

    fn http_mac(l: &LaneRecord, h: u64, method: &str, path: &str, body: &str) -> String {
        let key = hex32(&l.key).unwrap();
        hex::encode(frame_mac(&key, h, &http_event(method, path), body))
    }

    fn digest(body: &str) -> [u8; 32] {
        body_digest(body.as_bytes())
    }

    #[test]
    fn mint_binds_the_identity_and_derives_k_from_the_label_the_salt_and_the_handshake_nonces() {
        let (lane, offer) = minted();
        assert_eq!(lane.identity, IDENTITY);
        assert_eq!(lane.id, offer.id);
        assert_eq!(lane.expires_at_ms, 1_000 + LANE_IDLE_MS);
        assert_eq!(offer.expires_at_ms, lane.expires_at_ms);
        assert_eq!(offer.ask, ASK);
        assert_eq!(lane.last_h, 0);
        let salt = hex32(&offer.salt).unwrap();
        let id = hex32(&offer.id).unwrap();
        let k = derive_key(DEFAULT_LABEL, &salt, &id, CLIENT_NONCE, SERVER_NONCE);
        assert_eq!(lane.key, hex::encode(k));
        // Every input moves K: the label, either nonce, the salt, the id.
        assert_ne!(
            hex::encode(derive_key(
                b"low-relay-session/v1",
                &salt,
                &id,
                CLIENT_NONCE,
                SERVER_NONCE
            )),
            lane.key
        );
        assert_ne!(
            hex::encode(derive_key(DEFAULT_LABEL, &salt, &id, "x", SERVER_NONCE)),
            lane.key
        );
        assert_ne!(
            hex::encode(derive_key(DEFAULT_LABEL, &salt, &id, CLIENT_NONCE, "y")),
            lane.key
        );
        assert_ne!(
            hex::encode(derive_key(
                DEFAULT_LABEL,
                &[1u8; 32],
                &id,
                CLIENT_NONCE,
                SERVER_NONCE
            )),
            lane.key
        );
        assert_ne!(
            hex::encode(derive_key(
                DEFAULT_LABEL,
                &salt,
                &[1u8; 32],
                CLIENT_NONCE,
                SERVER_NONCE
            )),
            lane.key
        );
        // The identity is normalized.
        let upper = IDENTITY.to_ascii_uppercase();
        let (l2, _) = LaneRecord::mint(
            DEFAULT_LABEL,
            &Handshake {
                identity: &upper,
                client_nonce: CLIENT_NONCE,
                server_nonce: SERVER_NONCE,
            },
            &fixed_random(),
            1,
            1,
            ASK,
        );
        assert_eq!(l2.identity, IDENTITY);
    }

    #[test]
    fn a_good_http_request_advances_h_binds_the_method_and_refreshes_the_window() {
        let (mut l, _) = minted();
        assert!(!l.is_live(l.expires_at_ms + 1));
        let body = "{\"scriptHex\":\"6a\"}";
        let mac = http_mac(&l, 1, "post", "/record?kind=result&identity=02aa", body);
        let now = 5_000;
        assert_eq!(
            verify(
                &mut l,
                1,
                "POST",
                "/record?kind=result&identity=02aa",
                &digest(body),
                &mac,
                now
            ),
            Ok(())
        );
        assert_eq!(l.last_h, 1);
        assert_eq!(l.expires_at_ms, now + LANE_IDLE_MS);
        // The method is bound (case-insensitively); the path is bound byte-for-byte.
        let mac7 = http_mac(&l, 7, "POST", "/cases?o=ab:0", "");
        assert_eq!(
            verify(&mut l, 7, "get", "/cases?o=ab:0", &digest(""), &mac7, now),
            Err(Refusal::BadMac)
        );
        let mac7 = http_mac(&l, 7, "GET", "/cases?o=ab:0", "");
        assert_eq!(
            verify(&mut l, 7, "get", "/cases?o=AB:0", &digest(""), &mac7, now),
            Err(Refusal::BadMac),
            "the query is bound byte-for-byte"
        );
        assert_eq!(
            verify(&mut l, 7, "get", "/cases?o=ab:0", &digest(""), &mac7, now),
            Ok(())
        );
        assert_eq!(l.last_h, 7);
    }

    #[test]
    fn a_replay_a_bad_mac_a_wrong_body_or_an_expired_lane_is_refused_and_changes_nothing() {
        let (mut l, _) = minted();
        let body = "{\"a\":1}";
        let mac = http_mac(&l, 3, "POST", "/proof", body);
        assert_eq!(
            verify(&mut l, 3, "POST", "/proof", &digest(body), &mac, 5_000),
            Ok(())
        );
        let before = l.clone();
        assert_eq!(
            verify(&mut l, 3, "POST", "/proof", &digest(body), &mac, 5_000),
            Err(Refusal::Replay)
        );
        assert_eq!(l, before, "a replay changes nothing");
        let mac4 = http_mac(&l, 4, "POST", "/proof", body);
        assert_eq!(
            verify(
                &mut l,
                4,
                "POST",
                "/proof",
                &digest("{\"a\":2}"),
                &mac4,
                5_000
            ),
            Err(Refusal::BadMac),
            "the body is bound"
        );
        let mut bad = mac4.clone();
        bad.replace_range(0..2, if &mac4[0..2] == "00" { "01" } else { "00" });
        assert_eq!(
            verify(&mut l, 4, "POST", "/proof", &digest(body), &bad, 5_000),
            Err(Refusal::BadMac)
        );
        assert_eq!(
            verify(&mut l, 4, "POST", "/proof", &digest(body), "zz", 5_000),
            Err(Refusal::Malformed)
        );
        assert_eq!(l, before, "a refusal changes nothing");
        let expired_at = l.expires_at_ms + 1;
        assert_eq!(
            verify(
                &mut l,
                4,
                "POST",
                "/proof",
                &digest(body),
                &mac4,
                expired_at
            ),
            Err(Refusal::Expired)
        );
        assert_eq!(
            verify(&mut l, 4, "POST", "/proof", &digest(body), &mac4, 6_000),
            Ok(())
        );
        assert_eq!(
            l.expires_at_ms,
            6_000 + LANE_IDLE_MS,
            "a valid call refreshes the idle window"
        );
    }

    #[test]
    fn http_counters_are_accepted_once_each_in_any_order_inside_the_window() {
        let (mut l, _) = minted();
        let body = "{}";
        let call = |l: &mut LaneRecord, h: u64| {
            let mac = http_mac(l, h, "GET", "/results?identity=02aa", body);
            verify(
                l,
                h,
                "GET",
                "/results?identity=02aa",
                &digest(body),
                &mac,
                5_000,
            )
        };
        assert_eq!(call(&mut l, 2), Ok(()));
        assert_eq!(call(&mut l, 1), Ok(()), "the late h=1 is accepted");
        assert_eq!(call(&mut l, 1), Err(Refusal::Replay), "but only once");
        assert_eq!(call(&mut l, 2), Err(Refusal::Replay));
        assert_eq!(call(&mut l, 5), Ok(()));
        assert_eq!(call(&mut l, 3), Ok(()));
        assert_eq!(call(&mut l, 4), Ok(()));
        assert_eq!(call(&mut l, 3), Err(Refusal::Replay));
        assert_eq!(l.last_h, 5);
        assert_eq!(call(&mut l, 100), Ok(()));
        assert_eq!(
            call(&mut l, 36),
            Err(Refusal::Replay),
            "64 behind is out of the window"
        );
        assert_eq!(call(&mut l, 37), Ok(()), "63 behind is inside it");
        assert_eq!(call(&mut l, 37), Err(Refusal::Replay));
        assert_eq!(
            call(&mut l, 0),
            Err(Refusal::Replay),
            "zero is never a counter"
        );
        let old = "{\"id\":\"a\",\"key\":\"b\",\"identity\":\"c\",\"expiresAtMs\":9,\"lastH\":3}";
        let parsed: LaneRecord = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.seen_mask, 0);
        assert_eq!(parsed.last_h, 3);
    }

    /// 0.3.5: the store persists the whole cell through the
    /// Durable Object's `storage().put`, whose serializer carries a `u64` as a
    /// JavaScript number and throws past 2^53; a full replay window reaches
    /// that on the 54th accepted call. The mask rides as a decimal string on
    /// the wire; a number (every pre-0.3.5 row) and a missing field still read.
    #[test]
    fn the_seen_mask_rides_as_a_string_so_a_full_window_survives_the_storage_boundary() {
        let (mut l, _) = minted();
        l.last_h = 70;
        l.seen_mask = u64::MAX - 5; // the high bit set: every slot of the window but two taken
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(
            v["seenMask"],
            serde_json::Value::String((u64::MAX - 5).to_string())
        );
        assert_eq!(
            v["lastH"],
            serde_json::Value::String("70".to_string()),
            "the counter rides as a string too"
        );
        let back: LaneRecord = serde_json::from_value(v).unwrap();
        assert_eq!(back, l);
        // a gap of 53 sets bit 53 on the SECOND accepted call (the review's finding 5)
        let (mut gap, _) = minted();
        let body = "{}";
        let call_gap = |l: &mut LaneRecord, h: u64| {
            let mac = http_mac(l, h, "GET", "/results?identity=02aa", body);
            verify(
                l,
                h,
                "GET",
                "/results?identity=02aa",
                &digest(body),
                &mac,
                5_000,
            )
        };
        assert_eq!(call_gap(&mut gap, 1), Ok(()));
        assert_eq!(call_gap(&mut gap, 54), Ok(()));
        assert!(gap.seen_mask >= (1u64 << 53), "bit 53 after one skip of 53");
        assert!(serde_json::to_value(&gap).unwrap()["seenMask"].is_string());
        // 54 accepted calls in a row set bit 53: the value the old shape could not put
        let (mut fresh, _) = minted();
        let body = "{}";
        let call = |l: &mut LaneRecord, h: u64| {
            let mac = http_mac(l, h, "GET", "/results?identity=02aa", body);
            verify(
                l,
                h,
                "GET",
                "/results?identity=02aa",
                &digest(body),
                &mac,
                5_000,
            )
        };
        for h in 1..=54u64 {
            assert_eq!(call(&mut fresh, h), Ok(()));
        }
        assert!(
            fresh.seen_mask >= (1u64 << 53),
            "the 54th accepted call sets bit 53"
        );
        assert!(
            fresh.seen_mask > 9_007_199_254_740_991,
            "past Number.MAX_SAFE_INTEGER"
        );
        let v = serde_json::to_value(&fresh).unwrap();
        assert!(v["seenMask"].is_string(), "a string, whatever the value");
        assert_eq!(serde_json::from_value::<LaneRecord>(v).unwrap(), fresh);
        // a row persisted before 0.3.5 carried numbers (small by construction)
        let mut old = serde_json::to_value(minted().0).unwrap();
        old["seenMask"] = serde_json::json!(4_503_599_627_370_495u64); // 2^52 - 1
        old["lastH"] = serde_json::json!(52u64);
        let parsed: LaneRecord = serde_json::from_value(old).unwrap();
        assert_eq!(parsed.seen_mask, 4_503_599_627_370_495u64);
        assert_eq!(parsed.last_h, 52);
        // a missing field is the default (the pre-window rows)
        let mut none = serde_json::to_value(minted().0).unwrap();
        none.as_object_mut().unwrap().remove("seenMask");
        let parsed: LaneRecord = serde_json::from_value(none).unwrap();
        assert_eq!(parsed.seen_mask, 0);
        // a string that is no number reads as a fault, never as a value
        let mut junk = serde_json::to_value(minted().0).unwrap();
        junk["seenMask"] = serde_json::json!("not-a-mask");
        assert!(serde_json::from_value::<LaneRecord>(junk).is_err());
    }

    /// The review's MED (0.3.5): a counter above `Number.MAX_SAFE_INTEGER` is
    /// refused BY NAME at the header, never carried to the store as a JSON
    /// number that faults there.
    #[test]
    fn a_counter_past_the_safe_integer_is_malformed_at_the_header() {
        let id = "ab".repeat(32);
        let mac = "cd".repeat(32);
        let ok = parse_lane_headers(
            Some(&id),
            Some(IDENTITY),
            Some("9007199254740991"),
            Some(&mac),
        );
        assert_eq!(ok.unwrap().unwrap().h, MAX_SAFE_COUNTER);
        assert_eq!(
            parse_lane_headers(
                Some(&id),
                Some(IDENTITY),
                Some("9007199254740992"),
                Some(&mac)
            ),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            parse_lane_headers(
                Some(&id),
                Some(IDENTITY),
                Some("18446744073709551615"),
                Some(&mac)
            ),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            parse_lane_headers(
                Some(&id),
                Some(IDENTITY),
                Some("18446744073709551616"),
                Some(&mac)
            ),
            Err(Refusal::Malformed),
            "past u64 was malformed already"
        );
    }

    #[test]
    fn the_response_seal_binds_the_requests_counter_and_the_body() {
        let (l, _) = minted();
        let a = l.seal_response(9, "{\"ok\":true}").unwrap();
        assert_ne!(a, l.seal_response(10, "{\"ok\":true}").unwrap());
        assert_ne!(a, l.seal_response(9, "{\"ok\":false}").unwrap());
        assert_eq!(a, response_mac(&l.key, 9, "{\"ok\":true}").unwrap());
        let key = hex32(&l.key).unwrap();
        assert_eq!(
            a,
            hex::encode(frame_mac(&key, 9, HTTP_RESPONSE_EVENT, "{\"ok\":true}"))
        );
        assert!(response_mac("not-hex", 1, "").is_none());
    }

    #[test]
    fn refusal_reasons_are_stable_wire_words() {
        for (r, w) in [
            (Refusal::UnknownSession, "unknown-session"),
            (Refusal::Expired, "expired"),
            (Refusal::Replay, "replay"),
            (Refusal::BadMac, "bad-mac"),
            (Refusal::Malformed, "malformed"),
        ] {
            assert_eq!(r.as_str(), w);
            assert_eq!(serde_json::to_string(&r).unwrap(), format!("\"{w}\""));
        }
    }

    #[test]
    fn lane_headers_parse_only_when_every_part_is_well_formed_and_absent_means_the_reference_path()
    {
        let id = "ab".repeat(32);
        let mac = "cd".repeat(32);
        assert_eq!(
            parse_lane_headers(None, Some(IDENTITY), Some("1"), Some(&mac)),
            Ok(None)
        );
        assert_eq!(
            parse_lane_headers(Some("  "), Some(IDENTITY), Some("1"), Some(&mac)),
            Ok(None)
        );
        let ok = parse_lane_headers(
            Some(&id.to_ascii_uppercase()),
            Some(&IDENTITY.to_ascii_uppercase()),
            Some(" 7 "),
            Some(&mac.to_ascii_uppercase()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            ok,
            LaneRequest {
                id: id.clone(),
                identity: IDENTITY.to_string(),
                h: 7,
                mac: mac.clone()
            }
        );
        assert_eq!(
            parse_lane_headers(Some("abc"), Some(IDENTITY), Some("1"), Some(&mac)),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            parse_lane_headers(Some(&id), None, Some("1"), Some(&mac)),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            parse_lane_headers(Some(&id), Some("02zz"), Some("1"), Some(&mac)),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            parse_lane_headers(Some(&id), Some(IDENTITY), None, Some(&mac)),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            parse_lane_headers(Some(&id), Some(IDENTITY), Some("x"), Some(&mac)),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            parse_lane_headers(Some(&id), Some(IDENTITY), Some("-1"), Some(&mac)),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            parse_lane_headers(Some(&id), Some(IDENTITY), Some("1"), None),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            parse_lane_headers(Some(&id), Some(IDENTITY), Some("1"), Some("zz")),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            parse_ask(Some(" a1b2c3d4e5f60718 ")).as_deref(),
            Some("a1b2c3d4e5f60718")
        );
        assert_eq!(parse_ask(None), None);
        assert_eq!(parse_ask(Some("")), None);
        assert_eq!(parse_ask(Some("has space")), None);
        assert_eq!(parse_ask(Some(&"a".repeat(65))), None);
        assert_eq!(
            path_and_query("/results", Some("identity=02aa")),
            "/results?identity=02aa"
        );
        assert_eq!(path_and_query("/results", Some("")), "/results");
        assert_eq!(path_and_query("/results", None), "/results");
    }

    const SESSION_LANE_VECTORS: &str = include_str!("../tests/fixtures/session_lane.vectors.json");
    const SESSION_LANE_VECTORS_SHA256: &str =
        "d4ad8ba0eb10798453df395fc1e265d535ea57a7d3b0f0fdf1822e35d4d44d39";

    #[test]
    fn session_lane_vectors_are_the_pinned_bytes_and_the_real_producer_re_derives_them() {
        let digest_hex = hex::encode(sha256(SESSION_LANE_VECTORS.as_bytes()));
        assert_eq!(
            digest_hex, SESSION_LANE_VECTORS_SHA256,
            "session_lane.vectors.json changed. It is a CROSS-REPO agreement: copy it to \
             the adopting client unchanged and update the constant in BOTH repos' tests."
        );
        let v: serde_json::Value = serde_json::from_str(SESSION_LANE_VECTORS).unwrap();
        let (lane, offer) = minted();
        assert_eq!(v["key"], lane.key);
        assert_eq!(v["id"], offer.id);
        assert_eq!(v["salt"], offer.salt);
        assert_eq!(v["label"], std::str::from_utf8(DEFAULT_LABEL).unwrap());
        assert_eq!(v["idleMs"], LANE_IDLE_MS);
        assert_eq!(v["ask"], ASK);
        let key = hex32(&lane.key).unwrap();
        let http = v["http"].as_array().expect("http[]");
        assert!(http.len() >= 4);
        for c in http {
            let h = c["h"].as_u64().unwrap();
            let method = c["method"].as_str().unwrap();
            let path = c["path"].as_str().unwrap();
            let body = c["body"].as_str().unwrap();
            assert_eq!(
                c["mac"],
                hex::encode(frame_mac(&key, h, &http_event(method, path), body)),
                "{method} {path}"
            );
            assert_eq!(
                c["responseMac"],
                response_mac(&lane.key, h, c["responseBody"].as_str().unwrap()).unwrap(),
                "response to {method} {path}"
            );
        }
        assert!(
            http.iter().any(|c| c["h"].as_u64() == Some(u64::MAX)),
            "the u64::MAX counter is pinned"
        );
    }

    /// The absolute lifetime (the 2026-09-14 gate LOW-5): refreshes keep the
    /// idle window moving, but 12 h after the mint every call is `expired`
    /// whatever the traffic; a record without a mint stamp is expired at once.
    #[test]
    fn a_lane_dies_at_its_absolute_lifetime_whatever_the_idle_refreshes() {
        let (mut lane, _offer) = minted();
        let key = hex32(&lane.key).unwrap();
        let digest = body_digest(b"");
        let call = |h: u64, now: u64, k: &[u8; 32]| {
            let e = http_event("GET", "/x");
            let mac = hex::encode(frame_mac_over_digest(k, h, &e, &digest));
            (mac, now)
        };
        // Refreshed every minute up to just under the lifetime: fine.
        let mut h = 1;
        let mut now = 1_000;
        while now + 60_000 < 1_000 + LANE_MAX_LIFETIME_MS {
            let (mac, _) = call(h, now, &key);
            lane.verify_http(
                &HttpCall {
                    h,
                    method: "GET",
                    path_and_query: "/x",
                    body_digest: &digest,
                    mac_hex: &mac,
                },
                now,
                LANE_IDLE_MS,
            )
            .expect("inside the lifetime");
            h += 1;
            now += 60_000;
        }
        // One minute past the lifetime, with the idle window still fresh: expired.
        let now = 1_000 + LANE_MAX_LIFETIME_MS + 60_000;
        let (mac, _) = call(h, now, &key);
        assert_eq!(
            lane.verify_http(
                &HttpCall {
                    h,
                    method: "GET",
                    path_and_query: "/x",
                    body_digest: &digest,
                    mac_hex: &mac
                },
                now,
                LANE_IDLE_MS
            ),
            Err(Refusal::Expired)
        );
        // A record without a mint stamp (pre-lifetime) reads as minted at 0: expired.
        let (mut old, _) = minted();
        old.minted_at_ms = 0;
        let (mac, _) = call(1, 1_000, &key);
        assert_eq!(
            old.verify_http(
                &HttpCall {
                    h: 1,
                    method: "GET",
                    path_and_query: "/x",
                    body_digest: &digest,
                    mac_hex: &mac
                },
                1_000 + LANE_MAX_LIFETIME_MS + 1,
                LANE_IDLE_MS
            ),
            Err(Refusal::Expired)
        );
    }

    /// The offer's carrier: a signable `x-bsv-` header, base64 JSON, round-tripped;
    /// junk refused; the handshake's response field is gone from the protocol.
    #[test]
    fn the_offer_rides_a_signable_header_and_round_trips() {
        assert!(
            LANE_OFFER_HEADER.starts_with("x-bsv-")
                && !LANE_OFFER_HEADER.starts_with("x-bsv-auth-")
        );
        let (_, offer) = minted();
        let value = offer_header_value(&offer);
        assert!(!value.contains('{'), "base64, never raw JSON");
        assert_eq!(parse_offer_header(Some(&value)), Some(offer.clone()));
        assert_eq!(parse_offer_header(None), None);
        assert_eq!(parse_offer_header(Some("")), None);
        assert_eq!(parse_offer_header(Some("not base64!!")), None);
        let short =
            bsv_sdk::primitives::to_base64(br#"{"id":"ab","expiresAt":1,"salt":"cd","ask":"a"}"#);
        assert_eq!(parse_offer_header(Some(&short)), None);
        assert_eq!(parse_offer_header(Some(&"A".repeat(2000))), None);
    }

    /// `cargo test session_lane::tests::emit_session_lane_vectors -- --ignored`
    /// rewrites the artifact from the fixed inputs; then update the sha256 pin
    /// above and copy the file to the adopting client unchanged.
    #[test]
    #[ignore = "writes tests/fixtures/session_lane.vectors.json on purpose"]
    fn emit_session_lane_vectors() {
        let (lane, offer) = minted();
        let key = hex32(&lane.key).unwrap();
        let http: Vec<serde_json::Value> = [
            (1u64, "GET", "/results?identity=02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&limit=20", "", "{\"identity\":\"02aa\",\"results\":[]}"),
            (2, "POST", "/record?kind=result&identity=02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "{\"scriptHex\":\"6a\"}", "{\"filed\":true,\"txid\":\"filed:00\"}"),
            (3, "GET", "/cases?o=ab:0,cd:1", "", "{\"cases\":[],\"unknown\":[]}"),
            (u64::MAX, "POST", "/proof?identity=02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "{\"v\":1}", "{\"ok\":true}"),
        ]
        .iter()
        .map(|(h, method, path, body, response)| {
            serde_json::json!({
                "h": h,
                "method": method,
                "path": path,
                "body": body,
                "mac": hex::encode(frame_mac(&key, *h, &http_event(method, path), body)),
                "responseBody": response,
                "responseMac": response_mac(&lane.key, *h, response).unwrap(),
            })
        })
        .collect();
        let v = serde_json::json!({
            "producer": "bsv-middleware-cloudflare src/middleware/session_lane.rs emit_session_lane_vectors (fixed inputs; regenerate, never retype)",
            "label": std::str::from_utf8(DEFAULT_LABEL).unwrap(),
            "idleMs": LANE_IDLE_MS,
            "clientNonce": CLIENT_NONCE,
            "serverNonce": SERVER_NONCE,
            "identity": IDENTITY,
            "ask": ASK,
            "salt": offer.salt,
            "id": offer.id,
            "key": lane.key,
            "http": http,
        });
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/session_lane.vectors.json"
        );
        std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")).unwrap();
        std::fs::write(path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    }
}

// ── The ATTESTED mint (2026-09-14) ─────────────────────
//
// A first-party door (the app-layer, the tower) mints a lane for an identity
// the RELAY's hub mirror proved, instead of a signed read: the client presents
// its hub-lane credentials in the BODY of `POST /lane/attest` (never the
// `x-low-session*` headers: the door's own lane verify would judge those
// against ITS store and refuse), the door asks the relay through its service
// binding (`POST /session/attest`, the hub's verify body verbatim), and on
// `ok` mints with `mint_attested_lane`. The MAC'd text is `attestJson` exactly
// as the client transmitted it (no canonicalisation, the relay lane's own
// rule); the door hashes that text and parses it. PURE here; the relay call
// and the mint are the door's.

/// The attest body's bounds (every string bounded; the JSON text bounded).
pub const ATTEST_JSON_MAX: usize = 1024;
/// The path the MAC covers (the door's route; the relay verifies the same text).
pub const ATTEST_PATH: &str = "/lane/attest";

/// The outer body of `POST /lane/attest`: the hub-lane credentials and the
/// MAC'd inner text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestBody {
    pub lane: AttestLane,
    /// The inner JSON TEXT the client MAC'd (`{"origin","ask","clientNonce"}`).
    #[serde(rename = "attestJson")]
    pub attest_json: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestLane {
    pub id: String,
    pub identity: String,
    pub h: u64,
    pub mac: String,
}
/// The inner text, parsed AFTER it was hashed verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestInner {
    pub origin: String,
    pub ask: String,
    #[serde(rename = "clientNonce")]
    pub client_nonce: String,
}
/// What the door forwards to the relay (`POST /session/attest`): the hub's
/// verify body verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestHubBody {
    pub id: String,
    pub identity: String,
    pub h: u64,
    pub method: String,
    pub path: String,
    #[serde(rename = "bodySha256")]
    pub body_sha256: String,
    pub mac: String,
}
/// The door's answer on a mint: the offer plus the door's fresh server nonce
/// (the client derives K from the offer, its `clientNonce` and this).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestAnswer {
    pub session: LaneOffer,
    #[serde(rename = "serverNonce")]
    pub server_nonce: String,
}

/// Why an attest body is refused before the relay is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestRefusal {
    Malformed,
    /// The inner text names another door.
    WrongOrigin,
}
impl AttestRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            AttestRefusal::Malformed => "malformed",
            AttestRefusal::WrongOrigin => "wrong-origin",
        }
    }
}

/// Parse and bound the outer body, hash the inner text VERBATIM, parse it,
/// bind it to `this_origin`, and produce the hub verify body. PURE.
pub fn prepare_attest(
    body_text: &str,
    this_origin: &str,
) -> std::result::Result<(AttestHubBody, AttestInner), AttestRefusal> {
    if body_text.len() > 4096 {
        return Err(AttestRefusal::Malformed);
    }
    let outer: AttestBody =
        serde_json::from_str(body_text).map_err(|_| AttestRefusal::Malformed)?;
    let hex_ok = |v: &str, n: usize| v.len() == n && v.bytes().all(|b| b.is_ascii_hexdigit());
    let lane_ok = hex_ok(&outer.lane.id, 64)
        && hex_ok(&outer.lane.identity, 66)
        && hex_ok(&outer.lane.mac, 64)
        && !outer.attest_json.is_empty()
        && outer.attest_json.len() <= ATTEST_JSON_MAX;
    if !lane_ok {
        return Err(AttestRefusal::Malformed);
    }
    let inner: AttestInner =
        serde_json::from_str(&outer.attest_json).map_err(|_| AttestRefusal::Malformed)?;
    let inner_ok =
        hex_ok(&inner.ask, 16) && hex_ok(&inner.client_nonce, 64) && inner.origin.len() <= 256;
    if !inner_ok {
        return Err(AttestRefusal::Malformed);
    }
    if !inner
        .origin
        .eq_ignore_ascii_case(this_origin.trim_end_matches('/'))
    {
        return Err(AttestRefusal::WrongOrigin);
    }
    let digest = sha256(outer.attest_json.as_bytes());
    Ok((
        AttestHubBody {
            id: outer.lane.id.to_ascii_lowercase(),
            identity: outer.lane.identity.to_ascii_lowercase(),
            h: outer.lane.h,
            method: "POST".to_string(),
            path: ATTEST_PATH.to_string(),
            body_sha256: hex::encode(digest),
            mac: outer.lane.mac.to_ascii_lowercase(),
        },
        inner,
    ))
}

#[cfg(test)]
mod attest_tests {
    use super::*;

    fn body(origin: &str) -> String {
        let inner = format!(
            r#"{{"origin":"{origin}","ask":"a1b2c3d4e5f60718","clientNonce":"{}"}}"#,
            "ab".repeat(32)
        );
        serde_json::json!({
            "lane": { "id": "cd".repeat(32), "identity": format!("02{}", "ef".repeat(32)), "h": 9, "mac": "01".repeat(32) },
            "attestJson": inner,
        })
        .to_string()
    }

    #[test]
    fn a_good_attest_hashes_the_inner_text_verbatim_and_names_the_door_s_route() {
        let (hub, inner) =
            prepare_attest(&body("https://door.test"), "https://door.test/").unwrap();
        assert_eq!(hub.method, "POST");
        assert_eq!(hub.path, ATTEST_PATH);
        assert_eq!(hub.h, 9);
        assert_eq!(hub.identity, format!("02{}", "ef".repeat(32)));
        let outer: AttestBody = serde_json::from_str(&body("https://door.test")).unwrap();
        assert_eq!(
            hub.body_sha256,
            hex::encode(sha256(outer.attest_json.as_bytes())),
            "the digest is over the transmitted text, never a re-serialisation"
        );
        assert_eq!(inner.ask, "a1b2c3d4e5f60718");
        assert_eq!(inner.origin, "https://door.test");
    }

    #[test]
    fn the_wrong_door_junk_and_oversize_are_refused_before_the_relay_is_asked() {
        assert_eq!(
            prepare_attest(&body("https://other.test"), "https://door.test").unwrap_err(),
            AttestRefusal::WrongOrigin
        );
        assert_eq!(
            prepare_attest("not json", "https://door.test").unwrap_err(),
            AttestRefusal::Malformed
        );
        let mut bad =
            serde_json::from_str::<serde_json::Value>(&body("https://door.test")).unwrap();
        bad["lane"]["mac"] = serde_json::json!("zz");
        assert_eq!(
            prepare_attest(&bad.to_string(), "https://door.test").unwrap_err(),
            AttestRefusal::Malformed
        );
        let mut long =
            serde_json::from_str::<serde_json::Value>(&body("https://door.test")).unwrap();
        long["attestJson"] = serde_json::json!("x".repeat(ATTEST_JSON_MAX + 1));
        assert_eq!(
            prepare_attest(&long.to_string(), "https://door.test").unwrap_err(),
            AttestRefusal::Malformed
        );
        let mut short_ask =
            serde_json::from_str::<serde_json::Value>(&body("https://door.test")).unwrap();
        short_ask["attestJson"] =
            serde_json::json!(r#"{"origin":"https://door.test","ask":"abc","clientNonce":"00"}"#);
        assert_eq!(
            prepare_attest(&short_ask.to_string(), "https://door.test").unwrap_err(),
            AttestRefusal::Malformed
        );
    }

    #[test]
    fn the_answer_carries_the_offer_and_the_server_nonce_by_the_wire_names() {
        let a = AttestAnswer {
            session: LaneOffer {
                id: "aa".repeat(32),
                expires_at_ms: 5,
                salt: "bb".repeat(32),
                ask: "a1b2c3d4e5f60718".into(),
            },
            server_nonce: "cc".repeat(32),
        };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(j["session"]["expiresAt"], 5);
        assert!(j["serverNonce"].is_string());
    }
}
