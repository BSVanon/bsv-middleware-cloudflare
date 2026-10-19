//! The session lane's test suite, kept by the adapter after the rules moved
//! to `bsv_middleware_core::session_lane` (0.4.0): the SAME tests, run
//! against the re-exported path, are the proof that the 0.3 surface is still
//! the 0.3 surface, and the adapter's own vector fixture
//! (`tests/fixtures/session_lane.vectors.json`) stays pinned here. The core
//! runs the same suite against its own copy.

mod tests {
    use crate::middleware::session_lane::*;
    use bsv_sdk::primitives::hash::sha256;

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

    const SESSION_LANE_VECTORS: &str =
        include_str!("../../tests/fixtures/session_lane.vectors.json");
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

mod attest_tests {
    use crate::middleware::session_lane::*;
    use bsv_sdk::primitives::hash::sha256;

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
