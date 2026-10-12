//! BRC-104: the HTTP shape of a BRC-103 message. Header names, the signed
//! request and response payloads, and the header pairs a message is sent as.
//! Pure bytes; a host reads its own request type into these and writes them
//! back out.

use bsv_sdk::auth::types::AuthMessage;

/// BRC-104 header names for authenticated requests.
pub mod auth_headers {
    /// Auth protocol version.
    pub const VERSION: &str = "x-bsv-auth-version";
    /// Sender's identity public key (hex, 66 chars compressed).
    pub const IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
    /// Sender's nonce (base64).
    pub const NONCE: &str = "x-bsv-auth-nonce";
    /// Initial nonce for handshake (base64).
    pub const INITIAL_NONCE: &str = "x-bsv-auth-initial-nonce";
    /// Recipient's nonce from previous message (base64).
    pub const YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
    /// Message signature (hex or base64).
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    /// Message type.
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
    /// Request ID for correlating requests/responses (base64, 32 bytes).
    pub const REQUEST_ID: &str = "x-bsv-auth-request-id";
    /// Requested certificates specification (JSON).
    pub const REQUESTED_CERTIFICATES: &str = "x-bsv-auth-requested-certificates";
}

/// Deserialized HTTP request data from General message payload.
#[derive(Debug, Clone)]
pub struct HttpRequestData {
    /// Request ID (32 bytes, for correlation).
    pub request_id: [u8; 32],
    /// HTTP method (GET, POST, PUT, DELETE, etc.).
    pub method: String,
    /// URL path (e.g., "/api/users").
    pub path: String,
    /// URL query string (e.g., "?foo=bar").
    pub search: String,
    /// HTTP headers (key-value pairs) - only signed headers.
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
}

impl HttpRequestData {
    /// Returns the combined URL (path + search).
    pub fn url(&self) -> String {
        format!("{}{}", self.path, self.search)
    }

    /// Serializes this HTTP request into payload bytes for an AuthMessage
    /// (see [`build_request_payload`]).
    pub fn to_payload(&self) -> Vec<u8> {
        build_request_payload(
            &self.request_id,
            &self.method,
            &self.path,
            &self.search,
            &self.headers,
            &self.body,
        )
    }
}

/// HTTP response data to be serialized as General message payload.
#[derive(Debug, Clone)]
pub struct HttpResponseData {
    /// Request ID (32 bytes, from the request).
    pub request_id: [u8; 32],
    /// HTTP status code.
    pub status: u16,
    /// HTTP headers (only x-bsv-* and authorization, excluding x-bsv-auth-*).
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

impl HttpResponseData {
    /// Serializes this HTTP response into payload bytes for an AuthMessage.
    ///
    /// Format: `[request_id: 32][status: varint][headers: varint+pairs][body: varint+bytes]`
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // Write request ID (32 bytes)
        payload.extend_from_slice(&self.request_id);

        // Write status (varint)
        payload.extend(write_varint(self.status as i64));

        // Write headers (varint count, then pairs)
        payload.extend(write_varint(self.headers.len() as i64));
        for (key, value) in &self.headers {
            let key_bytes = key.as_bytes();
            payload.extend(write_varint(key_bytes.len() as i64));
            payload.extend_from_slice(key_bytes);
            let val_bytes = value.as_bytes();
            payload.extend(write_varint(val_bytes.len() as i64));
            payload.extend_from_slice(val_bytes);
        }

        // Write body (varint length + bytes, or -1 if empty)
        if self.body.is_empty() {
            payload.extend(write_varint(-1));
        } else {
            payload.extend(write_varint(self.body.len() as i64));
            payload.extend_from_slice(&self.body);
        }

        payload
    }
}

/// The request headers a BRC-104 general message signs, from the request's
/// own headers (any order, any case), matching the reference
/// `SimplifiedFetchTransport` rules:
///
///   - headers starting with `x-bsv-` (but NOT `x-bsv-auth-*`)
///   - the `authorization` header
///   - the `content-type` header (value stripped to media type, no params)
///
/// Keys lowercased; sorted alphabetically by key.
pub fn signable_request_headers<I, K, V>(headers: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut signable: Vec<(String, String)> = Vec::new();
    for (key, value) in headers {
        let key_lower = key.as_ref().to_lowercase();
        let value = value.as_ref();
        if key_lower == "authorization"
            || (key_lower.starts_with("x-bsv-") && !key_lower.starts_with("x-bsv-auth-"))
        {
            signable.push((key_lower, value.to_string()));
        } else if key_lower == "content-type" {
            // Match TS SDK: include content-type but strip parameters (e.g. "; charset=utf-8")
            let media_type = value.split(';').next().unwrap_or(value).trim().to_string();
            signable.push((key_lower, media_type));
        }
    }
    signable.sort_by(|a, b| a.0.cmp(&b.0));
    signable
}

/// The response headers a BRC-104 general message signs, from the headers a
/// host means to send, matching the reference `SimplifiedFetchTransport`:
///
///   - include headers starting with `x-bsv-` (but NOT `x-bsv-auth-*`)
///   - include the `authorization` header
///   - exclude everything else
///
/// Keys lowercased; sorted alphabetically by key.
pub fn signable_response_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut signable: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(key, value)| {
            let lower = key.to_lowercase();
            if lower.starts_with("x-bsv-auth-") {
                None
            } else if lower.starts_with("x-bsv-") || lower == "authorization" {
                Some((lower, value.clone()))
            } else {
                None
            }
        })
        .collect();
    signable.sort_by(|a, b| a.0.cmp(&b.0));
    signable
}

/// The BRC-104 header pairs an [`AuthMessage`] is sent as: version,
/// identity key, message type, then each present field (nonce, initial
/// nonce, your nonce, signature as hex, requested certificates as JSON).
/// The request-id header is the host's to add.
pub fn message_to_headers(message: &AuthMessage) -> Vec<(String, String)> {
    let mut headers = Vec::new();

    headers.push((auth_headers::VERSION.to_string(), message.version.clone()));
    headers.push((
        auth_headers::IDENTITY_KEY.to_string(),
        message.identity_key.to_hex(),
    ));
    headers.push((
        auth_headers::MESSAGE_TYPE.to_string(),
        message.message_type.as_str().to_string(),
    ));

    if let Some(ref nonce) = message.nonce {
        headers.push((auth_headers::NONCE.to_string(), nonce.clone()));
    }

    if let Some(ref initial_nonce) = message.initial_nonce {
        headers.push((
            auth_headers::INITIAL_NONCE.to_string(),
            initial_nonce.clone(),
        ));
    }

    if let Some(ref your_nonce) = message.your_nonce {
        headers.push((auth_headers::YOUR_NONCE.to_string(), your_nonce.clone()));
    }

    if let Some(ref sig) = message.signature {
        headers.push((auth_headers::SIGNATURE.to_string(), hex::encode(sig)));
    }

    if let Some(ref requested) = message.requested_certificates {
        if let Ok(json) = serde_json::to_string(requested) {
            headers.push((auth_headers::REQUESTED_CERTIFICATES.to_string(), json));
        }
    }

    headers
}

/// Builds the payload for a general message request.
///
/// Format: `[request_id: 32][method][path or -1][search or -1][headers][body or -1]`,
/// every variable field varint-length-prefixed.
pub fn build_request_payload(
    request_id: &[u8; 32],
    method: &str,
    path: &str,
    search: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();

    // Write request ID (32 bytes)
    payload.extend_from_slice(request_id);

    // Write method
    let method_bytes = method.as_bytes();
    payload.extend(write_varint(method_bytes.len() as i64));
    payload.extend_from_slice(method_bytes);

    // Write path (or -1 if empty)
    if path.is_empty() {
        payload.extend(write_varint(-1));
    } else {
        let path_bytes = path.as_bytes();
        payload.extend(write_varint(path_bytes.len() as i64));
        payload.extend_from_slice(path_bytes);
    }

    // Write search (or -1 if empty)
    if search.is_empty() {
        payload.extend(write_varint(-1));
    } else {
        let search_bytes = search.as_bytes();
        payload.extend(write_varint(search_bytes.len() as i64));
        payload.extend_from_slice(search_bytes);
    }

    // Write headers
    payload.extend(write_varint(headers.len() as i64));
    for (key, value) in headers {
        let key_bytes = key.as_bytes();
        payload.extend(write_varint(key_bytes.len() as i64));
        payload.extend_from_slice(key_bytes);
        let val_bytes = value.as_bytes();
        payload.extend(write_varint(val_bytes.len() as i64));
        payload.extend_from_slice(val_bytes);
    }

    // Write body (or -1 if empty)
    if body.is_empty() {
        payload.extend(write_varint(-1));
    } else {
        payload.extend(write_varint(body.len() as i64));
        payload.extend_from_slice(body);
    }

    payload
}

/// Writes a Bitcoin-style varint.
///
/// This matches the TS SDK's Writer.writeVarIntNum / toVarInt:
/// - value < 0 (i.e. -1): 9 bytes of 0xFF (means "missing/empty")
/// - value < 253: single byte
/// - value < 0x10000: 0xFD + 2 bytes LE
/// - value < 0x100000000: 0xFE + 4 bytes LE
/// - else: 0xFF + 8 bytes LE
pub fn write_varint(value: i64) -> Vec<u8> {
    // Preserve the TS missing-value sentinel for every negative input.
    let value = if value < 0 { u64::MAX } else { value as u64 };
    let mut writer = bsv_sdk::primitives::encoding::Writer::new();
    writer.write_var_int(value);
    writer.into_bytes()
}

/// SHA-256 of the exact BRC-104 request payload without copying the body.
pub fn request_payload_digest(
    request_id: &[u8; 32],
    method: &str,
    path: &str,
    search: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut prefix = build_request_payload(request_id, method, path, search, headers, &[]);
    if !body.is_empty() {
        prefix.truncate(prefix.len() - write_varint(-1).len());
        prefix.extend(write_varint(body.len() as i64));
    }
    let mut hash = Sha256::new();
    hash.update(prefix);
    hash.update(body);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_sdk::auth::types::MessageType;
    use bsv_sdk::primitives::PrivateKey;

    fn test_key(hex: &str) -> bsv_sdk::primitives::PublicKey {
        PrivateKey::from_hex(hex).unwrap().public_key()
    }

    const SERVER_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    // ===========================================
    // Varint encoding tests
    // ===========================================

    #[test]
    fn test_varint_zero() {
        assert_eq!(write_varint(0), vec![0]);
    }

    #[test]
    fn test_varint_single_byte_small() {
        assert_eq!(write_varint(1), vec![1]);
        assert_eq!(write_varint(100), vec![100]);
        assert_eq!(write_varint(252), vec![252]);
    }

    #[test]
    fn test_varint_boundary_252() {
        assert_eq!(write_varint(252), vec![252]);
        assert_eq!(write_varint(253), vec![0xFD, 253, 0]);
    }

    #[test]
    fn test_varint_two_byte() {
        assert_eq!(write_varint(253), vec![0xFD, 0xFD, 0x00]);
        assert_eq!(write_varint(1000), vec![0xFD, 0xE8, 0x03]);
        assert_eq!(write_varint(65535), vec![0xFD, 0xFF, 0xFF]);
    }

    #[test]
    fn test_varint_four_byte() {
        assert_eq!(write_varint(65536), vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(write_varint(4294967295), vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_varint_eight_byte() {
        assert_eq!(
            write_varint(4294967296),
            vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_varint_negative_is_empty_marker() {
        assert_eq!(write_varint(-1), vec![0xFF; 9]);
    }

    // ===========================================
    // Response payload tests
    // ===========================================

    #[test]
    fn test_response_payload_empty_body() {
        let data = HttpResponseData {
            request_id: [0xAB; 32],
            status: 200,
            headers: vec![],
            body: vec![],
        };
        let payload = data.to_payload();
        assert_eq!(&payload[0..32], &[0xAB; 32]);
        assert_eq!(payload[32], 200);
        assert_eq!(payload[33], 0);
        assert_eq!(&payload[34..43], &[0xFF; 9]);
        assert_eq!(payload.len(), 43);
    }

    #[test]
    fn test_response_payload_with_body() {
        let data = HttpResponseData {
            request_id: [0; 32],
            status: 200,
            headers: vec![],
            body: b"hello".to_vec(),
        };
        let payload = data.to_payload();
        assert_eq!(payload[32], 200);
        assert_eq!(payload[33], 0);
        assert_eq!(payload[34], 5);
        assert_eq!(&payload[35..40], b"hello");
    }

    #[test]
    fn test_response_payload_with_headers() {
        let data = HttpResponseData {
            request_id: [0; 32],
            status: 402,
            headers: vec![("x-bsv-payment-satoshis-required".into(), "100".into())],
            body: vec![],
        };
        let payload = data.to_payload();
        assert_eq!(&payload[32..35], &[0xFD, 0x92, 0x01]);
        assert_eq!(payload[35], 1);
        let key = "x-bsv-payment-satoshis-required";
        assert_eq!(payload[36], key.len() as u8);
        assert_eq!(&payload[37..37 + key.len()], key.as_bytes());
        let after_key = 37 + key.len();
        assert_eq!(payload[after_key], 3);
        assert_eq!(&payload[after_key + 1..after_key + 4], b"100");
        assert_eq!(&payload[after_key + 4..after_key + 13], &[0xFF; 9]);
    }

    #[test]
    fn test_response_payload_status_codes() {
        for (status, expected) in [(200u16, vec![200u8]), (404, vec![0xFD, 0x94, 0x01])] {
            let data = HttpResponseData {
                request_id: [0; 32],
                status,
                headers: vec![],
                body: vec![],
            };
            let payload = data.to_payload();
            assert_eq!(
                &payload[32..32 + expected.len()],
                &expected[..],
                "status {status}"
            );
        }
    }

    // ===========================================
    // Request payload tests
    // ===========================================

    #[test]
    fn test_request_payload_get_request() {
        let request_id = [0x42; 32];
        let payload = build_request_payload(&request_id, "GET", "/api/test", "", &[], &[]);
        assert_eq!(&payload[0..32], &[0x42; 32]);
        assert_eq!(payload[32], 3);
        assert_eq!(&payload[33..36], b"GET");
        assert_eq!(payload[36], 9);
        assert_eq!(&payload[37..46], b"/api/test");
        assert_eq!(&payload[46..55], &[0xFF; 9]);
        assert_eq!(payload[55], 0);
        assert_eq!(&payload[56..65], &[0xFF; 9]);
        assert_eq!(payload.len(), 65);
    }

    #[test]
    fn test_request_payload_post_with_body() {
        let payload = build_request_payload(
            &[0; 32],
            "POST",
            "/api/data",
            "",
            &[],
            b"{\"key\":\"value\"}",
        );
        let body_start = payload.len() - 15;
        assert_eq!(payload[body_start - 1], 15);
        assert_eq!(&payload[body_start..], b"{\"key\":\"value\"}");
    }

    #[test]
    fn test_request_payload_with_query_params() {
        let payload =
            build_request_payload(&[0; 32], "GET", "/search", "?q=test&limit=10", &[], &[]);
        assert_eq!(payload[32], 3);
        assert_eq!(payload[36], 7);
        assert_eq!(payload[44], 16);
        assert_eq!(&payload[45..61], b"?q=test&limit=10");
    }

    #[test]
    fn test_request_payload_with_headers() {
        let headers = vec![("x-bsv-custom".to_string(), "value".to_string())];
        let payload = build_request_payload(&[0; 32], "GET", "/", "", &headers, &[]);
        assert_eq!(payload[32], 3);
        assert_eq!(payload[36], 1);
        assert_eq!(&payload[37..38], b"/");
        assert_eq!(&payload[38..47], &[0xFF; 9]);
        assert_eq!(payload[47], 1);
        assert_eq!(payload[48], 12);
        assert_eq!(&payload[49..61], b"x-bsv-custom");
        assert_eq!(payload[61], 5);
        assert_eq!(&payload[62..67], b"value");
    }

    #[test]
    fn test_http_request_data_payload_matches_the_builder() {
        let data = HttpRequestData {
            request_id: [7; 32],
            method: "POST".into(),
            path: "/x".into(),
            search: "?a=1".into(),
            headers: vec![("x-bsv-a".into(), "1".into())],
            body: b"body".to_vec(),
        };
        assert_eq!(data.url(), "/x?a=1");
        assert_eq!(
            data.to_payload(),
            build_request_payload(&[7; 32], "POST", "/x", "?a=1", &data.headers, b"body")
        );
        let bare = HttpRequestData {
            request_id: [0; 32],
            method: "GET".into(),
            path: "/".into(),
            search: String::new(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(bare.url(), "/");
    }

    // ===========================================
    // Signable header filters
    // ===========================================

    #[test]
    fn test_signable_request_headers_filter_sort_and_strip_content_type() {
        let raw = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("x-bsv-auth-nonce", "secret-not-signed"),
            ("X-BSV-Payment", "{}"),
            ("Authorization", "Bearer t"),
            ("accept", "*/*"),
            ("x-bsv-a", "1"),
        ];
        assert_eq!(
            signable_request_headers(raw),
            vec![
                ("authorization".to_string(), "Bearer t".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
                ("x-bsv-a".to_string(), "1".to_string()),
                ("x-bsv-payment".to_string(), "{}".to_string()),
            ]
        );
    }

    #[test]
    fn test_signable_response_headers_filter_and_sort() {
        let raw = vec![
            ("X-BSV-Payment-Satoshis-Paid".to_string(), "5".to_string()),
            ("x-bsv-auth-signature".to_string(), "no".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), "y".to_string()),
            ("x-bsv-a".to_string(), "1".to_string()),
        ];
        assert_eq!(
            signable_response_headers(&raw),
            vec![
                ("authorization".to_string(), "y".to_string()),
                ("x-bsv-a".to_string(), "1".to_string()),
                ("x-bsv-payment-satoshis-paid".to_string(), "5".to_string()),
            ],
            "content-type is NOT signed on a response"
        );
    }

    // ===========================================
    // message_to_headers tests
    // ===========================================

    #[test]
    fn test_message_to_headers_initial_response() {
        let mut msg = AuthMessage::new(MessageType::InitialResponse, test_key(SERVER_KEY_HEX));
        msg.nonce = Some("server-nonce".to_string());
        msg.initial_nonce = Some("server-nonce".to_string());
        msg.your_nonce = Some("client-nonce".to_string());
        msg.signature = Some(vec![0xDE, 0xAD]);
        let headers = message_to_headers(&msg);
        let get = |k: &str| {
            headers
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get(auth_headers::VERSION), Some(msg.version.as_str()));
        assert_eq!(
            get(auth_headers::IDENTITY_KEY),
            Some(msg.identity_key.to_hex().as_str())
        );
        assert_eq!(get(auth_headers::MESSAGE_TYPE), Some("initialResponse"));
        assert_eq!(get(auth_headers::NONCE), Some("server-nonce"));
        assert_eq!(get(auth_headers::INITIAL_NONCE), Some("server-nonce"));
        assert_eq!(get(auth_headers::YOUR_NONCE), Some("client-nonce"));
        assert_eq!(get(auth_headers::SIGNATURE), Some("dead"));
        assert_eq!(get(auth_headers::REQUESTED_CERTIFICATES), None);
    }

    #[test]
    fn test_message_to_headers_general_and_excludes_none_fields() {
        let mut msg = AuthMessage::new(MessageType::General, test_key(SERVER_KEY_HEX));
        msg.nonce = Some("n".to_string());
        let headers = message_to_headers(&msg);
        let keys: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                auth_headers::VERSION,
                auth_headers::IDENTITY_KEY,
                auth_headers::MESSAGE_TYPE,
                auth_headers::NONCE
            ]
        );
        assert_eq!(headers[2].1, "general");
    }

    #[test]
    fn test_auth_header_constants() {
        assert_eq!(auth_headers::VERSION, "x-bsv-auth-version");
        assert_eq!(auth_headers::IDENTITY_KEY, "x-bsv-auth-identity-key");
        assert_eq!(auth_headers::NONCE, "x-bsv-auth-nonce");
        assert_eq!(auth_headers::INITIAL_NONCE, "x-bsv-auth-initial-nonce");
        assert_eq!(auth_headers::YOUR_NONCE, "x-bsv-auth-your-nonce");
        assert_eq!(auth_headers::SIGNATURE, "x-bsv-auth-signature");
        assert_eq!(auth_headers::MESSAGE_TYPE, "x-bsv-auth-message-type");
        assert_eq!(auth_headers::REQUEST_ID, "x-bsv-auth-request-id");
        assert_eq!(
            auth_headers::REQUESTED_CERTIFICATES,
            "x-bsv-auth-requested-certificates"
        );
    }
    #[test]
    fn incremental_request_digest_matches_wire_payload() {
        use sha2::{Digest, Sha256};
        let headers = vec![("content-type".into(), "multipart/form-data".into())];
        for size in [0, 1, 252, 253, 65535, 65536, 1_000_000] {
            let body = vec![7; size];
            let payload = build_request_payload(&[3; 32], "POST", "/pay", "?q=1", &headers, &body);
            assert_eq!(
                request_payload_digest(&[3; 32], "POST", "/pay", "?q=1", &headers, &body),
                <[u8; 32]>::from(Sha256::digest(payload))
            );
        }
    }
}
