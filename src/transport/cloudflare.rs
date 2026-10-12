//! Cloudflare Workers transport implementation for BRC-103/104.
//!
//! This module provides utilities for extracting and constructing BRC-104
//! authenticated HTTP requests and responses in Cloudflare Workers. The
//! wire shapes (header names, the signed request and response payloads, the
//! header pairs a message is sent as) are `bsv_middleware_core::brc104`,
//! re-exported here at their 0.3 paths; what stays is the reading of a
//! `worker::Request` into them.

use crate::error::{AuthCloudflareError, Result};
use bsv_sdk::auth::types::{AuthMessage, MessageType, AUTH_VERSION};
use bsv_sdk::primitives::{from_base64, PublicKey};
use worker::{Headers, Request};

pub use bsv_middleware_core::brc104::{auth_headers, HttpRequestData, HttpResponseData};
use bsv_middleware_core::brc104::{
    build_request_payload, message_to_headers, request_payload_digest, signable_request_headers,
};

/// Transport utilities for Cloudflare Workers.
///
/// This provides static methods for working with BRC-104 authenticated
/// HTTP requests in Cloudflare Workers.
pub struct CloudflareTransport;

impl CloudflareTransport {
    /// Checks if the request has BRC-104 auth headers.
    pub fn has_auth_headers(req: &Request) -> bool {
        req.headers()
            .get(auth_headers::REQUEST_ID)
            .ok()
            .flatten()
            .is_some()
            || req
                .headers()
                .get(auth_headers::MESSAGE_TYPE)
                .ok()
                .flatten()
                .is_some()
    }

    /// Checks if this is a handshake request (POST to /.well-known/auth).
    pub fn is_handshake_request(req: &Request) -> bool {
        req.path().ends_with("/.well-known/auth")
    }

    /// Extracts the identity key from request headers.
    pub fn get_identity_key(req: &Request) -> Result<String> {
        req.headers()
            .get(auth_headers::IDENTITY_KEY)
            .ok()
            .flatten()
            .ok_or_else(|| {
                AuthCloudflareError::InvalidAuthentication("Missing identity key header".into())
            })
    }

    /// Extracts the request ID from headers.
    pub fn get_request_id(req: &Request) -> Result<[u8; 32]> {
        let request_id_str = req
            .headers()
            .get(auth_headers::REQUEST_ID)
            .ok()
            .flatten()
            .ok_or_else(|| {
                AuthCloudflareError::InvalidAuthentication("Missing request ID header".into())
            })?;

        let bytes = from_base64(&request_id_str).map_err(|e| {
            AuthCloudflareError::InvalidAuthentication(format!("Invalid request ID: {}", e))
        })?;

        if bytes.len() != 32 {
            return Err(AuthCloudflareError::InvalidAuthentication(
                "Request ID must be 32 bytes".into(),
            ));
        }

        let mut request_id = [0u8; 32];
        request_id.copy_from_slice(&bytes);
        Ok(request_id)
    }

    /// Builds an AuthMessage from a Cloudflare Worker request.
    ///
    /// For handshake messages, the body is parsed as JSON.
    /// For general messages, the body is included as payload with HTTP metadata.
    ///
    /// Returns `(AuthMessage, Vec<u8>)` where the second element is the raw request
    /// body bytes. For General messages this is the body consumed during auth payload
    /// construction. For handshake messages this is empty (handshake body is protocol JSON).
    pub async fn extract_auth_message(req: &mut Request) -> Result<(AuthMessage, Vec<u8>)> {
        let (message, body, _) = Self::extract_auth_message_inner(req, false).await?;
        Ok((message, body))
    }

    /// Extract a message and one owned body, hashing its signed frame incrementally.
    /// General messages have no payload copy; verify the returned digest.
    pub async fn extract_auth_message_digest(
        req: &mut Request,
    ) -> Result<(AuthMessage, Vec<u8>, Option<[u8; 32]>)> {
        Self::extract_auth_message_inner(req, true).await
    }

    async fn extract_auth_message_inner(
        req: &mut Request,
        digest_only: bool,
    ) -> Result<(AuthMessage, Vec<u8>, Option<[u8; 32]>)> {
        let mut digest = None;
        // Extract header values first before consuming the body
        let version = req
            .headers()
            .get(auth_headers::VERSION)
            .ok()
            .flatten()
            .unwrap_or_else(|| AUTH_VERSION.to_string());

        let identity_key_hex = req
            .headers()
            .get(auth_headers::IDENTITY_KEY)
            .ok()
            .flatten()
            .ok_or_else(|| {
                AuthCloudflareError::InvalidAuthentication("Missing identity key header".into())
            })?;

        let message_type_str = req
            .headers()
            .get(auth_headers::MESSAGE_TYPE)
            .ok()
            .flatten()
            .unwrap_or_else(|| "general".to_string());

        let nonce = req.headers().get(auth_headers::NONCE).ok().flatten();
        let initial_nonce = req
            .headers()
            .get(auth_headers::INITIAL_NONCE)
            .ok()
            .flatten();
        let your_nonce = req.headers().get(auth_headers::YOUR_NONCE).ok().flatten();
        let sig_str = req.headers().get(auth_headers::SIGNATURE).ok().flatten();
        let certs_json = req
            .headers()
            .get(auth_headers::REQUESTED_CERTIFICATES)
            .ok()
            .flatten();

        // Get request metadata for general messages
        let method = req.method().to_string();
        let full_url = req.url().map_err(|e| {
            AuthCloudflareError::TransportError(format!("Failed to parse URL: {}", e))
        })?;
        let request_id = Self::get_request_id(req).unwrap_or([0u8; 32]);

        // Parse identity key
        let identity_key = PublicKey::from_hex(&identity_key_hex).map_err(|e| {
            AuthCloudflareError::InvalidAuthentication(format!("Invalid identity key: {}", e))
        })?;

        // Parse message type
        let message_type = MessageType::from_str(&message_type_str).ok_or_else(|| {
            AuthCloudflareError::InvalidAuthentication(format!(
                "Invalid message type: {}",
                message_type_str
            ))
        })?;

        // Build base message
        let mut msg = AuthMessage::new(message_type, identity_key);
        msg.version = version;
        msg.nonce = nonce;
        msg.initial_nonce = initial_nonce;
        msg.your_nonce = your_nonce;

        // Parse signature
        if let Some(sig) = sig_str {
            msg.signature = hex::decode(&sig).or_else(|_| from_base64(&sig)).ok();
        }

        // Parse requested certificates
        if let Some(json) = certs_json {
            msg.requested_certificates = serde_json::from_str(&json).ok();
        }

        // Handle body based on message type
        let raw_body_bytes;
        if message_type == MessageType::General {
            // For general messages, build payload from HTTP request
            let body = req
                .bytes()
                .await
                .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?;

            // Capture raw body bytes for passthrough to handlers

            let search = full_url
                .query()
                .map(|q| format!("?{}", q))
                .unwrap_or_default();

            // Extract signable headers from the request.
            // Must match SimplifiedFetchTransport rules: include x-bsv-* (excluding
            // x-bsv-auth-*) and authorization, sorted alphabetically by key.
            let signable_headers = signable_request_headers(req.headers());

            // Build payload with HTTP metadata
            if digest_only {
                digest = Some(request_payload_digest(
                    &request_id,
                    &method,
                    full_url.path(),
                    &search,
                    &signable_headers,
                    &body,
                ));
            } else {
                let payload = build_request_payload(
                    &request_id,
                    &method,
                    full_url.path(),
                    &search,
                    &signable_headers,
                    &body,
                );
                msg.payload = Some(payload);
            }
            raw_body_bytes = body;
        } else {
            // For handshake messages, body is JSON (not passed through)
            raw_body_bytes = vec![];

            let body_text = req
                .text()
                .await
                .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?;

            if !body_text.is_empty() {
                // Parse as JSON and merge fields
                if let Ok(json_msg) = serde_json::from_str::<AuthMessage>(&body_text) {
                    // Merge fields from JSON body
                    if json_msg.nonce.is_some() {
                        msg.nonce = json_msg.nonce;
                    }
                    if json_msg.initial_nonce.is_some() {
                        msg.initial_nonce = json_msg.initial_nonce;
                    }
                    if json_msg.your_nonce.is_some() {
                        msg.your_nonce = json_msg.your_nonce;
                    }
                    if json_msg.signature.is_some() {
                        msg.signature = json_msg.signature;
                    }
                    if json_msg.certificates.is_some() {
                        msg.certificates = json_msg.certificates;
                    }
                    if json_msg.requested_certificates.is_some() {
                        msg.requested_certificates = json_msg.requested_certificates;
                    }
                }
            }
        }

        Ok((msg, raw_body_bytes, digest))
    }

    /// Builds response headers from an AuthMessage
    /// (`bsv_middleware_core::brc104::message_to_headers`).
    pub fn message_to_headers(message: &AuthMessage) -> Vec<(String, String)> {
        message_to_headers(message)
    }

    /// Creates Worker response headers from a list of header pairs.
    pub fn create_headers(pairs: &[(String, String)]) -> Headers {
        let headers = Headers::new();
        for (key, value) in pairs {
            let _ = headers.set(key, value);
        }
        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_middleware_core::brc104::{build_request_payload, write_varint};

    // ===========================================
    // Varint encoding tests
    // ===========================================

    #[test]
    fn test_varint_zero() {
        assert_eq!(write_varint(0), vec![0x00]);
    }

    #[test]
    fn test_varint_single_byte_small() {
        assert_eq!(write_varint(1), vec![0x01]);
        assert_eq!(write_varint(100), vec![100]);
        assert_eq!(write_varint(252), vec![252]);
    }

    #[test]
    fn test_varint_boundary_252() {
        // 252 should still be single byte
        assert_eq!(write_varint(252), vec![252]);
    }

    #[test]
    fn test_varint_two_byte() {
        // 253 is the boundary for 2-byte encoding
        assert_eq!(write_varint(253), vec![0xFD, 253, 0]);
        assert_eq!(write_varint(256), vec![0xFD, 0, 1]);
        assert_eq!(write_varint(0xFFFF), vec![0xFD, 0xFF, 0xFF]);
    }

    #[test]
    fn test_varint_four_byte() {
        // 0x10000 is the boundary for 4-byte encoding
        assert_eq!(write_varint(0x10000), vec![0xFE, 0, 0, 1, 0]);
        assert_eq!(
            write_varint(0xFFFFFFFF_i64),
            vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn test_varint_eight_byte() {
        // Values >= 0x100000000 use 8-byte encoding
        let result = write_varint(0x100000000_i64);
        assert_eq!(result.len(), 9);
        assert_eq!(result[0], 0xFF);
        assert_eq!(result[1..], [0, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn test_varint_negative_is_empty_marker() {
        // -1 means "empty/missing" in the protocol
        let result = write_varint(-1);
        assert_eq!(result.len(), 9);
        assert!(result.iter().all(|&b| b == 0xFF));
    }

    // ===========================================
    // Response payload serialization tests
    // ===========================================

    #[test]
    fn test_response_payload_empty_body() {
        let response_data = HttpResponseData {
            request_id: [0u8; 32],
            status: 200,
            headers: vec![],
            body: vec![],
        };
        let payload = response_data.to_payload();

        // 32 bytes request_id + varint(200) + varint(0) headers + varint(-1) empty body
        assert!(payload.len() > 32);

        // First 32 bytes are request_id
        assert_eq!(&payload[0..32], &[0u8; 32]);

        // Status 200 as varint: 0xFD, 200, 0 (since 200 < 253, it's single byte)
        assert_eq!(payload[32], 200);

        // Headers count: 0
        assert_eq!(payload[33], 0);

        // Body: empty marker (-1) = 9 bytes of 0xFF
        assert_eq!(&payload[34..43], &[0xFF; 9]);
    }

    #[test]
    fn test_response_payload_with_body() {
        let body = b"Hello, World!";
        let response_data = HttpResponseData {
            request_id: [1u8; 32],
            status: 200,
            headers: vec![],
            body: body.to_vec(),
        };
        let payload = response_data.to_payload();

        // First 32 bytes are request_id
        assert_eq!(&payload[0..32], &[1u8; 32]);

        // Status: 200 (single byte varint)
        assert_eq!(payload[32], 200);

        // Headers count: 0
        assert_eq!(payload[33], 0);

        // Body length: 13 (single byte varint)
        assert_eq!(payload[34], 13);

        // Body content
        assert_eq!(&payload[35..48], body);
    }

    #[test]
    fn test_response_payload_with_headers() {
        let response_data = HttpResponseData {
            request_id: [0u8; 32],
            status: 404,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: vec![],
        };
        let payload = response_data.to_payload();

        // Verify request_id
        assert_eq!(&payload[0..32], &[0u8; 32]);

        // Status: 404 is > 253 so it's 0xFD + 2 bytes LE
        assert_eq!(payload[32], 0xFD);
        assert_eq!(payload[33], 0x94); // 404 & 0xFF = 148 = 0x94
        assert_eq!(payload[34], 0x01); // 404 >> 8 = 1

        // Headers count: 1
        assert_eq!(payload[35], 1);

        // Key: "content-type" (12 bytes)
        assert_eq!(payload[36], 12);
        assert_eq!(&payload[37..49], b"content-type");

        // Value: "application/json" (16 bytes)
        assert_eq!(payload[49], 16);
        assert_eq!(&payload[50..66], b"application/json");
    }

    #[test]
    fn test_response_payload_status_codes() {
        // Test various status codes encode correctly
        for status in [200u16, 201, 204, 400, 401, 402, 404, 500] {
            let response_data = HttpResponseData {
                request_id: [0u8; 32],
                status,
                headers: vec![],
                body: vec![],
            };
            let payload = response_data.to_payload();
            // Should produce valid payload for any status code
            assert!(payload.len() >= 32 + 1 + 1 + 9); // min: request_id + status + headers + body
        }
    }

    // ===========================================
    // Request payload serialization tests
    // ===========================================

    #[test]
    fn test_request_payload_get_request() {
        let request_id = [42u8; 32];
        let payload = build_request_payload(&request_id, "GET", "/api/data", "", &[], &[]);

        // Check request_id
        assert_eq!(&payload[0..32], &[42u8; 32]);

        // Check method: "GET" = 3 bytes
        assert_eq!(payload[32], 3); // length varint
        assert_eq!(&payload[33..36], b"GET");

        // Check path: "/api/data" = 9 bytes
        assert_eq!(payload[36], 9);
        assert_eq!(&payload[37..46], b"/api/data");

        // Check search: empty = varint(-1)
        assert_eq!(&payload[46..55], &[0xFF; 9]);
    }

    #[test]
    fn test_request_payload_post_with_body() {
        let request_id = [0u8; 32];
        let body = b"{\"key\":\"value\"}";
        let payload = build_request_payload(&request_id, "POST", "/api/create", "", &[], body);

        // Should contain the body
        assert!(payload.len() > 32 + 4 + 11); // request_id + method + path min
                                              // Body should be in the payload (not as -1 empty marker)
        let payload_str = String::from_utf8_lossy(&payload);
        assert!(payload_str.contains("key"));
    }

    #[test]
    fn test_request_payload_with_query_params() {
        let request_id = [0u8; 32];
        let payload =
            build_request_payload(&request_id, "GET", "/search", "?q=test&page=1", &[], &[]);

        // Verify search string is included (not -1 empty marker)
        let payload_str = String::from_utf8_lossy(&payload);
        assert!(payload_str.contains("q=test"));
    }

    #[test]
    fn test_request_payload_with_headers() {
        let request_id = [0u8; 32];
        let headers = vec![
            ("x-bsv-test".to_string(), "value1".to_string()),
            ("authorization".to_string(), "Bearer token".to_string()),
        ];
        let payload = build_request_payload(&request_id, "GET", "/api", "", &headers, &[]);

        let payload_str = String::from_utf8_lossy(&payload);
        assert!(payload_str.contains("x-bsv-test"));
        assert!(payload_str.contains("value1"));
        assert!(payload_str.contains("authorization"));
    }

    // ===========================================
    // message_to_headers tests
    // ===========================================

    #[test]
    fn test_message_to_headers_initial_response() {
        let pk = bsv_sdk::primitives::PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let identity_key = pk.public_key();

        let mut msg = AuthMessage::new(MessageType::InitialResponse, identity_key.clone());
        msg.nonce = Some("server-nonce".to_string());
        msg.initial_nonce = Some("server-nonce".to_string());
        msg.your_nonce = Some("client-nonce".to_string());
        msg.signature = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let headers = CloudflareTransport::message_to_headers(&msg);

        // Should include version, identity_key, message_type, nonce, initial_nonce, your_nonce, signature
        let header_map: std::collections::HashMap<&str, &str> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(header_map[auth_headers::VERSION], AUTH_VERSION);
        assert_eq!(
            header_map[auth_headers::IDENTITY_KEY],
            identity_key.to_hex()
        );
        assert_eq!(header_map[auth_headers::MESSAGE_TYPE], "initialResponse");
        assert_eq!(header_map[auth_headers::NONCE], "server-nonce");
        assert_eq!(header_map[auth_headers::INITIAL_NONCE], "server-nonce");
        assert_eq!(header_map[auth_headers::YOUR_NONCE], "client-nonce");
        assert_eq!(header_map[auth_headers::SIGNATURE], "deadbeef");
    }

    #[test]
    fn test_message_to_headers_general() {
        let pk = bsv_sdk::primitives::PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let identity_key = pk.public_key();

        let msg = AuthMessage::new(MessageType::General, identity_key);
        let headers = CloudflareTransport::message_to_headers(&msg);

        let header_map: std::collections::HashMap<&str, &str> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(header_map[auth_headers::MESSAGE_TYPE], "general");
        // Nonce/your_nonce should not be present since they're None
        assert!(!header_map.contains_key(auth_headers::NONCE));
        assert!(!header_map.contains_key(auth_headers::YOUR_NONCE));
    }

    #[test]
    fn test_message_to_headers_excludes_none_fields() {
        let pk = bsv_sdk::primitives::PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let msg = AuthMessage::new(MessageType::General, pk.public_key());
        let headers = CloudflareTransport::message_to_headers(&msg);

        // Only version, identity_key, message_type should be present
        assert_eq!(headers.len(), 3);
    }

    // ===========================================
    // Header constant tests
    // ===========================================

    #[test]
    fn test_auth_header_constants() {
        // Verify header names match BRC-104 spec exactly
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

    // ===========================================
    // HttpRequestData tests
    // ===========================================

    #[test]
    fn test_http_request_data_url() {
        let data = HttpRequestData {
            request_id: [0u8; 32],
            method: "GET".to_string(),
            path: "/api/data".to_string(),
            search: "?page=1".to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(data.url(), "/api/data?page=1");
    }

    #[test]
    fn test_http_request_data_url_no_search() {
        let data = HttpRequestData {
            request_id: [0u8; 32],
            method: "GET".to_string(),
            path: "/api/data".to_string(),
            search: "".to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(data.url(), "/api/data");
    }
}
