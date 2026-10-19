//! Middleware implementations for authentication and payment.

pub mod auth;
pub mod multipart;
pub mod payment;
pub mod session_lane;
#[cfg(test)]
mod session_lane_tests;

pub use auth::{
    add_lane_cors_headers, process_auth, process_auth_do, process_auth_lane,
    process_auth_lane_with_storage, request_presents_lane, seal_lane_response, sign_json_response,
    sign_response, AuthMiddlewareOptions, AuthResult, AuthSession, LaneAuth, LaneAuthResult,
    SessionLaneOptions,
};
#[allow(deprecated)]
pub use multipart::prepare_multipart_payment;
#[allow(deprecated)]
pub use payment::{
    payment_headers, process_payment_with_storage, process_payment_with_storage_signed,
    PaymentMiddlewareOptions, PaymentResult, PAYMENT_NONCE_SCOPE,
};
