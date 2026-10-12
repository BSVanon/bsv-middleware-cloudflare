//! Environment wrapper for Cloudflare Workers secrets and bindings.

use crate::error::{AuthCloudflareError, Result};
use worker::Env;

/// Helper for accessing Cloudflare Workers environment bindings.
pub struct WorkerEnv<'a> {
    env: &'a Env,
}

impl<'a> WorkerEnv<'a> {
    /// Creates a new WorkerEnv wrapper.
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    /// Gets the server private key from secrets.
    ///
    /// The secret should be named `SERVER_PRIVATE_KEY` and contain a 64-character
    /// hexadecimal string representing a secp256k1 private key.
    pub fn get_server_private_key(&self) -> Result<String> {
        self.env
            .secret("SERVER_PRIVATE_KEY")
            .map(|s| s.to_string())
            .map_err(|_| {
                AuthCloudflareError::ConfigError(
                    "SERVER_PRIVATE_KEY secret not configured".to_string(),
                )
            })
    }

    /// Gets the AUTH_SESSIONS KV namespace.
    pub fn get_auth_sessions_kv(&self) -> Result<worker::kv::KvStore> {
        self.env.kv("AUTH_SESSIONS").map_err(|e| {
            AuthCloudflareError::ConfigError(format!("AUTH_SESSIONS KV not bound: {}", e))
        })
    }

    /// Gets the PAYMENTS KV namespace.
    pub fn get_payments_kv(&self) -> Result<worker::kv::KvStore> {
        self.env
            .kv("PAYMENTS")
            .map_err(|e| AuthCloudflareError::ConfigError(format!("PAYMENTS KV not bound: {}", e)))
    }

    /// Gets an environment variable.
    pub fn get_var(&self, name: &str) -> Option<String> {
        self.env.var(name).ok().map(|v| v.to_string())
    }

    /// Gets the environment (development, production, etc.).
    pub fn get_environment(&self) -> String {
        self.get_var("ENVIRONMENT")
            .unwrap_or_else(|| "production".to_string())
    }
}

/// Read PAYMENT_WORK_LIMIT once per host request, before any payment work.
/// Absent or blank is unbounded. Invalid configuration is the host's own 500.
pub fn payment_work_limit(
    env: &Env,
) -> std::result::Result<Option<u64>, crate::payment_verify::PaymentVerifyError> {
    let value = env.var("PAYMENT_WORK_LIMIT").ok().map(|v| v.to_string());
    parse_payment_work_limit(value.as_deref())
}

/// Pure configuration parser, also usable by hosts without Worker bindings.
pub fn parse_payment_work_limit(
    value: Option<&str>,
) -> std::result::Result<Option<u64>, crate::payment_verify::PaymentVerifyError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(n @ 1..) = trimmed.parse::<u64>() {
            return Ok(Some(n));
        }
    }
    Err(crate::payment_verify::PaymentVerifyError::BadWorkLimit {
        value: value.into(),
    })
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn parse_table_and_host_fault_class() {
        for value in [None, Some(""), Some("  ")] {
            assert_eq!(parse_payment_work_limit(value).unwrap(), None);
        }
        for value in ["1000000", " 1000000 "] {
            assert_eq!(
                parse_payment_work_limit(Some(value)).unwrap(),
                Some(1_000_000)
            );
        }
        for value in ["0", "1MB", "-1", "+1", "18446744073709551616"] {
            let error = parse_payment_work_limit(Some(value)).unwrap_err();
            assert!(matches!(
                error,
                crate::payment_verify::PaymentVerifyError::BadWorkLimit { .. }
            ));
            assert_eq!(error.response_class(), (500, "ERR_SERVER_MISCONFIGURED"));
        }
    }
}
