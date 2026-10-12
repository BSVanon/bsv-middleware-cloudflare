//! The header service as a trait: the one seam SPV needs.
//!
//! The core never names a URL. A host implements [`HeaderService`] over
//! whatever it has (an HTTP header service, a service binding, a cached
//! header store, a fixture), and passes it as `Some(&service)`; passing
//! `None` is [`PaymentVerdict::NoHeaderService`](crate::PaymentVerdict::NoHeaderService),
//! fail closed, before any other check.

pub use bsv_sdk::transaction::beef_stream::ChainTip;
use std::fmt;
use std::future::Future;

/// A block header's merkle root as the service reports it: hex, compared
/// case-insensitively. Deliberately NOT validated on construction: a service
/// that answers an unparseable root is treated as answering a DIFFERENT root
/// (`RootMismatch`, a fraud signal), never as an outage (`Unverifiable`, a
/// refusal the host may let the client retry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleRoot(String);

impl MerkleRoot {
    /// Wrap the hex the service answered, verbatim.
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    /// The hex as answered.
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    /// Whether this root is `other` (case-insensitive hex compare).
    pub fn matches(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

impl From<String> for MerkleRoot {
    fn from(hex: String) -> Self {
        Self(hex)
    }
}

impl From<&str> for MerkleRoot {
    fn from(hex: &str) -> Self {
        Self(hex.to_string())
    }
}

/// Why the service could not answer: an outage, a timeout, an HTTP error,
/// an unparseable body. Carried into
/// [`PaymentVerdict::Unverifiable`](crate::PaymentVerdict::Unverifiable) (a
/// refusal) as the reason, so the host's log and response body say what
/// happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError(String);

impl ServiceError {
    /// A service error with its reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    /// The reason.
    pub fn reason(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ServiceError {}

/// A source of block-header merkle roots by height.
///
/// `Ok(Some(root))` is the header at `height`; `Ok(None)` means the service
/// has no header at that height yet (not indexed); `Err` means it could not
/// answer. The last two are the same to SPV: the root goes unchecked and the
/// verdict is [`Unverifiable`](crate::PaymentVerdict::Unverifiable), a
/// refusal (fail closed). A root that differs is
/// [`RootMismatch`](crate::PaymentVerdict::RootMismatch).
///
/// The future is whatever the implementation returns (no `Send` bound is
/// imposed, so a single-threaded wasm host and a multi-threaded native host
/// both fit); the verifier is generic over the service, never boxed.
pub trait HeaderService {
    /// Active tip and network context. Absence declines contextual checks.
    fn mining_tip(&self) -> impl Future<Output = Result<Option<ChainTip>, ServiceError>> {
        std::future::ready(Ok(None))
    }

    /// The merkle root of the block at `height`.
    fn merkle_root(
        &self,
        height: u32,
    ) -> impl Future<Output = Result<Option<MerkleRoot>, ServiceError>>;
}

impl<H: HeaderService + ?Sized> HeaderService for &H {
    fn mining_tip(&self) -> impl Future<Output = Result<Option<ChainTip>, ServiceError>> {
        (**self).mining_tip()
    }

    fn merkle_root(
        &self,
        height: u32,
    ) -> impl Future<Output = Result<Option<MerkleRoot>, ServiceError>> {
        (**self).merkle_root(height)
    }
}

/// A header service made of one lookup closure: `Fn(height) -> Future`. For a
/// fixture, a cache, or a host whose lookup is a function already.
pub struct LookupFn<F>(pub F);

impl<F, Fut> HeaderService for LookupFn<F>
where
    F: Fn(u32) -> Fut,
    Fut: Future<Output = Result<Option<MerkleRoot>, ServiceError>>,
{
    fn merkle_root(
        &self,
        height: u32,
    ) -> impl Future<Output = Result<Option<MerkleRoot>, ServiceError>> {
        (self.0)(height)
    }
}

/// The type to name when there is no service: `None::<&NoService>`. Its
/// lookup is never reached by the verifier (a `None` service is refused
/// before any lookup); should a host pass `Some(&NoService)` by mistake,
/// every lookup errors, so every root goes unchecked and the verdict is
/// `Unverifiable`, never `Verified`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoService;

impl HeaderService for NoService {
    fn merkle_root(
        &self,
        _height: u32,
    ) -> impl Future<Output = Result<Option<MerkleRoot>, ServiceError>> {
        std::future::ready(Err(ServiceError::new("no header service configured")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_compares_case_insensitively_and_keeps_its_hex() {
        let root = MerkleRoot::new("AbCd");
        assert_eq!(root.as_hex(), "AbCd");
        assert!(root.matches("abcd"));
        assert!(root.matches("ABCD"));
        assert!(!root.matches("abce"));
        assert!(!MerkleRoot::from("").matches("abcd"));
        assert_eq!(MerkleRoot::from("ef".to_string()), MerkleRoot::new("ef"));
    }

    #[test]
    fn service_error_carries_its_reason() {
        let e = ServiceError::new("header service HTTP 503 at height 7");
        assert_eq!(e.reason(), "header service HTTP 503 at height 7");
        assert_eq!(e.to_string(), e.reason());
        let boxed: Box<dyn std::error::Error> = Box::new(e);
        assert!(boxed.to_string().contains("503"));
    }

    #[tokio::test]
    async fn a_lookup_closure_is_a_service_and_a_reference_to_one_is_too() {
        let fixture = LookupFn(|height: u32| async move {
            if height == 7 {
                Ok(Some(MerkleRoot::new("aa")))
            } else {
                Ok(None)
            }
        });
        assert_eq!(
            fixture.merkle_root(7).await.unwrap(),
            Some(MerkleRoot::new("aa"))
        );
        async fn through<H: HeaderService>(service: H, height: u32) -> Option<MerkleRoot> {
            service.merkle_root(height).await.unwrap()
        }
        assert_eq!(through(&fixture, 8).await, None, "a reference is a service");
        assert_eq!(through(&fixture, 7).await, Some(MerkleRoot::new("aa")));
        assert!(NoService.merkle_root(7).await.is_err());
    }
}
