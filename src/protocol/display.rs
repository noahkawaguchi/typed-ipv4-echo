use std::fmt;

/// Wrapper implementing `Display` to convert the raw bytes of a payload into a printable
/// representation of its length and content (if UTF-8).
pub(super) struct PrettyPayload<'a>(&'a [u8]);

impl fmt::Display for PrettyPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match str::from_utf8(self.0) {
            Ok("") => write!(f, "<no payload>"),
            Ok(s) => write!(f, "{}-byte UTF-8 payload: {}", self.0.len(), s.escape_debug()),
            Err(_) => write!(f, "{}-byte non-UTF-8 payload", self.0.len()),
        }
    }
}

pub(super) trait AsPrettyPayload {
    /// Wraps the raw bytes of `self` in a `PrettyPayload` for pretty printing as a payload that may
    /// be empty, UTF-8, or non-UTF-8.
    fn as_pretty_payload(&self) -> PrettyPayload<'_>;
}

impl AsPrettyPayload for &[u8] {
    fn as_pretty_payload(&self) -> PrettyPayload<'_> { PrettyPayload(self) }
}
