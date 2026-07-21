use {
    crate::Result,
    std::{iter, num::NonZeroU16, rc::Rc},
};

/// A payload of bytes guaranteed to have a length in the range of `NonZeroU16`.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct TcpPayload {
    data: Rc<[u8]>,
    len: NonZeroU16,
}

impl TcpPayload {
    /// Returns the number of bytes in the payload.
    pub(super) const fn len(&self) -> NonZeroU16 { self.len }

    /// Returns a byte slice of the payload's data.
    pub(super) fn as_bytes(&self) -> &[u8] { &self.data }

    /// Attempts to create a `Self` from `iter`, returning `Ok(None)` if `iter` is empty.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the length of `iter` is greater than `u16::MAX`.
    pub(super) fn try_from_iter<I>(iter: I) -> Result<Option<Self>, &'static str>
    where
        I: IntoIterator<Item = u8>,
    {
        // Use of `ExactSizeIterator` rejected here because, as a safe trait, its `.len()` could be
        // implemented incorrectly, and the full data is about to collected anyway, so a check on
        // the actual length of the data would still be necessary to guarantee this struct's
        // invariant. The too long case is essentially impossible with normal IP traffic, while
        // avoiding allocating every time for the expected and common empty case can be detected
        // with plain `IntoIterator`, which provides a more flexible API.

        let mut it = iter.into_iter();

        let Some(first) = it.next() else { return Ok(None) };

        let data = iter::once(first).chain(it).collect::<Rc<_>>();

        u16::try_from(data.len())
            .map_err(|_| {
                "Attempted to create a `TcpPayload` from an iterator longer than `u16::MAX`"
            })
            .map(|maybe_zero_len| NonZeroU16::new(maybe_zero_len).map(|len| Self { data, len }))
    }
}
