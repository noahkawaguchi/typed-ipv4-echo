use {
    crate::Result,
    std::{num::NonZeroU16, ops::Deref, rc::Rc},
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

    /// Attempts to create a `Self` from `iter`, returning `Ok(None)` if `iter` is empty.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the length of `iter` is greater than `u16::MAX`.
    pub(super) fn try_from_iter<I>(iter: I) -> Result<Option<Self>, &'static str>
    where
        I: ExactSizeIterator<Item = u8>,
    {
        let it = iter.into_iter();

        u16::try_from(it.len())
            .map_err(|_| {
                "Attempted to create a `TcpPayload` from an iterator longer than `u16::MAX`"
            })
            .map(|maybe_zero_len| {
                NonZeroU16::try_from(maybe_zero_len)
                    .ok()
                    .map(|len| Self { data: it.collect(), len })
            })
    }
}

impl Deref for TcpPayload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target { self.data.as_ref() }
}
