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
        // `ExactSizeIterator` is a safe trait, so it's possible for `.len()` to be implemented
        // incorrectly. However, since this should be unlikely, check the claimed length before
        // allocating to avoid the unnecessary allocation, and then check the actual length after
        // allocating to guarantee the invariant.

        Self::try_payload_len(iter.len())?
            .map(|claimed_len| {
                let data = iter.collect::<Rc<_>>();

                if let Ok(Some(len)) = Self::try_payload_len(data.len())
                    && len == claimed_len
                {
                    Ok(Self { data, len })
                } else {
                    Err("Attempted to create a `TcpPayload` from an incorrectly implemented \
                         ExactSizeIterator")
                }
            })
            .transpose()
    }

    /// Attempts to convert a `usize` into a `NonZeroU16`, returning `Ok(None)` if `unknown_len` is
    /// zero.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `unknown_len` is greater than `u16::MAX`.
    fn try_payload_len(unknown_len: usize) -> Result<Option<NonZeroU16>, &'static str> {
        u16::try_from(unknown_len)
            .map_err(|_| {
                "Attempted to create a `TcpPayload` from an iterator longer than `u16::MAX`"
            })
            .map(|maybe_zero_len| NonZeroU16::try_from(maybe_zero_len).ok())
    }
}

impl Deref for TcpPayload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target { &self.data }
}
