use {
    crate::protocol::display::ThousandsSeparated,
    std::{
        fmt,
        marker::PhantomData,
        num::{NonZeroU16, Wrapping},
        ops::{Add, AddAssign},
    },
};

/// A distance between two points in TCP sequence number space that are both in direction `D`.
#[derive(Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct SeqDist<T, D> {
    wrapping: Wrapping<T>,
    phantom: PhantomData<D>,
}

impl<T: Copy, D> Clone for SeqDist<T, D> {
    fn clone(&self) -> Self { *self }
}

impl<T: Copy, D> Copy for SeqDist<T, D> {}

impl<T, D> SeqDist<T, D> {
    pub(super) const fn new(primitive: T) -> Self {
        Self { wrapping: Wrapping(primitive), phantom: PhantomData }
    }
}

impl<D> From<SeqDist<u16, D>> for SeqDist<u32, D> {
    fn from(value: SeqDist<u16, D>) -> Self {
        Self { wrapping: Wrapping(value.wrapping.0.into()), phantom: PhantomData }
    }
}

impl<T: From<u16>, D> From<NonZeroU16> for SeqDist<T, D> {
    fn from(value: NonZeroU16) -> Self {
        Self { wrapping: Wrapping(value.get().into()), phantom: PhantomData }
    }
}

impl<D> SeqDist<u16, D> {
    pub(super) const fn to_be_bytes(self) -> [u8; 2] { self.wrapping.0.to_be_bytes() }
}

impl<D> SeqDist<u32, D> {
    pub(super) const fn saturating_sub(self, rhs: Self) -> Self {
        Self {
            wrapping: Wrapping(self.wrapping.0.saturating_sub(rhs.wrapping.0)),
            phantom: PhantomData,
        }
    }
}

impl<T, D> TryFrom<SeqDist<T, D>> for usize
where
    Self: TryFrom<T>,
{
    type Error = <Self as TryFrom<T>>::Error;

    fn try_from(value: SeqDist<T, D>) -> Result<Self, Self::Error> {
        Self::try_from(value.wrapping.0)
    }
}

impl<T, D> fmt::Display for ThousandsSeparated<SeqDist<T, D>>
where
    T: Copy,
    ThousandsSeparated<T>: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ThousandsSeparated(self.0.wrapping.0).fmt(f)
    }
}

/// A specific point in TCP sequence number space in direction `D`.
#[derive(Eq)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct SeqPoint<D> {
    wrapping: Wrapping<u32>,
    phantom: PhantomData<D>,
}

impl<D> Clone for SeqPoint<D> {
    fn clone(&self) -> Self { *self }
}

impl<D> Copy for SeqPoint<D> {}

impl<D> PartialEq for SeqPoint<D> {
    fn eq(&self, other: &Self) -> bool { self.wrapping == other.wrapping }
}

impl<D> SeqPoint<D> {
    pub(super) const fn new(primitive: u32) -> Self {
        Self { wrapping: Wrapping(primitive), phantom: PhantomData }
    }

    pub(super) const fn to_be_bytes(self) -> [u8; 4] { self.wrapping.0.to_be_bytes() }

    /// Returns whether `self` precedes `other` in TCP sequence-number space, accounting for
    /// wraparound (RFC 9293, Section 3.4). Not transitive.
    pub(super) fn precedes(self, other: Self) -> bool {
        self.wrapping - other.wrapping >= Wrapping(1 << 31)
    }

    /// Returns whether `self` precedes or equals `other` in TCP sequence-number space, accounting
    /// for wraparound (RFC 9293, Section 3.4). Not transitive.
    pub(super) fn precedes_or_eq(self, other: Self) -> bool {
        self == other || self.precedes(other)
    }

    /// Returns the distance from `rhs` to `self`, or `None` if `rhs` does not precede or equal
    /// `self` in TCP sequence-number space (RFC 9293, Section 3.4).
    pub(super) fn distance_since(self, rhs: Self) -> Option<SeqDist<u32, D>> {
        rhs.precedes_or_eq(self)
            .then(|| SeqDist { wrapping: self.wrapping - rhs.wrapping, phantom: PhantomData })
    }
}

impl<D> Add<SeqDist<u32, D>> for SeqPoint<D> {
    type Output = Self;

    fn add(self, rhs: SeqDist<u32, D>) -> Self::Output {
        Self { wrapping: self.wrapping + rhs.wrapping, phantom: PhantomData }
    }
}

impl<D> AddAssign<SeqDist<u32, D>> for SeqPoint<D> {
    fn add_assign(&mut self, rhs: SeqDist<u32, D>) { *self = *self + rhs; }
}

impl<D> fmt::Display for ThousandsSeparated<SeqPoint<D>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ThousandsSeparated(self.0.wrapping.0).fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::endpoint::Local, std::ops::Sub};

    impl<D> SeqDist<u32, D> {
        pub(in super::super) const fn const_add(self, rhs: Self) -> Self {
            Self {
                wrapping: Wrapping(self.wrapping.0.wrapping_add(rhs.wrapping.0)),
                phantom: PhantomData,
            }
        }
    }

    impl<D> Add for SeqDist<u32, D> {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            Self { wrapping: self.wrapping + rhs.wrapping, phantom: PhantomData }
        }
    }

    impl<D> SeqPoint<D> {
        /// `self + rhs` with wrapping, but const. This should be removed once const traits are
        /// stabilized.
        pub(in super::super) const fn const_add(self, rhs: SeqDist<u32, D>) -> Self {
            Self::new(self.wrapping.0.wrapping_add(rhs.wrapping.0))
        }

        /// `self - rhs` with wrapping, but const. This should be removed once const traits are
        /// stabilized.
        pub(in super::super) const fn const_sub(self, rhs: SeqDist<u32, D>) -> Self {
            Self::new(self.wrapping.0.wrapping_sub(rhs.wrapping.0))
        }
    }

    impl<D> Sub<SeqDist<u32, D>> for SeqPoint<D> {
        type Output = Self;

        fn sub(self, rhs: SeqDist<u32, D>) -> Self::Output {
            Self { wrapping: self.wrapping - rhs.wrapping, phantom: PhantomData }
        }
    }

    #[test]
    fn point_equality() {
        for num in [0, 1, 42, 1 << 31, u32::MAX].map(SeqPoint::<Local>::new) {
            assert_eq!(num, num);
        }
    }

    #[test]
    fn point_comparison_is_not_transitive() {
        const A: SeqPoint<Local> = SeqPoint::new(0);
        const B: SeqPoint<Local> = SeqPoint::new(0x6000_0000);
        const C: SeqPoint<Local> = SeqPoint::new(0xC000_0000);

        assert!(A.precedes(B));
        assert!(B.precedes(C));
        assert!(!A.precedes(C));
    }

    #[test]
    #[expect(clippy::nonminimal_bool, reason = "Keep linear and circular comparisons parallel")]
    fn circular_comparison_agrees_with_linear_comparison_over_half_the_space() {
        for [prim_left, prim_right] in [[0, 1], [42, 1 << 31], [0xBEEF_CAFE, 0xCAFE_BEEF]] {
            let [seq_left, seq_right] =
                [SeqPoint::<Local>::new(prim_left), SeqPoint::new(prim_right)];

            assert!(seq_left.precedes(seq_right));
            assert!(prim_left < prim_right);
            assert!(!seq_right.precedes(seq_left));
            assert!(!(prim_right < prim_left));
        }
    }

    #[test]
    #[expect(clippy::nonminimal_bool, reason = "Keep linear and circular comparisons parallel")]
    fn circular_comparison_differs_from_linear_comparison_over_half_the_space() {
        for [prim_left, prim_right] in [[u32::MAX, 0], [(1 << 31) + 42, 1], [0xBAAD_D00D, 0xD00D]] {
            let [seq_left, seq_right] =
                [SeqPoint::<Local>::new(prim_left), SeqPoint::new(prim_right)];

            assert!(seq_left.precedes(seq_right));
            assert!(!(prim_left < prim_right));
            assert!(!seq_right.precedes(seq_left));
            assert!(prim_right < prim_left);
        }
    }

    #[test]
    fn antipode_and_near_antipode_comparisons_are_defined() {
        // As noted in RFC 1982, a pair of antipodes in serial number arithmetic may produce results
        // where both are strictly less than the other or strictly greater than the other. This
        // outcome is left undefined with the recommendation to avoid allowing such pairs to exist.
        // In TCP, sequence numbers of actual segments should never be this far away from each other
        // due to window sizes. Tested here for correctness and to avoid off-by-one errors.

        const NUM: SeqPoint<Local> = SeqPoint::new(42);
        const ANTIPODE: SeqPoint<Local> = NUM.const_add(SeqDist::new(1 << 31));
        const FARTHEST_GREATER: SeqPoint<Local> = ANTIPODE.const_sub(SeqDist::new(1));
        const FARTHEST_LESS: SeqPoint<Local> = ANTIPODE.const_add(SeqDist::new(1));

        assert!(
            NUM.precedes(FARTHEST_GREATER) && !FARTHEST_GREATER.precedes(NUM),
            "The first defined comparison one below the antipode"
        );

        assert!(
            FARTHEST_LESS.precedes(NUM) && !NUM.precedes(FARTHEST_LESS),
            "The first defined comparison one above the antipode"
        );

        assert!(
            NUM.precedes(ANTIPODE) && ANTIPODE.precedes(NUM),
            "The undefined outcome where a number and its antipode are both strictly less than \
             the other depends on the implementation and should result in true here"
        );
    }

    #[test]
    fn distance_since_computes_distance_when_rhs_precedes_or_equals_self() {
        for [later, earlier, expected] in [[140, 100, 40], [0, u32::MAX, 1], [42, 42, 0]] {
            assert_eq!(
                SeqPoint::<Local>::new(later).distance_since(SeqPoint::new(earlier)),
                Some(SeqDist::new(expected))
            );
        }
    }

    #[test]
    fn distance_since_returns_none_when_rhs_does_not_precede_or_equal_self() {
        assert_eq!(SeqPoint::<Local>::new(100).distance_since(SeqPoint::new(140)), None);
    }
}
