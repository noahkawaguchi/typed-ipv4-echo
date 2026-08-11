use {
    crate::protocol::display::ThousandsSeparated,
    std::{
        cmp::Ordering,
        fmt,
        marker::PhantomData,
        num::{NonZeroU16, Wrapping},
        ops::{Add, AddAssign, Sub},
    },
};

/// A distance between two points in TCP sequence number space.
#[derive(Clone, Copy, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct SeqDist<T>(Wrapping<T>);

impl<T> SeqDist<T> {
    pub(super) const fn new(primitive: T) -> Self { Self(Wrapping(primitive)) }
}

impl From<SeqDist<u16>> for SeqDist<u32> {
    fn from(value: SeqDist<u16>) -> Self { Self(Wrapping(value.0.0.into())) }
}

impl<T: From<u16>> From<NonZeroU16> for SeqDist<T> {
    fn from(value: NonZeroU16) -> Self { Self(Wrapping(value.get().into())) }
}

impl SeqDist<u16> {
    pub(super) const fn to_be_bytes(self) -> [u8; 2] { self.0.0.to_be_bytes() }
}

impl SeqDist<u32> {
    pub(super) const fn saturating_sub(self, rhs: Self) -> Self {
        Self(Wrapping(self.0.0.saturating_sub(rhs.0.0)))
    }
}

impl<T> TryFrom<SeqDist<T>> for usize
where
    Self: TryFrom<T>,
{
    type Error = <Self as TryFrom<T>>::Error;

    fn try_from(value: SeqDist<T>) -> Result<Self, Self::Error> { Self::try_from(value.0.0) }
}

impl<T> fmt::Display for ThousandsSeparated<SeqDist<T>>
where
    T: Copy,
    ThousandsSeparated<T>: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ThousandsSeparated(self.0.0.0).fmt(f)
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
}

impl<D> Add<SeqDist<u32>> for SeqPoint<D> {
    type Output = Self;

    fn add(self, rhs: SeqDist<u32>) -> Self::Output {
        Self { wrapping: self.wrapping + rhs.0, phantom: PhantomData }
    }
}

impl<D> AddAssign<SeqDist<u32>> for SeqPoint<D> {
    fn add_assign(&mut self, rhs: SeqDist<u32>) { *self = *self + rhs; }
}

impl<D> Sub for SeqPoint<D> {
    type Output = SeqDist<u32>;

    fn sub(self, rhs: Self) -> Self::Output { SeqDist(self.wrapping - rhs.wrapping) }
}

impl<D> PartialOrd for SeqPoint<D> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        /// Exactly halfway around 32-bit sequence number space.
        const SEMICIRCUMFERENCE: u32 = 1 << 31;

        /// One more than halfway around 32-bit sequence number space.
        const SEMICIRCUMFERENCE_PLUS_1: u32 = SEMICIRCUMFERENCE + 1;

        match (self.wrapping - other.wrapping).0 {
            0 => Some(Ordering::Equal),
            1..SEMICIRCUMFERENCE => Some(Ordering::Greater),
            SEMICIRCUMFERENCE => None,
            SEMICIRCUMFERENCE_PLUS_1.. => Some(Ordering::Less),
        }
    }
}

impl<D> fmt::Display for ThousandsSeparated<SeqPoint<D>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ThousandsSeparated(self.0.wrapping.0).fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::protocol::Local};

    impl SeqDist<u32> {
        pub(in super::super) const fn const_add(self, rhs: Self) -> Self {
            Self(Wrapping(self.0.0.wrapping_add(rhs.0.0)))
        }
    }

    impl Add for SeqDist<u32> {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output { Self(self.0 + rhs.0) }
    }

    impl Sub for SeqDist<u32> {
        type Output = Self;

        fn sub(self, rhs: Self) -> Self::Output { Self(self.0 - rhs.0) }
    }

    impl<D> SeqPoint<D> {
        pub(in super::super) const fn const_add(self, rhs: SeqDist<u32>) -> Self {
            Self::new(self.wrapping.0.wrapping_add(rhs.0.0))
        }

        pub(in super::super) const fn const_sub(self, rhs: SeqDist<u32>) -> Self {
            Self::new(self.wrapping.0.wrapping_sub(rhs.0.0))
        }

        /// Leaks the inner primitive type for use in test constants. This should be removed once
        /// const traits are stabilized.
        pub(in super::super) const fn leak_primitive(self) -> u32 { self.wrapping.0 }
    }

    impl<D> Sub<SeqDist<u32>> for SeqPoint<D> {
        type Output = Self;

        fn sub(self, rhs: SeqDist<u32>) -> Self::Output {
            Self { wrapping: self.wrapping - rhs.0, phantom: PhantomData }
        }
    }

    #[test]
    fn equality() {
        for num in [0, 1, 42, 1 << 31, u32::MAX].map(SeqPoint::<Local>::new) {
            assert_eq!(num, num);
        }
    }

    #[test]
    fn inequality() {
        for [left, right] in [0, 1, 42, 1 << 31, u32::MAX]
            .map(SeqPoint::<Local>::new)
            .array_windows::<2>()
        {
            assert_ne!(left, right);
            assert_ne!(right, left);
        }
    }

    #[test]
    fn agrees_with_linear_comparison_over_half_the_space() {
        for [left, right] in [[0, 1], [42, 1 << 31], [0xBEEF_CAFE, 0xCAFE_BEEF]] {
            assert_eq!(
                SeqPoint::<Local>::new(left).partial_cmp(&SeqPoint::new(right)),
                left.partial_cmp(&right)
            );
            assert_eq!(
                SeqPoint::<Local>::new(right).partial_cmp(&SeqPoint::new(left)),
                right.partial_cmp(&left)
            );
        }
    }

    #[test]
    fn differs_from_linear_comparison_over_half_the_space() {
        for [left, right] in [[u32::MAX, 0], [(1 << 31) + 42, 1], [0xBAAD_D00D, 0xD00D]] {
            assert_ne!(
                SeqPoint::<Local>::new(left).partial_cmp(&SeqPoint::new(right)),
                left.partial_cmp(&right)
            );
            assert_ne!(
                SeqPoint::<Local>::new(right).partial_cmp(&SeqPoint::new(left)),
                right.partial_cmp(&left)
            );
        }
    }

    #[test]
    fn near_antipode_comparisons() {
        // As noted in RFC 1982, a pair of antipodes in serial number arithmetic may produce results
        // where both are strictly less than the other or strictly greater than the other. This
        // outcome is left undefined with the recommendation to avoid allowing such pairs to exist.
        // In TCP, sequence numbers of actual segments should never be this far away from each other
        // due to window sizes. Tested here for correctness and to avoid off-by-one errors.

        const NUM: SeqPoint<Local> = SeqPoint::new(42);
        const ANTIPODE: SeqPoint<Local> = NUM.const_add(SeqDist::new(1 << 31));
        const FARTHEST_GREATER: SeqPoint<Local> = ANTIPODE.const_sub(SeqDist::new(1));
        const FARTHEST_LESS: SeqPoint<Local> = ANTIPODE.const_add(SeqDist::new(1));

        assert!(FARTHEST_GREATER > NUM, "The first defined comparison one below the antipode");
        assert!(FARTHEST_LESS < NUM, "The first defined comparison one above the antipode");

        assert!(
            !(NUM < ANTIPODE || ANTIPODE < NUM || NUM == ANTIPODE),
            "The undefined outcome where a number and its antipode are both strictly less than \
             the other depends on the implementation and should result in false here"
        );
    }
}
