pub(super) trait SeqLt {
    /// Returns whether `self` precedes `rhs` in TCP sequence-number space, accounting for
    /// wraparound (RFC 9293, Section 3.4).
    fn seq_lt(self, rhs: Self) -> bool;
}

impl SeqLt for u32 {
    fn seq_lt(self, rhs: Self) -> bool { self.wrapping_sub(rhs) >= 1 << 31 }
}

pub(super) trait SeqLe {
    /// Returns whether `self` precedes or equals `rhs` in TCP sequence-number space, accounting for
    /// wraparound (RFC 9293, Section 3.4).
    fn seq_le(self, rhs: Self) -> bool;
}

impl SeqLe for u32 {
    fn seq_le(self, rhs: Self) -> bool { self == rhs || self.seq_lt(rhs) }
}

pub(super) trait AdvanceBy {
    /// Like `wrapping_add`, but mutates `self` in place to avoid potentially verbose and
    /// error-prone reassignments. In other words, advances `self` by `rhs` in TCP sequence-number
    /// space.
    fn advance_by(&mut self, rhs: Self);
}

impl AdvanceBy for u32 {
    fn advance_by(&mut self, rhs: Self) { *self = self.wrapping_add(rhs) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equalities() {
        for num in [0, 1, 42, 1 << 31, u32::MAX] {
            assert!(!num.seq_lt(num));
            assert!(num.seq_le(num));
        }
    }

    #[test]
    #[expect(clippy::nonminimal_bool, reason = "Keep linear and circular comparisons parallel")]
    fn agrees_with_linear_comparison_over_half_the_space() {
        for [left, right] in [[0, 1], [42, 1 << 31], [0xBEEF_CAFE, 0xCAFE_BEEF]] {
            assert!(left.seq_lt(right) && left < right);
            assert!(left.seq_le(right) && left <= right);
            assert!(!right.seq_lt(left) && !(right < left));
            assert!(!right.seq_le(left) && !(right <= left));
        }
    }

    #[test]
    #[expect(clippy::nonminimal_bool, reason = "Keep linear and circular comparisons parallel")]
    fn differs_from_linear_comparison_over_half_the_space() {
        for [left, right] in [[u32::MAX, 0], [(1 << 31) + 42, 1], [0xBAAD_D00D, 0xD00D]] {
            assert!(left.seq_lt(right) && !(left < right));
            assert!(left.seq_le(right) && !(left <= right));
            assert!(!right.seq_lt(left) && right < left);
            assert!(!right.seq_le(left) && right <= left);
        }
    }

    #[test]
    fn near_antipode_comparisons() {
        // As noted in RFC 1982, a pair of antipodes in serial number arithmetic may produce results
        // where both are strictly less than the other or strictly greater than the other. This
        // outcome is left undefined with the recommendation to avoid allowing such pairs to exist.
        // In TCP, sequence numbers of actual segments should never be this far away from each other
        // due to window sizes. Tested here for correctness and to avoid off-by-one errors.

        const NUM: u32 = 42;
        const ANTIPODE: u32 = NUM.wrapping_add(1 << 31);
        const FARTHEST_GREATER: u32 = ANTIPODE.wrapping_sub(1);
        const FARTHEST_LESS: u32 = ANTIPODE.wrapping_add(1);

        assert!(
            NUM.seq_lt(FARTHEST_GREATER) && !FARTHEST_GREATER.seq_lt(NUM),
            "The first defined comparison one below the antipode"
        );

        assert!(
            FARTHEST_LESS.seq_lt(NUM) && !NUM.seq_lt(FARTHEST_LESS),
            "The first defined comparison one above the antipode"
        );

        assert!(
            NUM.seq_lt(ANTIPODE) && ANTIPODE.seq_lt(NUM),
            "The undefined outcome where a number and its antipode are both strictly less than \
             the other depends on the implementation and should result in true here"
        );
    }
}
