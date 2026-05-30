/// Computes the Internet checksum from data of arbitrary length (16-bit one's complement of the
/// one's complement sum, RFC 1071).
pub fn calculate(data: &[u8]) -> u16 {
    /// Folds the high half of a 32-bit accumulator back into the low half one time.
    const fn one_carry_fold(x: u32) -> u32 { (x & 0xFFFF).wrapping_add(x >> 16) }

    let (byte_pairs, maybe_odd_byte) = data.as_chunks::<2>();

    let sum = byte_pairs.iter().fold(
        // Treat an odd byte as the high byte of a 16-bit word
        maybe_odd_byte
            .first()
            .map_or(0, |&b| u32::from_be_bytes([0, 0, b, 0])),
        // Sum 16-bit words using a 32-bit accumulator to accumulate carries in bits 16-31
        // (deferred carries method)
        |sum, &[high_byte, low_byte]| {
            /// The lowest `u32` value that would overflow if `u16::MAX` was added to it.
            const WOULD_OVERFLOW: u32 = u32::MAX - u16::MAX as u32 + 1;

            // Perform an intermediate fold if the accumulator would overflow on the next iteration.
            //
            // Intermediate folding will never happen for most real-world input sizes such as 1500
            // bytes (Ethernet MTU) or 65,535 bytes (max IPv4 packet). See the test below for more
            // information.
            match sum.wrapping_add(u32::from_be_bytes([0, 0, high_byte, low_byte])) {
                enough_space @ u32::MIN..WOULD_OVERFLOW => enough_space,
                almost_full @ WOULD_OVERFLOW..=u32::MAX => one_carry_fold(almost_full),
            }
        },
    );

    // Fold 32 bits into 16 and return one's complement.
    //
    // No more than two folds are necessary because in the worst case, `u32::MAX` or 0xFFFF_FFFF,
    // folding once results in 0x1_FFFE and folding twice results in 0xFFFF, fitting exactly into a
    // `u16`. `u32::MAX` exactly will never occur due to the overflow check during the iteration
    // above, but the property still holds because other `u32` values are strictly less.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Truncation desired after folding"
    )]
    !(one_carry_fold(one_carry_fold(sum)) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_zeros_is_all_ones() {
        // All zeros should produce 0xFFFF (one's complement of 0x0000)
        assert_eq!(calculate(&[0u8; 20]), 0xFFFF);
    }

    #[test]
    fn checksum_of_all_ones_is_zero() {
        // All ones should produce 0x0000 (one's complement of 0xFFFF)
        assert_eq!(calculate(&[0xFFu8; 20]), 0x0000);
    }

    #[test]
    fn handles_odd_length() {
        // Should treat odd byte as high byte of 16-bit word

        // 3 bytes: 0x1234 + 0x5600 = 0x6834, ~0x6834 = 0x97CB
        let data1 = [0x12, 0x34, 0x56];
        assert_eq!(calculate(&data1), 0x97CB);

        // 5 bytes: 0x1234 + 0x5678 + 0xAB00 = 0x113AC
        // fold: 0x13AC + 0x1 = 0x13AD
        // ~0x13AD = 0xEC52
        let data2 = [0x12, 0x34, 0x56, 0x78, 0xAB];
        assert_eq!(calculate(&data2), 0xEC52);
    }

    #[test]
    fn folds_carry_bits() {
        // All 0xFF: 0xFFFF + 0xFFFF = 0x1FFFE, fold: 0xFFFE + 0x1 = 0xFFFF, ~0xFFFF = 0x0000
        let data1 = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(calculate(&data1), 0x0000);

        // Mixed values requiring folding: 0xAAAA + 0xBBBB = 0x16665
        // fold: 0x6665 + 0x1 = 0x6666
        // ~0x6666 = 0x9999
        let data2 = [0xAA, 0xAA, 0xBB, 0xBB];
        assert_eq!(calculate(&data2), 0x9999);
    }

    #[test]
    fn checksum_of_known_ipv4_header_without_folding() {
        // IPv4 header with simple values for manual verification
        // Version=4, IHL=5, TOS=0, Total Length=32, ID=1, Flags=0, TTL=64, Protocol=17 (UDP)
        #[rustfmt::skip]
        let header = [
            0x45, 0x00,  // Version/IHL, TOS           = 0x4500
            0x00, 0x20,  // Total Length               = 0x0020
            0x00, 0x01,  // Identification             = 0x0001
            0x00, 0x00,  // Flags, Fragment Offset     = 0x0000
            0x40, 0x11,  // TTL, Protocol              = 0x4011
            0x00, 0x00,  // Checksum (zeroed)          = 0x0000
            0x0a, 0x00,  // Source IP: 10.0.0.1        = 0x0a00
            0x00, 0x01,  //                            = 0x0001
            0x0a, 0x00,  // Dest IP: 10.0.0.2          = 0x0a00
            0x00, 0x02,  //                            = 0x0002
        ];

        // Sum: 0x4500 + 0x0020 + 0x0001 + 0x0000 + 0x4011 + 0x0000 + 0x0a00 + 0x0001 + 0x0a00 +
        //      0x0002 = 0x9935
        // No carry to fold (sum fits in 16 bits)
        // One's complement: ~0x9935 = 0x66CA
        assert_eq!(calculate(&header), 0x66CA);
    }

    #[test]
    fn checksum_of_known_ipv4_header_with_folding() {
        // IPv4 header with values that require carry folding
        // Using large IP addresses to force carries
        #[rustfmt::skip]
        let header = [
            0x45, 0x00,  // Version/IHL, TOS           = 0x4500
            0x00, 0x54,  // Total Length               = 0x0054
            0xab, 0xcd,  // Identification             = 0xabcd
            0x00, 0x00,  // Flags, Fragment Offset     = 0x0000
            0x40, 0x06,  // TTL, Protocol              = 0x4006
            0x00, 0x00,  // Checksum (zeroed)          = 0x0000
            0xc0, 0xa8,  // Source IP: 192.168.255.100 = 0xc0a8
            0xff, 0x64,  //                            = 0xff64
            0xc0, 0xa8,  // Dest IP: 192.168.255.200   = 0xc0a8
            0xff, 0xc8,  //                            = 0xffc8
        ];

        // Sum: 0x4500 + 0x0054 + 0xabcd + 0x0000 + 0x4006 + 0x0000 + 0xc0a8 + 0xff64 + 0xc0a8 +
        //      0xffc8 = 0x4B1A3
        // Fold carry: 0xB1A3 + 0x4 = 0xB1A7
        // One's complement: ~0xB1A7 = 0x4E58
        assert_eq!(calculate(&header), 0x4E58);
    }

    #[test]
    fn roundtrip_produces_zero() {
        // Checksum of data with its checksum embedded should be 0
        #[rustfmt::skip]
        let data = [
            0x45, 0x00, 0x00, 0x3c,
            0x1c, 0x46, 0x40, 0x00,
            0x40, 0x06, 0xb1, 0xe6,  // Checksum embedded here (0xb1e6)
            0xac, 0x10, 0x0a, 0x63,
            0xac, 0x10, 0x0a, 0x0c,
        ];

        // When checksum is already included, result should be 0
        assert_eq!(calculate(&data), 0x0000);
    }

    #[test]
    fn commutative_over_16_bit_word_order() {
        // Checksum is sum of 16-bit words, so reordering words should give same result
        let data1 = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let data2 = [0x9A, 0xBC, 0x12, 0x34, 0xDE, 0xF0, 0x56, 0x78];

        // data1: 0x1234 + 0x5678 + 0x9ABC + 0xDEF0
        // data2: 0x9ABC + 0x1234 + 0xDEF0 + 0x5678
        // Should be equal due to commutativity of addition
        assert_eq!(calculate(&data1), calculate(&data2));
    }
}
