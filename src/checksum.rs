/// Computes the Internet checksum (RFC 1071) for use in headers (16-bit one's complement of the
/// one's complement sum).
pub fn calculate(data: &[u8]) -> u16 {
    // Sum all 16-bit words (deferred carries method)
    let sum = data
        .chunks(2)
        .map(|chunk| {
            // Put 16-bit words into 32 bits to accumulate carries in bits 16-31 when summing.
            // Treat an odd byte as the high byte of a 16-bit word.
            u32::from_be_bytes([0, 0, chunk[0], if chunk.len() == 2 { chunk[1] } else { 0 }])
        })
        .sum();

    // Fold 32 bits into 16 and return one's complement
    !fold_carry_bits(sum)
}

/// Adds Internet checksum carry bits back into a 16-bit sum by folding a 32-bit sum.
#[expect(
    clippy::cast_possible_truncation,
    reason = "Truncation desired after folding"
)]
const fn fold_carry_bits(sum: u32) -> u16 {
    if sum >> 16 == 0 { sum as u16 } else { fold_carry_bits((sum & 0xFFFF) + (sum >> 16)) }
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
        let data = [0x12, 0x34, 0x56];
        assert_eq!(calculate(&data), 0x97CB);

        // 5 bytes: 0x1234 + 0x5678 + 0xAB00 = 0x113AC
        // fold: 0x13AC + 0x1 = 0x13AD
        // ~0x13AD = 0xEC52
        let data = [0x12, 0x34, 0x56, 0x78, 0xAB];
        assert_eq!(calculate(&data), 0xEC52);
    }

    #[test]
    fn folds_carry_bits() {
        // All 0xFF: 0xFFFF + 0xFFFF = 0x1FFFE, fold: 0xFFFE + 0x1 = 0xFFFF, ~0xFFFF = 0x0000
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(calculate(&data), 0x0000);

        // Mixed values requiring folding: 0xAAAA + 0xBBBB = 0x16665
        // fold: 0x6665 + 0x1 = 0x6666
        // ~0x6666 = 0x9999
        let data = [0xAA, 0xAA, 0xBB, 0xBB];
        assert_eq!(calculate(&data), 0x9999);
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
