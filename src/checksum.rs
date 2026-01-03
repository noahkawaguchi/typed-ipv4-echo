/// Computes the Internet checksum (RFC 1071) for IP and ICMP headers (16-bit one's complement of
/// the one's complement sum).
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
#[allow(clippy::cast_possible_truncation)] // Truncation desired after folding
const fn fold_carry_bits(sum: u32) -> u16 {
    if sum >> 16 == 0 { sum as u16 } else { fold_carry_bits((sum & 0xFFFF) + (sum >> 16)) }
}
