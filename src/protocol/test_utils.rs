use crate::{
    ETHERNET_MTU, Ipv4AddrPair, checksum,
    protocol::Protocol,
    try_ops::{TryGet, TryGetMut},
};

/// Calculates a TCP or UDP checksum for tests using a pseudo-header.
pub fn tcp_udp_test_checksum(
    reply: &[u8; ETHERNET_MTU],
    protocol: Protocol,
    proto_len: u16,
    ip_pair: Ipv4AddrPair,
) -> Result<u16, String> {
    let proto_len_usize = usize::from(proto_len);

    let mut pseudo_header = [0u8; 12];
    pseudo_header[0..4].copy_from_slice(&ip_pair.src.octets());
    pseudo_header[4..8].copy_from_slice(&ip_pair.dst.octets());
    pseudo_header[8] = 0;
    pseudo_header[9] = protocol.into();
    pseudo_header[10..12].copy_from_slice(&proto_len.to_be_bytes());

    let mut checksum_data = vec![0u8; 12 + proto_len_usize];
    checksum_data
        .try_get_mut(..12)?
        .copy_from_slice(&pseudo_header);
    checksum_data
        .try_get_mut(12..)?
        .copy_from_slice(reply.try_get(20..20 + proto_len_usize)?);

    Ok(checksum::calculate(&checksum_data))
}
