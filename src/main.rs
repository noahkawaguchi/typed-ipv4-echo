use libc::{IFF_NO_PI, IFF_TUN, IFNAMSIZ, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, TUNSETIFF};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::io::AsRawFd,
};

/// The minimum number of bytes for a valid IPv4 header.
const IPV4_HEADER_MIN_LEN: usize = 20;

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;

/// Adds Internet checksum carry bits back into a 16-bit sum by folding a 32-bit sum.
#[allow(clippy::cast_possible_truncation)] // Truncation desired after folding
const fn fold_carry_bits(sum: u32) -> u16 {
    if sum >> 16 == 0 { sum as u16 } else { fold_carry_bits((sum & 0xFFFF) + (sum >> 16)) }
}

/// Computes the Internet checksum (RFC 1071) for IP and ICMP headers (16-bit one's complement of
/// the one's complement sum).
fn calculate_checksum(data: &[u8]) -> u16 {
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

/// Creates a TUN device, requesting that the name be `desired_name`. Returns the opened `File` and
/// the actual assigned name.
#[allow(unsafe_code)]
fn create_tun(desired_name: &str) -> io::Result<(File, String)> {
    // Open the kernel's special device file for creating virtual network interfaces
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    // Initialize a new interface request C struct
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Copy desired device name into ifr_name (leaving room for the null terminator)
    for (i, b) in desired_name.bytes().enumerate().take(IFNAMSIZ - 1) {
        ifr.ifr_name[i] = b;
    }

    // Set flags
    #[allow(clippy::cast_possible_truncation)] // This is 0x1 | 0x1000, which fits in a short
    {
        // IFF_TUN   - TUN device (no Ethernet headers) rather than TAP
        // IFF_NO_PI - Do not prepend packet metadata (get IP packet only)
        ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as libc::c_short;
    }

    // Create the TUN interface
    if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &ifr) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok((
        file,
        // Extract the actual device name assigned by the kernel
        ifr.ifr_name
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| char::from(b))
            .collect(),
    ))
}

fn main() -> io::Result<()> {
    println!("Creating TUN device...");
    let (mut tun, name) = create_tun("tun0")?;
    println!("Created device: {name}");

    println!("\nNow run:");
    println!("  sudo ip addr add 10.0.0.1/24 dev {name}");
    println!("  sudo ip link set {name} up");
    println!("  ping 10.0.0.2              # Test ICMP");
    println!("  telnet 10.0.0.2 8080       # Test TCP handshake");
    println!("\nWaiting for packets...\n");

    let mut buf = [0u8; ETHERNET_MTU];

    loop {
        let n = tun.read(&mut buf)?;

        if n < IPV4_HEADER_MIN_LEN {
            println!("Packet too short for IPv4 header ({n} bytes), skipping");
            continue;
        }

        let packet = &buf[..n];

        let version = packet[0] >> 4;
        if version != 4 {
            println!("Non-IPv4 packet (version {version}), skipping");
            continue;
        }

        // Parse IPv4 header
        let ihl = usize::from(packet[0] & 0x0F) * 4; // Header length in bytes
        let total_len = u16::from_be_bytes([packet[2], packet[3]]);
        let protocol = packet[9].into();
        let src_ip = &packet[12..16];
        let dst_ip = &packet[16..20];

        let proto_name = match protocol {
            IPPROTO_ICMP => "ICMP",
            IPPROTO_TCP => "TCP",
            IPPROTO_UDP => "UDP",
            _ => "OTHER",
        };

        println!(
            "IPv4 | {total_len} bytes | {proto_name} | {}.{}.{}.{} -> {}.{}.{}.{}",
            src_ip[0], src_ip[1], src_ip[2], src_ip[3], dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
        );

        // Handle ICMP echo requests (ping)
        if protocol == IPPROTO_ICMP && packet.len() >= ihl + 8 {
            let icmp_type = packet[ihl];
            let icmp_code = packet[ihl + 1];
            println!("      ICMP type={icmp_type} code={icmp_code}");

            // ICMP Echo Request: type=8, code=0
            if icmp_type == 8 && icmp_code == 0 {
                print!("      Building echo reply...");

                // Build reply packet starting with the received packet data
                let mut reply = [0u8; ETHERNET_MTU];
                reply[..n].copy_from_slice(packet);

                // Swap src and dst IP addresses
                reply[12..16].copy_from_slice(dst_ip);
                reply[16..20].copy_from_slice(src_ip);

                // Clear IP header checksum field before recalculating
                reply[10] = 0;
                reply[11] = 0;

                // Recalculate IP header checksum (covers only the IP header)
                let ip_checksum = calculate_checksum(&reply[..ihl]);
                reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

                // Change ICMP type to Echo Reply (type=0)
                reply[ihl] = 0;

                // Clear ICMP checksum field before recalculating
                reply[ihl + 2] = 0;
                reply[ihl + 3] = 0;

                // Recalculate ICMP checksum (covers the entire ICMP message)
                let icmp_checksum = calculate_checksum(&reply[ihl..n]);
                reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

                // Write reply packet to TUN device
                tun.write_all(&reply[..n])?;
                println!(" sent!");
            }
        }

        // Handle TCP packets (3-way handshake)
        if protocol == IPPROTO_TCP && packet.len() >= ihl + 20 {
            // Parse TCP header (minimum 20 bytes)
            let tcp_start = ihl;
            let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);
            let dst_port = u16::from_be_bytes([packet[tcp_start + 2], packet[tcp_start + 3]]);
            let seq_num = u32::from_be_bytes([
                packet[tcp_start + 4],
                packet[tcp_start + 5],
                packet[tcp_start + 6],
                packet[tcp_start + 7],
            ]);
            let ack_num = u32::from_be_bytes([
                packet[tcp_start + 8],
                packet[tcp_start + 9],
                packet[tcp_start + 10],
                packet[tcp_start + 11],
            ]);
            let flags = packet[tcp_start + 13];
            let syn_flag = flags & 0x02 != 0;
            let ack_flag = flags & 0x10 != 0;

            println!(
                "      TCP {src_port} -> {dst_port} | seq={seq_num} ack={ack_num} \
                | SYN={syn_flag} ACK={ack_flag}"
            );

            // Handle SYN packet (connection request)
            if syn_flag && !ack_flag {
                print!("      Building SYN-ACK...");

                // Build SYN-ACK response
                let mut reply = [0u8; ETHERNET_MTU];

                // IP header (20 bytes)
                reply[0] = 0x45; // Version 4, IHL 5 (20 bytes)
                reply[1] = 0x00; // DSCP/ECN
                let total_len = 40u16; // 20 (IP) + 20 (TCP)
                reply[2..4].copy_from_slice(&total_len.to_be_bytes());
                reply[4..6].copy_from_slice(&[0x00, 0x00]); // Identification
                // Flags + Fragment offset (Don't Fragment)
                reply[6..8].copy_from_slice(&[0x40, 0x00]);
                reply[8] = 64; // TTL
                #[allow(clippy::cast_possible_truncation)] // Value is 6
                {
                    reply[9] = IPPROTO_TCP as u8; // Protocol
                }

                // Checksum at bytes 10-11 is calculated later

                // Swap src and dst IPs
                reply[12..16].copy_from_slice(dst_ip);
                reply[16..20].copy_from_slice(src_ip);

                // Calculate IP header checksum
                reply[10] = 0;
                reply[11] = 0;
                let ip_checksum = calculate_checksum(&reply[..20]);
                reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

                // TCP header (20 bytes minimum)
                let tcp_start = 20;
                // Swap ports
                reply[tcp_start..tcp_start + 2].copy_from_slice(&dst_port.to_be_bytes());
                reply[tcp_start + 2..tcp_start + 4].copy_from_slice(&src_port.to_be_bytes());

                // Our sequence number (can be random, using 0 for simplicity)
                let our_seq = 0u32;
                reply[tcp_start + 4..tcp_start + 8].copy_from_slice(&our_seq.to_be_bytes());

                // Acknowledgment number = their seq + 1
                let our_ack = seq_num.wrapping_add(1);
                reply[tcp_start + 8..tcp_start + 12].copy_from_slice(&our_ack.to_be_bytes());

                // Data offset (5 * 4 = 20 bytes) in upper 4 bits
                reply[tcp_start + 12] = 0x50; // 5 << 4

                // Flags: SYN + ACK
                reply[tcp_start + 13] = 0x12; // SYN (0x02) | ACK (0x10)

                // Window size
                reply[tcp_start + 14..tcp_start + 16].copy_from_slice(&8192u16.to_be_bytes());

                // Checksum at bytes 16-17 (calculate with pseudo-header)
                // Urgent pointer
                reply[tcp_start + 18..tcp_start + 20].copy_from_slice(&[0x00, 0x00]);

                // Calculate TCP checksum with pseudo-header
                let tcp_len = 20u16;
                let mut pseudo_header = [0u8; 12];
                pseudo_header[0..4].copy_from_slice(&reply[12..16]); // Source IP
                pseudo_header[4..8].copy_from_slice(&reply[16..20]); // Dest IP
                pseudo_header[8] = 0; // Reserved
                #[allow(clippy::cast_possible_truncation)] // Value is 6
                {
                    pseudo_header[9] = IPPROTO_TCP as u8; // Protocol
                }
                pseudo_header[10..12].copy_from_slice(&tcp_len.to_be_bytes());

                // Combine pseudo-header + TCP header for checksum
                let mut checksum_data = [0u8; 12 + 20];
                checksum_data[0..12].copy_from_slice(&pseudo_header);
                checksum_data[12..32].copy_from_slice(&reply[tcp_start..tcp_start + 20]);

                // Zero out checksum field before calculating
                checksum_data[12 + 16] = 0;
                checksum_data[12 + 17] = 0;

                let tcp_checksum = calculate_checksum(&checksum_data);
                reply[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

                // Write SYN-ACK packet to TUN device
                tun.write_all(&reply[..40])?;
                println!(" sent!");
            }
        }
    }
}
