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

/// Flags to use when creating a TUN device.
///   `IFF_TUN`   - TUN device (no Ethernet headers) rather than TAP
///   `IFF_NO_PI` - Do not prepend packet metadata (get IP packet only)
#[allow(clippy::cast_possible_truncation)] // Because this is 0x1 | 0x1000, which fits in a short
const IFF_TUN_IFF_NO_PI: libc::c_short = (IFF_TUN | IFF_NO_PI) as libc::c_short;

/// Computes the Internet checksum (RFC 1071) for IP and ICMP headers (16-bit one's complement of
/// the one's complement sum).
fn calculate_checksum(data: &[u8]) -> u16 {
    // Sum all 16-bit words (deferred carries method)
    let mut sum = data
        .chunks(2)
        .map(|chunk| {
            // Put 16-bit words into 32 bits to accumulate carries in bits 16-31 when summing.
            // Treat an odd byte as the high byte of a 16-bit word.
            u32::from_be_bytes([0, 0, chunk[0], if chunk.len() == 2 { chunk[1] } else { 0 }])
        })
        .sum::<u32>();

    // Add carry bits back into sum (fold 32-bit sum to 16-bit)
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    #[allow(clippy::cast_possible_truncation)] // Just folded into 16 bits above, truncation desired
    {
        !sum as u16
    }
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
        ifr.ifr_name[i] = libc::c_char::from(b);
    }

    // Set flags
    ifr.ifr_ifru.ifru_flags = IFF_TUN_IFF_NO_PI;

    // Create the TUN interface
    let ret = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Extract the actual device name assigned by the kernel
    let actual_name = ifr
        .ifr_name
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| char::from(b))
        .collect();

    Ok((file, actual_name))
}

fn main() -> io::Result<()> {
    println!("Creating TUN device...");
    let (mut tun, name) = create_tun("tun0")?;
    println!("Created device: {name}");

    println!("\nNow run:");
    println!("  sudo ip addr add 10.0.0.1/24 dev {name}");
    println!("  sudo ip link set {name} up");
    println!("  ping 10.0.0.2");
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
    }
}
