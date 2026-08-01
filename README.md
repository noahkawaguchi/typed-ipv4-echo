# Typenet

A type-safe, userspace IPv4 echo server implementing TCP, UDP, and ICMP protocols using Linux TUN devices.

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Prerequisites](#prerequisites)
5. [Running the Server](#running-the-server)
6. [Connecting as a Client](#connecting-as-a-client)
7. [Testing](#testing)

## Overview

This project demonstrates low-level networking in Rust by implementing a userspace echo server that operates over TCP, UDP, and ICMP. Using a virtual TUN network interface and manually processing raw IPv4 packets, it provides insight into protocol implementation details while upholding type safety, performance, and maintainability.

## Features

- **Minimal Dependencies**: Implements all necessary logic from scratch, depending only on `libc` to access platform C APIs
- **Multi-Protocol Support**: Manages TCP connections, ICMP Echo Request/Reply, and UDP datagrams
- **TUN Device Integration**: Performs low-level packet I/O using Linux TUN virtual network interfaces
- **Type-Safe Packet Parsing**: Leverages Rust's strong type system and zero-cost abstractions to safely interpret raw bytes as protocol structures
- **Graceful Shutdown**: Catches SIGINT, drains TCP connections with a timeout, and exits cleanly
- **Comprehensive Testing**: Includes unit tests for all packet handling logic with edge case coverage
- **Strict Linting**: Forbids panicking constructs like `unwrap` and `expect` completely and isolates limited use of `unsafe`
- **Continuous Integration**: Runs tests, linting, formatting checks, and spell checks in CI and requires all to pass before merging into main

## Architecture

The server separates protocol-agnostic IPv4 handling from protocol-specific ICMP/TCP/UDP logic using a `ProtocolHandler` enum with variants for each supported protocol.

```
┌────────────────────────────────────┐
│       TUN device, main loop,       │
│         shutdown signals           │
└────────────────┬───────────────────┘
                 │
                 ▼
┌────────────────────────────────────┐
│            IPv4 header             │
│          parsing/writing           │
└────────────────┬───────────────────┘
                 │
                 ▼
┌───────────────────────────────────┐
│       ProtocolHandler enum        │
│         (static dispatch)         │
└────┬───────────┬───────────┬──────┘
     │           │           │
     ▼           ▼           ▼
┌─────────┐ ┌─────────┐ ┌─────────┐
│  ICMP   │ │   TCP   │ │   UDP   │
│ handler │ │ handler │ │ handler │
└─────────┘ └─────────┘ └─────────┘
```

Each variant wraps a concrete protocol handler responsible for:

- Parsing protocol-specific headers and payloads from raw bytes
- Determining the packets to send to clients
- Encoding appropriate reply packets into raw bytes

## Prerequisites

- Linux (for its TUN device API)
- `sudo` privileges (for creating and managing TUN devices)
- For [Nix](https://github.com/NixOS/nix) users, the toolchain is included as a flake.
- Otherwise, install:
  - The [Rust toolchain](https://rust-lang.org/tools/install)
  - The command runner [Just](https://github.com/casey/just)
  - `telnet`, `nc`/`netcat`, `ping`, and `tc` (likely already installed)
  - [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) (only if generating test coverage reports)

<details>
<summary><i>Optional: Capture and save traffic with TShark (click to expand)</i></summary>
<br />

Although the server has logging functionality built in, [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) can also be used to capture network traffic on the TUN device and save/read PCAP files. In most package managers, the CLI-only version is called `tshark` or `wireshark-cli`, while the full [Wireshark](https://www.wireshark.org) GUI version is called `wireshark`.

If using TShark/Wireshark for live packet capture specifically, the `dumpcap` binary requires CAP_NET_RAW and CAP_NET_ADMIN capabilities. It works to just use `sudo` and be done, but to be more granular:

- On FHS-based distros (i.e. most normal Linux): Grant it the capabilities as described [here](https://wiki.wireshark.org/capturesetup/captureprivileges).
- On NixOS: Enable the `wireshark` program and add yourself to the `"wireshark"` group. This creates a setcap wrapper for `dumpcap` in your PATH.

```nix
programs.wireshark.enable = true;
users.users.<you>.extraGroups = [ "wireshark" ];
```

You should then be able to capture traffic without `sudo` by running `just sniff` in another terminal while creating traffic on the TUN device as explained below.

```bash
just sniff          # Capture, log, and save to PCAP
just sniff-inspect  # Read back the saved PCAP file
just sniff-clean    # Remove the saved PCAP file
```

For each of these three recipes, see `just --usage <RECIPE>` for further options.

</details>

## Running the Server

<details>
<summary><i>Optional environment variable configuration (click to expand)</i></summary>
<br />

The following environment variables can be used to configure the TUN device and server. A `.env` file will automatically be read if present.

| Key                     | Meaning                                                   | Default     |
| ----------------------- | --------------------------------------------------------- | ----------- |
| TYPENET_TUN_NAME        | Name of the TUN device to create and use                  | `tun0`      |
| TYPENET_TUN_CIDR        | CIDR used when creating the TUN device                    | 10.0.0.1/24 |
| TYPENET_GRACE_SECS      | Wait time before shutdown when draining connections       | 5           |
| TYPENET_INIT_RTO_MILLIS | Initial retransmission timeout before exponential backoff | 500         |
| TYPENET_MAX_RETRANSMITS | Number of retransmissions before giving up                | 5           |
| TYPENET_LOG_LEVEL       | Level of output for logging (see table below)             | 3           |

| Log level | Meaning                                                                       |
| --------- | ----------------------------------------------------------------------------- |
| 0         | No output at all                                                              |
| 1         | Server startup and shutdown information, but nothing about individual packets |
| 2         | Minimal indicators for each packet with no details                            |
| 3         | Full details for each packet                                                  |

---

</details>

You will be prompted to create the TUN device on first use, once per reboot, which requires `sudo` privileges.

Build and run the server:

```bash
just serve
```

The server will attach to the TUN device, listen for and reply to packets, and log processed data until it receives SIGINT (Ctrl+C).

## Connecting as a Client

With the server running, the different protocols can be tested from another terminal. If connecting with TCP or UDP, type a message and press Enter to see it echoed back.

```bash
just tcp     # TCP using telnet
just tcp-nc  # TCP using netcat
just udp
just icmp
```

To send a file through the echo server using TCP and diff the echoed reply against the original:

```bash
just throughput                # Defaults to README.md
just throughput -f Cargo.toml  # Send Cargo.toml instead
```

To emulate real-world networks with delay/loss/corruption/duplication/reordering:

```bash
just loss        # Add the emulation to the device (uses sudo)
just loss-show   # Show current network emulation and packet counters
just loss-clear  # Remove emulated network conditions (uses sudo)
```

See `just --usage throughput` and `just --usage loss` for further options.

## Testing

As with running the server, you will be prompted to create the TUN device if it does not already exist.

```bash
just test
```

Or with a coverage report:

```bash
just cov       # Text summary
just cov-open  # Generate detailed HTML and open in browser
```

The project includes comprehensive unit tests for:

- Internet checksum calculation
- IPv4 header parsing and creation
- ICMP Echo Request/Reply handling
- TCP handshake, connection state, and data echo logic
- UDP datagram parsing and echo responses
- Edge cases like malformed packets, empty payloads, and boundary values
