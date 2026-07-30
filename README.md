# typed-ipv4-echo

A type-safe, userspace IPv4 echo server implementing TCP, UDP, and ICMP protocols using Linux TUN devices.

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Running the Server](#running-the-server)
5. [Connecting as a Client](#connecting-as-a-client)
6. [Testing](#testing)

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
       TUN device, main loop,
         shutdown signals
└────────────────┬───────────────────┘
                 │
                 ▼
┌────────────────────────────────────┐
            IPv4 header
          parsing/writing
└────────────────┬───────────────────┘
                 │
                 ▼
┌───────────────────────────────────┐
       ProtocolHandler enum
         (static dispatch)
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

## Running the Server

### Prerequisites

- Linux (for its TUN device API)
- `sudo` privileges (specifically CAP_NET_ADMIN for creating network interfaces)
- For [Nix](https://github.com/NixOS/nix) users, the toolchain is included as a flake.
- Otherwise, install:
  - The [Rust toolchain](https://rust-lang.org/tools/install)
  - The command runner [Just](https://github.com/casey/just)
  - `telnet`, `nc`/`netcat`, `ping`, and `tc` (likely already installed)
  - [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) (only if capturing network traffic or reading PCAP files)
  - [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) (only if generating test coverage reports)

#### If using TShark:

The `dumpcap` binary requires CAP_NET_RAW and CAP_NET_ADMIN capabilities. It works to just use `sudo` and be done, but to be more granular:

- On FHS-based distros (i.e. most normal Linux): Grant it the capabilities as described [here](https://wiki.wireshark.org/capturesetup/captureprivileges).
- On NixOS: Enable the `wireshark` program and add yourself to the `"wireshark"` group. This creates a setcap wrapper that will automatically be given precedence by the `shellHook` in the project's flake.

```nix
programs.wireshark.enable = true;
users.users.<you>.extraGroups = [ "wireshark" ];
```

### Steps

Create the TUN device using the provided script (once per reboot):

```bash
sudo ./create-tun.sh
```

Build and run the server:

```bash
cargo run
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
just loss        # Add the emulation to the device (prompts for sudo)
just loss-show   # Show current network emulation and packet counters
just loss-clear  # Remove emulated network conditions (prompts for sudo)
```

Although the server logs incoming and outgoing packets, the `justfile` also includes recipes for capturing and logging traffic live and reading it back with TShark.

```bash
just sniff    # Run in another terminal while creating traffic
just inspect  # Read back the saved PCAP file
```

For the `throughput`, `loss`, `sniff`, and `inspect` recipes, see `just --usage <RECIPE>` for further options.

## Testing

For only pure unit tests with no dependencies, run:

```bash
cargo test
```

However, once the TUN device is created, the full test suite can run:

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
