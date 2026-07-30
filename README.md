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
  - `telnet`, `nc`/`netcat`, and `ping` (likely already installed)
  - [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) (only if generating test coverage reports)

### Steps

Create a TUN device using the provided script (once per reboot):

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
