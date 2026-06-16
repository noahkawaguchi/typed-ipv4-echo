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
- Writing appropriate reply packets

The design also prioritizes controlled use of the heap only when it truly improves clarity and maintainability. Error messages use `String` and `Box` heap allocations for readable and safe inclusion of runtime data, but all of the core packet data is managed in two fixed-size arrays on the stack.

## Running the Server

### Prerequisites

- Linux (for its TUN device API)
- Rust toolchain ([install here](https://rust-lang.org/tools/install))
- `sudo` privileges (specifically CAP_NET_ADMIN for creating network interfaces)
- Optional: [Just](https://github.com/casey/just) command runner

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

Or manually:

```bash
telnet 10.0.0.2 8080  # TCP
nc 10.0.0.2 8080      # TCP
nc -u 10.0.0.2 8080   # UDP
ping 10.0.0.2         # ICMP
```

## Testing

Run the test suite:

```bash
cargo test                       # Pure unit tests with no dependencies
cargo test -- --include-ignored  # TUN device must already exist
```

The project includes comprehensive unit tests for:

- Internet checksum calculation
- IPv4 header parsing and creation
- ICMP Echo Request/Reply handling
- TCP handshake, connection state, and data echo logic
- UDP datagram parsing and echo responses
- Edge cases like malformed packets, empty payloads, and boundary values
