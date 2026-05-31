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

This project demonstrates low-level networking in Rust by implementing a userspace echo server that handles TCP handshakes, UDP datagrams, and ICMP ping requests. Rather than binding to sockets, it creates a virtual TUN network interface and manually processes raw IPv4 packets, providing insight into protocol implementation details while upholding type safety, performance, and maintainability.

## Features

- **Multi-Protocol Support**: Handles ICMP Echo Request/Reply, TCP three-way handshake with data echo, and UDP echo
- **TUN Device Integration**: Performs low-level packet I/O using `libc` and Linux TUN virtual network interfaces
- **Type-Safe Packet Parsing**: Leverages Rust's strong type system and zero-cost abstractions to safely interpret raw bytes as protocol structures
- **Graceful Shutdown**: Handles SIGINT and exits cleanly
- **Comprehensive Testing**: Includes unit tests for all packet handling logic with edge case coverage
- **Strict Linting**: Forbids `unwrap` and `expect` completely and isolates limited use of `unsafe`
- **Continuous Integration**: Runs tests, linting, formatting checks, and spell checks in CI and requires all to pass before merging into main

## Architecture

The server's design uses a `ProtocolHandler` trait (interface) to separate protocol-agnostic IPv4 handling from protocol-specific logic. At the same time, the design prioritizes controlled use of the heap only when it truly improves clarity and maintainability.

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
      ProtocolHandler trait
   (runtime polymorphism via Box)
└────┬───────────┬───────────┬──────┘
     │           │           │
     ▼           ▼           ▼
┌─────────┐ ┌─────────┐ ┌─────────┐
│  ICMP   │ │   TCP   │ │   UDP   │
│ handler │ │ handler │ │ handler │
└─────────┘ └─────────┘ └─────────┘
```

Each concrete protocol handler implements the `ProtocolHandler` trait and performs the following:

- Parsing the protocol-specific header and payload from raw bytes
- Writing an appropriate reply packet

At the cost of vtable lookups and one `Box` (heap-allocated smart pointer without reference counting) per pair of packets, this design enables straightforward testing via dependency injection and maintains a clear separation of concerns between IPv4 and TCP/UDP/ICMP.

Error messages use `String` heap allocations for readable and and safe inclusion of runtime data, but all of the core packet data is managed in two fixed-size arrays on the stack.

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
just tcp
just udp
just icmp
```

Or manually:

```bash
telnet 10.0.0.2 8080  # TCP
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
- TCP handshake and data echo logic
- UDP datagram parsing and echo responses
- Edge cases like malformed packets, empty payloads, and boundary values
