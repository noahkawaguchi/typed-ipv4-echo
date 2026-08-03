# Typenet

Typenet is a userspace IPv4/ICMP/TCP/UDP implementation and echo server that operates over Linux TUN devices. This project demonstrates low-level networking in Rust, working with packet bytes and syscalls while focusing on type safety and manual protocol implementations.

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Running the Server](#running-the-server)
5. [Connecting as a Client](#connecting-as-a-client)
6. [Testing](#testing)
7. [Development and CI](#development-and-ci)

## Features

- **Type Safety**: Leverages Rust's strong type system and zero-cost abstractions to safely create and uphold static guarantees without compromising on performance
- **Near-Zero Dependencies**: Depends only on the Rust Standard Library and `libc` (raw FFI to access platform C APIs), implementing all other logic from scratch
- **TUN Device Integration**: Performs low-level packet I/O using Linux TUN virtual network interfaces rather than sockets
- **Multi-Protocol Support**: Manages TCP connections, ICMP Echo Request/Reply, and UDP datagrams
- **Flexible Configuration and Logging**: Allows customization of key parameters at runtime (see [Environment Variables](#environment-variables) below)
- **Graceful Shutdown**: Catches SIGINT, drains TCP connections with a timeout, and exits cleanly

### TCP Implementation

Although the TCP implementation is not complete, it covers a significant portion of RFC 9293 and is capable of reliable transmission of data in degraded network conditions (see [Network Emulation](#network-emulation) below). Some highlights include:

- Three-way handshake (passive open)
- 4-tuple-keyed state machine
- Data receipt and transmission (currently echo only)
- Retransmissions with binary exponential backoff
- Flow control (respects peer's window and buffers remaining bytes to send when the window opens)
- Active close, passive close, and simultaneous close
- Handling of unknown and aborted connections

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

- Linux (for its TUN devices and various low-level APIs)
- `sudo` privileges (for creating and managing TUN devices)
- For [Nix](https://github.com/NixOS/nix) users, the toolchain is included as a flake.
- Otherwise, install:
  - The [Rust toolchain](https://rust-lang.org/tools/install)
  - The command runner [Just](https://github.com/casey/just)
  - `telnet`, `nc`/`netcat`, `ping`, and `tc` (likely already installed)
  - [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) (only if generating test coverage reports)
  - [Codebook](https://github.com/blopker/codebook) (only if spell checking)

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

```sh
just sniff          # Capture, log, and save to PCAP
just sniff-inspect  # Read back the saved PCAP file
just sniff-clean    # Remove the saved PCAP file
```

For each of these three recipes, see `just --usage <RECIPE>` for further options.

</details>

## Running the Server

### Environment Variables

<details>
<summary><i>Optional environment variable configuration (click to expand)</i></summary>
<br />

The following environment variables can be used to configure the TUN device and server. A `.env` file will automatically be read if present.

| Key                     | Meaning                                                   | Default     |
| ----------------------- | --------------------------------------------------------- | ----------- |
| TYPENET_TUN_NAME        | Name of the TUN device to create and use                  | `tun0`      |
| TYPENET_TUN_CIDR        | CIDR used when creating the TUN device                    | 10.0.0.1/24 |
| TYPENET_INIT_RTO_MILLIS | Initial retransmission timeout before exponential backoff | 500         |
| TYPENET_MAX_RETRANSMITS | Number of retransmissions before giving up                | 5           |
| TYPENET_GRACE_SECS      | Wait time before shutdown when draining connections       | 5           |
| TYPENET_LOG_LEVEL       | Level of output for logging (see table below)             | 3           |

| Log level | Meaning                                                                       |
| --------- | ----------------------------------------------------------------------------- |
| 0         | No output at all                                                              |
| 1         | Server startup and shutdown information, but nothing about individual packets |
| 2         | Minimal indicators for each packet with no details                            |
| 3         | Full details for each packet                                                  |

</details>

### Build and Run

You will be prompted to create the TUN device on first use, once per reboot, which requires `sudo` privileges.

```sh
just serve
```

The server will attach to the TUN device, listen for and reply to packets, and log processed data until it receives SIGINT (Ctrl+C).

## Connecting as a Client

With the server running, the different protocols can be tested from another terminal. If connecting with TCP or UDP, type a message and press Enter to see it echoed back.

```sh
just tcp     # TCP using telnet
just tcp-nc  # TCP using netcat
just udp
just icmp
```

To send a file through the echo server using TCP and diff the echoed reply against the original:

```sh
just throughput                # Defaults to README.md
just throughput -f Cargo.toml  # Send Cargo.toml instead
```

See `just --usage throughput` for further options.

### Network Emulation

To emulate real-world networks with delay/loss/corruption/duplication/reordering:

```sh
just loss        # Add the emulation to the device (uses sudo)
just loss-show   # Show current network emulation and packet counters
just loss-clear  # Remove emulated network conditions (uses sudo)
```

See `just --usage loss` for further options.

## Testing

As with running the server, you will be prompted to create the TUN device if it does not already exist.

```sh
just test
```

Or with a coverage report:

```sh
just cov       # Text summary
just cov-open  # Generate detailed HTML and open in browser
```

The project includes comprehensive unit and integration tests for:

- Parsing, send/receive logic, and encoding for IPv4 headers, TCP segments, ICMP Echo Request/Reply, and UDP datagrams
- Server loop packet I/O, timers, and connection draining
- Low-level signal handling and syscall interrupts
- Internet checksum calculation
- Serial number arithmetic
- Custom type invariants

## Development and CI

Tests, lints, format checking, and spell checking run in CI (as defined in [.github/workflows/ci.yml](.github/workflows/ci.yml)) and must all pass before merging into `main`. Tests and lints run on both `ubuntu-24.04-arm` and `ubuntu-24.04` because the results can differ between architectures, especially due to the C FFI.

The project takes a strict approach to linting (as defined in [Cargo.toml](Cargo.toml)), completely forbidding panicking constructs like `unwrap` and `expect` and isolating limited use of `unsafe`.

The [justfile](justfile) includes recipes for running CI checks locally. The `lint-targets` recipe cross-compiles and lints for both `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-gnu`. If not using Nix, this requires `rustup target add <TARGET>` for one or both of the targets depending on whether your host platform is already one of the two.

```sh
just lint
just lint-targets
just fmt-check
just spell-check
just all-checks  # All CI checks (including tests)
```
