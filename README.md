# Typenet

Typenet is a userspace IPv4/ICMP/TCP/UDP implementation and echo server that operates over Linux TUN devices. This project demonstrates low-level networking in Rust, working with packet bytes and syscalls while focusing on type safety and manual protocol implementations.

## Table of Contents

1. [Goals and Non-Goals](#goals-and-non-goals)
2. [Features](#features)
3. [Design](#design)
4. [Prerequisites](#prerequisites)
5. [Running the Server](#running-the-server)
6. [Connecting as a Client](#connecting-as-a-client)
7. [Testing](#testing)
8. [Development and CI](#development-and-ci)
9. [Demos](#demos)

## Goals and Non-Goals

| Goal                                             | Non-goal                                   |
| ------------------------------------------------ | ------------------------------------------ |
| Learning and demonstration project               | Production-ready stack                     |
| Direct engagement with low-level Linux APIs      | Cross-platform abstraction layers          |
| Manual parsing/encoding of a few key protocols   | Supporting as many protocols as possible   |
| No panicking                                     | Avoiding theoretically infallible `Result` |
| Maximal type safety at little to no cost         | Absolutely zero-cost abstractions only     |
| Stack allocation and references where reasonable | No heap, `no_std`                          |

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

## Design

### Static Dispatch Architecture

The server separates IPv4 handling from ICMP/TCP/UDP-specific logic using a `ProtocolHandler` enum with variants for each supported protocol.

```
╭─────────────────────────────────╮
│      TUN device, main loop,     │
│        shutdown signals         │
╰────────────────┬────────────────╯
                 │
                 ▼
╭─────────────────────────────────╮
│           IPv4 header           │
│         parsing/writing         │
╰────────────────┬────────────────╯
                 │
                 ▼
╭─────────────────────────────────╮
│      ProtocolHandler enum       │
│        (static dispatch)        │
╰────┬───────────┬───────────┬────╯
     │           │           │
     ▼           ▼           ▼
╭─────────╮ ╭─────────╮ ╭─────────╮
│  ICMP   │ │   TCP   │ │   UDP   │
│ handler │ │ handler │ │ handler │
╰─────────╯ ╰─────────╯ ╰─────────╯
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
| TYPENET_LOG_LEVEL       | Level of output for logging (see table below)             | 4           |

| Log level | Meaning                                                                       |
| --------- | ----------------------------------------------------------------------------- |
| 0         | No output at all                                                              |
| 1         | Server startup and shutdown information, but nothing about individual packets |
| 2         | Minimal indicators for each packet with no details                            |
| 3         | Packet header details but only payload lengths and whether they are UTF-8     |
| 4         | Packet header details and payload content                                     |

</details>

### Build and Run

You will be prompted to create the TUN device on first use, once per reboot, which requires `sudo` privileges. The server will attach to the TUN device, listen for and reply to packets, and log processed data until it receives SIGINT (Ctrl+C).

```sh
just serve
```

The [`justfile`](justfile) also includes recipes for saving logs to file.

```sh
just serve-save  # Run and save log file to `logs` directory
just log-clean   # Remove `logs` directory
```

## Connecting as a Client

### Interactive Use

With the server running, the different protocols can be tested from another terminal. If connecting with TCP or UDP, type a message and press Enter to see it echoed back.

```sh
just tcp     # TCP using telnet
just tcp-nc  # TCP using netcat
just udp
just icmp
```

### File Transfer

To send a file through the echo server using TCP and diff the echoed reply against the original:

```sh
just throughput                # Defaults to README.md
just throughput -f Cargo.toml  # Send Cargo.toml instead
```

See `just --usage throughput` for further options.

### Network Emulation

To emulate real-world networks with delay/loss/corruption/duplication/reordering, run the `loss` recipe and then try connecting to the server again.

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

Tests, lints, format checking, and spell checking run in CI (as defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml)) and must all pass before merging into `main`. Tests and lints run on both `ubuntu-24.04-arm` and `ubuntu-24.04` because the results can differ between architectures, especially due to the C FFI.

The project takes a strict approach to linting (as defined in [`Cargo.toml`](Cargo.toml)), completely forbidding panicking constructs like `unwrap` and `expect` and isolating limited use of `unsafe`.

The [`justfile`](justfile) includes recipes for running CI checks locally. The `lint-targets` recipe cross-compiles and lints for both `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-gnu`. If not using Nix, this requires `rustup target add <TARGET>` for one or both of the targets depending on whether your host platform is already one of the two.

```sh
just lint
just lint-targets
just fmt-check
just spell-check
just all-checks  # All CI checks (including tests)
```

## Demos

### "hello world" Exchange and Server Shutdown

This example includes a brief exchange of "hello" and "world" before active close from the server side and draining of TCP connections.

<details>
<summary><i>Example log (click to expand)</i></summary>
<br />

```log
[00:00:00.000] Waiting for packets on TUN device tun0 (Ctrl+C to stop)

================================================================================

 ==== Packet received ====
00:00:01.681
IPv4 | 60 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 53666 -> 8080 | seq=1,250,353,561 ack=0 win=64,240 | SYN
<no payload>

 ==== Packet sent ====
00:00:01.681
IPv4 | 40 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 53666 | seq=2,732,711,060 ack=1,250,353,562 win=65,535 | SYN-ACK
<no payload>

================================================================================

 ==== Packet received ====
00:00:01.681
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 53666 -> 8080 | seq=1,250,353,562 ack=2,732,711,061 win=64,240 | ACK
<no payload>

<no reply>

================================================================================

 ==== Packet received ====
00:00:02.957
IPv4 | 46 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 53666 -> 8080 | seq=1,250,353,562 ack=2,732,711,061 win=64,240 | ACK
6-byte UTF-8 payload: hello\n

 ==== Packet sent ====
00:00:02.957
IPv4 | 46 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 53666 | seq=2,732,711,061 ack=1,250,353,568 win=65,535 | ACK
6-byte UTF-8 payload: hello\n

================================================================================

 ==== Packet received ====
00:00:02.957
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 53666 -> 8080 | seq=1,250,353,568 ack=2,732,711,067 win=64,234 | ACK
<no payload>

<no reply>

================================================================================

 ==== Packet received ====
00:00:04.306
IPv4 | 46 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 53666 -> 8080 | seq=1,250,353,568 ack=2,732,711,067 win=64,234 | ACK
6-byte UTF-8 payload: world\n

 ==== Packet sent ====
00:00:04.306
IPv4 | 46 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 53666 | seq=2,732,711,067 ack=1,250,353,574 win=65,535 | ACK
6-byte UTF-8 payload: world\n

================================================================================

 ==== Packet received ====
00:00:04.307
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 53666 -> 8080 | seq=1,250,353,574 ack=2,732,711,073 win=64,228 | ACK
<no payload>

<no reply>

================================================================================


[00:00:06.030] Shutdown signal received, closing established connections...

================================================================================

 ==== Packet sent ====
00:00:06.030
IPv4 | 40 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 53666 | seq=2,732,711,073 ack=1,250,353,574 win=65,535 | FIN-ACK
<no payload>

================================================================================

 ==== Packet received ====
00:00:06.074
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 53666 -> 8080 | seq=1,250,353,574 ack=2,732,711,074 win=64,227 | ACK
<no payload>

<no reply>

================================================================================

 ==== Packet received ====
00:00:07.321
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 53666 -> 8080 | seq=1,250,353,574 ack=2,732,711,074 win=64,227 | FIN-ACK
<no payload>

 ==== Packet sent ====
00:00:07.321
IPv4 | 40 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 53666 | seq=2,732,711,074 ack=1,250,353,575 win=65,535 | ACK
<no payload>

================================================================================


[00:00:07.321] All connections closed within grace period, exiting
```

</details>

### Echoing `Cargo.toml`

This example shows the bytes of `Cargo.toml` being echoed through the server instead of simple interactive use.

<details>
<summary><i>Example log (click to expand)</i></summary>
<br />

```log
[00:00:00.000] Waiting for packets on TUN device tun0 (Ctrl+C to stop)

================================================================================

 ==== Packet received ====
00:00:03.974
IPv4 | 60 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 58716 -> 8080 | seq=2,581,556,073 ack=0 win=64,240 | SYN
<no payload>

 ==== Packet sent ====
00:00:03.974
IPv4 | 40 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 58716 | seq=3,071,982,751 ack=2,581,556,074 win=65,535 | SYN-ACK
<no payload>

================================================================================

 ==== Packet received ====
00:00:03.974
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 58716 -> 8080 | seq=2,581,556,074 ack=3,071,982,752 win=64,240 | ACK
<no payload>

<no reply>

================================================================================

 ==== Packet received ====
00:00:03.975
IPv4 | 576 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 58716 -> 8080 | seq=2,581,556,074 ack=3,071,982,752 win=64,240 | ACK
536-byte UTF-8 payload

 ==== Packet sent ====
00:00:03.975
IPv4 | 576 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 58716 | seq=3,071,982,752 ack=2,581,556,610 win=65,535 | ACK
536-byte UTF-8 payload

================================================================================

 ==== Packet received ====
00:00:03.975
IPv4 | 576 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 58716 -> 8080 | seq=2,581,556,610 ack=3,071,982,752 win=64,240 | ACK
536-byte UTF-8 payload

 ==== Packet sent ====
00:00:03.975
IPv4 | 576 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 58716 | seq=3,071,983,288 ack=2,581,557,146 win=65,535 | ACK
536-byte UTF-8 payload

================================================================================

 ==== Packet received ====
00:00:03.975
IPv4 | 320 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 58716 -> 8080 | seq=2,581,557,146 ack=3,071,982,752 win=64,240 | ACK
280-byte UTF-8 payload

 ==== Packet sent ====
00:00:03.975
IPv4 | 320 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 58716 | seq=3,071,983,824 ack=2,581,557,426 win=65,535 | ACK
280-byte UTF-8 payload

================================================================================

 ==== Packet received ====
00:00:03.975
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 58716 -> 8080 | seq=2,581,557,426 ack=3,071,982,752 win=64,240 | FIN-ACK
<no payload>

 ==== Packet sent ====
00:00:03.975
IPv4 | 40 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 58716 | seq=3,071,984,104 ack=2,581,557,427 win=65,535 | FIN-ACK
<no payload>

================================================================================

 ==== Packet received ====
00:00:03.975
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 58716 -> 8080 | seq=2,581,557,427 ack=3,071,983,288 win=63,784 | ACK
<no payload>

<no reply>

================================================================================

 ==== Packet received ====
00:00:03.975
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 58716 -> 8080 | seq=2,581,557,427 ack=3,071,983,824 win=63,784 | ACK
<no payload>

<no reply>

================================================================================

 ==== Packet received ====
00:00:03.975
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 58716 -> 8080 | seq=2,581,557,427 ack=3,071,984,104 win=63,784 | ACK
<no payload>

<no reply>

================================================================================

 ==== Packet received ====
00:00:03.975
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 58716 -> 8080 | seq=2,581,557,427 ack=3,071,984,105 win=63,784 | ACK
<no payload>

<no reply>

================================================================================


[00:00:07.262] Shutdown signal received with no established connections, exiting
```

</details>

### Degraded Network Conditions

This example includes:

- Not letting an out-of-order FIN prematurely close the connection
- Dropping packets with invalid checksums
- Retransmitting a segment with exponential backoff until it is acknowledged

<details>
<summary><i>Example log (click to expand)</i></summary>
<br />

<!--
Commands used here for future reference:
  just loss --loss 50% --corrupt 25% --duplicate 50%
  just throughput --input-file Cargo.toml
-->

```log
[00:00:00.000] Waiting for packets on TUN device tun0 (Ctrl+C to stop)

================================================================================

 ==== Packet received ====
00:00:01.779
IPv4 | 60 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 45952 -> 8080 | seq=3,407,599,708 ack=0 win=64,240 | SYN
<no payload>

 ==== Packet sent ====
00:00:01.780
IPv4 | 40 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 45952 | seq=948,924,240 ack=3,407,599,709 win=65,535 | SYN-ACK
<no payload>

================================================================================

 ==== Packet received ====
00:00:01.864
IPv4 | 576 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 45952 -> 8080 | seq=3,407,599,709 ack=948,924,241 win=64,240 | ACK
536-byte UTF-8 payload

 ==== Packet sent ====
00:00:01.864
IPv4 | 576 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 45952 | seq=948,924,241 ack=3,407,600,245 win=65,535 | ACK
536-byte UTF-8 payload

================================================================================

 ==== Packet received ====
00:00:01.864
IPv4 | 576 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 45952 -> 8080 | seq=3,407,600,245 ack=948,924,241 win=64,240 | ACK
536-byte UTF-8 payload

 ==== Packet sent ====
00:00:01.864
IPv4 | 576 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 45952 | seq=948,924,777 ack=3,407,600,781 win=65,535 | ACK
536-byte UTF-8 payload

================================================================================

 ==== Packet received ====
00:00:01.872
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 45952 -> 8080 | seq=3,407,601,061 ack=948,924,241 win=64,240 | FIN-ACK
<no payload>

 ==== Packet sent ====
00:00:01.872
IPv4 | 40 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 45952 | seq=948,925,313 ack=3,407,600,781 win=65,535 | ACK
<no payload>

================================================================================

[00:00:01.933] Skipping packet: Invalid TCP checksum

================================================================================

 ==== Packet received ====
00:00:01.956
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 45952 -> 8080 | seq=3,407,601,062 ack=948,925,313 win=63,784 | ACK
<no payload>

<no reply>

================================================================================

 ==== Packet received ====
00:00:01.957
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 45952 -> 8080 | seq=3,407,601,062 ack=948,924,777 win=63,784 | ACK
<no payload>

<no reply>

================================================================================

 ==== Packet received ====
00:00:02.238
IPv4 | 320 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 45952 -> 8080 | seq=3,407,600,781 ack=948,925,313 win=63,784 | FIN-ACK
280-byte UTF-8 payload

 ==== Packet sent ====
00:00:02.238
IPv4 | 320 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 45952 | seq=948,925,313 ack=3,407,601,062 win=65,535 | FIN-ACK
280-byte UTF-8 payload

================================================================================

[00:00:02.336] Skipping packet: Invalid IPv4 header checksum

================================================================================

 ==== Packet sent (retransmission) ====
00:00:02.742
IPv4 | 320 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 45952 | seq=948,925,313 ack=3,407,601,062 win=65,535 | FIN-ACK
280-byte UTF-8 payload

================================================================================

 ==== Packet sent (retransmission) ====
00:00:03.743
IPv4 | 320 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 45952 | seq=948,925,313 ack=3,407,601,062 win=65,535 | FIN-ACK
280-byte UTF-8 payload

================================================================================

[00:00:03.909] Skipping packet: Invalid TCP checksum

================================================================================

 ==== Packet sent (retransmission) ====
00:00:05.746
IPv4 | 320 bytes total | TCP | 10.0.0.2 -> 10.0.0.1
TCP | 8080 -> 45952 | seq=948,925,313 ack=3,407,601,062 win=65,535 | FIN-ACK
280-byte UTF-8 payload

================================================================================

 ==== Packet received ====
00:00:05.847
IPv4 | 40 bytes total | TCP | 10.0.0.1 -> 10.0.0.2
TCP | 45952 -> 8080 | seq=3,407,601,062 ack=948,925,594 win=63,784 | ACK
<no payload>

<no reply>

================================================================================


[00:00:09.633] Shutdown signal received with no established connections, exiting
```

</details>
