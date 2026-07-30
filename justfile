####################################################################################################
# Config
####################################################################################################

project-name := 'typed-ipv4-echo'
server-addr := '10.0.0.2'
server-port := '8080'
tun := env('TUN_DEVICE_NAME', 'tun0')
tshark-cmd := 'tshark -n --print' \
    + ' -o ip.check_checksum:true -o tcp.check_checksum:true -o udp.check_checksum:true'

####################################################################################################
# Connecting as a client
####################################################################################################

# Connect to the server using TCP (telnet)
tcp:
    telnet {{ server-addr }} {{ server-port }}

# Connect to the server using TCP (netcat)
tcp-nc:
    nc {{ server-addr }} {{ server-port }}

# Connect to the server using ICMP
icmp:
    ping {{ server-addr }}

# Connect to the server using UDP
udp:
    nc -u {{ server-addr }} {{ server-port }}

####################################################################################################
# Observation and stress testing
####################################################################################################

# Capture and print TUN device traffic and save to PCAP
[
    arg('pcap', short, long, help='Name of PCAP file to write'),
    arg('x', short, value='-x', help='Show hex and ASCII')
]
sniff pcap=f'{{ project-name }}.pcap' x='':
    {{ tshark-cmd }} -i {{ tun }} -w {{ pcap }} {{ x }}

# Read a PCAP file with TShark
[
    arg('pcap', short, long, help='Name of PCAP file to read'),
    arg('x', short, value='-x', help='Show hex and ASCII'),
    arg('V', short, value='-V', help='Show full packet dissection')
]
inspect pcap=f'{{ project-name }}.pcap' x='' V='':
    {{ tshark-cmd }} -r {{ pcap }} {{ x }} {{ V }} | "${PAGER:-less}"

# Add emulation of real-world networks to the TUN device (prompts for sudo)
[
    arg('delay', short, long),
    arg('loss', short, long),
    arg('corrupt', short, long),
    arg('duplicate', short='u', long),
    arg('reorder', short, long)
]
loss delay='100ms' loss='1%' corrupt='1%' duplicate='1%' reorder='1%':
    sudo tc qdisc replace dev {{ tun }} root netem \
        delay {{ delay }} 20ms 25% distribution paretonormal \
        loss random {{ loss }} 25% \
        corrupt {{ corrupt }} 25% \
        duplicate {{ duplicate }} 25% \
        reorder {{ reorder }} 25%

# Show current network emulation and packet counters
loss-show:
    tc -stats qdisc show dev {{ tun }}

# Remove emulated network conditions (prompts for sudo)
loss-clear:
    sudo tc qdisc del dev {{ tun }} root

# Send a file through the TCP echo server and diff the echoed reply against the original
[
    arg('input-file', short='f', long, help='File to send'),
    arg('echo-file', short, long, help='Output location for echoed data'),
    arg('timeout-secs', short='s', long, help='Number of seconds to wait for echo')
]
throughput input-file='README.md' echo-file=f'/tmp/{{ project-name }}-out' timeout-secs='3':
    nc -nvw {{ timeout-secs }} {{ server-addr }} {{ server-port }} \
        < {{ input-file }} > {{ echo-file }}

    if command -v delta >/dev/null 2>&1; then \
        delta --paging never {{ input-file }} {{ echo-file }}; \
    else \
        diff {{ input-file }} {{ echo-file }}; \
    fi

    echo 'Echoed data matched input exactly'

####################################################################################################
# Testing and quality
####################################################################################################

# Run tests, lints, format checking, and spell checking to match CI
all-checks: (test '--quiet') lint-targets fmt-check spell-check

# Run tests, including ignored
test *ARGS:
    cargo test --workspace --all-targets {{ ARGS }} -- --include-ignored

# Generate test coverage report and print summary (includes ignored tests)
cov *ARGS:
    cargo llvm-cov {{ ARGS }} -- --include-ignored

# Generate HTML test coverage report and open in browser (includes ignored tests)
cov-open: (cov '--open')

# Lint with Clippy for {aarch64,x86_64}-unknown-linux-gnu, denying warnings
lint-targets: (lint '--target' 'aarch64-unknown-linux-gnu') \
              (lint '--target' 'x86_64-unknown-linux-gnu')

# Lint with Clippy, denying warnings
lint *ARGS:
    cargo clippy --workspace --all-targets {{ ARGS }} -- --deny warnings

# Check formatting
fmt-check:
    cargo fmt --all --check && echo 'Formatting check passed'

# Check spelling with Codebook
spell-check:
    git ls-files -z | xargs -0 codebook-lsp lint
