####################################################################################################
# Config
####################################################################################################

set dotenv-load

project-name := 'typenet'
user := env('USER')

server-addr := '10.0.0.2'
server-port := '8080'

# NOTE: "TUN_DEVICE_NAME" is also read by the server with a "tun0" fallback
tun-name := env('TUN_DEVICE_NAME', 'tun0')
tun-cidr := env('TUN_IP_CIDR', '10.0.0.1/24')

tshark-cmd := 'tshark -n --print' \
    + ' -o ip.check_checksum:true -o tcp.check_checksum:true -o udp.check_checksum:true'

####################################################################################################
# Running the server (including TUN device setup)
####################################################################################################

# Run the server (default recipe)
[continue]
serve: tun
    cargo run

# Create the TUN device if it doesn't already exist
tun:
    @if ! ip addr show {{ tun-name }} >/dev/null 2>&1; then \
        echo 'TUN device {{ tun-name }} not found'; \
        just tun-create; \
    fi

# Internal helper for the `tun` recipe (also used in CI for unconditional creation)
[private]
[confirm(f'Create TUN device {{ tun-name }}? (uses sudo)')]
tun-create:
    sudo ip tuntap add dev {{ tun-name }} mode tun user {{ user }}
    sudo ip addr add {{ tun-cidr }} dev {{ tun-name }}
    sudo ip link set {{ tun-name }} up
    @echo 'TUN device created: name={{ tun-name }}, CIDR={{ tun-cidr }}, user={{ user }}'

# Remove the TUN device manually instead of waiting for it to be destroyed on reboot (uses sudo)
tun-del:
    sudo ip link del {{ tun-name }}

####################################################################################################
# Connecting as a client
####################################################################################################

# Connect to the server using TCP (telnet)
tcp:
    telnet {{ server-addr }} {{ server-port }}

# Connect to the server using TCP (netcat)
tcp-nc:
    nc -Nnv {{ server-addr }} {{ server-port }}

# Connect to the server using UDP
udp:
    -nc -nu {{ server-addr }} {{ server-port }}

# Connect to the server using ICMP
[continue]
icmp:
    ping {{ server-addr }}

####################################################################################################
# Observation and stress testing
####################################################################################################

# Capture and print TUN device traffic and save to PCAP
[
    arg('pcap', short, long, help='Name of PCAP file to write'),
    arg('x', short, value='-x', help='Show hex and ASCII')
]
[continue]
sniff pcap=f'{{ project-name }}.pcap' x='': tun
    {{ tshark-cmd }} -i {{ tun-name }} -w {{ pcap }} {{ x }}

# Read a PCAP file with TShark
[
    arg('pcap', short, long, help='Name of PCAP file to read'),
    arg('x', short, value='-x', help='Show hex and ASCII'),
    arg('V', short, value='-V', help='Show full packet dissection')
]
sniff-inspect pcap=f'{{ project-name }}.pcap' x='' V='':
    {{ tshark-cmd }} -r {{ pcap }} {{ x }} {{ V }} | "${PAGER:-less}"

# Remove the saved PCAP file
[arg('pcap', short, long, help='Name of PCAP file to remove')]
sniff-clean pcap=f'{{ project-name }}.pcap':
    rm {{ pcap }}

# Send a file through the echo server using TCP and diff the reply against the original
[
    arg('input-file', short='f', long, help='File to send'),
    arg('echo-file', short, long, help='Output location for echoed data'),
    arg('timeout-secs', short='s', long, help='Number of seconds to wait for echo')
]
throughput input-file='README.md' echo-file=f'/tmp/{{ project-name }}-out' timeout-secs='60':
    nc -Nnvw {{ timeout-secs }} {{ server-addr }} {{ server-port }} \
        < {{ input-file }} > {{ echo-file }}

    if command -v delta >/dev/null 2>&1; then \
        delta --paging never {{ input-file }} {{ echo-file }}; \
    else \
        diff {{ input-file }} {{ echo-file }}; \
    fi

    echo 'Echoed data matched input exactly'

# Add emulation of real-world networks to the TUN device (uses sudo)
[
    arg('delay', short, long),
    arg('loss', short, long),
    arg('corrupt', short, long),
    arg('duplicate', short='u', long),
    arg('reorder', short, long)
]
loss delay='100ms' loss='1%' corrupt='1%' duplicate='1%' reorder='1%': tun
    sudo tc qdisc replace dev {{ tun-name }} root netem \
        delay {{ delay }} 20ms 25% distribution paretonormal \
        loss random {{ loss }} 25% \
        corrupt {{ corrupt }} 25% \
        duplicate {{ duplicate }} 25% \
        reorder {{ reorder }} 25%

# Show current network emulation and packet counters
loss-show:
    tc -stats qdisc show dev {{ tun-name }}

# Remove emulated network conditions (uses sudo)
loss-clear:
    sudo tc qdisc del dev {{ tun-name }} root

####################################################################################################
# Testing and quality
####################################################################################################

# Run tests, lints, format checking, and spell checking to match CI
all-checks: (test '--quiet') lint-targets fmt-check spell-check

# Run tests, including ignored
test *ARGS: tun
    cargo test --workspace --all-targets {{ ARGS }} -- --include-ignored

# Generate test coverage report and print summary (includes ignored tests)
cov *ARGS: tun
    cargo llvm-cov {{ ARGS }} -- --include-ignored

# Generate HTML test coverage report and open in browser (includes ignored tests)
cov-open: (cov '--open')

# Lint with Clippy, denying warnings
lint *ARGS:
    cargo clippy --workspace --all-targets {{ ARGS }} -- --deny warnings

# Lint with Clippy for {aarch64,x86_64}-unknown-linux-gnu, denying warnings
lint-targets: (lint '--target' 'aarch64-unknown-linux-gnu') \
              (lint '--target' 'x86_64-unknown-linux-gnu')

# Check formatting
fmt-check:
    cargo fmt --all --check && echo 'Formatting check passed'

# Check spelling with Codebook
spell-check:
    git ls-files -z | xargs -0 codebook-lsp lint
