####################################################################################################
# Connecting as a client
####################################################################################################

addr := '10.0.0.2'
port := '8080'

# Connect to the server using TCP (telnet)
tcp:
    telnet {{ addr }} {{ port }}

# Connect to the server using TCP (netcat)
tcp-nc:
    nc {{ addr }} {{ port }}

# Connect to the server using ICMP
icmp:
    ping {{ addr }}

# Connect to the server using UDP
udp:
    nc -u {{ addr }} {{ port }}

####################################################################################################
# Testing and quality
####################################################################################################

# Run tests, lints, format checking, and spell checking to match CI
all-checks: (test '--quiet') lint-targets fmt-check spell-check

# Run tests, including ignored
test *ARGS:
    cargo test --workspace --all-targets {{ ARGS }} -- --include-ignored

# Generate test coverage and open in browser (includes ignored tests)
coverage:
    cargo llvm-cov --open -- --include-ignored

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
