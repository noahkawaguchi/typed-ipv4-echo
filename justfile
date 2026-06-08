####################################################################################################
# Connecting as a client
####################################################################################################

addr := "10.0.0.2"
port := "8080"

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
# Development tasks
####################################################################################################

# Lint with Clippy for {aarch64,x86_64}-unknown-linux-gnu, denying warnings
lint: (lint-helper "aarch64") (lint-helper "x86_64")

# Lint with Clippy (denying warnings)
[private]
lint-helper arch:
    cargo clippy --workspace --all-targets --target {{ arch }}-unknown-linux-gnu -- --deny warnings
