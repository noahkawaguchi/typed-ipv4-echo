####################################################################################################
# Server recipes
####################################################################################################

# Build and run the server (default recipe)
[confirm("Runs the executable with sudo. Proceed?")]
serve: build
    sudo ./target/debug/typed-ipv4-echo

# Build the main server executable
build:
    cargo build

####################################################################################################
# Client recipes
####################################################################################################

addr := "10.0.0.2"
port := "8080"

# Connect to the server using TCP
tcp:
    telnet {{addr}} {{port}}

# Connect to the server using ICMP
icmp:
    ping {{addr}}

# Connect to the server using UDP
udp:
    nc -u {{addr}} {{port}}
