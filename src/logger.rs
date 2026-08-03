use {
    crate::{
        ipv4_header::Ipv4Header,
        protocol::handler::{Encode, ProtocolHandler},
    },
    std::{
        fmt::Display,
        io::{self, Write as _},
        str::FromStr,
        sync::atomic::{AtomicU8, Ordering},
    },
};

/// Internal atomic representation of the global log level.
static LOG_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::PacketVerbose as u8);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum LogLevel {
    /// No output at all.
    Silent = 0,

    /// Server startup and shutdown information, but nothing about individual packets.
    ServerInfo = 1,

    /// Minimal indicators for each packet with no details.
    PacketQuiet = 2,

    /// Full details for each packet.
    #[default]
    PacketVerbose = 3,
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "0" => Ok(Self::Silent),
            "1" => Ok(Self::ServerInfo),
            "2" => Ok(Self::PacketQuiet),
            "3" => Ok(Self::PacketVerbose),
            _ => Err("Log level must be a digit between 0 and 3 inclusive"),
        }
    }
}

impl From<LogLevel> for u8 {
    fn from(value: LogLevel) -> Self { value as Self }
}

/// Sets the global log level to `level`.
pub fn set_level(level: LogLevel) { LOG_LEVEL.store(level.into(), Ordering::Relaxed); }

/// Loads the atomic and converts it to `LogLevel`, silently accepting values greater than 3 as
/// equivalent to 3. This function should stay private to this module because outside the module,
/// trying to convert a `u8` that doesn't exactly match a variant should be considered an error.
fn load_level() -> LogLevel {
    match LOG_LEVEL.load(Ordering::Relaxed) {
        0 => LogLevel::Silent,
        1 => LogLevel::ServerInfo,
        2 => LogLevel::PacketQuiet,
        3.. => LogLevel::PacketVerbose,
    }
}

/// Prints a visual divider to stdout if and how the log level allows.
pub(crate) fn divider() {
    match load_level() {
        LogLevel::Silent | LogLevel::ServerInfo => {}
        // Buffered until the next newline or flush, which is desired
        LogLevel::PacketQuiet => print!(" "),
        LogLevel::PacketVerbose => println!("\n{:=<80}\n", ""),
    }
}

/// Logs information about the server to stdout if the log level allows.
pub fn server_info(msg: impl Display) {
    if load_level() >= LogLevel::ServerInfo {
        println!("{msg}");
    }
}

/// Logs receipt of a packet to stdout if and how the log level allows.
pub(crate) fn pkt_in(ipv4_header: &Ipv4Header, proto_handler: &ProtocolHandler) -> io::Result<()> {
    match load_level() {
        LogLevel::Silent | LogLevel::ServerInfo => {}
        LogLevel::PacketQuiet => {
            print!("↓");
            io::stdout().flush()?;
        }
        LogLevel::PacketVerbose => {
            println!("{ipv4_header}\n{proto_handler}\n{}", proto_handler.pretty_payload());
        }
    }

    Ok(())
}

/// Logs transmission of a packet to stdout if and how the log level allows.
pub(crate) fn pkt_out(ipv4_header: &Ipv4Header, proto_handler: &impl Encode) -> io::Result<()> {
    match load_level() {
        LogLevel::Silent | LogLevel::ServerInfo => {}
        LogLevel::PacketQuiet => {
            print!("↑");
            io::stdout().flush()?;
        }
        LogLevel::PacketVerbose => {
            println!("{ipv4_header}\n{proto_handler}\n{}", proto_handler.pretty_payload());
        }
    }

    Ok(())
}

/// Logs packet-related information and formatting other than the packets themselves to stdout if
/// the log level allows.
pub(crate) fn pkt_extra(msg: impl Display) {
    if load_level() >= LogLevel::PacketVerbose {
        println!("{msg}");
    }
}

/// Logs an error handling a packet to stderr if the log level allows.
pub(crate) fn pkt_err(msg: impl Display) {
    if load_level() >= LogLevel::PacketVerbose {
        eprintln!("{msg}");
    }
}
