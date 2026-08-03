use {
    crate::{
        ipv4_header::Ipv4Header,
        protocol::handler::{Encode, ProtocolHandler},
    },
    std::{
        fmt,
        io::{self, Write as _},
        str::FromStr,
        sync::{
            LazyLock,
            atomic::{AtomicU8, Ordering},
        },
        time::Instant,
    },
};

/// Internal atomic representation of the global log level.
static LOG_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::PacketFull as u8);

/// The `Instant` of the first timestamp access (i.e. first timestamped log).
static FIRST_TIMESTAMP_TIME: LazyLock<Instant> = LazyLock::new(Instant::now);

struct Timestamp;

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let elapsed = Instant::now().saturating_duration_since(*FIRST_TIMESTAMP_TIME);
        let secs = elapsed.as_secs();
        let (mins, sub_min_secs) = (secs / 60, secs % 60);
        let (hrs, sub_hr_mins) = (mins / 60, mins % 60);
        write!(f, "{hrs:02}:{sub_hr_mins:02}:{sub_min_secs:02}.{:03}", elapsed.subsec_millis())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum LogLevel {
    /// No output at all.
    Silent = 0,

    /// Server startup and shutdown information, but nothing about individual packets.
    ServerInfo = 1,

    /// Minimal indicators for each packet with no details.
    PacketQuiet = 2,

    /// Packet header details but only payload lengths and whether they are UTF-8.
    PacketDetails = 3,

    /// Packet header details and payload content.
    #[default]
    PacketFull = 4,
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "0" => Ok(Self::Silent),
            "1" => Ok(Self::ServerInfo),
            "2" => Ok(Self::PacketQuiet),
            "3" => Ok(Self::PacketDetails),
            "4" => Ok(Self::PacketFull),
            _ => Err("Log level must be a digit between 0 and 4 inclusive"),
        }
    }
}

impl From<LogLevel> for u8 {
    fn from(value: LogLevel) -> Self { value as Self }
}

/// Sets the global log level to `level`.
pub fn set_level(level: LogLevel) { LOG_LEVEL.store(level.into(), Ordering::Relaxed); }

/// Loads the atomic and converts it to `LogLevel`, silently accepting values greater than 4 as
/// equivalent to 4. This function should stay private to this module because outside the module,
/// trying to convert a `u8` that doesn't exactly match a variant should be considered an error.
fn load_level() -> LogLevel {
    match LOG_LEVEL.load(Ordering::Relaxed) {
        0 => LogLevel::Silent,
        1 => LogLevel::ServerInfo,
        2 => LogLevel::PacketQuiet,
        3 => LogLevel::PacketDetails,
        4.. => LogLevel::PacketFull,
    }
}

/// Prints a visual divider to stdout if and how the log level allows.
pub(crate) fn divider() {
    match load_level() {
        LogLevel::Silent | LogLevel::ServerInfo => {}
        // Buffered until the next newline or flush, which is desired
        LogLevel::PacketQuiet => print!(" "),
        LogLevel::PacketDetails | LogLevel::PacketFull => println!("\n{:=<80}\n", ""),
    }
}

/// Logs a bare newline from the server without a timestamp.
pub(crate) fn server_newline() {
    if load_level() >= LogLevel::ServerInfo {
        println!();
    }
}

/// Logs information about the server to stdout if the log level allows.
pub fn server_info(msg: impl fmt::Display) {
    if load_level() >= LogLevel::ServerInfo {
        println!("[{Timestamp}] {msg}");
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
        level @ (LogLevel::PacketDetails | LogLevel::PacketFull) => {
            println!(
                "{Timestamp}\n{ipv4_header}\n{proto_handler}\n{}",
                proto_handler.pretty_payload(level == LogLevel::PacketFull)
            );
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
        level @ (LogLevel::PacketDetails | LogLevel::PacketFull) => {
            println!(
                "{Timestamp}\n{ipv4_header}\n{proto_handler}\n{}",
                proto_handler.pretty_payload(level == LogLevel::PacketFull)
            );
        }
    }

    Ok(())
}

/// Logs packet-related information and formatting other than the packets themselves to stdout if
/// the log level allows.
pub(crate) fn pkt_extra(msg: impl fmt::Display) {
    if load_level() >= LogLevel::PacketDetails {
        println!("{msg}");
    }
}

/// Logs an error handling a packet to stderr if the log level allows.
pub(crate) fn pkt_err(msg: impl fmt::Display) {
    if load_level() >= LogLevel::PacketDetails {
        eprintln!("[{Timestamp}] {msg}");
    }
}
