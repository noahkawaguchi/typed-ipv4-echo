use {
    crate::{
        Local, Remote,
        ipv4_header::Ipv4Header,
        protocol::handler::{Encode, ProtocolHandler},
    },
    std::{
        fmt,
        io::{self, Write as _},
        str::FromStr,
        time::Instant,
    },
};

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

/// Wrapper struct for displaying the time elapsed since the inner `Instant`.
struct Timestamp(Instant);

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let elapsed = Instant::now().saturating_duration_since(self.0);
        let secs = elapsed.as_secs();
        let (mins, sub_min_secs) = (secs / 60, secs % 60);
        let (hrs, sub_hr_mins) = (mins / 60, mins % 60);
        write!(f, "{hrs:02}:{sub_hr_mins:02}:{sub_min_secs:02}.{:03}", elapsed.subsec_millis())
    }
}

pub struct Logger {
    /// The level of output for logging.
    level: LogLevel,

    /// The `Instant` at which `self` was created.
    birth: Instant,
}

impl Logger {
    pub(crate) fn new(level: LogLevel) -> Self { Self { level, birth: Instant::now() } }

    /// Prints a visual divider to stdout if and how the log level allows.
    pub(crate) fn divider(&self) {
        match self.level {
            LogLevel::Silent | LogLevel::ServerInfo => {}
            // Buffered until the next newline or flush, which is desired
            LogLevel::PacketQuiet => print!(" "),
            LogLevel::PacketDetails | LogLevel::PacketFull => println!("\n{:=<80}\n", ""),
        }
    }

    /// Logs a bare newline from the server without a timestamp.
    pub(crate) fn server_newline(&self) {
        if self.level >= LogLevel::ServerInfo {
            println!();
        }
    }

    /// Logs information about the server to stdout if the log level allows.
    pub(crate) fn server_info(&self, msg: impl fmt::Display) {
        if self.level >= LogLevel::ServerInfo {
            println!("[{}] {msg}", Timestamp(self.birth));
        }
    }

    /// Logs receipt of a packet to stdout if and how the log level allows.
    pub(crate) fn pkt_in(
        &self,
        ipv4_header: &Ipv4Header,
        proto_handler: &ProtocolHandler<Remote, Local>,
    ) -> io::Result<()> {
        self.pkt_in_or_out(true, ipv4_header, proto_handler)
    }

    /// Logs transmission of a packet to stdout if and how the log level allows.
    pub(crate) fn pkt_out(
        &self,
        ipv4_header: &Ipv4Header,
        proto_handler: &impl Encode<Local>,
    ) -> io::Result<()> {
        self.pkt_in_or_out(false, ipv4_header, proto_handler)
    }

    /// Logs receipt or transmission of a packet to stdout if and how the log level allows.
    fn pkt_in_or_out<S>(
        &self,
        is_in: bool,
        ipv4_header: &Ipv4Header,
        proto_handler: &impl Encode<S>,
    ) -> io::Result<()> {
        match self.level {
            LogLevel::Silent | LogLevel::ServerInfo => {}

            LogLevel::PacketQuiet => {
                print!("{}", if is_in { "↓" } else { "↑" });
                io::stdout().flush()?;
            }

            level @ (LogLevel::PacketDetails | LogLevel::PacketFull) => {
                println!(
                    "{}\n{ipv4_header}\n{proto_handler}\n{}",
                    Timestamp(self.birth),
                    proto_handler.pretty_payload(level == LogLevel::PacketFull)
                );
            }
        }

        Ok(())
    }

    /// Logs packet-related information and formatting other than the packets themselves to stdout
    /// if the log level allows.
    pub(crate) fn pkt_extra(&self, msg: impl fmt::Display) {
        if self.level >= LogLevel::PacketDetails {
            println!("{msg}");
        }
    }

    /// Logs an error handling a packet to stderr if the log level allows.
    pub(crate) fn pkt_err(&self, msg: impl fmt::Display) {
        if self.level >= LogLevel::PacketDetails {
            eprintln!("[{}] {msg}", Timestamp(self.birth));
        }
    }
}
