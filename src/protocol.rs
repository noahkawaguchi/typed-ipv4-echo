use std::fmt;

pub enum Protocol {
    Icmp,
    Tcp,
    Udp,
    Other(u8),
}

impl Protocol {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Other(other),
        }
    }

    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Other(other) => *other,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp => write!(f, "ICMP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Other(val) => write!(f, "Other ({val})"),
        }
    }
}
