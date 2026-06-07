use std::fmt;

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub(super) enum TcpFlags {
    Syn,
    SynAck,
    Ack,
    FinAck,
}

impl TcpFlags {
    const FIN_BIT: u8 = 0x01;
    const SYN_BIT: u8 = 0x02;
    const ACK_BIT: u8 = 0x10;
}

impl TryFrom<u8> for TcpFlags {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match (
            value & Self::SYN_BIT != 0,
            value & Self::ACK_BIT != 0,
            value & Self::FIN_BIT != 0,
        ) {
            (true, false, false) => Ok(Self::Syn),
            (true, true, false) => Ok(Self::SynAck),
            (false, true, false) => Ok(Self::Ack),
            (false, true, true) => Ok(Self::FinAck),

            (syn, ack, fin) => Err(format!(
                "Invalid TCP flag combination: SYN={syn} ACK={ack} FIN={fin}"
            )),
        }
    }
}

impl From<TcpFlags> for u8 {
    fn from(value: TcpFlags) -> Self {
        match value {
            TcpFlags::Syn => TcpFlags::SYN_BIT,
            TcpFlags::SynAck => TcpFlags::SYN_BIT | TcpFlags::ACK_BIT,
            TcpFlags::Ack => TcpFlags::ACK_BIT,
            TcpFlags::FinAck => TcpFlags::FIN_BIT | TcpFlags::ACK_BIT,
        }
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Syn => "SYN",
                Self::SynAck => "SYN-ACK",
                Self::Ack => "ACK",
                Self::FinAck => "FIN-ACK",
            }
        )
    }
}
