use std::{fmt, net::Ipv4Addr};

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Ipv4AddrPair {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4AddrPair {
    pub const fn swapped(self) -> Self { Self { src: self.dst, dst: self.src } }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct PortPair {
    pub src: u16,
    pub dst: u16,
}

impl PortPair {
    pub const fn swapped(self) -> Self { Self { src: self.dst, dst: self.src } }
}

impl fmt::Display for PortPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}
