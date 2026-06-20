use std::net::Ipv4Addr;

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Ipv4AddrPair {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4AddrPair {
    pub const fn swapped(self) -> Self { Self { src: self.dst, dst: self.src } }
}
