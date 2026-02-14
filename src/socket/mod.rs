pub mod icmp;
pub mod tcp;
pub mod udp;

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketFamily {
    Ipv4,
    Ipv6,
}

impl SocketFamily {
    pub fn from_ip(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => SocketFamily::Ipv4,
            IpAddr::V6(_) => SocketFamily::Ipv6,
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, SocketFamily::Ipv4)
    }

    pub fn to_domain(&self) -> socket2::Domain {
        match self {
            SocketFamily::Ipv4 => socket2::Domain::IPV4,
            SocketFamily::Ipv6 => socket2::Domain::IPV6,
        }
    }
}
