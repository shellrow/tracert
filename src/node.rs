use std::net::IpAddr;
use std::time::Duration;

/// Node type
#[derive(Clone, Debug, PartialEq)]
pub enum NodeType {
    /// Default gateway
    DefaultGateway,
    /// Relay node
    Relay,
    /// Destination host
    Destination,
}

/// Node structure
#[derive(Clone, Debug)]
pub struct Node {
    /// Sequence number
    pub seq: u8,
    /// IP address
    pub ip_addr: IpAddr,
    /// Host name
    pub host_name: String,
    /// Time To Live
    pub ttl: Option<u8>,
    /// Number of hops
    pub hop: Option<u8>,
    /// Node type
    pub node_type: NodeType,
    /// Round Trip Time
    pub rtt: Duration,
}
