use std::net::IpAddr;
use std::time::Duration;

/// Hop role in traceroute results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeType {
    /// Transit router (non-final hop)
    Hop,
    /// Final destination
    Destination,
}

/// Probe result for a single node.
#[derive(Clone, Debug)]
pub struct Node {
    /// Probe sequence number
    pub sequence: u8,
    /// Node IP address
    pub ip_addr: IpAddr,
    /// Resolved hostname, or the IP string if reverse lookup fails
    pub hostname: String,
    /// TTL value from the received packet
    pub ttl: Option<u8>,
    /// Hop count from the source
    pub hop_count: Option<u8>,
    /// Traceroute hop role
    pub node_type: NodeType,
    /// Round-trip time
    pub rtt: Duration,
}
