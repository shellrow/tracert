use std::net::IpAddr;
use std::time::Duration;

/// Role of a node in traceroute output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeType {
    /// Intermediate node on the route.
    Hop,
    /// Final destination node.
    Destination,
}

/// Probe result for a single observed node.
#[derive(Clone, Debug)]
pub struct Node {
    /// Sequence number of the probe.
    pub sequence: u8,
    /// Node IP address.
    pub ip_addr: IpAddr,
    /// Resolved hostname, or the IP string if reverse lookup fails.
    pub hostname: String,
    /// TTL value in the received packet, when available.
    pub ttl: Option<u8>,
    /// Hop count from the source, when available.
    pub hop_count: Option<u8>,
    /// Node role classification.
    pub node_type: NodeType,
    /// Round-trip time.
    pub rtt: Duration,
}
