use std::net::IpAddr;
use std::time::Duration;

/// Node type 
#[derive(Clone, Debug)]
pub enum NodeType{
    DefaultGateway,
    Relay,
    Destination,
}

/// Node structure
#[derive(Clone, Debug)]
pub struct Node {
    pub seq: u8,
    pub ip_addr: IpAddr,
    pub host_name: String,
    pub hop: Option<u8>,
    pub node_type: NodeType,
    pub rtt: Duration,
}
