use super::TraceResult;
use crate::node::Node;
use crate::protocol::Protocol;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::broadcast;

pub(crate) const BASE_DST_PORT: u16 = 33435;

/// Tracer structure
///
/// Holds runtime settings used by traceroute probes.
#[derive(Clone, Debug)]
pub struct Tracer {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Protocol used for traceroute
    pub protocol: Protocol,
    /// Maximum hop count
    pub max_hop: u8,
    /// Overall timeout for traceroute execution
    pub trace_timeout: Duration,
    /// Timeout for receiving each packet
    pub receive_timeout: Duration,
    /// Packet send interval
    pub send_interval: Duration,
    /// Sender for progress messaging
    pub progress_tx: broadcast::Sender<Node>,
}

impl Tracer {
    /// Create a new tracer for the destination IP address
    pub fn new(dst_ip: IpAddr) -> Result<Tracer, String> {
        match netdev::get_default_interface() {
            Ok(interface) => {
                let src_ip: IpAddr = if dst_ip.is_ipv4() && interface.ipv4.len() > 0 {
                    IpAddr::V4(interface.ipv4[0].addr())
                } else {
                    if interface.ipv6.len() > 0 {
                        IpAddr::V6(interface.ipv6[0].addr())
                    } else {
                        return Err(String::from("Failed to get default interface"));
                    }
                };
                let (progress_tx, _) = broadcast::channel(256);
                let tracer = Tracer {
                    src_ip: src_ip,
                    dst_ip: dst_ip,
                    protocol: Protocol::Udp,
                    max_hop: 64,
                    trace_timeout: Duration::from_millis(30000),
                    receive_timeout: Duration::from_millis(1000),
                    send_interval: Duration::from_millis(0),
                    progress_tx,
                };
                return Ok(tracer);
            }
            Err(e) => {
                return Err(format!("{}", e));
            }
        }
    }
    /// Run traceroute synchronously
    pub fn trace(&self) -> Result<TraceResult, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_time()
            .build()
            .map_err(|e| e.to_string())?;
        runtime.block_on(self.trace_async())
    }
    /// Run traceroute asynchronously
    pub async fn trace_async(&self) -> Result<TraceResult, String> {
        super::trace_route(self.clone(), &self.progress_tx).await
    }
    /// Set source IP address
    pub fn set_src_ip(&mut self, src_ip: IpAddr) {
        self.src_ip = src_ip;
    }
    /// Get source IP address
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip
    }
    /// Set destination IP address
    pub fn set_dst_ip(&mut self, dst_ip: IpAddr) {
        self.dst_ip = dst_ip;
    }
    /// Get destination IP address
    pub fn get_dst_ip(&self) -> IpAddr {
        self.dst_ip
    }
    /// Set protocol
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = protocol;
    }
    /// Get protocol
    pub fn get_protocol(&self) -> Protocol {
        self.protocol.clone()
    }
    /// Set max hop
    pub fn set_max_hop(&mut self, max_hop: u8) {
        self.max_hop = max_hop;
    }
    /// Get max hop
    pub fn get_max_hop(&self) -> u8 {
        self.max_hop
    }
    /// Set traceroute timeout
    pub fn set_trace_timeout(&mut self, trace_timeout: Duration) {
        self.trace_timeout = trace_timeout;
    }
    /// Get traceroute timeout
    pub fn get_trace_timeout(&self) -> Duration {
        self.trace_timeout
    }
    /// Set packet receive timeout
    pub fn set_receive_timeout(&mut self, receive_timeout: Duration) {
        self.receive_timeout = receive_timeout;
    }
    /// Get packet receive timeout
    pub fn get_receive_timeout(&self) -> Duration {
        self.receive_timeout
    }
    /// Set packet send interval
    pub fn set_send_interval(&mut self, send_interval: Duration) {
        self.send_interval = send_interval;
    }
    /// Get packet send interval
    pub fn get_send_interval(&self) -> Duration {
        self.send_interval
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> broadcast::Receiver<Node> {
        self.progress_tx.subscribe()
    }
}
