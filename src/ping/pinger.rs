use super::PingResult;
use crate::node::Node;
use crate::protocol::Protocol;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::broadcast;

/// Ping configuration and execution context.
///
/// Holds runtime settings used by ping probes.
#[derive(Clone, Debug)]
pub struct Pinger {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Destination port
    pub dst_port: u16,
    /// Protocol used for ping
    pub protocol: Protocol,
    /// Time to live
    ///
    /// Default is 64
    pub ttl: u8,
    /// Number of probes to send
    ///
    /// Default is 4
    pub probe_count: u8,
    /// Overall timeout for ping execution
    pub ping_timeout: Duration,
    /// Timeout for receiving each packet
    pub receive_timeout: Duration,
    /// Packet send interval
    pub send_interval: Duration,
    /// Sender for progress messaging
    pub progress_tx: broadcast::Sender<Node>,
}

impl Pinger {
    /// Create a new pinger for the destination IP address
    pub fn new(dst_ip: IpAddr) -> Result<Pinger, String> {
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
                let pinger = Pinger {
                    src_ip: src_ip,
                    dst_ip: dst_ip,
                    dst_port: 0,
                    protocol: Protocol::Icmpv4,
                    ttl: 64,
                    probe_count: 4,
                    ping_timeout: Duration::from_millis(30000),
                    receive_timeout: Duration::from_millis(1000),
                    send_interval: Duration::from_millis(1000),
                    progress_tx,
                };
                return Ok(pinger);
            }
            Err(e) => {
                return Err(format!("{}", e));
            }
        }
    }
    /// Run ping synchronously
    pub fn ping(&self) -> Result<PingResult, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_time()
            .build()
            .map_err(|e| e.to_string())?;
        runtime.block_on(self.ping_async())
    }
    /// Run ping asynchronously
    pub async fn ping_async(&self) -> Result<PingResult, String> {
        super::ping(self.clone(), &self.progress_tx).await
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
    /// Set destination port
    pub fn set_dst_port(&mut self, dst_port: u16) {
        self.dst_port = dst_port;
    }
    /// Get destination port
    pub fn get_dst_port(&self) -> u16 {
        self.dst_port
    }
    /// Set protocol
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = protocol;
    }
    /// Get protocol
    pub fn get_protocol(&self) -> Protocol {
        self.protocol.clone()
    }
    /// Set time to live
    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
    }
    /// Get time to live
    pub fn get_ttl(&self) -> u8 {
        self.ttl
    }
    /// Set probe count
    pub fn set_probe_count(&mut self, probe_count: u8) {
        self.probe_count = probe_count;
    }
    /// Get probe count
    pub fn get_probe_count(&self) -> u8 {
        self.probe_count
    }
    /// Set ping timeout
    pub fn set_ping_timeout(&mut self, ping_timeout: Duration) {
        self.ping_timeout = ping_timeout;
    }
    /// Get ping timeout
    pub fn get_ping_timeout(&self) -> Duration {
        self.ping_timeout
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
