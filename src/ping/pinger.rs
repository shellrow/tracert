use super::PingResult;
use crate::node::Node;
use crate::protocol::Protocol;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::broadcast;

/// Configuration and execution context for ping probes.
#[derive(Clone, Debug)]
pub struct Pinger {
    /// Source IP address used to send probes.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Destination port for TCP/UDP probes.
    pub dst_port: u16,
    /// Protocol used to send probes.
    pub protocol: Protocol,
    /// Time to live (TTL). Default is `64`.
    pub ttl: u8,
    /// Number of probes to send. Default is `4`.
    pub probe_count: u8,
    /// Overall timeout for a full ping run.
    pub ping_timeout: Duration,
    /// Timeout for receiving each probe response.
    pub receive_timeout: Duration,
    /// Delay between consecutive probes.
    pub send_interval: Duration,
    /// Broadcast sender for per-probe progress events.
    pub progress_tx: broadcast::Sender<Node>,
}

impl Pinger {
    /// Creates a new `Pinger` for the destination address.
    ///
    /// The source address is inferred from the default interface.
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
    /// Runs ping synchronously.
    pub fn ping(&self) -> Result<PingResult, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_time()
            .build()
            .map_err(|e| e.to_string())?;
        runtime.block_on(self.ping_async())
    }
    /// Runs ping asynchronously.
    pub async fn ping_async(&self) -> Result<PingResult, String> {
        super::ping(self.clone(), &self.progress_tx).await
    }
    /// Sets the source IP address.
    pub fn set_src_ip(&mut self, src_ip: IpAddr) {
        self.src_ip = src_ip;
    }
    /// Returns the source IP address.
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip
    }
    /// Sets the destination IP address.
    pub fn set_dst_ip(&mut self, dst_ip: IpAddr) {
        self.dst_ip = dst_ip;
    }
    /// Returns the destination IP address.
    pub fn get_dst_ip(&self) -> IpAddr {
        self.dst_ip
    }
    /// Sets the destination port.
    pub fn set_dst_port(&mut self, dst_port: u16) {
        self.dst_port = dst_port;
    }
    /// Returns the destination port.
    pub fn get_dst_port(&self) -> u16 {
        self.dst_port
    }
    /// Sets the probe protocol.
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = protocol;
    }
    /// Returns the probe protocol.
    pub fn get_protocol(&self) -> Protocol {
        self.protocol.clone()
    }
    /// Sets the TTL value.
    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
    }
    /// Returns the TTL value.
    pub fn get_ttl(&self) -> u8 {
        self.ttl
    }
    /// Sets the number of probes to send.
    pub fn set_probe_count(&mut self, probe_count: u8) {
        self.probe_count = probe_count;
    }
    /// Returns the number of probes to send.
    pub fn get_probe_count(&self) -> u8 {
        self.probe_count
    }
    /// Sets the overall ping timeout.
    pub fn set_ping_timeout(&mut self, ping_timeout: Duration) {
        self.ping_timeout = ping_timeout;
    }
    /// Returns the overall ping timeout.
    pub fn get_ping_timeout(&self) -> Duration {
        self.ping_timeout
    }
    /// Sets the per-probe receive timeout.
    pub fn set_receive_timeout(&mut self, receive_timeout: Duration) {
        self.receive_timeout = receive_timeout;
    }
    /// Returns the per-probe receive timeout.
    pub fn get_receive_timeout(&self) -> Duration {
        self.receive_timeout
    }
    /// Sets the interval between probes.
    pub fn set_send_interval(&mut self, send_interval: Duration) {
        self.send_interval = send_interval;
    }
    /// Returns the interval between probes.
    pub fn get_send_interval(&self) -> Duration {
        self.send_interval
    }
    /// Returns a receiver for per-probe progress events.
    pub fn get_progress_receiver(&self) -> broadcast::Receiver<Node> {
        self.progress_tx.subscribe()
    }
}
