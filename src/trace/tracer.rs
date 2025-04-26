use super::TraceResult;
use crate::node::Node;
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) const BASE_DST_PORT: u16 = 33435;

/// Tracer structure
///
/// Contains various settings for traceroute
#[derive(Clone, Debug)]
pub struct Tracer {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Max hop
    pub max_hop: u8,
    /// Timeout setting for trace   
    pub trace_timeout: Duration,
    /// Timeout setting for packet receive  
    pub receive_timeout: Duration,
    /// Packet send rate
    pub send_rate: Duration,
    /// Sender for progress messaging
    pub tx: Arc<Mutex<Sender<Node>>>,
    /// Receiver for progress messaging
    pub rx: Arc<Mutex<Receiver<Node>>>,
}

impl Tracer {
    /// Create new Tracer instance with destination IP address
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
                let (tx, rx) = channel();
                let tracer = Tracer {
                    src_ip: src_ip,
                    dst_ip: dst_ip,
                    max_hop: 64,
                    trace_timeout: Duration::from_millis(30000),
                    receive_timeout: Duration::from_millis(1000),
                    send_rate: Duration::from_millis(0),
                    tx: Arc::new(Mutex::new(tx)),
                    rx: Arc::new(Mutex::new(rx)),
                };
                return Ok(tracer);
            }
            Err(e) => {
                return Err(format!("{}", e));
            }
        }
    }
    /// Trace route to destination
    pub fn trace(&self) -> Result<TraceResult, String> {
        super::trace_route(self.clone(), &self.tx)
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
    /// Set packet send rate
    pub fn set_send_rate(&mut self, send_rate: Duration) {
        self.send_rate = send_rate;
    }
    /// Get packet send rate
    pub fn get_send_rate(&self) -> Duration {
        self.send_rate
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<Node>>> {
        self.rx.clone()
    }
}
