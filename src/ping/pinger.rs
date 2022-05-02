use std::net::IpAddr;
use std::time::Duration;
use std::sync::{Mutex, Arc};
use std::sync::mpsc::{channel ,Sender, Receiver};
use super::PingResult;
use crate::protocol::Protocol;
use crate::node::Node;

/// Pinger structure
/// 
/// Contains various settings for ping
#[derive(Clone, Debug)]
pub struct Pinger {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Destination port 
    pub dst_port: u16,
    /// Protocol used for PING
    pub protocol: Protocol,
    /// Time to live
    /// 
    /// Default is 64
    pub ttl: u8,
    /// Ping execution count
    /// 
    /// Default is 4
    pub count: u8,
    /// Timeout setting for ping   
    pub ping_timeout: Duration,
    /// Timeout setting for packet receive  
    pub receive_timeout: Duration,
    /// Packet send rate
    pub send_rate: Duration,
    /// Sender for progress messaging
    pub tx: Arc<Mutex<Sender<Node>>>,
    /// Receiver for progress messaging
    pub rx: Arc<Mutex<Receiver<Node>>>,
}

impl Pinger {
    /// Create new Pinger instance with destination IP address
    pub fn new(dst_ip: IpAddr) -> Result<Pinger, String> {
        match default_net::get_default_interface(){
            Ok(interface) => {
                let src_ip: IpAddr = 
                if interface.ipv4.len() > 0 {
                    IpAddr::V4(interface.ipv4[0].addr)
                }else{
                    if interface.ipv6.len() > 0 {
                        IpAddr::V6(interface.ipv6[0].addr)
                    }else{
                        return Err(String::from("Failed to get default interface"));
                    }
                };
                let (tx, rx) = channel();
                let pinger = Pinger {
                    src_ip: src_ip,
                    dst_ip: dst_ip,
                    dst_port: 0,
                    protocol: Protocol::Icmpv4,
                    ttl: 64,
                    count: 4,
                    ping_timeout: Duration::from_millis(30000),
                    receive_timeout: Duration::from_millis(1000),
                    send_rate: Duration::from_millis(1000),
                    tx: Arc::new(Mutex::new(tx)),
                    rx: Arc::new(Mutex::new(rx)),
                };
                return Ok(pinger);
            },
            Err(e) => {
                return Err(format!("{}",e));
            },
        }
    }
    /// Run ping
    pub fn ping(&self) -> Result<PingResult, String> {
        super::ping(self.clone(), &self.tx)
    }
    /// Set source IP address
    pub fn set_src_ip(&mut self, src_ip: IpAddr){
        self.src_ip = src_ip;
    }
    /// Get source IP address
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip
    }
    /// Set destination IP address
    pub fn set_dst_ip(&mut self, dst_ip: IpAddr){
        self.dst_ip = dst_ip;
    }
    /// Get destination IP address
    pub fn get_dst_ip(&self) -> IpAddr {
        self.dst_ip
    }
    /// Set destination port
    pub fn set_dst_port(&mut self, dst_port: u16){
        self.dst_port = dst_port;
    }
    /// Get destination port
    pub fn get_dst_port(&self) -> u16 {
        self.dst_port
    }
    /// Set protocol
    pub fn set_protocol(&mut self, protocol: Protocol){
        self.protocol = protocol;
    }
    /// Get protocol
    pub fn get_protocol(&self) -> Protocol {
        self.protocol.clone()
    }
    /// Set Time to live
    pub fn set_ttl(&mut self, ttl: u8){
        self.ttl = ttl;
    }
    /// Get Time to live
    pub fn get_ttl(&self) -> u8 {
        self.ttl
    }
    /// Set ping execution count
    pub fn set_count(&mut self, count: u8){
        self.ttl = count;
    }
    /// Get ping execution count
    pub fn get_count(&self) -> u8 {
        self.count
    }
    /// Set ping timeout
    pub fn set_ping_timeout(&mut self, ping_timeout: Duration){
        self.ping_timeout = ping_timeout;
    }
    /// Get ping timeout
    pub fn get_ping_timeout(&self) -> Duration {
        self.ping_timeout
    }
    /// Set packet receive timeout
    pub fn set_receive_timeout(&mut self, receive_timeout: Duration){
        self.receive_timeout = receive_timeout;
    }
    /// Get packet receive timeout
    pub fn get_receive_timeout(&self) -> Duration {
        self.receive_timeout
    }
    /// Set packet send rate
    pub fn set_send_rate(&mut self, send_rate: Duration){
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
