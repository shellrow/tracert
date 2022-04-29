use std::net::IpAddr;
use std::time::Duration;
use super::TraceResult;

pub(crate) const BASE_DST_PORT: u16 = 33435;

#[derive(Clone, Debug)]
pub struct Tracer {
    /// Source IP Address
    pub src_ip: IpAddr,
    /// Destination IP Address
    pub dst_ip: IpAddr,
    /// Max hop
    pub max_hop: u8,
    /// Timeout setting for trace   
    pub trace_timeout: Duration,
    /// Timeout setting for packet receive  
    pub receive_timeout: Duration,
    /// Packet send rate
    pub send_rate: Duration,
}

impl Tracer {
    pub fn new(dst_ip: IpAddr) -> Result<Tracer, String> {
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
                let tracer = Tracer {
                    src_ip: src_ip,
                    dst_ip: dst_ip,
                    max_hop: 64,
                    trace_timeout: Duration::from_millis(30000),
                    receive_timeout: Duration::from_millis(1000),
                    send_rate: Duration::from_millis(0),
                };
                return Ok(tracer);
            },
            Err(e) => {
                return Err(format!("{}",e));
            },
        }
    }
    pub fn trace(&self) -> Result<TraceResult, String> {
        super::trace_route(self.clone())
    }
    pub fn set_src_ip(&mut self, src_ip: IpAddr){
        self.src_ip = src_ip;
    }
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip
    }
    pub fn set_dst_ip(&mut self, dst_ip: IpAddr){
        self.dst_ip = dst_ip;
    }
    pub fn get_dst_ip(&self) -> IpAddr {
        self.dst_ip
    }
    pub fn set_max_hop(&mut self, max_hop: u8){
        self.max_hop = max_hop;
    }
    pub fn get_max_hop(&self) -> u8 {
        self.max_hop
    }
    pub fn set_trace_timeout(&mut self, trace_timeout: Duration){
        self.trace_timeout = trace_timeout;
    }
    pub fn get_trace_timeout(&self) -> Duration {
        self.trace_timeout
    }
    pub fn set_receive_timeout(&mut self, receive_timeout: Duration){
        self.receive_timeout = receive_timeout;
    }
    pub fn get_receive_timeout(&self) -> Duration {
        self.receive_timeout
    }
    pub fn set_send_rate(&mut self, send_rate: Duration){
        self.send_rate = send_rate;
    }
    pub fn get_send_rate(&self) -> Duration {
        self.send_rate
    }
}
