use std::net::IpAddr;
use std::time::{Duration, Instant};
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{SocketAddr, UdpSocket};
use pnet_packet::Packet;
use pnet_packet::icmp::IcmpTypes;

pub const BASE_DST_PORT: u16 = 33435;

#[derive(Clone, Debug)]
pub enum NodeType{
    DefaultGateway,
    Relay,
    Destination,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub ip_addr: IpAddr,
    pub host_name: String,
    pub hop: u8,
    pub node_type: NodeType,
    pub rtt: Duration,
}

#[derive(Clone, Debug)]
pub struct Tracer {
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
    /// Result of probes  
    pub trace_result: Vec<Node>,
}

impl Tracer {
    pub fn new(dst_ip: IpAddr) -> Tracer {
        Tracer {
            dst_ip: dst_ip,
            max_hop: 64,
            trace_timeout: Duration::from_millis(30000),
            receive_timeout: Duration::from_millis(1000),
            send_rate: Duration::from_millis(1000),
            trace_result: vec![],
        }
    }
    pub fn trace(&self) -> Result<Vec<Node>, String> {
        let mut result: Vec<Node> = vec![];
        let udp_socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                return Err(format!("{}", e));
            },
        };
        let icmp_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
        icmp_socket.set_read_timeout(Some(self.receive_timeout)).unwrap();
        for ttl in 1..self.max_hop {
            match udp_socket.set_ttl(ttl as u32) {
                Ok(_) => (),
                Err(e) => {
                    return Err(format!("{}", e));
                },
            }
            let udp_buf = [0u8; 0];
            let mut buf: Vec<u8> = vec![0; 512];
            let mut recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
            let dst: SocketAddr = SocketAddr::new(self.dst_ip, BASE_DST_PORT + ttl as u16);
            let send_time = Instant::now();
            match udp_socket.send_to(&udp_buf, dst) {
                Ok(_) => (),
                Err(e) => {
                    return Err(format!("{}", e));
                },
            }
            match icmp_socket.recv_from(&mut recv_buf) {
                Ok((bytes_len, _addr)) => {
                    let recv_time = Instant::now().duration_since(send_time);
                    //println!("{} {} {}", ttl, bytes_len, addr.as_socket_ipv4().unwrap());
                    let recv_buf = unsafe { *(recv_buf as *mut [MaybeUninit<u8>] as *mut [u8; 512]) };
                    if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(&recv_buf[0..bytes_len]){
                        let icmp_packet = pnet_packet::icmp::IcmpPacket::new(packet.payload());
                        if let Some(icmp) = icmp_packet {
                            let ip_addr: IpAddr = IpAddr::V4(packet.get_source());
                            let host_name: String = dns_lookup::lookup_addr(&ip_addr).unwrap_or(ip_addr.to_string());
                            match icmp.get_icmp_type() {
                                IcmpTypes::TimeExceeded => {
                                    result.push(Node {
                                        ip_addr: ip_addr,
                                        host_name: host_name,
                                        hop: ttl,
                                        node_type: if ttl == 1 {NodeType::DefaultGateway}else{NodeType::Relay},
                                        rtt: recv_time,
                                    });
                                    //println!("{} TimeExceeded {:?}", ttl, packet.get_source());
                                },
                                IcmpTypes::DestinationUnreachable => {
                                    result.push(Node {
                                        ip_addr: ip_addr,
                                        host_name: host_name,
                                        hop: ttl,
                                        node_type: NodeType::Destination,
                                        rtt: recv_time,
                                    });
                                    //println!("{} DestinationUnreachable {:?}", ttl, packet.get_source());
                                    break;
                                },
                                _ => {},
                            }
                        }
                    }
                },
                Err(_) => {},
            }
        }
        Ok(result)
    }
}
