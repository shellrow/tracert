use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use std::mem::MaybeUninit;
use std::collections::HashSet;
use std::thread;
use socket2::SockAddr;
use pnet_packet::Packet;
use pnet_packet::icmp::{IcmpTypes};
use winapi::shared::ws2def::{AF_INET, AF_INET6, IPPROTO_IP};
use winapi::um::winsock2::{SOCKET, SOCK_RAW, SOL_SOCKET, SO_RCVTIMEO};
use super::{Tracer, TraceStatus, TraceResult};
use super::BASE_DST_PORT;
use crate::node::{NodeType, Node};
use crate::sys;

pub(crate) fn trace_route(tracer: Tracer) -> Result<TraceResult, String> {
    let mut nodes: Vec<Node> = vec![];
    let udp_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            return Err(format!("{}", e));
        },
    };
    let socket: SOCKET = 
    if tracer.src_ip.is_ipv4() {
        sys::create_socket(AF_INET, SOCK_RAW, IPPROTO_IP).unwrap()
    }else if tracer.src_ip.is_ipv6(){
        sys::create_socket(AF_INET6, SOCK_RAW, IPPROTO_IP).unwrap()
    }else{
        return Err(String::from("invalid source address"));
    };
    let socket_addr: SocketAddr = SocketAddr::new(tracer.src_ip, 0);
    //let socket_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let sock_addr = SockAddr::from(socket_addr);
    sys::bind(socket, &sock_addr).unwrap();
    //set_nonblocking(socket, true).unwrap();
    sys::set_promiscuous(socket, true).unwrap();
    sys::set_timeout_opt(socket, SOL_SOCKET, SO_RCVTIMEO, Some(tracer.receive_timeout)).unwrap();
    let mut ip_set: HashSet<IpAddr> = HashSet::new();
    let mut end_trace: bool = false;
    let start_time = Instant::now();
    let mut trace_time = Duration::from_millis(0);
    for ttl in 1..tracer.max_hop {
        trace_time = Instant::now().duration_since(start_time);
        if end_trace {
            break;
        }
        if trace_time > tracer.trace_timeout {
            let result: TraceResult = TraceResult {
                nodes: nodes,
                status: TraceStatus::Timeout,
                probe_time: trace_time,
            };
            return Ok(result);
        }
        match udp_socket.set_ttl(ttl as u32) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!("{}", e));
            },
        }
        let udp_buf = [0u8; 0];
        let dst: SocketAddr = SocketAddr::new(tracer.dst_ip, BASE_DST_PORT + ttl as u16);
        let send_time = Instant::now();
        let mut buf: Vec<u8> = vec![0; 512];
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        match udp_socket.send_to(&udp_buf, dst) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!("{}", e));
            },
        }
        loop {
            //let elapsed_time = Instant::now().duration_since(send_time);
            if Instant::now().duration_since(send_time) > tracer.receive_timeout {
                break;
            }
            match sys::recv_from(socket, recv_buf, 0) {
                Ok((bytes_len, addr)) => {
                    let src_addr: IpAddr = addr.as_socket().unwrap_or(SocketAddr::new(tracer.src_ip, 0)).ip();
                    if tracer.src_ip == src_addr || ip_set.contains(&src_addr) {
                        continue;
                    }
                    let recv_time = Instant::now().duration_since(send_time);
                    let recv_buf = unsafe { *(recv_buf as *mut [MaybeUninit<u8>] as *mut [u8; 512]) };
                    if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(&recv_buf[0..bytes_len]){
                        let icmp_packet = pnet_packet::icmp::IcmpPacket::new(packet.payload());
                        if let Some(icmp) = icmp_packet {
                            let ip_addr: IpAddr = IpAddr::V4(packet.get_source());
                            match icmp.get_icmp_type() {
                                IcmpTypes::TimeExceeded => {
                                    nodes.push(Node {
                                        seq: ttl,
                                        ip_addr: ip_addr,
                                        host_name: String::new(),
                                        hop: Some(ttl),
                                        node_type: if ttl == 1 {NodeType::DefaultGateway}else{NodeType::Relay},
                                        rtt: recv_time,
                                    });
                                    ip_set.insert(ip_addr);
                                    break;
                                },
                                IcmpTypes::DestinationUnreachable => {
                                    nodes.push(Node {
                                        seq: ttl,
                                        ip_addr: ip_addr,
                                        host_name: String::new(),
                                        hop: Some(ttl),
                                        node_type: NodeType::Destination,
                                        rtt: recv_time,
                                    });
                                    end_trace = true;
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
        thread::sleep(tracer.send_rate);
    }
    for node in &mut nodes {
        let host_name: String = dns_lookup::lookup_addr(&node.ip_addr).unwrap_or(node.ip_addr.to_string());
        node.host_name = host_name;
    }
    let result: TraceResult = TraceResult {
        nodes: nodes,
        status: TraceStatus::Done,
        probe_time: trace_time,
    };
    Ok(result)
} 
