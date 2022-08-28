use std::net::IpAddr;
use std::time::{Instant, Duration};
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{SocketAddr, UdpSocket};
use std::collections::HashSet;
use std::thread;
use std::sync::{Mutex, Arc};
use std::sync::mpsc::Sender;
use pnet_packet::Packet;
use pnet_packet::icmp::IcmpTypes;
use crate::node::{NodeType, Node};
use super::{Tracer, TraceStatus, TraceResult};
use super::BASE_DST_PORT;

pub(crate) fn trace_route(tracer: Tracer, tx: &Arc<Mutex<Sender<Node>>>) -> Result<TraceResult, String> {
    let mut nodes: Vec<Node> = vec![];
    let udp_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            return Err(format!("{}", e));
        },
    };
    let icmp_socket: Socket = 
    if tracer.src_ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap()
    }else if tracer.src_ip.is_ipv6(){
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap()
    }else{
        return Err(String::from("invalid source address"));
    };
    icmp_socket.set_read_timeout(Some(tracer.receive_timeout)).unwrap();
    let mut ip_set: HashSet<IpAddr> = HashSet::new();
    let start_time = Instant::now();
    let mut trace_time = Duration::from_millis(0);
    for ttl in 1..tracer.max_hop {
        trace_time = Instant::now().duration_since(start_time);
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
        let mut buf: Vec<u8> = vec![0; 512];
        let mut recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let dst: SocketAddr = SocketAddr::new(tracer.dst_ip, BASE_DST_PORT + ttl as u16);
        let send_time = Instant::now();
        match udp_socket.send_to(&udp_buf, dst) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!("{}", e));
            },
        }
        match icmp_socket.recv_from(&mut recv_buf) {
            Ok((bytes_len, addr)) => {
                let src_addr: IpAddr = addr.as_socket().unwrap_or(SocketAddr::new(tracer.src_ip, 0)).ip();
                if ip_set.contains(&src_addr) {
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
                                let node = Node {
                                    seq: ttl,
                                    ip_addr: ip_addr,
                                    host_name: String::new(),
                                    ttl: Some(packet.get_ttl()),
                                    hop: Some(ttl),
                                    node_type: if ttl == 1 {NodeType::DefaultGateway}else{NodeType::Relay},
                                    rtt: recv_time,
                                };
                                nodes.push(node.clone());
                                match tx.lock() {
                                    Ok(lr) => {
                                        match lr.send(node) {
                                            Ok(_) => {},
                                            Err(_) => {},
                                        }
                                    },
                                    Err(_) => {},
                                }
                                ip_set.insert(ip_addr);
                            },
                            IcmpTypes::DestinationUnreachable => {
                                let node = Node {
                                    seq: ttl,
                                    ip_addr: ip_addr,
                                    host_name: String::new(),
                                    ttl: Some(packet.get_ttl()),
                                    hop: Some(ttl),
                                    node_type: NodeType::Destination,
                                    rtt: recv_time,
                                };
                                nodes.push(node.clone());
                                match tx.lock() {
                                    Ok(lr) => {
                                        match lr.send(node) {
                                            Ok(_) => {},
                                            Err(_) => {},
                                        }
                                    },
                                    Err(_) => {},
                                }
                                break;
                            },
                            _ => {},
                        }
                    }
                }
            },
            Err(_) => {},
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