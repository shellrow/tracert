use super::BASE_DST_PORT;
use super::{TraceResult, TraceStatus, Tracer};
use crate::node::{Node, NodeType};
use crate::sys;
use pnet_packet::icmp::IcmpTypes;
use pnet_packet::Packet;
use socket2::SockAddr;
use std::collections::HashSet;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, IPPROTO_IP};
use windows_sys::Win32::Networking::WinSock::{SOCKET, SOCK_RAW, SOL_SOCKET, SO_RCVTIMEO};

pub(crate) fn trace_route(
    tracer: Tracer,
    tx: &Arc<Mutex<Sender<Node>>>,
) -> Result<TraceResult, String> {
    let mut nodes: Vec<Node> = vec![];
    let udp_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            return Err(format!("{}", e));
        }
    };
    let socket: SOCKET = if tracer.src_ip.is_ipv4() {
        sys::create_socket(AF_INET as i32, SOCK_RAW, IPPROTO_IP).unwrap()
    } else if tracer.src_ip.is_ipv6() {
        sys::create_socket(AF_INET6 as i32, SOCK_RAW, IPPROTO_IP).unwrap()
    } else {
        return Err(String::from("invalid source address"));
    };
    let socket_addr: SocketAddr = SocketAddr::new(tracer.src_ip, 0);
    let sock_addr = SockAddr::from(socket_addr);
    sys::bind(socket, &sock_addr).unwrap();
    sys::set_promiscuous(socket, true).unwrap();
    sys::set_timeout_opt(
        socket,
        SOL_SOCKET,
        SO_RCVTIMEO,
        Some(tracer.receive_timeout),
    )
    .unwrap();
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
            }
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
            }
        }
        loop {
            if Instant::now().duration_since(send_time) > tracer.receive_timeout {
                break;
            }
            match sys::recv_from(socket, recv_buf, 0) {
                Ok((bytes_len, addr)) => {
                    let src_addr: IpAddr = addr
                        .as_socket()
                        .unwrap_or(SocketAddr::new(tracer.src_ip, 0))
                        .ip();
                    if tracer.src_ip == src_addr || ip_set.contains(&src_addr) {
                        continue;
                    }
                    let recv_time = Instant::now().duration_since(send_time);
                    let recv_buf =
                        unsafe { *(recv_buf as *mut [MaybeUninit<u8>] as *mut [u8; 512]) };
                    if let Some(packet) =
                        pnet_packet::ipv4::Ipv4Packet::new(&recv_buf[0..bytes_len])
                    {
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
                                        node_type: if ttl == 1 {
                                            NodeType::DefaultGateway
                                        } else {
                                            NodeType::Relay
                                        },
                                        rtt: recv_time,
                                    };
                                    nodes.push(node.clone());
                                    match tx.lock() {
                                        Ok(lr) => match lr.send(node) {
                                            Ok(_) => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {}
                                    }
                                    ip_set.insert(ip_addr);
                                    break;
                                }
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
                                        Ok(lr) => match lr.send(node) {
                                            Ok(_) => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {}
                                    }
                                    end_trace = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
        thread::sleep(tracer.send_rate);
    }
    for node in &mut nodes {
        let host_name: String =
            dns_lookup::lookup_addr(&node.ip_addr).unwrap_or(node.ip_addr.to_string());
        node.host_name = host_name;
    }
    let result: TraceResult = TraceResult {
        nodes: nodes,
        status: TraceStatus::Done,
        probe_time: trace_time,
    };
    Ok(result)
}
