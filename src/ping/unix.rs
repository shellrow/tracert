use super::{PingResult, PingStatus, Pinger};
use crate::node::{Node, NodeType};
use crate::packet;
use crate::protocol::Protocol as ProbeProtocol;
use crate::sys;
use crate::trace::BASE_DST_PORT;
use pnet_packet::icmp::IcmpTypes;
use pnet_packet::Packet;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn icmp_ping(pinger: Pinger, tx: &Arc<Mutex<Sender<Node>>>) -> Result<PingResult, String> {
    let host_name: String =
        dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or_else(|_| pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];
    let icmp_socket: Socket = if pinger.src_ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap()
    } else if pinger.src_ip.is_ipv6() {
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap()
    } else {
        return Err(String::from("invalid source address"));
    };
    icmp_socket
        .set_read_timeout(Some(pinger.receive_timeout))
        .unwrap();
    icmp_socket.set_ttl(pinger.ttl as u32).unwrap();
    let socket_addr = SocketAddr::new(pinger.dst_ip, 0);
    let sock_addr = SockAddr::from(socket_addr);
    let icmp_packet: Vec<u8> = packet::build_icmpv4_echo_packet();
    let start_time = Instant::now();
    let mut probe_time = Duration::from_millis(0);
    for seq in 1..pinger.count + 1 {
        probe_time = Instant::now().duration_since(start_time);
        if probe_time > pinger.ping_timeout {
            let result: PingResult = PingResult {
                results,
                status: PingStatus::Timeout,
                probe_time,
            };
            return Ok(result);
        }
        let mut buf: Vec<u8> = vec![0; 512];
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let send_time = Instant::now();
        if icmp_socket.send_to(&icmp_packet, &sock_addr).is_ok() {}
        loop {
            if let Ok((bytes_len, _addr)) = icmp_socket.recv_from(recv_buf) {
                let recv_time = Instant::now().duration_since(send_time);
                if recv_time > pinger.receive_timeout {
                    break;
                }
                let recv_buf = unsafe { *(recv_buf as *mut [MaybeUninit<u8>] as *mut [u8; 512]) };
                if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(&recv_buf[0..bytes_len]) {
                    let icmp_packet = pnet_packet::icmp::IcmpPacket::new(packet.payload());
                    if let Some(icmp) = icmp_packet {
                        let ip_addr: IpAddr = IpAddr::V4(packet.get_source());
                        if icmp.get_icmp_type() == IcmpTypes::EchoReply {
                            let node = Node {
                                seq,
                                ip_addr,
                                host_name: host_name.clone(),
                                hop: Some(
                                    sys::guess_initial_ttl(packet.get_ttl()) - packet.get_ttl(),
                                ),
                                node_type: NodeType::Destination,
                                rtt: recv_time,
                            };
                            results.push(node.clone());
                            if let Ok(lr) = tx.lock() {
                                if lr.send(node).is_ok() {}
                            }
                            break;
                        }
                    }
                }
            }
        }
        thread::sleep(pinger.send_rate);
    }
    let result: PingResult = PingResult {
        results,
        status: PingStatus::Done,
        probe_time,
    };
    Ok(result)
}

fn tcp_ping(pinger: Pinger, tx: &Arc<Mutex<Sender<Node>>>) -> Result<PingResult, String> {
    let host_name: String =
        dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or_else(|_| pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];
    let socket_addr: SocketAddr = SocketAddr::new(pinger.dst_ip, pinger.dst_port);
    let sock_addr = SockAddr::from(socket_addr);
    let mut probe_time = Duration::from_millis(0);
    let start_time = Instant::now();
    for seq in 1..pinger.count + 1 {
        probe_time = Instant::now().duration_since(start_time);
        if probe_time > pinger.ping_timeout {
            let result: PingResult = PingResult {
                results,
                status: PingStatus::Timeout,
                probe_time,
            };
            return Ok(result);
        }
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let connect_start_time = Instant::now();
        match socket.connect_timeout(&sock_addr, pinger.receive_timeout) {
            Ok(_) => {
                let connect_end_time = Instant::now().duration_since(connect_start_time);
                let node = Node {
                    seq,
                    ip_addr: pinger.dst_ip,
                    host_name: host_name.clone(),
                    hop: None,
                    node_type: NodeType::Destination,
                    rtt: connect_end_time,
                };
                results.push(node.clone());
                if let Ok(lr) = tx.lock() {
                    if lr.send(node).is_ok() {}
                }
            }
            Err(e) => {
                println!("{}", e);
            }
        }
        thread::sleep(pinger.send_rate);
    }
    let result: PingResult = PingResult {
        results,
        status: PingStatus::Done,
        probe_time,
    };
    Ok(result)
}

fn udp_ping(pinger: Pinger, tx: &Arc<Mutex<Sender<Node>>>) -> Result<PingResult, String> {
    let host_name: String =
        dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or_else(|_| pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];
    let udp_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            return Err(format!("{}", e));
        }
    };
    let icmp_socket: Socket = if pinger.src_ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap()
    } else if pinger.src_ip.is_ipv6() {
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap()
    } else {
        return Err(String::from("invalid source address"));
    };
    icmp_socket
        .set_read_timeout(Some(pinger.receive_timeout))
        .unwrap();
    let start_time = Instant::now();
    let mut probe_time = Duration::from_millis(0);
    for seq in 1..pinger.count + 1 {
        probe_time = Instant::now().duration_since(start_time);
        if probe_time > pinger.ping_timeout {
            let result: PingResult = PingResult {
                results,
                status: PingStatus::Timeout,
                probe_time,
            };
            return Ok(result);
        }
        match udp_socket.set_ttl(pinger.ttl as u32) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!("{}", e));
            }
        }
        let udp_buf = [0u8; 0];
        let mut buf: Vec<u8> = vec![0; 512];
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let dst: SocketAddr = SocketAddr::new(pinger.dst_ip, BASE_DST_PORT);
        let send_time = Instant::now();
        match udp_socket.send_to(&udp_buf, dst) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!("{}", e));
            }
        }
        loop {
            if Instant::now().duration_since(send_time) > pinger.receive_timeout {
                break;
            }
            if let Ok((bytes_len, _addr)) = icmp_socket.recv_from(recv_buf) {
                let recv_time = Instant::now().duration_since(send_time);
                let recv_buf = unsafe { *(recv_buf as *mut [MaybeUninit<u8>] as *mut [u8; 512]) };
                if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(&recv_buf[0..bytes_len]) {
                    let icmp_packet = pnet_packet::icmp::IcmpPacket::new(packet.payload());
                    if let Some(icmp) = icmp_packet {
                        let ip_addr: IpAddr = IpAddr::V4(packet.get_source());
                        if icmp.get_icmp_type() == IcmpTypes::DestinationUnreachable {
                            let node = Node {
                                seq,
                                ip_addr,
                                host_name: host_name.clone(),
                                hop: Some(
                                    sys::guess_initial_ttl(packet.get_ttl()) - packet.get_ttl(),
                                ),
                                node_type: NodeType::Destination,
                                rtt: recv_time,
                            };
                            results.push(node.clone());
                            if let Ok(lr) = tx.lock() {
                                if lr.send(node).is_ok() {}
                            }
                            break;
                        }
                    }
                }
            }
        }
        thread::sleep(pinger.send_rate);
    }
    for node in &mut results {
        let host_name: String =
            dns_lookup::lookup_addr(&node.ip_addr).unwrap_or_else(|_| node.ip_addr.to_string());
        node.host_name = host_name;
    }
    let result: PingResult = PingResult {
        results,
        status: PingStatus::Done,
        probe_time,
    };
    Ok(result)
}

pub(crate) fn ping(pinger: Pinger, tx: &Arc<Mutex<Sender<Node>>>) -> Result<PingResult, String> {
    match pinger.protocol {
        ProbeProtocol::Icmpv4 => icmp_ping(pinger, tx),
        ProbeProtocol::Icmpv6 => icmp_ping(pinger, tx),
        ProbeProtocol::Tcp => tcp_ping(pinger, tx),
        ProbeProtocol::Udp => udp_ping(pinger, tx),
    }
}
