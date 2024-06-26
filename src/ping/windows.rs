use super::{PingResult, PingStatus, Pinger};
use crate::node::{Node, NodeType};
use crate::packet;
use crate::protocol::Protocol as ProbeProtocol;
use crate::sys;
use crate::trace::BASE_DST_PORT;
use nex_packet::icmp::IcmpType;
use nex_packet::icmpv6::Icmpv6Type;
use nex_packet::Packet;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, IPPROTO_ICMPV6, IPPROTO_IP};
use windows_sys::Win32::Networking::WinSock::{SOCKET, SOCK_RAW, SOL_SOCKET, SO_RCVTIMEO};

fn icmp_ping(pinger: Pinger, tx: &Arc<Mutex<Sender<Node>>>) -> Result<PingResult, String> {
    let host_name: String =
        dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or(pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];
    let icmp_socket: Socket = if pinger.src_ip.is_ipv4() && pinger.dst_ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap()
    } else if pinger.src_ip.is_ipv6() && pinger.dst_ip.is_ipv6() {
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap()
    } else {
        return Err(String::from("Invalid address specified"));
    };
    icmp_socket
        .set_read_timeout(Some(pinger.receive_timeout))
        .unwrap();
    icmp_socket.set_ttl(pinger.ttl as u32).unwrap();
    let socket_addr = SocketAddr::new(pinger.dst_ip, 0);
    let sock_addr = SockAddr::from(socket_addr);
    let mut icmp_packet: Vec<u8> = if pinger.dst_ip.is_ipv4() {
        packet::build_icmpv4_echo_packet()
    } else {
        packet::build_icmpv6_echo_packet()
    };
    let start_time = Instant::now();
    let mut probe_time = Duration::from_millis(0);
    for seq in 1..pinger.count + 1 {
        probe_time = Instant::now().duration_since(start_time);
        if probe_time > pinger.ping_timeout {
            let result: PingResult = PingResult {
                results: results,
                status: PingStatus::Timeout,
                probe_time: probe_time,
            };
            return Ok(result);
        }
        let mut buf: Vec<u8> = vec![0; 512];
        let mut recv_buf =
            unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let send_time = Instant::now();
        match icmp_socket.send_to(&mut icmp_packet, &sock_addr) {
            Ok(_) => {}
            Err(_) => {}
        }
        loop {
            match icmp_socket.recv_from(&mut recv_buf) {
                Ok((bytes_len, _addr)) => {
                    let recv_time = Instant::now().duration_since(send_time);
                    if recv_time > pinger.receive_timeout {
                        break;
                    }
                    let recv_buf =
                        unsafe { *(recv_buf as *mut [MaybeUninit<u8>] as *mut [u8; 512]) };
                    if pinger.dst_ip.is_ipv4() {
                        if let Some(packet) =
                            nex_packet::ipv4::Ipv4Packet::new(&recv_buf[0..bytes_len])
                        {
                            let icmp_packet = nex_packet::icmp::IcmpPacket::new(packet.payload());
                            if let Some(icmp) = icmp_packet {
                                let ip_addr: IpAddr = IpAddr::V4(packet.get_source());
                                match icmp.get_icmp_type() {
                                    IcmpType::EchoReply => {
                                        let node = Node {
                                            seq: seq,
                                            ip_addr: ip_addr,
                                            host_name: host_name.clone(),
                                            ttl: Some(packet.get_ttl()),
                                            hop: Some(
                                                sys::guess_initial_ttl(packet.get_ttl())
                                                    - packet.get_ttl(),
                                            ),
                                            node_type: NodeType::Destination,
                                            rtt: recv_time,
                                        };
                                        results.push(node.clone());
                                        match tx.lock() {
                                            Ok(lr) => match lr.send(node) {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            },
                                            Err(_) => {}
                                        }
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    } else {
                        // IPv6 (ICMPv6 Header only)
                        // The IPv6 header is automatically cropped off when recvfrom() is used.
                        if let Some(icmp_packet) =
                            nex_packet::icmpv6::Icmpv6Packet::new(&recv_buf[0..bytes_len])
                        {
                            let ip_addr: IpAddr = pinger.dst_ip;
                            match icmp_packet.get_icmpv6_type() {
                                Icmpv6Type::EchoReply => {
                                    let node = Node {
                                        seq: seq,
                                        ip_addr: ip_addr,
                                        host_name: host_name.clone(),
                                        ttl: None,
                                        hop: None,
                                        node_type: NodeType::Destination,
                                        rtt: recv_time,
                                    };
                                    results.push(node.clone());
                                    match tx.lock() {
                                        Ok(lr) => match lr.send(node) {
                                            Ok(_) => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {}
                                    }
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
        thread::sleep(pinger.send_rate);
    }
    let result: PingResult = PingResult {
        results: results,
        status: PingStatus::Done,
        probe_time: probe_time,
    };
    Ok(result)
}

fn tcp_ping(pinger: Pinger, tx: &Arc<Mutex<Sender<Node>>>) -> Result<PingResult, String> {
    let host_name: String =
        dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or(pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];
    let socket_addr: SocketAddr = SocketAddr::new(pinger.dst_ip, pinger.dst_port);
    let sock_addr = SockAddr::from(socket_addr);
    let mut probe_time = Duration::from_millis(0);
    let start_time = Instant::now();
    for seq in 1..pinger.count + 1 {
        probe_time = Instant::now().duration_since(start_time);
        if probe_time > pinger.ping_timeout {
            let result: PingResult = PingResult {
                results: results,
                status: PingStatus::Timeout,
                probe_time: probe_time,
            };
            return Ok(result);
        }
        let socket = if pinger.src_ip.is_ipv4() && pinger.dst_ip.is_ipv4() {
            Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap()
        } else if pinger.src_ip.is_ipv6() && pinger.dst_ip.is_ipv6() {
            Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).unwrap()
        } else {
            return Err(String::from("Invalid address specified"));
        };
        let connect_start_time = Instant::now();
        match socket.connect_timeout(&sock_addr, pinger.receive_timeout) {
            Ok(_) => {
                let connect_end_time = Instant::now().duration_since(connect_start_time);
                let node = Node {
                    seq: seq,
                    ip_addr: pinger.dst_ip,
                    host_name: host_name.clone(),
                    ttl: None,
                    hop: None,
                    node_type: NodeType::Destination,
                    rtt: connect_end_time,
                };
                results.push(node.clone());
                match tx.lock() {
                    Ok(lr) => match lr.send(node) {
                        Ok(_) => {}
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
            }
            Err(e) => {
                println!("{}", e);
            }
        }
        thread::sleep(pinger.send_rate);
    }
    let result: PingResult = PingResult {
        results: results,
        status: PingStatus::Done,
        probe_time: probe_time,
    };
    Ok(result)
}

fn udp_ping(pinger: Pinger, tx: &Arc<Mutex<Sender<Node>>>) -> Result<PingResult, String> {
    let host_name: String =
        dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or(pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];
    let bind_socket_addr: SocketAddr = if pinger.src_ip.is_ipv4() && pinger.dst_ip.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else if pinger.src_ip.is_ipv6() && pinger.dst_ip.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        return Err(String::from("Invalid address specified"));
    };
    let udp_socket: Socket = if pinger.src_ip.is_ipv4() && pinger.dst_ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap()
    } else if pinger.src_ip.is_ipv6() && pinger.dst_ip.is_ipv6() {
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP)).unwrap()
    } else {
        return Err(String::from("Invalid address specified"));
    };
    udp_socket.bind(&SockAddr::from(bind_socket_addr)).unwrap();
    let socket: SOCKET = if pinger.src_ip.is_ipv4() && pinger.dst_ip.is_ipv4() {
        sys::create_socket(AF_INET as i32, SOCK_RAW, IPPROTO_IP).unwrap()
    } else if pinger.src_ip.is_ipv6() && pinger.dst_ip.is_ipv6() {
        sys::create_socket(AF_INET6 as i32, SOCK_RAW, IPPROTO_ICMPV6).unwrap()
    } else {
        return Err(String::from("Invalid address specified"));
    };
    let socket_addr: SocketAddr = SocketAddr::new(pinger.src_ip, 0);
    let sock_addr = SockAddr::from(socket_addr);
    sys::bind(socket, &sock_addr).unwrap();
    sys::set_promiscuous(socket, true).unwrap();
    sys::set_timeout_opt(
        socket,
        SOL_SOCKET,
        SO_RCVTIMEO,
        Some(pinger.receive_timeout),
    )
    .unwrap();
    let start_time = Instant::now();
    let mut trace_time = Duration::from_millis(0);
    for seq in 1..pinger.count + 1 {
        trace_time = Instant::now().duration_since(start_time);
        if trace_time > pinger.ping_timeout {
            let result: PingResult = PingResult {
                results: results,
                status: PingStatus::Timeout,
                probe_time: trace_time,
            };
            return Ok(result);
        }
        if pinger.dst_ip.is_ipv4() {
            match udp_socket.set_ttl(pinger.ttl as u32) {
                Ok(_) => (),
                Err(e) => {
                    return Err(format!("{}", e));
                }
            }
        } else {
            match udp_socket.set_unicast_hops_v6(pinger.ttl as u32) {
                Ok(_) => (),
                Err(e) => {
                    return Err(format!("{}", e));
                }
            }
        }
        let udp_buf = [0u8; 0];
        let dst: SocketAddr = SocketAddr::new(pinger.dst_ip, BASE_DST_PORT);
        let send_time = Instant::now();
        let mut buf: Vec<u8> = vec![0; 512];
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        if pinger.dst_ip.is_ipv4() {
            match udp_socket.send_to(&udp_buf, &SockAddr::from(dst)) {
                Ok(_) => (),
                Err(e) => {
                    return Err(format!("{}", e));
                }
            }
        } else {
            let udp_packet = crate::packet::build_udp_probe_packet(
                pinger.src_ip,
                crate::packet::DEFAULT_SRC_PORT,
                pinger.dst_ip,
                BASE_DST_PORT,
            );
            match udp_socket.send_to(&udp_packet, &SockAddr::from(dst)) {
                Ok(_) => (),
                Err(e) => {
                    return Err(format!("{}", e));
                }
            }
        }
        loop {
            if Instant::now().duration_since(send_time) > pinger.receive_timeout {
                break;
            }
            match sys::recv_from(socket, recv_buf, 0) {
                Ok((bytes_len, addr)) => {
                    let src_addr: IpAddr = addr
                        .as_socket()
                        .unwrap_or(SocketAddr::new(pinger.src_ip, 0))
                        .ip();
                    if pinger.src_ip == src_addr {
                        continue;
                    }
                    let recv_time = Instant::now().duration_since(send_time);
                    let recv_buf =
                        unsafe { *(recv_buf as *mut [MaybeUninit<u8>] as *mut [u8; 512]) };
                    if pinger.dst_ip.is_ipv4() {
                        if let Some(packet) =
                            nex_packet::ipv4::Ipv4Packet::new(&recv_buf[0..bytes_len])
                        {
                            let icmp_packet = nex_packet::icmp::IcmpPacket::new(packet.payload());
                            if let Some(icmp) = icmp_packet {
                                let ip_addr: IpAddr = IpAddr::V4(packet.get_source());
                                match icmp.get_icmp_type() {
                                    IcmpType::DestinationUnreachable => {
                                        let node = Node {
                                            seq: seq,
                                            ip_addr: ip_addr,
                                            host_name: host_name.clone(),
                                            ttl: Some(packet.get_ttl()),
                                            hop: Some(
                                                sys::guess_initial_ttl(packet.get_ttl())
                                                    - packet.get_ttl(),
                                            ),
                                            node_type: NodeType::Destination,
                                            rtt: recv_time,
                                        };
                                        results.push(node.clone());
                                        match tx.lock() {
                                            Ok(lr) => match lr.send(node) {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            },
                                            Err(_) => {}
                                        }
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    } else {
                        // IPv6 (ICMPv6 Header only)
                        // The IPv6 header is automatically cropped off when recvfrom() is used.
                        if let Some(icmp_packet) =
                            nex_packet::icmpv6::Icmpv6Packet::new(&recv_buf[0..bytes_len])
                        {
                            let ip_addr: IpAddr = pinger.dst_ip;
                            match icmp_packet.get_icmpv6_type() {
                                Icmpv6Type::DestinationUnreachable => {
                                    let node = Node {
                                        seq: seq,
                                        ip_addr: ip_addr,
                                        host_name: host_name.clone(),
                                        ttl: None,
                                        hop: None,
                                        node_type: NodeType::Destination,
                                        rtt: recv_time,
                                    };
                                    results.push(node.clone());
                                    match tx.lock() {
                                        Ok(lr) => match lr.send(node) {
                                            Ok(_) => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {}
                                    }
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
        thread::sleep(pinger.send_rate);
    }
    let result: PingResult = PingResult {
        results: results,
        status: PingStatus::Done,
        probe_time: trace_time,
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
