use std::time::{Instant, Duration};
use std::net::{SocketAddr, IpAddr, UdpSocket};
use std::mem::MaybeUninit;
use std::thread;
use std::sync::{Mutex, Arc};
use std::sync::mpsc::Sender;
use socket2::{Domain, Protocol, Socket, Type, SockAddr};
use pnet_packet::Packet;
use pnet_packet::icmp::IcmpTypes;
use crate::node::{NodeType, Node};
use crate::packet;
use super::{Pinger, PingStatus, PingResult};
use crate::protocol::Protocol as ProbeProtocol;
use crate::trace::BASE_DST_PORT;
use crate::sys;

fn icmp_ping(pinger: Pinger, tx: &Arc<Mutex<Sender<Node>>>) -> Result<PingResult, String> {
    let host_name: String = dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or(pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];
    let icmp_socket: Socket = 
    if pinger.src_ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap()
    }else if pinger.src_ip.is_ipv6(){
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap()
    }else{
        return Err(String::from("invalid source address"));
    };
    icmp_socket.set_read_timeout(Some(pinger.receive_timeout)).unwrap();
    icmp_socket.set_ttl(pinger.ttl as u32).unwrap();
    let socket_addr = SocketAddr::new(pinger.dst_ip, 0);
    let sock_addr = SockAddr::from(socket_addr);
    let mut icmp_packet: Vec<u8> = packet::build_icmpv4_echo_packet();
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
        let mut recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let send_time = Instant::now();
        match icmp_socket.send_to(&mut icmp_packet, &sock_addr) {
            Ok(_) => {},
            Err(_) => {},
        }
        loop {
            match icmp_socket.recv_from(&mut recv_buf) {
                Ok((bytes_len, _addr)) => {
                    let recv_time = Instant::now().duration_since(send_time);
                    if recv_time > pinger.receive_timeout {
                        break;
                    }
                    let recv_buf = unsafe { *(recv_buf as *mut [MaybeUninit<u8>] as *mut [u8; 512]) };
                    if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(&recv_buf[0..bytes_len]){
                        let icmp_packet = pnet_packet::icmp::IcmpPacket::new(packet.payload());
                        if let Some(icmp) = icmp_packet {
                            let ip_addr: IpAddr = IpAddr::V4(packet.get_source());
                            match icmp.get_icmp_type() {
                                IcmpTypes::EchoReply => {
                                    let node = Node {
                                        seq: seq,
                                        ip_addr: ip_addr,
                                        host_name: host_name.clone(),
                                        hop: Some(sys::guess_initial_ttl(packet.get_ttl()) - packet.get_ttl()),
                                        node_type: NodeType::Destination,
                                        rtt: recv_time,
                                    };
                                    results.push(node.clone());
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
    let host_name: String = dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or(pinger.dst_ip.to_string());
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
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let connect_start_time = Instant::now();
        match socket.connect_timeout(&sock_addr, pinger.receive_timeout) {
            Ok(_) => {
                let connect_end_time = Instant::now().duration_since(connect_start_time);
                let node = Node {
                    seq: seq,
                    ip_addr: pinger.dst_ip,
                    host_name: host_name.clone(),
                    hop: None,
                    node_type: NodeType::Destination,
                    rtt: connect_end_time,
                };
                results.push(node.clone());
                match tx.lock() {
                    Ok(lr) => {
                        match lr.send(node) {
                            Ok(_) => {},
                            Err(_) => {},
                        }
                    },
                    Err(_) => {},
                }
            },
            Err(e) => {
                println!("{}", e);
            },
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
    let host_name: String = dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or(pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];
    let udp_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            return Err(format!("{}", e));
        },
    };
    let icmp_socket: Socket = 
    if pinger.src_ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap()
    }else if pinger.src_ip.is_ipv6(){
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap()
    }else{
        return Err(String::from("invalid source address"));
    };
    icmp_socket.set_read_timeout(Some(pinger.receive_timeout)).unwrap();
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
        match udp_socket.set_ttl(pinger.ttl as u32) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!("{}", e));
            },
        }
        let udp_buf = [0u8; 0];
        let mut buf: Vec<u8> = vec![0; 512];
        let mut recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let dst: SocketAddr = SocketAddr::new(pinger.dst_ip, BASE_DST_PORT);
        let send_time = Instant::now();
        match udp_socket.send_to(&udp_buf, dst) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!("{}", e));
            },
        }
        loop{
            if Instant::now().duration_since(send_time) > pinger.receive_timeout {
                break;
            }
            match icmp_socket.recv_from(&mut recv_buf) {
                Ok((bytes_len, _addr)) => {
                    let recv_time = Instant::now().duration_since(send_time);
                    let recv_buf = unsafe { *(recv_buf as *mut [MaybeUninit<u8>] as *mut [u8; 512]) };
                    if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(&recv_buf[0..bytes_len]){
                        let icmp_packet = pnet_packet::icmp::IcmpPacket::new(packet.payload());
                        if let Some(icmp) = icmp_packet {
                            let ip_addr: IpAddr = IpAddr::V4(packet.get_source());
                            match icmp.get_icmp_type() {
                                IcmpTypes::DestinationUnreachable => {
                                    let node = Node {
                                        seq: seq,
                                        ip_addr: ip_addr,
                                        host_name: host_name.clone(),
                                        hop: Some(sys::guess_initial_ttl(packet.get_ttl()) - packet.get_ttl()),
                                        node_type: NodeType::Destination,
                                        rtt: recv_time,
                                    };
                                    results.push(node.clone());
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
        }
        thread::sleep(pinger.send_rate);
    }
    for node in &mut results {
        let host_name: String = dns_lookup::lookup_addr(&node.ip_addr).unwrap_or(node.ip_addr.to_string());
        node.host_name = host_name;
    }
    let result: PingResult = PingResult {
        results: results,
        status: PingStatus::Done,
        probe_time: probe_time,
    };
    Ok(result)
}

pub(crate) fn ping(pinger: Pinger, tx: &Arc<Mutex<Sender<Node>>>) -> Result<PingResult, String> {
    match pinger.protocol {
        ProbeProtocol::Icmpv4 => {
            icmp_ping(pinger, tx)
        },
        ProbeProtocol::Icmpv6 => {
            icmp_ping(pinger, tx)
        },
        ProbeProtocol::Tcp => {
            tcp_ping(pinger, tx)
        },
        ProbeProtocol::Udp => {
            udp_ping(pinger, tx)
        },
    }
}

