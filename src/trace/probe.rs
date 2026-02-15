use super::BASE_DST_PORT;
use super::{TraceResult, TraceStatus, Tracer};
use crate::node::{Node, NodeType};
use crate::packet;
use crate::protocol::Protocol;
use crate::socket::icmp::{AsyncIcmpSocket, IcmpConfig};
use crate::socket::udp::UdpConfig;
use crate::socket::{SocketFamily, udp::AsyncUdpSocket};
use nex_packet::icmp::IcmpType;
use nex_packet::icmpv6::Icmpv6Type;
use nex_packet::packet::Packet;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

fn send_progress(progress_tx: &broadcast::Sender<Node>, node: Node) {
    let _ = progress_tx.send(node);
}

fn parse_trace_reply(
    dst_ip: IpAddr,
    recv_buf: &[u8],
    bytes_len: usize,
    src_addr: IpAddr,
) -> Option<(IpAddr, Option<u8>, bool)> {
    if dst_ip.is_ipv4() {
        if let Some(packet) = nex_packet::ipv4::Ipv4Packet::from_buf(&recv_buf[0..bytes_len]) {
            if let Some(icmp) = nex_packet::icmp::IcmpPacket::from_buf(packet.payload().as_ref()) {
                let ip_addr: IpAddr = IpAddr::V4(packet.header.source);
                match icmp.header.icmp_type {
                    IcmpType::TimeExceeded => {
                        return Some((ip_addr, Some(packet.header.ttl), false));
                    }
                    IcmpType::DestinationUnreachable => {
                        return Some((ip_addr, Some(packet.header.ttl), true));
                    }
                    IcmpType::EchoReply => return Some((ip_addr, Some(packet.header.ttl), true)),
                    _ => {}
                }
            }
        }
    } else if let Some(icmp_packet) =
        nex_packet::icmpv6::Icmpv6Packet::from_buf(&recv_buf[0..bytes_len])
    {
        match icmp_packet.header.icmpv6_type {
            Icmpv6Type::TimeExceeded => return Some((src_addr, None, false)),
            Icmpv6Type::DestinationUnreachable => return Some((src_addr, None, true)),
            Icmpv6Type::EchoReply => return Some((src_addr, None, true)),
            _ => {}
        }
    }
    None
}

async fn trace_icmp(
    tracer: Tracer,
    progress_tx: &broadcast::Sender<Node>,
) -> Result<TraceResult, String> {
    let mut nodes: Vec<Node> = vec![];
    let mut ip_set: HashSet<IpAddr> = HashSet::new();
    let family = SocketFamily::from_ip(&tracer.dst_ip);

    let start_time = Instant::now();
    let mut trace_time = Duration::from_millis(0);

    for ttl in 1..=tracer.max_hop {
        trace_time = Instant::now().duration_since(start_time);
        if trace_time > tracer.trace_timeout {
            return Ok(TraceResult {
                nodes,
                status: TraceStatus::Timeout,
                probe_time: trace_time,
            });
        }

        let mut cfg = IcmpConfig::new(family);
        if tracer.dst_ip.is_ipv4() {
            cfg.ttl = Some(ttl as u32);
            cfg.bind = Some(SocketAddr::new(tracer.src_ip, 0));
        } else {
            cfg.hop_limit = Some(ttl as u32);
            cfg.bind = Some(SocketAddr::new(tracer.src_ip, 0));
        }

        let icmp_socket = AsyncIcmpSocket::new(&cfg)
            .await
            .map_err(|e| format!("{}", e))?;

        let socket_addr = SocketAddr::new(tracer.dst_ip, 0);
        let icmp_packet: Vec<u8> = if tracer.dst_ip.is_ipv4() {
            packet::build_icmpv4_echo_packet()
        } else {
            packet::build_icmpv6_echo_packet()
        };
        let send_time = Instant::now();

        let _ = icmp_socket.send_to(&icmp_packet, socket_addr).await;

        let mut buf = vec![0u8; 2048];
        let recv =
            tokio::time::timeout(tracer.receive_timeout, icmp_socket.recv_from(&mut buf)).await;
        if let Ok(Ok((bytes_len, addr))) = recv {
            let src_addr = addr.ip();
            if ip_set.contains(&src_addr) {
                if ttl != tracer.max_hop {
                    tokio::time::sleep(tracer.send_interval).await;
                }
                continue;
            }
            if let Some((ip_addr, node_ttl, reached)) =
                parse_trace_reply(tracer.dst_ip, &buf, bytes_len, src_addr)
            {
                let recv_time = Instant::now().duration_since(send_time);
                let node = Node {
                    sequence: ttl,
                    ip_addr,
                    hostname: ip_addr.to_string(),
                    ttl: node_ttl,
                    hop_count: Some(ttl),
                    node_type: if reached {
                        NodeType::Destination
                    } else {
                        NodeType::Hop
                    },
                    rtt: recv_time,
                };
                nodes.push(node.clone());
                send_progress(progress_tx, node);
                ip_set.insert(ip_addr);
                if reached {
                    break;
                }
            }
        }

        if ttl != tracer.max_hop {
            tokio::time::sleep(tracer.send_interval).await;
        }
    }

    for node in &mut nodes {
        if node.node_type == NodeType::Destination {
            node.hostname =
                dns_lookup::lookup_addr(&node.ip_addr).unwrap_or_else(|_| node.ip_addr.to_string());
        }
    }

    Ok(TraceResult {
        nodes,
        status: TraceStatus::Done,
        probe_time: trace_time,
    })
}

async fn trace_udp(
    tracer: Tracer,
    progress_tx: &broadcast::Sender<Node>,
) -> Result<TraceResult, String> {
    let mut nodes: Vec<Node> = vec![];
    let mut ip_set: HashSet<IpAddr> = HashSet::new();
    let family = SocketFamily::from_ip(&tracer.dst_ip);

    let bind_socket_addr: SocketAddr = if tracer.src_ip.is_ipv4() && tracer.dst_ip.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else if tracer.src_ip.is_ipv6() && tracer.dst_ip.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        return Err(String::from("Invalid address specified"));
    };

    let mut udp_cfg = UdpConfig::new(family);
    udp_cfg.bind_addr = Some(bind_socket_addr);
    let udp_socket = AsyncUdpSocket::from_config(&udp_cfg).map_err(|e| format!("{}", e))?;

    let icmp_socket = AsyncIcmpSocket::new(&IcmpConfig::new(family))
        .await
        .map_err(|e| format!("{}", e))?;

    let start_time = Instant::now();
    let mut trace_time = Duration::from_millis(0);
    for ttl in 1..=tracer.max_hop {
        trace_time = Instant::now().duration_since(start_time);
        if trace_time > tracer.trace_timeout {
            return Ok(TraceResult {
                nodes,
                status: TraceStatus::Timeout,
                probe_time: trace_time,
            });
        }

        let mut per_hop_cfg = UdpConfig::new(family);
        per_hop_cfg.bind_addr = Some(bind_socket_addr);
        if tracer.dst_ip.is_ipv4() {
            per_hop_cfg.ttl = Some(ttl as u32);
        } else {
            per_hop_cfg.hop_limit = Some(ttl as u32);
        }
        let udp_socket = AsyncUdpSocket::from_config(&per_hop_cfg).map_err(|e| format!("{}", e))?;

        let udp_buf = [0u8; 0];
        let dst: SocketAddr = SocketAddr::new(tracer.dst_ip, BASE_DST_PORT + ttl as u16);
        let send_time = Instant::now();

        udp_socket
            .send_to(&udp_buf, dst)
            .await
            .map_err(|e| format!("{}", e))?;

        let mut buf = vec![0u8; 2048];
        let recv =
            tokio::time::timeout(tracer.receive_timeout, icmp_socket.recv_from(&mut buf)).await;
        if let Ok(Ok((bytes_len, addr))) = recv {
            let src_addr = addr.ip();
            if ip_set.contains(&src_addr) {
                if ttl != tracer.max_hop {
                    tokio::time::sleep(tracer.send_interval).await;
                }
                continue;
            }

            if let Some((ip_addr, node_ttl, reached)) =
                parse_trace_reply(tracer.dst_ip, &buf, bytes_len, src_addr)
            {
                let recv_time = Instant::now().duration_since(send_time);
                let node = Node {
                    sequence: ttl,
                    ip_addr,
                    hostname: ip_addr.to_string(),
                    ttl: node_ttl,
                    hop_count: Some(ttl),
                    node_type: if reached {
                        NodeType::Destination
                    } else {
                        NodeType::Hop
                    },
                    rtt: recv_time,
                };
                nodes.push(node.clone());
                send_progress(progress_tx, node);
                ip_set.insert(ip_addr);
                if reached {
                    break;
                }
            }
        }

        if ttl != tracer.max_hop {
            tokio::time::sleep(tracer.send_interval).await;
        }
    }

    for node in &mut nodes {
        if node.node_type == NodeType::Destination {
            node.hostname =
                dns_lookup::lookup_addr(&node.ip_addr).unwrap_or_else(|_| node.ip_addr.to_string());
        }
    }

    let _ = udp_socket;

    Ok(TraceResult {
        nodes,
        status: TraceStatus::Done,
        probe_time: trace_time,
    })
}

pub(crate) async fn trace_route(
    tracer: Tracer,
    progress_tx: &broadcast::Sender<Node>,
) -> Result<TraceResult, String> {
    match tracer.protocol {
        Protocol::Udp => trace_udp(tracer, progress_tx).await,
        Protocol::Icmpv4 | Protocol::Icmpv6 => trace_icmp(tracer, progress_tx).await,
        Protocol::Tcp => Err(String::from("TCP traceroute is not supported")),
    }
}
