use super::{PingResult, PingStatus, Pinger};
use crate::node::{Node, NodeType};
use crate::packet;
use crate::protocol::Protocol as ProbeProtocol;
use crate::socket::SocketFamily;
use crate::socket::icmp::{AsyncIcmpSocket, IcmpConfig};
use crate::socket::tcp::{AsyncTcpSocket, TcpConfig};
use crate::socket::udp::{AsyncUdpSocket, UdpConfig};
use nex_packet::icmp::IcmpType;
use nex_packet::icmpv6::Icmpv6Type;
use nex_packet::packet::Packet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

fn send_progress(progress_tx: &broadcast::Sender<Node>, node: Node) {
    let _ = progress_tx.send(node);
}

fn recv_icmp_reply(
    dst_ip: IpAddr,
    recv_buf: &[u8],
    bytes_len: usize,
) -> Option<(IpAddr, Option<u8>, bool)> {
    if dst_ip.is_ipv4() {
        if let Some(packet) = nex_packet::ipv4::Ipv4Packet::from_buf(&recv_buf[0..bytes_len]) {
            if let Some(icmp) = nex_packet::icmp::IcmpPacket::from_buf(packet.payload().as_ref()) {
                let ip_addr: IpAddr = IpAddr::V4(packet.header.source);
                match icmp.header.icmp_type {
                    IcmpType::EchoReply => return Some((ip_addr, Some(packet.header.ttl), true)),
                    IcmpType::DestinationUnreachable => {
                        return Some((ip_addr, Some(packet.header.ttl), false));
                    }
                    _ => {}
                }
            }
        }
    } else if let Some(icmp_packet) =
        nex_packet::icmpv6::Icmpv6Packet::from_buf(&recv_buf[0..bytes_len])
    {
        match icmp_packet.header.icmpv6_type {
            Icmpv6Type::EchoReply => return Some((dst_ip, None, true)),
            Icmpv6Type::DestinationUnreachable => return Some((dst_ip, None, false)),
            _ => {}
        }
    }
    None
}

async fn icmp_ping(
    pinger: Pinger,
    progress_tx: &broadcast::Sender<Node>,
) -> Result<PingResult, String> {
    let hostname =
        dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or_else(|_| pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];

    let family = SocketFamily::from_ip(&pinger.dst_ip);
    let mut cfg = IcmpConfig::new(family);
    if pinger.dst_ip.is_ipv4() {
        cfg.ttl = Some(pinger.ttl as u32);
    } else {
        cfg.hop_limit = Some(pinger.ttl as u32);
    }
    let icmp_socket = AsyncIcmpSocket::new(&cfg)
        .await
        .map_err(|e| format!("{}", e))?;

    let socket_addr = SocketAddr::new(pinger.dst_ip, 0);
    let icmp_packet: Vec<u8> = if pinger.dst_ip.is_ipv4() {
        packet::build_icmpv4_echo_packet()
    } else {
        packet::build_icmpv6_echo_packet()
    };

    let start_time = Instant::now();
    let mut probe_time = Duration::from_millis(0);
    for sequence in 1..=pinger.probe_count {
        probe_time = Instant::now().duration_since(start_time);
        if probe_time > pinger.ping_timeout {
            return Ok(PingResult {
                results,
                status: PingStatus::Timeout,
                probe_time,
            });
        }

        let send_time = Instant::now();
        let _ = icmp_socket.send_to(&icmp_packet, socket_addr).await;

        let mut buf = vec![0u8; 2048];
        let recv = tokio::time::timeout(pinger.receive_timeout, async {
            loop {
                let (bytes_len, _) = icmp_socket.recv_from(&mut buf).await?;
                if let Some((ip_addr, ttl, is_echo_reply)) =
                    recv_icmp_reply(pinger.dst_ip, &buf, bytes_len)
                {
                    if is_echo_reply {
                        return Ok::<_, std::io::Error>((ip_addr, ttl));
                    }
                }
            }
        })
        .await;

        if let Ok(Ok((ip_addr, ttl))) = recv {
            let recv_time = Instant::now().duration_since(send_time);
            let node = Node {
                sequence,
                ip_addr,
                hostname: hostname.clone(),
                ttl,
                hop_count: ttl.map(|v| super::guess_initial_ttl(v) - v),
                node_type: NodeType::Destination,
                rtt: recv_time,
            };
            results.push(node.clone());
            send_progress(progress_tx, node);
        }

        if sequence != pinger.probe_count {
            tokio::time::sleep(pinger.send_interval).await;
        }
    }

    Ok(PingResult {
        results,
        status: PingStatus::Done,
        probe_time,
    })
}

async fn tcp_ping(
    pinger: Pinger,
    progress_tx: &broadcast::Sender<Node>,
) -> Result<PingResult, String> {
    let hostname =
        dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or_else(|_| pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];
    let socket_addr = SocketAddr::new(pinger.dst_ip, pinger.dst_port);
    let mut probe_time = Duration::from_millis(0);
    let start_time = Instant::now();

    for sequence in 1..=pinger.probe_count {
        probe_time = Instant::now().duration_since(start_time);
        if probe_time > pinger.ping_timeout {
            return Ok(PingResult {
                results,
                status: PingStatus::Timeout,
                probe_time,
            });
        }

        let family = SocketFamily::from_ip(&pinger.dst_ip);
        let mut cfg = TcpConfig::new(family);
        cfg.nodelay = Some(true);
        if pinger.dst_ip.is_ipv4() {
            cfg.ttl = Some(pinger.ttl as u32);
        } else {
            cfg.hop_limit = Some(pinger.ttl as u32);
        }

        let socket = AsyncTcpSocket::from_config(&cfg).map_err(|e| format!("{}", e))?;
        let connect_start_time = Instant::now();
        let connect_result = socket
            .connect_timeout(socket_addr, pinger.receive_timeout)
            .await;
        let connect_end_time = Instant::now().duration_since(connect_start_time);
        let node = Node {
            sequence,
            ip_addr: pinger.dst_ip,
            hostname: hostname.clone(),
            ttl: None,
            hop_count: None,
            node_type: NodeType::Destination,
            rtt: connect_end_time,
        };
        send_progress(progress_tx, node.clone());
        if connect_result.is_ok() {
            results.push(node.clone());
        }

        if sequence != pinger.probe_count {
            tokio::time::sleep(pinger.send_interval).await;
        }
    }

    Ok(PingResult {
        results,
        status: PingStatus::Done,
        probe_time,
    })
}

async fn udp_ping(
    pinger: Pinger,
    progress_tx: &broadcast::Sender<Node>,
) -> Result<PingResult, String> {
    let hostname =
        dns_lookup::lookup_addr(&pinger.dst_ip).unwrap_or_else(|_| pinger.dst_ip.to_string());
    let mut results: Vec<Node> = vec![];

    let bind_socket_addr: SocketAddr = if pinger.src_ip.is_ipv4() && pinger.dst_ip.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else if pinger.src_ip.is_ipv6() && pinger.dst_ip.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        return Err(String::from("Invalid address specified"));
    };

    let family = SocketFamily::from_ip(&pinger.dst_ip);
    let mut udp_cfg = UdpConfig::new(family);
    udp_cfg.bind_addr = Some(bind_socket_addr);
    if pinger.dst_ip.is_ipv4() {
        udp_cfg.ttl = Some(pinger.ttl as u32);
    } else {
        udp_cfg.hop_limit = Some(pinger.ttl as u32);
    }
    let udp_socket = AsyncUdpSocket::from_config(&udp_cfg).map_err(|e| format!("{}", e))?;

    let icmp_socket = AsyncIcmpSocket::new(&IcmpConfig::new(family))
        .await
        .map_err(|e| format!("{}", e))?;

    let start_time = Instant::now();
    let mut probe_time = Duration::from_millis(0);
    for sequence in 1..=pinger.probe_count {
        probe_time = Instant::now().duration_since(start_time);
        if probe_time > pinger.ping_timeout {
            return Ok(PingResult {
                results,
                status: PingStatus::Timeout,
                probe_time,
            });
        }

        let udp_buf = [0u8; 0];
        let dst: SocketAddr = SocketAddr::new(pinger.dst_ip, crate::trace::BASE_DST_PORT);
        let send_time = Instant::now();

        udp_socket
            .send_to(&udp_buf, dst)
            .await
            .map_err(|e| format!("{}", e))?;

        let mut buf = vec![0u8; 2048];
        let recv = tokio::time::timeout(pinger.receive_timeout, async {
            loop {
                let (bytes_len, _addr) = icmp_socket.recv_from(&mut buf).await?;
                if let Some((ip_addr, ttl, is_echo_reply)) =
                    recv_icmp_reply(pinger.dst_ip, &buf, bytes_len)
                {
                    if !is_echo_reply {
                        return Ok::<_, std::io::Error>((ip_addr, ttl));
                    }
                }
            }
        })
        .await;

        if let Ok(Ok((ip_addr, ttl))) = recv {
            let recv_time = Instant::now().duration_since(send_time);
            let node = Node {
                sequence,
                ip_addr,
                hostname: hostname.clone(),
                ttl,
                hop_count: ttl.map(|v| super::guess_initial_ttl(v) - v),
                node_type: NodeType::Destination,
                rtt: recv_time,
            };
            results.push(node.clone());
            send_progress(progress_tx, node);
        }

        if sequence != pinger.probe_count {
            tokio::time::sleep(pinger.send_interval).await;
        }
    }

    Ok(PingResult {
        results,
        status: PingStatus::Done,
        probe_time,
    })
}

pub(crate) async fn ping(
    pinger: Pinger,
    progress_tx: &broadcast::Sender<Node>,
) -> Result<PingResult, String> {
    match pinger.protocol {
        ProbeProtocol::Icmpv4 => icmp_ping(pinger, progress_tx).await,
        ProbeProtocol::Icmpv6 => icmp_ping(pinger, progress_tx).await,
        ProbeProtocol::Tcp => tcp_ping(pinger, progress_tx).await,
        ProbeProtocol::Udp => udp_ping(pinger, progress_tx).await,
    }
}
