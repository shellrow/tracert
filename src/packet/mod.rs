mod icmpv4;
mod icmpv6;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;

use pnet_packet::Packet;
use std::net::IpAddr;

const ETHERNET_HEADER_LEN: usize = pnet_packet::ethernet::MutableEthernetPacket::minimum_packet_size();
const IPV4_HEADER_LEN: usize = pnet_packet::ipv4::MutableIpv4Packet::minimum_packet_size();
//const IPV6_HEADER_LEN: usize = pnet_packet::ipv6::MutableIpv6Packet::minimum_packet_size();
const ICMPV4_HEADER_SIZE: usize = pnet_packet::icmp::echo_request::MutableEchoRequestPacket::minimum_packet_size();
const ICMPV6_HEADER_SIZE: usize = pnet_packet::icmpv6::echo_request::MutableEchoRequestPacket::minimum_packet_size();

pub(crate) const DEFAULT_SRC_PORT: u16 = 58443;

pub fn build_icmpv4_echo_packet() -> Vec<u8> {
    let mut buf = vec![0; ICMPV4_HEADER_SIZE];
    let mut icmp_packet =
        pnet_packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
    icmpv4::build_icmpv4_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

pub fn build_icmpv6_echo_packet() -> Vec<u8> {
    let mut buf = vec![0; ICMPV6_HEADER_SIZE];
    let mut icmp_packet = pnet_packet::icmpv6::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
    icmpv6::build_icmpv6_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

#[allow(dead_code)]
pub fn build_tcp_syn_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut tcp_packet = pnet_packet::tcp::MutableTcpPacket::new(
        &mut vec[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..],
    )
    .unwrap();
    tcp::build_tcp_packet(&mut tcp_packet, src_ip, src_port, dst_ip, dst_port);
    tcp_packet.packet().to_vec()
}

pub fn build_udp_probe_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut udp_packet = pnet_packet::udp::MutableUdpPacket::new(
        &mut vec[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..],
    )
    .unwrap();
    udp::build_udp_packet(&mut udp_packet, src_ip, src_port, dst_ip, dst_port);
    udp_packet.packet().to_vec()
}
