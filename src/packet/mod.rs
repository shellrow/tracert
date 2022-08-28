mod ipv4;
mod ipv6;
mod icmpv4;
mod icmpv6;
mod tcp;
mod udp;

use pnet_packet::Packet;
use std::net::IpAddr;

#[allow(dead_code)]
const ETHERNET_HEADER_LEN: usize = 14;
#[allow(dead_code)]
const IPV4_HEADER_LEN: usize = 20;

pub fn build_icmpv4_echo_packet() -> Vec<u8> {
    let mut buf = vec![0; 16];
    let mut icmp_packet = pnet_packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
    icmpv4::build_icmpv4_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

#[allow(dead_code)]
pub fn build_icmpv6_echo_packet() -> Vec<u8> {
    let mut buf = vec![0; 16];
    let mut icmp_packet = pnet_packet::icmpv6::MutableIcmpv6Packet::new(&mut buf[..]).unwrap();
    icmpv6::build_icmpv6_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

#[allow(dead_code)]
pub fn build_tcp_syn_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut tcp_packet = pnet_packet::tcp::MutableTcpPacket::new(&mut vec[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..]).unwrap();
    tcp::build_tcp_packet(&mut tcp_packet, src_ip, src_port, dst_ip, dst_port);
    tcp_packet.packet().to_vec()
}

#[allow(dead_code)]
pub fn build_udp_probe_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut udp_packet = pnet_packet::udp::MutableUdpPacket::new(&mut vec[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..]).unwrap();
    udp::build_udp_packet(&mut udp_packet, src_ip, src_port, dst_ip, dst_port);
    udp_packet.packet().to_vec()
}
