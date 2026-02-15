use nex_packet::ip::IpNextProtocol;
use nex_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use nex_packet::packet::MutablePacket;
use std::net::Ipv4Addr;

#[allow(dead_code)]
pub const IPV4_HEADER_LEN: usize = 20;

#[allow(dead_code)]
pub fn build_ipv4_packet(
    ipv4_packet: &mut MutableIpv4Packet,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    next_protocol: IpNextProtocol,
) {
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(52);
    ipv4_packet.set_source(src_ip);
    ipv4_packet.set_destination(dst_ip);
    ipv4_packet.set_identification(rand::random::<u16>());
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_version(4);
    ipv4_packet.set_flags(Ipv4Flags::DontFragment);
    match next_protocol {
        IpNextProtocol::Tcp => {
            ipv4_packet.set_next_level_protocol(IpNextProtocol::Tcp);
        }
        IpNextProtocol::Udp => {
            ipv4_packet.set_next_level_protocol(IpNextProtocol::Udp);
        }
        IpNextProtocol::Icmp => {
            ipv4_packet.set_next_level_protocol(IpNextProtocol::Icmp);
        }
        _ => {}
    }
    let checksum = nex_packet::ipv4::checksum(&ipv4_packet.freeze().unwrap());
    ipv4_packet.set_checksum(checksum);
}
