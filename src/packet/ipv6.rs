use nex_packet::ip::IpNextLevelProtocol;
use nex_packet::ipv6::MutableIpv6Packet;
use std::net::Ipv6Addr;

#[allow(dead_code)]
pub const IPV6_HEADER_LEN: usize = 40;

#[allow(dead_code)]
pub fn build_ipv6_packet(
    ipv6_packet: &mut MutableIpv6Packet,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    next_protocol: IpNextLevelProtocol,
) {
    ipv6_packet.set_source(src_ip);
    ipv6_packet.set_destination(dst_ip);
    ipv6_packet.set_version(6);
    match next_protocol {
        IpNextLevelProtocol::Tcp => {
            ipv6_packet.set_next_header(IpNextLevelProtocol::Tcp);
        }
        IpNextLevelProtocol::Udp => {
            ipv6_packet.set_next_header(IpNextLevelProtocol::Udp);
        }
        IpNextLevelProtocol::Icmp => {
            ipv6_packet.set_next_header(IpNextLevelProtocol::Icmp);
        }
        _ => {}
    }
}
