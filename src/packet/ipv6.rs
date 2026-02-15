use nex_packet::ip::IpNextProtocol;
use nex_packet::ipv6::MutableIpv6Packet;
use std::net::Ipv6Addr;

#[allow(dead_code)]
pub const IPV6_HEADER_LEN: usize = 40;

#[allow(dead_code)]
pub fn build_ipv6_packet(
    ipv6_packet: &mut MutableIpv6Packet,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    next_protocol: IpNextProtocol,
) {
    ipv6_packet.set_source(src_ip);
    ipv6_packet.set_destination(dst_ip);
    ipv6_packet.set_version(6);
    match next_protocol {
        IpNextProtocol::Tcp => {
            ipv6_packet.set_next_header(IpNextProtocol::Tcp);
        }
        IpNextProtocol::Udp => {
            ipv6_packet.set_next_header(IpNextProtocol::Udp);
        }
        IpNextProtocol::Icmp => {
            ipv6_packet.set_next_header(IpNextProtocol::Icmp);
        }
        _ => {}
    }
}
