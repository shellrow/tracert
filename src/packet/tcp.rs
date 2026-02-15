use nex_packet::tcp::{MutableTcpPacket, TcpFlags};
use std::net::IpAddr;

pub fn build_tcp_packet(
    tcp_packet: &mut MutableTcpPacket,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) {
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(8);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_sequence(0);
    tcp_packet
        .options_mut()
        .copy_from_slice(&[2, 4, 0x05, 0xb4, 4, 2, 1, 1, 3, 3, 7, 0]);
    tcp_packet.set_flags(TcpFlags::SYN);
    match src_ip {
        IpAddr::V4(src_ip) => match dst_ip {
            IpAddr::V4(dst_ip) => {
                tcp_packet.set_ipv4_checksum_context(src_ip, dst_ip);
                let _ = tcp_packet.recompute_checksum();
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(src_ip) => match dst_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(dst_ip) => {
                tcp_packet.set_ipv6_checksum_context(src_ip, dst_ip);
                let _ = tcp_packet.recompute_checksum();
            }
        },
    }
}
