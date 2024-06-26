use nex_packet::icmp::echo_request::MutableEchoRequestPacket;
use nex_packet::icmp::IcmpType;
use nex_packet::Packet;

pub fn build_icmpv4_packet(icmp_packet: &mut MutableEchoRequestPacket) {
    icmp_packet.set_icmp_type(IcmpType::EchoRequest);
    icmp_packet.set_sequence_number(rand::random::<u16>());
    icmp_packet.set_identifier(rand::random::<u16>());
    let icmp_check_sum = nex_packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}
