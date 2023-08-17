use pnet_packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmpv6::Icmpv6Types;
use pnet_packet::Packet;

pub fn build_icmpv6_packet(icmp_packet: &mut MutableEchoRequestPacket) {
    icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
    icmp_packet.set_identifier(rand::random::<u16>());
    icmp_packet.set_sequence_number(rand::random::<u16>());
    let icmp_check_sum = pnet_packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}
