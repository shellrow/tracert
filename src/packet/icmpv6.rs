use pnet_packet::icmpv6::Icmpv6Types;
use pnet_packet::icmpv6::MutableIcmpv6Packet;
use pnet_packet::Packet;

#[allow(dead_code)]
pub fn build_icmpv6_packet(icmp_packet: &mut MutableIcmpv6Packet) {
    icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
    let icmp_check_sum = pnet_packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}
