use nex_packet::icmpv6::Icmpv6Type;
use nex_packet::icmpv6::MutableIcmpv6Packet;
use nex_packet::packet::MutablePacket;

pub fn build_icmpv6_packet(icmp_packet: &mut MutableIcmpv6Packet) {
    icmp_packet.set_type(Icmpv6Type::EchoRequest);
    let identifier = rand::random::<u16>().to_be_bytes();
    let sequence_number = rand::random::<u16>().to_be_bytes();
    let payload = icmp_packet.payload_mut();
    payload[0..2].copy_from_slice(&identifier);
    payload[2..4].copy_from_slice(&sequence_number);
    let icmp_checksum = nex_packet::util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_checksum);
}
