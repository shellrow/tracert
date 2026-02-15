use nex_packet::icmp::IcmpType;
use nex_packet::icmp::MutableIcmpPacket;
use nex_packet::packet::MutablePacket;

pub fn build_icmpv4_packet(icmp_packet: &mut MutableIcmpPacket) {
    icmp_packet.set_type(IcmpType::EchoRequest);
    let identifier = rand::random::<u16>().to_be_bytes();
    let sequence_number = rand::random::<u16>().to_be_bytes();
    let payload = icmp_packet.payload_mut();
    payload[0..2].copy_from_slice(&identifier);
    payload[2..4].copy_from_slice(&sequence_number);
    let icmp_checksum = nex_packet::util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_checksum);
}
