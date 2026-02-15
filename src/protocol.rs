/// Supported probe protocols.
#[derive(Clone, Debug)]
pub enum Protocol {
    /// Internet Control Message Protocol v4.
    Icmpv4,
    /// Internet Control Message Protocol v6.
    Icmpv6,
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}
