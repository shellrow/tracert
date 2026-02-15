/// Supported probe protocols.
#[derive(Clone, Debug)]
pub enum Protocol {
    /// ICMPv4
    Icmpv4,
    /// ICMPv6
    Icmpv6,
    /// TCP
    Tcp,
    /// UDP
    Udp,
}
