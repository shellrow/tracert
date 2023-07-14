[crates-badge]: https://img.shields.io/crates/v/tracert.svg
[crates-url]: https://crates.io/crates/tracert
[license-badge]: https://img.shields.io/crates/l/tracert.svg
[tracert-url]: https://github.com/shellrow/tracert

# tracert [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform library for traceroute and ping. Written in Rust.

## Features
- traceroute
    - [x] UDP
- ping
    - [x] ICMPv4
    - [ ] ICMPv6
    - [x] UDP
    - [x] TCP

## Usage
Add `tracert` to your dependencies
```
[dependencies]
tracert = "0.5"
```

## Note for Windows users
You may need to set up firewall rules that allow `ICMP Time-to-live Exceeded` and `ICMP Destination (Port) Unreachable` packets to be received.

`netsh` example 
```
netsh advfirewall firewall add rule name="All ICMP v4" dir=in action=allow protocol=icmpv4:any,any
netsh advfirewall firewall add rule name="All ICMP v6" dir=in action=allow protocol=icmpv6:any,any
```

## Additional Notes
This library requires the ability to create raw sockets. Execute with administrator privileges.
