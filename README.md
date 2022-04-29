# tracert
Cross-platform traceroute library. Written in Rust.

## Note for Windows users
You may need to set up firewall rules that allow `ICMP Time-to-live Exceeded` and `ICMP Destination (Port) Unreachable` packets to be received.

`netsh` example 
```
netsh advfirewall firewall add rule name="All ICMP v4" dir=in action=allow protocol=icmpv4:any,any
netsh advfirewall firewall add rule name="All ICMP v6" dir=in action=allow protocol=icmpv6:any,any
```
