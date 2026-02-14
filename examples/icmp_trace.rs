use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::time::sleep;
use tracert::protocol::Protocol;
use tracert::trace::Tracer;

#[tokio::main]
async fn main() {
    // ICMPv4 traceroute to cloudflare's one.one.one.one (1.1.1.1)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    // ICMPv6 traceroute to cloudflare's one.one.one.one (2606:4700:4700::1111)
    //let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

    let mut tracer: Tracer = Tracer::new(dst_ip).unwrap();
    tracer.set_protocol(if dst_ip.is_ipv4() {
        Protocol::Icmpv4
    } else {
        Protocol::Icmpv6
    });

    let mut rx = tracer.get_progress_receiver();
    let handle = tokio::spawn(async move { tracer.trace_async().await });

    println!("Progress:");
    while !handle.is_finished() {
        let msg = rx.try_recv();
        if let Ok(msg) = msg {
            println!("{} {} {:?} {:?}", msg.seq, msg.ip_addr, msg.hop, msg.rtt);
        } else {
            sleep(Duration::from_millis(20)).await;
        }
    }

    while let Ok(msg) = rx.try_recv() {
        println!("{} {} {:?} {:?}", msg.seq, msg.ip_addr, msg.hop, msg.rtt);
    }

    println!("Result:");
    match handle.await.unwrap() {
        Ok(r) => {
            println!("Status: {:?}", r.status);
            for node in r.nodes {
                println!("{:?}", node);
            }
            println!("Trace Time: {:?}", r.probe_time);
        }
        Err(e) => {
            print!("{}", e);
        }
    }
}
