use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::time::sleep;
use tracert::trace::Tracer;

#[tokio::main]
async fn main() {
    // UDP traceroute to dns.google (8.8.8.8)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    // IPv6 UDP traceroute to dns.google (2001:4860:4860::8888)
    //let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
    let tracer: Tracer = Tracer::new(dst_ip).unwrap();
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
