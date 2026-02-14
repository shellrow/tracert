use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::time::sleep;
use tracert::ping::Pinger;

#[tokio::main]
async fn main() {
    // UDP ping to dns.google (8.8.8.8)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    // IPv6 UDP ping to dns.google (2001:4860:4860::8888)
    //let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
    let mut pinger: Pinger = Pinger::new(dst_ip).unwrap();
    pinger.set_protocol(tracert::protocol::Protocol::Udp);
    let rx = pinger.get_progress_receiver();

    let handle = tokio::spawn(async move { pinger.ping_async().await });

    println!("Progress:");
    while !handle.is_finished() {
        let msg = rx.lock().unwrap().try_recv();
        if let Ok(msg) = msg {
            println!("{} {} {:?} {:?}", msg.seq, msg.ip_addr, msg.hop, msg.rtt);
        } else {
            sleep(Duration::from_millis(20)).await;
        }
    }

    while let Ok(msg) = rx.lock().unwrap().try_recv() {
        println!("{} {} {:?} {:?}", msg.seq, msg.ip_addr, msg.hop, msg.rtt);
    }

    println!("Result:");
    match handle.await.unwrap() {
        Ok(r) => {
            println!("Status: {:?}", r.status);
            for result in r.results {
                println!("{:?}", result);
            }
            println!("Probe Time: {:?}", r.probe_time);
        }
        Err(e) => {
            print!("{}", e);
        }
    }
}
