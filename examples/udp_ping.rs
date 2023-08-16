use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use tracert::ping::Pinger;

fn main() {
    // UDP ping to dns.google (8.8.8.8)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    // IPv6 UDP ping to dns.google (2001:4860:4860::8888)
    //let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
    let mut pinger: Pinger = Pinger::new(dst_ip).unwrap();
    pinger.set_protocol(tracert::protocol::Protocol::Udp);
    let rx = pinger.get_progress_receiver();
    // Run ping
    let handle = thread::spawn(move || pinger.ping());
    // Print progress
    println!("Progress:");
    while let Ok(msg) = rx.lock().unwrap().recv() {
        println!("{} {} {:?} {:?}", msg.seq, msg.ip_addr, msg.hop, msg.rtt);
    }
    // Print final result
    println!("Result:");
    match handle.join().unwrap() {
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
