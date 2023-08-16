use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use tracert::ping::Pinger;

fn main() {
    // ICMPv4 ping to cloudflare's one.one.one.one (1.1.1.1)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let pinger: Pinger = Pinger::new(dst_ip).unwrap();
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
