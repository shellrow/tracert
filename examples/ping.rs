use std::net::{IpAddr, Ipv4Addr};
use tracert::ping::Pinger;

fn main() {
    // ICMP ping to scanme.nmap.org (45.33.32.156)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(45, 33, 32, 156));
    let pinger: Pinger = Pinger::new(dst_ip).unwrap();
    // Run Ping
    match pinger.ping() {
        Ok(r) => {
            println!("Status: {:?}", r.status);
            for result in r.results {
                println!("{:?}", result);
            }
            println!("Probe Time: {:?}", r.probe_time);
        },
        Err(e) => {
            print!("{}", e);
        }
    }
}
