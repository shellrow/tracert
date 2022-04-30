use std::net::{IpAddr, Ipv4Addr};
use tracert::trace::Tracer;

fn main() {
    // UDP traceroute to scanme.nmap.org (45.33.32.156)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(45, 33, 32, 156));
    let tracer: Tracer = Tracer::new(dst_ip).unwrap();
    // Run trace
    match tracer.trace() {
        Ok(r) => {
            println!("Status: {:?}", r.status);
            for node in r.nodes {
                println!("{:?}", node);
            }
            println!("Trace Time: {:?}", r.probe_time);
        },
        Err(e) => {
            print!("{}", e);
        }
    }
}
