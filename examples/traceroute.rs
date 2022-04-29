use std::net::{IpAddr, Ipv4Addr};
use tracert::trace::Tracer;

fn main() {
    // Trace the route to scanme.nmap.org (45.33.32.156)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(45, 33, 32, 156));
    let tracer: Tracer = Tracer::new(dst_ip).unwrap();
    // Run trace
    match tracer.trace() {
        Ok(nodes) => {
            for node in nodes {
                println!("{:?}", node);
            }
        },
        Err(e) => {
            print!("{}", e);
        }
    }
}
