use std::net::{IpAddr, Ipv4Addr};
use tracert::trace::Tracer;
use std::thread;

fn main() {
    // UDP traceroute to scanme.nmap.org (45.33.32.156)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(45, 33, 32, 156));
    let tracer: Tracer = Tracer::new(dst_ip).unwrap();
    let rx = tracer.get_progress_receiver();
    // Run trace
    let handle = thread::spawn(move|| {
        tracer.trace()
    });
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
