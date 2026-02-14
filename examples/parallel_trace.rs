use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracert::trace::Tracer;

#[tokio::main]
async fn main() {
    // Mixed targets (IPv4 / IPv6)
    let targets: Vec<IpAddr> = vec![
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    ];

    let mut set = JoinSet::new();

    for dst_ip in targets {
        set.spawn(async move {
            let tracer = match Tracer::new(dst_ip) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[{}] init error: {}", dst_ip, e);
                    return;
                }
            };

            let mut rx = tracer.get_progress_receiver();
            let handle = tokio::spawn(async move { tracer.trace_async().await });

            while !handle.is_finished() {
                if let Ok(msg) = rx.try_recv() {
                    println!(
                        "[{}] hop={} node={} rtt={:?}",
                        dst_ip, msg.seq, msg.ip_addr, msg.rtt
                    );
                } else {
                    sleep(Duration::from_millis(20)).await;
                }
            }

            while let Ok(msg) = rx.try_recv() {
                println!(
                    "[{}] hop={} node={} rtt={:?}",
                    dst_ip, msg.seq, msg.ip_addr, msg.rtt
                );
            }

            match handle.await {
                Ok(Ok(result)) => {
                    println!(
                        "[{}] done status={:?} hops={} total={:?}",
                        dst_ip,
                        result.status,
                        result.nodes.len(),
                        result.probe_time
                    );
                }
                Ok(Err(e)) => {
                    eprintln!("[{}] trace error: {}", dst_ip, e);
                }
                Err(e) => {
                    eprintln!("[{}] join error: {}", dst_ip, e);
                }
            }
        });
    }

    while let Some(joined) = set.join_next().await {
        if let Err(e) = joined {
            eprintln!("task join error: {}", e);
        }
    }
}
