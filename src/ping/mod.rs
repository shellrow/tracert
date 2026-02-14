mod pinger;
mod probe;
pub use pinger::*;
pub(crate) use probe::ping;

use crate::node::Node;
use std::time::Duration;

/// Exit status of ping
#[derive(Clone, Debug)]
pub enum PingStatus {
    /// Successfully completed
    Done,
    /// Interrupted by error
    Error,
    /// Execution time exceeds the configured timeout value
    Timeout,
}

/// Result of ping
#[derive(Clone, Debug)]
pub struct PingResult {
    /// Each ping results
    pub results: Vec<Node>,
    /// Ping status
    pub status: PingStatus,
    /// The entire ping probe time
    pub probe_time: Duration,
}

pub(crate) fn guess_initial_ttl(ttl: u8) -> u8 {
    if ttl <= 64 {
        64
    } else if 64 < ttl && ttl <= 128 {
        128
    } else {
        255
    }
}
