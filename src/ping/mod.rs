mod pinger;
mod probe;
pub use pinger::*;
pub(crate) use probe::ping;

use crate::node::Node;
use std::time::Duration;

/// Completion status of a ping run.
#[derive(Clone, Debug)]
pub enum PingStatus {
    /// Completed successfully.
    Done,
    /// Ended due to an error.
    Error,
    /// Stopped because execution exceeded the configured timeout.
    Timeout,
}

/// Aggregated result of a ping run.
#[derive(Clone, Debug)]
pub struct PingResult {
    /// Per-probe results.
    pub results: Vec<Node>,
    /// Completion status.
    pub status: PingStatus,
    /// Total probe time for the run.
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
