mod pinger;
mod probe;
pub use pinger::*;
pub(crate) use probe::ping;

use crate::node::Node;
use std::time::Duration;

/// Completion status of a ping run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::guess_initial_ttl;

    #[test]
    fn guesses_common_initial_ttl_buckets() {
        assert_eq!(guess_initial_ttl(1), 64);
        assert_eq!(guess_initial_ttl(64), 64);
        assert_eq!(guess_initial_ttl(65), 128);
        assert_eq!(guess_initial_ttl(128), 128);
        assert_eq!(guess_initial_ttl(129), 255);
        assert_eq!(guess_initial_ttl(255), 255);
    }
}
