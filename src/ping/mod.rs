#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(not(target_os = "windows"))]
use unix::ping;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use self::windows::ping;

mod pinger;
pub use pinger::*;

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
