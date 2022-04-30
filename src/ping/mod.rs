#[cfg(not(target_os="windows"))]
mod unix;
#[cfg(not(target_os="windows"))]
use unix::ping;

#[cfg(target_os="windows")]
mod windows;
#[cfg(target_os="windows")]
use self::windows::ping;

mod pinger;
pub use pinger::*;

use std::time::Duration;
use crate::node::Node;

/// Exit status of ping
#[derive(Clone, Debug)]
pub enum PingStatus {
    Done,
    Error,
    Timeout,
}

/// Result of ping
#[derive(Clone, Debug)]
pub struct PingResult {
    pub results: Vec<Node>,
    pub status: PingStatus,
    pub probe_time: Duration,
}
