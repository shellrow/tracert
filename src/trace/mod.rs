#[cfg(not(target_os="windows"))]
mod unix;
#[cfg(not(target_os="windows"))]
use unix::trace_route;

#[cfg(target_os="windows")]
mod windows;
#[cfg(target_os="windows")]
use self::windows::trace_route;

mod node;
pub use node::*;

mod tracer;
pub use tracer::*;

use std::time::Duration;

/// Exit status of traceroute
#[derive(Clone, Debug)]
pub enum TraceStatus {
    Done,
    Error,
    Timeout,
}

/// Result of traceroute
#[derive(Clone, Debug)]
pub struct TraceResult {
    pub nodes: Vec<node::Node>,
    pub status: TraceStatus,
    pub trace_time: Duration,
}
