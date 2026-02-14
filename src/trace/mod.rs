mod probe;
mod tracer;
pub(crate) use probe::trace_route;
pub use tracer::*;

use crate::node::Node;
use std::time::Duration;

/// Exit status of traceroute
#[derive(Clone, Debug)]
pub enum TraceStatus {
    /// Successfully completed
    Done,
    /// Interrupted by error
    Error,
    /// Execution time exceeds the configured timeout value
    Timeout,
}

/// Result of traceroute
#[derive(Clone, Debug)]
pub struct TraceResult {
    /// Nodes to destination
    pub nodes: Vec<Node>,
    /// Traceroute status
    pub status: TraceStatus,
    /// The entire traceroute time
    pub probe_time: Duration,
}
