mod probe;
mod tracer;
pub(crate) use probe::trace_route;
pub use tracer::*;

use crate::node::Node;
use std::time::Duration;

/// Completion status of a traceroute run.
#[derive(Clone, Debug)]
pub enum TraceStatus {
    /// Completed successfully.
    Done,
    /// Ended due to an error.
    Error,
    /// Stopped because execution exceeded the configured timeout.
    Timeout,
}

/// Aggregated result of a traceroute run.
#[derive(Clone, Debug)]
pub struct TraceResult {
    /// Observed nodes along the route.
    pub nodes: Vec<Node>,
    /// Completion status.
    pub status: TraceStatus,
    /// Total probe time for the run.
    pub probe_time: Duration,
}
