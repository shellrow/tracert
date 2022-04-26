#[cfg(not(target_os="windows"))]
mod unix;
#[cfg(not(target_os="windows"))]
use unix::trace_route;

#[cfg(target_os="windows")]
mod windows;
#[cfg(target_os="windows")]
use self::windows::trace_route;

mod node;
mod tracer;
pub use tracer::*;
