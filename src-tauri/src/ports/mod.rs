//! TCP connect port scan: port lists and presets, service names, the probe and the scan
//! engine. Plain sockets only: no admin rights, no raw sockets, no Npcap.

use serde::{Deserialize, Serialize};

pub mod names;
pub mod presets;
pub mod probe;
pub mod scanner;
pub mod spec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    /// The connection was accepted.
    Open,
    /// The host answered with a reset (connection refused).
    Closed,
    /// No answer within the timeout, or an ICMP "unreachable".
    Filtered,
}
