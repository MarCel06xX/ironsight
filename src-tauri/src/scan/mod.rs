//! Scan data model shared by the engine, the Tauri commands and (later) enrichment and export.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::mac::MacAddr;

pub mod engine;
pub mod range;

pub const DEFAULT_CONCURRENCY: u32 = 64;
pub const MAX_CONCURRENCY: u32 = 256;
pub const DEFAULT_TIMEOUT_MS: u32 = 1000;
pub const MIN_TIMEOUT_MS: u32 = 100;
pub const MAX_TIMEOUT_MS: u32 = 10_000;

#[derive(Debug, Clone, Copy)]
pub struct ScanConfig {
    /// Hosts probed at the same time.
    pub concurrency: usize,
    /// Per-host answer timeout.
    pub timeout: Duration,
}

/// Which discovery methods got an answer from a host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeenBy {
    pub arp: bool,
    pub icmp: bool,
}

/// Result for one scanned address. Sent once per host; later phases re-send it with
/// enrichment data, so the frontend treats it as an upsert keyed by `ip`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostResult {
    pub ip: IpAddr,
    pub online: bool,
    pub mac: Option<MacAddr>,
    /// ICMP round-trip time; 0 means below one millisecond.
    pub rtt_ms: Option<u32>,
    pub seen_by: SeenBy,
    /// Unix time in milliseconds when the probe finished.
    pub timestamp_ms: u64,
}

/// Live update: new host results plus the running totals.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanBatch {
    pub scan_id: u64,
    pub hosts: Vec<HostResult>,
    pub scanned: u32,
    pub total: u32,
    pub online: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub scan_id: u64,
    pub cancelled: bool,
    pub scanned: u32,
    pub total: u32,
    pub online: u32,
    /// Hosts where a probe failed with an OS error (not: host did not answer).
    pub errors: u32,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
}
