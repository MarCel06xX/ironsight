// Typed wrappers around the Tauri commands and events of the Rust backend.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface Ipv4Net {
  addr: string;
  prefixLen: number;
  /** Suggested scan target for the subnet, e.g. `192.168.1.0/24`. */
  scanTarget: string;
}

export interface Adapter {
  id: string;
  name: string;
  description: string;
  mac: string | null;
  ipv4: Ipv4Net[];
  hasGateway: boolean;
}

export interface HostResult {
  ip: string;
  online: boolean;
  mac: string | null;
  /** ICMP round-trip time; 0 means below one millisecond. */
  rttMs: number | null;
  seenBy: { arp: boolean; icmp: boolean };
  timestampMs: number;
}

export interface ScanBatch {
  scanId: number;
  hosts: HostResult[];
  scanned: number;
  total: number;
  online: number;
}

export interface ScanSummary {
  scanId: number;
  cancelled: boolean;
  scanned: number;
  total: number;
  online: number;
  errors: number;
  startedAtMs: number;
  finishedAtMs: number;
}

export interface ScanRequest {
  targets: string;
  concurrency?: number;
  timeoutMs?: number;
}

export interface ScanStarted {
  scanId: number;
  total: number;
}

/** Error shape of all backend commands. */
export interface CommandError {
  code: string;
  message: string;
}

export function isCommandError(value: unknown): value is CommandError {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.code === "string" && typeof candidate.message === "string";
}

export const listAdapters = (): Promise<Adapter[]> => invoke("list_adapters");

export const startScan = (request: ScanRequest): Promise<ScanStarted> =>
  invoke("start_scan", { request });

export const stopScan = (): Promise<void> => invoke("stop_scan");

export const onScanBatch = (handler: (batch: ScanBatch) => void): Promise<UnlistenFn> =>
  listen<ScanBatch>("scan:batch", (event) => handler(event.payload));

export const onScanFinished = (handler: (summary: ScanSummary) => void): Promise<UnlistenFn> =>
  listen<ScanSummary>("scan:finished", (event) => handler(event.payload));
