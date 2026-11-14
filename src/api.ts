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
  dnsServers: string[];
  hasGateway: boolean;
}

export type NameSource = "dns" | "mdns" | "netbios";

export interface HttpInfo {
  status: number | null;
  server: string | null;
  title: string | null;
}

export interface ServiceInfo {
  port: number;
  name: string;
  /** Filled for plain-HTTP ports that answered a `GET /`. */
  http: HttpInfo | null;
}

/**
 * One scanned address. Arrives once after probing and, for online hosts, again with
 * `complete = true` after enrichment: always upsert by `ip`.
 * Names, vendor, workgroup and HTTP fields are untrusted network data: `textContent` only.
 */
export interface HostResult {
  ip: string;
  online: boolean;
  /** `false` while name and service lookups are still running. */
  complete: boolean;
  seenBy: { arp: boolean; icmp: boolean; tcp: boolean };
  /** ICMP round-trip time; 0 means below one millisecond. */
  rttMs: number | null;
  mac: string | null;
  /** Locally administered (randomized/private or virtual) MAC: never has a vendor. */
  macLocal: boolean;
  vendor: string | null;
  hostname: string | null;
  hostnameSource: NameSource | null;
  names: { dns: string | null; mdns: string | null; netbios: string | null };
  workgroup: string | null;
  services: ServiceInfo[];
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

export type ThemeName = "dark" | "light" | "blue" | "terminal" | "purple";
export type LanguageSetting = "system" | "en" | "de";
export type CsvDelimiter = ";" | ",";
export type ExportFormat = "csv" | "json" | "html";

/** The only data that is persisted (settings.json in the app config directory). */
export interface Settings {
  theme: ThemeName;
  language: LanguageSetting;
  concurrency: number;
  timeoutMs: number;
  /** Last delimiter used for CSV export. */
  csvDelimiter: CsvDelimiter;
  /** Look for a new version in the background on every start. */
  checkUpdates: boolean;
  /** Version the user chose to skip in the update dialog. */
  skippedVersion: string | null;
}

export interface AppInfo {
  version: string;
  /** Portable single-exe build: updates are downloaded manually. */
  portable: boolean;
}

export interface ExportRequest {
  format: ExportFormat;
  delimiter: CsvDelimiter | null;
  /** Rows of the filtered view in display order; `null` exports every scanned address. */
  ips: string[] | null;
  language: "en" | "de";
  /** Local offset for timestamps in CSV/HTML, i.e. `-new Date().getTimezoneOffset()`. */
  utcOffsetMinutes: number;
}

/** Error shape of all backend commands; `code` maps to the `error.<code>` message. */
export interface CommandError {
  code: string;
  message: string;
  detail: string | null;
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

export const loadSettings = (): Promise<Settings> => invoke("load_settings");

export const saveSettings = (settings: Settings): Promise<void> =>
  invoke("save_settings", { settings });

export const openInBrowser = (ip: string, secure: boolean, port: number): Promise<void> =>
  invoke("open_in_browser", { ip, secure, port });

export const openRemoteDesktop = (ip: string): Promise<void> =>
  invoke("open_remote_desktop", { ip });

export const openFileShare = (ip: string): Promise<void> => invoke("open_file_share", { ip });

export const wakeOnLan = (mac: string, ip: string | null): Promise<void> =>
  invoke("wake_on_lan", { mac, ip });

/** Shows the save dialog and writes the file; resolves to its path, or `null` if cancelled. */
export const exportResults = (request: ExportRequest): Promise<string | null> =>
  invoke("export_results", { request });

export const getAppInfo = (): Promise<AppInfo> => invoke("app_info");

/** Opens the GitHub page of the newest release in the browser. */
export const openReleasePage = (): Promise<void> => invoke("open_release_page");

export const onScanBatch = (handler: (batch: ScanBatch) => void): Promise<UnlistenFn> =>
  listen<ScanBatch>("scan:batch", (event) => handler(event.payload));

export const onScanFinished = (handler: (summary: ScanSummary) => void): Promise<UnlistenFn> =>
  listen<ScanSummary>("scan:finished", (event) => handler(event.payload));
