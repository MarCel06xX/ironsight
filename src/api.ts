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

/** online: answered now; offline: silent but data exists; unused: silent, nothing known. */
export type HostStatus = "online" | "offline" | "unused";

/** Where a shown value came from. */
export type DataSource = "live" | "dns" | "arpCache" | "remembered" | "imported";

export interface FieldSources {
  hostname: DataSource | null;
  mac: DataSource | null;
  vendor: DataSource | null;
  services: DataSource | null;
  workgroup: DataSource | null;
}

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
  /** Cleaned greeting of the service (banner grabbing); untrusted, `textContent` only. */
  banner: string | null;
}

export type PortState = "open" | "closed" | "filtered";
export type PortPreset = "common" | "top100" | "top1000" | "all";
/** Which ports a port scan covers. */
export type PortSelection = { preset: PortPreset } | { custom: string };

/** Port scan of one host; its open ports are in `HostResult.services`. */
export interface PortScanInfo {
  selection: PortSelection;
  /** Every port has a result (`false` while running or after a stop). */
  complete: boolean;
  probed: number;
  total: number;
  open: number;
  closed: number;
  filtered: number;
  /** Probes that failed locally (no statement about the port). */
  errors: number;
  /** Closed and filtered ports one by one, while there are only a few of a state. */
  listed: { port: number; state: PortState }[];
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
  /** Port scan of this host, if one ran. */
  portScan: PortScanInfo | null;
  timestampMs: number;
  status: HostStatus;
  /** When the device was last seen online (now, or from the known devices). */
  lastSeenMs: number | null;
  sources: FieldSources;
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

export type OfflineNames = "auto" | "always" | "never";

export interface ScanRequest {
  targets: string;
  concurrency?: number;
  timeoutMs?: number;
  /** Reverse DNS for addresses that do not answer. */
  offlineNames?: OfflineNames;
  /** Read banners and HTTP titles of open ports (default: on). */
  banners?: boolean;
  /** Port scan of the hosts that answered, after host discovery. */
  ports?: PortScanOptions | null;
}

/** Port scan settings; missing limits use the backend defaults. */
export interface PortScanOptions {
  selection: PortSelection;
  timeoutMs?: number;
  concurrency?: number;
  perHost?: number;
  maxProbes?: number;
}

export interface HostPortsRequest {
  ip: string;
  ports: PortScanOptions;
  banners?: boolean;
}

export interface PortScanStarted {
  scanId: number;
  /** Probes to make. */
  total: number;
}

/** `ports:batch`: changed rows (upsert by `ip`) plus progress in probes. */
export interface PortsBatch {
  scanId: number;
  hosts: HostResult[];
  done: number;
  total: number;
}

export interface PortScanSummary {
  scanId: number;
  cancelled: boolean;
  hosts: number;
  hostsComplete: number;
  done: number;
  total: number;
  open: number;
  errors: number;
  startedAtMs: number;
  finishedAtMs: number;
}

/** `ports:finished`: `error` if the port scan was refused (e.g. above the probe limit). */
export interface PortsFinished {
  scanId: number;
  summary: PortScanSummary | null;
  error: CommandError | null;
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
  offlineNames: OfflineNames;
  /** Save known devices to disk (opt-in). */
  rememberDevices: boolean;
}

/** Result of loading a previous scan or forgetting known devices. */
export interface KnownUpdate {
  devices: number;
  /** Rows of the current results whose display changed. */
  hosts: HostResult[];
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

/** "Load previous scan…": `null` if the file dialog was cancelled. */
export const importScan = (): Promise<KnownUpdate | null> => invoke("import_scan");

export const forgetKnownDevices = (): Promise<KnownUpdate> => invoke("forget_known_devices");

/** Opens the GitHub page of the newest release in the browser. */
export const openReleasePage = (): Promise<void> => invoke("open_release_page");

export const onScanBatch = (handler: (batch: ScanBatch) => void): Promise<UnlistenFn> =>
  listen<ScanBatch>("scan:batch", (event) => handler(event.payload));

export const onScanFinished = (handler: (summary: ScanSummary) => void): Promise<UnlistenFn> =>
  listen<ScanSummary>("scan:finished", (event) => handler(event.payload));

/** "Scan ports…" for one host of the last scan; results arrive as `ports:*` events. */
export const scanHostPorts = (request: HostPortsRequest): Promise<PortScanStarted> =>
  invoke("scan_host_ports", { request });

export const onPortsBatch = (handler: (batch: PortsBatch) => void): Promise<UnlistenFn> =>
  listen<PortsBatch>("ports:batch", (event) => handler(event.payload));

export const onPortsFinished = (handler: (finished: PortsFinished) => void): Promise<UnlistenFn> =>
  listen<PortsFinished>("ports:finished", (event) => handler(event.payload));
