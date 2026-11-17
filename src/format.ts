// Display helpers shared by the table, the details panel, sorting and filtering.
import type {
  DataSource,
  HostResult,
  HostStatus,
  HttpInfo,
  NameSource,
  PortChoice,
  PortSelection,
  PortState,
  ServiceInfo,
} from "./api";
import { type MessageKey, formatNumber, t } from "./i18n";

const SOURCE_KEYS: Record<NameSource, MessageKey> = {
  dns: "source.dns",
  mdns: "source.mdns",
  netbios: "source.netbios",
};

export function sourceLabel(source: NameSource): string {
  return t(SOURCE_KEYS[source]);
}

const STATUS_KEYS: Record<HostStatus, MessageKey> = {
  online: "status.online",
  offline: "status.offline",
  unused: "status.unused",
};

const ORIGIN_KEYS: Record<DataSource, MessageKey> = {
  live: "origin.live",
  dns: "origin.dns",
  arpCache: "origin.arpCache",
  remembered: "origin.remembered",
  imported: "origin.imported",
};

export function statusKey(host: HostResult): MessageKey {
  return STATUS_KEYS[host.status];
}

/** CSS class of the status dot: online (enriched), pending (lookups running), offline, unused. */
export function statusClass(host: HostResult): string {
  if (host.status !== "online") return host.status;
  return host.complete ? "online" : "pending";
}

export function originLabel(source: DataSource): string {
  return t(ORIGIN_KEYS[source]);
}

export function hostnameText(host: HostResult): string {
  if (host.hostname !== null) return host.hostname;
  return host.online && !host.complete ? t("host.pending") : "";
}

export function vendorText(host: HostResult): string {
  return host.macLocal ? t("vendor.local") : (host.vendor ?? "");
}

export function rttText(host: HostResult): string {
  if (host.rttMs === null) return "";
  return host.rttMs === 0 ? t("rtt.subMs") : t("rtt.ms", { ms: formatNumber(host.rttMs) });
}

/** Open ports shown in the table before "+N". */
const SHORT_PORT_LIST = 4;
/** Custom port lists are cut to this length in labels. */
const MAX_LIST_LABEL = 40;

/**
 * Open ports for the table: "22, 80, 443, 445 +3"; "0" after a port scan that found none;
 * "" if nothing is known. `…` marks a port scan of the host that is still running.
 */
export function openPortsText(host: HostResult, scanning: boolean): string {
  const ports = host.services.map((service) => String(service.port));
  let text = "";
  if (ports.length > 0) {
    const more = ports.length - SHORT_PORT_LIST;
    const shown = ports.slice(0, SHORT_PORT_LIST).join(", ");
    text = more > 0 ? `${shown} +${formatNumber(more)}` : shown;
  } else if (host.portScan) {
    text = formatNumber(0);
  }
  if (scanning && host.portScan && !host.portScan.complete) {
    text = text === "" ? "…" : `${text} …`;
  }
  return text;
}

/** "HTTP 200 · nginx · Router Login" */
export function httpText(http: HttpInfo): string {
  const parts = [http.status === null ? null : `HTTP ${http.status}`, http.server, http.title];
  return parts.filter((part): part is string => part !== null && part !== "").join(" · ");
}

/** What a service said about itself: its banner, otherwise its HTTP details. */
export function bannerText(service: ServiceInfo): string {
  if (service.banner !== null) return service.banner;
  return service.http ? httpText(service.http) : "";
}

const PORT_CHOICE_KEYS: Record<PortChoice, MessageKey> = {
  common: "ports.preset.common",
  top100: "ports.preset.top100",
  top1000: "ports.preset.top1000",
  all: "ports.preset.all",
  custom: "ports.preset.custom",
};

export function portChoiceLabel(choice: PortChoice): string {
  return t(PORT_CHOICE_KEYS[choice]);
}

export function selectionLabel(selection: PortSelection): string {
  if ("preset" in selection) return portChoiceLabel(selection.preset);
  const list = selection.custom;
  const short = list.length > MAX_LIST_LABEL ? `${list.slice(0, MAX_LIST_LABEL)}…` : list;
  return t("ports.customLabel", { list: short });
}

const PORT_STATE_KEYS: Record<PortState, MessageKey> = {
  open: "ports.state.open",
  closed: "ports.state.closed",
  filtered: "ports.state.filtered",
};

export function portStateLabel(state: PortState): string {
  return t(PORT_STATE_KEYS[state]);
}

/** First page title, otherwise the first `Server` header. */
export function webText(host: HostResult): string | null {
  const infos = host.services.flatMap((service) => (service.http ? [service.http] : []));
  const title = infos.find((info) => info.title !== null)?.title;
  return title ?? infos.find((info) => info.server !== null)?.server ?? null;
}

/** Standard port, unless only the alternative one (8080/8443) was found open. */
export function webPort(host: HostResult, secure: boolean): number {
  const open = new Set(host.services.map((service) => service.port));
  const [standard, alternative] = secure ? [443, 8443] : [80, 8080];
  return !open.has(standard) && open.has(alternative) ? alternative : standard;
}

/** Numeric key for IPv4 addresses; anything else sorts after them. */
export function ipSortKey(ip: string): number {
  const octets = ip.split(".");
  if (octets.length !== 4) return Number.MAX_SAFE_INTEGER;
  return octets.reduce((acc, octet) => acc * 256 + Number(octet), 0);
}
