// Display helpers shared by the table, the details panel, sorting and filtering.
import type { DataSource, HostResult, HostStatus, NameSource } from "./api";
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

export function servicesText(host: HostResult): string {
  return host.services.map((service) => `${service.port} ${service.name}`).join(", ");
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
