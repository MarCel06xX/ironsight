// In-memory scan results with filtered + sorted view. Nothing here is ever persisted.
import type { HostResult, HostStatus } from "./api";
import { ipSortKey, webText } from "./format";
import { currentLanguage } from "./i18n";

export type SortKey =
  | "status"
  | "ip"
  | "hostname"
  | "mac"
  | "vendor"
  | "rtt"
  | "ports"
  | "web"
  | "workgroup"
  | "lastSeen";

interface Entry {
  host: HostResult;
  ipKey: number;
  /** Lower-cased text the filter matches against. */
  search: string;
  /** Open ports, for `port:22` filters. */
  ports: ReadonlySet<number>;
}

/** Filter input split into `port:N` conditions and the remaining text. */
interface Filter {
  text: string;
  ports: number[];
  /** A `port:` condition that is not a port number: nothing matches. */
  invalid: boolean;
}

const PORT_TERM = /(^|\s)port:(\S*)/gi;

/** `port:22 port:80 ssh` -> hosts with 22 and 80 open whose text contains "ssh". */
export function parseFilter(input: string): Filter {
  const ports: number[] = [];
  let invalid = false;
  const text = input
    .replace(PORT_TERM, (_match, before: string, value: string) => {
      const port = /^\d{1,5}$/.test(value) ? Number(value) : 0;
      if (port >= 1 && port <= 65_535) ports.push(port);
      else invalid = true;
      return before;
    })
    // "a port:22 b" leaves two spaces behind.
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
  return { text, ports, invalid };
}

type Compare = (a: Entry, b: Entry) => number;

function searchText(host: HostResult): string {
  const parts: (string | null)[] = [
    host.ip,
    host.hostname,
    host.names.dns,
    host.names.mdns,
    host.names.netbios,
    host.mac,
    host.mac?.replaceAll(":", "") ?? null,
    host.vendor,
    host.workgroup,
  ];
  for (const service of host.services) {
    parts.push(String(service.port), service.name, service.http?.server ?? null);
    parts.push(service.http?.title ?? null, service.banner);
  }
  return parts
    .filter((part): part is string => part !== null && part !== "")
    .join("\n")
    .toLowerCase();
}

function statusRank(host: HostResult): number {
  if (host.status === "online") return host.complete ? 0 : 1;
  return host.status === "offline" ? 2 : 3;
}

function makeCollator(): Intl.Collator {
  return new Intl.Collator(currentLanguage(), { numeric: true, sensitivity: "base" });
}

export class HostStore {
  private readonly entries = new Map<string, Entry>();
  private view: HostResult[] | null = null;
  private collator = makeCollator();
  private filterInput = "";
  private filter: Filter = { text: "", ports: [], invalid: false };
  /** Statuses shown in the table; unused addresses are hidden by default. */
  private readonly visible = new Set<HostStatus>(["online", "offline"]);
  private readonly counts: Record<HostStatus, number> = { online: 0, offline: 0, unused: 0 };
  sortKey: SortKey = "ip";
  ascending = true;

  get total(): number {
    return this.entries.size;
  }

  get(ip: string): HostResult | undefined {
    return this.entries.get(ip)?.host;
  }

  /** Scanned addresses per status. */
  count(status: HostStatus): number {
    return this.counts[status];
  }

  upsert(hosts: readonly HostResult[]): void {
    for (const host of hosts) {
      const previous = this.entries.get(host.ip);
      if (previous) this.counts[previous.host.status] -= 1;
      this.counts[host.status] += 1;
      this.entries.set(host.ip, {
        host,
        ipKey: ipSortKey(host.ip),
        search: searchText(host),
        ports: new Set(host.services.map((service) => service.port)),
      });
    }
    if (hosts.length > 0) this.view = null;
  }

  clear(): void {
    this.entries.clear();
    this.counts.online = 0;
    this.counts.offline = 0;
    this.counts.unused = 0;
    this.view = null;
  }

  /** After a stopped scan: hosts whose lookups were cut short are final as they are. */
  completeAll(): void {
    for (const [ip, entry] of this.entries) {
      if (!entry.host.complete) {
        this.entries.set(ip, { ...entry, host: { ...entry.host, complete: true } });
        this.view = null;
      }
    }
  }

  /** Same column again flips the direction. */
  setSort(key: SortKey): void {
    this.ascending = key === this.sortKey ? !this.ascending : true;
    this.sortKey = key;
    this.view = null;
  }

  setFilter(text: string): void {
    const input = text.trim().toLowerCase();
    if (input !== this.filterInput) {
      this.filterInput = input;
      this.filter = parseFilter(input);
      this.view = null;
    }
  }

  isVisible(status: HostStatus): boolean {
    return this.visible.has(status);
  }

  setVisible(status: HostStatus, shown: boolean): void {
    if (shown === this.visible.has(status)) return;
    if (shown) this.visible.add(status);
    else this.visible.delete(status);
    this.view = null;
  }

  /** Text sorting follows the UI language. */
  refreshLocale(): void {
    this.collator = makeCollator();
    this.view = null;
  }

  /** Filtered and sorted hosts; cached until something changes. */
  rows(): HostResult[] {
    this.view ??= this.compute();
    return this.view;
  }

  private compute(): HostResult[] {
    const matches: Entry[] = [];
    const { text, ports, invalid } = this.filter;
    if (invalid) return [];
    for (const entry of this.entries.values()) {
      if (!this.visible.has(entry.host.status)) continue;
      if (text !== "" && !entry.search.includes(text)) continue;
      if (!ports.every((port) => entry.ports.has(port))) continue;
      matches.push(entry);
    }
    matches.sort(this.comparator());
    return matches.map((entry) => entry.host);
  }

  private comparator(): Compare {
    const direction = this.ascending ? 1 : -1;
    const byIp: Compare = (a, b) =>
      a.ipKey - b.ipKey || (a.host.ip < b.host.ip ? -1 : a.host.ip > b.host.ip ? 1 : 0);
    // Empty values always go last, whatever the direction.
    const byText =
      (get: (host: HostResult) => string | null): Compare =>
      (a, b) => {
        const x = get(a.host) ?? "";
        const y = get(b.host) ?? "";
        if (x === "" || y === "") return x === y ? byIp(a, b) : x === "" ? 1 : -1;
        return direction * this.collator.compare(x, y) || byIp(a, b);
      };
    const byNumber =
      (get: (host: HostResult) => number | null): Compare =>
      (a, b) => {
        const x = get(a.host);
        const y = get(b.host);
        if (x === null || y === null) return x === y ? byIp(a, b) : x === null ? 1 : -1;
        return direction * (x - y) || byIp(a, b);
      };

    switch (this.sortKey) {
      case "ip":
        return (a, b) => direction * byIp(a, b);
      case "status":
        return (a, b) => direction * (statusRank(a.host) - statusRank(b.host)) || byIp(a, b);
      case "hostname":
        return byText((host) => host.hostname);
      case "mac":
        return byText((host) => host.mac);
      case "vendor":
        return byText((host) => host.vendor);
      case "rtt":
        return byNumber((host) => host.rttMs);
      case "ports":
        // Port-scanned hosts without open ports (0) sort before hosts that were not scanned.
        return byNumber((host) => host.services.length || (host.portScan ? 0 : null));
      case "web":
        return byText(webText);
      case "workgroup":
        return byText((host) => host.workgroup);
      case "lastSeen":
        return byNumber((host) => host.lastSeenMs);
    }
  }
}
