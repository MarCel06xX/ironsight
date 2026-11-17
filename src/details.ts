// Details panel for the selected host. Built with DOM APIs only: most values are
// untrusted network data.
import type { DataSource, HostResult, NameSource, PortState } from "./api";
import {
  bannerText,
  originLabel,
  portStateLabel,
  rttText,
  selectionLabel,
  sourceLabel,
  statusClass,
  statusKey,
} from "./format";
import { type MessageKey, formatDateTime, formatNumber, formatRelative, t } from "./i18n";

const NAME_SOURCES: readonly NameSource[] = ["dns", "mdns", "netbios"];

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text: string,
  className?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}

function statusNode(host: HostResult): HTMLElement {
  const wrapper = document.createElement("span");
  const dot = document.createElement("span");
  dot.className = `dot ${statusClass(host)}`;
  wrapper.append(dot, document.createTextNode(t(statusKey(host))));
  return wrapper;
}

/** "Source: ARP cache" for data that did not come from the device just now. */
function sourceNotes(source: DataSource | null): HTMLElement[] {
  if (source === null || source === "live") return [];
  return [el("div", t("details.fieldSource", { source: originLabel(source) }), "note")];
}

interface PortRow {
  port: number;
  name: string;
  state: PortState;
  banner: string;
}

const PORT_COLUMNS: readonly [string, MessageKey][] = [
  ["col-port", "ports.colPort"],
  ["col-service", "ports.colService"],
  ["col-state", "ports.colState"],
  ["col-banner", "ports.colBanner"],
];

function portTable(rows: readonly PortRow[]): HTMLTableElement {
  const table = document.createElement("table");
  table.className = "port-table";
  const columns = document.createElement("colgroup");
  const head = document.createElement("tr");
  for (const [className, label] of PORT_COLUMNS) {
    const col = document.createElement("col");
    col.className = className;
    columns.append(col);
    head.append(el("th", t(label)));
  }
  const thead = document.createElement("thead");
  thead.append(head);
  const tbody = document.createElement("tbody");
  for (const row of rows) {
    const tr = document.createElement("tr");
    const state = el("span", portStateLabel(row.state), `state-${row.state}`);
    const stateCell = document.createElement("td");
    stateCell.append(state);
    tr.append(
      el("td", String(row.port), "port"),
      el("td", row.name === "unknown" ? "" : row.name),
      stateCell,
      el("td", row.banner),
    );
    tbody.append(tr);
  }
  table.append(columns, thead, tbody);
  return table;
}

/** Open ports (with banners) plus the closed/filtered ports a port scan listed. */
function portsSection(host: HostResult): HTMLElement[] {
  const scan = host.portScan;
  if (host.services.length === 0 && !scan && !host.online) return [];
  const nodes: HTMLElement[] = [el("h3", t("details.ports"))];
  const note = (text: string): void => {
    nodes.push(el("div", text, "note"));
  };
  if (scan) {
    note(t("details.portScan", { selection: selectionLabel(scan.selection) }));
    note(
      t("details.portScanCounts", {
        probed: formatNumber(scan.probed),
        total: formatNumber(scan.total),
        open: formatNumber(scan.open),
        closed: formatNumber(scan.closed),
        filtered: formatNumber(scan.filtered),
      }),
    );
    if (!scan.complete) note(t("details.portScanIncomplete"));
    if (scan.errors > 0) note(t("details.portScanErrors", { errors: formatNumber(scan.errors) }));
  } else if (host.services.length > 0) {
    note(t("details.discoveryPorts"));
  }

  const rows: PortRow[] = [
    ...host.services.map((service) => ({
      port: service.port,
      name: service.name,
      state: "open" as const,
      banner: bannerText(service),
    })),
    ...(scan?.listed ?? []).map((listed) => ({ ...listed, banner: "" })),
  ].sort((a, b) => a.port - b.port);

  if (rows.length > 0) {
    nodes.push(portTable(rows));
  } else {
    nodes.push(el("p", t(scan ? "details.noOpenPorts" : "details.noServices"), "muted"));
  }
  if (scan) {
    const shown = (state: PortState): number => rows.filter((row) => row.state === state).length;
    const hidden: [number, MessageKey][] = [
      [scan.open - shown("open"), "details.moreOpen"],
      [scan.closed - shown("closed"), "details.closedNotListed"],
      [scan.filtered - shown("filtered"), "details.filteredNotListed"],
    ];
    for (const [count, key] of hidden) {
      if (count > 0) note(t(key, { count: formatNumber(count) }));
    }
  }
  nodes.push(...sourceNotes(host.sources.services));
  return nodes;
}

export function renderDetails(panel: HTMLElement, host: HostResult | undefined, isOwn: boolean): void {
  panel.replaceChildren(el("h2", t("details.title")));
  if (!host) {
    panel.append(el("p", t("details.empty"), "muted"));
    return;
  }

  panel.append(el("p", host.hostname ?? host.ip, "details-name"));
  if (host.online && !host.complete) {
    panel.append(el("p", t("details.lookupsPending"), "muted"));
  }

  const list = document.createElement("dl");
  const add = (label: MessageKey, values: readonly (string | Node)[]): void => {
    if (values.length === 0) return;
    const dd = document.createElement("dd");
    for (const value of values) dd.append(typeof value === "string" ? el("div", value) : value);
    list.append(el("dt", t(label)), dd);
  };
  const sources = host.sources;

  add("details.status", [statusNode(host)]);
  add("details.ip", [host.ip]);
  if (host.lastSeenMs !== null) {
    const seen = host.lastSeenMs;
    add("details.lastOnline", [`${formatDateTime(seen)} (${formatRelative(seen)})`]);
  } else if (!host.online) {
    add("details.lastOnline", [t("details.neverOnline")]);
  }
  const names = NAME_SOURCES.flatMap((source) => {
    const name = host.names[source];
    return name ? [`${sourceLabel(source)}: ${name}`] : [];
  });
  if (names.length > 0) add("details.names", [...names, ...sourceNotes(sources.hostname)]);
  if (host.mac !== null) {
    const note = host.macLocal ? [el("div", t("details.macLocal"), "note")] : [];
    add("details.mac", [host.mac, ...note, ...sourceNotes(sources.mac)]);
  }
  if (host.vendor !== null) add("details.vendor", [host.vendor, ...sourceNotes(sources.vendor)]);
  if (host.rttMs !== null) add("details.rtt", [rttText(host)]);
  if (host.workgroup !== null) {
    add("details.workgroup", [host.workgroup, ...sourceNotes(sources.workgroup)]);
  }

  const seenBy: string[] = [];
  if (isOwn) seenBy.push(t("seenBy.self"));
  if (host.seenBy.arp) seenBy.push(t("seenBy.arp"));
  if (host.seenBy.icmp) seenBy.push(t("seenBy.icmp"));
  if (host.seenBy.tcp) seenBy.push(t("seenBy.tcp"));
  if (seenBy.length > 0) add("details.seenBy", [seenBy.join(", ")]);

  if (host.timestampMs > 0) add("details.lastSeen", [formatDateTime(host.timestampMs)]);
  panel.append(list, ...portsSection(host));
}
