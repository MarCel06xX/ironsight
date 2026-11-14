// Details panel for the selected host. Built with DOM APIs only: most values are
// untrusted network data.
import type { HostResult, NameSource, ServiceInfo } from "./api";
import { rttText, sourceLabel, statusKey } from "./format";
import { type MessageKey, formatDateTime, t } from "./i18n";

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
  dot.className = `dot ${!host.online ? "offline" : host.complete ? "online" : "pending"}`;
  wrapper.append(dot, document.createTextNode(t(statusKey(host))));
  return wrapper;
}

function serviceNode(service: ServiceInfo): HTMLElement {
  const node = document.createElement("div");
  node.className = "service";
  node.append(el("div", `${service.port} ${service.name}`, "service-name"));
  const http = service.http;
  if (http) {
    if (http.status !== null) node.append(el("div", t("details.httpStatus", { status: http.status })));
    if (http.server !== null) node.append(el("div", t("details.server", { server: http.server })));
    if (http.title !== null) node.append(el("div", t("details.pageTitle", { title: http.title })));
  }
  return node;
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

  add("details.status", [statusNode(host)]);
  add("details.ip", [host.ip]);
  add(
    "details.names",
    NAME_SOURCES.flatMap((source) => {
      const name = host.names[source];
      return name ? [`${sourceLabel(source)}: ${name}`] : [];
    }),
  );
  if (host.mac !== null) {
    const note = host.macLocal ? [el("div", t("details.macLocal"), "note")] : [];
    add("details.mac", [host.mac, ...note]);
  }
  if (host.vendor !== null) add("details.vendor", [host.vendor]);
  if (host.rttMs !== null) add("details.rtt", [rttText(host)]);
  if (host.workgroup !== null) add("details.workgroup", [host.workgroup]);

  const seenBy: string[] = [];
  if (isOwn) seenBy.push(t("seenBy.self"));
  if (host.seenBy.arp) seenBy.push(t("seenBy.arp"));
  if (host.seenBy.icmp) seenBy.push(t("seenBy.icmp"));
  if (host.seenBy.tcp) seenBy.push(t("seenBy.tcp"));
  if (seenBy.length > 0) add("details.seenBy", [seenBy.join(", ")]);

  if (host.online) {
    const services = host.services.map(serviceNode);
    add("details.services", services.length > 0 ? services : [t("details.noServices")]);
  }
  if (host.timestampMs > 0) add("details.lastSeen", [formatDateTime(host.timestampMs)]);
  panel.append(list);
}
