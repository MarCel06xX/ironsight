// Phase 1 UI: just enough to drive and verify the backend. The real table (virtual
// scrolling, sorting, filter, details) replaces the simple one below in phase 3.
import {
  type HostResult,
  type ScanBatch,
  type ScanSummary,
  isCommandError,
  listAdapters,
  onScanBatch,
  onScanFinished,
  startScan,
  stopScan,
} from "./api";
import { type MessageKey, applyTranslations, t } from "./i18n";

function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
}

const adapterSelect = byId<HTMLSelectElement>("adapter");
const targetInput = byId<HTMLInputElement>("targets");
const scanButton = byId<HTMLButtonElement>("scan-btn");
const progressBar = byId<HTMLProgressElement>("progress");
const progressText = byId<HTMLSpanElement>("progress-text");
const errorBox = byId<HTMLParagraphElement>("error");
const rows = byId<HTMLTableSectionElement>("rows");

let running = false;
/** Numeric IPs of the rendered rows, ascending and parallel to `rows.children`. */
let rowKeys: number[] = [];
const rowByIp = new Map<string, HTMLTableRowElement>();
/** IPv4 addresses of this machine, to label its own row. */
const ownAddresses = new Set<string>();

function ipToNumber(ip: string): number {
  return ip.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
}

function showError(error: unknown): void {
  // Backend messages are English for now; `code` gets localized in phase 3.
  errorBox.textContent = isCommandError(error) ? error.message : String(error);
  errorBox.hidden = false;
}

function setRunning(value: boolean): void {
  running = value;
  scanButton.textContent = t(value ? "scan.stop" : "scan.start");
  scanButton.disabled = false;
  targetInput.disabled = value;
  adapterSelect.disabled = value;
}

function setProgress(scanned: number, total: number, online: number, status?: MessageKey): void {
  progressBar.max = Math.max(total, 1);
  progressBar.value = scanned;
  const counts = t("scan.progress", { scanned, total, online });
  progressText.textContent = status ? `${t(status)} – ${counts}` : counts;
}

function addCell(row: HTMLTableRowElement, text: string): void {
  // textContent only: everything shown here ultimately comes from the network.
  row.insertCell().textContent = text;
}

function renderRow(row: HTMLTableRowElement, host: HostResult): void {
  row.replaceChildren();
  const via: string[] = [];
  if (ownAddresses.has(host.ip)) via.push(t("seenBy.self"));
  if (host.seenBy.arp) via.push(t("seenBy.arp"));
  if (host.seenBy.icmp) via.push(t("seenBy.icmp"));
  let rtt = "";
  if (host.rttMs !== null) {
    rtt = host.rttMs === 0 ? t("rtt.subMs") : t("rtt.ms", { ms: host.rttMs });
  }
  addCell(row, host.ip);
  addCell(row, host.mac ?? "");
  addCell(row, rtt);
  addCell(row, via.join(", "));
}

/** Inserts or updates an online host, keeping rows sorted by numeric IP. */
function upsertHost(host: HostResult): void {
  const existing = rowByIp.get(host.ip);
  if (existing) {
    renderRow(existing, host);
    return;
  }
  const key = ipToNumber(host.ip);
  let lo = 0;
  let hi = rowKeys.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if ((rowKeys[mid] ?? Infinity) < key) lo = mid + 1;
    else hi = mid;
  }
  const row = document.createElement("tr");
  renderRow(row, host);
  rows.insertBefore(row, rows.children[lo] ?? null);
  rowKeys.splice(lo, 0, key);
  rowByIp.set(host.ip, row);
}

function clearResults(): void {
  rows.replaceChildren();
  rowKeys = [];
  rowByIp.clear();
}

function handleBatch(batch: ScanBatch): void {
  for (const host of batch.hosts) {
    if (host.online) upsertHost(host);
  }
  setProgress(batch.scanned, batch.total, batch.online);
}

function handleFinished(summary: ScanSummary): void {
  setRunning(false);
  setProgress(
    summary.scanned,
    summary.total,
    summary.online,
    summary.cancelled ? "scan.status.stopped" : "scan.status.done",
  );
}

async function toggleScan(): Promise<void> {
  errorBox.hidden = true;
  if (running) {
    scanButton.disabled = true; // re-enabled by the `scan:finished` event
    await stopScan().catch(showError);
    return;
  }
  clearResults();
  setRunning(true);
  progressBar.value = 0;
  progressText.textContent = "";
  try {
    const started = await startScan({ targets: targetInput.value });
    // Batches may already have arrived; only fill in the total if none did.
    if (progressBar.value === 0) setProgress(0, started.total, 0);
  } catch (error) {
    setRunning(false);
    showError(error);
  }
}

async function loadAdapters(): Promise<void> {
  const adapters = await listAdapters();
  adapterSelect.replaceChildren();
  ownAddresses.clear();
  for (const adapter of adapters) {
    for (const net of adapter.ipv4) {
      ownAddresses.add(net.addr);
      const option = document.createElement("option");
      option.value = net.scanTarget;
      option.textContent = `${adapter.name} – ${net.addr}/${net.prefixLen}`;
      adapterSelect.append(option);
    }
  }
  if (adapterSelect.options.length === 0) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = t("adapter.none");
    adapterSelect.append(option);
  }
  if (targetInput.value === "") targetInput.value = adapterSelect.value;
}

async function init(): Promise<void> {
  applyTranslations(document);
  setRunning(false);
  progressText.textContent = t("scan.status.ready");

  adapterSelect.addEventListener("change", () => {
    if (adapterSelect.value !== "") targetInput.value = adapterSelect.value;
  });
  scanButton.addEventListener("click", () => void toggleScan());
  targetInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !running) void toggleScan();
  });

  await onScanBatch(handleBatch);
  await onScanFinished(handleFinished);
  await loadAdapters();
}

init().catch(showError);
