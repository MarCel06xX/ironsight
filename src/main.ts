// Ironsight frontend entry: wires scan controls, results table, details panel, context
// menu and settings together. Scan results live in memory only.
import {
  type AppInfo,
  type HostResult,
  type ScanBatch,
  type ScanSummary,
  type Settings,
  getAppInfo,
  isCommandError,
  listAdapters,
  loadSettings,
  onScanBatch,
  onScanFinished,
  openFileShare,
  openInBrowser,
  openRemoteDesktop,
  saveSettings,
  startScan,
  stopScan,
  wakeOnLan,
} from "./api";
import { renderDetails } from "./details";
import { ExportDialog } from "./export";
import {
  hostnameText,
  rttText,
  servicesText,
  statusKey,
  vendorText,
  webPort,
  webText,
} from "./format";
import {
  type Language,
  type MessageKey,
  applyTranslations,
  detectLanguage,
  formatNumber,
  isMessageKey,
  onLanguageChange,
  setLanguage,
  t,
} from "./i18n";
import { ContextMenu, type MenuItem } from "./menu";
import { SettingsDialog } from "./settings";
import { HostStore, type SortKey } from "./store";
import { type Column, VirtualTable } from "./table";
import { applyTheme } from "./theme";
import { Toast } from "./toast";
import { UpdateDialog, findUpdate } from "./update";

const DEFAULT_SETTINGS: Settings = {
  theme: "dark",
  language: "system",
  concurrency: 64,
  timeoutMs: 1000,
  csvDelimiter: ";",
  checkUpdates: true,
  skippedVersion: null,
};
/** Delay before the background update check, so the window is shown first. */
const UPDATE_CHECK_DELAY_MS = 1500;
/** Minimum time between table refreshes while results stream in. */
const REFRESH_INTERVAL_MS = 200;
const FILTER_DELAY_MS = 120;

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
const settingsButton = byId<HTMLButtonElement>("settings-btn");
const exportButton = byId<HTMLButtonElement>("export-btn");
const errorBox = byId<HTMLParagraphElement>("error");
const filterInput = byId<HTMLInputElement>("filter");
const onlineOnlyBox = byId<HTMLInputElement>("only-online");
const shownCount = byId<HTMLSpanElement>("shown-count");
const detailsPanel = byId<HTMLElement>("details");

type ScanStatus = "ready" | "running" | "done" | "stopped";

const store = new HostStore();
const toast = new Toast(byId("toast"));
const menu = new ContextMenu(byId("context-menu"));
/** IPv4 addresses of this machine, to label its own row. */
const ownAddresses = new Set<string>();
const progress = { scanned: 0, total: 0, online: 0, status: "ready" as ScanStatus };

let settings: Settings = DEFAULT_SETTINGS;
let running = false;
let stopping = false;
/** Batches of scans up to this id are stale and ignored. */
let lastFinishedScanId = 0;
let selectedIp: string | null = null;
let detailsHost: HostResult | undefined;
let lastError: unknown = null;
let noAdapters = false;
let refreshTimer = 0;
let lastRefresh = 0;
let filterTimer = 0;

// --- table ---------------------------------------------------------------------------

function textColumn(key: SortKey, label: MessageKey, text: (host: HostResult) => string): Column {
  return {
    key,
    label,
    render: (cell, host) => {
      cell.textContent = text(host);
    },
  };
}

const columns: Column[] = [
  {
    key: "status",
    label: "col.status",
    render: (cell, host) => {
      const dot = document.createElement("span");
      dot.className = `dot ${!host.online ? "offline" : host.complete ? "online" : "pending"}`;
      cell.append(dot, document.createTextNode(t(statusKey(host))));
    },
  },
  textColumn("ip", "col.ip", (host) => host.ip),
  textColumn("hostname", "col.hostname", hostnameText),
  textColumn("mac", "col.mac", (host) => host.mac ?? ""),
  textColumn("vendor", "col.vendor", vendorText),
  textColumn("rtt", "col.rtt", rttText),
  textColumn("services", "col.services", servicesText),
  textColumn("web", "col.web", (host) => webText(host) ?? ""),
  textColumn("workgroup", "col.workgroup", (host) => host.workgroup ?? ""),
];

const table = new VirtualTable(byId("table"), columns, {
  select: selectHost,
  contextMenu: openHostMenu,
  sort: (key) => {
    store.setSort(key);
    table.setSort(store.sortKey, store.ascending);
    refreshView();
  },
});

function emptyText(): string {
  if (store.total > 0) return t("table.noMatches");
  return running ? t("table.scanning") : t("table.empty");
}

function refreshView(): void {
  window.clearTimeout(refreshTimer);
  refreshTimer = 0;
  lastRefresh = performance.now();
  const rows = store.rows();
  table.setRows(rows, emptyText());
  shownCount.textContent = t("filter.count", {
    shown: formatNumber(rows.length),
    total: formatNumber(store.total),
  });
  exportButton.disabled = running || store.total === 0;
  updateDetails(false);
}

/** Coalesces refreshes while batches stream in (sorting 65k rows is not free). */
function scheduleRefresh(): void {
  if (refreshTimer !== 0) return;
  const wait = Math.max(0, lastRefresh + REFRESH_INTERVAL_MS - performance.now());
  refreshTimer = window.setTimeout(refreshView, wait);
}

function selectHost(ip: string | null): void {
  selectedIp = ip;
  table.setSelected(ip);
  updateDetails(true);
}

/** Re-renders the panel when the selected host changed or got new data. */
function updateDetails(force: boolean): void {
  const host = selectedIp === null ? undefined : store.get(selectedIp);
  if (!force && host === detailsHost) return;
  detailsHost = host;
  renderDetails(detailsPanel, host, host !== undefined && ownAddresses.has(host.ip));
}

// --- errors and feedback ---------------------------------------------------------------

function formatDetail(detail: string | null): string {
  if (detail === null) return "";
  return /^\d+$/.test(detail) ? formatNumber(Number(detail)) : detail;
}

/** Localized text for a backend error, falling back to its English message. */
function errorText(error: unknown): string {
  if (isCommandError(error)) {
    const key = `error.${error.code}`;
    if (isMessageKey(key)) return t(key, { detail: formatDetail(error.detail ?? null) });
    return error.message;
  }
  return String(error);
}

function showError(error: unknown): void {
  lastError = error;
  renderError();
}

function renderError(): void {
  errorBox.hidden = lastError === null;
  errorBox.textContent = lastError === null ? "" : errorText(lastError);
}

async function runAction(action: () => Promise<void>, success?: () => string): Promise<void> {
  try {
    await action();
    if (success) toast.show(success());
  } catch (error) {
    toast.show(errorText(error), "error");
  }
}

/** Fallback for webviews without the async clipboard API. */
function legacyCopy(text: string): boolean {
  const area = document.createElement("textarea");
  area.value = text;
  area.readOnly = true;
  area.className = "offscreen";
  document.body.append(area);
  area.select();
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    area.remove();
  }
}

async function copyText(text: string): Promise<void> {
  let copied: boolean;
  try {
    await navigator.clipboard.writeText(text);
    copied = true;
  } catch {
    copied = legacyCopy(text);
  }
  if (copied) toast.show(t("toast.copied", { value: text }));
  else toast.show(t("toast.copyFailed"), "error");
}

// --- context menu ------------------------------------------------------------------------

function openHostMenu(ip: string, x: number, y: number): void {
  const host = store.get(ip);
  if (!host) return;
  const mac = host.mac;
  const items: MenuItem[] = [
    { label: t("menu.copyIp"), run: () => copyText(host.ip) },
    { label: t("menu.copyMac"), disabled: mac === null, run: () => copyText(mac ?? "") },
    {
      label: t("menu.openHttp"),
      separatorBefore: true,
      run: () => runAction(() => openInBrowser(ip, false, webPort(host, false))),
    },
    {
      label: t("menu.openHttps"),
      run: () => runAction(() => openInBrowser(ip, true, webPort(host, true))),
    },
    { label: t("menu.rdp"), run: () => runAction(() => openRemoteDesktop(ip)) },
    { label: t("menu.share"), run: () => runAction(() => openFileShare(ip)) },
    {
      label: t("menu.wol"),
      separatorBefore: true,
      disabled: mac === null,
      run: () =>
        runAction(
          () => wakeOnLan(mac ?? "", ip),
          () => t("toast.wolSent", { mac: mac ?? "" }),
        ),
    },
  ];
  menu.open(items, x, y, t("menu.label"));
}

// --- scanning ------------------------------------------------------------------------------

function renderScanButton(): void {
  scanButton.textContent = t(running ? "scan.stop" : "scan.start");
  scanButton.disabled = stopping;
}

function setRunning(value: boolean): void {
  running = value;
  stopping = false;
  targetInput.disabled = value;
  adapterSelect.disabled = value;
  exportButton.disabled = value || store.total === 0;
  renderScanButton();
}

function renderProgress(): void {
  const { scanned, total, online, status } = progress;
  progressBar.max = Math.max(total, 1);
  progressBar.value = scanned;
  if (status === "ready") {
    progressText.textContent = t("scan.status.ready");
    return;
  }
  const counts = t("scan.progress", {
    scanned: formatNumber(scanned),
    total: formatNumber(total),
    online: formatNumber(online),
  });
  const prefix: Record<ScanStatus, MessageKey | null> = {
    ready: null,
    running: null,
    done: "scan.status.done",
    stopped: "scan.status.stopped",
  };
  const key = prefix[status];
  progressText.textContent = key ? `${t(key)} – ${counts}` : counts;
}

async function toggleScan(): Promise<void> {
  lastError = null;
  renderError();
  if (running) {
    stopping = true; // the button comes back with `scan:finished`
    renderScanButton();
    await stopScan().catch(showError);
    return;
  }
  store.clear();
  selectHost(null);
  Object.assign(progress, { scanned: 0, total: 0, online: 0, status: "running" });
  setRunning(true);
  renderProgress();
  refreshView();
  try {
    const started = await startScan({
      targets: targetInput.value,
      concurrency: settings.concurrency,
      timeoutMs: settings.timeoutMs,
    });
    // Batches may already have arrived; only fill in the total if none did.
    if (progress.total === 0) {
      progress.total = started.total;
      renderProgress();
    }
  } catch (error) {
    setRunning(false);
    progress.status = "ready";
    renderProgress();
    refreshView();
    showError(error);
  }
}

function handleBatch(batch: ScanBatch): void {
  if (batch.scanId <= lastFinishedScanId) return;
  store.upsert(batch.hosts);
  Object.assign(progress, { scanned: batch.scanned, total: batch.total, online: batch.online });
  renderProgress();
  scheduleRefresh();
}

function handleFinished(summary: ScanSummary): void {
  lastFinishedScanId = Math.max(lastFinishedScanId, summary.scanId);
  store.completeAll();
  Object.assign(progress, {
    scanned: summary.scanned,
    total: summary.total,
    online: summary.online,
    status: summary.cancelled ? "stopped" : "done",
  });
  setRunning(false);
  renderProgress();
  refreshView();
}

// --- adapters, settings, language --------------------------------------------------------

function renderAdapterPlaceholder(): void {
  const option = adapterSelect.options[0];
  if (noAdapters && option) option.textContent = t("adapter.none");
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
  noAdapters = adapterSelect.options.length === 0;
  if (noAdapters) {
    const option = document.createElement("option");
    option.value = "";
    adapterSelect.append(option);
    renderAdapterPlaceholder();
  }
  if (targetInput.value === "") targetInput.value = adapterSelect.value;
}

function resolveLanguage(setting: Settings["language"]): Language {
  return setting === "system" ? detectLanguage(navigator.language) : setting;
}

function applySettings(next: Settings): void {
  settings = next;
  applyTheme(next.theme);
  setLanguage(resolveLanguage(next.language));
}

onLanguageChange(() => {
  menu.close(false);
  store.refreshLocale();
  table.invalidate();
  renderScanButton();
  renderProgress();
  renderError();
  renderAdapterPlaceholder();
  refreshView();
  updateDetails(true);
});

let appInfo: AppInfo = { version: "", portable: false };
let updateDialog: UpdateDialog | null = null;
let settingsDialog: SettingsDialog | null = null;

function skipVersion(version: string): void {
  settings = { ...settings, skippedVersion: version };
  saveSettings(settings).catch((error: unknown) => console.warn("saving settings failed", error));
}

/** Manual check from the settings dialog; errors are shown there. */
async function checkForUpdateNow(): Promise<string> {
  const update = await findUpdate();
  if (!update) return t("update.upToDate", { version: appInfo.version });
  updateDialog?.show(update);
  return "";
}

/** Background check on startup: silent on errors and for a skipped version. */
async function startupUpdateCheck(): Promise<void> {
  if (!settings.checkUpdates) return;
  try {
    const update = await findUpdate();
    if (!update) {
      console.info("update check: up to date");
    } else if (update.version === settings.skippedVersion) {
      console.info(`update check: ${update.version} is skipped`);
    } else {
      updateDialog?.show(update);
    }
  } catch (error) {
    console.warn("update check failed", error);
  }
}

const exportDialog = new ExportDialog(
  byId("export-dialog"),
  (path, delimiter) => {
    toast.show(t("export.done", { path }));
    // Remember the CSV delimiter for next time.
    if (delimiter !== null && delimiter !== settings.csvDelimiter) {
      settings = { ...settings, csvDelimiter: delimiter };
      saveSettings(settings).catch((error: unknown) => toast.show(errorText(error), "error"));
    }
  },
  (error) => toast.show(errorText(error), "error"),
);

function wireEvents(): void {
  adapterSelect.addEventListener("change", () => {
    if (adapterSelect.value !== "") targetInput.value = adapterSelect.value;
  });
  scanButton.addEventListener("click", () => void toggleScan());
  targetInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !running) void toggleScan();
  });
  settingsButton.addEventListener("click", () => settingsDialog?.open(settings));
  exportButton.addEventListener("click", () =>
    exportDialog.open({
      allCount: store.total,
      viewIps: store.rows().map((host) => host.ip),
      delimiter: settings.csvDelimiter,
    }),
  );
  filterInput.addEventListener("input", () => {
    window.clearTimeout(filterTimer);
    filterTimer = window.setTimeout(() => {
      store.setFilter(filterInput.value);
      refreshView();
    }, FILTER_DELAY_MS);
  });
  onlineOnlyBox.addEventListener("change", () => {
    store.setOnlineOnly(onlineOnlyBox.checked);
    refreshView();
  });
  // No browser context menu outside text fields; Ctrl+F jumps to the filter.
  document.addEventListener("contextmenu", (event) => {
    if (!(event.target instanceof Element && event.target.closest("input, textarea"))) {
      event.preventDefault();
    }
  });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
      event.preventDefault();
      filterInput.focus();
      filterInput.select();
    }
  });
}

async function init(): Promise<void> {
  settings = await loadSettings().catch(() => DEFAULT_SETTINGS);
  applyTheme(settings.theme);
  setLanguage(resolveLanguage(settings.language));
  applyTranslations(document);
  setRunning(false);
  renderProgress();
  table.setSort(store.sortKey, store.ascending);
  refreshView();
  updateDetails(true);

  appInfo = await getAppInfo();
  settingsDialog = new SettingsDialog(
    byId("settings-dialog"),
    applySettings,
    errorText,
    appInfo,
    checkForUpdateNow,
  );
  updateDialog = new UpdateDialog(byId("update-dialog"), appInfo, {
    isScanning: () => running,
    stopScan,
    skip: skipVersion,
    describeError: errorText,
  });
  wireEvents();

  await onScanBatch(handleBatch);
  await onScanFinished(handleFinished);
  await loadAdapters();
  window.setTimeout(() => void startupUpdateCheck(), UPDATE_CHECK_DELAY_MS);
}

init().catch(showError);
