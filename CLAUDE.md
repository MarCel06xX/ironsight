# Ironsight – session notes

Desktop network scanner (Rust + Tauri 2, vanilla TS). v1 = host discovery + device info + export,
Windows only. Port scanning / packet capture / Linux come later – keep platform code behind
`NetBackend`.

## Current phase

**v0.2.0 released** (offline devices, known devices, three states). Released: v0.1.0-v0.1.3, v0.2.0;
the updater was tested end to end (0.1.2 -> 0.1.3). Releases only after the user's OK.

**In progress: TCP port scanner, to be released as v0.4.0** (user's version number), in 5 phases;
commit + push after each phase, then stop and wait for the user's go.
- Phase 1 (backend engine) **done**: `ports/` module, see "Port scanning" below.
- Phase 2 (banners + pipeline) **done**: port step after discovery, `scan_host_ports`,
  `ports:*` events, merged discovery check.
- Phase 3 (UI) **done**: see "Port scan UI" below.
- Next: phase 4 export/import (`schema_version` 3, fixtures for 1 and 2; CSV/JSON/HTML get port
  state, service, banner), phase 5 README/CHANGELOG/version bump (do NOT run
  `scripts/release.ps1`).

Ideas: screenshots in `docs/`, code signing, HTTPS titles (needs a TLS crate - ask), packet
capture, Linux backend.

## Rules

- Allowed crates: `tauri`, `tauri-build`, `tauri-plugin-dialog`, `tauri-plugin-opener`, `serde`,
  `serde_json`, `tokio`, `windows`, `thiserror`. Anything else: ask first (one-line justification).
  HTTPS title grabbing needs a TLS crate → ask before adding.
- Frontend: vanilla TS strict, no UI/CSS framework. No hard-coded UI strings (i18n: `locales/en.json`,
  `locales/de.json`). Never insert scanned strings as HTML (`textContent` only).
- Never print or read the raw IEEE OUI CSV into context (several MB). Converter script produces a
  compact file embedded with `include_bytes!`; no runtime downloads.
- Launch processes (mstsc, explorer, browser) only from Rust with a validated `IpAddr`.
- Scan results are never persisted automatically; only settings go to the app config dir.
- The user tests the GUI themselves (`npm run tauri dev`). Don't try to view the window.
- Prefer `cargo check` / `cargo test`; `npm run tauri build` only in phase 5.
- Don't install global tools or change the git identity.

## Key decisions

- Repo root = this folder; GitHub `MarCel06xX/ironsight` (public), dual MIT OR Apache-2.0.
- GitHub blocks pushes exposing the private email: this repo has a *local* `user.email`
  (`199737179+MarCel06xX@users.noreply.github.com`). A fresh clone needs the same local setting.
- Tauri identifier `io.github.marcel06xx.ironsight` (login lowercased, reverse-DNS convention).
- `withGlobalTauri: false`; strict CSP in `tauri.conf.json` (`devCsp` relaxed only for Vite HMR).
  No inline styles/scripts – themes via `<html data-theme>` + CSS custom properties.
- Capability `default`: only `core:event:allow-listen/unlisten` plus the app's own commands. No
  shell plugin. `tauri-plugin-opener` is used only through its free function
  `tauri_plugin_opener::open_url` from Rust - the plugin is *not* registered, so the webview has
  no opener API at all. Do the same with the dialog plugin if possible (phase 4).
- Settings (`settings.rs`): `%APPDATA%\io.github.marcel06xx.ironsight\settings.json`, `{theme,
  language, concurrency, timeoutMs}`; missing/corrupt file -> defaults, out-of-range numbers reset
  per field, atomic write via `.tmp` + rename, 64 KiB read limit. Validated again on save.
- Lib crate has no mobile crate-types (desktop only). Bundle target: NSIS only.
- Data types use `IpAddr` (IPv4 only in v1, IPv6 not blocked by design).
- Online = ARP answers OR ICMP answers OR any TCP probe connects.
- App icon source: `app-icon.svg` (self-made). Regenerate with `npx tauri icon app-icon.svg`,
  then delete `src-tauri/icons/android` and `src-tauri/icons/ios` (desktop only).

## Releasing

Bump the version in `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml` (+ `Cargo.lock` via
`cargo check`) and `package.json` (`npm version X.Y.Z --no-git-tag-version`), commit, push, then
run `.\scripts\release.ps1` (`-NoPublish` = build into `release/` only). It builds the portable
exe, then the NSIS installer + `.sig` (signing key `%USERPROFILE%\.tauri\ironsight.key`, empty
password; the script only passes the path - never read/print/commit the private key), writes
`SHA256SUMS.txt` and `latest.json`, tags `vX.Y.Z` and creates a normal (latest) GitHub release.
New key only via `npx tauri signer generate --ci --force -w "$env:USERPROFILE\.tauri\ironsight.key"`:
the interactive prompt stored a non-empty password once (signing then fails with "Wrong password").
A new key needs the new `.pub` content in `plugins.updater.pubkey` - and installed apps with the old key
can no longer update.

## Portable build and updater

- Cargo feature `portable` (`npm run tauri build -- --no-bundle --features portable`): settings in
  `ironsight-settings.json`, WebView2 profile in `ironsight-webview\` next to the exe; AppData if
  the exe folder is not writable (`portable.rs`). The window is created in `lib.rs` setup via
  `WebviewWindowBuilder::from_config` + `data_directory` (config window has `create: false`).
  Installed build: settings `%APPDATA%\<id>\`, WebView2 `%LOCALAPPDATA%\<id>\EBWebView`.
- Updater: `tauri-plugin-updater` + `tauri-plugin-process`, used from the webview (`src/update.ts`;
  capabilities `updater:default`, `process:allow-restart`). Endpoint
  `https://github.com/MarCel06xX/ironsight/releases/latest/download/latest.json`, install mode
  `passive`, `requireSignedVersion: true` (CLI writes `version:` into the .sig trusted comment),
  `plugins.updater.pubkey` = content of `ironsight.key.pub`. Startup check 1.5 s after
  launch, 8 s timeout, silent on errors; settings `checkUpdates` / `skippedVersion`. Portable
  build (`app_info().portable`) only opens the release page (`open_release_page`).

## Backend design (phase 1)

- `scan/range.rs`: `TargetSet` = merged inclusive `u32` ranges; CIDR /16-/32 (network/broadcast
  skipped up to /30), `a.b.c.d-e[.f[.g]]` suffix ranges, full ranges, comma lists; max 65,536 hosts.
- `platform/`: sync, blocking `NetBackend` trait (`list_adapters`, `arp_resolve`, `icmp_ping`);
  `windows.rs` = IP Helper (`GetAdaptersAddresses`, `SendARP`, `IcmpSendEcho`), `windows` crate 0.62
  (same version Tauri pulls in). `unsupported.rs` keeps other OSes compiling.
- `scan/engine.rs`: `run_scan(backend, probes, targets, config, cancel: watch::Receiver<bool>, id,
  on_batch)`; Tauri-free, tested with `MockBackend` + `MockProbes`. Host slots = concurrency
  semaphore (held through enrichment). ARP only for on-link targets (own address: no ARP, MAC from
  adapter). SendARP blocks ~1-3 s and cannot be aborted: the first report comes after `timeout`,
  the still-running ARP call is awaited afterwards (adds the MAC, or revives a host first reported
  offline). Stop drops all pending lookups via `tokio::select!` on the watch channel.
- `HostProbes` trait (engine) = socket-based TCP probe + enrichment, implemented by
  `enrich::NetEnricher` (DNS servers per adapter from `GetAdaptersAddresses`).
- Events: `scan:batch` (`ScanBatch`: host upserts keyed by IP + totals, flushed every 100 ms or 512
  hosts; offline hosts are sent too; online hosts come again with `complete: true`) and `scan:finished` (`ScanSummary`). One scan at a time.
- IPC JSON is camelCase. Command errors are `{ code, message, detail }`; the frontend shows
  `error.<code>` from the locale files with `{detail}` filled in, falling back to `message`.
  New error codes need an `error.*` key in both locale files.
- Host actions (`actions.rs`, `platform::open_*`): browser URL built from `IpAddr` + bool + `u16`;
  `mstsc.exe /v:<ip>` and `explorer.exe \\<ip>` started by absolute path from
  `GetSystemDirectoryW` / `GetSystemWindowsDirectoryW` (no PATH search, IPv4 only for now);
  WoL magic packet = 6x FF + 16x MAC to UDP 9, directed + limited broadcast from the adapter of
  the host's subnet (all adapters if unknown/off-link; plus unicast if off-link).
- App commands are listed in `build.rs` (`AppManifest::commands`) and must also be allowed in
  `capabilities/default.json` (`allow-<command-name>`). Add new commands in both places plus
  `generate_handler!`.
- Limits: concurrency 1-256 (default 64), timeout 100-10,000 ms (default 1000).

## Frontend (`src/`)

- `api.ts` typed invoke/listen wrappers + IPC types · `export.ts` export dialog · `main.ts` wiring (scan flow, menu actions,
  error/toast, settings, language listener).
- `store.ts` `HostStore`: Map ip -> host + precomputed search text/IP key; `rows()` = filtered +
  sorted view, cached until a change. Empty values sort last in both directions. 65,536 hosts:
  3-52 ms per re-sort (Node bench); refreshes are coalesced to >= 200 ms while scanning.
- `table.ts` `VirtualTable`: sticky header + absolutely positioned pooled rows (`translateY`,
  slot = row index % pool size), fixed `ROW_HEIGHT` 28 px = CSS `--row-height`; grid columns via
  `--vt-columns`. Keyboard: arrows/Page/Home/End, context-menu key / Shift+F10.
- `details.ts` panel, `menu.ts` context menu, `toast.ts`, `settings.ts` dialog (theme preview,
  revert on cancel), `theme.ts` (5 themes = `[data-theme]` blocks in `styles.css`, colors only),
  `format.ts` display helpers.
- `i18n.ts`: flat keys, `data-i18n`, `-placeholder`, `-title`, `-aria-label`; `de` type-checked
  against `en`; `setLanguage` + `onLanguageChange` for runtime switching; `Intl` number/date formats.
- CSS changes go through CSSOM (`el.style.x = ...`), never `style` attributes (CSP).
- Browser context menu is suppressed outside inputs; Ctrl+F focuses the filter.

## Enrichment (phase 2, `src-tauri/src/enrich/`)

- `wire.rs` DNS message builder/parser (PTR only; compression with backward-only pointers, jump
  limit, RDATA bounds) shared by `dns.rs` (system DNS servers, max 2) and `mdns.rs` (unicast
  one-shot query to `<ip>:5353`, on-link hosts only). `netbios.rs` NBSTAT `*` query on UDP 137.
- `services.rs`: discovery TCP check on `DISCOVERY_PORTS` 21,22,23,80,443,445,3389,8080,8443
  with the tuned `ports::probe::connect`; per-port answers kept in `HostResult.probed_ports`
  (`#[serde(skip)]`). Only an *open* port makes a host online (an RST does not: some firewalls
  reset for nonexistent hosts). HTTP/1.0 `GET /` (`http_info`, shared with the port scan) on
  ports named `http`/`http-alt`, max 64 KiB, max 3 redirects and only same host+port (never
  follow to other hosts). HTTPS titles need a TLS crate -> not added, ask the user first.
- Enrichment (`NetEnricher::new(adapters, banners)`): with `banners` on (default) it reads HTTP
  titles and passive banners of the discovery check's open ports; off = neither.
- `oui.rs`: binary table `src-tauri/data/oui.bin` (`IOUI` v1, sorted 3-byte prefixes + u24 name
  offsets, ~700 KB), built by `npm run update-oui` (`tools/oui/update-oui.mjs`; raw CSV never in
  context). Locally administered MACs (bit 0x02) get `macLocal: true` and no vendor.
- All network strings go through `clean_text` (controls -> space, bidi/zero-width removed,
  length cap). Hostname priority: DNS > mDNS > NetBIOS (`hostnameSource`).
- Lookup timeout = scan timeout clamped to 500-3000 ms.

## Export (phase 4, `src-tauri/src/export/`)

- The backend keeps the last scan in memory (`commands::ScanRecord`, filled from the batch
  callback, cleared when a new scan starts). `export_results` writes from that copy; the
  frontend only sends the format, delimiter, language, UTC offset and - for "current view" - the
  ordered IP list. No export while a scan runs.
- Save dialog: `tauri-plugin-dialog` is registered (needed for the Rust API) but the webview has
  no `dialog:*` permission. Non-blocking `save_file` + oneshot; missing extension is added.
- `csv.rs`: BOM, CRLF, `;`/`,`, RFC 4180 quoting; network text starting with `= + - @ \t \r`
  gets a leading `'` (formula injection). Timestamps local RFC 3339 with offset.
- `json.rs`: own snake_case schema (`schema_version` 1, generator, exported_at, scope, scan
  metadata, hosts with all names/services); UTC timestamps. Bump the version on breaking changes.
- `html.rs`: one file, inline CSS, `<meta>` CSP `default-src 'none'`, everything escaped, A4
  landscape print styles.
- `labels.rs`: texts come from `src/locales/*.json` via `include_str!` (one catalog for UI and
  exports); a test renders every format in both languages and fails on raw keys/placeholders.
- `time.rs`: self-written civil-date conversion (no chrono). Settings now also store
  `csvDelimiter` (remembered from the last CSV export).

## Offline devices and known devices (v0.2.0)

- `HostResult.status` online/offline/unused (`decide_status`: offline = silent but any data),
  `last_seen_ms`, `sources` (per field: live, dns, arpCache, remembered, imported).
- Engine: reverse DNS also for silent addresses (`ScanConfig.resolve_offline_names`, setting
  `offlineNames` auto = up to 1,024 targets; max 32 lookups at a time), then
  `NetBackend::neighbor_cache` (`GetIpNetTable2`, filtered by `usable_neighbor`) fills MAC/vendor
  of silent addresses at scan end.
- `known.rs` `KnownDevices`: remembered (session; opt-in file `known-devices.json` in app data
  dir / `ironsight-known-devices.json` next to the portable exe) + imported (JSON export v1/v2,
  untrusted, sanitized). Key MAC, else IP; recording an IP removes it from other devices; a
  device online elsewhere in this scan is not shown at its old IP; a cache MAC only matches that
  MAC. `apply_known` merges known data into silent hosts.
- `commands::ScanRecord` keeps the engine's hosts (without known data) + live set; known data is
  applied at scan end (`finish_known` -> one extra `scan:batch` before `scan:finished`), on
  import/forget (`KnownUpdate.hosts`) and in exports. Lock order: `known` before `last_scan`.
- `save_settings`: remember on -> write file, off -> delete it.

## Port scanning (v0.4.0, `src-tauri/src/ports/`)

TCP connect scan only: no Npcap, no admin rights, no raw sockets. Tauri-free like the scan
engine; the Tauri glue is in `commands.rs`.
- `spec.rs` `PortSet` = merged inclusive `u16` ranges. Input: comma list of `N` / `A-B`,
  whitespace around entries and `-` allowed; strict otherwise: no empty entries (`22,,80`,
  trailing comma), ASCII digits only, no leading zeros, 1-65535, no open ranges, max 2048 bytes.
  Duplicates/overlaps are merged, so the normalized set never holds a port twice; `Display` gives
  the normalized spec (`22,80,443,1000-2000`). Errors `ports.*` with `code()`/`detail()`.
- `presets.rs` own curation (no nmap-services or other port databases - license): Common (22
  ports, contains the old 9 probe ports), Top 100 (grouped list), Top 1000 = Top 100 + every port
  of `names.rs` + remaining well-known ports 1-1023 from the lowest up to exactly 1000, All.
  Serde names `common`/`top100`/`top1000`/`all`.
- `names.rs` port -> service name, display only (IANA name, or the common one: 445 `smb`, 3389
  `rdp`, 8080 `http-alt`); the table is also the curated Top 1000 extension list.
- `probe.rs` one connect: open / closed (`ConnectionRefused`/`Reset`) / filtered (`TimedOut`,
  host/net unreachable) / failed (local error, counted as `errors`, never shown as a state).
  One retry after 100 ms on `AddrInUse`/`WSAENOBUFS`. Own address port 137 gives `WSAEACCES`
  (Windows blocks it) -> error, correct.
- **Windows SYN retry after RST** (measured, Win 11): a plain connect to a closed port takes
  2.03 s (loopback, own LAN address and LAN router alike) - with a 1 s timeout every closed port
  would look filtered. Fix in `platform::windows::prepare_probe_socket` before `connect`:
  `SIO_TCP_INITIAL_RTO` with `MaxSynRetransmissions = 0xFE` (no retransmissions; the windows
  crate declares the constant as u16 65534, the field is u8) -> RST reported in < 2 ms; and
  `Rtt = probe timeout`, because without retransmissions the OS gives up after the initial RTO
  (default 1 s; measured 300 ms -> 0.31 s, 3000 -> 3.0 s). Trade-off: one lost SYN = filtered.
  Plus best-effort `TCP_FAIL_CONNECT_ON_ICMP_ERROR`. Needs windows feature `Win32_System_IO`
  (for `WSAIoctl`). tokio timeout = probe timeout + 250 ms backstop only.
- **TIME_WAIT**: `TcpSocket::set_zero_linger()` (SO_LINGER 0) -> closing an open port sends RST,
  no TIME_WAIT (verified: Top 1000 on the router with 10 open ports left 0 entries, one plain
  connect+close leaves 1). Ephemeral range is 16,384 ports. Don't use deprecated `set_linger`.
- `scanner.rs` `scan_ports(prober, targets, ports, config, cancel, scan_id, on_batch)`:
  `PortProber` trait (real `TcpProber { banners }`, tests use a mock). `PortTarget { ip, known }`:
  known answers are taken over, not probed (progress `total` excludes them). Limits: timeout 100-10,000 ms (1000),
  concurrency 1-1024 (256, global semaphore), per host 1-256 (32, clamped to concurrency and port
  count); hosts in parallel = ceil(concurrency / per host) so hosts finish one after another.
  Cap hosts x ports: default 1,000,000 (a /24 with Top 1000 fits), configurable up to 2^24;
  above it the scan is refused (`ports.too_many_probes`), never truncated. Cancel (existing
  `watch` channel) aborts in-flight probes (drop = socket closed), stopped hosts are reported
  `complete: false`.
- Live results: `PortBatch { scanId, hosts: HostPorts[], done, total }` every 250 ms or 256 changed
  hosts; `HostPorts` is an upsert by IP (`complete`, `probed/total`, counts `open/closed/
  filtered/errors`, `ports[]` = open ports up to 1024 + closed/filtered ports while <= 32 of that
  state, like "997 closed"). `PortScanSummary` at the end.
- `banner.rs` (phase 2): per port `method()`: `Http` for ports named `http`/`http-alt` (reuses
  `services::http_info`, no duplicate HTTP code), `None` for client-first ports (`CLIENT_FIRST`:
  TLS-wrapped, RPC/SMB/RDP, DNS, LDAP, Kerberos), `Passive` for everything else - we never send
  a byte to non-HTTP ports (also safe for raw printer ports like 9100). Passive read: wait
  `greeting_wait` = probe timeout clamped 0.5-2 s for the first bytes, then 200 ms idle gap, at
  most +1 s and 1024 bytes. `sanitize`: drop a UTF-8 char cut at the end, strip Telnet IAC and
  ANSI CSI sequences, lossy UTF-8 (Latin-1 umlauts are lost, binary junk is not shown as
  letters); with binary parts only printable runs >= 4 chars stay (`strings`-like, keeps e.g.
  the MySQL version); then `clean_text` (one line, no controls/bidi) capped at 256 chars.
  Frontend/exports escape it (untrusted).
- **Merge with the old 9-port probe** (no duplicate scanning): host discovery keeps its TCP check
  (needed to find hosts that ignore ping behind a router) and records open/closed/filtered per
  port. The port step takes over every definite answer (open/closed) via
  `HostResult::port_target()` and re-probes only silent (filtered) ports - those may have been
  lost to a slow first ARP. Banners of discovery-open ports come from the enrichment, so the port
  step does not reconnect to them. "Scan ports..." on one host is a fresh scan (no take-over).
- Data model: open ports stay in `HostResult.services` (`ServiceInfo` + `banner`), the rest in
  `HostResult.port_scan: Option<PortScanInfo>` (`selection`, `complete`, counts, `listed`
  closed/filtered). `PortSelection` = `{"preset":"top100"}` | `{"custom":"22,80"}` (custom stored
  normalized). `HostResult::apply_ports`: new details win, discovery details stay if the scan has
  none; ports of the scanned set that are not open any more are removed only when the report is
  complete and not truncated. Status is never changed by a port scan.
- Commands (phase 2): `ScanRequest` gets `banners?` (default true) and `ports?: PortScanOptions
  { selection, timeoutMs?, concurrency?, perHost?, maxProbes? }`, validated before the scan
  starts. Pipeline: discovery -> `finish_known` -> port step on the online hosts (skipped if
  stopped) -> `end_scan` -> `ports:finished` -> `scan:finished`. `scan_host_ports({ ip, ports,
  banners? })` (only IPs of the last scan, else `ports.unknown_host`) takes the scan slot
  (`stop_scan` stops it), returns `{ scanId, total }`, sends `ports:batch`/`ports:finished`.
- `ScanRecord.ports` keeps the latest `PortRecord` per IP next to the discovery hosts;
  `effective()` = known data + `apply_ports`, so exports and rows include port results while
  `record.hosts` stays discovery-only. Events: `ports:batch { scanId, hosts: HostResult[]
  (upserts), done, total }` (engine-throttled, 250 ms), `ports:finished { scanId, summary,
  error }` (`error` e.g. `ports.too_many_probes` when online hosts x ports exceed the cap).
- Live check (Win 11, own /24): 14 online, 53 discovery answers taken over, Top 100 port step
  1347 probes in 5.1 s in 11 batches; stop after 1.5 s ended at 1.51 s.

## Port scan UI (phase 3)

- Settings (`settings.rs` + `settings.ts`): `portScan` (off), `portPreset` (`PortChoice`
  common|top100|top1000|all|custom), `portCustom` (kept while another preset is chosen; must
  parse only when `custom` is selected, max 2048 bytes), `portTimeoutMs` (1000),
  `portConcurrency` (256), `portMaxProbes` (1,000,000), `banners` (on), `portNoticeAccepted`.
  Load resets bad values per field (invalid custom list -> preset `common`, text kept). Per-host
  limit is not a setting (32).
- Custom lists are checked by the Rust parser via `check_port_list(spec)` -> `{ normalized,
  count }` (debounced 250 ms, `PortListField` in `ports.ts`), so UI and scan rules are identical;
  the error shows inline (`.field-message`), the normalized list is what gets saved/sent.
- `ports.ts`: `PortChoiceInput` (select + custom field), `HostPortsDialog` ("Scan ports …":
  settings' list preselected or another one for this scan), `NoticeDialog` (one-time
  authorization notice before the first port scan - network scan with `portScan` on, or "Scan
  ports …"; Cancel aborts and asks again next time, accept is saved), `portOptions()`.
- Table: column "Open ports" (`SortKey` `ports`, replaced the old services column; `col.services`
  stays for exports): first 4 port numbers + "+N", "0" after a port scan without open ports,
  "…" while the host's port scan runs; sort by count, scanned-with-0 before not scanned (nulls
  last both ways). Filter: `port:N` terms (AND, any case) + remaining text (whitespace
  collapsed); an invalid `port:` term matches nothing. Banners are part of the search text.
- Details: "Ports" section after the `dl`: notes (selection, `probed of total – open/closed/
  filtered`, stopped, local errors, or "quick check of 9 ports" without a port scan), table
  Port/Service/State/Banner (banner, else `HTTP status · server · title`), "N closed/filtered/
  open ports not listed". `ListedPort` carries the service `name`.
- Progress (`main.ts`): `progress.mode` network|hostPorts, `progress.ports` {done,total} from
  `ports:batch`; network mode switches the bar to checks during the port step and appends
  "port scan: N open ports" at the end; `portsStopped` makes the final status "Stopped". Stop
  button = `stop_scan` for both. "Scan ports …" keeps the table and shows its own progress.
- Themes: new text colors only via variables; `--online-text` per theme for the "open" state
  (light theme needs `#15803d`: `--online` is 3.5:1 on white). Checked: all five themes reach
  WCAG AA (>= 4.5:1) for the new texts on `--bg-raised`/`--bg-input`.

## Commands

```
npm run typecheck                                   # tsc strict
cd src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
cargo test live_scan -- --ignored --nocapture       # real scan of the local /24 (manual)
cargo test connect_timing -- --ignored --nocapture  # plain vs tuned connect to a closed port
cargo test live_port_scan -- --ignored --nocapture  # Top 1000 on own address (IRONSIGHT_PORTS_HOST=<ip>)
cargo test live_scan_with_ports -- --ignored --nocapture  # /24 discovery + Top 100 (IRONSIGHT_STOP_AFTER_MS)
npm run update-oui                                  # refresh the embedded IEEE OUI table
npm run tauri dev                                   # user runs this
```
